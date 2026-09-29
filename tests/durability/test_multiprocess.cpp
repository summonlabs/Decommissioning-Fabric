// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Cross-process single-writer exclusion, proven with independent operating
// system processes.
//
// Nothing here is a thread standing in for a process: every contender is a real
// dfab.exe started with CreateProcess, all of them are started before any is
// waited on, and the results are collected with WaitForMultipleObjects and
// GetExitCodeProcess. The store directory, the single-writer lock, the durable
// commit and the recovery are the production ones. No case uses a timeout.
//
// Proof obligations:
//   * Eight concurrent dfab processes mutating one store either succeed (exit 0)
//     or are refused with store_locked (exit 1); at least one succeeds.
//   * The final durable sequence is exactly the number of successful mutations
//     plus the generations that were committed before the race, so no losing
//     process mutated anything and no winner mutated twice.
//   * While this process holds the store open, every concurrent dfab process is
//     refused with store_locked and exit 1, and not one of them mutates.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ios>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "harness.hpp"

#include "decommissioning_fabric/format.hpp"
#include "decommissioning_fabric/store.hpp"

#ifndef DF_CLI_PATH
#error "DF_CLI_PATH must be defined to the absolute path of the dfab executable"
#endif

namespace {

namespace df = decommissioning_fabric;
namespace fs = std::filesystem;

using df::DurableStore;
using df::ErrorCode;
using df::StoreOptions;
using df::StoreState;

// ---------------------------------------------------------------------------
// Failures and text helpers
// ---------------------------------------------------------------------------

[[noreturn]] void Fail(std::string message) { throw df_test::Failure{std::move(message)}; }

[[nodiscard]] bool Contains(std::string_view text, std::string_view needle) {
  return text.find(needle) != std::string_view::npos;
}

[[nodiscard]] std::wstring Widen(std::string_view text) {
  if (text.empty()) {
    return std::wstring();
  }
  const int size = ::MultiByteToWideChar(CP_UTF8, 0, text.data(),
                                         static_cast<int>(text.size()), nullptr, 0);
  if (size <= 0) {
    Fail("a process argument is not valid UTF-8");
  }
  std::wstring wide(static_cast<std::size_t>(size), L'\0');
  ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), size);
  return wide;
}

/// A filesystem path rendered as UTF-8, which is what the CLI expects.
[[nodiscard]] std::string PathToUtf8(const fs::path& path) {
  const std::wstring wide = path.wstring();
  if (wide.empty()) {
    return std::string();
  }
  const int size = ::WideCharToMultiByte(CP_UTF8, 0, wide.data(),
                                         static_cast<int>(wide.size()), nullptr, 0, nullptr,
                                         nullptr);
  if (size <= 0) {
    Fail("a store path is not representable as UTF-8");
  }
  std::string narrow(static_cast<std::size_t>(size), '\0');
  ::WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), narrow.data(),
                        size, nullptr, nullptr);
  return narrow;
}

/// The CLI takes and renders asset identities in hexadecimal, so the test must
/// name the identity the same way the operator does.
[[nodiscard]] std::string HexText(std::uint64_t value) {
  std::ostringstream text;
  text << std::hex << value;
  return text.str();
}

/// Quotes one argument using the CommandLineToArgvW rules, so paths containing
/// spaces survive the round trip through CreateProcessW.
[[nodiscard]] std::wstring QuoteArgument(const std::wstring& argument) {
  if (!argument.empty() && argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
    return argument;
  }
  std::wstring quoted(1, L'"');
  for (auto cursor = argument.begin();; ++cursor) {
    std::size_t backslashes = 0;
    while (cursor != argument.end() && *cursor == L'\\') {
      ++cursor;
      ++backslashes;
    }
    if (cursor == argument.end()) {
      quoted.append(backslashes * 2U, L'\\');
      break;
    }
    if (*cursor == L'"') {
      quoted.append((backslashes * 2U) + 1U, L'\\');
      quoted.push_back(*cursor);
    } else {
      quoted.append(backslashes, L'\\');
      quoted.push_back(*cursor);
    }
  }
  quoted.push_back(L'"');
  return quoted;
}

[[nodiscard]] fs::path CapturePath(std::string_view label) {
  static unsigned counter = 0;
  ++counter;
  std::ostringstream name;
  name << "dfab-multiprocess-" << label << "-"
       << static_cast<unsigned long long>(::GetCurrentProcessId()) << "-" << counter << ".txt";
  return fs::temp_directory_path() / name.str();
}

[[nodiscard]] std::string ReadWholeFile(const fs::path& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return std::string();
  }
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  return buffer.str();
}

// ---------------------------------------------------------------------------
// Concurrent processes
// ---------------------------------------------------------------------------

struct CliRun {
  int exit_code{-1};
  std::string output;
};

/// A batch of real dfab processes. Every process of a batch is started before
/// any of them is waited on, and the batch is waited on indefinitely.
class Batch {
 public:
  Batch() = default;

  ~Batch() {
    if (!waited_ && !slots_.empty()) {
      // The results are deliberately dropped here: this path only runs when a
      // test threw before collecting them, and the processes must still be
      // reaped rather than leaked.
      static_cast<void>(WaitAll());
    }
    for (Slot& slot : slots_) {
      if (slot.process != nullptr) {
        ::CloseHandle(slot.process);
      }
      if (slot.thread != nullptr) {
        ::CloseHandle(slot.thread);
      }
      std::error_code ignored;
      fs::remove(slot.capture, ignored);
    }
  }

  Batch(const Batch&) = delete;
  Batch& operator=(const Batch&) = delete;

  /// Starts one dfab process. It is not waited on here.
  void Start(const std::vector<std::string>& arguments) {
    std::wstring command_line = QuoteArgument(Widen(DF_CLI_PATH));
    for (const std::string& argument : arguments) {
      command_line.push_back(L' ');
      command_line += QuoteArgument(Widen(argument));
    }

    Slot slot;
    slot.capture = CapturePath("cli");

    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;

    const std::wstring capture_wide = slot.capture.wstring();
    HANDLE output = ::CreateFileW(capture_wide.c_str(), GENERIC_READ | GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (output == INVALID_HANDLE_VALUE) {
      Fail("cannot create the child capture file: error " +
           std::to_string(static_cast<unsigned long long>(::GetLastError())));
    }
    HANDLE input = ::CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ, &attributes, OPEN_EXISTING,
                                 0, nullptr);
    if (input == INVALID_HANDLE_VALUE) {
      ::CloseHandle(output);
      Fail("cannot open NUL for the child stdin: error " +
           std::to_string(static_cast<unsigned long long>(::GetLastError())));
    }

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = input;
    startup.hStdOutput = output;
    startup.hStdError = output;

    PROCESS_INFORMATION process{};
    std::wstring mutable_line = command_line;
    const BOOL started = ::CreateProcessW(nullptr, mutable_line.data(), nullptr, nullptr, TRUE,
                                          CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
    const DWORD failure = started != 0 ? 0U : ::GetLastError();
    ::CloseHandle(input);
    ::CloseHandle(output);
    if (started == 0) {
      Fail("cannot start '" + std::string(DF_CLI_PATH) + "': error " +
           std::to_string(static_cast<unsigned long long>(failure)));
    }
    slot.process = process.hProcess;
    slot.thread = process.hThread;
    slots_.push_back(slot);
  }

  /// Waits for every process and returns one result per process, in start order.
  [[nodiscard]] std::vector<CliRun> WaitAll() {
    std::vector<HANDLE> handles;
    handles.reserve(slots_.size());
    for (const Slot& slot : slots_) {
      handles.push_back(slot.process);
    }
    if (!handles.empty()) {
      const DWORD count = static_cast<DWORD>(handles.size());
      if (::WaitForMultipleObjects(count, handles.data(), TRUE, INFINITE) == WAIT_FAILED) {
        Fail("WaitForMultipleObjects failed: error " +
             std::to_string(static_cast<unsigned long long>(::GetLastError())));
      }
    }
    waited_ = true;

    std::vector<CliRun> results;
    results.reserve(slots_.size());
    for (Slot& slot : slots_) {
      DWORD code = 0;
      if (::GetExitCodeProcess(slot.process, &code) == 0) {
        Fail("GetExitCodeProcess failed: error " +
             std::to_string(static_cast<unsigned long long>(::GetLastError())));
      }
      CliRun run;
      run.exit_code = static_cast<int>(code);
      run.output = ReadWholeFile(slot.capture);
      results.push_back(std::move(run));
    }
    return results;
  }

 private:
  struct Slot {
    HANDLE process{nullptr};
    HANDLE thread{nullptr};
    fs::path capture;
  };

  std::vector<Slot> slots_;
  bool waited_{false};
};

/// Runs one dfab process synchronously, which is what the setup phase needs.
[[nodiscard]] CliRun RunCli(const std::vector<std::string>& arguments) {
  Batch batch;
  batch.Start(arguments);
  std::vector<CliRun> results = batch.WaitAll();
  return std::move(results.front());
}

// ---------------------------------------------------------------------------
// Assertions that carry the child's output into the failure message
// ---------------------------------------------------------------------------

void RequireExit(const CliRun& run, int expected, const std::string& what) {
  if (run.exit_code != expected) {
    Fail(what + " exited with code " + std::to_string(run.exit_code) + ", expected " +
         std::to_string(expected) + "\n--- output ---\n" + run.output);
  }
}

void RequireContains(const CliRun& run, std::string_view needle, const std::string& what) {
  if (!Contains(run.output, needle)) {
    Fail(what + " did not report '" + std::string(needle) + "'\n--- output ---\n" + run.output);
  }
}

// ---------------------------------------------------------------------------
// Store directory fixture
// ---------------------------------------------------------------------------

/// A private store directory, named with this process id so two runs of the
/// suite can never share one, removed when the case ends even on failure.
class TempStore {
 public:
  explicit TempStore(std::string_view label) {
    static unsigned sequence = 0;
    ++sequence;
    std::ostringstream name;
    name << "dfab-multiprocess-" << label << "-"
         << static_cast<unsigned long long>(::GetCurrentProcessId()) << "-" << sequence;
    path_ = fs::temp_directory_path() / name.str();
    std::error_code ignored;
    fs::remove_all(path_, ignored);
    fs::create_directories(path_, ignored);
  }

  ~TempStore() {
    std::error_code ignored;
    fs::remove_all(path_, ignored);
  }

  TempStore(const TempStore&) = delete;
  TempStore& operator=(const TempStore&) = delete;

  [[nodiscard]] const fs::path& path() const noexcept { return path_; }
  [[nodiscard]] std::string utf8() const { return PathToUtf8(path_); }

 private:
  fs::path path_;
};

[[nodiscard]] DurableStore OpenOrFail(const fs::path& directory, const std::string& context,
                                      StoreState& out_state) {
  StoreOptions options;
  options.create_if_missing = false;
  auto opened = DurableStore::Open(PathToUtf8(directory), options, out_state);
  if (!opened.ok()) {
    Fail(context + ": DurableStore::Open failed: " + opened.error().to_string());
  }
  return std::move(opened).value();
}

/// The dfab arguments that register one asset, used both by the setup phase and
/// by the refusal round.
[[nodiscard]] std::vector<std::string> RegisterArguments(const TempStore& store,
                                                         std::string_view asset_text,
                                                         std::string_view serial) {
  return {"asset", "register", "--store", store.utf8(), "--create",
          "--asset", std::string(asset_text), "--site", "2", "--rack", "3",
          "--hardware-generation", "1", "--firmware-generation", "1",
          "--authority-mask", "0", "--model", "concurrency-unit",
          "--serial", std::string(serial)};
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

DF_TEST(eight_concurrent_cli_processes_are_excluded_by_the_single_writer_lock) {
  constexpr int kProcesses = 8;
  constexpr std::uint64_t kFirstAsset = 0x1000;

  TempStore store("round-one");

  // The store already contains the registered assets the concurrent plan
  // creations act on: each registration is one synchronous CLI call, so the
  // durable sequence after this phase is exactly the number of registrations.
  for (int index = 0; index < kProcesses; ++index) {
    const std::uint64_t asset = kFirstAsset + static_cast<std::uint64_t>(index);
    RequireExit(RunCli(RegisterArguments(store, HexText(asset), "sn-" + std::to_string(index))), 0,
                "asset register " + HexText(asset));
  }

  std::uint64_t initial_sequence = 0;
  {
    StoreState state;
    DurableStore handle = OpenOrFail(store.path(), "after registration", state);
    initial_sequence = handle.sequence().value();
    DF_CHECK_EQ(initial_sequence, static_cast<std::uint64_t>(kProcesses));
    DF_CHECK_EQ(state.fleet.size(), static_cast<std::size_t>(kProcesses));
  }

  // All eight processes are started before any of them is waited on.
  Batch batch;
  for (int index = 0; index < kProcesses; ++index) {
    const std::uint64_t asset = kFirstAsset + static_cast<std::uint64_t>(index);
    batch.Start({"plan", "create", "--store", store.utf8(), "--create",
                 "--asset", HexText(asset),
                 "--attempt", HexText(0x10U + static_cast<std::uint64_t>(index))});
  }
  const std::vector<CliRun> results = batch.WaitAll();
  DF_CHECK_EQ(results.size(), static_cast<std::size_t>(kProcesses));

  int succeeded = 0;
  int refused = 0;
  for (std::size_t index = 0; index < results.size(); ++index) {
    const std::string what =
        "plan create " + HexText(kFirstAsset + static_cast<std::uint64_t>(index));
    if (results[index].exit_code == 0) {
      ++succeeded;
      RequireContains(results[index], "applied: true", what);
    } else {
      RequireExit(results[index], 1, what);
      RequireContains(results[index], "store_locked", what);
      ++refused;
    }
  }
  DF_CHECK_MSG(succeeded >= 1, "at least one process must have won the single-writer lock");
  DF_CHECK_EQ(succeeded + refused, kProcesses);

  // The final durable sequence is the pre-race sequence plus exactly the
  // successful mutations: no refused process mutated anything, and no winner
  // committed twice.
  StoreState final_state;
  DurableStore final_handle = OpenOrFail(store.path(), "after the concurrent round", final_state);
  DF_CHECK_EQ(final_handle.sequence().value(),
              initial_sequence + static_cast<std::uint64_t>(succeeded));
  DF_CHECK_MSG(!final_handle.recovery().fresh, "the store was mutated by the round");
  DF_CHECK_MSG(!final_handle.recovery().unrecoverable, "the store is recoverable");
  DF_CHECK_EQ(final_handle.recovery().recovered_sequence.value(), final_handle.sequence().value());
  DF_CHECK_EQ(final_state.sequence.value(), final_handle.sequence().value());
  DF_CHECK_EQ(final_state.fleet.size(), static_cast<std::size_t>(kProcesses));
  DF_CHECK_EQ(final_state.cases.size(), static_cast<std::size_t>(succeeded));

  for (int index = 0; index < kProcesses; ++index) {
    const std::uint64_t asset = kFirstAsset + static_cast<std::uint64_t>(index);
    DF_CHECK_MSG(final_state.FindAsset(df::AssetId::FromValue(asset)) != nullptr,
                 "asset " + HexText(asset) + " must still be registered");
  }
}

DF_TEST(four_concurrent_cli_processes_are_all_refused_while_the_parent_holds_the_store) {
  constexpr int kProcesses = 4;
  constexpr std::uint64_t kHeldAsset = 0x7000;
  constexpr std::uint64_t kFirstRefused = 0x7100;

  TempStore store("round-two");
  RequireExit(RunCli(RegisterArguments(store, HexText(kHeldAsset), "sn-held")), 0,
              "asset register");

  {
    StoreOptions options;
    options.create_if_missing = true;
    StoreState state;
    auto opened = DurableStore::Open(store.utf8(), options, state);
    if (!opened.ok()) {
      Fail("the parent could not take the store: " + opened.error().to_string());
    }
    DurableStore holder = std::move(opened).value();
    DF_CHECK(holder.holds_lock());
    DF_CHECK_EQ(holder.sequence().value(), std::uint64_t{1});

    // Every one of these mutations would succeed if the store were free.
    Batch batch;
    for (int index = 0; index < kProcesses; ++index) {
      const std::uint64_t asset = kFirstRefused + static_cast<std::uint64_t>(index);
      batch.Start(
          RegisterArguments(store, HexText(asset), "sn-refused-" + std::to_string(index)));
    }
    const std::vector<CliRun> results = batch.WaitAll();
    DF_CHECK_EQ(results.size(), static_cast<std::size_t>(kProcesses));
    for (std::size_t index = 0; index < results.size(); ++index) {
      const std::string what =
          "asset register " + HexText(kFirstRefused + static_cast<std::uint64_t>(index));
      RequireExit(results[index], 1, what);
      RequireContains(results[index], "store_locked", what);
    }

    // The refusals did not release the holder's lock, and the holder is the one
    // that would notice: it still holds it after the round.
    DF_CHECK(holder.holds_lock());
  }

  // The lock was released with the holder, and no refused process mutated
  // anything: the sequence is still the one registration, and none of the four
  // assets exists.
  StoreState final_state;
  DurableStore final_handle = OpenOrFail(store.path(), "after the refused round", final_state);
  DF_CHECK_EQ(final_handle.sequence().value(), std::uint64_t{1});
  DF_CHECK_EQ(final_state.sequence.value(), std::uint64_t{1});
  DF_CHECK_EQ(final_state.fleet.size(), std::size_t{1});
  DF_CHECK_MSG(final_state.FindAsset(df::AssetId::FromValue(kHeldAsset)) != nullptr,
               "the registered asset must still be present");
  for (int index = 0; index < kProcesses; ++index) {
    const std::uint64_t asset = kFirstRefused + static_cast<std::uint64_t>(index);
    DF_CHECK_MSG(final_state.FindAsset(df::AssetId::FromValue(asset)) == nullptr,
                 "a refused process must not have mutated the store: asset " +
                     HexText(asset) + " must not exist");
  }
}

}  // namespace

DF_TEST_MAIN()

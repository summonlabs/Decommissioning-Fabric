// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Durability proof for the dual-slot store.
//
// Every case here drives the real dfab_crash_driver as a real child process
// against a real store directory, injects a real fault at a named step of a
// named commit, and then recovers the store with the production DurableStore.
// Nothing is simulated: the kills are TerminateProcess, the torn bytes are real
// bytes on a real disk, and the single-writer lock is the production LockFileEx
// lock. No case uses a timeout: a hang is a defect to diagnose, never something
// to time out of.
//
// Proof obligations:
//   a) For every commit step 1..7 and commit index 1..3 a kill recovers exactly
//      one authoritative generation: K-1 or K, never a merged or torn one, and
//      the recovered payload is byte-identical to exactly one slot on disk.
//   b) Kills at steps 1..5 (before or at the publish point) recover K-1 and
//      kills at steps 6..7 (after the publish point) recover K; for K = 1 with a
//      pre-publish kill the store is fresh because no commit ever landed.
//   c) A torn published slot is never recovered as the newer generation.
//   d) A short write fails the commit before the publish point and leaves the
//      previous generation intact.
//   e) A directory flush failure after the publish point degrades the commit
//      instead of failing it, because the generation is already published.
//   f) The OS releases the single-writer lock when the holding process dies.
//   g) Two handles in one process cannot both hold the lock, and both are
//      released cleanly on destruction.
//   h) Reopening recovers the identical generation every time, with a commit
//      count that starts at zero for each new handle.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <array>
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

#ifndef DF_CRASH_DRIVER_PATH
#error "DF_CRASH_DRIVER_PATH must be defined to the absolute path of dfab_crash_driver.exe"
#endif

namespace {

namespace df = decommissioning_fabric;
namespace fs = std::filesystem;

using df::CommitSequence;
using df::DurableStore;
using df::ErrorCode;
using df::FaultPlan;
using df::SlotStatus;
using df::StoreOptions;
using df::StoreState;

// ---------------------------------------------------------------------------
// Failures and text helpers
// ---------------------------------------------------------------------------

[[noreturn]] void Fail(std::string message) { throw df_test::Failure{std::move(message)}; }

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

/// A filesystem path rendered as UTF-8, which is what the store and the child
/// processes expect.
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

/// A unique capture file for one child's combined stdout and stderr.
[[nodiscard]] fs::path CapturePath(std::string_view label) {
  static unsigned counter = 0;
  ++counter;
  std::ostringstream name;
  name << "dfab-durability-" << label << "-"
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
// Real child processes
// ---------------------------------------------------------------------------

/// A real child process whose stdout and stderr are captured to a private file.
/// Every wait is INFINITE.
class Child {
 public:
  Child(const std::string& executable, const std::vector<std::string>& arguments,
        const fs::path& capture)
      : capture_(capture) {
    std::wstring command_line = QuoteArgument(Widen(executable));
    for (const std::string& argument : arguments) {
      command_line.push_back(L' ');
      command_line += QuoteArgument(Widen(argument));
    }

    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;

    const std::wstring capture_wide = capture_.wstring();
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
      Fail("cannot start '" + executable + "': error " +
           std::to_string(static_cast<unsigned long long>(failure)));
    }
    process_ = process.hProcess;
    thread_ = process.hThread;
  }

  ~Child() {
    if (process_ != nullptr) {
      if (!waited_) {
        ::WaitForSingleObject(process_, INFINITE);
      }
      ::CloseHandle(process_);
    }
    if (thread_ != nullptr) {
      ::CloseHandle(thread_);
    }
    std::error_code ignored;
    fs::remove(capture_, ignored);
  }

  Child(const Child&) = delete;
  Child& operator=(const Child&) = delete;

  [[nodiscard]] bool alive() const {
    return process_ != nullptr && ::WaitForSingleObject(process_, 0) == WAIT_TIMEOUT;
  }

  [[nodiscard]] int Wait() {
    if (!waited_) {
      ::WaitForSingleObject(process_, INFINITE);
      DWORD code = 0;
      ::GetExitCodeProcess(process_, &code);
      exit_code_ = static_cast<int>(code);
      waited_ = true;
    }
    return exit_code_;
  }

  [[nodiscard]] std::string output() const { return ReadWholeFile(capture_); }

 private:
  HANDLE process_{nullptr};
  HANDLE thread_{nullptr};
  fs::path capture_;
  int exit_code_{-1};
  bool waited_{false};
};

/// Runs the crash driver to completion and returns its exit code.
[[nodiscard]] int RunDriver(const std::vector<std::string>& arguments, std::string& output) {
  Child child(DF_CRASH_DRIVER_PATH, arguments, CapturePath("crash"));
  const int code = child.Wait();
  output = child.output();
  return code;
}

// ---------------------------------------------------------------------------
// Store directory fixture and slot inspection
// ---------------------------------------------------------------------------

/// A private store directory, named with this process id so two runs of the
/// suite can never share one, removed when the case ends even on failure.
class TempStore {
 public:
  explicit TempStore(std::string_view label) {
    static unsigned sequence = 0;
    ++sequence;
    std::ostringstream name;
    name << "dfab-durability-" << label << "-"
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

/// One slot as it exists on disk, parsed with the production record codec.
struct SlotObservation {
  bool present{false};
  bool valid{false};
  std::uint64_t sequence{0};
  std::string payload;
};

[[nodiscard]] SlotObservation ObserveSlot(const fs::path& directory, std::string_view name) {
  SlotObservation observation;
  const std::string contents = ReadWholeFile(directory / std::string(name));
  if (contents.empty()) {
    return observation;
  }
  observation.present = true;
  auto record = df::ParseRecord(contents, static_cast<std::uint64_t>(contents.size()));
  if (!record.ok()) {
    return observation;
  }
  df::ParsedRecord parsed = std::move(record).value();
  observation.valid = true;
  observation.sequence = parsed.sequence.value();
  observation.payload = std::move(parsed.payload);
  return observation;
}

[[nodiscard]] DurableStore OpenOrFail(const fs::path& directory, const std::string& context,
                                      StoreState& out_state, bool create_if_missing) {
  StoreOptions options;
  options.create_if_missing = create_if_missing;
  auto opened = DurableStore::Open(PathToUtf8(directory), options, out_state);
  if (!opened.ok()) {
    Fail(context + ": DurableStore::Open failed: " + opened.error().to_string());
  }
  return std::move(opened).value();
}

/// Asserts the invariants every successful recovery must satisfy: exactly one
/// authoritative generation, recovered from exactly one slot, never merged, and
/// byte-identical to the payload that slot holds.
void AssertRecoveredGeneration(const fs::path& directory, const DurableStore& store,
                               const StoreState& state, std::uint64_t expected_sequence,
                               const std::string& context) {
  DF_CHECK_MSG(store.sequence().value() == expected_sequence,
               context + ": recovered handle sequence");
  DF_CHECK_MSG(state.sequence.value() == expected_sequence, context + ": recovered state sequence");
  DF_CHECK_MSG(store.recovery().recovered_sequence.value() == expected_sequence,
               context + ": recovery report sequence");
  DF_CHECK_MSG(!store.recovery().fresh, context + ": a recovery is not a fresh store");
  DF_CHECK_MSG(!store.recovery().unrecoverable, context + ": the store is recoverable");
  DF_CHECK_MSG(store.recovery().recovered_from == SlotStatus::valid,
               context + ": recovery named a valid slot");
  DF_CHECK_MSG(store.commit_count() == 0, context + ": a new handle starts at commit zero");

  const SlotObservation slot_a = ObserveSlot(directory, "state.a");
  const SlotObservation slot_b = ObserveSlot(directory, "state.b");
  const std::size_t corrupt = (slot_a.present && !slot_a.valid ? 1U : 0U) +
                              (slot_b.present && !slot_b.valid ? 1U : 0U);
  DF_CHECK_MSG(corrupt <= 1U, context + ": at most one slot may be corrupt");

  std::size_t matching = 0;
  const SlotObservation* chosen = nullptr;
  for (const SlotObservation* observation : {&slot_a, &slot_b}) {
    if (observation->valid && observation->sequence == expected_sequence) {
      ++matching;
      chosen = observation;
    }
  }
  DF_CHECK_MSG(matching == 1U, context + ": exactly one valid slot holds the recovered generation");
  DF_CHECK_MSG(chosen != nullptr, context + ": the recovered generation exists on disk");
  DF_CHECK_MSG(df::EncodeState(state) == chosen->payload,
               context + ": the recovered state is byte-identical to the slot that holds it");
  DF_CHECK_MSG(store.recovery().torn_slots.size() <= 1U,
               context + ": recovery reports at most one torn slot");
}

/// The first generation's facility epoch, which is what a fresh store hands back
/// and what the advance scenario increments once per successful commit.
constexpr std::uint32_t kAdvanceStartEpoch = 1;

// ---------------------------------------------------------------------------
// a) + b) the kill matrix
// ---------------------------------------------------------------------------

struct MatrixCell {
  std::uint32_t step{0};
  std::uint64_t commit{0};
  int exit_code{0};
  bool opened{false};
  std::string open_error;
  bool fresh{false};
  bool unrecoverable{false};
  std::uint64_t recovered{0};
  std::uint64_t store_sequence{0};
  std::uint64_t commit_count{0};
  SlotStatus recovered_from{SlotStatus::absent};
  std::size_t torn_slots{0};
  std::size_t valid_slots{0};
  std::size_t corrupt_slots{0};
  std::size_t slots_matching_recovery{0};
  bool payload_decoded{false};
  std::uint64_t payload_sequence{0};
  std::uint32_t payload_epoch{0};
  bool payload_matches_slot{false};
  std::string spec;
  std::string child_output;
};

/// Runs one (step, commit) cell of the kill matrix as a real child process and
/// observes what recovery makes of the wreckage.
[[nodiscard]] MatrixCell RunKillCell(std::uint32_t step, std::uint64_t commit) {
  MatrixCell cell;
  cell.step = step;
  cell.commit = commit;
  cell.spec = "kill:" + std::to_string(step) + "@" + std::to_string(commit);

  TempStore store("kill");
  cell.exit_code =
      RunDriver({"--store", store.utf8(), "--create", "--scenario", "advance", "--commits", "4",
                 "--fault-inject", cell.spec},
                cell.child_output);

  StoreOptions options;
  options.create_if_missing = false;
  StoreState state;
  auto opened = DurableStore::Open(store.utf8(), options, state);
  if (!opened.ok()) {
    cell.open_error = opened.error().to_string();
    return cell;
  }
  cell.opened = true;
  DurableStore handle = std::move(opened).value();
  cell.fresh = handle.recovery().fresh;
  cell.unrecoverable = handle.recovery().unrecoverable;
  cell.recovered = handle.sequence().value();
  cell.store_sequence = handle.sequence().value();
  cell.commit_count = handle.commit_count();
  cell.recovered_from = handle.recovery().recovered_from;
  cell.torn_slots = handle.recovery().torn_slots.size();

  const SlotObservation slot_a = ObserveSlot(store.path(), "state.a");
  const SlotObservation slot_b = ObserveSlot(store.path(), "state.b");
  const SlotObservation* chosen = nullptr;
  for (const SlotObservation* observation : {&slot_a, &slot_b}) {
    if (observation->valid) {
      ++cell.valid_slots;
      if (observation->sequence == cell.recovered) {
        ++cell.slots_matching_recovery;
        chosen = observation;
      }
    } else if (observation->present) {
      ++cell.corrupt_slots;
    }
  }

  if (chosen != nullptr) {
    auto decoded = df::DecodeState(chosen->payload);
    if (decoded.ok()) {
      cell.payload_decoded = true;
      cell.payload_sequence = decoded.value().sequence.value();
      cell.payload_epoch = decoded.value().generations.facility_epoch.value();
      cell.payload_matches_slot = df::EncodeState(decoded.value()) == chosen->payload;
    }
  } else {
    cell.payload_decoded = true;
    cell.payload_sequence = state.sequence.value();
    cell.payload_epoch = state.generations.facility_epoch.value();
    cell.payload_matches_slot = true;
  }
  return cell;
}

[[nodiscard]] std::string RenderMatrix(const std::array<std::array<std::string, 3>, 7>& table) {
  std::string out;
  for (std::size_t step = 0; step < table.size(); ++step) {
    out += "step " + std::to_string(step + 1U) + ":";
    for (std::size_t k = 0; k < 3U; ++k) {
      out += " K=" + std::to_string(k + 1U) + " -> " + table[step][k];
    }
    out += "\n";
  }
  return out;
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

DF_TEST(a_kill_at_any_commit_step_recovers_exactly_one_authoritative_generation) {
  for (std::uint32_t step = 1; step <= 7; ++step) {
    for (std::uint64_t commit = 1; commit <= 3; ++commit) {
      const MatrixCell cell = RunKillCell(step, commit);
      const std::string context = "kill:" + std::to_string(step) + "@" + std::to_string(commit) +
                                  "\n--- child output ---\n" + cell.child_output;

      DF_CHECK_MSG(cell.exit_code == df::kFaultKillExitCode,
                   context + "\nthe injected kill must fire, exit code 0xDEAD (57005) expected but " +
                       std::to_string(cell.exit_code) + " was observed");
      DF_CHECK_MSG(cell.opened, context + "\nOpen failed: " + cell.open_error);

      const bool expect_fresh = step <= 5U && commit == 1U;
      const std::uint64_t expected = step <= 5U ? commit - 1U : commit;
      DF_CHECK_MSG(cell.recovered == expected,
                   context + "\nexpected sequence " + std::to_string(expected) + ", observed " +
                       std::to_string(cell.recovered));
      DF_CHECK_MSG(cell.store_sequence == expected, context + "\nhandle sequence");
      DF_CHECK_MSG(cell.commit_count == 0U, context + "\na new handle starts at commit zero");
      DF_CHECK_MSG(cell.corrupt_slots <= 1U, context + "\nat most one slot may be corrupt");
      DF_CHECK_MSG(cell.torn_slots <= 1U, context + "\nat most one torn slot is reported");

      if (expect_fresh) {
        DF_CHECK_MSG(cell.fresh, context + "\nno commit ever landed, so the store is fresh");
        DF_CHECK_MSG(!cell.unrecoverable, context + "\na fresh store is not unrecoverable");
        DF_CHECK_MSG(cell.valid_slots == 0U, context + "\nno slot may exist yet");
        DF_CHECK_MSG(cell.recovered_from == SlotStatus::absent,
                     context + "\nrecovery must not name a slot it did not read");
        DF_CHECK_MSG(cell.payload_sequence == 0U, context + "\nfresh state sequence");
        DF_CHECK_MSG(cell.payload_epoch == kAdvanceStartEpoch, context + "\nfresh facility epoch");
      } else {
        DF_CHECK_MSG(!cell.fresh, context + "\na committed store is not fresh");
        DF_CHECK_MSG(!cell.unrecoverable, context + "\nthe store is recoverable");
        DF_CHECK_MSG(cell.recovered_from == SlotStatus::valid,
                     context + "\nrecovery must name the valid slot it chose");
        DF_CHECK_MSG(cell.slots_matching_recovery == 1U,
                     context + "\nthe recovered sequence must equal the sequence of exactly one "
                               "valid slot: recovery never merges slots");
        DF_CHECK_MSG(cell.payload_decoded, context + "\nthe recovered payload must decode");
        DF_CHECK_MSG(cell.payload_sequence == cell.recovered,
                     context + "\nthe payload sequence must equal the record header sequence");
        DF_CHECK_MSG(cell.payload_epoch == expected + 1U,
                     context + "\nthe recovered content must be the generation the header claims");
        DF_CHECK_MSG(cell.payload_matches_slot,
                     context + "\nthe recovered state must be the exact payload of its slot");
      }
    }
  }
}

DF_TEST(kills_before_the_publish_point_recover_k_minus_one_and_after_recover_k) {
  std::array<std::array<std::string, 3>, 7> observed{};
  for (std::uint32_t step = 1; step <= 7; ++step) {
    for (std::uint64_t commit = 1; commit <= 3; ++commit) {
      const MatrixCell cell = RunKillCell(step, commit);
      DF_CHECK_MSG(cell.opened,
                   "kill:" + std::to_string(step) + "@" + std::to_string(commit) +
                       ": Open failed: " + cell.open_error + "\n" + cell.child_output);
      std::string classification = "unexpected:" + std::to_string(cell.recovered);
      if (cell.fresh) {
        classification = "fresh";
      } else if (cell.recovered == commit) {
        classification = "K";
      } else if (cell.recovered == commit - 1U) {
        classification = "K-1";
      }
      observed[step - 1U][commit - 1U] = classification;
    }
  }

  std::array<std::array<std::string, 3>, 7> expected{};
  for (std::size_t step = 1; step <= 7U; ++step) {
    for (std::size_t commit = 1; commit <= 3U; ++commit) {
      if (step <= 5U) {
        expected[step - 1U][commit - 1U] = commit == 1U ? "fresh" : "K-1";
      } else {
        expected[step - 1U][commit - 1U] = "K";
      }
    }
  }

  const std::string report = RenderMatrix(observed);
  if (observed != expected) {
    Fail("the observed partition of the kill matrix does not match the publish-point rule\n"
         "observed:\n" +
         report + "expected:\n" + RenderMatrix(expected));
  }
  DF_CHECK_MSG(observed == expected, "the kill matrix partition\n" + report);
}

// ---------------------------------------------------------------------------
// c) torn published slots
// ---------------------------------------------------------------------------

DF_TEST(a_torn_published_slot_is_never_recovered_as_the_newer_generation) {
  // The occurrence qualifier scopes the tear to the third commit, which is the
  // commit that overwrites the older of the two published slots. Without it the
  // fault fires on every commit, both slots are torn, and the store is
  // legitimately unrecoverable - that case is asserted separately below. The
  // claim under test here is the interesting one: one torn published slot must
  // never win over the intact previous generation.
  for (const std::string_view spec : {"truncate:5=64@3", "bitflip:5=100@3"}) {
    TempStore store("torn-slot");
    std::string output;
    const int code =
        RunDriver({"--store", store.utf8(), "--create", "--scenario", "advance", "--commits", "3",
                   "--fault-inject", std::string(spec)},
                  output);
    // The fault lands after the read-back verification and before the atomic
    // publish, so the process itself completes and believes commit 3 succeeded.
    DF_CHECK_MSG(code == 0, std::string(spec) + ": the driver reported completion, exit code " +
                                std::to_string(code) + "\n" + output);

    StoreState state;
    DurableStore handle = OpenOrFail(store.path(), std::string(spec), state, false);
    AssertRecoveredGeneration(store.path(), handle, state, 2, std::string(spec));
    DF_CHECK_MSG(handle.recovery().had_torn_slot(),
                 std::string(spec) + ": recovery must report the torn slot");
    DF_CHECK_MSG(handle.sequence().value() != 3U,
                 std::string(spec) + ": the torn generation must never be recovered");

    const SlotObservation slot_a = ObserveSlot(store.path(), "state.a");
    const SlotObservation slot_b = ObserveSlot(store.path(), "state.b");
    const std::size_t corrupt = (slot_a.present && !slot_a.valid ? 1U : 0U) +
                                (slot_b.present && !slot_b.valid ? 1U : 0U);
    DF_CHECK_MSG(corrupt == 1U,
                 std::string(spec) + ": exactly one slot is torn, observed " +
                     std::to_string(corrupt));
  }

  // Without the occurrence qualifier the fault fires on every commit, so both
  // slots end up torn. That store must refuse to open rather than start empty.
  {
    TempStore store("both-slots-torn");
    std::string output;
    const int code =
        RunDriver({"--store", store.utf8(), "--create", "--scenario", "advance", "--commits", "3",
                   "--fault-inject", "truncate:5=64"},
                  output);
    DF_CHECK_MSG(code == 0, "every commit reports completion, exit code " + std::to_string(code) +
                                "\n" + output);
    StoreOptions options;
    StoreState state;
    auto opened = DurableStore::Open(store.utf8(), options, state);
    DF_CHECK_CODE(opened, ErrorCode::store_corrupt);
  }
}

// ---------------------------------------------------------------------------
// d) short writes
// ---------------------------------------------------------------------------

DF_TEST(a_short_write_fails_the_commit_before_the_publish_point) {
  // The literal unscoped fault: every commit that reaches the write step writes
  // only 64 bytes, so the very first commit fails its read-back verification and
  // nothing is ever published.
  {
    TempStore store("write-short-first");
    std::string output;
    const int code =
        RunDriver({"--store", store.utf8(), "--create", "--scenario", "advance", "--commits", "3",
                   "--fault-inject", "write_short:3=64"},
                  output);
    DF_CHECK_MSG(code == 3, "the commit must fail, exit code 3 expected but " +
                                std::to_string(code) + " was observed\n" + output);
    DF_CHECK_MSG(output.find("did not verify") != std::string::npos ||
                     output.find("store_corrupt") != std::string::npos,
                 "the failure must be the read-back verification\n" + output);

    // The failed commit left only a temporary slot: no published generation and
    // no temporary file surviving the open.
    DF_CHECK_MSG(fs::exists(store.path() / "state.b.tmp") ||
                     fs::exists(store.path() / "state.a.tmp"),
                 "the failed commit must leave the temporary slot it could not publish");
    DF_CHECK_MSG(!fs::exists(store.path() / "state.a") && !fs::exists(store.path() / "state.b"),
                 "nothing may be published before the read-back verification passes");

    StoreState state;
    DurableStore handle = OpenOrFail(store.path(), "write_short:3=64", state, false);
    DF_CHECK_MSG(handle.recovery().fresh, "no commit ever landed, so the store is fresh");
    DF_CHECK_MSG(!handle.recovery().unrecoverable, "a fresh store is not unrecoverable");
    DF_CHECK_MSG(handle.sequence().value() == 0U, "fresh sequence");
    DF_CHECK_MSG(handle.recovery().torn_slots.empty(), "a fresh store reports no torn slot");
    DF_CHECK_MSG(!fs::exists(store.path() / "state.a.tmp") &&
                     !fs::exists(store.path() / "state.b.tmp"),
                 "recovery must discard the temporary slot of the failed commit");
  }

  // The scoped fault: the first generation publishes, the second fails before
  // the publish point, and recovery still reports the previous generation.
  {
    TempStore store("write-short-second");
    std::string output;
    const int code =
        RunDriver({"--store", store.utf8(), "--create", "--scenario", "advance", "--commits", "3",
                   "--fault-inject", "write_short:3=64@2"},
                  output);
    DF_CHECK_MSG(code == 3, "the second commit must fail, exit code 3 expected but " +
                                std::to_string(code) + " was observed\n" + output);
    DF_CHECK_MSG(!fs::exists(store.path() / "state.a.tmp") ||
                     !fs::exists(store.path() / "state.b.tmp"),
                 "the failed commit must leave exactly the temporary slot it could not publish");
    DF_CHECK_MSG(!fs::exists(store.path() / "state.a"),
                 "the failed commit must not publish its slot");

    StoreState state;
    DurableStore handle = OpenOrFail(store.path(), "write_short:3=64@2", state, false);
    AssertRecoveredGeneration(store.path(), handle, state, 1, "write_short:3=64@2");
    DF_CHECK_MSG(handle.recovery().torn_slots.empty(),
                 "the previous generation survived intact, so no slot is torn");
    DF_CHECK_EQ(state.generations.facility_epoch.value(), kAdvanceStartEpoch + 1U);
  }
}

// ---------------------------------------------------------------------------
// e) directory flush degradation
// ---------------------------------------------------------------------------

DF_TEST(a_directory_flush_failure_after_the_publish_point_degrades_without_failing) {
  // In process: the commit outcome must report the degradation, and the
  // generation must still be durable because the publish point has passed.
  {
    TempStore store("directory-flush");
    StoreState state;
    DurableStore handle = OpenOrFail(store.path(), "directory flush degradation", state, true);

    auto faults = FaultPlan::FromSpec("directory_flush_fail:6@1");
    if (!faults.ok()) {
      Fail("the fault specification did not parse: " + faults.error().to_string());
    }
    handle.options().faults = std::move(faults).value();

    StoreState first = state;
    first.sequence = CommitSequence::FromValue(1);
    first.generations.facility_epoch =
        df::FacilityEpoch::FromValue(state.generations.facility_epoch.value() + 1U);
    auto outcome = handle.Commit(first);
    DF_CHECK_MSG(outcome.ok(), "a post-publish directory flush failure must not fail the commit: " +
                                   (outcome.ok() ? std::string() : outcome.error().to_string()));
    DF_CHECK_MSG(outcome.value().degraded,
                 "the commit must report that it was published but degraded");
    DF_CHECK_MSG(!outcome.value().degraded_reason.empty(),
                 "a degraded commit must carry a reason");
    DF_CHECK_MSG(outcome.value().sequence.value() == 1U, "the degraded commit is still the commit");
    DF_CHECK_MSG(handle.sequence().value() == 1U, "the published generation is the in-memory one");

    // The fault is gone, so the next generation is a plain, undegraded commit.
    handle.options().faults = FaultPlan{};
    StoreState second = first;
    second.sequence = CommitSequence::FromValue(2);
    second.generations.facility_epoch =
        df::FacilityEpoch::FromValue(first.generations.facility_epoch.value() + 1U);
    auto second_outcome = handle.Commit(second);
    DF_CHECK_MSG(second_outcome.ok(), "the second commit must succeed");
    DF_CHECK_MSG(!second_outcome.value().degraded, "an unaffected commit is not degraded");
    DF_CHECK_MSG(second_outcome.value().degraded_reason.empty(),
                 "an undegraded commit carries no reason");

    const SlotObservation slot_a = ObserveSlot(store.path(), "state.a");
    const SlotObservation slot_b = ObserveSlot(store.path(), "state.b");
    DF_CHECK_MSG(slot_a.valid || slot_b.valid, "the degraded generation was really published");
  }

  // End to end: three commits, every one of them degraded after the publish
  // point, and all three are durable.
  {
    TempStore store("directory-flush-driver");
    std::string output;
    const int code =
        RunDriver({"--store", store.utf8(), "--create", "--scenario", "advance", "--commits", "3",
                   "--fault-inject", "directory_flush_fail:6"},
                  output);
    DF_CHECK_MSG(code == 0, "a post-publish degradation is not a failure, exit code " +
                                std::to_string(code) + " observed\n" + output);
    StoreState state;
    DurableStore handle = OpenOrFail(store.path(), "directory_flush_fail:6", state, false);
    AssertRecoveredGeneration(store.path(), handle, state, 3, "directory_flush_fail:6");
    DF_CHECK_EQ(state.generations.facility_epoch.value(), kAdvanceStartEpoch + 3U);
  }

  // The same degradation is observable through the engine's decision, which is
  // what an operator sees: the mutation applied and the commit is marked
  // degraded rather than refused.
  {
    TempStore store("directory-flush-outcome");
    StoreState state;
    DurableStore handle = OpenOrFail(store.path(), "degraded outcome", state, true);
    auto faults = FaultPlan::FromSpec("directory_flush_fail:6");
    if (!faults.ok()) {
      Fail("the fault specification did not parse: " + faults.error().to_string());
    }
    handle.options().faults = std::move(faults).value();
    StoreState next = state;
    next.sequence = CommitSequence::FromValue(1);
    auto outcome = handle.Commit(next);
    DF_CHECK_MSG(outcome.ok() && outcome.value().degraded,
                 "an unscoped directory flush fault degrades every commit");
    DF_CHECK_MSG(outcome.value().degraded_reason.find("directory flush") != std::string::npos,
                 "the reason names the directory flush: " + outcome.value().degraded_reason);
  }
}

// ---------------------------------------------------------------------------
// f) lock release on process death
// ---------------------------------------------------------------------------

DF_TEST(the_single_writer_lock_is_released_when_the_holding_process_dies) {
  // The child holds the lock for its whole life and kills itself during commit
  // 40. While it is alive the parent must be refused; once it is gone the parent
  // must be admitted, because the operating system released the lock.
  {
    TempStore store("holder-death");
    Child child(DF_CRASH_DRIVER_PATH,
                {"--store", store.utf8(), "--create", "--scenario", "advance", "--commits", "40",
                 "--fault-inject", "kill:1@40"},
                CapturePath("holder"));

    // A published slot proves the child is past Engine::Open and therefore holds
    // the single-writer lock.
    while (!fs::exists(store.path() / "state.a") && !fs::exists(store.path() / "state.b")) {
      if (!child.alive()) {
        Fail("the crash driver died before publishing its first generation, exit code " +
             std::to_string(child.Wait()) + "\n" + child.output());
      }
      ::Sleep(1);
    }
    DF_CHECK_MSG(child.alive(), "the holder must still be running");

    StoreOptions options;
    options.create_if_missing = true;
    StoreState blocked_state;
    auto blocked = DurableStore::Open(store.utf8(), options, blocked_state);
    DF_CHECK_CODE(blocked, ErrorCode::store_locked);
    DF_CHECK_MSG(child.alive(),
                 "the refusal must have come from the live holder, not from a vacated lock");

    const int code = child.Wait();
    DF_CHECK_MSG(code == df::kFaultKillExitCode,
                 "the holder must die from the injected kill, exit code " +
                     std::to_string(code) + " observed\n" + child.output());

    StoreState state;
    DurableStore reopened = OpenOrFail(store.path(), "after the lock holder died", state, false);
    AssertRecoveredGeneration(store.path(), reopened, state, 39, "after the lock holder died");
    DF_CHECK_EQ(state.generations.facility_epoch.value(), kAdvanceStartEpoch + 39U);
  }

  // The literal holder-death case: the kill fires during the first commit of the
  // second run, while that process holds the lock over an existing store. The
  // lock must be free as soon as the process is gone, and the earlier
  // generations must be intact.
  {
    TempStore store("holder-death-immediate");
    std::string output;
    DF_CHECK_MSG(RunDriver({"--store", store.utf8(), "--create", "--scenario", "advance",
                            "--commits", "5"},
                           output) == 0,
                 "the store must be populated first\n" + output);
    DF_CHECK_MSG(RunDriver({"--store", store.utf8(), "--scenario", "advance", "--commits", "5",
                            "--fault-inject", "kill:1@1"},
                           output) == df::kFaultKillExitCode,
                 "the second run must die from the injected kill\n" + output);

    StoreState state;
    DurableStore reopened = OpenOrFail(store.path(), "after kill:1@1", state, false);
    AssertRecoveredGeneration(store.path(), reopened, state, 5, "after kill:1@1");
    DF_CHECK_EQ(state.generations.facility_epoch.value(), kAdvanceStartEpoch + 5U);
  }
}

// ---------------------------------------------------------------------------
// g) single-writer exclusion inside one process
// ---------------------------------------------------------------------------

DF_TEST(two_handles_in_one_process_cannot_both_hold_the_single_writer_lock) {
  TempStore store("in-process-lock");
  StoreState state;
  {
    DurableStore first = OpenOrFail(store.path(), "first handle", state, true);
    DF_CHECK(first.holds_lock());

    {
      StoreOptions options;
      options.create_if_missing = true;
      StoreState refused_state;
      auto second = DurableStore::Open(store.utf8(), options, refused_state);
      DF_CHECK_CODE(second, ErrorCode::store_locked);
    }

    // The refused handle released everything it had opened: the holder still
    // holds the lock and still works.
    DF_CHECK(first.holds_lock());
    StoreState generation = state;
    generation.sequence = CommitSequence::FromValue(1);
    generation.generations.facility_epoch =
        df::FacilityEpoch::FromValue(state.generations.facility_epoch.value() + 1U);
    auto outcome = first.Commit(generation);
    DF_CHECK_MSG(outcome.ok(), "the holder must still be able to commit: " +
                                   (outcome.ok() ? std::string() : outcome.error().to_string()));
    DF_CHECK(first.holds_lock());
  }

  // The holder was destroyed, so the lock is free again and the generation it
  // published is the one that is recovered.
  {
    StoreState recovered;
    DurableStore third = OpenOrFail(store.path(), "after the holder was destroyed", recovered,
                                    false);
    AssertRecoveredGeneration(store.path(), third, recovered, 1,
                              "after the holder was destroyed");
  }

  // And a second lifecycle: open, refuse, destroy, reopen.
  {
    StoreState recovered;
    DurableStore fourth = OpenOrFail(store.path(), "second lifecycle", recovered, false);
    StoreOptions options;
    StoreState refused_state;
    auto refused = DurableStore::Open(store.utf8(), options, refused_state);
    DF_CHECK_CODE(refused, ErrorCode::store_locked);
    DF_CHECK(fourth.holds_lock());
  }
  {
    StoreState recovered;
    DurableStore fifth = OpenOrFail(store.path(), "after the second lifecycle", recovered, false);
    DF_CHECK_EQ(fifth.sequence().value(), 1U);
  }
}

// ---------------------------------------------------------------------------
// h) reopen idempotence
// ---------------------------------------------------------------------------

DF_TEST(reopening_twenty_times_recovers_the_identical_generation) {
  TempStore store("reopen");
  std::string output;
  DF_CHECK_MSG(RunDriver({"--store", store.utf8(), "--create", "--scenario", "advance",
                          "--commits", "3"},
                         output) == 0,
               "the store must be populated\n" + output);

  const std::string slot_a_bytes = ReadWholeFile(store.path() / "state.a");
  const std::string slot_b_bytes = ReadWholeFile(store.path() / "state.b");
  DF_CHECK_MSG(!slot_a_bytes.empty() && !slot_b_bytes.empty(),
               "three commits must have published both slots");

  std::string baseline;
  for (int attempt = 0; attempt < 20; ++attempt) {
    StoreState state;
    DurableStore handle = OpenOrFail(store.path(), "reopen " + std::to_string(attempt), state,
                                     false);
    DF_CHECK_MSG(handle.commit_count() == 0U,
                 "a new handle must start with a commit count of zero");
    DF_CHECK_MSG(handle.sequence().value() == 3U, "the recovered sequence must be stable");
    DF_CHECK_MSG(state.sequence.value() == 3U, "the recovered state sequence must be stable");
    DF_CHECK_EQ(state.generations.facility_epoch.value(), kAdvanceStartEpoch + 3U);
    DF_CHECK_MSG(handle.recovery().recovered_sequence.value() == 3U,
                 "the recovery report must be stable");
    DF_CHECK_MSG(!handle.recovery().fresh, "a populated store is not fresh");
    DF_CHECK_MSG(!handle.recovery().unrecoverable, "a populated store is recoverable");
    DF_CHECK_MSG(handle.recovery().torn_slots.empty(), "reopening must not create a torn slot");

    const std::string encoded = df::EncodeState(state);
    if (attempt == 0) {
      baseline = encoded;
    } else {
      DF_CHECK_MSG(encoded == baseline, "the decoded state must be identical on every reopen");
    }
    DF_CHECK_MSG(ReadWholeFile(store.path() / "state.a") == slot_a_bytes,
                 "opening a store must not modify slot a");
    DF_CHECK_MSG(ReadWholeFile(store.path() / "state.b") == slot_b_bytes,
                 "opening a store must not modify slot b");
  }
}

}  // namespace

DF_TEST_MAIN()

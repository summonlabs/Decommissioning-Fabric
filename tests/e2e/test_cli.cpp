// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// End-to-end proof for the dfab command line front end.
//
// Every case in this file drives the real executable as a child process against
// a real store directory on disk. Nothing is mocked: the process boundary, the
// single-writer store lock, the durable commit and recovery path, and the
// rendered human and JSON output are the production ones. Each case creates its
// own store under the system temporary directory, named with the process id so
// concurrent runs cannot collide, and removes it when the case ends.
//
// Proof obligations covered here:
//   * 'version' exits 0 and prints the runtime version string.
//   * 'asset register' then 'asset show' reports the same generations across a
//     process boundary, and 'store status --json' reports a numeric sequence.
//   * 'plan create' exits 0, prints a fence token, and 'plan show' reports phase
//     requested with the same fence.
//   * A replayed mutation (same explicit --attempt) reports a replay and does not
//     advance the phase or the durable sequence twice - the lost-response proof.
//   * A stale fence captured before an intervening mutation is refused with exit
//     code 1 and a fence error naming the exact mismatching field.
//   * 'plan explain' exits 0 and names a concrete blocker with its required action.
//   * The full happy path reaches phase decommissioned with canonical_deletion
//     false and removal_observed true.
//   * While the store is held open in-process, a child process is refused with
//     store_locked and exit code 1.

// windows.h must not define the min/max macros: the library headers use
// std::numeric_limits<T>::max() and would not survive the substitution.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstddef>
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

#include "decommissioning_fabric/store.hpp"
#include "decommissioning_fabric/version.hpp"

// The build system supplies the absolute path of the dfab executable. A missing
// definition is a configuration error, not something to paper over with a
// relative path that might silently test the wrong binary.
#ifndef DF_CLI_PATH
#error "DF_CLI_PATH must be defined to the absolute path of the dfab executable"
#endif

namespace {

namespace fs = std::filesystem;

using decommissioning_fabric::DurableStore;
using decommissioning_fabric::StoreOptions;
using decommissioning_fabric::StoreState;

// ---------------------------------------------------------------------------
// Failures and small text helpers
// ---------------------------------------------------------------------------

[[noreturn]] void Fail(std::string message) { throw df_test::Failure{std::move(message)}; }

[[nodiscard]] bool IsSpace(char character) {
  return character == ' ' || character == '\t' || character == '\n' || character == '\r';
}

[[nodiscard]] bool IsHexDigit(char character) {
  return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') ||
         (character >= 'A' && character <= 'F');
}

[[nodiscard]] bool IsDigit(char character) { return character >= '0' && character <= '9'; }

[[nodiscard]] bool IsAllDigits(std::string_view text) {
  if (text.empty()) {
    return false;
  }
  for (const char character : text) {
    if (!IsDigit(character)) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] bool Contains(std::string_view text, std::string_view needle) {
  return text.find(needle) != std::string_view::npos;
}

[[nodiscard]] std::size_t CountOccurrences(std::string_view text, std::string_view needle) {
  std::size_t count = 0;
  std::size_t position = text.find(needle);
  while (position != std::string_view::npos) {
    ++count;
    position = text.find(needle, position + needle.size());
  }
  return count;
}

/// Reads one scalar out of the CLI's JSON. The writer puts the value on the line
/// after the key, so whitespace between the colon and the value is expected.
[[nodiscard]] std::string JsonScalar(std::string_view output, std::string_view key) {
  const std::string needle = "\"" + std::string(key) + "\"";
  std::size_t position = output.find(needle);
  while (position != std::string_view::npos) {
    std::size_t cursor = position + needle.size();
    while (cursor < output.size() && IsSpace(output[cursor])) {
      ++cursor;
    }
    if (cursor < output.size() && output[cursor] == ':') {
      ++cursor;
      while (cursor < output.size() && IsSpace(output[cursor])) {
        ++cursor;
      }
      if (cursor < output.size() && output[cursor] == '"') {
        ++cursor;
        const std::size_t start = cursor;
        while (cursor < output.size() && output[cursor] != '"') {
          ++cursor;
        }
        return std::string(output.substr(start, cursor - start));
      }
      const std::size_t start = cursor;
      while (cursor < output.size() && !IsSpace(output[cursor]) && output[cursor] != ',' &&
             output[cursor] != '}' && output[cursor] != ']') {
        ++cursor;
      }
      if (cursor > start) {
        return std::string(output.substr(start, cursor - start));
      }
    }
    position = output.find(needle, position + 1U);
  }
  return std::string();
}

/// Extracts the compare-and-swap token from either rendering. Human output prints
/// '  fence_token: <hex>' and JSON prints '"fence_token": "<hex>"'.
[[nodiscard]] std::string ExtractFenceToken(std::string_view output) {
  constexpr std::string_view kKey = "fence_token";
  std::size_t position = output.find(kKey);
  while (position != std::string_view::npos) {
    std::size_t cursor = position + kKey.size();
    while (cursor < output.size() && IsSpace(output[cursor])) {
      ++cursor;
    }
    if (cursor < output.size() && output[cursor] == ':') {
      ++cursor;
      while (cursor < output.size() && (IsSpace(output[cursor]) || output[cursor] == '"')) {
        ++cursor;
      }
      const std::size_t start = cursor;
      while (cursor < output.size() && IsHexDigit(output[cursor])) {
        ++cursor;
      }
      if (cursor > start) {
        return std::string(output.substr(start, cursor - start));
      }
    }
    position = output.find(kKey, position + 1U);
  }
  return std::string();
}

// ---------------------------------------------------------------------------
// Child process plumbing
// ---------------------------------------------------------------------------

struct CliResult {
  int exit_code{0};
  std::string output;
};

[[nodiscard]] std::wstring Widen(std::string_view text) {
  if (text.empty()) {
    return std::wstring();
  }
  const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                       nullptr, 0);
  if (size <= 0) {
    Fail("argument is not valid UTF-8");
  }
  std::wstring wide(static_cast<std::size_t>(size), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), size);
  return wide;
}

/// A filesystem path rendered as UTF-8, which is what the CLI expects.
[[nodiscard]] std::string PathToUtf8(const fs::path& path) {
  const std::wstring wide = path.wstring();
  if (wide.empty()) {
    return std::string();
  }
  const int size = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                                       nullptr, 0, nullptr, nullptr);
  if (size <= 0) {
    Fail("store path is not representable as UTF-8");
  }
  std::string narrow(static_cast<std::size_t>(size), '\0');
  WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), narrow.data(), size,
                      nullptr, nullptr);
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

/// Spawns the real dfab executable, waits for it without any timeout, and
/// returns its exit code together with everything it wrote to stdout and stderr.
[[nodiscard]] CliResult RunCli(const std::vector<std::string>& arguments) {
  static unsigned capture_sequence = 0;
  ++capture_sequence;

  std::wstring command_line = QuoteArgument(Widen(DF_CLI_PATH));
  for (const std::string& argument : arguments) {
    command_line.push_back(L' ');
    command_line += QuoteArgument(Widen(argument));
  }

  std::ostringstream capture_name;
  capture_name << "dfab-e2e-output-" << static_cast<unsigned long long>(GetCurrentProcessId())
               << "-" << capture_sequence << ".txt";
  const fs::path capture_path = fs::temp_directory_path() / capture_name.str();

  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;

  const std::wstring capture_wide = capture_path.wstring();
  HANDLE output = CreateFileW(capture_wide.c_str(), GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_TEMPORARY, nullptr);
  if (output == INVALID_HANDLE_VALUE) {
    Fail("cannot create the child output file: error " +
         std::to_string(static_cast<unsigned long long>(GetLastError())));
  }
  HANDLE input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ, &attributes, OPEN_EXISTING, 0,
                             nullptr);
  if (input == INVALID_HANDLE_VALUE) {
    CloseHandle(output);
    Fail("cannot open NUL for the child stdin: error " +
         std::to_string(static_cast<unsigned long long>(GetLastError())));
  }

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = input;
  startup.hStdOutput = output;
  startup.hStdError = output;

  PROCESS_INFORMATION process{};
  std::wstring mutable_line = command_line;
  const BOOL started =
      CreateProcessW(nullptr, mutable_line.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                     nullptr, nullptr, &startup, &process);
  if (!started) {
    const unsigned long long failure = static_cast<unsigned long long>(GetLastError());
    CloseHandle(input);
    CloseHandle(output);
    DeleteFileW(capture_wide.c_str());
    Fail("cannot start '" + std::string(DF_CLI_PATH) + "': error " + std::to_string(failure));
  }

  WaitForSingleObject(process.hProcess, INFINITE);
  DWORD exit_code = 0;
  GetExitCodeProcess(process.hProcess, &exit_code);
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  CloseHandle(input);
  CloseHandle(output);

  std::string output_text;
  {
    std::ifstream stream(capture_path, std::ios::binary);
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    output_text = buffer.str();
  }
  DeleteFileW(capture_wide.c_str());
  return CliResult{static_cast<int>(exit_code), std::move(output_text)};
}

/// Runs a command against a store directory, creating the directory when absent.
[[nodiscard]] CliResult RunInStore(const fs::path& store, std::vector<std::string> arguments) {
  arguments.push_back("--store");
  arguments.push_back(PathToUtf8(store));
  arguments.push_back("--create");
  return RunCli(arguments);
}

/// Runs a mutating command with the current fence and an explicit attempt id.
[[nodiscard]] CliResult RunFenced(const fs::path& store, std::vector<std::string> arguments,
                                  std::string_view fence, int attempt) {
  arguments.push_back("--fence");
  arguments.push_back(std::string(fence));
  arguments.push_back("--attempt");
  arguments.push_back(std::to_string(attempt));
  return RunInStore(store, std::move(arguments));
}

// ---------------------------------------------------------------------------
// Assertions that carry the child's output into the failure message
// ---------------------------------------------------------------------------

void RequireExit(const CliResult& result, int expected, std::string_view what) {
  if (result.exit_code != expected) {
    Fail(std::string(what) + " exited with code " + std::to_string(result.exit_code) +
         ", expected " + std::to_string(expected) + "\n--- output ---\n" + result.output);
  }
}

void RequireOk(const CliResult& result, std::string_view what) { RequireExit(result, 0, what); }

void RequireContains(const CliResult& result, std::string_view needle, std::string_view what) {
  if (!Contains(result.output, needle)) {
    Fail(std::string(what) + " did not report '" + std::string(needle) + "'\n--- output ---\n" +
         result.output);
  }
}

[[nodiscard]] std::string FenceOf(const CliResult& result, std::string_view what) {
  const std::string token = ExtractFenceToken(result.output);
  if (token.empty()) {
    Fail(std::string(what) + " printed no fence token\n--- output ---\n" + result.output);
  }
  return token;
}

/// One drain obligation as reported in a decision's effects:
/// '    obligation: <hex>:<kind>:<state>'.
struct ObligationRef {
  std::string id;
  std::string kind;
};

[[nodiscard]] std::vector<ObligationRef> ObligationsOf(std::string_view output) {
  constexpr std::string_view kKey = "obligation: ";
  std::vector<ObligationRef> obligations;
  std::size_t position = output.find(kKey);
  while (position != std::string_view::npos) {
    std::size_t cursor = position + kKey.size();
    std::string fields[3];
    for (std::size_t index = 0; index < 3U; ++index) {
      const std::size_t start = cursor;
      while (cursor < output.size() && output[cursor] != ':' && output[cursor] != '\n' &&
             output[cursor] != '\r') {
        ++cursor;
      }
      fields[index] = std::string(output.substr(start, cursor - start));
      if (cursor < output.size() && output[cursor] == ':') {
        ++cursor;
      }
    }
    if (!fields[0].empty() && !fields[1].empty()) {
      obligations.push_back(ObligationRef{fields[0], fields[1]});
    }
    position = output.find(kKey, position + 1U);
  }
  return obligations;
}

// ---------------------------------------------------------------------------
// Store directory fixture
// ---------------------------------------------------------------------------

/// A private store directory, named with this process id so that two runs of the
/// suite can never share one, removed when the case ends even on failure.
class TempStore {
 public:
  TempStore() {
    static unsigned sequence = 0;
    ++sequence;
    std::ostringstream name;
    name << "dfab-e2e-" << static_cast<unsigned long long>(GetCurrentProcessId()) << "-"
         << sequence;
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

 private:
  fs::path path_;
};

/// 8 settable residual categories. 'unknown' is the absence of a disposition and
/// is deliberately not a category an operator may record.
constexpr std::string_view kResidualCategories[] = {
    "workload_state",       "persistent_media",   "credential_reference",
    "network_identity",     "reservation",        "monitoring_binding",
    "facility_reference",   "physical_asset"};

/// The ten independent authority domains, revoked in one command.
constexpr std::string_view kAuthorityDomains[] = {
    "asi_execution",     "dfi_network",        "power_control",     "cooling_control",
    "tenant_lease",      "inventory_record",   "monitoring_binding", "credential_scope",
    "reservation_hold",  "maintenance_window"};

void RegisterAsset(const fs::path& store, std::string_view asset) {
  RequireOk(RunInStore(store, {"asset", "register", "--asset", std::string(asset), "--site", "2",
                               "--rack", "3", "--hardware-generation", "1",
                               "--firmware-generation", "1", "--authority-mask", "0",
                               "--model", "edge-node", "--serial", "sn-42"}),
            "asset register");
}

/// Registers the asset and opens the retirement plan, returning the fence token
/// the rest of the flow must carry.
[[nodiscard]] std::string StartRetirement(const fs::path& store, std::string_view asset) {
  RegisterAsset(store, asset);
  const CliResult created =
      RunInStore(store, {"plan", "create", "--asset", std::string(asset), "--attempt", "1"});
  RequireOk(created, "plan create");
  RequireContains(created, "applied: true", "plan create");
  // The phase is read back from the durable record in a separate process rather
  // than from the decision, which reports only the step it just took.
  const CliResult view =
      RunInStore(store, {"plan", "show", "--asset", std::string(asset), "--json"});
  RequireOk(view, "plan show after create");
  if (JsonScalar(view.output, "phase") != "requested") {
    Fail("plan show after create reported phase '" + JsonScalar(view.output, "phase") +
         "', expected 'requested'\n--- output ---\n" + view.output);
  }
  return FenceOf(created, "plan create");
}

}  // namespace

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

DF_TEST(version_exits_zero_and_prints_the_version_string) {
  const CliResult human = RunCli({"version"});
  RequireOk(human, "dfab version");
  RequireContains(human, std::string("dfab ") + std::string(decommissioning_fabric::kVersionString),
                  "dfab version");
  RequireContains(human, "repository      : DCCP 34 of 72", "dfab version");

  const CliResult json = RunCli({"version", "--json"});
  RequireOk(json, "dfab version --json");
  DF_CHECK_EQ(JsonScalar(json.output, "version"),
              std::string(decommissioning_fabric::kVersionString));
  DF_CHECK_EQ(JsonScalar(json.output, "repository_ordinal"), std::string("34"));
  DF_CHECK_EQ(JsonScalar(json.output, "repository_total"), std::string("72"));
}

DF_TEST(asset_register_then_asset_show_reports_the_same_generations) {
  TempStore store;
  const CliResult registered =
      RunInStore(store.path(), {"asset", "register", "--asset", "7", "--site", "2", "--rack", "3",
                                "--hardware-generation", "11", "--firmware-generation", "13",
                                "--model", "unit-under-test", "--serial", "sn-7"});
  RequireOk(registered, "asset register");
  RequireContains(registered, "applied: true", "asset register");

  // A separate process, a fresh recovery of the durable generation.
  const CliResult human = RunInStore(store.path(), {"asset", "show", "--asset", "7"});
  RequireOk(human, "asset show");
  RequireContains(human, "hardware_generation: 11", "asset show");
  RequireContains(human, "firmware_generation: 13", "asset show");
  RequireContains(human, "site: 0000000000000002", "asset show");

  const CliResult json = RunInStore(store.path(), {"asset", "show", "--asset", "7", "--json"});
  RequireOk(json, "asset show --json");
  DF_CHECK_EQ(JsonScalar(json.output, "asset"), std::string("0000000000000007"));
  DF_CHECK_EQ(JsonScalar(json.output, "site"), std::string("0000000000000002"));
  DF_CHECK_EQ(JsonScalar(json.output, "rack"), std::string("0000000000000003"));
  DF_CHECK_EQ(JsonScalar(json.output, "hardware_generation"), std::string("11"));
  DF_CHECK_EQ(JsonScalar(json.output, "firmware_generation"), std::string("13"));
  // No retirement attempt has begun, so the asset carries no lifecycle generation.
  DF_CHECK_EQ(JsonScalar(json.output, "lifecycle_generation"), std::string("0"));

  // An unregistered asset is a governed refusal, not a crash and not a success.
  const CliResult unknown = RunInStore(store.path(), {"asset", "show", "--asset", "8"});
  RequireExit(unknown, 1, "asset show of an unregistered asset");
  RequireContains(unknown, "unknown_asset", "asset show of an unregistered asset");
}

DF_TEST(plan_create_prints_a_fence_token_and_plan_show_reports_requested) {
  TempStore store;
  RegisterAsset(store.path(), "1");

  const CliResult created =
      RunInStore(store.path(), {"plan", "create", "--asset", "1", "--attempt", "1"});
  RequireOk(created, "plan create");
  RequireContains(created, "applied: true", "plan create");
  RequireContains(created, "replayed: false", "plan create");
  const std::string fence = FenceOf(created, "plan create");
  DF_CHECK(fence.size() >= 64U);

  const CliResult human = RunInStore(store.path(), {"plan", "show", "--asset", "1"});
  RequireOk(human, "plan show");
  RequireContains(human, "phase: requested", "plan show");
  DF_CHECK_EQ(ExtractFenceToken(human.output), fence);

  const CliResult json = RunInStore(store.path(), {"plan", "show", "--asset", "1", "--json"});
  RequireOk(json, "plan show --json");
  DF_CHECK_EQ(JsonScalar(json.output, "phase"), std::string("requested"));
  DF_CHECK_EQ(JsonScalar(json.output, "lifecycle_generation"), std::string("1"));
  DF_CHECK_EQ(JsonScalar(json.output, "fence_token"), fence);
  DF_CHECK_EQ(JsonScalar(json.output, "revision"), std::string("1"));
}

DF_TEST(replaying_a_mutation_does_not_advance_the_phase_twice) {
  TempStore store;
  const std::string fence = StartRetirement(store.path(), "1");

  const std::vector<std::string> assess = {"dependencies", "assess", "--authority", "facility-ops",
                                           "--reference", "dep-1",        "--require",
                                           "asi_workload", "--require",   "dfi_route"};

  const CliResult first = RunFenced(store.path(), assess, fence, 2);
  RequireOk(first, "first dependencies assess");
  RequireContains(first, "applied: true", "first dependencies assess");
  RequireContains(first, "replayed: false", "first dependencies assess");
  RequireContains(first, "-> dependency_assessment", "first dependencies assess");

  const CliResult after_first = RunInStore(store.path(), {"plan", "show", "--asset", "1", "--json"});
  RequireOk(after_first, "plan show after the first assess");
  const std::string phase_after_first = JsonScalar(after_first.output, "phase");
  const std::string revision_after_first = JsonScalar(after_first.output, "revision");
  DF_CHECK_EQ(phase_after_first, std::string("dependency_assessment"));
  DF_CHECK_EQ(revision_after_first, std::string("2"));
  DF_CHECK_EQ(CountOccurrences(after_first.output, "\"obligation\""), std::size_t{2});
  const std::string sequence_after_first =
      JsonScalar(RunInStore(store.path(), {"store", "status", "--json"}).output, "sequence");

  // The response was lost, so the operator re-sends the identical request under
  // the identical attempt identity.
  const CliResult replay = RunFenced(store.path(), assess, fence, 2);
  RequireOk(replay, "replayed dependencies assess");
  RequireContains(replay, "replayed: true", "replayed dependencies assess");
  RequireContains(replay, "applied: false", "replayed dependencies assess");
  RequireContains(replay, "idempotent_replay", "replayed dependencies assess");

  const CliResult after_replay =
      RunInStore(store.path(), {"plan", "show", "--asset", "1", "--json"});
  RequireOk(after_replay, "plan show after the replay");
  DF_CHECK_EQ(JsonScalar(after_replay.output, "phase"), phase_after_first);
  DF_CHECK_EQ(JsonScalar(after_replay.output, "revision"), revision_after_first);
  DF_CHECK_EQ(CountOccurrences(after_replay.output, "\"obligation\""), std::size_t{2});

  // Nothing was committed a second time: the durable sequence is unchanged.
  const CliResult status = RunInStore(store.path(), {"store", "status", "--json"});
  RequireOk(status, "store status --json");
  DF_CHECK_EQ(JsonScalar(status.output, "sequence"), sequence_after_first);
}

DF_TEST(a_stale_fence_is_refused_and_names_the_mismatching_field) {
  TempStore store;
  const std::string stale = StartRetirement(store.path(), "1");

  // The intervening mutation: two required drain obligations become blocking, so
  // the obligation binding and the revision both move on.
  const CliResult assessed =
      RunFenced(store.path(),
                {"dependencies", "assess", "--authority", "facility-ops", "--reference", "dep-1",
                 "--require", "asi_workload", "--require", "dfi_route"},
                stale, 2);
  RequireOk(assessed, "dependencies assess");
  const std::string current = FenceOf(assessed, "dependencies assess");
  DF_CHECK_NE(current, stale);

  // The operator now acts on the fence they read before that mutation.
  const CliResult refused = RunFenced(store.path(), {"drain", "begin"}, stale, 3);
  RequireExit(refused, 1, "drain begin with a stale fence");
  RequireContains(refused, "refused", "stale fence refusal");
  RequireContains(refused, "fence_stale", "stale fence refusal");
  RequireContains(refused, "active_obligation_digest", "stale fence refusal");

  const CliResult refused_json = RunFenced(store.path(), {"drain", "begin", "--json"}, stale, 4);
  RequireExit(refused_json, 1, "drain begin with a stale fence (json)");
  DF_CHECK_EQ(JsonScalar(refused_json.output, "ok"), std::string("false"));
  DF_CHECK_EQ(JsonScalar(refused_json.output, "stage"), std::string("fence"));
  DF_CHECK_EQ(JsonScalar(refused_json.output, "code"), std::string("fence_stale"));
  DF_CHECK_EQ(JsonScalar(refused_json.output, "classification"), std::string("stale"));
  DF_CHECK_EQ(JsonScalar(refused_json.output, "field"), std::string("active_obligation_digest"));

  // The refusal was the staleness, not the request: the current fence is accepted.
  const CliResult accepted = RunFenced(store.path(), {"drain", "begin"}, current, 5);
  RequireOk(accepted, "drain begin with the current fence");
  RequireContains(accepted, "-> draining", "drain begin with the current fence");

  // A fence captured before a mutation that leaves the obligation binding alone is
  // behind on the revision, and the refusal names that field instead.
  const std::string fence_before_draining = current;
  const CliResult behind = RunFenced(store.path(), {"drain", "conclude"}, fence_before_draining, 6);
  RequireExit(behind, 1, "drain conclude with a revision-behind fence");
  RequireContains(behind, "fence_revision_behind", "revision-behind fence refusal");
  const CliResult behind_json =
      RunFenced(store.path(), {"drain", "conclude", "--json"}, fence_before_draining, 7);
  RequireExit(behind_json, 1, "drain conclude with a revision-behind fence (json)");
  DF_CHECK_EQ(JsonScalar(behind_json.output, "code"), std::string("fence_revision_behind"));
  DF_CHECK_EQ(JsonScalar(behind_json.output, "field"), std::string("revision"));
}

DF_TEST(plan_explain_names_a_blocker_and_its_required_action) {
  TempStore store;
  std::string fence = StartRetirement(store.path(), "1");

  const CliResult assessed =
      RunFenced(store.path(),
                {"dependencies", "assess", "--authority", "facility-ops", "--reference", "dep-1",
                 "--require", "asi_workload", "--require", "dfi_route"},
                fence, 2);
  RequireOk(assessed, "dependencies assess");
  fence = FenceOf(assessed, "dependencies assess");

  const CliResult draining = RunFenced(store.path(), {"drain", "begin"}, fence, 3);
  RequireOk(draining, "drain begin");
  fence = FenceOf(draining, "drain begin");

  const CliResult human = RunInStore(store.path(), {"plan", "explain", "--asset", "1"});
  RequireOk(human, "plan explain");
  RequireContains(human, "blocker 1", "plan explain");
  RequireContains(human, "drain_outstanding", "plan explain");
  RequireContains(human, "required:", "plan explain");
  RequireContains(human, "ready_to_advance: false", "plan explain");

  const CliResult json = RunInStore(store.path(), {"plan", "explain", "--asset", "1", "--json"});
  RequireOk(json, "plan explain --json");
  DF_CHECK_EQ(JsonScalar(json.output, "phase"), std::string("draining"));
  DF_CHECK_EQ(JsonScalar(json.output, "ready_to_advance"), std::string("false"));
  DF_CHECK_EQ(JsonScalar(json.output, "open_obligations"), std::string("2"));
  DF_CHECK_EQ(JsonScalar(json.output, "total_obligations"), std::string("2"));
  DF_CHECK_EQ(JsonScalar(json.output, "reason"), std::string("drain_outstanding"));
  DF_CHECK_EQ(JsonScalar(json.output, "code"), std::string("unmet_obligation"));
  const std::string required_action = JsonScalar(json.output, "required_action");
  DF_CHECK(!required_action.empty());
  DF_CHECK(Contains(required_action, "drain"));
}

DF_TEST(happy_path_reaches_phase_decommissioned) {
  TempStore store;
  const fs::path directory = store.path();

  RequireOk(RunInStore(directory, {"asset", "register", "--asset", "1", "--site", "2", "--rack",
                                   "3", "--hardware-generation", "1", "--firmware-generation", "1",
                                   "--authority-mask", "0", "--model", "edge-node", "--serial",
                                   "sn-42"}),
            "asset register");

  const CliResult created =
      RunInStore(directory, {"plan", "create", "--asset", "1", "--attempt", "1"});
  RequireOk(created, "plan create");
  RequireContains(created, "applied: true", "plan create");
  std::string fence = FenceOf(created, "plan create");

  int attempt = 2;
  std::size_t mutations = 0;
  // Every mutating command carries the current fence, and every accepted mutation
  // moves the fence on: a token that did not change would be a lost compare-and-swap.
  const auto mutate = [&](std::string_view label, std::vector<std::string> arguments,
                          std::string_view expected_phase) {
    const CliResult result = RunFenced(directory, std::move(arguments), fence, attempt);
    ++attempt;
    RequireOk(result, label);
    RequireContains(result, "applied: true", label);
    const std::string next = FenceOf(result, label);
    DF_CHECK_NE(next, fence);
    fence = next;
    ++mutations;
    // The durable record, read back by a separate process, agrees: the phase
    // moved exactly one step and the live fence is the token just printed.
    const CliResult view = RunInStore(directory, {"plan", "show", "--asset", "1", "--json"});
    RequireOk(view, "plan show after a mutation");
    DF_CHECK_EQ(JsonScalar(view.output, "phase"), std::string(expected_phase));
    DF_CHECK_EQ(JsonScalar(view.output, "fence_token"), fence);
    return result;
  };

  const CliResult assessed =
      mutate("dependencies assess",
             {"dependencies", "assess", "--authority", "facility-ops", "--reference", "dep-1",
              "--require", "asi_workload", "--require", "dfi_route"},
             "dependency_assessment");

  const std::vector<ObligationRef> obligations = ObligationsOf(assessed.output);
  DF_CHECK_EQ(obligations.size(), std::size_t{2});
  for (const ObligationRef& obligation : obligations) {
    mutate(std::string("drain satisfy ") + obligation.kind,
           {"drain", "satisfy", "--obligation", obligation.id, "--kind", obligation.kind,
            "--observer", "drain-authority", "--reference", std::string("drain-") + obligation.kind},
           "dependency_assessment");
  }

  mutate("drain begin", {"drain", "begin"}, "draining");
  mutate("drain conclude", {"drain", "conclude"}, "authority_revocation");

  std::vector<std::string> revoke = {"authority", "revoke", "--authority", "facility-authority",
                                     "--reference", "rev-1"};
  for (const std::string_view domain : kAuthorityDomains) {
    revoke.push_back("--domain");
    revoke.push_back(std::string(domain));
  }
  mutate("authority revoke", std::move(revoke), "authority_revocation");
  mutate("authority conclude", {"authority", "conclude"}, "residual_handling");

  for (const std::string_view category : kResidualCategories) {
    mutate(std::string("residual set ") + std::string(category),
           {"residual", "set", "--category", std::string(category), "--disposition", "handled",
            "--authority", "residual-authority", "--reference",
            std::string("res-") + std::string(category)},
           "residual_handling");
  }

  mutate("isolation declare",
         {"isolation", "declare", "--observer", "isolation-observer", "--reference", "iso-1"},
         "isolation_ready");
  mutate("removal authorize",
         {"removal", "authorize", "--authority", "removal-authority", "--reference", "ra-1"},
         "removal_authorized");
  mutate("removal observe",
         {"removal", "observe", "--observer", "removal-observer", "--reference", "ro-1"},
         "removed_observed");
  mutate("plan finalize", {"plan", "finalize"}, "decommissioned");

  const CliResult human = RunInStore(directory, {"plan", "show", "--asset", "1"});
  RequireOk(human, "plan show");
  RequireContains(human, "phase: decommissioned", "plan show");
  RequireContains(human, "canonical_deletion: false", "plan show");
  RequireContains(human, "removal_observed", "plan show");

  const CliResult json = RunInStore(directory, {"plan", "show", "--asset", "1", "--json"});
  RequireOk(json, "plan show --json");
  DF_CHECK_EQ(JsonScalar(json.output, "phase"), std::string("decommissioned"));
  DF_CHECK_EQ(JsonScalar(json.output, "canonical_deletion"), std::string("false"));
  DF_CHECK_EQ(JsonScalar(json.output, "removal_observed"), std::string("true"));
  DF_CHECK_EQ(JsonScalar(json.output, "isolation_observed"), std::string("true"));
  DF_CHECK_EQ(JsonScalar(json.output, "removal_authorized"), std::string("true"));
  DF_CHECK_EQ(JsonScalar(json.output, "active_obligation_count"), std::string("0"));
  DF_CHECK_EQ(CountOccurrences(json.output, "\"obligation\""), std::size_t{2});
  DF_CHECK_EQ(CountOccurrences(json.output, "\"receipt\""), std::size_t{10});
  DF_CHECK_EQ(CountOccurrences(json.output, "\"residual\""), std::size_t{1});

  // One durable generation per accepted mutation, plus registration and plan
  // creation. The count is read back through a separate process.
  const CliResult status = RunInStore(directory, {"store", "status", "--json"});
  RequireOk(status, "store status --json");
  DF_CHECK_EQ(JsonScalar(status.output, "sequence"), std::to_string(mutations + 2U));
  DF_CHECK_EQ(JsonScalar(status.output, "fresh"), std::string("false"));
}

DF_TEST(a_second_process_is_excluded_while_the_store_is_held_open) {
  TempStore store;
  RegisterAsset(store.path(), "1");

  StoreOptions options;
  options.create_if_missing = true;
  StoreState state;
  {
    auto opened = DurableStore::Open(PathToUtf8(store.path()), options, state);
    if (!opened.ok()) {
      Fail("in-process DurableStore::Open failed: " + opened.error().to_string());
    }
    DF_CHECK(opened.value().holds_lock());

    const CliResult refused = RunInStore(store.path(), {"store", "status"});
    RequireExit(refused, 1, "store status while the store is held by this process");
    RequireContains(refused, "store_locked", "store status while the store is held");
    RequireContains(refused, "infrastructure", "store status while the store is held");

    const CliResult mutation = RunInStore(store.path(), {"asset", "show", "--asset", "1"});
    RequireExit(mutation, 1, "asset show while the store is held by this process");
    RequireContains(mutation, "store_locked", "asset show while the store is held");
  }

  // Releasing the handle releases the single-writer lock for the next process.
  const CliResult accepted = RunInStore(store.path(), {"store", "status", "--json"});
  RequireOk(accepted, "store status after the lock was released");
  DF_CHECK_EQ(JsonScalar(accepted.output, "sequence"), std::string("1"));
}

DF_TEST(store_status_json_reports_a_numeric_sequence) {
  TempStore store;

  const CliResult fresh = RunInStore(store.path(), {"store", "status", "--json"});
  RequireOk(fresh, "store status --json on a fresh store");
  DF_CHECK_EQ(JsonScalar(fresh.output, "sequence"), std::string("0"));
  DF_CHECK_EQ(JsonScalar(fresh.output, "fresh"), std::string("true"));

  RegisterAsset(store.path(), "1");
  const CliResult after_register =
      RunInStore(store.path(), {"store", "status", "--json"});
  RequireOk(after_register, "store status --json after registration");
  const std::string first = JsonScalar(after_register.output, "sequence");
  DF_CHECK(IsAllDigits(first));
  DF_CHECK_EQ(first, std::string("1"));

  RequireOk(RunInStore(store.path(), {"plan", "create", "--asset", "1", "--attempt", "1"}),
            "plan create");
  const CliResult after_plan = RunInStore(store.path(), {"store", "status", "--json"});
  RequireOk(after_plan, "store status --json after plan creation");
  DF_CHECK(IsAllDigits(JsonScalar(after_plan.output, "sequence")));
  DF_CHECK_EQ(JsonScalar(after_plan.output, "sequence"), std::string("2"));
  DF_CHECK_EQ(JsonScalar(after_plan.output, "recovered_sequence"), std::string("2"));
  DF_CHECK_EQ(JsonScalar(after_plan.output, "fresh"), std::string("false"));
  DF_CHECK_EQ(JsonScalar(after_plan.output, "unrecoverable"), std::string("false"));
}

DF_TEST_MAIN()

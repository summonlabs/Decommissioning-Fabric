// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Command line front end. Private to the build; not installed as a header.

#ifndef DECOMMISSIONING_FABRIC_CLI_HPP
#define DECOMMISSIONING_FABRIC_CLI_HPP

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "decommissioning_fabric/engine.hpp"
#include "decommissioning_fabric/errors.hpp"

namespace decommissioning_fabric::cli {

/// Exit codes. 0 is success, 2 means the command line itself was wrong, and 1
/// means the engine refused the request. The distinction matters: a refusal is
/// a governed answer, a usage error is not.
inline constexpr int kExitOk = 0;
inline constexpr int kExitRefused = 1;
inline constexpr int kExitUsage = 2;

struct Args {
  /// Positional words, in order: the command path followed by its arguments.
  std::vector<std::string> words;

  /// Option name (without the leading --) to its values.
  std::map<std::string, std::vector<std::string>> options;

  [[nodiscard]] bool has(std::string_view name) const;
  [[nodiscard]] std::string one(std::string_view name,
                               std::string_view fallback = std::string_view()) const;
  [[nodiscard]] std::vector<std::string> many(std::string_view name) const;
  [[nodiscard]] Result<std::uint64_t> number(std::string_view name) const;
  [[nodiscard]] Result<std::uint64_t> number_or(std::string_view name, std::uint64_t fallback) const;
  [[nodiscard]] Result<std::uint32_t> number32_or(std::string_view name,
                                                  std::uint32_t fallback) const;
  [[nodiscard]] std::string word(std::size_t index) const;
  [[nodiscard]] std::size_t word_count() const { return words.size(); }
};

[[nodiscard]] Result<Args> ParseArgs(const std::vector<std::string>& argv);

/// Parses a hexadecimal identity. Rejects empty input, odd length, non-hex
/// characters, and anything wider than 64 bits.
[[nodiscard]] Result<std::uint64_t> ParseHexU64(std::string_view text, std::string_view field);

/// Tiny JSON writer with correct comma and nesting handling.
class JsonWriter {
 public:
  explicit JsonWriter(std::string& sink);

  void BeginObject();
  void EndObject();
  void BeginArray(std::string_view key);
  void EndArray();
  void Key(std::string_view key);
  void Value(std::string_view value);
  void Value(std::uint64_t value);
  void Value(std::uint32_t value);
  void Value(std::int64_t value);
  void Value(bool value);
  /// Emits a key followed by a string value, the common case.
  void Field(std::string_view key, std::string_view value);
  void Field(std::string_view key, std::uint64_t value);
  void Field(std::string_view key, std::uint32_t value);
  void Field(std::string_view key, bool value);
  void Field(std::string_view key, std::int64_t value);

 private:
  void Separator();
  void NewlineIndent();

  std::string* sink_;
  int depth_{0};
  bool need_comma_{false};
  bool after_key_{false};
};

// --- rendering -------------------------------------------------------------

[[nodiscard]] std::string RenderDecision(const Decision& decision, bool json);
[[nodiscard]] std::string RenderError(const Error& error, bool json);
[[nodiscard]] std::string RenderAsset(const AssetView& view, bool json);
[[nodiscard]] std::string RenderCase(const CaseView& view, bool json);
[[nodiscard]] std::string RenderBlockers(const BlockerReport& report, bool json);
[[nodiscard]] std::string RenderRecovery(const std::string& directory, const RecoveryReport& report,
                                         CommitSequence sequence, bool json);
[[nodiscard]] std::string RenderAuthority(const AuthorityReport& report, bool json);
[[nodiscard]] std::string RenderGenerations(const FacilityGenerations& generations, bool json);

// --- dispatch --------------------------------------------------------------

/// Runs one command. Returns a process exit code.
int Run(const std::vector<std::string>& argv);

/// Prints the command index.
void PrintUsage(std::string& out);

}  // namespace decommissioning_fabric::cli

#endif  // DECOMMISSIONING_FABRIC_CLI_HPP

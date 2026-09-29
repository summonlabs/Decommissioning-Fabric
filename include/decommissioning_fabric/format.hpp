// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Bounded, versioned, integrity checked payload codec.
//
// The payload is line oriented ASCII so the durable format does not depend on
// host endianness and can be inspected with a text tool. Every identity is
// stored as an explicit integer; every string is hex encoded so quoting,
// escaping, and invalid Unicode can never produce an ambiguous record.
//
// Decoding is strict. Wrong version, unknown tag, wrong token count, trailing
// tokens, out-of-range enumerators, duplicate identities, impossible field
// combinations, oversized strings, invalid UTF-8, and non-ASCII bytes are all
// rejected with a specific error rather than repaired.

#ifndef DECOMMISSIONING_FABRIC_FORMAT_HPP
#define DECOMMISSIONING_FABRIC_FORMAT_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "decommissioning_fabric/errors.hpp"
#include "decommissioning_fabric/hash.hpp"
#include "decommissioning_fabric/store.hpp"

namespace decommissioning_fabric {

/// Payload grammar version, carried on the first line of every payload.
inline constexpr std::uint32_t kPayloadVersion = 1;
inline constexpr std::string_view kPayloadHeaderTag = "DFAB";

/// Bounds enforced on decode and on request construction. A value outside these
/// limits is reported, never clamped.
inline constexpr std::size_t kMaxStringBytes = 4096;
inline constexpr std::size_t kMaxFleetAssets = 4096;
inline constexpr std::size_t kMaxCases = 4096;
inline constexpr std::size_t kMaxObligationsPerCase = 1024;
inline constexpr std::size_t kMaxResidualPerCase = 1024;
inline constexpr std::size_t kMaxExceptionsPerCase = 1024;
inline constexpr std::size_t kMaxEvidencePerCase = 8192;
inline constexpr std::size_t kMaxReceiptsPerCase = 4096;
inline constexpr std::size_t kMaxRegistryPerCase = 8192;
inline constexpr std::size_t kMaxNotesPerCase = 256;
inline constexpr std::size_t kMaxObservedDetails = 64;
inline constexpr std::size_t kMaxTokenLength = 8192;

/// Line oriented payload writer. Deterministic: fields appear in the order the
/// caller emits them, and every encoder in this repository emits a fixed order.
class PayloadWriter {
 public:
  explicit PayloadWriter(std::string& sink) noexcept;

  void Tok(std::string_view token);
  void Num(std::uint64_t value);
  void Num32(std::uint32_t value);
  void Signed(std::int64_t value);
  void Flag(bool value);
  /// Hex encodes; an empty string is written as a single '-'.
  void Str(std::string_view value);
  /// Exactly 64 lowercase hexadecimal characters.
  void DigestField(const Digest& digest);
  void EndLine();

  [[nodiscard]] std::size_t lines() const noexcept { return lines_; }

 private:
  std::string* sink_;
  bool line_open_{false};
  std::size_t lines_{0};
};

/// Strict line oriented payload reader. Rejects anything it does not fully
/// understand, including bytes outside printable ASCII.
class PayloadReader {
 public:
  explicit PayloadReader(std::string_view payload);

  /// Advances to the next line. Returns false in the value when the payload is
  /// exhausted. Fails with malformed_payload on a non-ASCII byte, an empty
  /// line, a line without a terminator, or a line that is too long.
  [[nodiscard]] Result<bool> NextLine();

  [[nodiscard]] Result<std::string_view> Tag();
  [[nodiscard]] Result<std::uint64_t> Num();
  [[nodiscard]] Result<std::uint32_t> Num32();
  [[nodiscard]] Result<std::int64_t> Signed();
  [[nodiscard]] Result<bool> Flag();
  [[nodiscard]] Result<std::string> Str();
  [[nodiscard]] Result<Digest> DigestField();

  /// Requires that the current line has no unconsumed tokens.
  [[nodiscard]] Status EndOfLine();
  [[nodiscard]] Status RequireEof();

  [[nodiscard]] std::size_t line_number() const noexcept { return line_index_ + 1U; }
  [[nodiscard]] std::string_view current_tag() const noexcept { return tag_; }

 private:
  [[nodiscard]] Result<std::string_view> NextToken();

  std::string_view payload_;
  std::size_t cursor_{0};
  std::size_t line_index_{0};
  std::string_view tag_;
  std::string_view body_;
  std::size_t body_offset_{0};
};

/// Serialises one generation of state. Deterministic: the same state always
/// produces the same bytes, and map iteration follows key order.
[[nodiscard]] std::string EncodeState(const StoreState& state);

/// Strict inverse of EncodeState.
[[nodiscard]] Result<StoreState> DecodeState(std::string_view payload);

// ---------------------------------------------------------------------------
// Record framing
// ---------------------------------------------------------------------------

/// Builds a framed record: 56 byte header followed by the payload.
[[nodiscard]] std::string BuildRecord(std::string_view payload, CommitSequence sequence);

/// Result of parsing a framed record.
struct ParsedRecord {
  CommitSequence sequence;
  std::string payload;
  Digest payload_digest;
  std::uint64_t payload_size{0};
};

/// Fully validates a framed record.
///
/// \p expected_size, when set, must equal the exact byte length of the record:
/// a record followed by trailing bytes is rejected rather than truncated.
[[nodiscard]] Result<ParsedRecord> ParseRecord(std::string_view record,
                                               std::optional<std::uint64_t> expected_size);

/// Convenience for the store: on failure, fills \p report with the reason.
[[nodiscard]] bool TryParseRecord(std::string_view record, ParsedRecord& out,
                                  SlotReport& report);

}  // namespace decommissioning_fabric

#endif  // DECOMMISSIONING_FABRIC_FORMAT_HPP

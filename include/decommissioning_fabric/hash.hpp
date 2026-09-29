// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Hashing, hexadecimal encoding, and UTF-8 validation primitives.
//
// Every digest in this repository is produced by exactly one implementation so
// that a persisted record's integrity check cannot drift between the writer and
// the reader. Nothing here allocates on the hot path beyond the returned string.

#ifndef DECOMMISSIONING_FABRIC_HASH_HPP
#define DECOMMISSIONING_FABRIC_HASH_HPP

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace decommissioning_fabric {

namespace detail {

/// Lowercase hexadecimal rendering of \p value, zero padded to exactly
/// \p digits characters. Digits beyond 16 contribute leading zeros.
[[nodiscard]] std::string to_hex_fixed(std::uint64_t value, std::size_t digits);

}  // namespace detail

inline constexpr std::size_t kSha256DigestBytes = 32;

/// A SHA-256 digest. Default constructed digests are all zero; a zero digest is
/// never a valid integrity check for a non-empty payload, and callers that
/// require a set digest must say so rather than treating zero as acceptable.
struct Digest {
  std::array<std::uint8_t, kSha256DigestBytes> bytes{};

  [[nodiscard]] bool is_zero() const noexcept {
    for (const std::uint8_t b : bytes) {
      if (b != 0U) {
        return false;
      }
    }
    return true;
  }

  /// Lowercase hexadecimal, 64 characters.
  [[nodiscard]] std::string to_hex() const;

  /// First eight digest bytes interpreted little-endian. Used for the compact
  /// on-disk digest fields, which are fixed-width regardless of host byte order.
  [[nodiscard]] std::uint64_t low64() const noexcept;

  /// Parses exactly 64 hexadecimal characters. Returns nullopt for any other
  /// length or for a non-hexadecimal character; never throws and never pads.
  [[nodiscard]] static std::optional<Digest> FromHex(std::string_view hex);

  friend bool operator==(const Digest& lhs, const Digest& rhs) noexcept {
    return lhs.bytes == rhs.bytes;
  }
  friend bool operator!=(const Digest& lhs, const Digest& rhs) noexcept {
    return !(lhs == rhs);
  }
  friend bool operator<(const Digest& lhs, const Digest& rhs) noexcept {
    return lhs.bytes < rhs.bytes;
  }
};

/// Streaming SHA-256 (FIPS 180-4). Deterministic and locale independent.
class Sha256 {
 public:
  Sha256() noexcept;

  Sha256(const Sha256&) = delete;
  Sha256& operator=(const Sha256&) = delete;

  void Update(const void* data, std::size_t size) noexcept;
  void Update(std::string_view text) noexcept;

  /// Completes the digest. The object must not be updated afterwards.
  [[nodiscard]] Digest Final() noexcept;

  [[nodiscard]] static Digest Of(std::string_view text) noexcept;

 private:
  void Compress(const std::uint8_t* block) noexcept;

  std::array<std::uint32_t, 8> state_{};
  std::array<std::uint8_t, 64> buffer_{};
  std::uint64_t total_bytes_{0};
  std::size_t buffer_size_{0};
};

/// Lowercase hexadecimal encoding of raw bytes. Always even length.
[[nodiscard]] std::string HexEncode(std::string_view raw);

/// Decodes an even-length lowercase or uppercase hexadecimal string. Returns
/// nullopt for odd length, for any non-hexadecimal character, and for input
/// whose decoded size would exceed \p max_bytes.
[[nodiscard]] std::optional<std::string> HexDecode(std::string_view hex,
                                                   std::size_t max_bytes);

/// Strict UTF-8 well-formedness check: rejects overlong encodings, surrogates,
/// code points above U+10FFFF, and truncated sequences.
[[nodiscard]] bool IsValidUtf8(std::string_view text) noexcept;

/// 64-bit FNV-1a. Used for non-cryptographic stable ordering and for the
/// deterministic shuffle seeds in property tests.
[[nodiscard]] std::uint64_t Fnv1a64(std::string_view text) noexcept;

/// Deterministic 64-bit SplitMix64 step, used to derive reproducible pseudo
/// random streams from an explicit seed.
[[nodiscard]] constexpr std::uint64_t SplitMix64Next(std::uint64_t& state) noexcept {
  state += 0x9E3779B97F4A7C15ULL;
  std::uint64_t z = state;
  z = (z ^ (z >> 30U)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27U)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31U);
}

}  // namespace decommissioning_fabric

#endif  // DECOMMISSIONING_FABRIC_HASH_HPP

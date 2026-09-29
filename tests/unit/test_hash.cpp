// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Proof obligations for include/decommissioning_fabric/hash.hpp.
//
// The claims under test: SHA-256 matches the published NIST vectors; streaming
// a payload in arbitrary pieces is byte-identical to hashing it in one shot;
// the hex codec round trips and rejects malformed input rather than guessing;
// UTF-8 validation rejects every non-shortest form, surrogate, truncated
// sequence and out-of-range code point; and the non-cryptographic primitives
// are deterministic.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>

#include "decommissioning_fabric/hash.hpp"
#include "harness.hpp"

namespace {

using decommissioning_fabric::Digest;
using decommissioning_fabric::Fnv1a64;
using decommissioning_fabric::HexDecode;
using decommissioning_fabric::HexEncode;
using decommissioning_fabric::IsValidUtf8;
using decommissioning_fabric::kSha256DigestBytes;
using decommissioning_fabric::Sha256;
using decommissioning_fabric::SplitMix64Next;

// FIPS 180-4 / NIST published example digests.
constexpr std::string_view kEmptyDigest =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
constexpr std::string_view kAbcDigest =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
constexpr std::string_view k448BitDigest =
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
constexpr std::string_view kMillionADigest =
    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

/// The 448-bit NIST message: 56 bytes, which forces a second compression block
/// during padding.
constexpr std::string_view k448BitMessage =
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

/// Builds a byte string from explicit byte values, so that malformed sequences
/// are written down as the exact bytes they are.
[[nodiscard]] std::string Bytes(std::initializer_list<unsigned int> values) {
  std::string out;
  out.reserve(values.size());
  for (const unsigned int value : values) {
    out.push_back(static_cast<char>(static_cast<unsigned char>(value & 0xFFU)));
  }
  return out;
}

[[nodiscard]] std::string Uppercase(std::string text) {
  for (char& ch : text) {
    if (ch >= 'a' && ch <= 'f') {
      ch = static_cast<char>(ch - 'a' + 'A');
    }
  }
  return text;
}

/// The digest of a payload must not depend on how the bytes were fed in.
void CheckStreamedEqualsOneShot(std::string_view payload, std::size_t chunk) {
  Sha256 hasher;
  std::size_t offset = 0;
  while (offset < payload.size()) {
    const std::size_t take = std::min(chunk, payload.size() - offset);
    hasher.Update(payload.data() + offset, take);
    offset += take;
  }
  DF_CHECK_EQ(hasher.Final().to_hex(), Sha256::Of(payload).to_hex());
}

}  // namespace

DF_TEST(Hash_Sha256MatchesPublishedNistVectors) {
  const std::string empty_hex = Sha256::Of("").to_hex();
  DF_CHECK_EQ(empty_hex.size(), std::size_t{64});
  DF_CHECK_EQ(empty_hex, std::string(kEmptyDigest));

  const std::string abc_hex = Sha256::Of("abc").to_hex();
  DF_CHECK_EQ(abc_hex.size(), std::size_t{64});
  DF_CHECK_EQ(abc_hex, std::string(kAbcDigest));

  const std::string long_hex = Sha256::Of(k448BitMessage).to_hex();
  DF_CHECK_EQ(long_hex.size(), std::size_t{64});
  DF_CHECK_EQ(long_hex, std::string(k448BitDigest));

  DF_CHECK_NE(empty_hex, abc_hex);
  DF_CHECK_NE(abc_hex, long_hex);
  DF_CHECK_EQ(Sha256::Of("abc").to_hex(), abc_hex);
}

DF_TEST(Hash_Sha256OfOneMillionAsMatchesThePublishedVector) {
  const std::string payload(1000000, 'a');
  DF_CHECK_EQ(Sha256::Of(payload).to_hex(), std::string(kMillionADigest));
  CheckStreamedEqualsOneShot(payload, 4096U);
  CheckStreamedEqualsOneShot(payload, 64U);
}

DF_TEST(Hash_Sha256StreamingInSmallPiecesEqualsOneShot) {
  // Byte at a time, including the empty prefix and a payload that crosses the
  // 55/56 byte padding boundary and the 64 byte block boundary.
  CheckStreamedEqualsOneShot("", 1U);
  CheckStreamedEqualsOneShot("a", 1U);
  CheckStreamedEqualsOneShot("abc", 1U);
  CheckStreamedEqualsOneShot(k448BitMessage, 1U);
  CheckStreamedEqualsOneShot(std::string(55U, 'x'), 1U);
  CheckStreamedEqualsOneShot(std::string(56U, 'x'), 1U);
  CheckStreamedEqualsOneShot(std::string(63U, 'x'), 1U);
  CheckStreamedEqualsOneShot(std::string(64U, 'x'), 1U);
  CheckStreamedEqualsOneShot(std::string(65U, 'x'), 1U);
  CheckStreamedEqualsOneShot(std::string(1000U, 'q'), 7U);
  CheckStreamedEqualsOneShot(std::string(1000U, 'q'), 63U);
  CheckStreamedEqualsOneShot(std::string(1000U, 'q'), 64U);
  CheckStreamedEqualsOneShot(std::string(1000U, 'q'), 65U);

  // Zero length updates between real ones are no-ops.
  Sha256 hasher;
  hasher.Update(std::string_view());
  hasher.Update("abc", 3U);
  hasher.Update(std::string_view());
  DF_CHECK_EQ(hasher.Final().to_hex(), std::string(kAbcDigest));

  // The pointer/size overload and the string_view overload agree, and the
  // prefix of a buffer is hashed, not the whole buffer.
  const std::string buffer = "abcXXX";
  Sha256 sliced;
  sliced.Update(buffer.data(), 3U);
  DF_CHECK_EQ(sliced.Final().to_hex(), std::string(kAbcDigest));
}

DF_TEST(Hash_DigestHexRoundTripsAndRejectsMalformedText) {
  const Digest digest = Sha256::Of("abc");
  const std::string hex = digest.to_hex();
  DF_CHECK_EQ(hex, std::string(kAbcDigest));

  const auto parsed = Digest::FromHex(hex);
  DF_CHECK(parsed.has_value());
  if (parsed.has_value()) {
    DF_CHECK(*parsed == digest);
    DF_CHECK_EQ(parsed->to_hex(), hex);
    DF_CHECK_EQ(parsed->low64(), digest.low64());
  }

  const auto parsed_upper = Digest::FromHex(Uppercase(hex));
  DF_CHECK(parsed_upper.has_value());
  if (parsed_upper.has_value()) {
    DF_CHECK(*parsed_upper == digest);
  }

  const auto parsed_empty = Digest::FromHex(kEmptyDigest);
  DF_CHECK(parsed_empty.has_value());
  if (parsed_empty.has_value()) {
    DF_CHECK(*parsed_empty == Sha256::Of(""));
    DF_CHECK(!parsed_empty->is_zero());
    // low64() reads the first eight digest bytes little-endian:
    // e3 b0 c4 42 98 fc 1c 14 -> 0x141cfc9842c4b0e3
    DF_CHECK_EQ(parsed_empty->low64(), 0x141CFC9842C4B0E3ULL);
  }

  // Wrong length, in both directions, is rejected rather than padded or cut.
  DF_CHECK(!Digest::FromHex("").has_value());
  DF_CHECK(!Digest::FromHex("abc").has_value());
  DF_CHECK(!Digest::FromHex(hex.substr(0, 63)).has_value());
  DF_CHECK(!Digest::FromHex(hex + "0").has_value());
  DF_CHECK(!Digest::FromHex(hex.substr(1)).has_value());

  // A single non-hexadecimal character anywhere in the 64 characters is fatal.
  std::string substituted = hex;
  substituted[0] = 'z';
  DF_CHECK(!Digest::FromHex(substituted).has_value());
  substituted = hex;
  substituted[31] = 'g';
  DF_CHECK(!Digest::FromHex(substituted).has_value());
  substituted = hex;
  substituted[63] = ' ';
  DF_CHECK(!Digest::FromHex(substituted).has_value());
  DF_CHECK(!Digest::FromHex(std::string(64U, ' ')).has_value());
  DF_CHECK(!Digest::FromHex(std::string(64U, '0') + "-").has_value());
}

DF_TEST(Hash_DigestZeroStateIsDistinguishableFromARealDigest) {
  const Digest unset;
  DF_CHECK(unset.is_zero());
  DF_CHECK_EQ(unset.to_hex(), std::string(64U, '0'));
  DF_CHECK_EQ(unset.low64(), std::uint64_t{0});

  DF_CHECK(!Sha256::Of("").is_zero());
  DF_CHECK(!Sha256::Of("abc").is_zero());
  DF_CHECK(Sha256::Of("abc") != unset);
  DF_CHECK_EQ(Sha256::Of("").bytes.size(), kSha256DigestBytes);

  // A digest compares and orders by its bytes, so it can key an ordered map.
  DF_CHECK(Sha256::Of("abc") < Sha256::Of("abd") || Sha256::Of("abd") < Sha256::Of("abc"));
  DF_CHECK(!(Sha256::Of("abc") < Sha256::Of("abc")));
}

DF_TEST(Hash_HexEncodeDecodeRoundTripsAndRejectsMalformedInput) {
  const std::string raw = Bytes({0x00, 0x01, 0x7F, 0x80, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF});
  const std::string hex = HexEncode(raw);
  DF_CHECK_EQ(hex.size(), std::size_t{18});
  DF_CHECK_EQ(hex, std::string("00017f80ffdeadbeef"));

  const auto decoded = HexDecode(hex, 64U);
  DF_CHECK(decoded.has_value());
  if (decoded.has_value()) {
    DF_CHECK_EQ(*decoded, raw);
    DF_CHECK_EQ(HexEncode(*decoded), hex);
  }

  const auto decoded_upper = HexDecode(Uppercase(hex), 64U);
  DF_CHECK(decoded_upper.has_value());
  if (decoded_upper.has_value()) {
    DF_CHECK_EQ(*decoded_upper, raw);
  }

  DF_CHECK(HexEncode("").empty());
  DF_CHECK_EQ(HexEncode("A"), std::string("41"));
  DF_CHECK_EQ(HexEncode(Bytes({0xFF})), std::string("ff"));
  const auto decoded_empty = HexDecode("", 0U);
  DF_CHECK(decoded_empty.has_value());
  if (decoded_empty.has_value()) {
    DF_CHECK(decoded_empty->empty());
  }

  // Odd length is never a valid byte string.
  DF_CHECK(!HexDecode("a", 1U).has_value());
  DF_CHECK(!HexDecode("abc", 8U).has_value());
  DF_CHECK(!HexDecode(hex + "0", 64U).has_value());

  // Non-hexadecimal characters, including whitespace and a sign.
  DF_CHECK(!HexDecode("zz", 8U).has_value());
  DF_CHECK(!HexDecode("0g", 8U).has_value());
  DF_CHECK(!HexDecode("  ", 8U).has_value());
  DF_CHECK(!HexDecode("+1", 8U).has_value());
  DF_CHECK(!HexDecode("0x", 8U).has_value());

  // The decoded size, not the text length, is bounded by max_bytes.
  DF_CHECK(!HexDecode("deadbeef", 3U).has_value());
  DF_CHECK(HexDecode("deadbeef", 4U).has_value());
  DF_CHECK(!HexDecode("00", 0U).has_value());
  DF_CHECK(HexDecode("", 0U).has_value());
  DF_CHECK(HexDecode("00", 1U).has_value());
}

DF_TEST(Hash_IsValidUtf8AcceptsWellFormedSequences) {
  DF_CHECK(IsValidUtf8(""));
  DF_CHECK(IsValidUtf8("plain ascii"));
  DF_CHECK(IsValidUtf8("tab\tnewline\nend"));
  DF_CHECK(IsValidUtf8(Bytes({0x00, 0x7F})));  // NUL and DEL are single valid bytes
  DF_CHECK(IsValidUtf8(Bytes({0xC2, 0x80})));  // U+0080, shortest 2-byte form
  DF_CHECK(IsValidUtf8(Bytes({0xC3, 0xA9})));  // U+00E9
  DF_CHECK(IsValidUtf8(Bytes({0xDF, 0xBF})));  // U+07FF, longest 2-byte form
  DF_CHECK(IsValidUtf8(Bytes({0xE0, 0xA0, 0x80})));  // U+0800, shortest 3-byte form
  DF_CHECK(IsValidUtf8(Bytes({0xE2, 0x82, 0xAC})));  // U+20AC euro sign
  DF_CHECK(IsValidUtf8(Bytes({0xEF, 0xBF, 0xBF})));  // U+FFFF, last 3-byte code point
  DF_CHECK(IsValidUtf8(Bytes({0xF0, 0x90, 0x80, 0x80})));  // U+10000, shortest 4-byte form
  DF_CHECK(IsValidUtf8(Bytes({0xF0, 0x9F, 0x98, 0x80})));  // U+1F600
  DF_CHECK(IsValidUtf8(Bytes({0xF4, 0x8F, 0xBF, 0xBF})));  // U+10FFFF, the last code point
  DF_CHECK(IsValidUtf8(Bytes({'a', 0xC3, 0xA9, 'b', 0xF0, 0x9F, 0x98, 0x80, 'c'})));
  DF_CHECK(IsValidUtf8(Bytes({0xF0, 0x90, 0x80, 0x80, 0xF4, 0x8F, 0xBF, 0xBF})));
}

DF_TEST(Hash_IsValidUtf8RejectsOverlongSurrogateTruncatedAndOutOfRange) {
  // Non-shortest (overlong) forms encode a code point in more bytes than needed.
  DF_CHECK(!IsValidUtf8(Bytes({0xC0, 0x80})));  // overlong NUL
  DF_CHECK(!IsValidUtf8(Bytes({0xC1, 0xAF})));  // overlong '/'
  DF_CHECK(!IsValidUtf8(Bytes({0xC0, 0xAF})));
  DF_CHECK(!IsValidUtf8(Bytes({0xE0, 0x80, 0xAF})));  // overlong 3-byte '/'
  DF_CHECK(!IsValidUtf8(Bytes({0xE0, 0x9F, 0xBF})));
  DF_CHECK(!IsValidUtf8(Bytes({0xF0, 0x80, 0x80, 0xAF})));  // overlong 4-byte '/'
  DF_CHECK(!IsValidUtf8(Bytes({0xF0, 0x8F, 0xBF, 0xBF})));

  // UTF-16 surrogates are not code points and are never well-formed UTF-8.
  DF_CHECK(!IsValidUtf8(Bytes({0xED, 0xA0, 0x80})));  // U+D800
  DF_CHECK(!IsValidUtf8(Bytes({0xED, 0xAD, 0xBF})));  // U+DB7F
  DF_CHECK(!IsValidUtf8(Bytes({0xED, 0xBF, 0xBF})));  // U+DFFF

  // Truncated sequences, including one at the end of otherwise valid text.
  DF_CHECK(!IsValidUtf8(Bytes({0xC3})));
  DF_CHECK(!IsValidUtf8(Bytes({0xE2, 0x82})));
  DF_CHECK(!IsValidUtf8(Bytes({0xF0, 0x9F, 0x98})));
  DF_CHECK(!IsValidUtf8(Bytes({'o', 'k', 0xE2, 0x82})));
  DF_CHECK(!IsValidUtf8(Bytes({0xC3, 0xA9, 0xF0, 0x9F})));

  // Code points above U+10FFFF and lead bytes that can never occur.
  DF_CHECK(!IsValidUtf8(Bytes({0xF4, 0x90, 0x80, 0x80})));  // U+110000
  DF_CHECK(!IsValidUtf8(Bytes({0xF5, 0x80, 0x80, 0x80})));
  DF_CHECK(!IsValidUtf8(Bytes({0xF7, 0xBF, 0xBF, 0xBF})));
  DF_CHECK(!IsValidUtf8(Bytes({0xF8, 0x88, 0x80, 0x80, 0x80})));  // 5-byte form
  DF_CHECK(!IsValidUtf8(Bytes({0xFE})));
  DF_CHECK(!IsValidUtf8(Bytes({0xFF})));
  DF_CHECK(!IsValidUtf8(Bytes({0x80})));  // lone continuation byte
  DF_CHECK(!IsValidUtf8(Bytes({0xBF})));
  DF_CHECK(!IsValidUtf8(Bytes({0xC3, 0x28})));  // continuation expected, got '('
  DF_CHECK(!IsValidUtf8(Bytes({0xE2, 0x28, 0xA1})));
  DF_CHECK(!IsValidUtf8(Bytes({0xF0, 0x9F, 0x28, 0x80})));

  // A valid prefix followed by a malformed tail must not be accepted.
  DF_CHECK(!IsValidUtf8(Bytes({0xC3, 0xA9, 0xED, 0xA0, 0x80})));
  DF_CHECK(!IsValidUtf8(Bytes({0x41, 0x42, 0xC3})));
}

DF_TEST(Hash_Fnv1a64MatchesKnownValuesAndSeparatesDistinctInputs) {
  DF_CHECK_EQ(Fnv1a64(""), 0xCBF29CE484222325ULL);
  DF_CHECK_EQ(Fnv1a64("a"), 0xAF63DC4C8601EC8CULL);
  DF_CHECK_EQ(Fnv1a64("b"), 0xAF63DF4C8601F1A5ULL);
  DF_CHECK_EQ(Fnv1a64("abc"), 0xE71FA2190541574BULL);
  DF_CHECK_EQ(Fnv1a64("foobar"), 0x85944171F73967E8ULL);
  // Derived from the FNV-1a definition over the UTF-8 bytes of the input.
  DF_CHECK_EQ(Fnv1a64("decommissioning_fabric"), 0x31899D557BEC4757ULL);

  // Deterministic across call sites and across std::string / string_view.
  DF_CHECK_EQ(Fnv1a64("abc"), Fnv1a64(std::string("abc")));
  DF_CHECK_EQ(Fnv1a64("abc"), Fnv1a64(std::string_view("abc")));
  DF_CHECK_EQ(Fnv1a64(""), Fnv1a64(std::string()));

  // The hash is case sensitive and position sensitive.
  DF_CHECK_NE(Fnv1a64("abc"), Fnv1a64("ABC"));
  DF_CHECK_NE(Fnv1a64("abc"), Fnv1a64("acb"));
  DF_CHECK_NE(Fnv1a64("ab"), Fnv1a64("abc"));
  DF_CHECK_NE(Fnv1a64("a"), Fnv1a64("aa"));

  const std::string_view inputs[] = {"",      "a",     "b",       "aa",     "ab",
                                     "abc",   "abd",   "abcd",    "foobar", "fooba",
                                     "foobaz", "asset", "plan",   "fence",  "decommissioning_fabric"};
  const std::size_t count = sizeof(inputs) / sizeof(inputs[0]);
  for (std::size_t i = 0; i < count; ++i) {
    for (std::size_t j = i + 1; j < count; ++j) {
      DF_CHECK_MSG(Fnv1a64(inputs[i]) != Fnv1a64(inputs[j]),
                   "FNV-1a must distinguish '" + std::string(inputs[i]) + "' from '" +
                       std::string(inputs[j]) + "'");
    }
  }
}

DF_TEST(Hash_SplitMix64IsReproducibleFromAFixedSeed) {
  std::uint64_t state = 0U;
  DF_CHECK_EQ(SplitMix64Next(state), 0xE220A8397B1DCDAFULL);
  DF_CHECK_EQ(SplitMix64Next(state), 0x6E789E6AA1B965F4ULL);
  DF_CHECK_EQ(SplitMix64Next(state), 0x06C45D188009454FULL);
  DF_CHECK_EQ(SplitMix64Next(state), 0xF88BB8A8724C81ECULL);
  // Four golden-ratio increments, modulo 2^64.
  DF_CHECK_EQ(state, 0x78DDE6E5FD29F054ULL);

  // Replaying the same seed reproduces the same stream exactly.
  std::uint64_t replay = 0U;
  for (int step = 0; step < 4; ++step) {
    (void)SplitMix64Next(replay);
  }
  DF_CHECK_EQ(replay, state);

  // A different seed produces a different stream, and the values differ
  // pairwise within a stream.
  std::uint64_t other = 0x0123456789ABCDEFULL;
  DF_CHECK_EQ(SplitMix64Next(other), 0x157A3807A48FAA9DULL);
  DF_CHECK_EQ(SplitMix64Next(other), 0xD573529B34A1D093ULL);
  DF_CHECK_EQ(SplitMix64Next(other), 0x2F90B72E996DCCBEULL);
  DF_CHECK_EQ(SplitMix64Next(other), 0xA2D419334C4667ECULL);

  std::uint64_t walker = 12345U;
  std::uint64_t previous[8] = {};
  for (std::size_t i = 0; i < 8U; ++i) {
    previous[i] = SplitMix64Next(walker);
    for (std::size_t j = 0; j < i; ++j) {
      DF_CHECK_MSG(previous[i] != previous[j], "SplitMix64 repeated a value within eight steps");
    }
  }
}

DF_TEST_MAIN()

// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0

#include "decommissioning_fabric/hash.hpp"

#include <cstring>

namespace decommissioning_fabric {
namespace detail {

std::string to_hex_fixed(std::uint64_t value, std::size_t digits) {
  static constexpr char kHexDigits[] = "0123456789abcdef";
  std::string out(digits, '0');
  for (std::size_t i = 0; i < digits; ++i) {
    const std::size_t shift = (digits - 1U - i) * 4U;
    std::uint8_t nibble = 0;
    if (shift < 64U) {
      nibble = static_cast<std::uint8_t>((value >> shift) & 0xFULL);
    }
    out[i] = kHexDigits[nibble];
  }
  return out;
}

}  // namespace detail

namespace {

constexpr std::array<std::uint32_t, 64> kRoundConstants = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U,
    0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U,
    0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
    0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU,
    0x5b9cca4fU, 0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

constexpr std::array<std::uint32_t, 8> kInitialState = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};

[[nodiscard]] constexpr std::uint32_t Rotr(std::uint32_t x, unsigned n) noexcept {
  return (x >> n) | (x << (32U - n));
}

[[nodiscard]] std::uint8_t HexNibble(char c) noexcept {
  if (c >= '0' && c <= '9') {
    return static_cast<std::uint8_t>(c - '0');
  }
  if (c >= 'a' && c <= 'f') {
    return static_cast<std::uint8_t>(c - 'a' + 10);
  }
  if (c >= 'A' && c <= 'F') {
    return static_cast<std::uint8_t>(c - 'A' + 10);
  }
  return 0xFFU;
}

}  // namespace

std::string Digest::to_hex() const {
  static constexpr char kHexDigits[] = "0123456789abcdef";
  std::string out;
  out.resize(bytes.size() * 2U);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    const std::uint8_t b = bytes[i];
    out[i * 2U] = kHexDigits[static_cast<std::size_t>(b >> 4U)];
    out[(i * 2U) + 1U] = kHexDigits[static_cast<std::size_t>(b & 0x0FU)];
  }
  return out;
}

std::uint64_t Digest::low64() const noexcept {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8U; ++i) {
    value |= static_cast<std::uint64_t>(bytes[i]) << (8U * i);
  }
  return value;
}

std::optional<Digest> Digest::FromHex(std::string_view hex) {
  if (hex.size() != kSha256DigestBytes * 2U) {
    return std::nullopt;
  }
  Digest out;
  for (std::size_t i = 0; i < kSha256DigestBytes; ++i) {
    const std::uint8_t hi = HexNibble(hex[i * 2U]);
    const std::uint8_t lo = HexNibble(hex[(i * 2U) + 1U]);
    if (hi == 0xFFU || lo == 0xFFU) {
      return std::nullopt;
    }
    out.bytes[i] = static_cast<std::uint8_t>((hi << 4U) | lo);
  }
  return out;
}

Sha256::Sha256() noexcept : state_(kInitialState) {}

void Sha256::Compress(const std::uint8_t* block) noexcept {
  std::array<std::uint32_t, 64> w{};
  for (std::size_t i = 0; i < 16U; ++i) {
    w[i] = (static_cast<std::uint32_t>(block[i * 4U]) << 24U) |
           (static_cast<std::uint32_t>(block[(i * 4U) + 1U]) << 16U) |
           (static_cast<std::uint32_t>(block[(i * 4U) + 2U]) << 8U) |
           static_cast<std::uint32_t>(block[(i * 4U) + 3U]);
  }
  for (std::size_t i = 16U; i < 64U; ++i) {
    const std::uint32_t s0 = Rotr(w[i - 15U], 7U) ^ Rotr(w[i - 15U], 18U) ^ (w[i - 15U] >> 3U);
    const std::uint32_t s1 = Rotr(w[i - 2U], 17U) ^ Rotr(w[i - 2U], 19U) ^ (w[i - 2U] >> 10U);
    w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t i = 0; i < 64U; ++i) {
    const std::uint32_t s1 = Rotr(e, 6U) ^ Rotr(e, 11U) ^ Rotr(e, 25U);
    const std::uint32_t ch = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + s1 + ch + kRoundConstants[i] + w[i];
    const std::uint32_t s0 = Rotr(a, 2U) ^ Rotr(a, 13U) ^ Rotr(a, 22U);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::Update(const void* data, std::size_t size) noexcept {
  if (size == 0U) {
    return;
  }
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  total_bytes_ += static_cast<std::uint64_t>(size);

  std::size_t offset = 0;
  if (buffer_size_ != 0U) {
    const std::size_t want = 64U - buffer_size_;
    const std::size_t take = size < want ? size : want;
    std::memcpy(buffer_.data() + buffer_size_, bytes, take);
    buffer_size_ += take;
    offset += take;
    if (buffer_size_ == 64U) {
      Compress(buffer_.data());
      buffer_size_ = 0U;
    }
  }

  while (offset + 64U <= size) {
    Compress(bytes + offset);
    offset += 64U;
  }

  if (offset < size) {
    const std::size_t remaining = size - offset;
    std::memcpy(buffer_.data(), bytes + offset, remaining);
    buffer_size_ = remaining;
  }
}

void Sha256::Update(std::string_view text) noexcept {
  Update(text.data(), text.size());
}

Digest Sha256::Final() noexcept {
  const std::uint64_t bit_length = total_bytes_ * 8U;
  const std::uint8_t pad = 0x80U;

  Update(&pad, 1U);

  const std::uint8_t zero = 0x00U;
  while (buffer_size_ != 56U) {
    Update(&zero, 1U);
  }

  std::array<std::uint8_t, 8> length_bytes{};
  for (std::size_t i = 0; i < 8U; ++i) {
    length_bytes[i] = static_cast<std::uint8_t>((bit_length >> (8U * (7U - i))) & 0xFFULL);
  }
  Update(length_bytes.data(), length_bytes.size());

  Digest digest;
  for (std::size_t i = 0; i < 8U; ++i) {
    const std::uint32_t word = state_[i];
    digest.bytes[i * 4U] = static_cast<std::uint8_t>((word >> 24U) & 0xFFU);
    digest.bytes[(i * 4U) + 1U] = static_cast<std::uint8_t>((word >> 16U) & 0xFFU);
    digest.bytes[(i * 4U) + 2U] = static_cast<std::uint8_t>((word >> 8U) & 0xFFU);
    digest.bytes[(i * 4U) + 3U] = static_cast<std::uint8_t>(word & 0xFFU);
  }
  return digest;
}

Digest Sha256::Of(std::string_view text) noexcept {
  Sha256 hasher;
  hasher.Update(text);
  return hasher.Final();
}

std::string HexEncode(std::string_view raw) {
  static constexpr char kHexDigits[] = "0123456789abcdef";
  std::string out;
  out.resize(raw.size() * 2U);
  for (std::size_t i = 0; i < raw.size(); ++i) {
    const auto b = static_cast<std::uint8_t>(raw[i]);
    out[i * 2U] = kHexDigits[static_cast<std::size_t>(b >> 4U)];
    out[(i * 2U) + 1U] = kHexDigits[static_cast<std::size_t>(b & 0x0FU)];
  }
  return out;
}

std::optional<std::string> HexDecode(std::string_view hex, std::size_t max_bytes) {
  if ((hex.size() % 2U) != 0U) {
    return std::nullopt;
  }
  if ((hex.size() / 2U) > max_bytes) {
    return std::nullopt;
  }
  std::string out;
  out.resize(hex.size() / 2U);
  for (std::size_t i = 0; i < out.size(); ++i) {
    const std::uint8_t hi = HexNibble(hex[i * 2U]);
    const std::uint8_t lo = HexNibble(hex[(i * 2U) + 1U]);
    if (hi == 0xFFU || lo == 0xFFU) {
      return std::nullopt;
    }
    out[i] = static_cast<char>((hi << 4U) | lo);
  }
  return out;
}

bool IsValidUtf8(std::string_view text) noexcept {
  std::size_t i = 0;
  const std::size_t n = text.size();
  while (i < n) {
    const auto c0 = static_cast<std::uint8_t>(text[i]);
    if (c0 < 0x80U) {
      ++i;
      continue;
    }
    std::size_t extra = 0;
    std::uint32_t code_point = 0;
    std::uint32_t minimum = 0;
    if ((c0 & 0xE0U) == 0xC0U) {
      extra = 1;
      code_point = static_cast<std::uint32_t>(c0 & 0x1FU);
      minimum = 0x80U;
    } else if ((c0 & 0xF0U) == 0xE0U) {
      extra = 2;
      code_point = static_cast<std::uint32_t>(c0 & 0x0FU);
      minimum = 0x800U;
    } else if ((c0 & 0xF8U) == 0xF0U) {
      extra = 3;
      code_point = static_cast<std::uint32_t>(c0 & 0x07U);
      minimum = 0x10000U;
    } else {
      return false;
    }
    if (i + extra >= n) {
      return false;
    }
    for (std::size_t k = 1; k <= extra; ++k) {
      const auto cx = static_cast<std::uint8_t>(text[i + k]);
      if ((cx & 0xC0U) != 0x80U) {
        return false;
      }
      code_point = (code_point << 6U) | static_cast<std::uint32_t>(cx & 0x3FU);
    }
    if (code_point < minimum) {
      return false;
    }
    if (code_point > 0x10FFFFU) {
      return false;
    }
    if (code_point >= 0xD800U && code_point <= 0xDFFFU) {
      return false;
    }
    i += extra + 1U;
  }
  return true;
}

std::uint64_t Fnv1a64(std::string_view text) noexcept {
  std::uint64_t hash = 0xCBF29CE484222325ULL;
  for (const char ch : text) {
    hash ^= static_cast<std::uint64_t>(static_cast<std::uint8_t>(ch));
    hash *= 0x100000001B3ULL;
  }
  return hash;
}

}  // namespace decommissioning_fabric

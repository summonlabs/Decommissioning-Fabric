// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "cli.hpp"

namespace decommissioning_fabric::cli {
namespace {

/// Options that take no value. Everything else consumes the next token unless
/// it is written as --name=value.
constexpr std::string_view kBooleanOptions[] = {"json", "create", "absent", "present",
                                                "help", "wait-lock"};

[[nodiscard]] bool TakesValue(std::string_view name) {
  for (const std::string_view candidate : kBooleanOptions) {
    if (candidate == name) {
      return false;
    }
  }
  return true;
}

/// Escapes a string for JSON. Invalid UTF-8 bytes are escaped as \uFFFD rather
/// than emitted raw, so a malformed store cannot produce malformed JSON.
[[nodiscard]] std::string JsonEscape(std::string_view text) {
  std::string out;
  out.reserve(text.size() + 8U);
  for (std::size_t index = 0; index < text.size();) {
    const auto byte = static_cast<unsigned char>(text[index]);
    if (byte == '"' || byte == '\\') {
      out.push_back('\\');
      out.push_back(static_cast<char>(byte));
      ++index;
      continue;
    }
    if (byte == '\n') {
      out += "\\n";
      ++index;
      continue;
    }
    if (byte == '\r') {
      out += "\\r";
      ++index;
      continue;
    }
    if (byte == '\t') {
      out += "\\t";
      ++index;
      continue;
    }
    if (byte < 0x20U) {
      out += "\\u00";
      constexpr char kHex[] = "0123456789abcdef";
      out.push_back(kHex[(byte >> 4U) & 0x0FU]);
      out.push_back(kHex[byte & 0x0FU]);
      ++index;
      continue;
    }
    if (byte < 0x80U) {
      out.push_back(static_cast<char>(byte));
      ++index;
      continue;
    }
    // Multi-byte sequence: copy verbatim when well formed, otherwise substitute.
    std::size_t length = 0;
    std::uint32_t code_point = 0;
    if ((byte & 0xE0U) == 0xC0U) {
      length = 1;
      code_point = byte & 0x1FU;
    } else if ((byte & 0xF0U) == 0xE0U) {
      length = 2;
      code_point = byte & 0x0FU;
    } else if ((byte & 0xF8U) == 0xF0U) {
      length = 3;
      code_point = byte & 0x07U;
    } else {
      out += "\\uFFFD";
      ++index;
      continue;
    }
    if (index + length >= text.size()) {
      out += "\\uFFFD";
      ++index;
      continue;
    }
    bool well_formed = true;
    for (std::size_t extra = 1; extra <= length; ++extra) {
      const auto continuation = static_cast<unsigned char>(text[index + extra]);
      if ((continuation & 0xC0U) != 0x80U) {
        well_formed = false;
        break;
      }
      code_point = (code_point << 6U) | (continuation & 0x3FU);
    }
    if (!well_formed) {
      out += "\\uFFFD";
      ++index;
      continue;
    }
    if (code_point >= 0xD800U && code_point <= 0xDFFFU) {
      out += "\\uFFFD";
      index += length + 1U;
      continue;
    }
    out.append(text.substr(index, length + 1U));
    index += length + 1U;
  }
  return out;
}

}  // namespace

bool Args::has(std::string_view name) const {
  return options.find(std::string(name)) != options.end();
}

std::string Args::one(std::string_view name, std::string_view fallback) const {
  const auto found = options.find(std::string(name));
  if (found == options.end() || found->second.empty()) {
    return std::string(fallback);
  }
  return found->second.back();
}

std::vector<std::string> Args::many(std::string_view name) const {
  const auto found = options.find(std::string(name));
  if (found == options.end()) {
    return {};
  }
  return found->second;
}

Result<std::uint64_t> Args::number(std::string_view name) const {
  const auto found = options.find(std::string(name));
  if (found == options.end() || found->second.empty()) {
    return ErrorBuilder(ErrorCode::missing_field, "a required option is absent")
        .With("option", name)
        .Build();
  }
  const std::string& text = found->second.back();
  if (text.empty() || text.size() > 20U) {
    return ErrorBuilder(ErrorCode::out_of_range, "option is not a decimal integer")
        .With("option", name)
        .With("value", text)
        .Build();
  }
  std::uint64_t value = 0;
  for (const char ch : text) {
    if (ch < '0' || ch > '9') {
      return ErrorBuilder(ErrorCode::out_of_range, "option is not a decimal integer")
          .With("option", name)
          .With("value", text)
          .Build();
    }
    if (value > (0xFFFFFFFFFFFFFFFFULL - static_cast<std::uint64_t>(ch - '0')) / 10U) {
      return ErrorBuilder(ErrorCode::out_of_range, "option overflows 64 bits")
          .With("option", name)
          .Build();
    }
    value = (value * 10U) + static_cast<std::uint64_t>(ch - '0');
  }
  return value;
}

Result<std::uint64_t> Args::number_or(std::string_view name, std::uint64_t fallback) const {
  if (!has(name)) {
    return fallback;
  }
  return number(name);
}

Result<std::uint32_t> Args::number32_or(std::string_view name, std::uint32_t fallback) const {
  if (!has(name)) {
    return fallback;
  }
  DF_TRY_DECL(std::uint64_t, value, number(name));
  if (value > 0xFFFFFFFFULL) {
    return ErrorBuilder(ErrorCode::out_of_range, "option exceeds 32 bits")
        .With("option", name)
        .Build();
  }
  return static_cast<std::uint32_t>(value);
}

std::string Args::word(std::size_t index) const {
  return index < words.size() ? words[index] : std::string();
}

Result<Args> ParseArgs(const std::vector<std::string>& argv) {
  Args args;
  bool options_only = false;
  for (std::size_t index = 0; index < argv.size(); ++index) {
    const std::string& token = argv[index];
    if (!options_only && token == "--") {
      options_only = true;
      continue;
    }
    if (!options_only && token.size() > 2U && token[0] == '-' && token[1] == '-') {
      std::string name = token.substr(2);
      std::string value;
      bool has_value = false;
      const std::size_t equals = name.find('=');
      if (equals != std::string::npos) {
        value = name.substr(equals + 1U);
        name = name.substr(0, equals);
        has_value = true;
      }
      if (name.empty()) {
        return MakeError(ErrorCode::malformed_request, "empty option name");
      }
      if (!has_value && TakesValue(name)) {
        if (index + 1U >= argv.size()) {
          return ErrorBuilder(ErrorCode::missing_field, "option requires a value")
              .With("option", name)
              .Build();
        }
        value = argv[index + 1U];
        ++index;
        has_value = true;
      }
      args.options[name].push_back(has_value ? value : std::string());
      continue;
    }
    args.words.push_back(token);
  }
  return args;
}

Result<std::uint64_t> ParseHexU64(std::string_view text, std::string_view field) {
  if (text.empty() || text.size() > 16U) {
    return ErrorBuilder(ErrorCode::malformed_hex, "identity is not 1 to 16 hexadecimal characters")
        .With("field", field)
        .With("value", text)
        .Build();
  }
  std::uint64_t value = 0;
  for (const char ch : text) {
    std::uint8_t nibble = 0;
    if (ch >= '0' && ch <= '9') {
      nibble = static_cast<std::uint8_t>(ch - '0');
    } else if (ch >= 'a' && ch <= 'f') {
      nibble = static_cast<std::uint8_t>(ch - 'a' + 10);
    } else if (ch >= 'A' && ch <= 'F') {
      nibble = static_cast<std::uint8_t>(ch - 'A' + 10);
    } else {
      return ErrorBuilder(ErrorCode::malformed_hex, "identity contains a non-hexadecimal character")
          .With("field", field)
          .With("value", text)
          .Build();
    }
    value = (value << 4U) | static_cast<std::uint64_t>(nibble);
  }
  return value;
}

JsonWriter::JsonWriter(std::string& sink) : sink_(&sink) {}

void JsonWriter::Separator() {
  if (need_comma_) {
    sink_->push_back(',');
  }
  if (depth_ > 0) {
    sink_->push_back('\n');
    for (int level = 0; level < depth_; ++level) {
      sink_->append("  ");
    }
  }
  need_comma_ = false;
}

void JsonWriter::BeginObject() {
  Separator();
  sink_->push_back('{');
  ++depth_;
  need_comma_ = false;
}

void JsonWriter::EndObject() {
  --depth_;
  sink_->push_back('\n');
  for (int level = 0; level < depth_; ++level) {
    sink_->append("  ");
  }
  sink_->push_back('}');
  need_comma_ = true;
}

void JsonWriter::BeginArray(std::string_view key) {
  Key(key);
  sink_->push_back('[');
  ++depth_;
  need_comma_ = false;
}

void JsonWriter::EndArray() {
  --depth_;
  sink_->push_back('\n');
  for (int level = 0; level < depth_; ++level) {
    sink_->append("  ");
  }
  sink_->push_back(']');
  need_comma_ = true;
}

void JsonWriter::Key(std::string_view key) {
  Separator();
  sink_->push_back('"');
  sink_->append(JsonEscape(key));
  sink_->append("\": ");
  after_key_ = true;
}

void JsonWriter::Value(std::string_view value) {
  Separator();
  sink_->push_back('"');
  sink_->append(JsonEscape(value));
  sink_->push_back('"');
  after_key_ = false;
  need_comma_ = true;
}

void JsonWriter::Value(std::uint64_t value) {
  Separator();
  sink_->append(std::to_string(value));
  after_key_ = false;
  need_comma_ = true;
}

void JsonWriter::Value(std::uint32_t value) {
  Separator();
  sink_->append(std::to_string(value));
  after_key_ = false;
  need_comma_ = true;
}

void JsonWriter::Value(std::int64_t value) {
  Separator();
  sink_->append(std::to_string(value));
  after_key_ = false;
  need_comma_ = true;
}

void JsonWriter::Value(bool value) {
  Separator();
  sink_->append(value ? "true" : "false");
  after_key_ = false;
  need_comma_ = true;
}

void JsonWriter::Field(std::string_view key, std::string_view value) {
  Key(key);
  Value(value);
}

void JsonWriter::Field(std::string_view key, std::uint64_t value) {
  Key(key);
  Value(value);
}

void JsonWriter::Field(std::string_view key, std::uint32_t value) {
  Key(key);
  Value(value);
}

void JsonWriter::Field(std::string_view key, bool value) {
  Key(key);
  Value(value);
}

void JsonWriter::Field(std::string_view key, std::int64_t value) {
  Key(key);
  Value(value);
}

}  // namespace decommissioning_fabric::cli

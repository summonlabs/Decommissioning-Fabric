// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Windows implementation of the durable store.
//
// The platform is Windows by construction, not by convenience: the durability
// claims in this repository rest on LockFileEx (an OS lock released when the
// holding process dies), FlushFileBuffers, and MoveFileExW with
// MOVEFILE_WRITE_THROUGH. Shipping an untested second implementation of those
// primitives would make the claims weaker, not stronger, so there is exactly one.

#if !defined(_WIN32)
#error "Decommissioning Fabric durable state is implemented for Windows only"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "decommissioning_fabric/format.hpp"
#include "decommissioning_fabric/store.hpp"
#include "decommissioning_fabric/time.hpp"

namespace decommissioning_fabric {
namespace {

constexpr const char* kSlotNames[2] = {"state.a", "state.b"};
constexpr const char* kLockName = "lock";
constexpr const char* kTempSuffix = ".tmp";

/// Paths at or beyond this length are passed with the extended-length prefix so
/// that Windows does not silently apply MAX_PATH truncation.
constexpr std::size_t kExtendedPathThreshold = 240;

[[nodiscard]] std::string Win32ErrorText(DWORD code) {
  LPWSTR buffer = nullptr;
  const DWORD written = ::FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
  std::string text;
  if (written != 0 && buffer != nullptr) {
    std::wstring wide(buffer, written);
    while (!wide.empty() && (wide.back() == L'\r' || wide.back() == L'\n' || wide.back() == L' ')) {
      wide.pop_back();
    }
    const int needed = ::WideCharToMultiByte(CP_UTF8, 0, wide.data(),
                                             static_cast<int>(wide.size()), nullptr, 0,
                                             nullptr, nullptr);
    if (needed > 0) {
      text.resize(static_cast<std::size_t>(needed));
      ::WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                            text.data(), needed, nullptr, nullptr);
    }
  }
  if (buffer != nullptr) {
    ::LocalFree(buffer);
  }
  if (text.empty()) {
    text = "windows error " + std::to_string(code);
  }
  return text;
}

[[nodiscard]] bool Utf8ToWide(std::string_view text, std::wstring& out) {
  if (text.empty()) {
    return false;
  }
  const int needed = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                           static_cast<int>(text.size()), nullptr, 0);
  if (needed <= 0) {
    return false;
  }
  out.resize(static_cast<std::size_t>(needed));
  const int written = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                            static_cast<int>(text.size()), out.data(), needed);
  return written == needed;
}

/// Converts a normalised absolute UTF-8 path to the wide form, adding the
/// extended-length prefix when the path is long. Returns false when the path is
/// not representable.
[[nodiscard]] bool ToWidePath(std::string_view utf8_path, std::wstring& out) {
  std::string normalised(utf8_path);
  std::replace(normalised.begin(), normalised.end(), '/', '\\');

  std::string prefixed;
  if (normalised.size() >= kExtendedPathThreshold) {
    if (normalised.rfind("\\\\?\\", 0) != 0) {
      if (normalised.rfind("\\\\", 0) == 0) {
        prefixed = "\\\\?\\UNC\\" + normalised.substr(2);
      } else {
        prefixed = "\\\\?\\" + normalised;
      }
    } else {
      prefixed = normalised;
    }
  } else {
    prefixed = normalised;
  }
  return Utf8ToWide(prefixed, out);
}

[[nodiscard]] std::string JoinPath(std::string_view directory, std::string_view leaf) {
  std::string out(directory);
  if (!out.empty() && out.back() != '\\' && out.back() != '/') {
    out.push_back('\\');
  }
  out.append(leaf);
  return out;
}

/// Distinguishes "this file was never written" from "this file could not be
/// read". A fresh store must not be reported as corruption.
enum class FileReadOutcome : std::uint32_t { ok = 0, absent = 1, failed = 2 };

[[nodiscard]] FileReadOutcome ReadWholeFile(const std::wstring& path, std::string& out,
                                           std::string& failure) {
  HANDLE handle = ::CreateFileW(path.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD error = ::GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
      return FileReadOutcome::absent;
    }
    failure = Win32ErrorText(error);
    return FileReadOutcome::failed;
  }

  LARGE_INTEGER size{};
  if (::GetFileSizeEx(handle, &size) == 0) {
    failure = Win32ErrorText(::GetLastError());
    ::CloseHandle(handle);
    return FileReadOutcome::failed;
  }
  const std::uint64_t file_size = static_cast<std::uint64_t>(size.QuadPart);
  if (file_size > kStoreHeaderSize + kMaxPayloadSize) {
    failure = "file is larger than any valid record";
    ::CloseHandle(handle);
    return FileReadOutcome::failed;
  }

  out.clear();
  out.resize(static_cast<std::size_t>(file_size));
  std::size_t offset = 0;
  while (offset < out.size()) {
    const DWORD want = static_cast<DWORD>(
        (std::min)(static_cast<std::size_t>(1U << 20U), out.size() - offset));
    DWORD got = 0;
    if (::ReadFile(handle, out.data() + offset, want, &got, nullptr) == 0) {
      failure = Win32ErrorText(::GetLastError());
      ::CloseHandle(handle);
      return FileReadOutcome::failed;
    }
    if (got == 0) {
      failure = "file ended before its recorded length";
      ::CloseHandle(handle);
      return FileReadOutcome::failed;
    }
    offset += got;
  }
  ::CloseHandle(handle);
  return FileReadOutcome::ok;
}

/// Writes \p bytes and flushes them, in one call. \p limit_of_bytes, when
/// non-zero, truncates the write to that many bytes so a partial write can be
/// injected deterministically.
[[nodiscard]] bool WriteWholeFileFlushed(const std::wstring& path, std::string_view bytes,
                                         std::uint64_t limit_of_bytes, std::string& failure) {
  HANDLE handle = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    failure = Win32ErrorText(::GetLastError());
    return false;
  }

  std::size_t total = bytes.size();
  if (limit_of_bytes != 0U && limit_of_bytes < static_cast<std::uint64_t>(total)) {
    total = static_cast<std::size_t>(limit_of_bytes);
  }

  std::size_t offset = 0;
  while (offset < total) {
    const DWORD want = static_cast<DWORD>(
        (std::min)(static_cast<std::size_t>(1U << 20U), total - offset));
    DWORD wrote = 0;
    if (::WriteFile(handle, bytes.data() + offset, want, &wrote, nullptr) == 0) {
      failure = Win32ErrorText(::GetLastError());
      ::CloseHandle(handle);
      return false;
    }
    if (wrote == 0) {
      failure = "write made no progress";
      ::CloseHandle(handle);
      return false;
    }
    offset += wrote;
  }

  if (::FlushFileBuffers(handle) == 0) {
    failure = Win32ErrorText(::GetLastError());
    ::CloseHandle(handle);
    return false;
  }
  ::CloseHandle(handle);
  return true;
}

[[nodiscard]] bool TruncateFileTo(const std::wstring& path, std::uint64_t size,
                                  std::string& failure) {
  HANDLE handle = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    failure = Win32ErrorText(::GetLastError());
    return false;
  }
  LARGE_INTEGER position{};
  position.QuadPart = static_cast<LONGLONG>(size);
  if (::SetFilePointerEx(handle, position, nullptr, FILE_BEGIN) == 0) {
    failure = Win32ErrorText(::GetLastError());
    ::CloseHandle(handle);
    return false;
  }
  if (::SetEndOfFile(handle) == 0) {
    failure = Win32ErrorText(::GetLastError());
    ::CloseHandle(handle);
    return false;
  }
  if (::FlushFileBuffers(handle) == 0) {
    failure = Win32ErrorText(::GetLastError());
    ::CloseHandle(handle);
    return false;
  }
  ::CloseHandle(handle);
  return true;
}

[[nodiscard]] bool FlipByteAt(const std::wstring& path, std::uint64_t offset,
                              std::string& failure) {
  HANDLE handle = ::CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    failure = Win32ErrorText(::GetLastError());
    return false;
  }
  LARGE_INTEGER position{};
  position.QuadPart = static_cast<LONGLONG>(offset);
  if (::SetFilePointerEx(handle, position, nullptr, FILE_BEGIN) == 0) {
    failure = Win32ErrorText(::GetLastError());
    ::CloseHandle(handle);
    return false;
  }
  unsigned char byte = 0;
  DWORD got = 0;
  if (::ReadFile(handle, &byte, 1, &got, nullptr) == 0 || got != 1) {
    failure = "fault injection could not read the target byte";
    ::CloseHandle(handle);
    return false;
  }
  byte = static_cast<unsigned char>(byte ^ 0x01U);
  position.QuadPart = static_cast<LONGLONG>(offset);
  if (::SetFilePointerEx(handle, position, nullptr, FILE_BEGIN) == 0) {
    failure = Win32ErrorText(::GetLastError());
    ::CloseHandle(handle);
    return false;
  }
  DWORD wrote = 0;
  if (::WriteFile(handle, &byte, 1, &wrote, nullptr) == 0 || wrote != 1) {
    failure = "fault injection could not write the target byte";
    ::CloseHandle(handle);
    return false;
  }
  if (::FlushFileBuffers(handle) == 0) {
    failure = Win32ErrorText(::GetLastError());
    ::CloseHandle(handle);
    return false;
  }
  ::CloseHandle(handle);
  return true;
}

[[nodiscard]] bool IsReparsePoint(HANDLE handle) {
  FILE_ATTRIBUTE_TAG_INFO info{};
  if (::GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &info, sizeof(info)) == 0) {
    return false;
  }
  return (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

}  // namespace

// ---------------------------------------------------------------------------
// Process incarnation
// ---------------------------------------------------------------------------

IncarnationId CurrentIncarnation() noexcept {
  // Computed once per process. Combining the process identifier with the tick
  // count at first use keeps two successive processes on one host apart without
  // requiring a durable write just to observe a start.
  static const IncarnationId kIncarnation = []() noexcept {
    const std::uint64_t pid = static_cast<std::uint64_t>(::GetCurrentProcessId());
    const std::uint64_t tick = static_cast<std::uint64_t>(::GetTickCount64());
    std::uint64_t combined = (pid << 32U) | (tick & 0xFFFFFFFFULL);
    if (combined == 0U) {
      combined = 1U;
    }
    return IncarnationId::FromValue(combined);
  }();
  return kIncarnation;
}

// ---------------------------------------------------------------------------
// StoreState lookups
// ---------------------------------------------------------------------------

const FleetAsset* StoreState::FindAsset(AssetId id) const noexcept {
  const auto it = fleet.find(id);
  return it == fleet.end() ? nullptr : &it->second;
}

FleetAsset* StoreState::FindAsset(AssetId id) noexcept {
  const auto it = fleet.find(id);
  return it == fleet.end() ? nullptr : &it->second;
}

LifecycleGeneration StoreState::LatestGeneration(AssetId id) const noexcept {
  LifecycleGeneration latest;
  for (const auto& entry : cases) {
    if (entry.first.asset == id && latest < entry.first.generation) {
      latest = entry.first.generation;
    }
  }
  return latest;
}

const RetirementCase* StoreState::FindCase(const CaseKey& key) const noexcept {
  const auto it = cases.find(key);
  return it == cases.end() ? nullptr : &it->second;
}

RetirementCase* StoreState::FindCase(const CaseKey& key) noexcept {
  const auto it = cases.find(key);
  return it == cases.end() ? nullptr : &it->second;
}

const RetirementCase* StoreState::CurrentCase(AssetId id) const noexcept {
  const LifecycleGeneration latest = LatestGeneration(id);
  if (latest.is_unset()) {
    return nullptr;
  }
  return FindCase(CaseKey{id, latest});
}

RetirementCase* StoreState::CurrentCase(AssetId id) noexcept {
  const LifecycleGeneration latest = LatestGeneration(id);
  if (latest.is_unset()) {
    return nullptr;
  }
  return FindCase(CaseKey{id, latest});
}

// ---------------------------------------------------------------------------
// Fault injection
// ---------------------------------------------------------------------------

std::string_view ToString(FaultAction action) noexcept {
  switch (action) {
    case FaultAction::none: return "none";
    case FaultAction::kill: return "kill";
    case FaultAction::truncate: return "truncate";
    case FaultAction::bitflip: return "bitflip";
    case FaultAction::write_short: return "write_short";
    case FaultAction::directory_flush_fail: return "directory_flush_fail";
  }
  return "none";
}

FaultAction FaultActionFromString(std::string_view name) noexcept {
  if (name == "kill") {
    return FaultAction::kill;
  }
  if (name == "truncate") {
    return FaultAction::truncate;
  }
  if (name == "bitflip") {
    return FaultAction::bitflip;
  }
  if (name == "write_short") {
    return FaultAction::write_short;
  }
  if (name == "directory_flush_fail") {
    return FaultAction::directory_flush_fail;
  }
  return FaultAction::none;
}

Result<FaultPlan> FaultPlan::FromSpec(std::string_view spec) {
  FaultPlan plan;
  if (spec.empty()) {
    return plan;
  }

  std::size_t start = 0;
  while (start <= spec.size()) {
    const std::size_t comma = spec.find(',', start);
    std::string_view rule_text =
        comma == std::string_view::npos ? spec.substr(start) : spec.substr(start, comma - start);
    if (rule_text.empty()) {
      return MakeError(ErrorCode::malformed_request, "fault specification has an empty rule");
    }

    // action ':' step [ '=' value ] [ '@' occurrence ]
    const std::size_t colon = rule_text.find(':');
    if (colon == std::string_view::npos) {
      return ErrorBuilder(ErrorCode::malformed_request, "fault rule has no step")
          .With("rule", rule_text)
          .Build();
    }
    const std::string_view action_name = rule_text.substr(0, colon);
    std::string_view rest = rule_text.substr(colon + 1U);

    const FaultAction action = FaultActionFromString(action_name);
    if (action == FaultAction::none) {
      return ErrorBuilder(ErrorCode::malformed_request, "fault rule names an unknown action")
          .With("rule", rule_text)
          .With("action", action_name)
          .Build();
    }

    std::uint64_t occurrence = 0;
    const std::size_t at = rest.find('@');
    if (at != std::string_view::npos) {
      const std::string_view occurrence_text = rest.substr(at + 1U);
      rest = rest.substr(0, at);
      if (occurrence_text.empty()) {
        return ErrorBuilder(ErrorCode::malformed_request, "fault rule has an empty occurrence")
            .With("rule", rule_text)
            .Build();
      }
      std::uint64_t parsed = 0;
      for (const char ch : occurrence_text) {
        if (ch < '0' || ch > '9') {
          return ErrorBuilder(ErrorCode::malformed_request,
                              "fault rule occurrence is not decimal")
              .With("rule", rule_text)
              .Build();
        }
        parsed = (parsed * 10U) + static_cast<std::uint64_t>(ch - '0');
      }
      if (parsed == 0U) {
        return ErrorBuilder(ErrorCode::malformed_request,
                            "fault rule occurrence must be at least 1")
            .With("rule", rule_text)
            .Build();
      }
      occurrence = parsed;
    }

    std::uint64_t value = 0;
    const std::size_t equals = rest.find('=');
    std::string_view step_text = rest;
    if (equals != std::string_view::npos) {
      step_text = rest.substr(0, equals);
      const std::string_view value_text = rest.substr(equals + 1U);
      if (value_text.empty()) {
        return ErrorBuilder(ErrorCode::malformed_request, "fault rule has an empty value")
            .With("rule", rule_text)
            .Build();
      }
      std::uint64_t parsed = 0;
      for (const char ch : value_text) {
        if (ch < '0' || ch > '9') {
          return ErrorBuilder(ErrorCode::malformed_request, "fault rule value is not decimal")
              .With("rule", rule_text)
              .Build();
        }
        if (parsed > (0xFFFFFFFFFFFFFFFFULL - static_cast<std::uint64_t>(ch - '0')) / 10U) {
          return ErrorBuilder(ErrorCode::out_of_range, "fault rule value overflows")
              .With("rule", rule_text)
              .Build();
        }
        parsed = (parsed * 10U) + static_cast<std::uint64_t>(ch - '0');
      }
      value = parsed;
    }

    if (step_text.empty()) {
      return ErrorBuilder(ErrorCode::malformed_request, "fault rule has an empty step")
          .With("rule", rule_text)
          .Build();
    }
    std::uint64_t step = 0;
    for (const char ch : step_text) {
      if (ch < '0' || ch > '9') {
        return ErrorBuilder(ErrorCode::malformed_request, "fault rule step is not decimal")
            .With("rule", rule_text)
            .Build();
      }
      step = (step * 10U) + static_cast<std::uint64_t>(ch - '0');
    }
    if (step < 1U || step > static_cast<std::uint64_t>(CommitStep::advance_sequence)) {
      return ErrorBuilder(ErrorCode::out_of_range, "fault rule step is outside the commit protocol")
          .With("rule", rule_text)
          .With("step", step)
          .With("max_step", static_cast<std::uint64_t>(CommitStep::advance_sequence))
          .Build();
    }

    if (action == FaultAction::truncate && value == 0U) {
      return ErrorBuilder(ErrorCode::malformed_request, "truncate fault requires a byte count")
          .With("rule", rule_text)
          .Build();
    }
    if (action == FaultAction::write_short && value == 0U) {
      return ErrorBuilder(ErrorCode::malformed_request, "write_short fault requires a byte count")
          .With("rule", rule_text)
          .Build();
    }

    FaultRule rule;
    rule.action = action;
    rule.step = static_cast<std::uint32_t>(step);
    rule.value = value;
    rule.occurrence = occurrence;
    plan.rules_.push_back(rule);
    plan.fire_count_.push_back(0);

    if (comma == std::string_view::npos) {
      break;
    }
    start = comma + 1U;
  }

  return plan;
}

const FaultRule* FaultPlan::Match(std::uint32_t step, std::uint64_t commit_index) {
  for (std::size_t i = 0; i < rules_.size(); ++i) {
    const FaultRule& rule = rules_[i];
    if (rule.step != step) {
      continue;
    }
    if (rule.occurrence != 0U && rule.occurrence != commit_index) {
      continue;
    }
    fire_count_[i] += 1U;
    return &rule;
  }
  return nullptr;
}

std::string FaultPlan::to_string() const {
  std::string out;
  for (std::size_t i = 0; i < rules_.size(); ++i) {
    if (i != 0U) {
      out.push_back(',');
    }
    out += ToString(rules_[i].action);
    out.push_back(':');
    out += std::to_string(rules_[i].step);
    if (rules_[i].value != 0U) {
      out.push_back('=');
      out += std::to_string(rules_[i].value);
    }
    if (rules_[i].occurrence != 0U) {
      out.push_back('@');
      out += std::to_string(rules_[i].occurrence);
    }
  }
  return out;
}

std::size_t FaultPlan::fired_count() const noexcept {
  std::size_t total = 0;
  for (const std::uint64_t count : fire_count_) {
    total += static_cast<std::size_t>(count);
  }
  return total;
}

// ---------------------------------------------------------------------------
// DurableStore
// ---------------------------------------------------------------------------

DurableStore::~DurableStore() { CloseHandles(); }

DurableStore::DurableStore(DurableStore&& other) noexcept
    : directory_(std::move(other.directory_)),
      lock_handle_(other.lock_handle_),
      directory_handle_(other.directory_handle_),
      directory_writable_(other.directory_writable_),
      recovery_(std::move(other.recovery_)),
      sequence_(other.sequence_),
      commit_count_(other.commit_count_),
      options_(std::move(other.options_)) {
  other.lock_handle_ = nullptr;
  other.directory_handle_ = nullptr;
  other.directory_writable_ = false;
}

DurableStore& DurableStore::operator=(DurableStore&& other) noexcept {
  if (this != &other) {
    CloseHandles();
    directory_ = std::move(other.directory_);
    lock_handle_ = other.lock_handle_;
    directory_handle_ = other.directory_handle_;
    directory_writable_ = other.directory_writable_;
    recovery_ = std::move(other.recovery_);
    sequence_ = other.sequence_;
    commit_count_ = other.commit_count_;
    options_ = std::move(other.options_);
    other.lock_handle_ = nullptr;
    other.directory_handle_ = nullptr;
    other.directory_writable_ = false;
  }
  return *this;
}

void DurableStore::CloseHandles() noexcept {
  if (lock_handle_ != nullptr) {
    auto* handle = static_cast<HANDLE>(lock_handle_);
    OVERLAPPED overlapped{};
    ::UnlockFileEx(handle, 0, 1, 0, &overlapped);
    ::CloseHandle(handle);
    lock_handle_ = nullptr;
  }
  if (directory_handle_ != nullptr) {
    ::CloseHandle(static_cast<HANDLE>(directory_handle_));
    directory_handle_ = nullptr;
  }
  directory_writable_ = false;
}

std::string DurableStore::Path(std::string_view leaf) const {
  return JoinPath(directory_, leaf);
}

Result<DurableStore> DurableStore::Open(std::string directory, const StoreOptions& options,
                                        StoreState& out_state) {
  if (directory.empty()) {
    return MakeError(ErrorCode::store_directory_invalid, "store directory is empty");
  }
  if (!IsValidUtf8(directory)) {
    return MakeError(ErrorCode::store_directory_invalid,
                     "store directory is not well-formed UTF-8");
  }

  std::error_code ec;
  const std::filesystem::path supplied(directory);
  std::filesystem::path absolute = std::filesystem::absolute(supplied, ec);
  if (ec) {
    return ErrorBuilder(ErrorCode::store_directory_invalid,
                        "store directory could not be made absolute")
        .With("directory", directory)
        .With("reason", ec.message())
        .Build();
  }
  std::string normalised = absolute.lexically_normal().string();

  const bool exists = std::filesystem::exists(absolute, ec);
  if (ec) {
    return ErrorBuilder(ErrorCode::store_directory_invalid, "store directory could not be examined")
        .With("directory", normalised)
        .With("reason", ec.message())
        .Build();
  }
  if (!exists) {
    if (!options.create_if_missing) {
      return ErrorBuilder(ErrorCode::store_missing, "store directory does not exist")
          .With("directory", normalised)
          .Build();
    }
    if (!std::filesystem::create_directories(absolute, ec) && ec) {
      return ErrorBuilder(ErrorCode::store_io_error, "store directory could not be created")
          .With("directory", normalised)
          .With("reason", ec.message())
          .Build();
    }
  } else if (!std::filesystem::is_directory(absolute, ec)) {
    return ErrorBuilder(ErrorCode::store_directory_invalid,
                        "store path exists but is not a directory")
        .With("directory", normalised)
        .Build();
  }

  DurableStore store;
  store.directory_ = normalised;
  store.options_ = options;

  // Directory handle: opened with the reparse-point flag so a store cannot be
  // silently redirected through a junction or symlink.
  std::wstring wide_directory;
  if (!ToWidePath(store.directory_, wide_directory)) {
    return ErrorBuilder(ErrorCode::store_directory_invalid,
                        "store directory is not representable as a Windows path")
        .With("directory", store.directory_)
        .Build();
  }

  HANDLE directory_handle =
      ::CreateFileW(wide_directory.c_str(), GENERIC_READ | GENERIC_WRITE | FILE_LIST_DIRECTORY,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  bool directory_writable = true;
  if (directory_handle == INVALID_HANDLE_VALUE) {
    directory_writable = false;
    directory_handle =
        ::CreateFileW(wide_directory.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      nullptr, OPEN_EXISTING,
                      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  }
  if (directory_handle == INVALID_HANDLE_VALUE) {
    return ErrorBuilder(ErrorCode::store_directory_invalid, "store directory could not be opened")
        .With("directory", store.directory_)
        .With("reason", Win32ErrorText(::GetLastError()))
        .Build();
  }
  if (IsReparsePoint(directory_handle)) {
    ::CloseHandle(directory_handle);
    return ErrorBuilder(ErrorCode::store_directory_invalid,
                        "store directory is a reparse point and will not be followed")
        .With("directory", store.directory_)
        .Build();
  }
  store.directory_handle_ = directory_handle;
  store.directory_writable_ = directory_writable;
  const LockOrderGuard directory_guard(options.lock_order, kLockLevelStoreDirectory);

  // Single-writer lock. Acquired before any data-bearing file is opened.
  const std::string lock_path = store.Path(kLockName);
  std::wstring wide_lock;
  if (!ToWidePath(lock_path, wide_lock)) {
    return ErrorBuilder(ErrorCode::store_directory_invalid, "lock path is not representable")
        .With("path", lock_path)
        .Build();
  }
  HANDLE lock_handle = ::CreateFileW(wide_lock.c_str(), GENERIC_READ | GENERIC_WRITE,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                                     FILE_ATTRIBUTE_NORMAL, nullptr);
  if (lock_handle == INVALID_HANDLE_VALUE) {
    return ErrorBuilder(ErrorCode::store_io_error, "store lock file could not be opened")
        .With("path", lock_path)
        .With("reason", Win32ErrorText(::GetLastError()))
        .Build();
  }

  const std::uint64_t deadline_millis =
      options.lock_mode == LockMode::retry_bounded ? options.lock_retry_millis : 0U;
  std::uint64_t waited_millis = 0;
  bool locked = false;
  for (;;) {
    OVERLAPPED overlapped{};
    if (::LockFileEx(lock_handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0,
                     &overlapped) != 0) {
      locked = true;
      break;
    }
    const DWORD error = ::GetLastError();
    if (error != ERROR_LOCK_VIOLATION) {
      ::CloseHandle(lock_handle);
      return ErrorBuilder(ErrorCode::store_io_error, "store lock could not be acquired")
          .With("path", lock_path)
          .With("reason", Win32ErrorText(error))
          .Build();
    }
    if (waited_millis >= deadline_millis) {
      break;
    }
    ::Sleep(10);
    waited_millis += 10U;
  }
  if (!locked) {
    ::CloseHandle(lock_handle);
    return ErrorBuilder(ErrorCode::store_locked,
                        "another process holds the single-writer lock for this store")
        .With("directory", store.directory_)
        .With("waited_millis", waited_millis)
        .Build();
  }
  store.lock_handle_ = lock_handle;
  const LockOrderGuard writer_guard(options.lock_order, kLockLevelWriterLock);

  // Leftover temporary files are never authoritative: they are the residue of a
  // commit that did not reach its publish point.
  for (const char* slot_name : kSlotNames) {
    const std::string temp_path = store.Path(std::string(slot_name) + kTempSuffix);
    std::wstring wide_temp;
    if (ToWidePath(temp_path, wide_temp)) {
      ::DeleteFileW(wide_temp.c_str());
    }
  }

  // Recover exactly one generation. Neither slot is ever merged with the other.
  SlotReport reports[2];
  std::string payloads[2];
  for (std::size_t index = 0; index < 2U; ++index) {
    store.ReadSlot(index == 1U, reports[index], &payloads[index]);
  }

  std::size_t chosen = 2U;
  for (std::size_t index = 0; index < 2U; ++index) {
    if (reports[index].status != SlotStatus::valid) {
      continue;
    }
    if (chosen == 2U || reports[chosen].sequence < reports[index].sequence) {
      chosen = index;
    }
  }

  store.recovery_.slot_a = reports[0];
  store.recovery_.slot_b = reports[1];

  if (chosen == 2U) {
    const bool any_present = reports[0].status != SlotStatus::absent ||
                             reports[1].status != SlotStatus::absent;
    store.recovery_.fresh = !any_present;
    store.recovery_.unrecoverable = any_present;
    if (reports[0].status == SlotStatus::corrupt) {
      store.recovery_.torn_slots.push_back("state.a: " + reports[0].failure);
    }
    if (reports[1].status == SlotStatus::corrupt) {
      store.recovery_.torn_slots.push_back("state.b: " + reports[1].failure);
    }
    if (!any_present) {
      // A brand new store. Nothing is invented: the caller receives a state with
      // sequence 0 and generations at their first value.
      out_state = StoreState{};
      out_state.sequence = CommitSequence{};
      out_state.generations.facility_epoch = FacilityEpoch::First();
      out_state.generations.policy_generation = PolicyGeneration::First();
      out_state.generations.dependency_generation = DependencyGeneration::First();
      out_state.generations.capacity_generation = CapacityGeneration::First();
      out_state.generations.topology_generation = TopologyGeneration::First();
      out_state.generations.maintenance_generation = MaintenanceGeneration::First();
      return std::move(store);
    }
    return ErrorBuilder(ErrorCode::store_corrupt,
                        "store has slots but none of them verifies; refusing to start empty")
        .With("directory", store.directory_)
        .With("torn", std::to_string(store.recovery_.torn_slots.size()))
        .Build();
  }

  store.recovery_.recovered_from = SlotStatus::valid;
  store.recovery_.recovered_sequence = reports[chosen].sequence;
  store.recovery_.recovered_from_slot_b = chosen == 1U;
  for (std::size_t index = 0; index < 2U; ++index) {
    if (index != chosen && reports[index].status == SlotStatus::corrupt) {
      store.recovery_.torn_slots.push_back(
          (index == 0U ? std::string("state.a: ") : std::string("state.b: ")) +
          reports[index].failure);
    }
  }

  auto decoded = DecodeState(payloads[chosen]);
  if (!decoded.ok()) {
    return ErrorBuilder(ErrorCode::store_corrupt,
                        "recovered payload does not decode into a valid generation")
        .With("directory", store.directory_)
        .With("reason", decoded.error().to_string())
        .Build();
  }
  StoreState state = std::move(decoded).value();
  if (state.sequence != reports[chosen].sequence) {
    return ErrorBuilder(ErrorCode::store_corrupt,
                        "recovered payload sequence disagrees with its record header")
        .With("record", reports[chosen].sequence.value())
        .With("payload", state.sequence.value())
        .Build();
  }

  store.sequence_ = state.sequence;
  out_state = std::move(state);
  return std::move(store);
}

void DurableStore::ReadSlot(bool slot_b, SlotReport& report, std::string* payload_out) const {
  report = SlotReport{};
  const std::string path = Path(kSlotNames[slot_b ? 1 : 0]);
  std::wstring wide_path;
  if (!ToWidePath(path, wide_path)) {
    report.status = SlotStatus::corrupt;
    report.failure = "slot path is not representable";
    return;
  }

  std::string contents;
  std::string failure;
  const FileReadOutcome outcome = ReadWholeFile(wide_path, contents, failure);
  if (outcome == FileReadOutcome::absent) {
    report.status = SlotStatus::absent;
    return;
  }
  if (outcome == FileReadOutcome::failed) {
    report.status = SlotStatus::corrupt;
    report.failure = failure;
    return;
  }

  ParsedRecord parsed;
  if (!TryParseRecord(contents, parsed, report)) {
    return;
  }
  if (payload_out != nullptr) {
    *payload_out = std::move(parsed.payload);
  }
}

Status DurableStore::ApplyFaults(CommitStep step, std::uint64_t commit_index,
                                 const std::string& temp_path) {
  const auto step_number = static_cast<std::uint32_t>(step);
  const FaultRule* rule = options_.faults.Match(step_number, commit_index);
  if (rule == nullptr) {
    return OkStatus();
  }

  std::wstring wide_temp;
  switch (rule->action) {
    case FaultAction::kill:
      // Deliberately no unwinding, no flush, and no cleanup: this is the crash.
      ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(kFaultKillExitCode));
      std::abort();
      break;

    case FaultAction::truncate:
      if (!ToWidePath(temp_path, wide_temp)) {
        return MakeError(ErrorCode::fault_injected, "fault target path is not representable");
      }
      if (!TruncateFileTo(wide_temp, rule->value, injection_failure_)) {
        return ErrorBuilder(ErrorCode::fault_injected, "injected truncate failed")
            .With("reason", injection_failure_)
            .Build();
      }
      break;

    case FaultAction::bitflip:
      if (!ToWidePath(temp_path, wide_temp)) {
        return MakeError(ErrorCode::fault_injected, "fault target path is not representable");
      }
      if (!FlipByteAt(wide_temp, rule->value, injection_failure_)) {
        return ErrorBuilder(ErrorCode::fault_injected, "injected bit flip failed")
            .With("reason", injection_failure_)
            .Build();
      }
      break;

    case FaultAction::write_short:
      pending_write_limit_ = rule->value;
      break;

    case FaultAction::directory_flush_fail:
      pending_directory_failure_ = true;
      break;

    case FaultAction::none:
      break;
  }
  return OkStatus();
}

Result<CommitOutcome> DurableStore::Commit(const StoreState& state) {
  if (state.sequence.value() <= sequence_.value()) {
    return ErrorBuilder(ErrorCode::out_of_range,
                        "commit would not advance the durable sequence")
        .With("current", sequence_.value())
        .With("proposed", state.sequence.value())
        .Build();
  }

  const LockOrderGuard store_guard(options_.lock_order, kLockLevelDurableStore);

  const std::uint64_t commit_index = commit_count_ + 1U;
  const std::int64_t started = MonotonicCounter::NowNanos();

  pending_write_limit_ = 0;
  pending_directory_failure_ = false;

  CommitOutcome outcome;
  outcome.sequence = state.sequence;

  // Step 1: serialise the candidate generation.
  DF_TRY(ApplyFaults(CommitStep::serialise, commit_index, std::string()));
  const std::string payload = EncodeState(state);
  outcome.payload_bytes = static_cast<std::uint64_t>(payload.size());
  outcome.serialise_nanos =
      static_cast<std::uint64_t>(MonotonicCounter::NowNanos() - started);

  // Step 2: choose the slot that is NOT the last published one, so the
  // previously published generation survives whatever happens next.
  DF_TRY(ApplyFaults(CommitStep::select_slot, commit_index, std::string()));
  bool use_slot_b = false;
  {
    const std::uint64_t sequence_a =
        recovery_.slot_a.status == SlotStatus::valid ? recovery_.slot_a.sequence.value() : 0U;
    const std::uint64_t sequence_b =
        recovery_.slot_b.status == SlotStatus::valid ? recovery_.slot_b.sequence.value() : 0U;
    if (sequence_a < sequence_b) {
      use_slot_b = false;
    } else if (sequence_b < sequence_a) {
      use_slot_b = true;
    } else {
      // Equal (including the both-absent fresh case): alternate away from the
      // slot the last recovery used, defaulting to slot b when nothing was
      // recovered.
      use_slot_b = recovery_.recovered_from == SlotStatus::valid
                       ? !recovery_.recovered_from_slot_b
                       : true;
    }
  }
  outcome.used_slot_b = use_slot_b;

  const std::string slot_path = Path(kSlotNames[use_slot_b ? 1 : 0]);
  const std::string temp_path = slot_path + kTempSuffix;
  std::wstring wide_temp;
  if (!ToWidePath(temp_path, wide_temp)) {
    return MakeError(ErrorCode::store_io_error, "temporary slot path is not representable");
  }

  // Step 3: write the temporary slot, flush it, and close it.
  const std::string record = BuildRecord(payload, state.sequence);
  outcome.record_bytes = static_cast<std::uint64_t>(record.size());
  outcome.payload_digest = Sha256::Of(payload);
  const std::int64_t write_started = MonotonicCounter::NowNanos();
  DF_TRY(ApplyFaults(CommitStep::write_temp, commit_index, temp_path));
  if (!WriteWholeFileFlushed(wide_temp, record, pending_write_limit_, injection_failure_)) {
    return ErrorBuilder(ErrorCode::store_io_error, "durable write failed")
        .With("path", temp_path)
        .With("reason", injection_failure_)
        .Build();
  }
  outcome.write_nanos =
      static_cast<std::uint64_t>(MonotonicCounter::NowNanos() - write_started);

  // Step 4: read the temporary slot back and re-verify everything.
  const std::int64_t verify_started = MonotonicCounter::NowNanos();
  DF_TRY(ApplyFaults(CommitStep::verify_temp, commit_index, temp_path));
  {
    std::string readback;
    std::string failure;
    if (ReadWholeFile(wide_temp, readback, failure) != FileReadOutcome::ok) {
      return ErrorBuilder(ErrorCode::store_io_error, "read-back of the temporary slot failed")
          .With("path", temp_path)
          .With("reason", failure)
          .Build();
    }
    auto parsed = ParseRecord(readback, static_cast<std::uint64_t>(readback.size()));
    if (!parsed.ok()) {
      return ErrorBuilder(ErrorCode::store_corrupt,
                          "read-back of the temporary slot did not verify")
          .With("path", temp_path)
          .With("reason", parsed.error().to_string())
          .Build();
    }
    if (parsed.value().payload != payload) {
      return ErrorBuilder(ErrorCode::store_corrupt,
                          "read-back payload differs from the payload that was written")
          .With("path", temp_path)
          .Build();
    }
  }
  outcome.verify_nanos =
      static_cast<std::uint64_t>(MonotonicCounter::NowNanos() - verify_started);

  // Step 5: the atomic publish point.
  const std::int64_t publish_started = MonotonicCounter::NowNanos();
  DF_TRY(ApplyFaults(CommitStep::publish, commit_index, temp_path));
  {
    std::wstring wide_slot;
    if (!ToWidePath(slot_path, wide_slot)) {
      return MakeError(ErrorCode::store_io_error, "slot path is not representable");
    }
    if (::MoveFileExW(wide_temp.c_str(), wide_slot.c_str(),
                      MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
      return ErrorBuilder(ErrorCode::store_io_error, "atomic publish failed")
          .With("from", temp_path)
          .With("to", slot_path)
          .With("reason", Win32ErrorText(::GetLastError()))
          .Build();
    }
  }
  outcome.publish_nanos =
      static_cast<std::uint64_t>(MonotonicCounter::NowNanos() - publish_started);

  // Step 6: flush the directory so the rename itself is durable.
  //
  // This step is AFTER the publish point, so it can no longer fail the commit.
  // The rename already used MOVEFILE_WRITE_THROUGH; a directory flush problem is
  // recorded as a degradation and reported to the caller as one.
  const std::int64_t directory_started = MonotonicCounter::NowNanos();
  DF_TRY(ApplyFaults(CommitStep::flush_directory, commit_index, temp_path));
  if (pending_directory_failure_) {
    outcome.degraded = true;
    outcome.degraded_reason = "injected directory flush failure after the publish point";
  } else if (directory_writable_ && directory_handle_ != nullptr) {
    if (::FlushFileBuffers(static_cast<HANDLE>(directory_handle_)) == 0) {
      const DWORD error = ::GetLastError();
      if (error != ERROR_ACCESS_DENIED && error != ERROR_INVALID_FUNCTION) {
        outcome.degraded = true;
        outcome.degraded_reason =
            std::string("directory flush failed after the publish point: ") +
            Win32ErrorText(error);
      }
      directory_writable_ = false;
    }
  }
  outcome.directory_nanos =
      static_cast<std::uint64_t>(MonotonicCounter::NowNanos() - directory_started);

  // Step 7: only now does the published generation become the in-memory one.
  // Nothing below this line may return an error: the generation is durable.
  const Status advance_status = ApplyFaults(CommitStep::advance_sequence, commit_index, temp_path);
  if (!advance_status.ok()) {
    outcome.degraded = true;
    outcome.degraded_reason = advance_status.error().to_string();
  }
  sequence_ = state.sequence;
  commit_count_ = commit_index;
  SlotReport& written = use_slot_b ? recovery_.slot_b : recovery_.slot_a;
  written.status = SlotStatus::valid;
  written.sequence = state.sequence;
  written.payload_size = outcome.payload_bytes;
  written.payload_digest = outcome.payload_digest;
  written.failure.clear();
  recovery_.recovered_from = SlotStatus::valid;
  recovery_.recovered_sequence = state.sequence;
  recovery_.recovered_from_slot_b = use_slot_b;
  recovery_.fresh = false;
  recovery_.unrecoverable = false;

  outcome.total_nanos = static_cast<std::uint64_t>(MonotonicCounter::NowNanos() - started);
  return outcome;
}

}  // namespace decommissioning_fabric

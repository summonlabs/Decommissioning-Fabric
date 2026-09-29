// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Error model and deterministic validation precedence.
//
// Two properties are load bearing and are property tested:
//
//   * Determinism  - the same (state, request) pair always resolves to the same
//                    (stage, code), independent of map iteration order,
//                    insertion order, and concurrent readers.
//   * Monotonicity - adding an error at a LATER stage never changes the verdict
//                    of an EARLIER stage.
//
// Both follow from Validate() walking kValidationPrecedence in order and
// stopping at the first failing stage, and from each stage inspecting its
// fields in a documented fixed order rather than iterating a container.

#ifndef DECOMMISSIONING_FABRIC_ERRORS_HPP
#define DECOMMISSIONING_FABRIC_ERRORS_HPP

#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace decommissioning_fabric {

/// Where in the request-validation precedence a failure was detected.
///
/// Stages 1..9 are the ordered validation precedence. Stage 10 (ok) is the
/// successful verdict. Stage 11 (infrastructure) is deliberately OUTSIDE the
/// precedence: store, filesystem, locking, and fault-injection failures are not
/// statements about the request, and reporting them as a request-validation
/// stage would let an I/O failure masquerade as a malformed request.
enum class ValidationStage : std::uint32_t {
  parse_shape = 1,
  bounds_limits = 2,
  identity = 3,
  request_registry = 4,
  asset_existence = 5,
  fence = 6,
  phase_predicate = 7,
  prerequisite = 8,
  policy = 9,
  ok = 10,
  infrastructure = 11,
};

[[nodiscard]] std::string_view ToString(ValidationStage stage) noexcept;

/// The ordered request-validation precedence. A validator walks this list and
/// stops at the first stage that fails.
inline constexpr ValidationStage kValidationPrecedence[] = {
    ValidationStage::parse_shape,      ValidationStage::bounds_limits,
    ValidationStage::identity,         ValidationStage::request_registry,
    ValidationStage::asset_existence,  ValidationStage::fence,
    ValidationStage::phase_predicate,  ValidationStage::prerequisite,
    ValidationStage::policy,
};

/// Stable error codes. A code is never reused with a different meaning; new
/// meanings get new codes. The numeric values are part of the public contract
/// and appear in machine-readable CLI output.
enum class ErrorCode : std::uint32_t {
  ok = 0,

  // --- stage 1: parse / shape ---------------------------------------------
  malformed_request = 100,
  malformed_hex = 101,
  malformed_payload = 102,
  invalid_utf8 = 103,
  unexpected_token = 104,
  trailing_data = 105,
  missing_field = 106,

  // --- stage 2: bounds / limits -------------------------------------------
  out_of_range = 200,
  too_many_items = 201,
  string_too_long = 202,
  reserved_not_zero = 203,
  value_saturated = 204,
  payload_too_large = 205,
  payload_too_small = 206,
  unsupported_format_version = 207,

  // --- stage 3: identity ---------------------------------------------------
  unset_identity = 300,
  unset_generation = 301,
  unset_attempt = 302,
  duplicate_identity = 303,
  identity_mismatch = 304,

  // --- stage 4: request registry ------------------------------------------
  already_issued = 400,

  // --- stage 5: asset / case existence ------------------------------------
  unknown_asset = 500,
  unknown_case = 501,
  wrong_plan_for_asset = 502,
  unknown_obligation = 503,
  unknown_residual_item = 504,
  unknown_evidence = 505,
  unknown_receipt = 506,
  unknown_exception = 507,
  asset_generation_regressed = 508,
  case_already_open = 509,

  // --- stage 6: fence ------------------------------------------------------
  fence_superseded = 600,
  fence_stale = 601,
  fence_revision_behind = 602,
  fence_malformed = 603,

  // --- stage 7: phase predicate -------------------------------------------
  invalid_transition = 700,
  phase_terminal = 701,
  phase_does_not_permit = 702,

  // --- stage 8: prerequisite ----------------------------------------------
  unmet_obligation = 800,
  unresolved_residual = 801,
  authority_unknown = 802,
  authority_active = 803,
  missing_evidence = 804,
  evidence_kind_mismatch = 805,
  evidence_stale = 806,
  isolation_not_observed = 807,
  removal_not_authorized = 808,
  drain_required = 809,
  residual_checklist_incomplete = 810,
  obligation_already_resolved = 811,

  // --- stage 9: policy -----------------------------------------------------
  policy_violation = 900,
  exception_required = 901,
  exception_not_permitted = 902,
  protected_service_unresolved = 903,

  // --- infrastructure (outside the precedence) -----------------------------
  store_locked = 1000,
  store_corrupt = 1001,
  store_io_error = 1002,
  store_directory_invalid = 1003,
  store_missing = 1004,
  recovery_failed = 1005,
  fault_injected = 1006,
  callback_failed = 1007,
  internal_error = 1008,
  not_implemented = 1009,
};

[[nodiscard]] std::string_view ToString(ErrorCode code) noexcept;

/// Maps a code to the validation stage that produces it. Total: every code has
/// exactly one stage, so a stage never has to be inferred from context.
[[nodiscard]] ValidationStage StageOf(ErrorCode code) noexcept;

/// True when the code belongs to the ordered request-validation precedence.
[[nodiscard]] bool IsValidationCode(ErrorCode code) noexcept;

struct ErrorDetail {
  std::string key;
  std::string value;

  friend bool operator==(const ErrorDetail&, const ErrorDetail&) = default;
};

/// A failure with a stable code, the stage that produced it, a human readable
/// summary, and ordered details naming the exact fields involved.
struct Error {
  ErrorCode code{ErrorCode::ok};
  ValidationStage stage{ValidationStage::ok};
  std::string message;
  std::vector<ErrorDetail> details;

  [[nodiscard]] bool is_error() const noexcept { return code != ErrorCode::ok; }

  /// Single-line rendering: \c "[stage=... code=...] message key=value ..."
  [[nodiscard]] std::string to_string() const;

  /// Looks up a detail by key. Returns nullptr when absent; a missing detail is
  /// never treated as an empty string.
  [[nodiscard]] const std::string* find(std::string_view key) const noexcept;
};

/// Builds an Error that carries the stage implied by its code. Callers cannot
/// attach a wrong stage.
[[nodiscard]] Error MakeError(ErrorCode code, std::string message);

/// Builder helper: MakeError(...).With("plan", "0000...").With("current", "3")
class ErrorBuilder {
 public:
  ErrorBuilder(ErrorCode code, std::string message);

  ErrorBuilder& With(std::string key, std::string value);
  ErrorBuilder& With(std::string key, std::uint64_t value);
  ErrorBuilder& With(std::string key, std::int64_t value);
  ErrorBuilder& With(std::string key, bool value);
  ErrorBuilder& With(std::string key, std::string_view value);
  ErrorBuilder& With(std::string key, const char* value);

  [[nodiscard]] Error Build() const;
  [[nodiscard]] operator Error() const { return Build(); }  // NOLINT(google-explicit-constructor)

 private:
  Error error_;
};

/// Explicit unit type used by Status, so that "succeeded, no value" cannot be
/// confused with "succeeded with a default-constructed value".
struct Unit {
  friend constexpr bool operator==(Unit, Unit) noexcept { return true; }
};

/// A value or an Error. Never a silent default: reading the value of a failed
/// Result is a programming error and throws std::bad_variant_access.
template <typename T>
class Result {
 public:
  using value_type = T;

  Result(T value) : storage_(std::in_place_index<0>, std::move(value)) {}  // NOLINT
  Result(Error error) : storage_(std::in_place_index<1>, std::move(error)) {}  // NOLINT

  [[nodiscard]] bool ok() const noexcept { return storage_.index() == 0; }
  [[nodiscard]] explicit operator bool() const noexcept { return ok(); }
  [[nodiscard]] bool failed() const noexcept { return !ok(); }

  [[nodiscard]] T& value() & { return std::get<0>(storage_); }
  [[nodiscard]] const T& value() const& { return std::get<0>(storage_); }
  [[nodiscard]] T&& value() && { return std::get<0>(std::move(storage_)); }

  [[nodiscard]] const Error& error() const& { return std::get<1>(storage_); }
  [[nodiscard]] Error& error() & { return std::get<1>(storage_); }
  [[nodiscard]] Error&& error() && { return std::get<1>(std::move(storage_)); }

  [[nodiscard]] T value_or(T fallback) const {
    return ok() ? std::get<0>(storage_) : std::move(fallback);
  }

  template <typename Fn>
  [[nodiscard]] auto Map(Fn&& fn) const -> Result<decltype(fn(std::declval<const T&>()))> {
    using U = decltype(fn(std::declval<const T&>()));
    if (!ok()) {
      return error();
    }
    return fn(std::get<0>(storage_));
  }

 private:
  std::variant<T, Error> storage_;
};

/// Status is Result<void>: success carries no value at all.
using Status = Result<Unit>;

[[nodiscard]] inline Status OkStatus() noexcept { return Status(Unit{}); }

/// Propagation helpers. Both return the Error from the enclosing function, so
/// they only make sense inside a function whose return type is a Result.
#define DF_TRY_ASSIGN(lvalue, expression)                        \
  do {                                                           \
    auto df_try_result = (expression);                           \
    if (!df_try_result.ok()) {                                   \
      return std::move(df_try_result).error();                   \
    }                                                            \
    (lvalue) = std::move(df_try_result).value();                 \
  } while (false)

#define DF_TRY_DECL(type, name, expression) \
  type name{};                              \
  DF_TRY_ASSIGN(name, expression)

#define DF_TRY(expression)                 \
  do {                                     \
    auto df_try_result = (expression);     \
    if (!df_try_result.ok()) {             \
      return std::move(df_try_result).error(); \
    }                                      \
  } while (false)

}  // namespace decommissioning_fabric

#endif  // DECOMMISSIONING_FABRIC_ERRORS_HPP

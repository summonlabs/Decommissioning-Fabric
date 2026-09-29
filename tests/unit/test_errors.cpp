// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Proof obligations for include/decommissioning_fabric/errors.hpp.
//
// The claims under test: every declared code has exactly one documented stage
// and one stable spelling; a numeric value that is not declared is
// infrastructure rather than a request-validation failure and never
// masquerades as a declared code; the validation precedence is strictly
// increasing, complete and correctly ordered; the stage is taken from the code
// rather than supplied by the caller; details survive the builder in order; and
// Result<T> propagates an Error unchanged instead of defaulting a value.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "decommissioning_fabric/errors.hpp"
#include "harness.hpp"

namespace {

using decommissioning_fabric::Error;
using decommissioning_fabric::ErrorBuilder;
using decommissioning_fabric::ErrorCode;
using decommissioning_fabric::IsValidationCode;
using decommissioning_fabric::kValidationPrecedence;
using decommissioning_fabric::MakeError;
using decommissioning_fabric::OkStatus;
using decommissioning_fabric::Result;
using decommissioning_fabric::StageOf;
using decommissioning_fabric::Status;
using decommissioning_fabric::ToString;
using decommissioning_fabric::ValidationStage;

/// The highest declared numeric code. The test sweeps 0..kHighestDeclaredCode,
/// so every declared code and every gap is exercised.
constexpr std::uint32_t kHighestDeclaredCode = 1009U;

struct CodeRow {
  ErrorCode code;
  ValidationStage stage;
  std::string_view name;
};

/// Every declared ErrorCode, its documented stage and its exact spelling.
constexpr CodeRow kDeclaredCodes[] = {
    {ErrorCode::ok, ValidationStage::ok, "ok"},

    {ErrorCode::malformed_request, ValidationStage::parse_shape, "malformed_request"},
    {ErrorCode::malformed_hex, ValidationStage::parse_shape, "malformed_hex"},
    {ErrorCode::malformed_payload, ValidationStage::parse_shape, "malformed_payload"},
    {ErrorCode::invalid_utf8, ValidationStage::parse_shape, "invalid_utf8"},
    {ErrorCode::unexpected_token, ValidationStage::parse_shape, "unexpected_token"},
    {ErrorCode::trailing_data, ValidationStage::parse_shape, "trailing_data"},
    {ErrorCode::missing_field, ValidationStage::parse_shape, "missing_field"},

    {ErrorCode::out_of_range, ValidationStage::bounds_limits, "out_of_range"},
    {ErrorCode::too_many_items, ValidationStage::bounds_limits, "too_many_items"},
    {ErrorCode::string_too_long, ValidationStage::bounds_limits, "string_too_long"},
    {ErrorCode::reserved_not_zero, ValidationStage::bounds_limits, "reserved_not_zero"},
    {ErrorCode::value_saturated, ValidationStage::bounds_limits, "value_saturated"},
    {ErrorCode::payload_too_large, ValidationStage::bounds_limits, "payload_too_large"},
    {ErrorCode::payload_too_small, ValidationStage::bounds_limits, "payload_too_small"},
    {ErrorCode::unsupported_format_version, ValidationStage::bounds_limits,
     "unsupported_format_version"},

    {ErrorCode::unset_identity, ValidationStage::identity, "unset_identity"},
    {ErrorCode::unset_generation, ValidationStage::identity, "unset_generation"},
    {ErrorCode::unset_attempt, ValidationStage::identity, "unset_attempt"},
    {ErrorCode::duplicate_identity, ValidationStage::identity, "duplicate_identity"},
    {ErrorCode::identity_mismatch, ValidationStage::identity, "identity_mismatch"},

    {ErrorCode::already_issued, ValidationStage::request_registry, "already_issued"},

    {ErrorCode::unknown_asset, ValidationStage::asset_existence, "unknown_asset"},
    {ErrorCode::unknown_case, ValidationStage::asset_existence, "unknown_case"},
    {ErrorCode::wrong_plan_for_asset, ValidationStage::asset_existence, "wrong_plan_for_asset"},
    {ErrorCode::unknown_obligation, ValidationStage::asset_existence, "unknown_obligation"},
    {ErrorCode::unknown_residual_item, ValidationStage::asset_existence, "unknown_residual_item"},
    {ErrorCode::unknown_evidence, ValidationStage::asset_existence, "unknown_evidence"},
    {ErrorCode::unknown_receipt, ValidationStage::asset_existence, "unknown_receipt"},
    {ErrorCode::unknown_exception, ValidationStage::asset_existence, "unknown_exception"},
    {ErrorCode::asset_generation_regressed, ValidationStage::asset_existence,
     "asset_generation_regressed"},
    {ErrorCode::case_already_open, ValidationStage::asset_existence, "case_already_open"},

    {ErrorCode::fence_superseded, ValidationStage::fence, "fence_superseded"},
    {ErrorCode::fence_stale, ValidationStage::fence, "fence_stale"},
    {ErrorCode::fence_revision_behind, ValidationStage::fence, "fence_revision_behind"},
    {ErrorCode::fence_malformed, ValidationStage::fence, "fence_malformed"},

    {ErrorCode::invalid_transition, ValidationStage::phase_predicate, "invalid_transition"},
    {ErrorCode::phase_terminal, ValidationStage::phase_predicate, "phase_terminal"},
    {ErrorCode::phase_does_not_permit, ValidationStage::phase_predicate,
     "phase_does_not_permit"},

    {ErrorCode::unmet_obligation, ValidationStage::prerequisite, "unmet_obligation"},
    {ErrorCode::unresolved_residual, ValidationStage::prerequisite, "unresolved_residual"},
    {ErrorCode::authority_unknown, ValidationStage::prerequisite, "authority_unknown"},
    {ErrorCode::authority_active, ValidationStage::prerequisite, "authority_active"},
    {ErrorCode::missing_evidence, ValidationStage::prerequisite, "missing_evidence"},
    {ErrorCode::evidence_kind_mismatch, ValidationStage::prerequisite,
     "evidence_kind_mismatch"},
    {ErrorCode::evidence_stale, ValidationStage::prerequisite, "evidence_stale"},
    {ErrorCode::isolation_not_observed, ValidationStage::prerequisite,
     "isolation_not_observed"},
    {ErrorCode::removal_not_authorized, ValidationStage::prerequisite,
     "removal_not_authorized"},
    {ErrorCode::drain_required, ValidationStage::prerequisite, "drain_required"},
    {ErrorCode::residual_checklist_incomplete, ValidationStage::prerequisite,
     "residual_checklist_incomplete"},
    {ErrorCode::obligation_already_resolved, ValidationStage::prerequisite,
     "obligation_already_resolved"},

    {ErrorCode::policy_violation, ValidationStage::policy, "policy_violation"},
    {ErrorCode::exception_required, ValidationStage::policy, "exception_required"},
    {ErrorCode::exception_not_permitted, ValidationStage::policy, "exception_not_permitted"},
    {ErrorCode::protected_service_unresolved, ValidationStage::policy,
     "protected_service_unresolved"},

    {ErrorCode::store_locked, ValidationStage::infrastructure, "store_locked"},
    {ErrorCode::store_corrupt, ValidationStage::infrastructure, "store_corrupt"},
    {ErrorCode::store_io_error, ValidationStage::infrastructure, "store_io_error"},
    {ErrorCode::store_directory_invalid, ValidationStage::infrastructure,
     "store_directory_invalid"},
    {ErrorCode::store_missing, ValidationStage::infrastructure, "store_missing"},
    {ErrorCode::recovery_failed, ValidationStage::infrastructure, "recovery_failed"},
    {ErrorCode::fault_injected, ValidationStage::infrastructure, "fault_injected"},
    {ErrorCode::callback_failed, ValidationStage::infrastructure, "callback_failed"},
    {ErrorCode::internal_error, ValidationStage::infrastructure, "internal_error"},
    {ErrorCode::not_implemented, ValidationStage::infrastructure, "not_implemented"},
};

[[nodiscard]] const CodeRow* Lookup(std::uint32_t raw) noexcept {
  for (const CodeRow& row : kDeclaredCodes) {
    if (static_cast<std::uint32_t>(row.code) == raw) {
      return &row;
    }
  }
  return nullptr;
}

[[nodiscard]] bool StageIsInPrecedence(ValidationStage stage) noexcept {
  for (const ValidationStage candidate : kValidationPrecedence) {
    if (candidate == stage) {
      return true;
    }
  }
  return false;
}

/// Uses the propagation macros, so the helpers are exercised, not just Result.
[[nodiscard]] Result<int> DoubledOrPropagated(const Result<int>& input) {
  int value = 0;
  DF_TRY_ASSIGN(value, input);
  return value * 2;
}

}  // namespace

DF_TEST(Errors_DeclaredCodeTableIsCompleteDuplicateFreeAndOrdered) {
  const std::size_t count = sizeof(kDeclaredCodes) / sizeof(kDeclaredCodes[0]);
  DF_CHECK_EQ(count, std::size_t{65});
  for (std::size_t i = 0; i < count; ++i) {
    const std::uint32_t raw = static_cast<std::uint32_t>(kDeclaredCodes[i].code);
    DF_CHECK_MSG(raw <= kHighestDeclaredCode,
                 "a declared code lies outside the swept 0..1009 range");
    DF_CHECK_MSG(!kDeclaredCodes[i].name.empty(), "a declared code has no spelling");
    if (i > 0U) {
      DF_CHECK_MSG(static_cast<std::uint32_t>(kDeclaredCodes[i - 1U].code) < raw,
                   "the declared code table must be strictly increasing");
    }
  }
}

DF_TEST(Errors_StageOfMapsEveryDeclaredCodeAndUndeclaredValuesToInfrastructure) {
  for (std::uint32_t raw = 0U; raw <= kHighestDeclaredCode; ++raw) {
    const ErrorCode code = static_cast<ErrorCode>(raw);
    const CodeRow* row = Lookup(raw);
    const std::string_view first_name = ToString(code);
    const std::string_view second_name = ToString(code);

    DF_CHECK_MSG(!first_name.empty(), "ToString(ErrorCode) must never be empty");
    DF_CHECK_EQ(first_name, second_name);

    if (row != nullptr) {
      DF_CHECK_EQ(StageOf(code), row->stage);
      DF_CHECK_EQ(first_name, row->name);
      DF_CHECK_EQ(static_cast<std::uint32_t>(StageOf(code)),
                  static_cast<std::uint32_t>(row->stage));
    } else {
      DF_CHECK_EQ(StageOf(code), ValidationStage::infrastructure);
      DF_CHECK(!IsValidationCode(code));
      // An undeclared numeric value must not borrow a declared code's spelling.
      for (const CodeRow& declared : kDeclaredCodes) {
        DF_CHECK_MSG(first_name != declared.name,
                     "an undeclared code reported the spelling of a declared code");
      }
    }
  }
}

DF_TEST(Errors_ToStringSpotChecksExactSpellings) {
  DF_CHECK_EQ(ToString(ErrorCode::ok), std::string_view("ok"));
  DF_CHECK_EQ(ToString(ErrorCode::malformed_hex), std::string_view("malformed_hex"));
  DF_CHECK_EQ(ToString(ErrorCode::invalid_utf8), std::string_view("invalid_utf8"));
  DF_CHECK_EQ(ToString(ErrorCode::unsupported_format_version),
              std::string_view("unsupported_format_version"));
  DF_CHECK_EQ(ToString(ErrorCode::unset_identity), std::string_view("unset_identity"));
  DF_CHECK_EQ(ToString(ErrorCode::already_issued), std::string_view("already_issued"));
  DF_CHECK_EQ(ToString(ErrorCode::case_already_open), std::string_view("case_already_open"));
  DF_CHECK_EQ(ToString(ErrorCode::asset_generation_regressed),
              std::string_view("asset_generation_regressed"));
  DF_CHECK_EQ(ToString(ErrorCode::fence_stale), std::string_view("fence_stale"));
  DF_CHECK_EQ(ToString(ErrorCode::fence_revision_behind),
              std::string_view("fence_revision_behind"));
  DF_CHECK_EQ(ToString(ErrorCode::invalid_transition), std::string_view("invalid_transition"));
  DF_CHECK_EQ(ToString(ErrorCode::phase_terminal), std::string_view("phase_terminal"));
  DF_CHECK_EQ(ToString(ErrorCode::unmet_obligation), std::string_view("unmet_obligation"));
  DF_CHECK_EQ(ToString(ErrorCode::unresolved_residual),
              std::string_view("unresolved_residual"));
  DF_CHECK_EQ(ToString(ErrorCode::evidence_kind_mismatch),
              std::string_view("evidence_kind_mismatch"));
  DF_CHECK_EQ(ToString(ErrorCode::residual_checklist_incomplete),
              std::string_view("residual_checklist_incomplete"));
  DF_CHECK_EQ(ToString(ErrorCode::obligation_already_resolved),
              std::string_view("obligation_already_resolved"));
  DF_CHECK_EQ(ToString(ErrorCode::policy_violation), std::string_view("policy_violation"));
  DF_CHECK_EQ(ToString(ErrorCode::store_locked), std::string_view("store_locked"));
  DF_CHECK_EQ(ToString(ErrorCode::store_corrupt), std::string_view("store_corrupt"));
  DF_CHECK_EQ(ToString(ErrorCode::internal_error), std::string_view("internal_error"));
  DF_CHECK_EQ(ToString(ErrorCode::not_implemented), std::string_view("not_implemented"));

  // Stage names are stable and distinct across every declared stage.
  const ValidationStage stages[] = {
      ValidationStage::parse_shape,     ValidationStage::bounds_limits,
      ValidationStage::identity,        ValidationStage::request_registry,
      ValidationStage::asset_existence, ValidationStage::fence,
      ValidationStage::phase_predicate, ValidationStage::prerequisite,
      ValidationStage::policy,          ValidationStage::ok,
      ValidationStage::infrastructure,
  };
  const std::string_view expected_names[] = {
      "parse_shape", "bounds_limits", "identity",  "request_registry", "asset_existence",
      "fence",       "phase_predicate", "prerequisite", "policy",       "ok",
      "infrastructure",
  };
  const std::size_t stage_count = sizeof(stages) / sizeof(stages[0]);
  DF_CHECK_EQ(stage_count, sizeof(expected_names) / sizeof(expected_names[0]));
  for (std::size_t i = 0; i < stage_count; ++i) {
    const std::string_view name = ToString(stages[i]);
    DF_CHECK_MSG(!name.empty(), "ToString(ValidationStage) must never be empty");
    DF_CHECK_EQ(name, expected_names[i]);
    DF_CHECK_EQ(name, ToString(stages[i]));
    for (std::size_t j = 0; j < i; ++j) {
      DF_CHECK_MSG(ToString(stages[j]) != name, "two stages share one spelling");
    }
  }

  // A numeric value that names no stage is rendered as an unknown stage rather
  // than silently borrowing one.
  const std::string_view unknown_zero = ToString(static_cast<ValidationStage>(0U));
  DF_CHECK_MSG(!unknown_zero.empty(), "an unnamed stage must still render a token");
  DF_CHECK_NE(unknown_zero, std::string_view("ok"));
  DF_CHECK_NE(unknown_zero, std::string_view("infrastructure"));
  DF_CHECK_EQ(unknown_zero, ToString(static_cast<ValidationStage>(0U)));
  DF_CHECK_EQ(ToString(static_cast<ValidationStage>(99U)), unknown_zero);
}

DF_TEST(Errors_IsValidationCodeIsExactlyPrecedenceMembership) {
  for (std::uint32_t raw = 0U; raw <= kHighestDeclaredCode; ++raw) {
    const ErrorCode code = static_cast<ErrorCode>(raw);
    DF_CHECK_EQ(IsValidationCode(code), StageIsInPrecedence(StageOf(code)));
  }

  // The two endpoints of the enum are deliberately outside the precedence.
  DF_CHECK(!IsValidationCode(ErrorCode::ok));
  DF_CHECK(!IsValidationCode(ErrorCode::store_locked));
  DF_CHECK(!IsValidationCode(ErrorCode::internal_error));
  DF_CHECK(!IsValidationCode(static_cast<ErrorCode>(1U)));
  DF_CHECK(IsValidationCode(ErrorCode::malformed_request));
  DF_CHECK(IsValidationCode(ErrorCode::fence_stale));
  DF_CHECK(IsValidationCode(ErrorCode::policy_violation));
  DF_CHECK(!IsValidationCode(static_cast<ErrorCode>(150U)));
}

DF_TEST(Errors_ValidationPrecedenceIsStrictlyIncreasingAndCoversEveryStageInOrder) {
  constexpr ValidationStage kExpected[] = {
      ValidationStage::parse_shape,     ValidationStage::bounds_limits,
      ValidationStage::identity,        ValidationStage::request_registry,
      ValidationStage::asset_existence, ValidationStage::fence,
      ValidationStage::phase_predicate, ValidationStage::prerequisite,
      ValidationStage::policy,
  };
  const std::size_t expected_count = sizeof(kExpected) / sizeof(kExpected[0]);
  const std::size_t actual_count = sizeof(kValidationPrecedence) / sizeof(kValidationPrecedence[0]);
  DF_CHECK_EQ(actual_count, std::size_t{9});
  DF_CHECK_EQ(actual_count, expected_count);
  for (std::size_t i = 0; i < expected_count; ++i) {
    DF_CHECK_EQ(kValidationPrecedence[i], kExpected[i]);
  }
  for (std::size_t i = 1; i < actual_count; ++i) {
    DF_CHECK_MSG(static_cast<std::uint32_t>(kValidationPrecedence[i - 1U]) <
                     static_cast<std::uint32_t>(kValidationPrecedence[i]),
                 "the validation precedence must be strictly increasing");
  }
  DF_CHECK_EQ(static_cast<std::uint32_t>(kValidationPrecedence[0]),
              static_cast<std::uint32_t>(ValidationStage::parse_shape));
  DF_CHECK_EQ(static_cast<std::uint32_t>(kValidationPrecedence[actual_count - 1U]),
              static_cast<std::uint32_t>(ValidationStage::policy));

  // ok and infrastructure are outside the precedence by construction.
  DF_CHECK(!StageIsInPrecedence(ValidationStage::ok));
  DF_CHECK(!StageIsInPrecedence(ValidationStage::infrastructure));
  for (const ValidationStage stage : kValidationPrecedence) {
    DF_CHECK_MSG(StageIsInPrecedence(stage), "a precedence entry is not in the precedence");
  }
}

DF_TEST(Errors_MakeErrorTakesItsStageFromTheCode) {
  for (const CodeRow& row : kDeclaredCodes) {
    const Error error = MakeError(row.code, "synthetic failure");
    DF_CHECK_EQ(error.code, row.code);
    DF_CHECK_EQ(error.stage, row.stage);
    DF_CHECK_EQ(error.stage, StageOf(row.code));
    DF_CHECK_EQ(error.message, std::string("synthetic failure"));
    DF_CHECK_EQ(error.is_error(), row.code != ErrorCode::ok);
    DF_CHECK(error.details.empty());
  }

  const Error ok_error = MakeError(ErrorCode::ok, "no failure");
  DF_CHECK(!ok_error.is_error());
  DF_CHECK_EQ(ok_error.stage, ValidationStage::ok);
  DF_CHECK_EQ(ok_error.to_string(), std::string("[stage=ok code=ok] no failure"));

  const Error fence_error = MakeError(ErrorCode::fence_stale, "fence is stale");
  DF_CHECK(fence_error.is_error());
  DF_CHECK_EQ(fence_error.stage, ValidationStage::fence);
  DF_CHECK_EQ(fence_error.to_string(), std::string("[stage=fence code=fence_stale] fence is stale"));
}

DF_TEST(Errors_ErrorBuilderChainsDetailsInOrderAndBuildPreservesThem) {
  const Error error = ErrorBuilder(ErrorCode::fence_revision_behind, "revision behind")
                          .With("plan", std::string("0000000000000042"))
                          .With("have", std::uint64_t{3})
                          .With("need", std::uint64_t{18446744073709551615ULL})
                          .With("delta", std::int64_t{-6})
                          .With("retryable", false)
                          .With("asset", std::string_view("0000000000000007"))
                          .With("check", "fence")
                          .Build();

  DF_CHECK_EQ(error.code, ErrorCode::fence_revision_behind);
  DF_CHECK_EQ(error.stage, ValidationStage::fence);
  DF_CHECK_EQ(error.message, std::string("revision behind"));
  DF_CHECK(error.is_error());
  DF_CHECK_EQ(error.details.size(), std::size_t{7});

  const char* const expected_keys[] = {"plan",  "have",  "need",     "delta",
                                       "retryable", "asset", "check"};
  const char* const expected_values[] = {"0000000000000042",
                                         "3",
                                         "18446744073709551615",
                                         "-6",
                                         "false",
                                         "0000000000000007",
                                         "fence"};
  for (std::size_t i = 0; i < error.details.size(); ++i) {
    DF_CHECK_EQ(error.details[i].key, std::string(expected_keys[i]));
    DF_CHECK_EQ(error.details[i].value, std::string(expected_values[i]));
  }

  // to_string carries the stage, the code, the message and every detail.
  const std::string rendered = error.to_string();
  DF_CHECK_MSG(rendered.find("stage=fence") != std::string::npos,
               "to_string must name the stage: " + rendered);
  DF_CHECK_MSG(rendered.find("code=fence_revision_behind") != std::string::npos,
               "to_string must name the code: " + rendered);
  DF_CHECK_MSG(rendered.find("revision behind") != std::string::npos,
               "to_string must carry the message: " + rendered);
  for (const auto& detail : error.details) {
    const std::string pair = detail.key + "=" + detail.value;
    DF_CHECK_MSG(rendered.find(pair) != std::string::npos,
                 "to_string must carry the detail " + pair + ": " + rendered);
  }

  // An ErrorBuilder converts to an Error carrying the same content.
  ErrorBuilder mutable_builder(ErrorCode::unmet_obligation, "obligation open");
  const Error converted =
      mutable_builder.With("obligation", std::uint64_t{9}).With("open", true);
  DF_CHECK_EQ(converted.code, ErrorCode::unmet_obligation);
  DF_CHECK_EQ(converted.stage, ValidationStage::prerequisite);
  DF_CHECK_EQ(converted.details.size(), std::size_t{2});
  DF_CHECK_EQ(converted.details[0].value, std::string("9"));
  DF_CHECK_EQ(converted.details[1].value, std::string("true"));
  // Build() is const and repeatable; an untouched builder builds a bare error.
  const ErrorBuilder untouched(ErrorCode::internal_error, "fresh");
  DF_CHECK_EQ(untouched.Build().details.size(), std::size_t{0});
  DF_CHECK_EQ(untouched.Build().to_string(),
              std::string("[stage=infrastructure code=internal_error] fresh"));
  DF_CHECK_EQ(untouched.Build().to_string(), untouched.Build().to_string());
  DF_CHECK_EQ(mutable_builder.Build().details.size(), std::size_t{2});
}

DF_TEST(Errors_FindReturnsTheFirstMatchingDetailAndNullWhenAbsent) {
  const Error error = ErrorBuilder(ErrorCode::unmet_obligation, "obligation open")
                          .With("obligation", "first")
                          .With("asset", "0000000000000007")
                          .With("obligation", "second")
                          .Build();

  const std::string* found = error.find("obligation");
  DF_CHECK(found != nullptr);
  if (found != nullptr) {
    DF_CHECK_EQ(*found, std::string("first"));
    DF_CHECK_NE(*found, std::string("second"));
  }

  const std::string* asset = error.find("asset");
  DF_CHECK(asset != nullptr);
  if (asset != nullptr) {
    DF_CHECK_EQ(*asset, std::string("0000000000000007"));
  }

  DF_CHECK(error.find("missing") == nullptr);
  DF_CHECK(error.find("") == nullptr);
  DF_CHECK(error.find("Obligation") == nullptr);

  const Error bare = MakeError(ErrorCode::internal_error, "no details");
  DF_CHECK(bare.details.empty());
  DF_CHECK(bare.find("anything") == nullptr);
}

DF_TEST(Errors_ResultHoldsAValueOrAnErrorNeverADefault) {
  const Result<int> ok_result = 5;
  DF_CHECK(ok_result.ok());
  DF_CHECK(!ok_result.failed());
  DF_CHECK(static_cast<bool>(ok_result));
  DF_CHECK_EQ(ok_result.value(), 5);
  DF_CHECK_EQ(ok_result.value_or(99), 5);

  const Error failure =
      ErrorBuilder(ErrorCode::out_of_range, "too big").With("limit", std::int64_t{10}).Build();
  const Result<int> bad_result = failure;
  DF_CHECK_CODE(bad_result, ErrorCode::out_of_range);
  DF_CHECK(!bad_result.ok());
  DF_CHECK(bad_result.failed());
  DF_CHECK(!static_cast<bool>(bad_result));
  DF_CHECK_EQ(bad_result.error().code, ErrorCode::out_of_range);
  DF_CHECK_EQ(bad_result.error().stage, ValidationStage::bounds_limits);
  DF_CHECK_EQ(bad_result.error().message, std::string("too big"));
  DF_CHECK_EQ(bad_result.error().details.size(), std::size_t{1});
  DF_CHECK_EQ(bad_result.value_or(99), 99);
  DF_CHECK_EQ(bad_result.value_or(0), 0);

  // Reading the value of a failed Result is a programming error, not a default.
  bool threw = false;
  try {
    (void)bad_result.value();
  } catch (const std::bad_variant_access&) {
    threw = true;
  }
  DF_CHECK_MSG(threw, "value() on a failed Result must throw std::bad_variant_access");

  const Result<std::string> text = std::string("fence");
  DF_CHECK(text.ok());
  DF_CHECK_EQ(text.value(), std::string("fence"));
  DF_CHECK_EQ(text.value().size(), std::size_t{5});

  const Status ok_status = OkStatus();
  DF_CHECK(ok_status.ok());
  const Status failed_status = MakeError(ErrorCode::store_locked, "locked");
  DF_CHECK(!failed_status.ok());
  DF_CHECK_EQ(failed_status.error().code, ErrorCode::store_locked);
  DF_CHECK_EQ(failed_status.error().stage, ValidationStage::infrastructure);
}

DF_TEST(Errors_ResultMapAppliesOnSuccessAndPropagatesOnFailure) {
  const Result<int> ok_result = 21;
  const Result<int> mapped = ok_result.Map([](const int& value) { return value * 2; });
  DF_CHECK(mapped.ok());
  DF_CHECK_EQ(mapped.value(), 42);
  DF_CHECK_EQ(ok_result.value(), 21);

  // Map may change the value type without touching the error path.
  const Result<std::size_t> sized =
      ok_result.Map([](const int& value) { return static_cast<std::size_t>(value); });
  DF_CHECK(sized.ok());
  DF_CHECK_EQ(sized.value(), std::size_t{21});

  // A failure propagates byte for byte: same code, stage, message and details.
  const Error original = ErrorBuilder(ErrorCode::fence_revision_behind, "revision behind")
                             .With("have", std::uint64_t{3})
                             .With("need", std::uint64_t{9})
                             .Build();
  const Result<int> failed = original;
  const Result<int> mapped_failure = failed.Map([](const int& value) { return value * 2; });
  DF_CHECK_CODE(mapped_failure, ErrorCode::fence_revision_behind);
  DF_CHECK(!mapped_failure.ok());
  DF_CHECK_EQ(mapped_failure.error().code, original.code);
  DF_CHECK_EQ(mapped_failure.error().stage, original.stage);
  DF_CHECK_EQ(mapped_failure.error().message, original.message);
  DF_CHECK_EQ(mapped_failure.error().details.size(), original.details.size());
  DF_CHECK(mapped_failure.error().details == original.details);
  DF_CHECK_EQ(mapped_failure.error().to_string(), original.to_string());

  const Result<std::size_t> cross_type_failure =
      failed.Map([](const int& value) { return static_cast<std::size_t>(value); });
  DF_CHECK(!cross_type_failure.ok());
  DF_CHECK_EQ(cross_type_failure.error().code, ErrorCode::fence_revision_behind);
  DF_CHECK_EQ(cross_type_failure.error().to_string(), original.to_string());

  // The propagation macros return the error unchanged and never a default value.
  const Result<int> doubled = DoubledOrPropagated(Result<int>(21));
  DF_CHECK(doubled.ok());
  DF_CHECK_EQ(doubled.value(), 42);
  const Result<int> propagated = DoubledOrPropagated(failed);
  DF_CHECK_CODE(propagated, ErrorCode::fence_revision_behind);
  DF_CHECK(!propagated.ok());
  DF_CHECK_EQ(propagated.error().code, ErrorCode::fence_revision_behind);
  DF_CHECK_EQ(propagated.error().to_string(), original.to_string());
}

DF_TEST_MAIN()

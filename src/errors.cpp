// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0

#include "decommissioning_fabric/errors.hpp"

#include <utility>

namespace decommissioning_fabric {

std::string_view ToString(ValidationStage stage) noexcept {
  switch (stage) {
    case ValidationStage::parse_shape: return "parse_shape";
    case ValidationStage::bounds_limits: return "bounds_limits";
    case ValidationStage::identity: return "identity";
    case ValidationStage::request_registry: return "request_registry";
    case ValidationStage::asset_existence: return "asset_existence";
    case ValidationStage::fence: return "fence";
    case ValidationStage::phase_predicate: return "phase_predicate";
    case ValidationStage::prerequisite: return "prerequisite";
    case ValidationStage::policy: return "policy";
    case ValidationStage::ok: return "ok";
    case ValidationStage::infrastructure: return "infrastructure";
  }
  return "unknown_stage";
}

namespace {

/// The single authoritative code -> stage table. Both ToString and StageOf walk
/// kCodeTable, so a code can never be added without a stage.
struct CodeRow {
  ErrorCode code;
  ValidationStage stage;
  std::string_view name;
};

constexpr CodeRow kCodeTable[] = {
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
    {ErrorCode::phase_does_not_permit, ValidationStage::phase_predicate, "phase_does_not_permit"},

    {ErrorCode::unmet_obligation, ValidationStage::prerequisite, "unmet_obligation"},
    {ErrorCode::unresolved_residual, ValidationStage::prerequisite, "unresolved_residual"},
    {ErrorCode::authority_unknown, ValidationStage::prerequisite, "authority_unknown"},
    {ErrorCode::authority_active, ValidationStage::prerequisite, "authority_active"},
    {ErrorCode::missing_evidence, ValidationStage::prerequisite, "missing_evidence"},
    {ErrorCode::evidence_kind_mismatch, ValidationStage::prerequisite, "evidence_kind_mismatch"},
    {ErrorCode::evidence_stale, ValidationStage::prerequisite, "evidence_stale"},
    {ErrorCode::isolation_not_observed, ValidationStage::prerequisite, "isolation_not_observed"},
    {ErrorCode::removal_not_authorized, ValidationStage::prerequisite, "removal_not_authorized"},
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

const CodeRow* FindRow(ErrorCode code) noexcept {
  for (const CodeRow& row : kCodeTable) {
    if (row.code == code) {
      return &row;
    }
  }
  return nullptr;
}

}  // namespace

std::string_view ToString(ErrorCode code) noexcept {
  const CodeRow* row = FindRow(code);
  return row == nullptr ? std::string_view("unrecognised_error_code") : row->name;
}

ValidationStage StageOf(ErrorCode code) noexcept {
  const CodeRow* row = FindRow(code);
  return row == nullptr ? ValidationStage::infrastructure : row->stage;
}

bool IsValidationCode(ErrorCode code) noexcept {
  const ValidationStage stage = StageOf(code);
  return stage != ValidationStage::infrastructure && stage != ValidationStage::ok;
}

const std::string* Error::find(std::string_view key) const noexcept {
  for (const ErrorDetail& detail : details) {
    if (detail.key == key) {
      return &detail.value;
    }
  }
  return nullptr;
}

std::string Error::to_string() const {
  std::string out;
  out += "[stage=";
  out += ToString(stage);
  out += " code=";
  out += ToString(code);
  out += "] ";
  out += message;
  for (const ErrorDetail& detail : details) {
    out += ' ';
    out += detail.key;
    out += '=';
    out += detail.value;
  }
  return out;
}

Error MakeError(ErrorCode code, std::string message) {
  Error error;
  error.code = code;
  error.stage = StageOf(code);
  error.message = std::move(message);
  return error;
}

ErrorBuilder::ErrorBuilder(ErrorCode code, std::string message)
    : error_(MakeError(code, std::move(message))) {}

ErrorBuilder& ErrorBuilder::With(std::string key, std::string value) {
  error_.details.push_back(ErrorDetail{std::move(key), std::move(value)});
  return *this;
}

ErrorBuilder& ErrorBuilder::With(std::string key, std::uint64_t value) {
  return With(std::move(key), std::to_string(value));
}

ErrorBuilder& ErrorBuilder::With(std::string key, std::int64_t value) {
  return With(std::move(key), std::to_string(value));
}

ErrorBuilder& ErrorBuilder::With(std::string key, bool value) {
  return With(std::move(key), std::string(value ? "true" : "false"));
}

ErrorBuilder& ErrorBuilder::With(std::string key, std::string_view value) {
  return With(std::move(key), std::string(value));
}

ErrorBuilder& ErrorBuilder::With(std::string key, const char* value) {
  return With(std::move(key), std::string_view(value));
}

Error ErrorBuilder::Build() const {
  return error_;
}

}  // namespace decommissioning_fabric

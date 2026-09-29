// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0

#include "decommissioning_fabric/plan.hpp"

#include <algorithm>
#include <array>
#include <string>

namespace decommissioning_fabric {
namespace {

[[nodiscard]] std::string U64Hex(std::uint64_t value) {
  return detail::to_hex_fixed(value, 16);
}

[[nodiscard]] std::string U32Hex(std::uint32_t value) {
  return detail::to_hex_fixed(value, 8);
}

[[nodiscard]] bool ParseFixedHex(std::string_view token, std::size_t digits,
                                 std::uint64_t& out) {
  if (token.size() != digits) {
    return false;
  }
  std::uint64_t value = 0;
  for (const char ch : token) {
    std::uint8_t nibble = 0;
    if (ch >= '0' && ch <= '9') {
      nibble = static_cast<std::uint8_t>(ch - '0');
    } else if (ch >= 'a' && ch <= 'f') {
      nibble = static_cast<std::uint8_t>(ch - 'a' + 10);
    } else if (ch >= 'A' && ch <= 'F') {
      nibble = static_cast<std::uint8_t>(ch - 'A' + 10);
    } else {
      return false;
    }
    value = (value << 4U) | static_cast<std::uint64_t>(nibble);
  }
  out = value;
  return true;
}

[[nodiscard]] bool IsFieldUnset(const PlanFence& fence, FenceField field) noexcept {
  switch (field) {
    case FenceField::asset: return fence.asset.is_unset();
    case FenceField::site: return fence.site.is_unset();
    case FenceField::rack: return fence.rack.is_unset();
    case FenceField::hardware_generation: return fence.hardware_generation.is_unset();
    case FenceField::firmware_generation: return fence.firmware_generation.is_unset();
    case FenceField::lifecycle_generation: return fence.lifecycle_generation.is_unset();
    case FenceField::dependency_generation: return fence.dependency_generation.is_unset();
    case FenceField::policy_generation: return fence.policy_generation.is_unset();
    case FenceField::capacity_generation: return fence.capacity_generation.is_unset();
    case FenceField::topology_generation: return fence.topology_generation.is_unset();
    case FenceField::maintenance_generation: return fence.maintenance_generation.is_unset();
    case FenceField::facility_epoch: return fence.facility_epoch.is_unset();
    case FenceField::active_obligation_count: return false;
    case FenceField::active_obligation_digest: return false;
    case FenceField::revision: return fence.revision.is_unset();
    case FenceField::none: return false;
  }
  return false;
}

/// True when the two fences disagree on the named binding field.
[[nodiscard]] bool FieldDiffers(const PlanFence& lhs, const PlanFence& rhs,
                                FenceField field) noexcept {
  switch (field) {
    case FenceField::asset: return lhs.asset != rhs.asset;
    case FenceField::site: return lhs.site != rhs.site;
    case FenceField::rack: return lhs.rack != rhs.rack;
    case FenceField::hardware_generation:
      return lhs.hardware_generation != rhs.hardware_generation;
    case FenceField::firmware_generation:
      return lhs.firmware_generation != rhs.firmware_generation;
    case FenceField::lifecycle_generation:
      return lhs.lifecycle_generation != rhs.lifecycle_generation;
    case FenceField::dependency_generation:
      return lhs.dependency_generation != rhs.dependency_generation;
    case FenceField::policy_generation:
      return lhs.policy_generation != rhs.policy_generation;
    case FenceField::capacity_generation:
      return lhs.capacity_generation != rhs.capacity_generation;
    case FenceField::topology_generation:
      return lhs.topology_generation != rhs.topology_generation;
    case FenceField::maintenance_generation:
      return lhs.maintenance_generation != rhs.maintenance_generation;
    case FenceField::facility_epoch: return lhs.facility_epoch != rhs.facility_epoch;
    case FenceField::active_obligation_count:
      return lhs.active_obligation_count != rhs.active_obligation_count;
    case FenceField::active_obligation_digest:
      return lhs.active_obligation_digest != rhs.active_obligation_digest;
    case FenceField::revision: return lhs.revision != rhs.revision;
    case FenceField::none: return false;
  }
  return false;
}

}  // namespace

GenerationBinding PlanFence::binding() const noexcept {
  GenerationBinding out;
  out.asset = asset;
  out.site = site;
  out.rack = rack;
  out.lifecycle_generation = lifecycle_generation;
  out.hardware_generation = hardware_generation;
  out.firmware_generation = firmware_generation;
  out.facility_epoch = facility_epoch;
  out.policy_generation = policy_generation;
  out.dependency_generation = dependency_generation;
  out.capacity_generation = capacity_generation;
  out.topology_generation = topology_generation;
  out.maintenance_generation = maintenance_generation;
  return out;
}

Digest BindingDigest(const GenerationBinding& binding) {
  std::string canonical;
  canonical.reserve(256);
  canonical += binding.asset.to_hex();
  canonical += '|';
  canonical += binding.site.to_hex();
  canonical += '|';
  canonical += binding.rack.to_hex();
  canonical += '|';
  canonical += U32Hex(binding.lifecycle_generation.value());
  canonical += '|';
  canonical += U32Hex(binding.hardware_generation.value());
  canonical += '|';
  canonical += U32Hex(binding.firmware_generation.value());
  canonical += '|';
  canonical += U32Hex(binding.facility_epoch.value());
  canonical += '|';
  canonical += U32Hex(binding.policy_generation.value());
  canonical += '|';
  canonical += U32Hex(binding.dependency_generation.value());
  canonical += '|';
  canonical += U32Hex(binding.capacity_generation.value());
  canonical += '|';
  canonical += U32Hex(binding.topology_generation.value());
  canonical += '|';
  canonical += U32Hex(binding.maintenance_generation.value());
  return Sha256::Of(canonical);
}

bool PlanFence::all_required_set() const noexcept {
  return first_unset_field() == FenceField::none && plan.is_set() && revision.is_set();
}

FenceField PlanFence::first_unset_field() const noexcept {
  for (const FenceField field : kFenceFieldOrder) {
    if (IsFieldUnset(*this, field)) {
      return field;
    }
  }
  return FenceField::none;
}

std::string_view ToString(FenceField field) noexcept {
  switch (field) {
    case FenceField::none: return "none";
    case FenceField::asset: return "asset";
    case FenceField::site: return "site";
    case FenceField::rack: return "rack";
    case FenceField::hardware_generation: return "hardware_generation";
    case FenceField::firmware_generation: return "firmware_generation";
    case FenceField::lifecycle_generation: return "lifecycle_generation";
    case FenceField::dependency_generation: return "dependency_generation";
    case FenceField::policy_generation: return "policy_generation";
    case FenceField::capacity_generation: return "capacity_generation";
    case FenceField::topology_generation: return "topology_generation";
    case FenceField::maintenance_generation: return "maintenance_generation";
    case FenceField::facility_epoch: return "facility_epoch";
    case FenceField::active_obligation_count: return "active_obligation_count";
    case FenceField::active_obligation_digest: return "active_obligation_digest";
    case FenceField::revision: return "revision";
  }
  return "none";
}

std::string RenderFenceField(const PlanFence& fence, FenceField field) {
  switch (field) {
    case FenceField::asset: return fence.asset.to_hex();
    case FenceField::site: return fence.site.to_hex();
    case FenceField::rack: return fence.rack.to_hex();
    case FenceField::hardware_generation: return U32Hex(fence.hardware_generation.value());
    case FenceField::firmware_generation: return U32Hex(fence.firmware_generation.value());
    case FenceField::lifecycle_generation: return U32Hex(fence.lifecycle_generation.value());
    case FenceField::dependency_generation: return U32Hex(fence.dependency_generation.value());
    case FenceField::policy_generation: return U32Hex(fence.policy_generation.value());
    case FenceField::capacity_generation: return U32Hex(fence.capacity_generation.value());
    case FenceField::topology_generation: return U32Hex(fence.topology_generation.value());
    case FenceField::maintenance_generation: return U32Hex(fence.maintenance_generation.value());
    case FenceField::facility_epoch: return U32Hex(fence.facility_epoch.value());
    case FenceField::active_obligation_count: return std::to_string(fence.active_obligation_count);
    case FenceField::active_obligation_digest: return fence.active_obligation_digest.to_hex();
    case FenceField::revision: return U64Hex(fence.revision.value());
    case FenceField::none: return "none";
  }
  return "none";
}

ErrorCode FenceComparison::code() const noexcept {
  switch (classification) {
    case FenceClass::current: return ErrorCode::ok;
    case FenceClass::stale: return ErrorCode::fence_stale;
    case FenceClass::revision_behind: return ErrorCode::fence_revision_behind;
    case FenceClass::superseded: return ErrorCode::fence_superseded;
    case FenceClass::malformed: return ErrorCode::fence_malformed;
  }
  return ErrorCode::internal_error;
}

FenceComparison ClassifyFence(const PlanFence& requested, const PlanFence& current) {
  FenceComparison comparison;

  // 1. A different asset is not a stale plan; it is a different plan entirely.
  if (requested.asset != current.asset) {
    comparison.classification = FenceClass::superseded;
    comparison.first_mismatch = FenceField::asset;
    comparison.requested_value = RenderFenceField(requested, FenceField::asset);
    comparison.current_value = RenderFenceField(current, FenceField::asset);
    return comparison;
  }

  // 2. A fence with an unset unit is malformed, never silently defaulted.
  const FenceField unset = requested.first_unset_field();
  if (unset != FenceField::none || !requested.plan.is_set() || !requested.revision.is_set()) {
    comparison.classification = FenceClass::malformed;
    comparison.first_mismatch = unset != FenceField::none ? unset : FenceField::revision;
    comparison.requested_value = "unset";
    comparison.current_value = RenderFenceField(current, comparison.first_mismatch);
    return comparison;
  }

  // 3. First binding mismatch, in the fixed field order.
  for (const FenceField field : kFenceFieldOrder) {
    if (FieldDiffers(requested, current, field)) {
      comparison.classification = FenceClass::stale;
      comparison.first_mismatch = field;
      comparison.requested_value = RenderFenceField(requested, field);
      comparison.current_value = RenderFenceField(current, field);
      return comparison;
    }
  }

  // 4. Same binding, older revision: the caller read a generation that has since
  //    been superseded by our own later mutation.
  if (requested.revision < current.revision) {
    comparison.classification = FenceClass::revision_behind;
    comparison.first_mismatch = FenceField::revision;
    comparison.requested_value = RenderFenceField(requested, FenceField::revision);
    comparison.current_value = RenderFenceField(current, FenceField::revision);
    return comparison;
  }

  // 5. Same binding, newer revision: this runtime never published it.
  if (current.revision < requested.revision) {
    comparison.classification = FenceClass::stale;
    comparison.first_mismatch = FenceField::revision;
    comparison.requested_value = RenderFenceField(requested, FenceField::revision);
    comparison.current_value = RenderFenceField(current, FenceField::revision);
    return comparison;
  }

  comparison.classification = FenceClass::current;
  return comparison;
}

std::string EncodeFenceToken(const PlanFence& fence) {
  std::string plain;
  plain.reserve(200);
  plain += fence.asset.to_hex();
  plain += ':';
  plain += fence.site.to_hex();
  plain += ':';
  plain += fence.rack.to_hex();
  plain += ':';
  plain += U32Hex(fence.lifecycle_generation.value());
  plain += ':';
  plain += U32Hex(fence.hardware_generation.value());
  plain += ':';
  plain += U32Hex(fence.firmware_generation.value());
  plain += ':';
  plain += U32Hex(fence.facility_epoch.value());
  plain += ':';
  plain += U32Hex(fence.policy_generation.value());
  plain += ':';
  plain += U32Hex(fence.dependency_generation.value());
  plain += ':';
  plain += U32Hex(fence.capacity_generation.value());
  plain += ':';
  plain += U32Hex(fence.topology_generation.value());
  plain += ':';
  plain += U32Hex(fence.maintenance_generation.value());
  plain += ':';
  plain += U32Hex(fence.active_obligation_count);
  plain += ':';
  plain += fence.active_obligation_digest.to_hex();
  plain += ':';
  plain += fence.plan.to_hex();
  plain += ':';
  plain += U64Hex(fence.revision.value());
  return HexEncode(plain);
}

Result<PlanFence> DecodeFenceToken(std::string_view token) {
  constexpr std::size_t kFenceTokenFields = 16;

  if (token.empty()) {
    return MakeError(ErrorCode::malformed_hex, "fence token is empty");
  }
  if ((token.size() % 2U) != 0U) {
    return ErrorBuilder(ErrorCode::malformed_hex, "fence token has odd hex length")
        .With("length", static_cast<std::uint64_t>(token.size()))
        .Build();
  }
  // The exact width of every field. Defined once, immediately above the bound
  // derived from it, so the encoder, the bound, and the per-field parser cannot
  // drift apart again.
  constexpr std::array<std::size_t, kFenceTokenFields> kWidths = {
      16U, 16U, 16U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 64U, 16U, 16U};
  constexpr std::size_t kPlainChars = []() constexpr {
    std::size_t total = 0;
    for (const std::size_t width : kWidths) {
      total += width;
    }
    return total + (kFenceTokenFields - 1U);
  }();

  if ((token.size() / 2U) > kPlainChars) {
    return ErrorBuilder(ErrorCode::out_of_range, "fence token is longer than any valid fence")
        .With("length", static_cast<std::uint64_t>(token.size()))
        .Build();
  }

  const std::optional<std::string> plain = HexDecode(token, kPlainChars);
  if (!plain.has_value()) {
    return MakeError(ErrorCode::malformed_hex, "fence token is not valid hexadecimal");
  }

  std::array<std::string_view, kFenceTokenFields> fields{};
  std::size_t field_count = 0;
  std::size_t start = 0;
  for (std::size_t i = 0; i <= plain->size(); ++i) {
    if (i == plain->size() || (*plain)[i] == ':') {
      if (field_count >= kFenceTokenFields) {
        return MakeError(ErrorCode::malformed_request, "fence token has too many fields");
      }
      fields[field_count] = std::string_view(*plain).substr(start, i - start);
      ++field_count;
      start = i + 1U;
    }
  }
  if (field_count != kFenceTokenFields) {
    return ErrorBuilder(ErrorCode::malformed_request, "fence token has the wrong field count")
        .With("expected", static_cast<std::uint64_t>(kFenceTokenFields))
        .With("actual", static_cast<std::uint64_t>(field_count))
        .Build();
  }

  std::array<std::uint64_t, kFenceTokenFields> values{};
  for (std::size_t i = 0; i < kFenceTokenFields; ++i) {
    if (!ParseFixedHex(fields[i], kWidths[i], values[i])) {
      return ErrorBuilder(ErrorCode::malformed_hex, "fence token field is malformed")
          .With("index", static_cast<std::uint64_t>(i))
          .With("expected_digits", static_cast<std::uint64_t>(kWidths[i]))
          .With("actual_digits", static_cast<std::uint64_t>(fields[i].size()))
          .Build();
    }
  }

  if (values[3] > 0xFFFFFFFFULL || values[4] > 0xFFFFFFFFULL || values[5] > 0xFFFFFFFFULL ||
      values[6] > 0xFFFFFFFFULL || values[7] > 0xFFFFFFFFULL || values[8] > 0xFFFFFFFFULL ||
      values[9] > 0xFFFFFFFFULL || values[10] > 0xFFFFFFFFULL || values[11] > 0xFFFFFFFFULL ||
      values[12] > 0xFFFFFFFFULL) {
    return MakeError(ErrorCode::out_of_range, "fence token generation exceeds 32 bits");
  }

  PlanFence fence;
  fence.asset = AssetId::FromValue(values[0]);
  fence.site = SiteId::FromValue(values[1]);
  fence.rack = RackId::FromValue(values[2]);
  fence.lifecycle_generation = LifecycleGeneration::FromValue(static_cast<std::uint32_t>(values[3]));
  fence.hardware_generation = HardwareGeneration::FromValue(static_cast<std::uint32_t>(values[4]));
  fence.firmware_generation = FirmwareGeneration::FromValue(static_cast<std::uint32_t>(values[5]));
  fence.facility_epoch = FacilityEpoch::FromValue(static_cast<std::uint32_t>(values[6]));
  fence.policy_generation = PolicyGeneration::FromValue(static_cast<std::uint32_t>(values[7]));
  fence.dependency_generation =
      DependencyGeneration::FromValue(static_cast<std::uint32_t>(values[8]));
  fence.capacity_generation = CapacityGeneration::FromValue(static_cast<std::uint32_t>(values[9]));
  fence.topology_generation = TopologyGeneration::FromValue(static_cast<std::uint32_t>(values[10]));
  fence.maintenance_generation =
      MaintenanceGeneration::FromValue(static_cast<std::uint32_t>(values[11]));
  fence.active_obligation_count = static_cast<std::uint32_t>(values[12]);
  fence.active_obligation_digest = Digest::FromHex(fields[13]).value_or(Digest{});
  fence.plan = PlanId::FromValue(values[14]);
  fence.revision = Revision::FromValue(values[15]);
  return fence;
}

std::string_view ToString(RequestKind kind) noexcept {
  switch (kind) {
    case RequestKind::unknown: return "unknown";
    case RequestKind::create_plan: return "create_plan";
    case RequestKind::assess_dependencies: return "assess_dependencies";
    case RequestKind::set_drain_requirement: return "set_drain_requirement";
    case RequestKind::acknowledge_drain: return "acknowledge_drain";
    case RequestKind::satisfy_drain: return "satisfy_drain";
    case RequestKind::waive_drain: return "waive_drain";
    case RequestKind::begin_draining: return "begin_draining";
    case RequestKind::conclude_draining: return "conclude_draining";
    case RequestKind::record_revocation: return "record_revocation";
    case RequestKind::conclude_authority_revocation: return "conclude_authority_revocation";
    case RequestKind::set_residual_disposition: return "set_residual_disposition";
    case RequestKind::record_policy_exception: return "record_policy_exception";
    case RequestKind::declare_isolation_ready: return "declare_isolation_ready";
    case RequestKind::authorize_removal: return "authorize_removal";
    case RequestKind::observe_removal: return "observe_removal";
    case RequestKind::finalize_decommissioning: return "finalize_decommissioning";
    case RequestKind::cancel_plan: return "cancel_plan";
    case RequestKind::fail_plan: return "fail_plan";
    case RequestKind::block_plan: return "block_plan";
    case RequestKind::resume_plan: return "resume_plan";
    case RequestKind::ingest_evidence: return "ingest_evidence";
  }
  return "unknown";
}

Phase BoundaryTargetPhase(RequestKind kind) noexcept {
  switch (kind) {
    case RequestKind::create_plan: return Phase::requested;
    case RequestKind::assess_dependencies: return Phase::dependency_assessment;
    case RequestKind::set_drain_requirement: return Phase::drain_required;
    case RequestKind::begin_draining: return Phase::draining;
    case RequestKind::conclude_draining: return Phase::authority_revocation;
    case RequestKind::declare_isolation_ready: return Phase::isolation_ready;
    case RequestKind::authorize_removal: return Phase::removal_authorized;
    case RequestKind::observe_removal: return Phase::removed_observed;
    case RequestKind::finalize_decommissioning: return Phase::decommissioned;
    case RequestKind::cancel_plan: return Phase::cancelled;
    case RequestKind::fail_plan: return Phase::failed;
    case RequestKind::block_plan: return Phase::blocked;
    // Resume returns to the recorded resume phase, which is state dependent.
    case RequestKind::resume_plan:
    case RequestKind::unknown:
    case RequestKind::acknowledge_drain:
    case RequestKind::satisfy_drain:
    case RequestKind::waive_drain:
    case RequestKind::record_revocation:
    case RequestKind::conclude_authority_revocation:
    case RequestKind::set_residual_disposition:
    case RequestKind::record_policy_exception:
    case RequestKind::ingest_evidence:
      return Phase::unknown;
  }
  return Phase::unknown;
}

RequestKind RequestKindFromString(std::string_view name) noexcept {
  for (std::uint32_t i = 0; i < static_cast<std::uint32_t>(kRequestKindCount); ++i) {
    const auto kind = static_cast<RequestKind>(i);
    if (ToString(kind) == name) {
      return kind;
    }
  }
  return RequestKind::unknown;
}

Digest ActiveObligationDigest(const std::vector<DrainObligation>& obligations) {
  std::vector<const DrainObligation*> active;
  active.reserve(obligations.size());
  for (const DrainObligation& obligation : obligations) {
    if (obligation.blocks_progress()) {
      active.push_back(&obligation);
    }
  }
  // Sort by ObligationId so the digest does not depend on insertion order.
  std::sort(active.begin(), active.end(),
            [](const DrainObligation* lhs, const DrainObligation* rhs) {
              return lhs->id < rhs->id;
            });

  std::string canonical;
  for (const DrainObligation* obligation : active) {
    canonical += obligation->id.to_hex();
    canonical += '|';
    canonical += ToString(obligation->kind);
    canonical += '|';
    canonical += ToString(obligation->protected_class);
    canonical += '|';
    canonical += ToString(obligation->state);
    canonical += ';';
  }
  return Sha256::Of(canonical);
}

void RefreshObligationBinding(RetirementCase& record) {
  std::uint32_t count = 0;
  for (const DrainObligation& obligation : record.obligations) {
    if (obligation.blocks_progress()) {
      ++count;
    }
  }
  record.fence.active_obligation_count = count;
  record.fence.active_obligation_digest = ActiveObligationDigest(record.obligations);
}

const DrainObligation* FindObligation(const RetirementCase& record, ObligationId id) noexcept {
  for (const DrainObligation& obligation : record.obligations) {
    if (obligation.id == id) {
      return &obligation;
    }
  }
  return nullptr;
}

DrainObligation* FindObligation(RetirementCase& record, ObligationId id) noexcept {
  for (DrainObligation& obligation : record.obligations) {
    if (obligation.id == id) {
      return &obligation;
    }
  }
  return nullptr;
}

const ResidualItem* FindResidual(const RetirementCase& record, ResidualItemId id) noexcept {
  for (const ResidualItem& item : record.residual) {
    if (item.id == id) {
      return &item;
    }
  }
  return nullptr;
}

ResidualItem* FindResidual(RetirementCase& record, ResidualItemId id) noexcept {
  for (ResidualItem& item : record.residual) {
    if (item.id == id) {
      return &item;
    }
  }
  return nullptr;
}

const EvidenceRef* FindEvidence(const RetirementCase& record, EvidenceId id) noexcept {
  for (const EvidenceRef& evidence : record.evidence) {
    if (evidence.id == id) {
      return &evidence;
    }
  }
  return nullptr;
}

const PolicyException* FindException(const RetirementCase& record, ExceptionId id) noexcept {
  for (const PolicyException& exception : record.exceptions) {
    if (exception.id == id) {
      return &exception;
    }
  }
  return nullptr;
}

const IssuedRequest* FindIssued(const RetirementCase& record, AttemptId attempt) noexcept {
  for (const IssuedRequest& issued : record.registry) {
    if (issued.attempt == attempt) {
      return &issued;
    }
  }
  return nullptr;
}

const RecordedNote* RetirementCase::find_note(std::string_view code) const noexcept {
  for (const RecordedNote& entry : notes) {
    if (entry.code == code) {
      return &entry;
    }
  }
  return nullptr;
}

}  // namespace decommissioning_fabric

// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0

#include "decommissioning_fabric/format.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <utility>

namespace decommissioning_fabric {
namespace {

// ---------------------------------------------------------------------------
// Enum range checks. Every stored enumerator is range checked on decode; an
// out-of-range value is rejected rather than reinterpreted.
// ---------------------------------------------------------------------------

[[nodiscard]] bool InRange(std::uint32_t value, std::uint32_t max_value) noexcept {
  return value <= max_value;
}

[[nodiscard]] bool DomainBitValid(std::uint32_t bits) noexcept {
  for (const AuthorityDomain domain : kAuthorityDomains) {
    if (BitOf(domain) == bits) {
      return true;
    }
  }
  return false;
}

[[nodiscard]] bool MaskValid(std::uint32_t bits) noexcept {
  return (bits & ~kAllAuthorityBits) == 0U;
}

// ---------------------------------------------------------------------------
// Small parsing helpers
// ---------------------------------------------------------------------------

[[nodiscard]] Status ExpectLine(PayloadReader& reader, std::string_view expected) {
  auto has_line = reader.NextLine();
  if (!has_line.ok()) {
    return has_line.error();
  }
  if (!has_line.value()) {
    return ErrorBuilder(ErrorCode::malformed_payload, "payload ended before a required line")
        .With("expected", expected)
        .With("line", static_cast<std::uint64_t>(reader.line_number()))
        .Build();
  }
  auto tag = reader.Tag();
  if (!tag.ok()) {
    return tag.error();
  }
  if (tag.value() != expected) {
    return ErrorBuilder(ErrorCode::trailing_data, "unexpected record tag")
        .With("expected", expected)
        .With("actual", tag.value())
        .With("line", static_cast<std::uint64_t>(reader.line_number()))
        .Build();
  }
  return OkStatus();
}

[[nodiscard]] Result<std::uint32_t> ReadBoundedCount(PayloadReader& reader,
                                                     std::uint64_t limit,
                                                     std::string_view what) {
  auto count = reader.Num32();
  if (!count.ok()) {
    return count.error();
  }
  if (count.value() > limit) {
    return ErrorBuilder(ErrorCode::too_many_items, "declared count exceeds the supported bound")
        .With("what", what)
        .With("count", static_cast<std::uint64_t>(count.value()))
        .With("limit", limit)
        .Build();
  }
  return count.value();
}

// ---------------------------------------------------------------------------
// Field encoders / decoders
// ---------------------------------------------------------------------------

void WriteFence(PayloadWriter& writer, const PlanFence& fence) {
  writer.Tok("FENCE");
  writer.Num(fence.asset.value());
  writer.Num(fence.site.value());
  writer.Num(fence.rack.value());
  writer.Num32(fence.lifecycle_generation.value());
  writer.Num32(fence.hardware_generation.value());
  writer.Num32(fence.firmware_generation.value());
  writer.Num32(fence.facility_epoch.value());
  writer.Num32(fence.policy_generation.value());
  writer.Num32(fence.dependency_generation.value());
  writer.Num32(fence.capacity_generation.value());
  writer.Num32(fence.topology_generation.value());
  writer.Num32(fence.maintenance_generation.value());
  writer.Num32(fence.active_obligation_count);
  writer.DigestField(fence.active_obligation_digest);
  writer.Num(fence.plan.value());
  writer.Num(fence.revision.value());
  writer.EndLine();
}

[[nodiscard]] Status ReadFence(PayloadReader& reader, PlanFence& fence) {
  DF_TRY_DECL(std::uint64_t, asset, reader.Num());
  DF_TRY_DECL(std::uint64_t, site, reader.Num());
  DF_TRY_DECL(std::uint64_t, rack, reader.Num());
  DF_TRY_DECL(std::uint32_t, lifecycle, reader.Num32());
  DF_TRY_DECL(std::uint32_t, hardware, reader.Num32());
  DF_TRY_DECL(std::uint32_t, firmware, reader.Num32());
  DF_TRY_DECL(std::uint32_t, facility_epoch, reader.Num32());
  DF_TRY_DECL(std::uint32_t, policy, reader.Num32());
  DF_TRY_DECL(std::uint32_t, dependency, reader.Num32());
  DF_TRY_DECL(std::uint32_t, capacity, reader.Num32());
  DF_TRY_DECL(std::uint32_t, topology, reader.Num32());
  DF_TRY_DECL(std::uint32_t, maintenance, reader.Num32());
  DF_TRY_DECL(std::uint32_t, active_count, reader.Num32());
  DF_TRY_DECL(Digest, active_digest, reader.DigestField());
  DF_TRY_DECL(std::uint64_t, plan, reader.Num());
  DF_TRY_DECL(std::uint64_t, revision, reader.Num());
  DF_TRY(reader.EndOfLine());

  fence.asset = AssetId::FromValue(asset);
  fence.site = SiteId::FromValue(site);
  fence.rack = RackId::FromValue(rack);
  fence.lifecycle_generation = LifecycleGeneration::FromValue(lifecycle);
  fence.hardware_generation = HardwareGeneration::FromValue(hardware);
  fence.firmware_generation = FirmwareGeneration::FromValue(firmware);
  fence.facility_epoch = FacilityEpoch::FromValue(facility_epoch);
  fence.policy_generation = PolicyGeneration::FromValue(policy);
  fence.dependency_generation = DependencyGeneration::FromValue(dependency);
  fence.capacity_generation = CapacityGeneration::FromValue(capacity);
  fence.topology_generation = TopologyGeneration::FromValue(topology);
  fence.maintenance_generation = MaintenanceGeneration::FromValue(maintenance);
  fence.active_obligation_count = active_count;
  fence.active_obligation_digest = active_digest;
  fence.plan = PlanId::FromValue(plan);
  fence.revision = Revision::FromValue(revision);
  return OkStatus();
}

void WriteBlocker(PayloadWriter& writer, const Blocker& blocker) {
  writer.Tok("BLOCKER");
  writer.Num32(static_cast<std::uint32_t>(blocker.reason));
  writer.Num32(static_cast<std::uint32_t>(blocker.code));
  writer.Num32(static_cast<std::uint32_t>(blocker.observed_phase));
  writer.Num32(static_cast<std::uint32_t>(blocker.blocked_at));
  writer.Str(blocker.detail);
  writer.Str(blocker.required_action);
  writer.Num(blocker.observed.size());
  writer.EndLine();
  for (const ErrorDetail& entry : blocker.observed) {
    writer.Tok("OBS");
    writer.Str(entry.key);
    writer.Str(entry.value);
    writer.EndLine();
  }
}

[[nodiscard]] Status ReadBlocker(PayloadReader& reader, Blocker& blocker) {
  DF_TRY_DECL(std::uint32_t, reason, reader.Num32());
  DF_TRY_DECL(std::uint32_t, code, reader.Num32());
  DF_TRY_DECL(std::uint32_t, observed_phase, reader.Num32());
  DF_TRY_DECL(std::uint32_t, blocked_at, reader.Num32());
  DF_TRY_DECL(std::string, detail, reader.Str());
  DF_TRY_DECL(std::string, required_action, reader.Str());
  DF_TRY_DECL(std::uint32_t, observed_count, reader.Num32());
  DF_TRY(reader.EndOfLine());

  if (!InRange(reason, 23U)) {
    return ErrorBuilder(ErrorCode::malformed_payload, "blocker reason out of range")
        .With("value", static_cast<std::uint64_t>(reason))
        .Build();
  }
  if (code > static_cast<std::uint32_t>(ErrorCode::not_implemented)) {
    return ErrorBuilder(ErrorCode::malformed_payload, "error code out of range")
        .With("value", static_cast<std::uint64_t>(code))
        .Build();
  }
  if (!InRange(observed_phase, 14U) || !InRange(blocked_at, 14U)) {
    return MakeError(ErrorCode::malformed_payload, "blocker phase out of range");
  }
  if (observed_count > kMaxObservedDetails) {
    return ErrorBuilder(ErrorCode::too_many_items, "blocker has too many observed details")
        .With("count", static_cast<std::uint64_t>(observed_count))
        .With("limit", static_cast<std::uint64_t>(kMaxObservedDetails))
        .Build();
  }

  blocker.reason = static_cast<BlockerReason>(reason);
  blocker.code = static_cast<ErrorCode>(code);
  blocker.observed_phase = static_cast<Phase>(observed_phase);
  blocker.blocked_at = static_cast<Phase>(blocked_at);
  blocker.detail = std::move(detail);
  blocker.required_action = std::move(required_action);
  blocker.observed.clear();
  for (std::uint32_t i = 0; i < observed_count; ++i) {
    DF_TRY(ExpectLine(reader, "OBS"));
    DF_TRY_DECL(std::string, key, reader.Str());
    DF_TRY_DECL(std::string, value, reader.Str());
    DF_TRY(reader.EndOfLine());
    blocker.observed.push_back(ErrorDetail{std::move(key), std::move(value)});
  }
  return OkStatus();
}

void WriteObligation(PayloadWriter& writer, const DrainObligation& obligation) {
  writer.Tok("O");
  writer.Num(obligation.id.value());
  writer.Num32(static_cast<std::uint32_t>(obligation.kind));
  writer.Num(obligation.target.value());
  writer.Num32(static_cast<std::uint32_t>(obligation.protected_class));
  writer.Flag(obligation.required);
  writer.Num32(static_cast<std::uint32_t>(obligation.state));
  writer.Num(obligation.issued_sequence.value());
  writer.Signed(obligation.issued_at.unix_nanos);
  writer.Str(obligation.issued_to);
  writer.Str(obligation.detail);
  writer.Num(obligation.acknowledged_sequence.value());
  writer.Signed(obligation.acknowledged_at.unix_nanos);
  writer.Str(obligation.acknowledged_by);
  writer.Num(obligation.satisfaction_evidence.value());
  writer.Num(obligation.satisfied_sequence.value());
  writer.Signed(obligation.satisfied_at.unix_nanos);
  writer.Str(obligation.satisfied_by);
  writer.Num(obligation.waiver.value());
  writer.Str(obligation.failure_reason);
  writer.EndLine();
}

[[nodiscard]] Status ReadObligation(PayloadReader& reader, DrainObligation& obligation) {
  DF_TRY_DECL(std::uint64_t, id, reader.Num());
  DF_TRY_DECL(std::uint32_t, kind, reader.Num32());
  DF_TRY_DECL(std::uint64_t, target, reader.Num());
  DF_TRY_DECL(std::uint32_t, protected_class, reader.Num32());
  DF_TRY_DECL(bool, required, reader.Flag());
  DF_TRY_DECL(std::uint32_t, state, reader.Num32());
  DF_TRY_DECL(std::uint64_t, issued_sequence, reader.Num());
  DF_TRY_DECL(std::int64_t, issued_at, reader.Signed());
  DF_TRY_DECL(std::string, issued_to, reader.Str());
  DF_TRY_DECL(std::string, detail, reader.Str());
  DF_TRY_DECL(std::uint64_t, ack_sequence, reader.Num());
  DF_TRY_DECL(std::int64_t, ack_at, reader.Signed());
  DF_TRY_DECL(std::string, ack_by, reader.Str());
  DF_TRY_DECL(std::uint64_t, satisfaction_evidence, reader.Num());
  DF_TRY_DECL(std::uint64_t, satisfied_sequence, reader.Num());
  DF_TRY_DECL(std::int64_t, satisfied_at, reader.Signed());
  DF_TRY_DECL(std::string, satisfied_by, reader.Str());
  DF_TRY_DECL(std::uint64_t, waiver, reader.Num());
  DF_TRY_DECL(std::string, failure_reason, reader.Str());
  DF_TRY(reader.EndOfLine());

  if (!InRange(kind, 8U)) {
    return ErrorBuilder(ErrorCode::malformed_payload, "drain kind out of range").Build();
  }
  if (!InRange(protected_class, 5U)) {
    return MakeError(ErrorCode::malformed_payload, "protected service class out of range");
  }
  if (!InRange(state, 5U)) {
    return MakeError(ErrorCode::malformed_payload, "obligation state out of range");
  }
  if (id == 0U || issued_sequence == 0U) {
    return MakeError(ErrorCode::unset_identity,
                     "obligation has an unset identity or issue sequence");
  }

  obligation.id = ObligationId::FromValue(id);
  obligation.kind = static_cast<DrainKind>(kind);
  obligation.target = AssetId::FromValue(target);
  obligation.protected_class = static_cast<ProtectedServiceClass>(protected_class);
  obligation.required = required;
  obligation.state = static_cast<ObligationState>(state);
  obligation.issued_sequence = ObservationSequence::FromValue(issued_sequence);
  obligation.issued_at = Timestamp{issued_at};
  obligation.issued_to = std::move(issued_to);
  obligation.detail = std::move(detail);
  obligation.acknowledged_sequence = ObservationSequence::FromValue(ack_sequence);
  obligation.acknowledged_at = Timestamp{ack_at};
  obligation.acknowledged_by = std::move(ack_by);
  obligation.satisfaction_evidence = EvidenceId::FromValue(satisfaction_evidence);
  obligation.satisfied_sequence = ObservationSequence::FromValue(satisfied_sequence);
  obligation.satisfied_at = Timestamp{satisfied_at};
  obligation.satisfied_by = std::move(satisfied_by);
  obligation.waiver = ExceptionId::FromValue(waiver);
  obligation.failure_reason = std::move(failure_reason);

  // Impossible combinations. These are refused rather than normalised, because
  // a satisfied obligation with no evidence is exactly the kind of record that
  // would let a claim silently become true after a restart.
  if (obligation.state == ObligationState::satisfied) {
    if (obligation.satisfaction_evidence.is_unset() ||
        obligation.satisfied_sequence.is_unset() ||
        obligation.satisfied_sequence <= obligation.issued_sequence) {
      return ErrorBuilder(ErrorCode::malformed_payload,
                          "satisfied obligation lacks later bound evidence")
          .With("obligation", obligation.id.to_hex())
          .Build();
    }
  }
  if (obligation.state == ObligationState::waived && obligation.waiver.is_unset()) {
    return ErrorBuilder(ErrorCode::malformed_payload, "waived obligation has no exception")
        .With("obligation", obligation.id.to_hex())
        .Build();
  }
  // A required obligation in the unknown state is legal: an unevaluated
  // requirement is the honest representation, and it blocks progress until the
  // runtime can evaluate it. Nothing to reject here.
  return OkStatus();
}

void WriteResidual(PayloadWriter& writer, const ResidualItem& item) {
  writer.Tok("R");
  writer.Num(item.id.value());
  writer.Num32(static_cast<std::uint32_t>(item.category));
  writer.Num32(static_cast<std::uint32_t>(item.disposition));
  writer.Num(item.observed_sequence.value());
  writer.Signed(item.recorded_at.unix_nanos);
  writer.Str(item.detail);
  writer.Str(item.authority);
  writer.Str(item.reference);
  writer.Num(item.waiver.value());
  writer.EndLine();
}

[[nodiscard]] Status ReadResidual(PayloadReader& reader, ResidualItem& item) {
  DF_TRY_DECL(std::uint64_t, id, reader.Num());
  DF_TRY_DECL(std::uint32_t, category, reader.Num32());
  DF_TRY_DECL(std::uint32_t, disposition, reader.Num32());
  DF_TRY_DECL(std::uint64_t, observed_sequence, reader.Num());
  DF_TRY_DECL(std::int64_t, recorded_at, reader.Signed());
  DF_TRY_DECL(std::string, detail, reader.Str());
  DF_TRY_DECL(std::string, authority, reader.Str());
  DF_TRY_DECL(std::string, reference, reader.Str());
  DF_TRY_DECL(std::uint64_t, waiver, reader.Num());
  DF_TRY(reader.EndOfLine());

  if (id == 0U) {
    return MakeError(ErrorCode::unset_identity, "residual item has an unset identity");
  }
  if (!InRange(category, 8U)) {
    return MakeError(ErrorCode::malformed_payload, "residual category out of range");
  }
  if (!InRange(disposition, 4U)) {
    return MakeError(ErrorCode::malformed_payload, "residual disposition out of range");
  }

  item.id = ResidualItemId::FromValue(id);
  item.category = static_cast<ResidualCategory>(category);
  item.disposition = static_cast<ResidualDisposition>(disposition);
  item.observed_sequence = ObservationSequence::FromValue(observed_sequence);
  item.recorded_at = Timestamp{recorded_at};
  item.detail = std::move(detail);
  item.authority = std::move(authority);
  item.reference = std::move(reference);
  item.waiver = ExceptionId::FromValue(waiver);

  if (item.disposition == ResidualDisposition::waived && item.waiver.is_unset()) {
    return ErrorBuilder(ErrorCode::malformed_payload, "waived residual item has no exception")
        .With("item", item.id.to_hex())
        .Build();
  }
  if (ClosesResidualChecklist(item.disposition) && item.authority.empty()) {
    return ErrorBuilder(ErrorCode::unset_identity,
                        "closed residual item has no reporting authority")
        .With("item", item.id.to_hex())
        .Build();
  }
  return OkStatus();
}

void WriteException(PayloadWriter& writer, const PolicyException& exception) {
  writer.Tok("X");
  writer.Num(exception.id.value());
  writer.Num(exception.item.value());
  writer.Num(exception.obligation.value());
  writer.Num(exception.plan.value());
  writer.Num(exception.revision.value());
  writer.DigestField(exception.binding_digest);
  writer.Num32(exception.policy_generation.value());
  writer.Str(exception.authority);
  writer.Str(exception.reference);
  writer.Str(exception.rationale);
  writer.Signed(exception.recorded_at.unix_nanos);
  writer.Num(exception.recorded_by.value());
  writer.EndLine();
}

[[nodiscard]] Status ReadException(PayloadReader& reader, PolicyException& exception) {
  DF_TRY_DECL(std::uint64_t, id, reader.Num());
  DF_TRY_DECL(std::uint64_t, item, reader.Num());
  DF_TRY_DECL(std::uint64_t, obligation, reader.Num());
  DF_TRY_DECL(std::uint64_t, plan, reader.Num());
  DF_TRY_DECL(std::uint64_t, revision, reader.Num());
  DF_TRY_DECL(Digest, binding_digest, reader.DigestField());
  DF_TRY_DECL(std::uint32_t, policy_generation, reader.Num32());
  DF_TRY_DECL(std::string, authority, reader.Str());
  DF_TRY_DECL(std::string, reference, reader.Str());
  DF_TRY_DECL(std::string, rationale, reader.Str());
  DF_TRY_DECL(std::int64_t, recorded_at, reader.Signed());
  DF_TRY_DECL(std::uint64_t, recorded_by, reader.Num());
  DF_TRY(reader.EndOfLine());

  if (id == 0U) {
    return MakeError(ErrorCode::unset_identity, "policy exception has an unset identity");
  }
  if (authority.empty() || reference.empty() || rationale.empty()) {
    return ErrorBuilder(ErrorCode::unset_identity,
                        "policy exception is not attributable: empty authority, reference, or rationale")
        .With("exception", detail::to_hex_fixed(id, 16))
        .Build();
  }

  exception.id = ExceptionId::FromValue(id);
  exception.item = ResidualItemId::FromValue(item);
  exception.obligation = ObligationId::FromValue(obligation);
  exception.plan = PlanId::FromValue(plan);
  exception.revision = Revision::FromValue(revision);
  exception.binding_digest = binding_digest;
  exception.policy_generation = PolicyGeneration::FromValue(policy_generation);
  exception.authority = std::move(authority);
  exception.reference = std::move(reference);
  exception.rationale = std::move(rationale);
  exception.recorded_at = Timestamp{recorded_at};
  exception.recorded_by = IncarnationId::FromValue(recorded_by);
  return OkStatus();
}

void WriteEvidence(PayloadWriter& writer, const EvidenceRef& evidence) {
  writer.Tok("E");
  writer.Num(evidence.id.value());
  writer.Num32(static_cast<std::uint32_t>(evidence.kind));
  writer.Num32(static_cast<std::uint32_t>(evidence.provenance));
  writer.Num32(static_cast<std::uint32_t>(evidence.freshness));
  writer.Num32(static_cast<std::uint32_t>(evidence.subject_kind));
  writer.Num(evidence.subject_obligation.value());
  writer.Str(evidence.observer);
  writer.Str(evidence.reference);
  writer.Str(evidence.detail);
  writer.Num(evidence.observation_sequence.value());
  writer.Signed(evidence.recorded_at.unix_nanos);
  writer.Num(evidence.recorded_by.value());
  writer.EndLine();
}

[[nodiscard]] Status ReadEvidence(PayloadReader& reader, EvidenceRef& evidence) {
  DF_TRY_DECL(std::uint64_t, id, reader.Num());
  DF_TRY_DECL(std::uint32_t, kind, reader.Num32());
  DF_TRY_DECL(std::uint32_t, provenance, reader.Num32());
  DF_TRY_DECL(std::uint32_t, freshness, reader.Num32());
  DF_TRY_DECL(std::uint32_t, subject_kind, reader.Num32());
  DF_TRY_DECL(std::uint64_t, subject_obligation, reader.Num());
  DF_TRY_DECL(std::string, observer, reader.Str());
  DF_TRY_DECL(std::string, reference, reader.Str());
  DF_TRY_DECL(std::string, detail, reader.Str());
  DF_TRY_DECL(std::uint64_t, sequence, reader.Num());
  DF_TRY_DECL(std::int64_t, recorded_at, reader.Signed());
  DF_TRY_DECL(std::uint64_t, recorded_by, reader.Num());
  DF_TRY(reader.EndOfLine());

  if (id == 0U || sequence == 0U) {
    return MakeError(ErrorCode::unset_identity,
                     "evidence has an unset identity or observation sequence");
  }
  if (!InRange(kind, 9U) || !InRange(provenance, 2U) || !InRange(freshness, 2U) ||
      !InRange(subject_kind, 8U)) {
    return MakeError(ErrorCode::malformed_payload, "evidence enumerator out of range");
  }
  if (kind == static_cast<std::uint32_t>(EvidenceKind::drain_satisfaction) &&
      (subject_obligation == 0U || subject_kind == 0U)) {
    return ErrorBuilder(ErrorCode::malformed_payload,
                        "drain satisfaction evidence does not name its obligation and drain kind")
        .With("evidence", detail::to_hex_fixed(id, 16))
        .Build();
  }
  // Any evidence may be bound to the obligation it is about; what is not
  // allowed is naming an obligation without also naming the drain kind, because
  // then the binding is not interpretable.
  if (subject_obligation != 0U && subject_kind == 0U) {
    return ErrorBuilder(ErrorCode::malformed_payload,
                        "evidence names an obligation without naming a drain kind")
        .With("evidence", detail::to_hex_fixed(id, 16))
        .Build();
  }
  if (observer.empty() || reference.empty()) {
    return ErrorBuilder(ErrorCode::unset_identity, "evidence is not attributable")
        .With("evidence", detail::to_hex_fixed(id, 16))
        .Build();
  }

  evidence.id = EvidenceId::FromValue(id);
  evidence.kind = static_cast<EvidenceKind>(kind);
  evidence.provenance = static_cast<EvidenceProvenance>(provenance);
  evidence.freshness = static_cast<EvidenceFreshness>(freshness);
  evidence.subject_kind = static_cast<DrainKind>(subject_kind);
  evidence.subject_obligation = ObligationId::FromValue(subject_obligation);
  evidence.observer = std::move(observer);
  evidence.reference = std::move(reference);
  evidence.detail = std::move(detail);
  evidence.observation_sequence = ObservationSequence::FromValue(sequence);
  evidence.recorded_at = Timestamp{recorded_at};
  evidence.recorded_by = IncarnationId::FromValue(recorded_by);
  return OkStatus();
}

void WriteReceipt(PayloadWriter& writer, const RevocationReceipt& receipt) {
  writer.Tok("V");
  writer.Num(receipt.id.value());
  writer.Num32(static_cast<std::uint32_t>(receipt.domain));
  writer.DigestField(receipt.binding_digest);
  writer.Str(receipt.authority);
  writer.Str(receipt.reference);
  writer.Str(receipt.detail);
  writer.Num(receipt.observation_sequence.value());
  writer.Signed(receipt.recorded_at.unix_nanos);
  writer.Num(receipt.recorded_by.value());
  writer.Num(receipt.recorded_under_plan.value());
  writer.Num(receipt.recorded_under_revision.value());
  writer.EndLine();
}

[[nodiscard]] Status ReadReceipt(PayloadReader& reader, RevocationReceipt& receipt) {
  DF_TRY_DECL(std::uint64_t, id, reader.Num());
  DF_TRY_DECL(std::uint32_t, domain, reader.Num32());
  DF_TRY_DECL(Digest, binding_digest, reader.DigestField());
  DF_TRY_DECL(std::string, authority, reader.Str());
  DF_TRY_DECL(std::string, reference, reader.Str());
  DF_TRY_DECL(std::string, detail, reader.Str());
  DF_TRY_DECL(std::uint64_t, sequence, reader.Num());
  DF_TRY_DECL(std::int64_t, recorded_at, reader.Signed());
  DF_TRY_DECL(std::uint64_t, recorded_by, reader.Num());
  DF_TRY_DECL(std::uint64_t, plan, reader.Num());
  DF_TRY_DECL(std::uint64_t, revision, reader.Num());
  DF_TRY(reader.EndOfLine());

  if (id == 0U || sequence == 0U) {
    return MakeError(ErrorCode::unset_identity, "receipt has an unset identity or sequence");
  }
  if (!DomainBitValid(domain)) {
    return ErrorBuilder(ErrorCode::malformed_payload, "receipt domain is not a known domain")
        .With("domain", static_cast<std::uint64_t>(domain))
        .Build();
  }
  if (authority.empty() || reference.empty()) {
    return ErrorBuilder(ErrorCode::unset_identity, "receipt is not attributable")
        .With("receipt", detail::to_hex_fixed(id, 16))
        .Build();
  }

  receipt.id = ReceiptId::FromValue(id);
  receipt.domain = static_cast<AuthorityDomain>(domain);
  receipt.binding_digest = binding_digest;
  receipt.authority = std::move(authority);
  receipt.reference = std::move(reference);
  receipt.detail = std::move(detail);
  receipt.observation_sequence = ObservationSequence::FromValue(sequence);
  receipt.recorded_at = Timestamp{recorded_at};
  receipt.recorded_by = IncarnationId::FromValue(recorded_by);
  receipt.recorded_under_plan = PlanId::FromValue(plan);
  receipt.recorded_under_revision = Revision::FromValue(revision);
  return OkStatus();
}

void WriteRegistry(PayloadWriter& writer, const IssuedRequest& issued) {
  writer.Tok("G");
  writer.Num(issued.attempt.value());
  writer.Num32(static_cast<std::uint32_t>(issued.kind));
  writer.DigestField(issued.key.digest);
  writer.Num(issued.committed_sequence.value());
  writer.Num(issued.resulting_revision.value());
  writer.Num32(static_cast<std::uint32_t>(issued.resulting_phase));
  writer.Signed(issued.issued_at.unix_nanos);
  writer.EndLine();
}

[[nodiscard]] Status ReadRegistry(PayloadReader& reader, IssuedRequest& issued) {
  DF_TRY_DECL(std::uint64_t, attempt, reader.Num());
  DF_TRY_DECL(std::uint32_t, kind, reader.Num32());
  DF_TRY_DECL(Digest, key, reader.DigestField());
  DF_TRY_DECL(std::uint64_t, committed_sequence, reader.Num());
  DF_TRY_DECL(std::uint64_t, resulting_revision, reader.Num());
  DF_TRY_DECL(std::uint32_t, resulting_phase, reader.Num32());
  DF_TRY_DECL(std::int64_t, issued_at, reader.Signed());
  DF_TRY(reader.EndOfLine());

  if (attempt == 0U || committed_sequence == 0U || resulting_revision == 0U) {
    return MakeError(ErrorCode::unset_identity, "registry entry has an unset identity");
  }
  if (!InRange(kind, static_cast<std::uint32_t>(kRequestKindCount) - 1U) ||
      !InRange(resulting_phase, 14U)) {
    return MakeError(ErrorCode::malformed_payload, "registry enumerator out of range");
  }

  issued.attempt = AttemptId::FromValue(attempt);
  issued.kind = static_cast<RequestKind>(kind);
  issued.key.digest = key;
  issued.committed_sequence = CommitSequence::FromValue(committed_sequence);
  issued.resulting_revision = Revision::FromValue(resulting_revision);
  issued.resulting_phase = static_cast<Phase>(resulting_phase);
  issued.issued_at = Timestamp{issued_at};
  return OkStatus();
}

void WriteNote(PayloadWriter& writer, const RecordedNote& note) {
  writer.Tok("N");
  writer.Str(note.code);
  writer.Str(note.text);
  writer.Signed(note.recorded_at.unix_nanos);
  writer.EndLine();
}

[[nodiscard]] Status ReadNote(PayloadReader& reader, RecordedNote& note) {
  DF_TRY_DECL(std::string, code, reader.Str());
  DF_TRY_DECL(std::string, text, reader.Str());
  DF_TRY_DECL(std::int64_t, recorded_at, reader.Signed());
  DF_TRY(reader.EndOfLine());
  if (code.empty()) {
    return MakeError(ErrorCode::unset_identity, "recorded note has an empty code");
  }
  note.code = std::move(code);
  note.text = std::move(text);
  note.recorded_at = Timestamp{recorded_at};
  return OkStatus();
}

}  // namespace

// ---------------------------------------------------------------------------
// PayloadWriter
// ---------------------------------------------------------------------------

PayloadWriter::PayloadWriter(std::string& sink) noexcept : sink_(&sink) {}

void PayloadWriter::Tok(std::string_view token) {
  if (line_open_) {
    sink_->push_back(' ');
  }
  sink_->append(token);
  line_open_ = true;
}

void PayloadWriter::Num(std::uint64_t value) { Tok(std::to_string(value)); }

void PayloadWriter::Num32(std::uint32_t value) { Tok(std::to_string(value)); }

void PayloadWriter::Signed(std::int64_t value) { Tok(std::to_string(value)); }

void PayloadWriter::Flag(bool value) { Tok(value ? "1" : "0"); }

void PayloadWriter::Str(std::string_view value) {
  if (value.empty()) {
    Tok("-");
    return;
  }
  Tok(HexEncode(value));
}

void PayloadWriter::DigestField(const Digest& digest) { Tok(digest.to_hex()); }

void PayloadWriter::EndLine() {
  sink_->push_back('\n');
  line_open_ = false;
  ++lines_;
}

// ---------------------------------------------------------------------------
// PayloadReader
// ---------------------------------------------------------------------------

PayloadReader::PayloadReader(std::string_view payload) : payload_(payload) {}

Result<bool> PayloadReader::NextLine() {
  if (cursor_ >= payload_.size()) {
    return false;
  }
  const std::size_t newline = payload_.find('\n', cursor_);
  if (newline == std::string_view::npos) {
    return ErrorBuilder(ErrorCode::malformed_payload, "payload line is not terminated")
        .With("line", static_cast<std::uint64_t>(line_index_ + 1U))
        .Build();
  }
  const std::string_view line = payload_.substr(cursor_, newline - cursor_);
  if (line.empty()) {
    return ErrorBuilder(ErrorCode::malformed_payload, "payload contains an empty line")
        .With("line", static_cast<std::uint64_t>(line_index_ + 1U))
        .Build();
  }
  for (const char ch : line) {
    const auto byte = static_cast<unsigned char>(ch);
    if (byte < 0x20U || byte > 0x7EU) {
      return ErrorBuilder(ErrorCode::invalid_utf8,
                          "payload contains a byte outside printable ASCII")
          .With("line", static_cast<std::uint64_t>(line_index_ + 1U))
          .With("byte", static_cast<std::uint64_t>(byte))
          .Build();
    }
  }
  const std::size_t space = line.find(' ');
  if (space == std::string_view::npos) {
    tag_ = line;
    body_ = std::string_view{};
  } else {
    tag_ = line.substr(0, space);
    body_ = line.substr(space + 1U);
  }
  body_offset_ = 0;
  cursor_ = newline + 1U;
  ++line_index_;
  return true;
}

Result<std::string_view> PayloadReader::Tag() {
  if (tag_.empty()) {
    return MakeError(ErrorCode::malformed_payload, "no line is loaded");
  }
  return tag_;
}

Result<std::string_view> PayloadReader::NextToken() {
  if (body_offset_ >= body_.size()) {
    return ErrorBuilder(ErrorCode::missing_field, "record has fewer fields than required")
        .With("tag", tag_)
        .With("line", static_cast<std::uint64_t>(line_index_))
        .Build();
  }
  const std::size_t space = body_.find(' ', body_offset_);
  std::string_view token;
  if (space == std::string_view::npos) {
    token = body_.substr(body_offset_);
    body_offset_ = body_.size();
  } else {
    token = body_.substr(body_offset_, space - body_offset_);
    body_offset_ = space + 1U;
  }
  if (token.empty()) {
    return ErrorBuilder(ErrorCode::unexpected_token, "record contains an empty field")
        .With("tag", tag_)
        .With("line", static_cast<std::uint64_t>(line_index_))
        .Build();
  }
  if (token.size() > kMaxTokenLength) {
    return ErrorBuilder(ErrorCode::string_too_long, "record field exceeds the maximum length")
        .With("tag", tag_)
        .With("length", static_cast<std::uint64_t>(token.size()))
        .With("limit", static_cast<std::uint64_t>(kMaxTokenLength))
        .Build();
  }
  return token;
}

Result<std::uint64_t> PayloadReader::Num() {
  auto token = NextToken();
  if (!token.ok()) {
    return token.error();
  }
  const std::string_view text = token.value();
  if (text.empty() || text.size() > 20U) {
    return ErrorBuilder(ErrorCode::malformed_payload, "integer field has an impossible length")
        .With("tag", tag_)
        .With("token", text)
        .Build();
  }
  if (text.size() > 1U && text[0] == '0') {
    return ErrorBuilder(ErrorCode::malformed_payload, "integer field is not canonical")
        .With("tag", tag_)
        .With("token", text)
        .Build();
  }
  std::uint64_t value = 0;
  for (const char ch : text) {
    if (ch < '0' || ch > '9') {
      return ErrorBuilder(ErrorCode::malformed_payload, "integer field is not decimal")
          .With("tag", tag_)
          .With("token", text)
          .Build();
    }
    const auto digit = static_cast<std::uint64_t>(ch - '0');
    if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U) {
      return ErrorBuilder(ErrorCode::out_of_range, "integer field overflows 64 bits")
          .With("tag", tag_)
          .With("token", text)
          .Build();
    }
    value = (value * 10U) + digit;
  }
  return value;
}

Result<std::uint32_t> PayloadReader::Num32() {
  auto value = Num();
  if (!value.ok()) {
    return value.error();
  }
  if (value.value() > 0xFFFFFFFFULL) {
    return ErrorBuilder(ErrorCode::out_of_range, "integer field exceeds 32 bits")
        .With("tag", tag_)
        .With("value", value.value())
        .Build();
  }
  return static_cast<std::uint32_t>(value.value());
}

Result<std::int64_t> PayloadReader::Signed() {
  auto token = NextToken();
  if (!token.ok()) {
    return token.error();
  }
  std::string_view text = token.value();
  bool negative = false;
  if (!text.empty() && text[0] == '-') {
    negative = true;
    text.remove_prefix(1);
  }
  if (text.empty() || text.size() > 19U) {
    return ErrorBuilder(ErrorCode::malformed_payload, "signed field has an impossible length")
        .With("tag", tag_)
        .Build();
  }
  if (text.size() > 1U && text[0] == '0') {
    return ErrorBuilder(ErrorCode::malformed_payload, "signed field is not canonical")
        .With("tag", tag_)
        .Build();
  }
  std::uint64_t magnitude = 0;
  for (const char ch : text) {
    if (ch < '0' || ch > '9') {
      return ErrorBuilder(ErrorCode::malformed_payload, "signed field is not decimal")
          .With("tag", tag_)
          .Build();
    }
    magnitude = (magnitude * 10U) + static_cast<std::uint64_t>(ch - '0');
    if (magnitude > 9223372036854775807ULL + (negative ? 1ULL : 0ULL)) {
      return ErrorBuilder(ErrorCode::out_of_range, "signed field overflows 64 bits")
          .With("tag", tag_)
          .Build();
    }
  }
  if (negative) {
    if (magnitude == 9223372036854775808ULL) {
      return std::numeric_limits<std::int64_t>::min();
    }
    return -static_cast<std::int64_t>(magnitude);
  }
  return static_cast<std::int64_t>(magnitude);
}

Result<bool> PayloadReader::Flag() {
  auto token = NextToken();
  if (!token.ok()) {
    return token.error();
  }
  if (token.value() == "1") {
    return true;
  }
  if (token.value() == "0") {
    return false;
  }
  return ErrorBuilder(ErrorCode::malformed_payload, "boolean field is neither 0 nor 1")
      .With("tag", tag_)
      .With("token", token.value())
      .Build();
}

Result<std::string> PayloadReader::Str() {
  auto token = NextToken();
  if (!token.ok()) {
    return token.error();
  }
  if (token.value() == "-") {
    return std::string();
  }
  if ((token.value().size() % 2U) != 0U) {
    return ErrorBuilder(ErrorCode::malformed_hex, "text field has an odd hex length")
        .With("tag", tag_)
        .Build();
  }
  const std::optional<std::string> decoded = HexDecode(token.value(), kMaxStringBytes);
  if (!decoded.has_value()) {
    return ErrorBuilder(ErrorCode::string_too_long,
                        "text field is not valid hexadecimal within the length limit")
        .With("tag", tag_)
        .With("limit", static_cast<std::uint64_t>(kMaxStringBytes))
        .Build();
  }
  if (!IsValidUtf8(*decoded)) {
    return ErrorBuilder(ErrorCode::invalid_utf8, "text field is not well-formed UTF-8")
        .With("tag", tag_)
        .Build();
  }
  return *decoded;
}

Result<Digest> PayloadReader::DigestField() {
  auto token = NextToken();
  if (!token.ok()) {
    return token.error();
  }
  const std::optional<Digest> digest = Digest::FromHex(token.value());
  if (!digest.has_value()) {
    return ErrorBuilder(ErrorCode::malformed_hex,
                        "digest field is not exactly 64 hexadecimal characters")
        .With("tag", tag_)
        .With("length", static_cast<std::uint64_t>(token.value().size()))
        .Build();
  }
  return *digest;
}

Status PayloadReader::EndOfLine() {
  if (body_offset_ < body_.size()) {
    return ErrorBuilder(ErrorCode::trailing_data, "record has more fields than allowed")
        .With("tag", tag_)
        .With("line", static_cast<std::uint64_t>(line_index_))
        .Build();
  }
  return OkStatus();
}

Status PayloadReader::RequireEof() {
  if (cursor_ < payload_.size()) {
    return ErrorBuilder(ErrorCode::trailing_data, "payload has content after the final record")
        .With("line", static_cast<std::uint64_t>(line_index_))
        .Build();
  }
  return OkStatus();
}

}  // namespace decommissioning_fabric

namespace decommissioning_fabric {
namespace {

void WriteFleetAsset(PayloadWriter& writer, const FleetAsset& asset) {
  writer.Tok("A");
  writer.Num(asset.id.value());
  writer.Num(asset.site.value());
  writer.Num(asset.rack.value());
  writer.Num32(asset.hardware_generation.value());
  writer.Num32(asset.firmware_generation.value());
  writer.Num32(asset.lifecycle_generation.value());
  writer.Num32(asset.active_authority.bits);
  writer.Flag(asset.present);
  writer.Str(asset.model);
  writer.Str(asset.serial);
  writer.Signed(asset.registered_at.unix_nanos);
  writer.Num(asset.registered_by.value());
  writer.Num(asset.current_plan.value());
  writer.EndLine();
}

[[nodiscard]] Status ReadFleetAsset(PayloadReader& reader, FleetAsset& asset) {
  DF_TRY_DECL(std::uint64_t, id, reader.Num());
  DF_TRY_DECL(std::uint64_t, site, reader.Num());
  DF_TRY_DECL(std::uint64_t, rack, reader.Num());
  DF_TRY_DECL(std::uint32_t, hardware, reader.Num32());
  DF_TRY_DECL(std::uint32_t, firmware, reader.Num32());
  DF_TRY_DECL(std::uint32_t, lifecycle, reader.Num32());
  DF_TRY_DECL(std::uint32_t, authority, reader.Num32());
  DF_TRY_DECL(bool, present, reader.Flag());
  DF_TRY_DECL(std::string, model, reader.Str());
  DF_TRY_DECL(std::string, serial, reader.Str());
  DF_TRY_DECL(std::int64_t, registered_at, reader.Signed());
  DF_TRY_DECL(std::uint64_t, registered_by, reader.Num());
  DF_TRY_DECL(std::uint64_t, current_plan, reader.Num());
  DF_TRY(reader.EndOfLine());

  if (id == 0U || site == 0U || rack == 0U) {
    return ErrorBuilder(ErrorCode::unset_identity, "fleet asset has an unset identity")
        .With("asset", detail::to_hex_fixed(id, 16))
        .Build();
  }
  if (hardware == 0U || firmware == 0U) {
    return ErrorBuilder(ErrorCode::unset_generation, "fleet asset has an unset generation")
        .With("asset", detail::to_hex_fixed(id, 16))
        .Build();
  }
  // lifecycle == 0 is meaningful and valid: the asset is registered but no
  // retirement attempt has begun. It is NOT a missing generation, and turning
  // it into one would refuse to load a store containing an unplanned asset.
  if (!MaskValid(authority)) {
    return ErrorBuilder(ErrorCode::malformed_payload,
                        "fleet asset authority mask has bits outside the known domains")
        .With("asset", detail::to_hex_fixed(id, 16))
        .With("mask", static_cast<std::uint64_t>(authority))
        .Build();
  }

  asset.id = AssetId::FromValue(id);
  asset.site = SiteId::FromValue(site);
  asset.rack = RackId::FromValue(rack);
  asset.hardware_generation = HardwareGeneration::FromValue(hardware);
  asset.firmware_generation = FirmwareGeneration::FromValue(firmware);
  asset.lifecycle_generation = LifecycleGeneration::FromValue(lifecycle);
  asset.active_authority = AuthorityMask{authority};
  asset.present = present;
  asset.model = std::move(model);
  asset.serial = std::move(serial);
  asset.registered_at = Timestamp{registered_at};
  asset.registered_by = IncarnationId::FromValue(registered_by);
  asset.current_plan = PlanId::FromValue(current_plan);
  return OkStatus();
}

void WriteCase(PayloadWriter& writer, const RetirementCase& record) {
  writer.Tok("CASE");
  writer.Num(record.key.asset.value());
  writer.Num32(record.key.generation.value());
  writer.EndLine();

  writer.Tok("PLANID");
  writer.Num(record.plan.value());
  writer.EndLine();

  WriteFence(writer, record.fence);

  writer.Tok("PHASE");
  writer.Num32(static_cast<std::uint32_t>(record.phase));
  writer.Num32(static_cast<std::uint32_t>(record.resume_phase));
  writer.EndLine();

  WriteBlocker(writer, record.blocker);

  writer.Tok("META");
  writer.Signed(record.created_at.unix_nanos);
  writer.Signed(record.updated_at.unix_nanos);
  writer.Num(record.created_by.value());
  writer.Num32(record.active_authority.bits);
  writer.EndLine();

  writer.Tok("ISOLATION");
  writer.Flag(record.isolation_observed);
  writer.Num(record.isolation_evidence.value());
  writer.Num(record.isolation_sequence.value());
  writer.Str(record.isolation_observer);
  writer.Str(record.isolation_reference);
  writer.EndLine();

  writer.Tok("REMOVALAUTH");
  writer.Flag(record.removal_authorized);
  writer.Num(record.removal_authorization_evidence.value());
  writer.Str(record.removal_authority);
  writer.Str(record.removal_authorization_reference);
  writer.Signed(record.removal_authorized_at.unix_nanos);
  writer.EndLine();

  writer.Tok("REMOVAL");
  writer.Flag(record.removal.observed);
  writer.Num(record.removal.evidence.value());
  writer.Str(record.removal.observer);
  writer.Str(record.removal.reference);
  writer.Num(record.removal.observation_sequence.value());
  writer.Signed(record.removal.observed_at.unix_nanos);
  writer.Flag(record.removal.canonical_deletion);
  writer.EndLine();

  writer.Tok("CANCEL");
  writer.Str(record.cancel_reason);
  writer.EndLine();

  writer.Tok("FAIL");
  writer.Str(record.failure_reason);
  writer.EndLine();

  writer.Tok("OBLIGATIONS");
  writer.Num(record.obligations.size());
  writer.EndLine();
  for (const DrainObligation& obligation : record.obligations) {
    WriteObligation(writer, obligation);
  }

  writer.Tok("RESIDUAL");
  writer.Num(record.residual.size());
  writer.EndLine();
  for (const ResidualItem& item : record.residual) {
    WriteResidual(writer, item);
  }

  writer.Tok("EXCEPTIONS");
  writer.Num(record.exceptions.size());
  writer.EndLine();
  for (const PolicyException& exception : record.exceptions) {
    WriteException(writer, exception);
  }

  writer.Tok("EVIDENCE");
  writer.Num(record.evidence.size());
  writer.EndLine();
  for (const EvidenceRef& evidence : record.evidence) {
    WriteEvidence(writer, evidence);
  }

  writer.Tok("RECEIPTS");
  writer.Num(record.receipts.size());
  writer.EndLine();
  for (const RevocationReceipt& receipt : record.receipts) {
    WriteReceipt(writer, receipt);
  }

  writer.Tok("REGISTRY");
  writer.Num(record.registry.size());
  writer.EndLine();
  for (const IssuedRequest& issued : record.registry) {
    WriteRegistry(writer, issued);
  }

  writer.Tok("NOTES");
  writer.Num(record.notes.size());
  writer.EndLine();
  for (const RecordedNote& note : record.notes) {
    WriteNote(writer, note);
  }
}

[[nodiscard]] Status ReadCase(PayloadReader& reader, RetirementCase& record) {
  DF_TRY(ExpectLine(reader, "CASE"));
  DF_TRY_DECL(std::uint64_t, asset, reader.Num());
  DF_TRY_DECL(std::uint32_t, generation, reader.Num32());
  DF_TRY(reader.EndOfLine());
  if (asset == 0U || generation == 0U) {
    return MakeError(ErrorCode::unset_identity, "case key has an unset identity or generation");
  }
  record.key.asset = AssetId::FromValue(asset);
  record.key.generation = LifecycleGeneration::FromValue(generation);

  DF_TRY(ExpectLine(reader, "PLANID"));
  DF_TRY_DECL(std::uint64_t, plan, reader.Num());
  DF_TRY(reader.EndOfLine());
  if (plan == 0U) {
    return ErrorBuilder(ErrorCode::unset_identity, "case has an unset plan identity")
        .With("asset", detail::to_hex_fixed(asset, 16))
        .Build();
  }
  record.plan = PlanId::FromValue(plan);

  DF_TRY(ExpectLine(reader, "FENCE"));
  DF_TRY(ReadFence(reader, record.fence));

  DF_TRY(ExpectLine(reader, "PHASE"));
  DF_TRY_DECL(std::uint32_t, phase, reader.Num32());
  DF_TRY_DECL(std::uint32_t, resume_phase, reader.Num32());
  DF_TRY(reader.EndOfLine());
  if (!InRange(phase, 14U) || !InRange(resume_phase, 14U)) {
    return MakeError(ErrorCode::malformed_payload, "case phase out of range");
  }
  record.phase = static_cast<Phase>(phase);
  record.resume_phase = static_cast<Phase>(resume_phase);

  DF_TRY(ExpectLine(reader, "BLOCKER"));
  DF_TRY(ReadBlocker(reader, record.blocker));

  DF_TRY(ExpectLine(reader, "META"));
  DF_TRY_DECL(std::int64_t, created_at, reader.Signed());
  DF_TRY_DECL(std::int64_t, updated_at, reader.Signed());
  DF_TRY_DECL(std::uint64_t, created_by, reader.Num());
  DF_TRY_DECL(std::uint32_t, active_authority, reader.Num32());
  DF_TRY(reader.EndOfLine());
  if (!MaskValid(active_authority)) {
    return MakeError(ErrorCode::malformed_payload, "case authority mask has unknown bits");
  }
  record.created_at = Timestamp{created_at};
  record.updated_at = Timestamp{updated_at};
  record.created_by = IncarnationId::FromValue(created_by);
  record.active_authority = AuthorityMask{active_authority};

  DF_TRY(ExpectLine(reader, "ISOLATION"));
  DF_TRY_DECL(bool, isolation_observed, reader.Flag());
  DF_TRY_DECL(std::uint64_t, isolation_evidence, reader.Num());
  DF_TRY_DECL(std::uint64_t, isolation_sequence, reader.Num());
  DF_TRY_DECL(std::string, isolation_observer, reader.Str());
  DF_TRY_DECL(std::string, isolation_reference, reader.Str());
  DF_TRY(reader.EndOfLine());
  record.isolation_observed = isolation_observed;
  record.isolation_evidence = EvidenceId::FromValue(isolation_evidence);
  record.isolation_sequence = ObservationSequence::FromValue(isolation_sequence);
  record.isolation_observer = std::move(isolation_observer);
  record.isolation_reference = std::move(isolation_reference);

  DF_TRY(ExpectLine(reader, "REMOVALAUTH"));
  DF_TRY_DECL(bool, removal_authorized, reader.Flag());
  DF_TRY_DECL(std::uint64_t, removal_evidence, reader.Num());
  DF_TRY_DECL(std::string, removal_authority, reader.Str());
  DF_TRY_DECL(std::string, removal_reference, reader.Str());
  DF_TRY_DECL(std::int64_t, removal_authorized_at, reader.Signed());
  DF_TRY(reader.EndOfLine());
  record.removal_authorized = removal_authorized;
  record.removal_authorization_evidence = EvidenceId::FromValue(removal_evidence);
  record.removal_authority = std::move(removal_authority);
  record.removal_authorization_reference = std::move(removal_reference);
  record.removal_authorized_at = Timestamp{removal_authorized_at};

  DF_TRY(ExpectLine(reader, "REMOVAL"));
  DF_TRY_DECL(bool, removal_observed, reader.Flag());
  DF_TRY_DECL(std::uint64_t, removal_obs_evidence, reader.Num());
  DF_TRY_DECL(std::string, removal_observer, reader.Str());
  DF_TRY_DECL(std::string, removal_obs_reference, reader.Str());
  DF_TRY_DECL(std::uint64_t, removal_obs_sequence, reader.Num());
  DF_TRY_DECL(std::int64_t, removal_observed_at, reader.Signed());
  DF_TRY_DECL(bool, canonical_deletion, reader.Flag());
  DF_TRY(reader.EndOfLine());
  if (canonical_deletion) {
    return ErrorBuilder(ErrorCode::malformed_payload,
                        "canonical deletion cannot be claimed by this runtime")
        .With("asset", detail::to_hex_fixed(asset, 16))
        .Build();
  }
  record.removal.observed = removal_observed;
  record.removal.evidence = EvidenceId::FromValue(removal_obs_evidence);
  record.removal.observer = std::move(removal_observer);
  record.removal.reference = std::move(removal_obs_reference);
  record.removal.observation_sequence = ObservationSequence::FromValue(removal_obs_sequence);
  record.removal.observed_at = Timestamp{removal_observed_at};
  record.removal.canonical_deletion = false;

  DF_TRY(ExpectLine(reader, "CANCEL"));
  DF_TRY_DECL(std::string, cancel_reason, reader.Str());
  DF_TRY(reader.EndOfLine());
  record.cancel_reason = std::move(cancel_reason);

  DF_TRY(ExpectLine(reader, "FAIL"));
  DF_TRY_DECL(std::string, failure_reason, reader.Str());
  DF_TRY(reader.EndOfLine());
  record.failure_reason = std::move(failure_reason);

  DF_TRY(ExpectLine(reader, "OBLIGATIONS"));
  DF_TRY_DECL(std::uint32_t, obligation_count,
              ReadBoundedCount(reader, kMaxObligationsPerCase, "obligations"));
  DF_TRY(reader.EndOfLine());
  record.obligations.clear();
  record.obligations.reserve(obligation_count);
  for (std::uint32_t i = 0; i < obligation_count; ++i) {
    DF_TRY(ExpectLine(reader, "O"));
    DrainObligation obligation;
    DF_TRY(ReadObligation(reader, obligation));
    record.obligations.push_back(std::move(obligation));
  }

  DF_TRY(ExpectLine(reader, "RESIDUAL"));
  DF_TRY_DECL(std::uint32_t, residual_count,
              ReadBoundedCount(reader, kMaxResidualPerCase, "residual items"));
  DF_TRY(reader.EndOfLine());
  record.residual.clear();
  record.residual.reserve(residual_count);
  for (std::uint32_t i = 0; i < residual_count; ++i) {
    DF_TRY(ExpectLine(reader, "R"));
    ResidualItem item;
    DF_TRY(ReadResidual(reader, item));
    record.residual.push_back(std::move(item));
  }

  DF_TRY(ExpectLine(reader, "EXCEPTIONS"));
  DF_TRY_DECL(std::uint32_t, exception_count,
              ReadBoundedCount(reader, kMaxExceptionsPerCase, "exceptions"));
  DF_TRY(reader.EndOfLine());
  record.exceptions.clear();
  record.exceptions.reserve(exception_count);
  for (std::uint32_t i = 0; i < exception_count; ++i) {
    DF_TRY(ExpectLine(reader, "X"));
    PolicyException exception;
    DF_TRY(ReadException(reader, exception));
    record.exceptions.push_back(std::move(exception));
  }

  DF_TRY(ExpectLine(reader, "EVIDENCE"));
  DF_TRY_DECL(std::uint32_t, evidence_count,
              ReadBoundedCount(reader, kMaxEvidencePerCase, "evidence"));
  DF_TRY(reader.EndOfLine());
  record.evidence.clear();
  record.evidence.reserve(evidence_count);
  for (std::uint32_t i = 0; i < evidence_count; ++i) {
    DF_TRY(ExpectLine(reader, "E"));
    EvidenceRef evidence;
    DF_TRY(ReadEvidence(reader, evidence));
    record.evidence.push_back(std::move(evidence));
  }

  DF_TRY(ExpectLine(reader, "RECEIPTS"));
  DF_TRY_DECL(std::uint32_t, receipt_count,
              ReadBoundedCount(reader, kMaxReceiptsPerCase, "receipts"));
  DF_TRY(reader.EndOfLine());
  record.receipts.clear();
  record.receipts.reserve(receipt_count);
  for (std::uint32_t i = 0; i < receipt_count; ++i) {
    DF_TRY(ExpectLine(reader, "V"));
    RevocationReceipt receipt;
    DF_TRY(ReadReceipt(reader, receipt));
    record.receipts.push_back(std::move(receipt));
  }

  DF_TRY(ExpectLine(reader, "REGISTRY"));
  DF_TRY_DECL(std::uint32_t, registry_count,
              ReadBoundedCount(reader, kMaxRegistryPerCase, "registry entries"));
  DF_TRY(reader.EndOfLine());
  record.registry.clear();
  record.registry.reserve(registry_count);
  for (std::uint32_t i = 0; i < registry_count; ++i) {
    DF_TRY(ExpectLine(reader, "G"));
    IssuedRequest issued;
    DF_TRY(ReadRegistry(reader, issued));
    record.registry.push_back(std::move(issued));
  }

  DF_TRY(ExpectLine(reader, "NOTES"));
  DF_TRY_DECL(std::uint32_t, note_count, ReadBoundedCount(reader, kMaxNotesPerCase, "notes"));
  DF_TRY(reader.EndOfLine());
  record.notes.clear();
  record.notes.reserve(note_count);
  for (std::uint32_t i = 0; i < note_count; ++i) {
    DF_TRY(ExpectLine(reader, "N"));
    RecordedNote note;
    DF_TRY(ReadNote(reader, note));
    record.notes.push_back(std::move(note));
  }

  return OkStatus();
}

/// Cross-field invariants of a decoded case. These are "impossible
/// combinations": states that the encoder cannot produce and that the decoder
/// therefore refuses rather than repairing.
[[nodiscard]] Status ValidateCase(const RetirementCase& record) {
  const std::string asset_hex = record.key.asset.to_hex();

  if (record.fence.asset != record.key.asset ||
      record.fence.lifecycle_generation != record.key.generation) {
    return ErrorBuilder(ErrorCode::identity_mismatch,
                        "case fence does not agree with the case key")
        .With("asset", asset_hex)
        .Build();
  }
  if (record.fence.plan != record.plan) {
    return ErrorBuilder(ErrorCode::identity_mismatch, "case fence plan does not agree")
        .With("asset", asset_hex)
        .Build();
  }
  if (!record.fence.all_required_set()) {
    return ErrorBuilder(ErrorCode::unset_generation,
                        "case fence has an unset required unit")
        .With("asset", asset_hex)
        .With("field", std::string(ToString(record.fence.first_unset_field())))
        .Build();
  }
  if (record.phase == Phase::unknown) {
    return ErrorBuilder(ErrorCode::malformed_payload, "case is in the unknown phase")
        .With("asset", asset_hex)
        .Build();
  }
  if (record.phase == Phase::blocked && !IsActionable(record.resume_phase)) {
    return ErrorBuilder(ErrorCode::malformed_payload,
                        "blocked case has no actionable resume phase")
        .With("asset", asset_hex)
        .With("resume_phase", std::string(ToString(record.resume_phase)))
        .Build();
  }
  if (record.phase != Phase::blocked && record.resume_phase != Phase::unknown) {
    return ErrorBuilder(ErrorCode::malformed_payload,
                        "non-blocked case carries a resume phase")
        .With("asset", asset_hex)
        .Build();
  }

  // The obligation binding is derived state. Recomputing it here means a
  // hand-edited or corrupted generation cannot smuggle a stale obligation view
  // past the fence comparison.
  if (record.fence.active_obligation_digest != ActiveObligationDigest(record.obligations)) {
    return ErrorBuilder(ErrorCode::malformed_payload,
                        "case active-obligation digest does not match its obligations")
        .With("asset", asset_hex)
        .Build();
  }
  std::uint32_t expected_active = 0;
  for (const DrainObligation& obligation : record.obligations) {
    if (obligation.blocks_progress()) {
      ++expected_active;
    }
  }
  if (record.fence.active_obligation_count != expected_active) {
    return ErrorBuilder(ErrorCode::malformed_payload,
                        "case active-obligation count does not match its obligations")
        .With("asset", asset_hex)
        .Build();
  }

  std::set<std::uint64_t> obligation_ids;
  for (const DrainObligation& obligation : record.obligations) {
    if (!obligation_ids.insert(obligation.id.value()).second) {
      return ErrorBuilder(ErrorCode::duplicate_identity, "duplicate obligation identity")
          .With("asset", asset_hex)
          .With("obligation", obligation.id.to_hex())
          .Build();
    }
  }
  std::set<std::uint64_t> residual_ids;
  for (const ResidualItem& item : record.residual) {
    if (!residual_ids.insert(item.id.value()).second) {
      return ErrorBuilder(ErrorCode::duplicate_identity, "duplicate residual item identity")
          .With("asset", asset_hex)
          .With("item", item.id.to_hex())
          .Build();
    }
  }
  std::set<std::uint64_t> exception_ids;
  for (const PolicyException& exception : record.exceptions) {
    if (!exception_ids.insert(exception.id.value()).second) {
      return ErrorBuilder(ErrorCode::duplicate_identity, "duplicate exception identity")
          .With("asset", asset_hex)
          .With("exception", exception.id.to_hex())
          .Build();
    }
  }
  std::set<std::uint64_t> evidence_ids;
  for (const EvidenceRef& evidence : record.evidence) {
    if (!evidence_ids.insert(evidence.id.value()).second) {
      return ErrorBuilder(ErrorCode::duplicate_identity, "duplicate evidence identity")
          .With("asset", asset_hex)
          .With("evidence", evidence.id.to_hex())
          .Build();
    }
  }
  std::set<std::uint64_t> receipt_ids;
  for (const RevocationReceipt& receipt : record.receipts) {
    if (!receipt_ids.insert(receipt.id.value()).second) {
      return ErrorBuilder(ErrorCode::duplicate_identity, "duplicate receipt identity")
          .With("asset", asset_hex)
          .With("receipt", receipt.id.to_hex())
          .Build();
    }
  }
  std::set<std::uint64_t> attempts;
  for (const IssuedRequest& issued : record.registry) {
    if (!attempts.insert(issued.attempt.value()).second) {
      return ErrorBuilder(ErrorCode::duplicate_identity, "duplicate attempt identity")
          .With("asset", asset_hex)
          .With("attempt", issued.attempt.to_hex())
          .Build();
    }
  }

  // Evidence referenced by an obligation or an observation must exist.
  for (const DrainObligation& obligation : record.obligations) {
    if (obligation.state == ObligationState::satisfied &&
        FindEvidence(record, obligation.satisfaction_evidence) == nullptr) {
      return ErrorBuilder(ErrorCode::unknown_evidence,
                          "satisfied obligation references absent evidence")
          .With("asset", asset_hex)
          .With("obligation", obligation.id.to_hex())
          .Build();
    }
    if (obligation.state == ObligationState::waived &&
        FindException(record, obligation.waiver) == nullptr) {
      return ErrorBuilder(ErrorCode::unknown_exception,
                          "waived obligation references an absent exception")
          .With("asset", asset_hex)
          .With("obligation", obligation.id.to_hex())
          .Build();
    }
  }
  for (const ResidualItem& item : record.residual) {
    if (item.disposition == ResidualDisposition::waived &&
        FindException(record, item.waiver) == nullptr) {
      return ErrorBuilder(ErrorCode::unknown_exception,
                          "waived residual item references an absent exception")
          .With("asset", asset_hex)
          .With("item", item.id.to_hex())
          .Build();
    }
  }
  if (record.isolation_observed &&
      FindEvidence(record, record.isolation_evidence) == nullptr) {
    return ErrorBuilder(ErrorCode::unknown_evidence,
                        "isolation observation references absent evidence")
        .With("asset", asset_hex)
        .Build();
  }
  if (record.removal_authorized &&
      FindEvidence(record, record.removal_authorization_evidence) == nullptr) {
    return ErrorBuilder(ErrorCode::unknown_evidence,
                        "removal authorization references absent evidence")
        .With("asset", asset_hex)
        .Build();
  }
  if (record.removal.observed && FindEvidence(record, record.removal.evidence) == nullptr) {
    return ErrorBuilder(ErrorCode::unknown_evidence,
                        "removal observation references absent evidence")
        .With("asset", asset_hex)
        .Build();
  }
  for (const EvidenceRef& evidence : record.evidence) {
    if (evidence.subject_obligation.is_set() &&
        FindObligation(record, evidence.subject_obligation) == nullptr) {
      return ErrorBuilder(ErrorCode::unknown_obligation,
                          "evidence is bound to an obligation that does not exist")
          .With("asset", asset_hex)
          .With("evidence", evidence.id.to_hex())
          .With("obligation", evidence.subject_obligation.to_hex())
          .Build();
    }
  }
  return OkStatus();
}

}  // namespace

// ---------------------------------------------------------------------------
// EncodeState
// ---------------------------------------------------------------------------

std::string EncodeState(const StoreState& state) {
  std::string out;
  out.reserve(2048);
  PayloadWriter writer(out);

  writer.Tok(kPayloadHeaderTag);
  writer.Num32(kPayloadVersion);
  writer.EndLine();

  writer.Tok("STATE");
  writer.Num(state.sequence.value());
  writer.Num32(state.generations.facility_epoch.value());
  writer.Num32(state.generations.policy_generation.value());
  writer.Num32(state.generations.dependency_generation.value());
  writer.Num32(state.generations.capacity_generation.value());
  writer.Num32(state.generations.topology_generation.value());
  writer.Num32(state.generations.maintenance_generation.value());
  writer.EndLine();

  writer.Tok("NEXT");
  writer.Num(state.counters.last_plan.value());
  writer.Num(state.counters.last_evidence.value());
  writer.Num(state.counters.last_receipt.value());
  writer.Num(state.counters.last_obligation.value());
  writer.Num(state.counters.last_residual.value());
  writer.Num(state.counters.last_exception.value());
  writer.Num(state.counters.last_observation.value());
  writer.EndLine();

  writer.Tok("FLEET");
  writer.Num(state.fleet.size());
  writer.EndLine();
  for (const auto& entry : state.fleet) {
    WriteFleetAsset(writer, entry.second);
  }

  writer.Tok("CASES");
  writer.Num(state.cases.size());
  writer.EndLine();
  for (const auto& entry : state.cases) {
    WriteCase(writer, entry.second);
  }

  writer.Tok("END");
  writer.EndLine();
  return out;
}

// ---------------------------------------------------------------------------
// DecodeState
// ---------------------------------------------------------------------------

Result<StoreState> DecodeState(std::string_view payload) {
  if (payload.size() > kMaxPayloadSize) {
    return ErrorBuilder(ErrorCode::payload_too_large, "payload exceeds the maximum size")
        .With("size", static_cast<std::uint64_t>(payload.size()))
        .With("limit", kMaxPayloadSize)
        .Build();
  }
  if (payload.size() < kMinPayloadSize) {
    return ErrorBuilder(ErrorCode::payload_too_small, "payload is smaller than the minimum size")
        .With("size", static_cast<std::uint64_t>(payload.size()))
        .With("limit", kMinPayloadSize)
        .Build();
  }

  PayloadReader reader(payload);
  StoreState state;

  DF_TRY(ExpectLine(reader, kPayloadHeaderTag));
  DF_TRY_DECL(std::uint32_t, version, reader.Num32());
  DF_TRY(reader.EndOfLine());
  if (version != kPayloadVersion) {
    return ErrorBuilder(ErrorCode::unsupported_format_version,
                        "payload format version is not supported")
        .With("found", static_cast<std::uint64_t>(version))
        .With("supported", static_cast<std::uint64_t>(kPayloadVersion))
        .Build();
  }

  DF_TRY(ExpectLine(reader, "STATE"));
  DF_TRY_DECL(std::uint64_t, sequence, reader.Num());
  DF_TRY_DECL(std::uint32_t, facility_epoch, reader.Num32());
  DF_TRY_DECL(std::uint32_t, policy_generation, reader.Num32());
  DF_TRY_DECL(std::uint32_t, dependency_generation, reader.Num32());
  DF_TRY_DECL(std::uint32_t, capacity_generation, reader.Num32());
  DF_TRY_DECL(std::uint32_t, topology_generation, reader.Num32());
  DF_TRY_DECL(std::uint32_t, maintenance_generation, reader.Num32());
  DF_TRY(reader.EndOfLine());
  if (sequence == 0U) {
    return MakeError(ErrorCode::unset_identity, "committed state has sequence zero");
  }
  if (facility_epoch == 0U || policy_generation == 0U || dependency_generation == 0U ||
      capacity_generation == 0U || topology_generation == 0U || maintenance_generation == 0U) {
    return MakeError(ErrorCode::unset_generation, "committed state has an unset generation");
  }
  state.sequence = CommitSequence::FromValue(sequence);
  state.generations.facility_epoch = FacilityEpoch::FromValue(facility_epoch);
  state.generations.policy_generation = PolicyGeneration::FromValue(policy_generation);
  state.generations.dependency_generation = DependencyGeneration::FromValue(dependency_generation);
  state.generations.capacity_generation = CapacityGeneration::FromValue(capacity_generation);
  state.generations.topology_generation = TopologyGeneration::FromValue(topology_generation);
  state.generations.maintenance_generation =
      MaintenanceGeneration::FromValue(maintenance_generation);

  DF_TRY(ExpectLine(reader, "NEXT"));
  DF_TRY_DECL(std::uint64_t, last_plan, reader.Num());
  DF_TRY_DECL(std::uint64_t, last_evidence, reader.Num());
  DF_TRY_DECL(std::uint64_t, last_receipt, reader.Num());
  DF_TRY_DECL(std::uint64_t, last_obligation, reader.Num());
  DF_TRY_DECL(std::uint64_t, last_residual, reader.Num());
  DF_TRY_DECL(std::uint64_t, last_exception, reader.Num());
  DF_TRY_DECL(std::uint64_t, last_observation, reader.Num());
  DF_TRY(reader.EndOfLine());
  state.counters.last_plan = PlanId::FromValue(last_plan);
  state.counters.last_evidence = EvidenceId::FromValue(last_evidence);
  state.counters.last_receipt = ReceiptId::FromValue(last_receipt);
  state.counters.last_obligation = ObligationId::FromValue(last_obligation);
  state.counters.last_residual = ResidualItemId::FromValue(last_residual);
  state.counters.last_exception = ExceptionId::FromValue(last_exception);
  state.counters.last_observation = ObservationSequence::FromValue(last_observation);

  DF_TRY(ExpectLine(reader, "FLEET"));
  DF_TRY_DECL(std::uint32_t, fleet_count,
              ReadBoundedCount(reader, kMaxFleetAssets, "fleet assets"));
  DF_TRY(reader.EndOfLine());
  for (std::uint32_t i = 0; i < fleet_count; ++i) {
    DF_TRY(ExpectLine(reader, "A"));
    FleetAsset asset;
    DF_TRY(ReadFleetAsset(reader, asset));
    const auto inserted = state.fleet.emplace(asset.id, std::move(asset));
    if (!inserted.second) {
      return ErrorBuilder(ErrorCode::duplicate_identity, "duplicate fleet asset identity")
          .With("asset", inserted.first->first.to_hex())
          .Build();
    }
  }

  DF_TRY(ExpectLine(reader, "CASES"));
  DF_TRY_DECL(std::uint32_t, case_count, ReadBoundedCount(reader, kMaxCases, "cases"));
  DF_TRY(reader.EndOfLine());
  for (std::uint32_t i = 0; i < case_count; ++i) {
    RetirementCase record;
    DF_TRY(ReadCase(reader, record));
    DF_TRY(ValidateCase(record));
    if (state.fleet.find(record.key.asset) == state.fleet.end()) {
      return ErrorBuilder(ErrorCode::unknown_asset, "case references an unregistered asset")
          .With("asset", record.key.asset.to_hex())
          .Build();
    }
    const auto inserted = state.cases.emplace(record.key, std::move(record));
    if (!inserted.second) {
      return ErrorBuilder(ErrorCode::duplicate_identity, "duplicate case key")
          .With("asset", inserted.first->first.asset.to_hex())
          .With("generation", static_cast<std::uint64_t>(inserted.first->first.generation.value()))
          .Build();
    }
  }

  DF_TRY(ExpectLine(reader, "END"));
  DF_TRY(reader.EndOfLine());
  DF_TRY(reader.RequireEof());

  // The fleet asset's current lifecycle generation must agree with the newest
  // case for that asset. This is derived state, and recomputing it here means a
  // hand-edited generation cannot make the runtime believe a superseded attempt
  // is still the current one.
  for (const auto& entry : state.fleet) {
    const LifecycleGeneration latest = state.LatestGeneration(entry.first);
    const LifecycleGeneration recorded = entry.second.lifecycle_generation;
    if (latest.is_set() && recorded != latest) {
      return ErrorBuilder(ErrorCode::identity_mismatch,
                          "fleet asset lifecycle generation does not match its newest case")
          .With("asset", entry.first.to_hex())
          .With("recorded", static_cast<std::uint64_t>(recorded.value()))
          .With("newest_case", static_cast<std::uint64_t>(latest.value()))
          .Build();
    }
    if (!latest.is_set() && recorded.is_set()) {
      return ErrorBuilder(ErrorCode::identity_mismatch,
                          "fleet asset claims a lifecycle generation with no case")
          .With("asset", entry.first.to_hex())
          .With("recorded", static_cast<std::uint64_t>(recorded.value()))
          .Build();
    }
  }

  return state;
}

// ---------------------------------------------------------------------------
// Record framing
// ---------------------------------------------------------------------------

namespace {

void AppendLe32(std::string& out, std::uint32_t value) {
  for (std::size_t i = 0; i < 4U; ++i) {
    out.push_back(static_cast<char>((value >> (8U * i)) & 0xFFU));
  }
}

void AppendLe64(std::string& out, std::uint64_t value) {
  for (std::size_t i = 0; i < 8U; ++i) {
    out.push_back(static_cast<char>((value >> (8U * i)) & 0xFFU));
  }
}

[[nodiscard]] std::uint32_t ReadLe32(std::string_view data, std::size_t offset) {
  std::uint32_t value = 0;
  for (std::size_t i = 0; i < 4U; ++i) {
    value |= static_cast<std::uint32_t>(static_cast<unsigned char>(data[offset + i]))
             << (8U * i);
  }
  return value;
}

[[nodiscard]] std::uint64_t ReadLe64(std::string_view data, std::size_t offset) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8U; ++i) {
    value |= static_cast<std::uint64_t>(static_cast<unsigned char>(data[offset + i]))
             << (8U * i);
  }
  return value;
}

void AppendDigestPrefix(std::string& out, const Digest& digest) {
  for (std::size_t i = 0; i < 8U; ++i) {
    out.push_back(static_cast<char>(digest.bytes[i]));
  }
}

}  // namespace

std::string BuildRecord(std::string_view payload, CommitSequence sequence) {
  std::string record;
  record.reserve(kStoreHeaderSize + payload.size());

  record.append(kStoreMagic);
  AppendLe32(record, kStoreFormatVersion);
  AppendLe32(record, kStoreRecordKind);
  AppendLe64(record, sequence.value());
  AppendLe64(record, static_cast<std::uint64_t>(payload.size()));

  const Digest payload_digest = Sha256::Of(payload);
  AppendDigestPrefix(record, payload_digest);

  const Digest header_digest =
      Sha256::Of(std::string_view(record).substr(0, kStoreHeaderSize - 16U));
  AppendDigestPrefix(record, header_digest);

  AppendLe64(record, 0);  // reserved, must be zero
  record.append(payload);
  return record;
}

Result<ParsedRecord> ParseRecord(std::string_view record,
                                 std::optional<std::uint64_t> expected_size) {
  if (record.size() < kStoreHeaderSize) {
    return ErrorBuilder(ErrorCode::malformed_payload, "record is shorter than its header")
        .With("size", static_cast<std::uint64_t>(record.size()))
        .With("header", static_cast<std::uint64_t>(kStoreHeaderSize))
        .Build();
  }

  for (std::size_t i = 0; i < kStoreMagic.size(); ++i) {
    if (record[i] != kStoreMagic[i]) {
      return MakeError(ErrorCode::malformed_payload, "record magic does not match");
    }
  }

  const std::uint32_t format_version = ReadLe32(record, 8);
  if (format_version != kStoreFormatVersion) {
    return ErrorBuilder(ErrorCode::unsupported_format_version,
                        "record format version is not supported")
        .With("found", static_cast<std::uint64_t>(format_version))
        .With("supported", static_cast<std::uint64_t>(kStoreFormatVersion))
        .Build();
  }

  const std::uint32_t record_kind = ReadLe32(record, 12);
  if (record_kind != kStoreRecordKind) {
    return ErrorBuilder(ErrorCode::malformed_payload, "record kind is not supported")
        .With("found", static_cast<std::uint64_t>(record_kind))
        .With("supported", static_cast<std::uint64_t>(kStoreRecordKind))
        .Build();
  }

  const std::uint64_t sequence = ReadLe64(record, 16);
  const std::uint64_t payload_size = ReadLe64(record, 24);

  if (payload_size < kMinPayloadSize) {
    return ErrorBuilder(ErrorCode::payload_too_small, "record payload is smaller than the minimum")
        .With("size", payload_size)
        .With("limit", kMinPayloadSize)
        .Build();
  }
  if (payload_size > kMaxPayloadSize) {
    return ErrorBuilder(ErrorCode::payload_too_large, "record payload exceeds the maximum")
        .With("size", payload_size)
        .With("limit", kMaxPayloadSize)
        .Build();
  }

  const std::uint64_t reserved = ReadLe64(record, 48);
  if (reserved != 0U) {
    return ErrorBuilder(ErrorCode::reserved_not_zero, "reserved header field is not zero")
        .With("value", reserved)
        .Build();
  }

  const std::uint64_t expected_total = kStoreHeaderSize + payload_size;
  if (record.size() != expected_total) {
    return ErrorBuilder(ErrorCode::trailing_data,
                        "record length does not equal header plus payload size")
        .With("actual", static_cast<std::uint64_t>(record.size()))
        .With("expected", expected_total)
        .Build();
  }
  if (expected_size.has_value() && *expected_size != expected_total) {
    return ErrorBuilder(ErrorCode::out_of_range, "record length does not match the file length")
        .With("actual", *expected_size)
        .With("expected", expected_total)
        .Build();
  }

  const Digest header_digest =
      Sha256::Of(record.substr(0, kStoreHeaderSize - 16U));
  for (std::size_t i = 0; i < 8U; ++i) {
    const auto stored = static_cast<unsigned char>(record[40U + i]);
    if (stored != header_digest.bytes[i]) {
      return ErrorBuilder(ErrorCode::malformed_payload, "record header digest mismatch")
          .With("offset", static_cast<std::uint64_t>(40U + i))
          .Build();
    }
  }

  const std::string_view payload = record.substr(kStoreHeaderSize, payload_size);
  const Digest payload_digest = Sha256::Of(payload);
  for (std::size_t i = 0; i < 8U; ++i) {
    const auto stored = static_cast<unsigned char>(record[32U + i]);
    if (stored != payload_digest.bytes[i]) {
      return ErrorBuilder(ErrorCode::malformed_payload, "record payload digest mismatch")
          .With("offset", static_cast<std::uint64_t>(32U + i))
          .Build();
    }
  }

  ParsedRecord parsed;
  parsed.sequence = CommitSequence::FromValue(sequence);
  parsed.payload_size = payload_size;
  parsed.payload_digest = payload_digest;
  parsed.payload.assign(payload);
  return parsed;
}

bool TryParseRecord(std::string_view record, ParsedRecord& out, SlotReport& report) {
  auto parsed = ParseRecord(record, std::nullopt);
  if (!parsed.ok()) {
    report.status = SlotStatus::corrupt;
    report.failure = parsed.error().to_string();
    return false;
  }
  out = std::move(parsed).value();
  report.status = SlotStatus::valid;
  report.sequence = out.sequence;
  report.payload_size = out.payload_size;
  report.payload_digest = out.payload_digest;
  report.failure.clear();
  return true;
}

}  // namespace decommissioning_fabric

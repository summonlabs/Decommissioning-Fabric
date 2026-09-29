// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// format.hpp proof obligations.
//
// The payload codec is the only path by which durable state re-enters the
// process, so these tests establish three things: encoding is deterministic and
// round trips exactly, decoding rejects every targeted corruption with a
// specific error code, and the record framing validates its header and both
// digests before any byte of payload is trusted.

#include "decommissioning_fabric/format.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "harness.hpp"

namespace {

using namespace decommissioning_fabric;

constexpr std::int64_t kBaseNanos = 1767225600000000000LL;  // 2026-01-01T00:00:00Z

constexpr std::uint32_t kFacilityEpoch = 3U;
constexpr std::uint32_t kPolicyGeneration = 2U;
constexpr std::uint32_t kDependencyGeneration = 5U;
constexpr std::uint32_t kCapacityGeneration = 6U;
constexpr std::uint32_t kTopologyGeneration = 7U;
constexpr std::uint32_t kMaintenanceGeneration = 8U;

/// Non-ASCII text assembled from explicit byte escapes so the fixture does not
/// depend on the compiler's source or execution character set.
const std::string kNonAsciiText = "caf\xC3\xA9 na\xC3\xAFve";

constexpr std::uint64_t kAssetOne = 0x1001U;
constexpr std::uint64_t kAssetTwo = 0x1002U;
constexpr std::uint64_t kPlanOne = 0x5001U;
constexpr std::uint64_t kPlanTwo = 0x5002U;

// ---------------------------------------------------------------------------
// Fixture construction
// ---------------------------------------------------------------------------

[[nodiscard]] FleetAsset MakeAsset(std::uint64_t id, std::uint64_t site, std::uint64_t rack,
                                   std::uint32_t hardware, std::uint32_t firmware,
                                   std::uint32_t lifecycle, std::uint32_t authority_bits,
                                   std::string model, std::string serial, PlanId plan) {
  FleetAsset asset;
  asset.id = AssetId::FromValue(id);
  asset.site = SiteId::FromValue(site);
  asset.rack = RackId::FromValue(rack);
  asset.hardware_generation = HardwareGeneration::FromValue(hardware);
  asset.firmware_generation = FirmwareGeneration::FromValue(firmware);
  asset.lifecycle_generation = LifecycleGeneration::FromValue(lifecycle);
  asset.active_authority = AuthorityMask{authority_bits};
  asset.present = true;
  asset.model = std::move(model);
  asset.serial = std::move(serial);
  asset.registered_at = Timestamp{kBaseNanos};
  asset.registered_by = IncarnationId::FromValue(0x7001U);
  asset.current_plan = plan;
  return asset;
}

[[nodiscard]] PlanFence MakeFence(AssetId asset, SiteId site, RackId rack,
                                  LifecycleGeneration lifecycle, HardwareGeneration hardware,
                                  FirmwareGeneration firmware, PlanId plan, Revision revision) {
  PlanFence fence;
  fence.asset = asset;
  fence.site = site;
  fence.rack = rack;
  fence.lifecycle_generation = lifecycle;
  fence.hardware_generation = hardware;
  fence.firmware_generation = firmware;
  fence.facility_epoch = FacilityEpoch::FromValue(kFacilityEpoch);
  fence.policy_generation = PolicyGeneration::FromValue(kPolicyGeneration);
  fence.dependency_generation = DependencyGeneration::FromValue(kDependencyGeneration);
  fence.capacity_generation = CapacityGeneration::FromValue(kCapacityGeneration);
  fence.topology_generation = TopologyGeneration::FromValue(kTopologyGeneration);
  fence.maintenance_generation = MaintenanceGeneration::FromValue(kMaintenanceGeneration);
  fence.plan = plan;
  fence.revision = revision;
  return fence;
}

[[nodiscard]] EvidenceRef MakeEvidence(std::uint64_t id, EvidenceKind kind, std::uint64_t sequence,
                                       std::string observer, std::string reference,
                                       std::string detail, DrainKind subject_kind,
                                       ObligationId subject_obligation) {
  EvidenceRef evidence;
  evidence.id = EvidenceId::FromValue(id);
  evidence.kind = kind;
  evidence.provenance = EvidenceProvenance::external_authority;
  evidence.freshness = EvidenceFreshness::live;
  evidence.observer = std::move(observer);
  evidence.reference = std::move(reference);
  evidence.detail = std::move(detail);
  evidence.subject_kind = subject_kind;
  evidence.subject_obligation = subject_obligation;
  evidence.observation_sequence = ObservationSequence::FromValue(sequence);
  evidence.recorded_at =
      Timestamp{kBaseNanos + static_cast<std::int64_t>(sequence) * kNanosPerSecond};
  evidence.recorded_by = IncarnationId::FromValue(0x7002U);
  return evidence;
}

[[nodiscard]] RevocationReceipt MakeReceipt(std::uint64_t id, AuthorityDomain domain,
                                            const Digest& binding, std::uint64_t sequence,
                                            PlanId plan, Revision revision) {
  RevocationReceipt receipt;
  receipt.id = ReceiptId::FromValue(id);
  receipt.domain = domain;
  receipt.binding_digest = binding;
  receipt.authority = std::string(ToString(domain)) + "-authority";
  receipt.reference = "REV-" + std::to_string(id);
  receipt.detail = "revocation observed and reported";
  receipt.observation_sequence = ObservationSequence::FromValue(sequence);
  receipt.recorded_at =
      Timestamp{kBaseNanos + static_cast<std::int64_t>(sequence) * kNanosPerSecond};
  receipt.recorded_by = IncarnationId::FromValue(0x7003U);
  receipt.recorded_under_plan = plan;
  receipt.recorded_under_revision = revision;
  return receipt;
}

[[nodiscard]] IssuedRequest MakeRegistry(std::uint64_t attempt, RequestKind kind,
                                         std::string_view key_material, std::uint64_t committed,
                                         std::uint64_t revision, Phase phase) {
  IssuedRequest issued;
  issued.attempt = AttemptId::FromValue(attempt);
  issued.kind = kind;
  issued.key.digest = Sha256::Of(key_material);
  issued.committed_sequence = CommitSequence::FromValue(committed);
  issued.resulting_revision = Revision::FromValue(revision);
  issued.resulting_phase = phase;
  issued.issued_at = Timestamp{kBaseNanos + static_cast<std::int64_t>(attempt) * kNanosPerSecond};
  return issued;
}

[[nodiscard]] DrainObligation MakeObligation(std::uint64_t id, DrainKind kind, AssetId target,
                                             ProtectedServiceClass protected_class, bool required,
                                             ObligationState state, std::uint64_t issued_sequence) {
  DrainObligation obligation;
  obligation.id = ObligationId::FromValue(id);
  obligation.kind = kind;
  obligation.target = target;
  obligation.protected_class = protected_class;
  obligation.required = required;
  obligation.state = state;
  obligation.issued_sequence = ObservationSequence::FromValue(issued_sequence);
  obligation.issued_at =
      Timestamp{kBaseNanos + static_cast<std::int64_t>(issued_sequence) * kNanosPerSecond};
  obligation.issued_to = std::string(ToString(kind)) + "-owner";
  obligation.detail = "drain obligation " + std::to_string(id);
  return obligation;
}

/// First case: a fully populated authorized-removal case whose obligations,
/// residual items, exceptions, evidence, receipts, registry entries and notes
/// exercise every optional field the codec carries.
[[nodiscard]] RetirementCase MakeFirstCase() {
  const AssetId asset = AssetId::FromValue(kAssetOne);
  const SiteId site = SiteId::FromValue(0x2001U);
  const RackId rack = RackId::FromValue(0x3001U);
  const LifecycleGeneration lifecycle = LifecycleGeneration::FromValue(1U);
  const HardwareGeneration hardware = HardwareGeneration::FromValue(11U);
  const FirmwareGeneration firmware = FirmwareGeneration::FromValue(12U);

  RetirementCase record;
  record.key = CaseKey{asset, lifecycle};
  record.plan = PlanId::FromValue(kPlanOne);
  record.fence = MakeFence(asset, site, rack, lifecycle, hardware, firmware, record.plan,
                           Revision::FromValue(4U));
  record.phase = Phase::removal_authorized;
  record.resume_phase = Phase::unknown;
  record.blocker = Blocker{};
  record.created_at = Timestamp{kBaseNanos};
  record.updated_at = Timestamp{kBaseNanos + 400 * kNanosPerSecond};
  record.created_by = IncarnationId::FromValue(0x7004U);
  record.active_authority = AuthorityMask{BitOf(AuthorityDomain::monitoring_binding)};

  // Obligation 3 is not required, so it never contributes to the fence binding.
  record.obligations.push_back(
      MakeObligation(1U, DrainKind::asi_workload, asset, ProtectedServiceClass::none, true,
                     ObligationState::outstanding, 11U));
  record.obligations.back().acknowledged_sequence = ObservationSequence::FromValue(12U);
  record.obligations.back().acknowledged_at = Timestamp{kBaseNanos + 12 * kNanosPerSecond};
  record.obligations.back().acknowledged_by = "asi-scheduler";

  DrainObligation satisfied =
      MakeObligation(2U, DrainKind::dfi_route, asset, ProtectedServiceClass::none, true,
                     ObligationState::satisfied, 20U);
  satisfied.satisfaction_evidence = EvidenceId::FromValue(2U);
  satisfied.satisfied_sequence = ObservationSequence::FromValue(25U);
  satisfied.satisfied_at = Timestamp{kBaseNanos + 25 * kNanosPerSecond};
  satisfied.satisfied_by = "dfi-control";
  record.obligations.push_back(satisfied);

  record.obligations.push_back(
      MakeObligation(3U, DrainKind::tenant_service, asset, ProtectedServiceClass::none, false,
                     ObligationState::acknowledged, 30U));

  DrainObligation waived =
      MakeObligation(4U, DrainKind::power_dependency, asset, ProtectedServiceClass::none, true,
                     ObligationState::waived, 40U);
  waived.waiver = ExceptionId::FromValue(1U);
  record.obligations.push_back(waived);

  ResidualItem pending;
  pending.id = ResidualItemId::FromValue(1U);
  pending.category = ResidualCategory::persistent_media;
  pending.disposition = ResidualDisposition::pending;
  pending.observed_sequence = ObservationSequence::FromValue(60U);
  pending.recorded_at = Timestamp{kBaseNanos + 60 * kNanosPerSecond};
  pending.detail = "NVMe media retained on site";
  record.residual.push_back(pending);

  ResidualItem handled;
  handled.id = ResidualItemId::FromValue(2U);
  handled.category = ResidualCategory::network_identity;
  handled.disposition = ResidualDisposition::handled;
  handled.observed_sequence = ObservationSequence::FromValue(61U);
  handled.recorded_at = Timestamp{kBaseNanos + 61 * kNanosPerSecond};
  handled.detail = "address released";
  handled.authority = "dfi";
  handled.reference = "DFI-RELEASE-9";
  record.residual.push_back(handled);

  ResidualItem not_applicable;
  not_applicable.id = ResidualItemId::FromValue(3U);
  not_applicable.category = ResidualCategory::reservation;
  not_applicable.disposition = ResidualDisposition::not_applicable;
  not_applicable.observed_sequence = ObservationSequence::FromValue(62U);
  not_applicable.recorded_at = Timestamp{kBaseNanos + 62 * kNanosPerSecond};
  not_applicable.detail = "no reservation was ever held";
  not_applicable.authority = "capacity-board";
  not_applicable.reference = "CAP-1";
  record.residual.push_back(not_applicable);

  ResidualItem waived_residual;
  waived_residual.id = ResidualItemId::FromValue(4U);
  waived_residual.category = ResidualCategory::credential_reference;
  waived_residual.disposition = ResidualDisposition::waived;
  waived_residual.observed_sequence = ObservationSequence::FromValue(63U);
  waived_residual.recorded_at = Timestamp{kBaseNanos + 63 * kNanosPerSecond};
  waived_residual.detail = "key reference outlives the asset";
  waived_residual.authority = "security-board";
  waived_residual.reference = "SEC-7";
  waived_residual.waiver = ExceptionId::FromValue(2U);
  record.residual.push_back(waived_residual);

  PolicyException exception_one;
  exception_one.id = ExceptionId::FromValue(1U);
  exception_one.obligation = ObligationId::FromValue(4U);
  exception_one.plan = record.plan;
  exception_one.revision = record.fence.revision;
  exception_one.binding_digest = BindingDigest(record.fence.binding());
  exception_one.policy_generation = PolicyGeneration::FromValue(kPolicyGeneration);
  exception_one.authority = "facilities-policy-board";
  exception_one.reference = "EXC-2026-0001";
  exception_one.rationale = "tenant drain exceeds the maintenance window";
  exception_one.recorded_at = Timestamp{kBaseNanos + kNanosPerSecond};
  exception_one.recorded_by = IncarnationId::FromValue(0x7005U);
  record.exceptions.push_back(exception_one);

  PolicyException exception_two;
  exception_two.id = ExceptionId::FromValue(2U);
  exception_two.item = ResidualItemId::FromValue(4U);
  exception_two.plan = record.plan;
  exception_two.revision = record.fence.revision;
  exception_two.binding_digest = BindingDigest(record.fence.binding());
  exception_two.policy_generation = PolicyGeneration::FromValue(kPolicyGeneration);
  exception_two.authority = "security-board";
  exception_two.reference = "EXC-2026-0002";
  exception_two.rationale = "credential reference removal is owned by the key authority";
  exception_two.recorded_at = Timestamp{kBaseNanos + 2 * kNanosPerSecond};
  exception_two.recorded_by = IncarnationId::FromValue(0x7005U);
  record.exceptions.push_back(exception_two);

  record.evidence.push_back(MakeEvidence(1U, EvidenceKind::drain_request_acknowledgement, 12U,
                                         "asi-scheduler", "ASI-ACK-1", kNonAsciiText,
                                         DrainKind::unknown, ObligationId{}));
  record.evidence.push_back(MakeEvidence(2U, EvidenceKind::drain_satisfaction, 25U, "dfi-control",
                                         "DFI-1", "route withdrawn", DrainKind::dfi_route,
                                         ObligationId::FromValue(2U)));
  record.evidence.push_back(MakeEvidence(3U, EvidenceKind::isolation_observation, 50U,
                                         "facility-observer", "ISO-1", "isolation observed",
                                         DrainKind::unknown, ObligationId{}));
  record.evidence.push_back(MakeEvidence(4U, EvidenceKind::removal_authorization, 55U,
                                         "removal-board", "AUTH-1", "removal authorized",
                                         DrainKind::unknown, ObligationId{}));

  const Digest binding = BindingDigest(record.fence.binding());
  record.receipts.push_back(MakeReceipt(1U, AuthorityDomain::power_control, binding, 70U,
                                        record.plan, record.fence.revision));
  record.receipts.push_back(MakeReceipt(2U, AuthorityDomain::dfi_network, binding, 71U,
                                        record.plan, record.fence.revision));

  record.registry.push_back(MakeRegistry(1U, RequestKind::create_plan, "attempt-1", 3U, 1U,
                                         Phase::commissioned));
  record.registry.push_back(MakeRegistry(2U, RequestKind::begin_draining, "attempt-2", 8U, 2U,
                                         Phase::draining));

  record.notes.push_back(
      RecordedNote{"canonical_deletion_not_owned", "canonical asset deletion is not owned", 
                   Timestamp{kBaseNanos + 3 * kNanosPerSecond}});
  record.notes.push_back(
      RecordedNote{"media_retained", kNonAsciiText, Timestamp{kBaseNanos + 4 * kNanosPerSecond}});

  record.isolation_observed = true;
  record.isolation_evidence = EvidenceId::FromValue(3U);
  record.isolation_sequence = ObservationSequence::FromValue(50U);
  record.isolation_observer = "facility-observer";
  record.isolation_reference = "ISO-1";

  record.removal_authorized = true;
  record.removal_authorization_evidence = EvidenceId::FromValue(4U);
  record.removal_authority = "removal-board";
  record.removal_authorization_reference = "AUTH-1";
  record.removal_authorized_at = Timestamp{kBaseNanos + 55 * kNanosPerSecond};

  record.removal.observed = true;
  record.removal.evidence = EvidenceId::FromValue(3U);
  record.removal.observer = "facility-observer";
  record.removal.reference = "REM-1";
  record.removal.observation_sequence = ObservationSequence::FromValue(90U);
  record.removal.observed_at = Timestamp{kBaseNanos + 90 * kNanosPerSecond};
  record.removal.canonical_deletion = false;

  record.cancel_reason.clear();
  record.failure_reason.clear();

  RefreshObligationBinding(record);
  return record;
}

/// Second case: blocked on an outstanding protected drain, with a non-actionable
/// resume phase absent and a full battery of attached records.
[[nodiscard]] RetirementCase MakeSecondCase() {
  const AssetId asset = AssetId::FromValue(kAssetTwo);
  const SiteId site = SiteId::FromValue(0x2002U);
  const RackId rack = RackId::FromValue(0x3002U);
  const LifecycleGeneration lifecycle = LifecycleGeneration::FromValue(2U);
  const HardwareGeneration hardware = HardwareGeneration::FromValue(21U);
  const FirmwareGeneration firmware = FirmwareGeneration::FromValue(22U);

  RetirementCase record;
  record.key = CaseKey{asset, lifecycle};
  record.plan = PlanId::FromValue(kPlanTwo);
  record.fence = MakeFence(asset, site, rack, lifecycle, hardware, firmware, record.plan,
                           Revision::FromValue(9U));
  record.phase = Phase::blocked;
  record.resume_phase = Phase::residual_handling;

  Blocker blocker;
  blocker.reason = BlockerReason::drain_outstanding;
  blocker.code = ErrorCode::unmet_obligation;
  blocker.observed_phase = Phase::drain_required;
  blocker.blocked_at = Phase::drain_required;
  blocker.detail = "obligation 0000000000000005 is still outstanding";
  blocker.observed.push_back(ErrorDetail{"obligation", "0000000000000005"});
  blocker.observed.push_back(ErrorDetail{"state", "unknown"});
  blocker.observed.push_back(ErrorDetail{"protected_class", "safety"});
  blocker.required_action = "record external drain satisfaction evidence";
  record.blocker = blocker;

  record.created_at = Timestamp{kBaseNanos + 10 * kNanosPerSecond};
  record.updated_at = Timestamp{kBaseNanos + 20 * kNanosPerSecond};
  record.created_by = IncarnationId::FromValue(0x7006U);
  record.active_authority = AuthorityMask{};

  record.obligations.push_back(MakeObligation(5U, DrainKind::protected_service, asset,
                                              ProtectedServiceClass::safety, true,
                                              ObligationState::unknown, 15U));

  DrainObligation satisfied =
      MakeObligation(6U, DrainKind::maintenance_window, asset, ProtectedServiceClass::none, true,
                     ObligationState::satisfied, 16U);
  satisfied.satisfaction_evidence = EvidenceId::FromValue(5U);
  satisfied.satisfied_sequence = ObservationSequence::FromValue(80U);
  satisfied.satisfied_at = Timestamp{kBaseNanos + 80 * kNanosPerSecond};
  satisfied.satisfied_by = "maintenance-office";
  record.obligations.push_back(satisfied);

  DrainObligation failed =
      MakeObligation(7U, DrainKind::cooling_dependency, asset, ProtectedServiceClass::none, true,
                     ObligationState::failed, 17U);
  failed.failure_reason = "cooling loop cannot be isolated before the facility window";
  record.obligations.push_back(failed);

  DrainObligation waived =
      MakeObligation(8U, DrainKind::external_dependency, asset, ProtectedServiceClass::none, true,
                     ObligationState::waived, 18U);
  waived.waiver = ExceptionId::FromValue(3U);
  record.obligations.push_back(waived);

  ResidualItem handled;
  handled.id = ResidualItemId::FromValue(5U);
  handled.category = ResidualCategory::physical_asset;
  handled.disposition = ResidualDisposition::handled;
  handled.observed_sequence = ObservationSequence::FromValue(30U);
  handled.recorded_at = Timestamp{kBaseNanos + 30 * kNanosPerSecond};
  handled.detail = "chassis staged for removal";
  handled.authority = "site-operations";
  handled.reference = "SITE-1";
  record.residual.push_back(handled);

  ResidualItem unknown_item;
  unknown_item.id = ResidualItemId::FromValue(6U);
  unknown_item.category = ResidualCategory::facility_reference;
  unknown_item.disposition = ResidualDisposition::unknown;
  unknown_item.observed_sequence = ObservationSequence::FromValue(31U);
  unknown_item.recorded_at = Timestamp{kBaseNanos + 31 * kNanosPerSecond};
  unknown_item.detail = "facility reference not yet enumerated";
  record.residual.push_back(unknown_item);

  PolicyException exception_three;
  exception_three.id = ExceptionId::FromValue(3U);
  exception_three.obligation = ObligationId::FromValue(8U);
  exception_three.plan = record.plan;
  exception_three.revision = record.fence.revision;
  exception_three.binding_digest = BindingDigest(record.fence.binding());
  exception_three.policy_generation = PolicyGeneration::FromValue(kPolicyGeneration);
  exception_three.authority = "facilities-policy-board";
  exception_three.reference = "EXC-2026-0003";
  exception_three.rationale = "external dependency is owned by a third party";
  exception_three.recorded_at = Timestamp{kBaseNanos + 5 * kNanosPerSecond};
  exception_three.recorded_by = IncarnationId::FromValue(0x7007U);
  record.exceptions.push_back(exception_three);

  record.evidence.push_back(MakeEvidence(5U, EvidenceKind::drain_satisfaction, 80U,
                                         "maintenance-office", "MW-9", "window honoured",
                                         DrainKind::maintenance_window,
                                         ObligationId::FromValue(6U)));
  record.evidence.push_back(MakeEvidence(6U, EvidenceKind::policy_exception, 81U, "policy-board",
                                         "POL-1", "exception granted", DrainKind::unknown,
                                         ObligationId{}));

  const Digest binding = BindingDigest(record.fence.binding());
  record.receipts.push_back(MakeReceipt(3U, AuthorityDomain::tenant_lease, binding, 82U,
                                        record.plan, record.fence.revision));

  record.registry.push_back(MakeRegistry(3U, RequestKind::block_plan, "attempt-3", 12U, 9U,
                                         Phase::blocked));

  record.notes.push_back(RecordedNote{"blocked_pending_residual",
                                      "residual checklist is incomplete",
                                      Timestamp{kBaseNanos + 6 * kNanosPerSecond}});

  record.isolation_observed = false;
  record.removal_authorized = false;
  record.removal.observed = false;
  record.removal.canonical_deletion = false;

  RefreshObligationBinding(record);
  return record;
}

[[nodiscard]] StoreState MakeFixtureState() {
  StoreState state;
  state.sequence = CommitSequence::FromValue(12U);
  state.generations.facility_epoch = FacilityEpoch::FromValue(kFacilityEpoch);
  state.generations.policy_generation = PolicyGeneration::FromValue(kPolicyGeneration);
  state.generations.dependency_generation = DependencyGeneration::FromValue(kDependencyGeneration);
  state.generations.capacity_generation = CapacityGeneration::FromValue(kCapacityGeneration);
  state.generations.topology_generation = TopologyGeneration::FromValue(kTopologyGeneration);
  state.generations.maintenance_generation =
      MaintenanceGeneration::FromValue(kMaintenanceGeneration);

  state.counters.last_plan = PlanId::FromValue(kPlanTwo);
  state.counters.last_evidence = EvidenceId::FromValue(6U);
  state.counters.last_receipt = ReceiptId::FromValue(3U);
  state.counters.last_obligation = ObligationId::FromValue(8U);
  state.counters.last_residual = ResidualItemId::FromValue(6U);
  state.counters.last_exception = ExceptionId::FromValue(3U);
  state.counters.last_observation = ObservationSequence::FromValue(90U);

  const FleetAsset first =
      MakeAsset(kAssetOne, 0x2001U, 0x3001U, 11U, 12U, 1U,
                BitOf(AuthorityDomain::asi_execution) | BitOf(AuthorityDomain::dfi_network),
                "R-9000", "SN-ALPHA-0001", PlanId::FromValue(kPlanOne));
  const FleetAsset second = MakeAsset(kAssetTwo, 0x2002U, 0x3002U, 21U, 22U, 2U,
                                      BitOf(AuthorityDomain::maintenance_window), kNonAsciiText,
                                      "SN-BETA-0002", PlanId::FromValue(kPlanTwo));
  state.fleet.emplace(first.id, first);
  state.fleet.emplace(second.id, second);

  const RetirementCase case_one = MakeFirstCase();
  const RetirementCase case_two = MakeSecondCase();
  state.cases.emplace(case_one.key, case_one);
  state.cases.emplace(case_two.key, case_two);
  return state;
}

[[nodiscard]] std::string MakeFixturePayload() { return EncodeState(MakeFixtureState()); }

// ---------------------------------------------------------------------------
// Field by field comparison
// ---------------------------------------------------------------------------

void CheckDigest(const Digest& actual, const Digest& expected, const std::string& label) {
  DF_CHECK_MSG(actual == expected,
               label + ": digest mismatch actual=" + actual.to_hex() +
                   " expected=" + expected.to_hex());
}

void CheckAssetEqual(const FleetAsset& actual, const FleetAsset& expected) {
  DF_CHECK_EQ(actual.id.value(), expected.id.value());
  DF_CHECK_EQ(actual.site.value(), expected.site.value());
  DF_CHECK_EQ(actual.rack.value(), expected.rack.value());
  DF_CHECK_EQ(actual.hardware_generation.value(), expected.hardware_generation.value());
  DF_CHECK_EQ(actual.firmware_generation.value(), expected.firmware_generation.value());
  DF_CHECK_EQ(actual.lifecycle_generation.value(), expected.lifecycle_generation.value());
  DF_CHECK_EQ(actual.active_authority.bits, expected.active_authority.bits);
  DF_CHECK_EQ(actual.present, expected.present);
  DF_CHECK_EQ(actual.model, expected.model);
  DF_CHECK_EQ(actual.serial, expected.serial);
  DF_CHECK_EQ(actual.registered_at.unix_nanos, expected.registered_at.unix_nanos);
  DF_CHECK_EQ(actual.registered_by.value(), expected.registered_by.value());
  DF_CHECK_EQ(actual.current_plan.value(), expected.current_plan.value());
  DF_CHECK(actual == expected);
}

void CheckFenceEqual(const PlanFence& actual, const PlanFence& expected) {
  DF_CHECK_EQ(actual.asset.value(), expected.asset.value());
  DF_CHECK_EQ(actual.site.value(), expected.site.value());
  DF_CHECK_EQ(actual.rack.value(), expected.rack.value());
  DF_CHECK_EQ(actual.lifecycle_generation.value(), expected.lifecycle_generation.value());
  DF_CHECK_EQ(actual.hardware_generation.value(), expected.hardware_generation.value());
  DF_CHECK_EQ(actual.firmware_generation.value(), expected.firmware_generation.value());
  DF_CHECK_EQ(actual.facility_epoch.value(), expected.facility_epoch.value());
  DF_CHECK_EQ(actual.policy_generation.value(), expected.policy_generation.value());
  DF_CHECK_EQ(actual.dependency_generation.value(), expected.dependency_generation.value());
  DF_CHECK_EQ(actual.capacity_generation.value(), expected.capacity_generation.value());
  DF_CHECK_EQ(actual.topology_generation.value(), expected.topology_generation.value());
  DF_CHECK_EQ(actual.maintenance_generation.value(), expected.maintenance_generation.value());
  DF_CHECK_EQ(actual.active_obligation_count, expected.active_obligation_count);
  CheckDigest(actual.active_obligation_digest, expected.active_obligation_digest, "fence");
  DF_CHECK_EQ(actual.plan.value(), expected.plan.value());
  DF_CHECK_EQ(actual.revision.value(), expected.revision.value());
}

void CheckBlockerEqual(const Blocker& actual, const Blocker& expected) {
  DF_CHECK_EQ(actual.reason, expected.reason);
  DF_CHECK_EQ(actual.code, expected.code);
  DF_CHECK_EQ(actual.observed_phase, expected.observed_phase);
  DF_CHECK_EQ(actual.blocked_at, expected.blocked_at);
  DF_CHECK_EQ(actual.detail, expected.detail);
  DF_CHECK_EQ(actual.required_action, expected.required_action);
  DF_CHECK_EQ(actual.observed.size(), expected.observed.size());
  for (std::size_t i = 0; i < actual.observed.size() && i < expected.observed.size(); ++i) {
    DF_CHECK_EQ(actual.observed[i].key, expected.observed[i].key);
    DF_CHECK_EQ(actual.observed[i].value, expected.observed[i].value);
  }
}

void CheckObligationEqual(const DrainObligation& actual, const DrainObligation& expected) {
  DF_CHECK_EQ(actual.id.value(), expected.id.value());
  DF_CHECK_EQ(actual.kind, expected.kind);
  DF_CHECK_EQ(actual.target.value(), expected.target.value());
  DF_CHECK_EQ(actual.protected_class, expected.protected_class);
  DF_CHECK_EQ(actual.required, expected.required);
  DF_CHECK_EQ(actual.state, expected.state);
  DF_CHECK_EQ(actual.issued_sequence.value(), expected.issued_sequence.value());
  DF_CHECK_EQ(actual.issued_at.unix_nanos, expected.issued_at.unix_nanos);
  DF_CHECK_EQ(actual.issued_to, expected.issued_to);
  DF_CHECK_EQ(actual.detail, expected.detail);
  DF_CHECK_EQ(actual.acknowledged_sequence.value(), expected.acknowledged_sequence.value());
  DF_CHECK_EQ(actual.acknowledged_at.unix_nanos, expected.acknowledged_at.unix_nanos);
  DF_CHECK_EQ(actual.acknowledged_by, expected.acknowledged_by);
  DF_CHECK_EQ(actual.satisfaction_evidence.value(), expected.satisfaction_evidence.value());
  DF_CHECK_EQ(actual.satisfied_sequence.value(), expected.satisfied_sequence.value());
  DF_CHECK_EQ(actual.satisfied_at.unix_nanos, expected.satisfied_at.unix_nanos);
  DF_CHECK_EQ(actual.satisfied_by, expected.satisfied_by);
  DF_CHECK_EQ(actual.waiver.value(), expected.waiver.value());
  DF_CHECK_EQ(actual.failure_reason, expected.failure_reason);
  DF_CHECK(actual == expected);
}

void CheckResidualEqual(const ResidualItem& actual, const ResidualItem& expected) {
  DF_CHECK_EQ(actual.id.value(), expected.id.value());
  DF_CHECK_EQ(actual.category, expected.category);
  DF_CHECK_EQ(actual.disposition, expected.disposition);
  DF_CHECK_EQ(actual.observed_sequence.value(), expected.observed_sequence.value());
  DF_CHECK_EQ(actual.recorded_at.unix_nanos, expected.recorded_at.unix_nanos);
  DF_CHECK_EQ(actual.detail, expected.detail);
  DF_CHECK_EQ(actual.authority, expected.authority);
  DF_CHECK_EQ(actual.reference, expected.reference);
  DF_CHECK_EQ(actual.waiver.value(), expected.waiver.value());
  DF_CHECK(actual == expected);
}

void CheckExceptionEqual(const PolicyException& actual, const PolicyException& expected) {
  DF_CHECK_EQ(actual.id.value(), expected.id.value());
  DF_CHECK_EQ(actual.item.value(), expected.item.value());
  DF_CHECK_EQ(actual.obligation.value(), expected.obligation.value());
  DF_CHECK_EQ(actual.plan.value(), expected.plan.value());
  DF_CHECK_EQ(actual.revision.value(), expected.revision.value());
  CheckDigest(actual.binding_digest, expected.binding_digest, "exception");
  DF_CHECK_EQ(actual.policy_generation.value(), expected.policy_generation.value());
  DF_CHECK_EQ(actual.authority, expected.authority);
  DF_CHECK_EQ(actual.reference, expected.reference);
  DF_CHECK_EQ(actual.rationale, expected.rationale);
  DF_CHECK_EQ(actual.recorded_at.unix_nanos, expected.recorded_at.unix_nanos);
  DF_CHECK_EQ(actual.recorded_by.value(), expected.recorded_by.value());
  DF_CHECK(actual == expected);
}

void CheckEvidenceEqual(const EvidenceRef& actual, const EvidenceRef& expected) {
  DF_CHECK_EQ(actual.id.value(), expected.id.value());
  DF_CHECK_EQ(actual.kind, expected.kind);
  DF_CHECK_EQ(actual.provenance, expected.provenance);
  DF_CHECK_EQ(actual.freshness, expected.freshness);
  DF_CHECK_EQ(actual.observer, expected.observer);
  DF_CHECK_EQ(actual.subject_kind, expected.subject_kind);
  DF_CHECK_EQ(actual.subject_obligation.value(), expected.subject_obligation.value());
  DF_CHECK_EQ(actual.reference, expected.reference);
  DF_CHECK_EQ(actual.detail, expected.detail);
  DF_CHECK_EQ(actual.observation_sequence.value(), expected.observation_sequence.value());
  DF_CHECK_EQ(actual.recorded_at.unix_nanos, expected.recorded_at.unix_nanos);
  DF_CHECK_EQ(actual.recorded_by.value(), expected.recorded_by.value());
  DF_CHECK(actual == expected);
}

void CheckReceiptEqual(const RevocationReceipt& actual, const RevocationReceipt& expected) {
  DF_CHECK_EQ(actual.id.value(), expected.id.value());
  DF_CHECK_EQ(actual.domain, expected.domain);
  CheckDigest(actual.binding_digest, expected.binding_digest, "receipt");
  DF_CHECK_EQ(actual.authority, expected.authority);
  DF_CHECK_EQ(actual.reference, expected.reference);
  DF_CHECK_EQ(actual.detail, expected.detail);
  DF_CHECK_EQ(actual.observation_sequence.value(), expected.observation_sequence.value());
  DF_CHECK_EQ(actual.recorded_at.unix_nanos, expected.recorded_at.unix_nanos);
  DF_CHECK_EQ(actual.recorded_by.value(), expected.recorded_by.value());
  DF_CHECK_EQ(actual.recorded_under_plan.value(), expected.recorded_under_plan.value());
  DF_CHECK_EQ(actual.recorded_under_revision.value(), expected.recorded_under_revision.value());
  DF_CHECK(actual == expected);
}

void CheckRegistryEqual(const IssuedRequest& actual, const IssuedRequest& expected) {
  DF_CHECK_EQ(actual.attempt.value(), expected.attempt.value());
  DF_CHECK_EQ(actual.kind, expected.kind);
  CheckDigest(actual.key.digest, expected.key.digest, "registry key");
  DF_CHECK_EQ(actual.committed_sequence.value(), expected.committed_sequence.value());
  DF_CHECK_EQ(actual.resulting_revision.value(), expected.resulting_revision.value());
  DF_CHECK_EQ(actual.resulting_phase, expected.resulting_phase);
  DF_CHECK_EQ(actual.issued_at.unix_nanos, expected.issued_at.unix_nanos);
  DF_CHECK(actual == expected);
}

void CheckNoteEqual(const RecordedNote& actual, const RecordedNote& expected) {
  DF_CHECK_EQ(actual.code, expected.code);
  DF_CHECK_EQ(actual.text, expected.text);
  DF_CHECK_EQ(actual.recorded_at.unix_nanos, expected.recorded_at.unix_nanos);
  DF_CHECK(actual == expected);
}

void CheckCaseEqual(const RetirementCase& actual, const RetirementCase& expected) {
  DF_CHECK_EQ(actual.key.asset.value(), expected.key.asset.value());
  DF_CHECK_EQ(actual.key.generation.value(), expected.key.generation.value());
  DF_CHECK_EQ(actual.plan.value(), expected.plan.value());
  CheckFenceEqual(actual.fence, expected.fence);
  DF_CHECK_EQ(actual.phase, expected.phase);
  DF_CHECK_EQ(actual.resume_phase, expected.resume_phase);
  CheckBlockerEqual(actual.blocker, expected.blocker);
  DF_CHECK_EQ(actual.created_at.unix_nanos, expected.created_at.unix_nanos);
  DF_CHECK_EQ(actual.updated_at.unix_nanos, expected.updated_at.unix_nanos);
  DF_CHECK_EQ(actual.created_by.value(), expected.created_by.value());
  DF_CHECK_EQ(actual.active_authority.bits, expected.active_authority.bits);

  DF_CHECK_EQ(actual.obligations.size(), expected.obligations.size());
  for (std::size_t i = 0; i < actual.obligations.size() && i < expected.obligations.size(); ++i) {
    CheckObligationEqual(actual.obligations[i], expected.obligations[i]);
  }
  DF_CHECK_EQ(actual.residual.size(), expected.residual.size());
  for (std::size_t i = 0; i < actual.residual.size() && i < expected.residual.size(); ++i) {
    CheckResidualEqual(actual.residual[i], expected.residual[i]);
  }
  DF_CHECK_EQ(actual.exceptions.size(), expected.exceptions.size());
  for (std::size_t i = 0; i < actual.exceptions.size() && i < expected.exceptions.size(); ++i) {
    CheckExceptionEqual(actual.exceptions[i], expected.exceptions[i]);
  }
  DF_CHECK_EQ(actual.evidence.size(), expected.evidence.size());
  for (std::size_t i = 0; i < actual.evidence.size() && i < expected.evidence.size(); ++i) {
    CheckEvidenceEqual(actual.evidence[i], expected.evidence[i]);
  }
  DF_CHECK_EQ(actual.receipts.size(), expected.receipts.size());
  for (std::size_t i = 0; i < actual.receipts.size() && i < expected.receipts.size(); ++i) {
    CheckReceiptEqual(actual.receipts[i], expected.receipts[i]);
  }
  DF_CHECK_EQ(actual.registry.size(), expected.registry.size());
  for (std::size_t i = 0; i < actual.registry.size() && i < expected.registry.size(); ++i) {
    CheckRegistryEqual(actual.registry[i], expected.registry[i]);
  }
  DF_CHECK_EQ(actual.notes.size(), expected.notes.size());
  for (std::size_t i = 0; i < actual.notes.size() && i < expected.notes.size(); ++i) {
    CheckNoteEqual(actual.notes[i], expected.notes[i]);
  }

  DF_CHECK_EQ(actual.isolation_observed, expected.isolation_observed);
  DF_CHECK_EQ(actual.isolation_evidence.value(), expected.isolation_evidence.value());
  DF_CHECK_EQ(actual.isolation_sequence.value(), expected.isolation_sequence.value());
  DF_CHECK_EQ(actual.isolation_observer, expected.isolation_observer);
  DF_CHECK_EQ(actual.isolation_reference, expected.isolation_reference);
  DF_CHECK_EQ(actual.removal_authorized, expected.removal_authorized);
  DF_CHECK_EQ(actual.removal_authorization_evidence.value(),
              expected.removal_authorization_evidence.value());
  DF_CHECK_EQ(actual.removal_authority, expected.removal_authority);
  DF_CHECK_EQ(actual.removal_authorization_reference,
              expected.removal_authorization_reference);
  DF_CHECK_EQ(actual.removal_authorized_at.unix_nanos, expected.removal_authorized_at.unix_nanos);
  DF_CHECK_EQ(actual.removal.observed, expected.removal.observed);
  DF_CHECK_EQ(actual.removal.evidence.value(), expected.removal.evidence.value());
  DF_CHECK_EQ(actual.removal.observer, expected.removal.observer);
  DF_CHECK_EQ(actual.removal.reference, expected.removal.reference);
  DF_CHECK_EQ(actual.removal.observation_sequence.value(),
              expected.removal.observation_sequence.value());
  DF_CHECK_EQ(actual.removal.observed_at.unix_nanos, expected.removal.observed_at.unix_nanos);
  DF_CHECK_EQ(actual.removal.canonical_deletion, expected.removal.canonical_deletion);
  DF_CHECK_EQ(actual.cancel_reason, expected.cancel_reason);
  DF_CHECK_EQ(actual.failure_reason, expected.failure_reason);
}

void CheckStateEqual(const StoreState& actual, const StoreState& expected) {
  DF_CHECK_EQ(actual.sequence.value(), expected.sequence.value());
  DF_CHECK(actual.generations == expected.generations);
  DF_CHECK(actual.counters == expected.counters);

  DF_CHECK_EQ(actual.fleet.size(), expected.fleet.size());
  for (const auto& entry : actual.fleet) {
    const auto found = expected.fleet.find(entry.first);
    DF_CHECK_MSG(found != expected.fleet.end(), "decoded fleet lost an asset");
    if (found != expected.fleet.end()) {
      CheckAssetEqual(entry.second, found->second);
    }
  }

  DF_CHECK_EQ(actual.cases.size(), expected.cases.size());
  for (const auto& entry : actual.cases) {
    const auto found = expected.cases.find(entry.first);
    DF_CHECK_MSG(found != expected.cases.end(), "decoded cases lost a case key");
    if (found != expected.cases.end()) {
      CheckCaseEqual(entry.second, found->second);
    }
  }
}

// ---------------------------------------------------------------------------
// Textual mutation helpers
// ---------------------------------------------------------------------------

[[nodiscard]] std::vector<std::string> LinesOf(const std::string& payload) {
  std::vector<std::string> lines;
  std::size_t start = 0;
  while (start < payload.size()) {
    const std::size_t newline = payload.find('\n', start);
    if (newline == std::string::npos) {
      lines.push_back(payload.substr(start));
      break;
    }
    lines.push_back(payload.substr(start, newline - start));
    start = newline + 1U;
  }
  return lines;
}

[[nodiscard]] std::string JoinLines(const std::vector<std::string>& lines) {
  std::string out;
  for (const std::string& line : lines) {
    out += line;
    out += '\n';
  }
  return out;
}

/// Index of the first line whose tag equals \p tag exactly.
[[nodiscard]] std::size_t FindLine(const std::vector<std::string>& lines, std::string_view tag) {
  for (std::size_t i = 0; i < lines.size(); ++i) {
    const std::string_view line(lines[i]);
    if (line == tag) {
      return i;
    }
    if (line.size() > tag.size() && line.substr(0, tag.size()) == tag &&
        line[tag.size()] == ' ') {
      return i;
    }
  }
  return lines.size();
}

[[nodiscard]] std::vector<std::string> TokensOf(const std::string& line) {
  std::vector<std::string> tokens;
  std::size_t start = 0;
  while (start < line.size()) {
    const std::size_t space = line.find(' ', start);
    if (space == std::string::npos) {
      tokens.push_back(line.substr(start));
      break;
    }
    tokens.push_back(line.substr(start, space - start));
    start = space + 1U;
  }
  return tokens;
}

[[nodiscard]] std::string JoinTokens(const std::vector<std::string>& tokens) {
  std::string out;
  for (std::size_t i = 0; i < tokens.size(); ++i) {
    if (i != 0U) {
      out += ' ';
    }
    out += tokens[i];
  }
  return out;
}

/// Replaces one whitespace separated token of a payload line.
[[nodiscard]] std::string ReplaceToken(const std::string& payload, std::string_view tag,
                                       std::size_t token_index, const std::string& replacement) {
  std::vector<std::string> lines = LinesOf(payload);
  const std::size_t index = FindLine(lines, tag);
  DF_CHECK_MSG(index < lines.size(), "fixture payload has no line with the expected tag");
  std::vector<std::string> tokens = TokensOf(lines[index]);
  DF_CHECK_MSG(token_index < tokens.size(), "fixture line has fewer tokens than expected");
  tokens[token_index] = replacement;
  lines[index] = JoinTokens(tokens);
  return JoinLines(lines);
}

/// Removes one whitespace separated token of a payload line.
[[nodiscard]] std::string RemoveToken(const std::string& payload, std::string_view tag,
                                      std::size_t token_index) {
  std::vector<std::string> lines = LinesOf(payload);
  const std::size_t index = FindLine(lines, tag);
  DF_CHECK_MSG(index < lines.size(), "fixture payload has no line with the expected tag");
  std::vector<std::string> tokens = TokensOf(lines[index]);
  DF_CHECK_MSG(token_index < tokens.size(), "fixture line has fewer tokens than expected");
  tokens.erase(tokens.begin() + static_cast<std::ptrdiff_t>(token_index));
  lines[index] = JoinTokens(tokens);
  return JoinLines(lines);
}

/// Appends a token to a payload line.
[[nodiscard]] std::string AppendToken(const std::string& payload, std::string_view tag,
                                      const std::string& extra) {
  std::vector<std::string> lines = LinesOf(payload);
  const std::size_t index = FindLine(lines, tag);
  DF_CHECK_MSG(index < lines.size(), "fixture payload has no line with the expected tag");
  lines[index] += ' ';
  lines[index] += extra;
  return JoinLines(lines);
}

/// Replaces the first byte of a payload line.
[[nodiscard]] std::string ReplaceFirstByte(const std::string& payload, std::string_view tag,
                                           char replacement) {
  std::vector<std::string> lines = LinesOf(payload);
  const std::size_t index = FindLine(lines, tag);
  DF_CHECK_MSG(index < lines.size(), "fixture payload has no line with the expected tag");
  DF_CHECK_MSG(!lines[index].empty(), "fixture line is empty");
  lines[index][0] = replacement;
  return JoinLines(lines);
}

[[nodiscard]] std::string WithByteAt(std::string text, std::size_t offset, char value) {
  DF_CHECK_MSG(offset < text.size(), "byte offset is outside the record");
  text[offset] = value;
  return text;
}

void WriteLe64(std::string& text, std::size_t offset, std::uint64_t value) {
  for (std::size_t i = 0; i < 8U; ++i) {
    const auto byte = static_cast<char>((value >> (8U * i)) & 0xFFU);
    text[offset + i] = byte;
  }
}

/// Token positions within the fixed encodings of the fixture's lines.
constexpr std::size_t kAssetModelToken = 9U;
constexpr std::size_t kFenceDigestToken = 14U;
constexpr std::size_t kStateSequenceToken = 1U;
constexpr std::size_t kPhaseToken = 1U;
constexpr std::size_t kObligationRequiredToken = 5U;

// ---------------------------------------------------------------------------
// Round trip and determinism
// ---------------------------------------------------------------------------

DF_TEST(Format_EncodeState_RoundTripsHandBuiltStateExactly) {
  const StoreState original = MakeFixtureState();
  const std::string payload = EncodeState(original);
  DF_CHECK(!payload.empty());
  DF_CHECK_EQ(payload.substr(0, 5), std::string("DFAB "));

  const auto decoded = DecodeState(payload);
  DF_CHECK_MSG(decoded.ok(), "hand-built fixture payload failed to decode: " +
                                 (decoded.ok() ? std::string() : decoded.error().to_string()));
  if (!decoded.ok()) {
    return;
  }
  CheckStateEqual(decoded.value(), original);
  DF_CHECK_EQ(EncodeState(decoded.value()), payload);
}

DF_TEST(Format_EncodeState_IsDeterministic) {
  const StoreState state = MakeFixtureState();
  const std::string first = EncodeState(state);
  const std::string second = EncodeState(state);
  DF_CHECK_EQ(first, second);

  // The same logical state built in a different insertion order encodes
  // identically: the fleet and case maps are walked in key order.
  StoreState reordered;
  reordered.sequence = state.sequence;
  reordered.generations = state.generations;
  reordered.counters = state.counters;
  std::vector<std::pair<AssetId, FleetAsset>> assets(state.fleet.begin(), state.fleet.end());
  for (auto it = assets.rbegin(); it != assets.rend(); ++it) {
    reordered.fleet.emplace(it->first, it->second);
  }
  std::vector<std::pair<CaseKey, RetirementCase>> cases(state.cases.begin(), state.cases.end());
  for (auto it = cases.rbegin(); it != cases.rend(); ++it) {
    reordered.cases.emplace(it->first, it->second);
  }
  DF_CHECK_EQ(EncodeState(reordered), first);
}

DF_TEST(Format_EncodeDecodeEncode_IsStable) {
  const std::string payload = MakeFixturePayload();
  const auto decoded = DecodeState(payload);
  DF_CHECK(decoded.ok());
  if (!decoded.ok()) {
    return;
  }
  const std::string reencoded = EncodeState(decoded.value());
  DF_CHECK_EQ(reencoded, payload);

  const auto again = DecodeState(reencoded);
  DF_CHECK(again.ok());
  if (again.ok()) {
    DF_CHECK_EQ(EncodeState(again.value()), reencoded);
  }
}

// ---------------------------------------------------------------------------
// Strict rejection: one targeted textual mutation per documented failure
// ---------------------------------------------------------------------------

DF_TEST(Format_DecodeState_RejectsWrongPayloadVersion) {
  const std::string mutated = ReplaceToken(MakeFixturePayload(), "DFAB", 1U, "2");
  DF_CHECK_CODE(DecodeState(mutated), ErrorCode::unsupported_format_version);
}

DF_TEST(Format_DecodeState_RejectsUnknownFirstTag) {
  std::vector<std::string> lines = LinesOf(MakeFixturePayload());
  const std::size_t index = FindLine(lines, "DFAB");
  DF_CHECK(index < lines.size());
  lines[index] = "DFAX 1";
  DF_CHECK_CODE(DecodeState(JoinLines(lines)), ErrorCode::trailing_data);
}

DF_TEST(Format_DecodeState_RejectsMissingTokenOnALine) {
  // The STATE line carries seven integers; dropping the last one leaves the
  // reader without a field it requires.
  const std::string payload = MakeFixturePayload();
  const std::vector<std::string> lines = LinesOf(payload);
  const std::size_t index = FindLine(lines, "STATE");
  DF_CHECK(index < lines.size());
  DF_CHECK_EQ(TokensOf(lines[index]).size(), static_cast<std::size_t>(8));
  const std::string mutated = RemoveToken(payload, "STATE", 7U);
  DF_CHECK_CODE(DecodeState(mutated), ErrorCode::missing_field);
}

DF_TEST(Format_DecodeState_RejectsTrailingTokenOnALine) {
  const std::string mutated = AppendToken(MakeFixturePayload(), "STATE", "0");
  DF_CHECK_CODE(DecodeState(mutated), ErrorCode::trailing_data);
}

DF_TEST(Format_DecodeState_RejectsTrailingContentAfterEnd) {
  const std::string payload = MakeFixturePayload();
  DF_CHECK(payload.size() > 4U);
  DF_CHECK_EQ(payload.substr(payload.size() - 4U), std::string("END\n"));
  std::string mutated = payload;
  mutated += "JUNK\n";
  DF_CHECK_CODE(DecodeState(mutated), ErrorCode::trailing_data);
}

DF_TEST(Format_DecodeState_RejectsEmptyLine) {
  std::vector<std::string> lines = LinesOf(MakeFixturePayload());
  DF_CHECK(lines.size() > 2U);
  lines.insert(lines.begin() + 1, std::string());
  DF_CHECK_CODE(DecodeState(JoinLines(lines)), ErrorCode::malformed_payload);
}

DF_TEST(Format_DecodeState_RejectsByteOutsidePrintableAscii) {
  const std::string mutated = ReplaceFirstByte(MakeFixturePayload(), "STATE", '\x01');
  DF_CHECK_CODE(DecodeState(mutated), ErrorCode::invalid_utf8);
}

DF_TEST(Format_DecodeState_RejectsNonDecimalInteger) {
  const std::string mutated = ReplaceToken(MakeFixturePayload(), "STATE", kStateSequenceToken, "7x");
  DF_CHECK_CODE(DecodeState(mutated), ErrorCode::malformed_payload);
}

DF_TEST(Format_DecodeState_RejectsNonCanonicalIntegerWithLeadingZero) {
  const std::string mutated = ReplaceToken(MakeFixturePayload(), "STATE", kStateSequenceToken, "07");
  DF_CHECK_CODE(DecodeState(mutated), ErrorCode::malformed_payload);
}

DF_TEST(Format_DecodeState_RejectsIntegerOverflowingSixtyFourBits) {
  const std::string mutated =
      ReplaceToken(MakeFixturePayload(), "STATE", kStateSequenceToken, "99999999999999999999");
  DF_CHECK_CODE(DecodeState(mutated), ErrorCode::out_of_range);
}

DF_TEST(Format_DecodeState_RejectsOutOfRangeEnumerator) {
  // Phase 15 does not exist; the greatest legal phase is 14 (cancelled).
  const std::string mutated = ReplaceToken(MakeFixturePayload(), "PHASE", kPhaseToken, "15");
  DF_CHECK_CODE(DecodeState(mutated), ErrorCode::malformed_payload);
}

DF_TEST(Format_DecodeState_RejectsBadDigestField) {
  std::vector<std::string> lines = LinesOf(MakeFixturePayload());
  const std::size_t index = FindLine(lines, "FENCE");
  DF_CHECK(index < lines.size());
  std::vector<std::string> tokens = TokensOf(lines[index]);
  DF_CHECK(kFenceDigestToken < tokens.size());
  DF_CHECK_EQ(tokens[kFenceDigestToken].size(), static_cast<std::size_t>(64));
  tokens[kFenceDigestToken][0] = 'z';
  lines[index] = JoinTokens(tokens);
  DF_CHECK_CODE(DecodeState(JoinLines(lines)), ErrorCode::malformed_hex);
}

DF_TEST(Format_DecodeState_RejectsInvalidHexInTextField) {
  const std::string mutated = ReplaceToken(MakeFixturePayload(), "A", kAssetModelToken, "abc");
  DF_CHECK_CODE(DecodeState(mutated), ErrorCode::malformed_hex);
}

DF_TEST(Format_DecodeState_RejectsInvalidUtf8InTextField) {
  // 0xFF is valid hexadecimal but is not a well-formed UTF-8 leading byte.
  const std::string mutated = ReplaceToken(MakeFixturePayload(), "A", kAssetModelToken, "ff");
  DF_CHECK_CODE(DecodeState(mutated), ErrorCode::invalid_utf8);
}

DF_TEST(Format_DecodeState_RejectsCaseWhoseObligationBindingWasEdited) {
  // The active-obligation count and digest are derived state. Clearing the
  // "required" flag of a blocking obligation without recomputing the fence must
  // be refused: a hand-edited generation cannot smuggle a stale obligation view
  // past the fence comparison.
  std::vector<std::string> lines = LinesOf(MakeFixturePayload());
  const std::size_t index = FindLine(lines, "O");
  DF_CHECK(index < lines.size());
  std::vector<std::string> tokens = TokensOf(lines[index]);
  DF_CHECK(kObligationRequiredToken < tokens.size());
  DF_CHECK_EQ(tokens[kObligationRequiredToken], std::string("1"));
  tokens[kObligationRequiredToken] = "0";
  lines[index] = JoinTokens(tokens);
  DF_CHECK_CODE(DecodeState(JoinLines(lines)), ErrorCode::malformed_payload);
}

// ---------------------------------------------------------------------------
// Truncation robustness
// ---------------------------------------------------------------------------

DF_TEST(Format_DecodeState_EveryPrefixFailsCleanlyOrDecodesExactly) {
  const std::string payload = MakeFixturePayload();
  const std::vector<ErrorCode> allowed = {
      ErrorCode::payload_too_small,     ErrorCode::malformed_payload,
      ErrorCode::missing_field,         ErrorCode::trailing_data,
      ErrorCode::invalid_utf8,          ErrorCode::unsupported_format_version,
      ErrorCode::out_of_range,          ErrorCode::string_too_long,
      ErrorCode::unexpected_token,      ErrorCode::too_many_items,
      ErrorCode::unset_identity,        ErrorCode::unset_generation,
      ErrorCode::malformed_hex,         ErrorCode::duplicate_identity,
      ErrorCode::unknown_asset,         ErrorCode::unknown_evidence,
      ErrorCode::unknown_exception,     ErrorCode::identity_mismatch,
      ErrorCode::payload_too_large};
  for (std::size_t length = 0; length <= payload.size(); ++length) {
    const std::string prefix = payload.substr(0, length);
    const auto decoded = DecodeState(prefix);
    if (decoded.ok()) {
      // A prefix that decodes must be a complete, canonical generation.
      DF_CHECK_EQ(EncodeState(decoded.value()), prefix);
      DF_CHECK_EQ(length, payload.size());
      continue;
    }
    bool recognised = false;
    for (const ErrorCode code : allowed) {
      if (decoded.error().code == code) {
        recognised = true;
        break;
      }
    }
    DF_CHECK_MSG(recognised, "truncation produced an undocumented error code: " +
                                 decoded.error().to_string());
  }
}

// ---------------------------------------------------------------------------
// Record framing
// ---------------------------------------------------------------------------

DF_TEST(Format_BuildRecord_ParseRecordRoundTrips) {
  const std::string payload = MakeFixturePayload();
  const std::string record = BuildRecord(payload, CommitSequence::FromValue(42U));
  DF_CHECK_EQ(record.size(), kStoreHeaderSize + payload.size());

  const auto parsed = ParseRecord(record, std::nullopt);
  DF_CHECK_MSG(parsed.ok(), "a freshly built record failed to parse: " +
                                (parsed.ok() ? std::string() : parsed.error().to_string()));
  if (!parsed.ok()) {
    return;
  }
  DF_CHECK_EQ(parsed.value().sequence.value(), 42ULL);
  DF_CHECK_EQ(parsed.value().payload, payload);
  DF_CHECK_EQ(parsed.value().payload_size, static_cast<std::uint64_t>(payload.size()));
  CheckDigest(parsed.value().payload_digest, Sha256::Of(payload), "parsed payload");

  const auto exact = ParseRecord(record, static_cast<std::uint64_t>(record.size()));
  DF_CHECK(exact.ok());

  // A record followed by trailing bytes is rejected rather than truncated.
  const std::string padded = record + "x";
  DF_CHECK_CODE(ParseRecord(padded, std::nullopt), ErrorCode::trailing_data);
  DF_CHECK_CODE(ParseRecord(padded, static_cast<std::uint64_t>(padded.size())),
                ErrorCode::trailing_data);

  // An explicit expected_size that does not equal header plus payload is a
  // length disagreement, not a silent truncation.
  DF_CHECK_CODE(ParseRecord(record, static_cast<std::uint64_t>(record.size() + 1U)),
                ErrorCode::out_of_range);
  DF_CHECK_CODE(ParseRecord(record, static_cast<std::uint64_t>(record.size() - 1U)),
                ErrorCode::out_of_range);
}

DF_TEST(Format_ParseRecord_RejectsShortRecord) {
  const std::string record = BuildRecord(MakeFixturePayload(), CommitSequence::FromValue(1U));
  const std::string truncated = record.substr(0, kStoreHeaderSize - 1U);
  DF_CHECK_CODE(ParseRecord(truncated, std::nullopt), ErrorCode::malformed_payload);
}

DF_TEST(Format_ParseRecord_RejectsWrongMagic) {
  const std::string record = BuildRecord(MakeFixturePayload(), CommitSequence::FromValue(1U));
  const std::string mutated = WithByteAt(record, 0U, 'X');
  DF_CHECK_CODE(ParseRecord(mutated, std::nullopt), ErrorCode::malformed_payload);
}

DF_TEST(Format_ParseRecord_RejectsWrongFormatVersion) {
  const std::string record = BuildRecord(MakeFixturePayload(), CommitSequence::FromValue(1U));
  const std::string mutated = WithByteAt(record, 8U, '\x02');
  DF_CHECK_CODE(ParseRecord(mutated, std::nullopt), ErrorCode::unsupported_format_version);
}

DF_TEST(Format_ParseRecord_RejectsWrongRecordKind) {
  const std::string record = BuildRecord(MakeFixturePayload(), CommitSequence::FromValue(1U));
  const std::string mutated = WithByteAt(record, 12U, '\x02');
  DF_CHECK_CODE(ParseRecord(mutated, std::nullopt), ErrorCode::malformed_payload);
}

DF_TEST(Format_ParseRecord_RejectsNonZeroReservedField) {
  const std::string record = BuildRecord(MakeFixturePayload(), CommitSequence::FromValue(1U));
  const std::string mutated = WithByteAt(record, 48U, '\x01');
  DF_CHECK_CODE(ParseRecord(mutated, std::nullopt), ErrorCode::reserved_not_zero);
}

DF_TEST(Format_ParseRecord_RejectsPayloadSizeBelowTheMinimum) {
  const std::string record = BuildRecord(MakeFixturePayload(), CommitSequence::FromValue(1U));
  std::string mutated = record;
  WriteLe64(mutated, 24U, 0U);
  DF_CHECK_CODE(ParseRecord(mutated, std::nullopt), ErrorCode::payload_too_small);
}

DF_TEST(Format_ParseRecord_RejectsPayloadSizeAboveTheMaximum) {
  const std::string record = BuildRecord(MakeFixturePayload(), CommitSequence::FromValue(1U));
  std::string mutated = record;
  WriteLe64(mutated, 24U, kMaxPayloadSize + 1U);
  DF_CHECK_CODE(ParseRecord(mutated, std::nullopt), ErrorCode::payload_too_large);
}

DF_TEST(Format_ParseRecord_RejectsLengthNotEqualToHeaderPlusPayload) {
  const std::string record = BuildRecord(MakeFixturePayload(), CommitSequence::FromValue(1U));
  const std::string truncated = record.substr(0, record.size() - 1U);
  DF_CHECK_CODE(ParseRecord(truncated, std::nullopt), ErrorCode::trailing_data);
}

DF_TEST(Format_ParseRecord_RejectsFlippedHeaderDigestByte) {
  const std::string record = BuildRecord(MakeFixturePayload(), CommitSequence::FromValue(1U));
  const std::string mutated = WithByteAt(record, 41U, static_cast<char>(record[41] ^ 0x5A));
  DF_CHECK_CODE(ParseRecord(mutated, std::nullopt), ErrorCode::malformed_payload);
}

DF_TEST(Format_ParseRecord_RejectsFlippedPayloadByte) {
  const std::string payload = MakeFixturePayload();
  const std::string record = BuildRecord(payload, CommitSequence::FromValue(1U));
  const std::size_t offset = kStoreHeaderSize + 3U;
  const std::string mutated =
      WithByteAt(record, offset, static_cast<char>(record[offset] ^ 0x01));
  DF_CHECK_CODE(ParseRecord(mutated, std::nullopt), ErrorCode::malformed_payload);
  DF_CHECK(ParseRecord(record, std::nullopt).ok());
}

DF_TEST(Format_BuildRecord_EmbedsTheSuppliedSequence) {
  const std::string payload = MakeFixturePayload();
  const std::string first = BuildRecord(payload, CommitSequence::FromValue(1U));
  const std::string second = BuildRecord(payload, CommitSequence::FromValue(2U));
  DF_CHECK_EQ(first.size(), second.size());
  DF_CHECK_NE(first, second);
  const auto parsed = ParseRecord(second, std::nullopt);
  DF_CHECK(parsed.ok());
  if (parsed.ok()) {
    DF_CHECK_EQ(parsed.value().sequence.value(), 2ULL);
  }
}

}  // namespace

DF_TEST_MAIN()

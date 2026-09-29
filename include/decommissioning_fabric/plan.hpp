// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// The decommissioning plan: fence, case record, registry, and decision.
//
// A plan is bound to an exact generation binding. If any generation in that
// binding changes, the plan's fence no longer matches and every request against
// the old binding is rejected rather than best-effort applied. That is the whole
// point of the fence: an operator cannot authorise removal against a facility
// shape that no longer exists.

#ifndef DECOMMISSIONING_FABRIC_PLAN_HPP
#define DECOMMISSIONING_FABRIC_PLAN_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "decommissioning_fabric/authority.hpp"
#include "decommissioning_fabric/errors.hpp"
#include "decommissioning_fabric/evidence.hpp"
#include "decommissioning_fabric/hash.hpp"
#include "decommissioning_fabric/ids.hpp"
#include "decommissioning_fabric/lifecycle.hpp"
#include "decommissioning_fabric/obligations.hpp"
#include "decommissioning_fabric/residual.hpp"
#include "decommissioning_fabric/time.hpp"

namespace decommissioning_fabric {

// ---------------------------------------------------------------------------
// Generation binding
// ---------------------------------------------------------------------------

/// The generation portion of a fence: everything whose change invalidates
/// previously recorded authority, drain evidence, and residual dispositions.
///
/// Deliberately excluded: the plan revision (which advances on every accepted
/// mutation) and the active-obligation digest (which changes when a drain is
/// satisfied). Adding a drain obligation must NOT silently un-revoke power, but
/// advancing the facility epoch or the policy generation must force authority to
/// be re-established.
struct GenerationBinding {
  AssetId asset;
  SiteId site;
  RackId rack;
  LifecycleGeneration lifecycle_generation;
  HardwareGeneration hardware_generation;
  FirmwareGeneration firmware_generation;
  FacilityEpoch facility_epoch;
  PolicyGeneration policy_generation;
  DependencyGeneration dependency_generation;
  CapacityGeneration capacity_generation;
  TopologyGeneration topology_generation;
  MaintenanceGeneration maintenance_generation;

  friend bool operator==(const GenerationBinding&, const GenerationBinding&) = default;
  friend bool operator<(const GenerationBinding& lhs, const GenerationBinding& rhs) noexcept {
    return lhs.asset < rhs.asset;
  }
};

/// SHA-256 over the canonical fixed-order encoding of every binding field.
/// Never zero for a well-formed binding, so a zero digest always means "unset".
[[nodiscard]] Digest BindingDigest(const GenerationBinding& binding);

// ---------------------------------------------------------------------------
// Fence
// ---------------------------------------------------------------------------

enum class FenceField : std::uint32_t {
  none = 0,
  asset = 1,
  site = 2,
  rack = 3,
  hardware_generation = 4,
  firmware_generation = 5,
  lifecycle_generation = 6,
  dependency_generation = 7,
  policy_generation = 8,
  capacity_generation = 9,
  topology_generation = 10,
  maintenance_generation = 11,
  facility_epoch = 12,
  active_obligation_count = 13,
  active_obligation_digest = 14,
  revision = 15,
};

inline constexpr std::size_t kFenceFieldOrderCount = 13;

/// The fixed order in which binding mismatches are reported. The same request
/// against the same state therefore always names the same first mismatching
/// field, independent of map ordering, thread scheduling, and unrelated state.
inline constexpr FenceField kFenceFieldOrder[kFenceFieldOrderCount] = {
    FenceField::asset,
    FenceField::site,
    FenceField::rack,
    FenceField::hardware_generation,
    FenceField::firmware_generation,
    FenceField::lifecycle_generation,
    FenceField::dependency_generation,
    FenceField::policy_generation,
    FenceField::capacity_generation,
    FenceField::topology_generation,
    FenceField::maintenance_generation,
    FenceField::facility_epoch,
    FenceField::active_obligation_digest};

[[nodiscard]] std::string_view ToString(FenceField field) noexcept;

struct PlanFence {
  AssetId asset;
  SiteId site;
  RackId rack;

  LifecycleGeneration lifecycle_generation;
  HardwareGeneration hardware_generation;
  FirmwareGeneration firmware_generation;

  FacilityEpoch facility_epoch;
  PolicyGeneration policy_generation;
  DependencyGeneration dependency_generation;
  CapacityGeneration capacity_generation;
  TopologyGeneration topology_generation;
  MaintenanceGeneration maintenance_generation;

  /// Count and digest of the obligations that are required and not yet
  /// resolved, i.e. the ones actively blocking this plan.
  std::uint32_t active_obligation_count{0};
  Digest active_obligation_digest;

  PlanId plan;
  Revision revision;

  [[nodiscard]] GenerationBinding binding() const noexcept;

  /// True when every unit the domain requires to be set is set. A zero
  /// generation where the domain requires >= 1 is malformed, never "default".
  [[nodiscard]] bool all_required_set() const noexcept;

  /// The first required unit that is unset, in kFenceFieldOrder order, or
  /// FenceField::none when the fence is well formed.
  [[nodiscard]] FenceField first_unset_field() const noexcept;

  friend bool operator==(const PlanFence&, const PlanFence&) = default;
};

enum class FenceClass : std::uint32_t {
  current = 0,
  stale = 1,
  revision_behind = 2,
  superseded = 3,
  malformed = 4,
};

[[nodiscard]] constexpr std::string_view ToString(FenceClass klass) noexcept {
  switch (klass) {
    case FenceClass::current: return "current";
    case FenceClass::stale: return "stale";
    case FenceClass::revision_behind: return "revision_behind";
    case FenceClass::superseded: return "superseded";
    case FenceClass::malformed: return "malformed";
  }
  return "malformed";
}

struct FenceComparison {
  FenceClass classification{FenceClass::current};
  FenceField first_mismatch{FenceField::none};

  /// Rendered values of the mismatching field, for the refusal detail. Both are
  /// rendered with the same formatter so a human can see the difference.
  std::string requested_value;
  std::string current_value;

  [[nodiscard]] ErrorCode code() const noexcept;
};

/// Compares a caller-supplied fence against the live fence of a case.
///
/// Order: superseded (different asset) -> malformed (unset unit) -> stale
/// (binding mismatch, first field in kFenceFieldOrder) -> revision_behind
/// (current revision is newer) -> stale (requested revision is newer than any
/// revision this runtime published) -> current.
[[nodiscard]] FenceComparison ClassifyFence(const PlanFence& requested,
                                            const PlanFence& current);

/// Renders a fence field's value from a fence. Used for refusal details.
[[nodiscard]] std::string RenderFenceField(const PlanFence& fence, FenceField field);

/// Canonical, single-token rendering of a whole fence.
///
/// This is the compare-and-swap token an operator carries from the read that
/// produced their plan to the write that acts on it. It is hex encoded so it
/// survives shells, files, and copy/paste without quoting rules, and it round
/// trips exactly: DecodeFenceToken(EncodeFenceToken(f)) == f. A caller that
/// fabricates one is rejected by the fence comparison rather than trusted.
[[nodiscard]] std::string EncodeFenceToken(const PlanFence& fence);

/// Strict inverse of EncodeFenceToken. Rejects wrong field counts, non-hex
/// characters, out-of-range integers, and a digest that is not 64 hex digits.
[[nodiscard]] Result<PlanFence> DecodeFenceToken(std::string_view token);

// ---------------------------------------------------------------------------
// Case identity
// ---------------------------------------------------------------------------

/// Identifies one retirement attempt of one asset. Re-planning a cancelled or
/// failed asset increments LifecycleGeneration and therefore creates a distinct
/// case, leaving the previous attempt's evidence intact and fenced out.
struct CaseKey {
  AssetId asset;
  LifecycleGeneration generation;

  friend bool operator==(const CaseKey&, const CaseKey&) = default;
  friend bool operator<(const CaseKey& lhs, const CaseKey& rhs) noexcept {
    if (lhs.asset < rhs.asset) {
      return true;
    }
    if (rhs.asset < lhs.asset) {
      return false;
    }
    return lhs.generation < rhs.generation;
  }
};

// ---------------------------------------------------------------------------
// Request identity and idempotency
// ---------------------------------------------------------------------------

/// Every externally meaningful mutation is exactly one of these. Each one
/// carries its own attempt identity and its own fence, so a phase can never move
/// as a side effect of an unrelated request.
enum class RequestKind : std::uint32_t {
  unknown = 0,
  create_plan = 1,
  assess_dependencies = 2,
  set_drain_requirement = 3,
  acknowledge_drain = 4,
  satisfy_drain = 5,
  waive_drain = 6,
  begin_draining = 7,
  conclude_draining = 8,
  record_revocation = 9,
  conclude_authority_revocation = 10,
  set_residual_disposition = 11,
  record_policy_exception = 12,
  declare_isolation_ready = 13,
  authorize_removal = 14,
  observe_removal = 15,
  finalize_decommissioning = 16,
  cancel_plan = 17,
  fail_plan = 18,
  block_plan = 19,
  resume_plan = 20,
  ingest_evidence = 21,
};

inline constexpr std::size_t kRequestKindCount = 22;

/// The phase each request kind is a boundary for, when it is a boundary request.
/// Returns Phase::unknown for requests that never move the phase on their own.
[[nodiscard]] Phase BoundaryTargetPhase(RequestKind kind) noexcept;

[[nodiscard]] std::string_view ToString(RequestKind kind) noexcept;
[[nodiscard]] RequestKind RequestKindFromString(std::string_view name) noexcept;

/// Identity of one externally meaningful mutation.
///
/// The key is derived from the plan, the caller's attempt id, the request kind,
/// and a digest of the request payload. Replaying the identical request after a
/// lost response therefore produces the identical key, which is exactly what
/// makes replay detectable before staleness rejection.
struct IdempotencyKey {
  Digest digest;

  [[nodiscard]] std::string to_hex() const { return digest.to_hex(); }
  [[nodiscard]] bool is_set() const noexcept { return !digest.is_zero(); }

  friend bool operator==(const IdempotencyKey&, const IdempotencyKey&) = default;
};

/// A registry entry recording that a request was already applied.
struct IssuedRequest {
  AttemptId attempt;
  RequestKind kind{RequestKind::unknown};
  IdempotencyKey key;

  /// The durable commit sequence the original application produced.
  CommitSequence committed_sequence;
  Revision resulting_revision;
  Phase resulting_phase{Phase::unknown};
  Timestamp issued_at;

  friend bool operator==(const IssuedRequest&, const IssuedRequest&) = default;
};

// ---------------------------------------------------------------------------
// Notes and observations
// ---------------------------------------------------------------------------

/// A recorded, durable statement attached to a case. Notes are how the runtime
/// states what it did NOT do: "canonical deletion is not owned by this runtime".
struct RecordedNote {
  std::string code;
  std::string text;
  Timestamp recorded_at;

  friend bool operator==(const RecordedNote&, const RecordedNote&) = default;
};

/// Final-removal proof, distinct from the authorization to remove.
struct RemovalObservation {
  bool observed{false};
  EvidenceId evidence;
  std::string observer;
  std::string reference;
  ObservationSequence observation_sequence;
  Timestamp observed_at;

  /// Always false. This runtime does not own canonical asset deletion, and the
  /// field exists so that reports can say so explicitly rather than by omission.
  bool canonical_deletion{false};

  friend bool operator==(const RemovalObservation&, const RemovalObservation&) = default;
};

// ---------------------------------------------------------------------------
// Fleet asset
// ---------------------------------------------------------------------------

struct FleetAsset {
  AssetId id;
  SiteId site;
  RackId rack;
  HardwareGeneration hardware_generation;
  FirmwareGeneration firmware_generation;

  /// The current retirement attempt. Incremented by re-planning.
  LifecycleGeneration lifecycle_generation;

  /// The authority domains this asset currently holds. Retirement revokes them;
  /// absence of a bit is not by itself proof of revocation.
  AuthorityMask active_authority;

  bool present{true};
  std::string model;
  std::string serial;
  Timestamp registered_at;
  IncarnationId registered_by;
  PlanId current_plan;

  friend bool operator==(const FleetAsset&, const FleetAsset&) = default;
};

// ---------------------------------------------------------------------------
// The retirement case
// ---------------------------------------------------------------------------

struct RetirementCase {
  CaseKey key;
  PlanId plan;

  /// The live fence. Its revision is the case revision.
  PlanFence fence;

  Phase phase{Phase::unknown};

  /// Valid only while phase == blocked: the actionable phase to return to.
  Phase resume_phase{Phase::unknown};

  /// Last refusal. Cleared on a successful mutation.
  Blocker blocker;

  Timestamp created_at;
  Timestamp updated_at;
  IncarnationId created_by;

  /// The case's live belief about which authority domains the asset still
  /// holds, seeded from the fleet asset at plan creation.
  ///
  /// It is cleared ONLY by recording an external authority's revocation receipt:
  /// a bit never disappears because the runtime assumed something, and a receipt
  /// never revokes anything on its own. "A domain is revoked" therefore means
  /// exactly "the bit is absent AND a receipt bound to the current generation
  /// binding covers it", which is why absence without a receipt is reported as
  /// unknown rather than revoked.
  ///
  /// A new lifecycle generation seeds this mask from the fleet asset again, and
  /// the previous generation's receipts do not cover the new binding — so
  /// re-planning cannot silently inherit revoked authority.
  AuthorityMask active_authority;

  std::vector<DrainObligation> obligations;
  std::vector<ResidualItem> residual;
  std::vector<PolicyException> exceptions;
  std::vector<EvidenceRef> evidence;
  std::vector<RevocationReceipt> receipts;
  std::vector<IssuedRequest> registry;
  std::vector<RecordedNote> notes;

  bool isolation_observed{false};
  EvidenceId isolation_evidence;
  ObservationSequence isolation_sequence;
  std::string isolation_observer;
  std::string isolation_reference;

  bool removal_authorized{false};
  EvidenceId removal_authorization_evidence;
  std::string removal_authority;
  std::string removal_authorization_reference;
  Timestamp removal_authorized_at;

  RemovalObservation removal;

  std::string cancel_reason;
  std::string failure_reason;

  /// Looks up a recorded note by code. Returns nullptr when absent; an absent
  /// note is never rendered as an empty note.
  [[nodiscard]] const RecordedNote* find_note(std::string_view code) const noexcept;

  friend bool operator==(const RetirementCase&, const RetirementCase&) = default;
};

/// Recomputes fence.active_obligation_count and fence.active_obligation_digest
/// from the case's obligations. Called after every mutation that touches them.
void RefreshObligationBinding(RetirementCase& record);

/// Digest over the required-and-unresolved obligations, ascending ObligationId.
[[nodiscard]] Digest ActiveObligationDigest(const std::vector<DrainObligation>& obligations);

/// Sorted lookups. These never fall back to a default: a missing id returns
/// nullptr so the caller must produce a specific error.
[[nodiscard]] const DrainObligation* FindObligation(const RetirementCase& record,
                                                    ObligationId id) noexcept;
[[nodiscard]] DrainObligation* FindObligation(RetirementCase& record, ObligationId id) noexcept;
[[nodiscard]] const ResidualItem* FindResidual(const RetirementCase& record,
                                               ResidualItemId id) noexcept;
[[nodiscard]] ResidualItem* FindResidual(RetirementCase& record, ResidualItemId id) noexcept;
[[nodiscard]] const EvidenceRef* FindEvidence(const RetirementCase& record,
                                              EvidenceId id) noexcept;
[[nodiscard]] const PolicyException* FindException(const RetirementCase& record,
                                                   ExceptionId id) noexcept;

/// Returns the registry entry for an attempt, or nullptr.
[[nodiscard]] const IssuedRequest* FindIssued(const RetirementCase& record,
                                              AttemptId attempt) noexcept;

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

/// The outcome of an accepted mutation. "Applied" means the durable commit
/// landed; the caller never observes success before the commit point.
struct Decision {
  bool applied{false};
  bool replayed{false};
  RequestKind kind{RequestKind::unknown};

  PlanId plan;
  AssetId asset;
  LifecycleGeneration lifecycle_generation;

  Phase from_phase{Phase::unknown};
  Phase to_phase{Phase::unknown};

  Revision revision;
  CommitSequence committed_sequence;

  IdempotencyKey key;

  std::vector<RecordedNote> notes;
  std::vector<ErrorDetail> effects;

  friend bool operator==(const Decision&, const Decision&) = default;
};

}  // namespace decommissioning_fabric

#endif  // DECOMMISSIONING_FABRIC_PLAN_HPP

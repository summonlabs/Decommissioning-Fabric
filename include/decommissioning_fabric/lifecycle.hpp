// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Lifecycle phases, the legal transition table, and blockers.
//
// The transition table is the whole truth about what may follow what. Anything
// not in it is InvalidTransition, so a phase can never be reached by accident,
// by replay, or by a caller who "nearly" satisfied a predicate.
//
// Blocked is a first-class phase, not an error: it retains the last actionable
// phase in AssetRecord::resume_phase, so unblocking is a real transition rather
// than a re-plan that would silently discard accumulated evidence.

#ifndef DECOMMISSIONING_FABRIC_LIFECYCLE_HPP
#define DECOMMISSIONING_FABRIC_LIFECYCLE_HPP

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "decommissioning_fabric/errors.hpp"

namespace decommissioning_fabric {

enum class Phase : std::uint32_t {
  unknown = 0,
  commissioned = 1,
  requested = 2,
  dependency_assessment = 3,
  drain_required = 4,
  draining = 5,
  authority_revocation = 6,
  residual_handling = 7,
  isolation_ready = 8,
  removal_authorized = 9,
  removed_observed = 10,
  decommissioned = 11,
  blocked = 12,
  failed = 13,
  cancelled = 14,
};

inline constexpr std::size_t kPhaseCount = 15;

/// Fixed iteration order for reports and renderings.
inline constexpr std::array<Phase, kPhaseCount> kPhaseOrder = {
    Phase::unknown,       Phase::commissioned,       Phase::requested,
    Phase::dependency_assessment, Phase::drain_required, Phase::draining,
    Phase::authority_revocation,  Phase::residual_handling, Phase::isolation_ready,
    Phase::removal_authorized,    Phase::removed_observed,  Phase::decommissioned,
    Phase::blocked,       Phase::failed,             Phase::cancelled};

[[nodiscard]] constexpr std::string_view ToString(Phase phase) noexcept {
  switch (phase) {
    case Phase::unknown: return "unknown";
    case Phase::commissioned: return "commissioned";
    case Phase::requested: return "requested";
    case Phase::dependency_assessment: return "dependency_assessment";
    case Phase::drain_required: return "drain_required";
    case Phase::draining: return "draining";
    case Phase::authority_revocation: return "authority_revocation";
    case Phase::residual_handling: return "residual_handling";
    case Phase::isolation_ready: return "isolation_ready";
    case Phase::removal_authorized: return "removal_authorized";
    case Phase::removed_observed: return "removed_observed";
    case Phase::decommissioned: return "decommissioned";
    case Phase::blocked: return "blocked";
    case Phase::failed: return "failed";
    case Phase::cancelled: return "cancelled";
  }
  return "unknown";
}

/// Parses a phase name exactly. Returns Phase::unknown for anything
/// unrecognised, including the literal "unknown", so a caller must decide.
[[nodiscard]] Phase PhaseFromString(std::string_view name) noexcept;

/// Terminal phases accept no further transition except through a new lifecycle
/// generation, which creates a separate case record.
[[nodiscard]] constexpr bool IsTerminal(Phase phase) noexcept {
  return phase == Phase::decommissioned || phase == Phase::failed ||
         phase == Phase::cancelled;
}

/// The single terminal RETIREMENT phase. Removed observation is not canonical
/// deletion, and no other phase claims to be a completed retirement.
[[nodiscard]] constexpr bool IsRetirementComplete(Phase phase) noexcept {
  return phase == Phase::decommissioned;
}

/// A phase in which the plan is actively worked and from which a request may be
/// made, blocked, failed, or (where permitted) cancelled.
[[nodiscard]] constexpr bool IsActionable(Phase phase) noexcept {
  switch (phase) {
    case Phase::requested:
    case Phase::dependency_assessment:
    case Phase::drain_required:
    case Phase::draining:
    case Phase::authority_revocation:
    case Phase::residual_handling:
    case Phase::isolation_ready:
    case Phase::removal_authorized:
    case Phase::removed_observed:
      return true;
    default:
      return false;
  }
}

/// Cancellation is permitted only strictly before removal is authorized. Once
/// authorization has been granted the only safe outcomes are removal or an
/// explicit failure record; silently cancelling would leave an authorized
/// removal unaccounted for.
[[nodiscard]] constexpr bool IsCancellable(Phase phase) noexcept {
  switch (phase) {
    case Phase::requested:
    case Phase::dependency_assessment:
    case Phase::drain_required:
    case Phase::draining:
    case Phase::authority_revocation:
    case Phase::residual_handling:
    case Phase::isolation_ready:
      return true;
    default:
      return false;
  }
}

struct TransitionRule {
  Phase from{Phase::unknown};
  Phase to{Phase::unknown};
};

/// The static transition table. Regression edges (Draining -> DrainRequired and
/// friends) are deliberately present: a newly discovered dependency must send
/// the plan back to draining, not merely annotate it.
inline constexpr std::array<TransitionRule, 17> kLifecycleTransitions = {{
    {Phase::commissioned, Phase::requested},
    {Phase::requested, Phase::dependency_assessment},
    {Phase::requested, Phase::drain_required},
    {Phase::dependency_assessment, Phase::drain_required},
    {Phase::dependency_assessment, Phase::draining},
    {Phase::drain_required, Phase::draining},
    {Phase::draining, Phase::drain_required},
    {Phase::draining, Phase::authority_revocation},
    {Phase::authority_revocation, Phase::drain_required},
    {Phase::authority_revocation, Phase::residual_handling},
    {Phase::residual_handling, Phase::drain_required},
    {Phase::residual_handling, Phase::isolation_ready},
    {Phase::isolation_ready, Phase::drain_required},
    {Phase::isolation_ready, Phase::removal_authorized},
    {Phase::removal_authorized, Phase::removed_observed},
    {Phase::removed_observed, Phase::decommissioned},
    {Phase::removed_observed, Phase::removal_authorized},
}};

/// The complete legality predicate, including the dynamic Blocked/Failed/
/// Cancelled edges. \p resume_phase is consulted only when \p from is Blocked.
[[nodiscard]] bool IsLegalTransition(Phase from, Phase to, Phase resume_phase) noexcept;

/// A structured, auditable refusal.
///
/// Every refusal names four things: the reason category, the unmet prerequisite,
/// the observed values that were actually seen, and the action that would clear
/// it. A refusal that omits any of these is a defect, and the tests assert that
/// a non-none reason always carries a required_action and at least one detail
/// for the prerequisite class of failures.
enum class BlockerReason : std::uint32_t {
  none = 0,
  dependencies_unresolved = 1,
  drain_outstanding = 2,
  drain_acknowledged_not_satisfied = 3,
  drain_evidence_out_of_order = 4,
  authority_active = 5,
  authority_unknown = 6,
  residual_unknown = 7,
  residual_pending = 8,
  residual_checklist_incomplete = 9,
  isolation_not_observed = 10,
  removal_not_authorized = 11,
  removal_not_observed = 12,
  policy_violation = 13,
  protected_service_unresolved = 14,
  exception_required = 15,
  evidence_stale = 16,
  evidence_kind_mismatch = 17,
  fence_stale = 18,
  asset_unknown = 19,
  phase_does_not_permit = 20,
  operator_cancelled = 21,
  operator_failed = 22,
  store_unavailable = 23,
};

[[nodiscard]] constexpr std::string_view ToString(BlockerReason reason) noexcept {
  switch (reason) {
    case BlockerReason::none: return "none";
    case BlockerReason::dependencies_unresolved: return "dependencies_unresolved";
    case BlockerReason::drain_outstanding: return "drain_outstanding";
    case BlockerReason::drain_acknowledged_not_satisfied:
      return "drain_acknowledged_not_satisfied";
    case BlockerReason::drain_evidence_out_of_order: return "drain_evidence_out_of_order";
    case BlockerReason::authority_active: return "authority_active";
    case BlockerReason::authority_unknown: return "authority_unknown";
    case BlockerReason::residual_unknown: return "residual_unknown";
    case BlockerReason::residual_pending: return "residual_pending";
    case BlockerReason::residual_checklist_incomplete: return "residual_checklist_incomplete";
    case BlockerReason::isolation_not_observed: return "isolation_not_observed";
    case BlockerReason::removal_not_authorized: return "removal_not_authorized";
    case BlockerReason::removal_not_observed: return "removal_not_observed";
    case BlockerReason::policy_violation: return "policy_violation";
    case BlockerReason::protected_service_unresolved: return "protected_service_unresolved";
    case BlockerReason::exception_required: return "exception_required";
    case BlockerReason::evidence_stale: return "evidence_stale";
    case BlockerReason::evidence_kind_mismatch: return "evidence_kind_mismatch";
    case BlockerReason::fence_stale: return "fence_stale";
    case BlockerReason::asset_unknown: return "asset_unknown";
    case BlockerReason::phase_does_not_permit: return "phase_does_not_permit";
    case BlockerReason::operator_cancelled: return "operator_cancelled";
    case BlockerReason::operator_failed: return "operator_failed";
    case BlockerReason::store_unavailable: return "store_unavailable";
  }
  return "none";
}

struct Blocker {
  BlockerReason reason{BlockerReason::none};
  ErrorCode code{ErrorCode::ok};

  /// The phase the plan was in when the refusal was produced.
  Phase observed_phase{Phase::unknown};

  /// The phase whose predicate could not be satisfied.
  Phase blocked_at{Phase::unknown};

  /// One-line summary naming the unmet prerequisite.
  std::string detail;

  /// Observed values that caused the refusal. Ordered and deterministic.
  std::vector<ErrorDetail> observed;

  /// The concrete action that would clear the refusal.
  std::string required_action;

  [[nodiscard]] bool is_set() const noexcept { return reason != BlockerReason::none; }
  [[nodiscard]] std::string to_string() const;

  // Declared so that every record containing a Blocker (and therefore
  // RetirementCase itself) keeps a usable defaulted comparison instead of
  // silently having one deleted.
  friend bool operator==(const Blocker&, const Blocker&) = default;
};

}  // namespace decommissioning_fabric

#endif  // DECOMMISSIONING_FABRIC_LIFECYCLE_HPP

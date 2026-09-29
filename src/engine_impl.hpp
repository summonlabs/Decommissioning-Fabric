// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Private engine internals shared by engine.cpp and engine_query.cpp. Not
// installed and not part of the public API.

#ifndef DECOMMISSIONING_FABRIC_ENGINE_IMPL_HPP
#define DECOMMISSIONING_FABRIC_ENGINE_IMPL_HPP

#include <cstddef>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>

#include "decommissioning_fabric/engine.hpp"
#include "decommissioning_fabric/format.hpp"
#include "decommissioning_fabric/lock_order.hpp"
#include "decommissioning_fabric/store.hpp"
#include "decommissioning_fabric/time.hpp"

namespace decommissioning_fabric {

struct EngineImpl {
  Engine::Options options;
  Clock* clock{nullptr};
  SystemClock fallback_clock;

  /// One writer at a time. Held across validation, the durable commit, and
  /// publication, so two writers can never lose each other's update, while
  /// readers only ever contend on index_mu.
  mutable std::mutex mutation_mu;

  /// Guards the in-memory index. Shared for readers and for writers validating
  /// against a stable snapshot.
  mutable std::shared_mutex index_mu;

  mutable LockOrderValidator lock_order;

  DurableStore store;
  StoreState state;

  /// Recorded after every successful commit, read by Engine::last_commit().
  CommitStatistics last_commit;
};

/// The clock the engine is configured with.
[[nodiscard]] Timestamp NowOf(const EngineImpl& impl);

/// Computes the authority report for a case against its current binding.
[[nodiscard]] AuthorityReport AuthorityOf(const RetirementCase& record);

// ---------------------------------------------------------------------------
// Shared predicates. Validation and explanation call exactly the same code, so
// a blocker explanation can never disagree with a refusal.
// ---------------------------------------------------------------------------

/// Which prerequisite families a step must satisfy.
struct PrerequisiteNeeds {
  bool obligations{false};
  bool authority{false};
  bool residual{false};
};

/// The prerequisite families that must hold before a case may leave its phase.
[[nodiscard]] PrerequisiteNeeds NeedsForPhaseClosure(Phase phase);

/// The prerequisite families a specific request kind must satisfy.
[[nodiscard]] PrerequisiteNeeds NeedsForRequest(RequestKind kind);

/// Appends every unmet prerequisite blocker, in a fixed order: obligations in
/// stored (ascending identity) order, then authority domains in
/// kAuthorityDomains order, then residual items in ascending identity order.
void CollectPrerequisiteBlockers(const RetirementCase& record,
                                 const AuthorityReport& authority,
                                 const PrerequisiteNeeds& needs,
                                 std::vector<Blocker>& out);

/// Appends every policy blocker for a specific request kind.
void CollectPolicyBlockers(const RetirementCase& record, const AuthorityReport& authority,
                           RequestKind kind, std::vector<Blocker>& out);

/// The phase a case would advance to if every blocker cleared.
[[nodiscard]] Phase NextForwardPhase(const RetirementCase& record);

/// The action that clears the current blockers.
[[nodiscard]] std::string NextRequiredAction(const RetirementCase& record);

/// The evidence kind a drain obligation must be satisfied by.
[[nodiscard]] EvidenceKind RequiredEvidenceKind(const DrainObligation& obligation);

/// True when the residual checklist admits closure, ignoring exceptions.
[[nodiscard]] bool ResidualChecklistComplete(const RetirementCase& record);

/// True when every required obligation of the case is resolved.
[[nodiscard]] bool AllRequiredObligationsResolved(const RetirementCase& record);

/// The exception that passes a residual item, or nullptr when the item is not
/// waived or its exception is absent.
[[nodiscard]] const PolicyException* ResidualWaiver(const RetirementCase& record,
                                                    const ResidualItem& item);

/// True when an exception is bound to the case's current binding and policy
/// generation, i.e. it still applies.
[[nodiscard]] bool ExceptionStillBinds(const RetirementCase& record,
                                       const PolicyException& exception);

}  // namespace decommissioning_fabric

#endif  // DECOMMISSIONING_FABRIC_ENGINE_IMPL_HPP

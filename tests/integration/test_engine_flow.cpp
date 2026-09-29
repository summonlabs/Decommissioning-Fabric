// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// The substance of the repository: the semantics that are easy to get wrong.
// Each test here corresponds to one line of the doctrine, and each one would
// fail if that line were relaxed.

#include <string>
#include <vector>

#include "decommissioning_fabric/engine.hpp"
#include "fixture.hpp"
#include "harness.hpp"

namespace df = decommissioning_fabric;
using df_fixture::Driver;
using df_fixture::Finding;
using df_fixture::OpenEngine;
using df_fixture::TempDir;

namespace {

constexpr df::AssetId::underlying_type kAsset = 0x1001U;

/// Drives the plan to the point where isolation is declared, with every
/// precondition genuinely satisfied.
void ReachIsolationReady(Driver& driver) {
  DF_CHECK(driver.Register().ok());
  DF_CHECK(driver.CreatePlan().ok());
  DF_CHECK(driver
               .Assess({Finding(df::DrainKind::asi_workload), Finding(df::DrainKind::dfi_route)})
               .ok());
  const std::vector<df::ObligationId> obligations = driver.Obligations();
  DF_CHECK(obligations.size() == 2U);
  DF_CHECK(driver.Satisfy(obligations[0], df::DrainKind::asi_workload).ok());
  DF_CHECK(driver.Satisfy(obligations[1], df::DrainKind::dfi_route).ok());
  DF_CHECK(driver.Drains().ok());
  DF_CHECK(driver.RevokeAll().ok());
  DF_CHECK(driver.ConcludeDraining().ok());
  DF_CHECK(driver.ConcludeAuthority().ok());
  DF_CHECK(driver.FillResidual().ok());
  DF_CHECK(driver.Isolation().ok());
  DF_CHECK(driver.Phase() == df::Phase::isolation_ready);
}

}  // namespace

DF_TEST(Flow_FullLifecycleReachesDecommissioned) {
  const TempDir directory("flow_full");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));

  DF_CHECK(driver.Register().ok());
  DF_CHECK(driver.CreatePlan().ok());
  DF_CHECK(driver.Phase() == df::Phase::requested);

  DF_CHECK(driver.Assess({Finding(df::DrainKind::asi_workload),
                          Finding(df::DrainKind::tenant_service)})
               .ok());
  DF_CHECK(driver.Phase() == df::Phase::dependency_assessment);

  const std::vector<df::ObligationId> obligations = driver.Obligations();
  DF_CHECK(obligations.size() == 2U);
  DF_CHECK(driver.Satisfy(obligations[0], df::DrainKind::asi_workload).ok());
  DF_CHECK(driver.Satisfy(obligations[1], df::DrainKind::tenant_service).ok());
  DF_CHECK(driver.Drains().ok());
  DF_CHECK(driver.Phase() == df::Phase::draining);
  DF_CHECK(driver.RevokeAll().ok());
  DF_CHECK(driver.ConcludeDraining().ok());
  DF_CHECK(driver.Phase() == df::Phase::authority_revocation);
  DF_CHECK(driver.ConcludeAuthority().ok());
  DF_CHECK(driver.Phase() == df::Phase::residual_handling);
  DF_CHECK(driver.FillResidual().ok());
  DF_CHECK(driver.Isolation().ok());
  DF_CHECK(driver.Phase() == df::Phase::isolation_ready);
  DF_CHECK(driver.AuthorizeRemoval().ok());
  DF_CHECK(driver.Phase() == df::Phase::removal_authorized);
  DF_CHECK(driver.ObserveRemoval().ok());
  DF_CHECK(driver.Phase() == df::Phase::removed_observed);
  DF_CHECK(driver.Finalize().ok());
  DF_CHECK(driver.Phase() == df::Phase::decommissioned);
  DF_CHECK(df::IsRetirementComplete(driver.Phase()));

  // The sequence advanced once per accepted mutation and never went backwards.
  DF_CHECK(engine.value().commit_sequence().value() > 10U);

  // Nothing may follow the single terminal retirement phase.
  DF_CHECK(driver.Finalize().ok() == false);
  DF_CHECK(df::IsTerminal(driver.Phase()));
}

DF_TEST(Flow_DrainRequestedIsNotDrained) {
  const TempDir directory("flow_ack");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));

  DF_CHECK(driver.Register().ok());
  DF_CHECK(driver.CreatePlan().ok());
  DF_CHECK(driver.Assess({Finding(df::DrainKind::asi_workload)}).ok());
  const std::vector<df::ObligationId> obligations = driver.Obligations();
  DF_CHECK(obligations.size() == 1U);

  // Acknowledgement is metadata. It must not satisfy anything, and it must not
  // move the plan forward.
  DF_CHECK(driver.Acknowledge(obligations[0]).ok());
  auto view = driver.Case();
  DF_CHECK(view.ok());
  DF_CHECK(view.value().record.obligations[0].state == df::ObligationState::acknowledged);
  DF_CHECK(view.value().record.obligations[0].blocks_progress());
  DF_CHECK(view.value().record.obligations[0].satisfaction_evidence.is_unset());

  // Nothing blocks merely reaching the drain phase, but nothing may leave it
  // either: the acknowledgement is not a completion.
  DF_CHECK(driver.Drains().ok());
  DF_CHECK(driver.Phase() == df::Phase::draining);

  // Acknowledged-but-not-satisfied is a distinct, named blocker.
  auto blockers = engine.value().ExplainBlockers(view.value().record.key);
  DF_CHECK(blockers.ok());
  DF_CHECK(blockers.value().blockers.empty() == false);
  DF_CHECK(blockers.value().blockers.front().reason ==
           df::BlockerReason::drain_acknowledged_not_satisfied);
  DF_CHECK(blockers.value().ready_to_advance == false);

  const auto refused = driver.ConcludeDraining();
  DF_CHECK_CODE(refused, df::ErrorCode::unmet_obligation);
  DF_CHECK(driver.Phase() == df::Phase::draining);
}

DF_TEST(Flow_DrainSatisfactionNeedsEvidenceOfTheRightKind) {
  const TempDir directory("flow_kind");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));

  DF_CHECK(driver.Register().ok());
  DF_CHECK(driver.CreatePlan().ok());
  DF_CHECK(driver.Assess({Finding(df::DrainKind::asi_workload),
                          Finding(df::DrainKind::dfi_route)})
               .ok());
  const std::vector<df::ObligationId> obligations = driver.Obligations();

  // A report about a different drain satisfies nothing.
  const auto mismatched = driver.Satisfy(obligations[0], df::DrainKind::asi_workload, true);
  DF_CHECK_CODE(mismatched, df::ErrorCode::evidence_kind_mismatch);
  auto view = driver.Case();
  DF_CHECK(view.ok());
  DF_CHECK(view.value().record.obligations[0].is_open());

  // The right kind satisfies it, and binds the evidence to the obligation.
  DF_CHECK(driver.Satisfy(obligations[0], df::DrainKind::asi_workload).ok());
  view = driver.Case();
  DF_CHECK(view.ok());
  const df::DrainObligation& satisfied = view.value().record.obligations[0];
  DF_CHECK(satisfied.state == df::ObligationState::satisfied);
  DF_CHECK(satisfied.satisfaction_evidence.is_set());
  DF_CHECK(satisfied.satisfied_sequence > satisfied.issued_sequence);
  const df::EvidenceRef* evidence =
      df::FindEvidence(view.value().record, satisfied.satisfaction_evidence);
  DF_CHECK(evidence != nullptr);
  DF_CHECK(evidence->subject_obligation == satisfied.id);
  DF_CHECK(evidence->subject_kind == df::DrainKind::asi_workload);
  DF_CHECK(evidence->provenance == df::EvidenceProvenance::external_authority);
  DF_CHECK(df::IsAttributable(*evidence));
}

DF_TEST(Flow_DrainedIsNotIsolated) {
  const TempDir directory("flow_drained");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));

  DF_CHECK(driver.Register().ok());
  DF_CHECK(driver.CreatePlan().ok());
  DF_CHECK(driver.Assess({Finding(df::DrainKind::asi_workload)}).ok());
  const std::vector<df::ObligationId> obligations = driver.Obligations();
  DF_CHECK(driver.Satisfy(obligations[0], df::DrainKind::asi_workload).ok());
  DF_CHECK(driver.Drains().ok());
  DF_CHECK(driver.RevokeAll().ok());
  DF_CHECK(driver.ConcludeDraining().ok());
  DF_CHECK(driver.ConcludeAuthority().ok());
  DF_CHECK(driver.Phase() == df::Phase::residual_handling);

  // Everything is drained and every authority is revoked, but the residual
  // checklist is empty AND no isolation has been observed.
  const auto refused = driver.Isolation();
  DF_CHECK(refused.ok() == false);
  DF_CHECK(refused.error().stage == df::ValidationStage::prerequisite);
}

DF_TEST(Flow_IsolatedIsNotRemovedAndAuthorizationIsNotObservation) {
  const TempDir directory("flow_isolated");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));
  ReachIsolationReady(driver);

  // At isolation_ready, observing a removal is not permitted at all: removal
  // must be authorised first.
  DF_CHECK_CODE(driver.ObserveRemoval(), df::ErrorCode::phase_does_not_permit);
  DF_CHECK(driver.Phase() == df::Phase::isolation_ready);

  DF_CHECK(driver.AuthorizeRemoval().ok());
  auto view = driver.Case();
  DF_CHECK(view.ok());
  DF_CHECK(view.value().record.removal_authorized);
  // Authorisation is a grant, not an observation.
  DF_CHECK(view.value().record.removal.observed == false);
  DF_CHECK(view.value().record.removal.evidence.is_unset());

  DF_CHECK_CODE(driver.Finalize(), df::ErrorCode::phase_does_not_permit);
  DF_CHECK(driver.ObserveRemoval().ok());
  view = driver.Case();
  DF_CHECK(view.ok());
  DF_CHECK(view.value().record.removal.observed);
  DF_CHECK(view.value().record.removal.canonical_deletion == false);
  DF_CHECK(view.value().record.phase == df::Phase::removed_observed);

  DF_CHECK(driver.Finalize().ok());
  view = driver.Case();
  DF_CHECK(view.ok());
  DF_CHECK(view.value().record.phase == df::Phase::decommissioned);
  // Removed observation is not canonical deletion, and the runtime says so in
  // the record rather than by omission.
  DF_CHECK(view.value().record.removal.canonical_deletion == false);
  const df::RecordedNote* note =
      view.value().record.find_note("canonical_deletion_not_owned");
  DF_CHECK(note != nullptr);
  DF_CHECK(note->text.empty() == false);
}

DF_TEST(Flow_ProtectedDependencyCanNeverBeWaived) {
  const TempDir directory("flow_protected");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));

  DF_CHECK(driver.Register().ok());
  DF_CHECK(driver.CreatePlan().ok());
  DF_CHECK(driver
               .Assess({Finding(df::DrainKind::protected_service,
                                df::ProtectedServiceClass::safety, true, true)})
               .ok());
  const std::vector<df::ObligationId> obligations = driver.Obligations();
  DF_CHECK(obligations.size() == 1U);

  df::WaiveDrainPayload waiver;
  waiver.obligation = obligations[0];
  waiver.authority = "operator";
  waiver.reference = "W-1";
  waiver.rationale = "we would rather not";
  const auto refused = driver.Submit(df::RequestKind::waive_drain, waiver);
  DF_CHECK_CODE(refused, df::ErrorCode::exception_not_permitted);

  auto view = driver.Case();
  DF_CHECK(view.ok());
  DF_CHECK(view.value().record.obligations[0].blocks_progress());
  DF_CHECK(view.value().record.obligations[0].state != df::ObligationState::waived);
}

DF_TEST(Flow_LateDiscoveredDependencyForcesThePlanBackToDraining) {
  const TempDir directory("flow_unmet");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));
  ReachIsolationReady(driver);

  // A newly discovered dependency sends the plan back to draining rather than
  // letting it close.
  df::SetDrainRequirementPayload requirement;
  requirement.kind = df::DrainKind::power_dependency;
  requirement.issued_to = "power";
  requirement.detail = "discovered late";
  DF_CHECK(driver.Submit(df::RequestKind::set_drain_requirement, requirement).ok());
  DF_CHECK(driver.Phase() == df::Phase::drain_required);

  DF_CHECK(driver.Drains().ok());
  const std::vector<df::ObligationId> all = driver.Obligations();
  DF_CHECK(all.size() == 3U);

  // The newly discovered dependency is outstanding, so the plan cannot leave
  // draining: a late dependency is a real blocker, not an annotation.
  DF_CHECK_CODE(driver.ConcludeDraining(), df::ErrorCode::unmet_obligation);
  auto blockers = engine.value().ExplainBlockers(driver.Case().value().record.key);
  DF_CHECK(blockers.ok());
  DF_CHECK(blockers.value().blockers.empty() == false);
  DF_CHECK(blockers.value().blockers.front().reason == df::BlockerReason::drain_outstanding);
  DF_CHECK(blockers.value().blockers.front().observed.front().key == "obligation");
  DF_CHECK(blockers.value().blockers.front().observed.front().value == all.back().to_hex());
  DF_CHECK(blockers.value().blockers.front().required_action.empty() == false);
  DF_CHECK(blockers.value().ready_to_advance == false);

  // Discharging it lets the plan continue from where it was.
  DF_CHECK(driver.Satisfy(all.back(), df::DrainKind::power_dependency).ok());
  DF_CHECK(driver.ConcludeDraining().ok());
  DF_CHECK(driver.ConcludeAuthority().ok());
  DF_CHECK(driver.Isolation().ok());
  DF_CHECK(driver.AuthorizeRemoval().ok());
  DF_CHECK(driver.ObserveRemoval().ok());
  DF_CHECK(driver.Phase() == df::Phase::removed_observed);
  DF_CHECK(driver.Finalize().ok());
  DF_CHECK(driver.Phase() == df::Phase::decommissioned);
}

DF_TEST(Flow_UnevaluatedDependencyIsNotAnAbsentOne) {
  const TempDir directory("flow_unknown_dep");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));

  DF_CHECK(driver.Register().ok());
  DF_CHECK(driver.CreatePlan().ok());
  // evaluated == false means the facility authority could not decide. That is
  // recorded as unknown, and an unknown dependency blocks exactly like an
  // outstanding one instead of being treated as "nothing to drain".
  DF_CHECK(driver.Assess({Finding(df::DrainKind::cooling_dependency,
                                  df::ProtectedServiceClass::none, true, false)})
               .ok());
  auto view = driver.Case();
  DF_CHECK(view.ok());
  DF_CHECK(view.value().record.obligations.size() == 1U);
  DF_CHECK(view.value().record.obligations[0].state == df::ObligationState::unknown);
  DF_CHECK(view.value().record.obligations[0].blocks_progress());

  DF_CHECK(driver.Drains().ok());
  auto blockers = engine.value().ExplainBlockers(view.value().record.key);
  DF_CHECK(blockers.ok());
  DF_CHECK(blockers.value().blockers.empty() == false);
  DF_CHECK(blockers.value().blockers.front().reason == df::BlockerReason::dependencies_unresolved);
  DF_CHECK(blockers.value().blockers.front().required_action.empty() == false);
  DF_CHECK_CODE(driver.ConcludeDraining(), df::ErrorCode::unmet_obligation);
}

DF_TEST(Flow_UnknownAuthorityBlocksClosureAndIsNotSilentlyRevoked) {
  const TempDir directory("flow_authority_unknown");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));

  DF_CHECK(driver.Register().ok());
  DF_CHECK(driver.CreatePlan().ok());
  DF_CHECK(driver.Assess({Finding(df::DrainKind::asi_workload)}).ok());
  const std::vector<df::ObligationId> obligations = driver.Obligations();
  DF_CHECK(driver.Satisfy(obligations[0], df::DrainKind::asi_workload).ok());
  DF_CHECK(driver.Drains().ok());
  // Revoke half the domains under the FIRST lifecycle generation.
  std::vector<df::AuthorityDomain> subset;
  for (std::size_t index = 0; index < df::kAuthorityDomainCount / 2U; ++index) {
    subset.push_back(df::kAuthorityDomains[index]);
  }
  DF_CHECK(driver.RevokeDomains(subset).ok());
  DF_CHECK(driver.ConcludeDraining().ok());
  DF_CHECK(driver.Phase() == df::Phase::authority_revocation);
  auto view = driver.Case();
  DF_CHECK(view.ok());
  DF_CHECK(view.value().authority.revoked_count == subset.size());

  // Cancel and re-plan. The revoked bits carry over as facility belief, but the
  // receipts were recorded under the previous lifecycle generation and therefore
  // do NOT cover the new binding. The domains are UNKNOWN, not revoked.
  df::CancelPlanPayload cancel;
  cancel.reason = "re-plan under the current facility shape";
  DF_CHECK(driver.Submit(df::RequestKind::cancel_plan, cancel).ok());
  DF_CHECK(driver.CreatePlan("second attempt").ok());
  DF_CHECK(driver.Assess({Finding(df::DrainKind::asi_workload)}).ok());
  const std::vector<df::ObligationId> replan_obligations = driver.Obligations();
  DF_CHECK(replan_obligations.size() == 1U);
  DF_CHECK(driver.Satisfy(replan_obligations[0], df::DrainKind::asi_workload).ok());
  DF_CHECK(driver.Drains().ok());
  DF_CHECK(driver.ConcludeDraining().ok());
  DF_CHECK(driver.Phase() == df::Phase::authority_revocation);

  view = driver.Case();
  DF_CHECK(view.ok());
  DF_CHECK(view.value().authority.unknown_count == subset.size());
  DF_CHECK(view.value().authority.revoked_count == 0U);
  DF_CHECK(view.value().authority.blocks_closure());

  auto blockers = engine.value().ExplainBlockers(view.value().record.key);
  DF_CHECK(blockers.ok());
  DF_CHECK(blockers.value().blockers.empty() == false);
  DF_CHECK(blockers.value().blockers.front().reason == df::BlockerReason::authority_unknown);
  DF_CHECK(blockers.value().blockers.front().required_action.empty() == false);

  DF_CHECK_CODE(driver.ConcludeAuthority(), df::ErrorCode::authority_unknown);
}

DF_TEST(Flow_FenceChangeInvalidatesTheOldBinding) {
  const TempDir directory("flow_fence_change");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));

  DF_CHECK(driver.Register().ok());
  DF_CHECK(driver.CreatePlan().ok());
  auto view = driver.Case();
  DF_CHECK(view.ok());
  const df::PlanFence captured = view.value().record.fence;

  df::GenerationAdvanceRequest advance;
  advance.kind = df::GenerationKind::dependency;
  advance.expected_current = engine.value().generations().dependency_generation.value();
  advance.incarnation = df::CurrentIncarnation();
  advance.at = df::Timestamp{df::ManualClock::kDefaultStartNanos + 5};
  advance.reason = "dependency graph changed";
  DF_CHECK(engine.value().AdvanceGeneration(advance).ok());

  df::AssessDependenciesPayload assessment;
  assessment.authority = "dep-authority";
  assessment.reference = "DEP-1";
  const auto refused =
      driver.SubmitAgainst(df::RequestKind::assess_dependencies, assessment, captured);
  DF_CHECK_CODE(refused, df::ErrorCode::fence_stale);
  DF_CHECK(refused.error().find("field") != nullptr);
  DF_CHECK(*refused.error().find("field") == "dependency_generation");

  // And the plan's own binding is now behind the facility's, so even a fence the
  // engine itself would produce is refused: the plan is fenced, not merely
  // mis-addressed.
  DF_CHECK_CODE(driver.Assess({Finding(df::DrainKind::asi_workload)}),
                df::ErrorCode::fence_stale);

  // The plan did not move, and its recorded binding is deliberately still the
  // OLD one: a case does not silently adopt a facility generation it was never
  // planned against. It is now behind the facility, which is exactly why every
  // request against it is refused.
  view = driver.Case();
  DF_CHECK(view.ok());
  DF_CHECK(view.value().record.phase == df::Phase::requested);
  DF_CHECK(view.value().record.fence.dependency_generation == captured.dependency_generation);
  DF_CHECK(engine.value().generations().dependency_generation !=
           captured.dependency_generation);

  // Advancing a fenced plan is forbidden for every request kind...
  DF_CHECK_CODE(driver.AuthorizeRemoval(), df::ErrorCode::fence_stale);

  // ...but closing it is not a facility mutation, and refusing that would strand
  // the asset forever, because a behind plan can neither advance nor be replaced
  // while it is open. The closure records that it happened while fenced.
  df::CancelPlanPayload cancel;
  cancel.reason = "facility changed under the plan";
  const auto closed = driver.Submit(df::RequestKind::cancel_plan, cancel);
  DF_CHECK(closed.ok());
  DF_CHECK(driver.Phase() == df::Phase::cancelled);
  bool explained = false;
  for (const df::RecordedNote& note : closed.value().notes) {
    if (note.code == "closed_while_fenced") {
      explained = true;
    }
  }
  DF_CHECK(explained);

  // With the old generation closed, the asset can be planned again.
  DF_CHECK(driver.CreatePlan("third attempt").ok());
  DF_CHECK(driver.Phase() == df::Phase::requested);
  DF_CHECK(engine.value()
               .GetCase(df::CaseKey{df::AssetId::FromValue(kAsset),
                                    df::LifecycleGeneration::First()})
               .ok());
}

DF_TEST(Flow_AssetGenerationChangeInvalidatesTheOldBinding) {
  const TempDir directory("flow_asset_gen");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));

  DF_CHECK(driver.Register(3U, 7U).ok());
  DF_CHECK(driver.CreatePlan().ok());
  auto view = driver.Case();
  DF_CHECK(view.ok());
  const df::PlanFence captured = view.value().record.fence;

  // Replacing the firmware is a physical change to the asset, so the plan that
  // was bound to the previous firmware generation is fenced.
  DF_CHECK(driver.Register(3U, 8U).ok());
  df::AssessDependenciesPayload assessment;
  assessment.authority = "dep-authority";
  assessment.reference = "DEP-1";
  const auto refused =
      driver.SubmitAgainst(df::RequestKind::assess_dependencies, assessment, captured);
  DF_CHECK_CODE(refused, df::ErrorCode::fence_stale);
  DF_CHECK(*refused.error().find("field") == "firmware_generation");
}

DF_TEST(Flow_IdempotentReplayIsNotASecondMutation) {
  const TempDir directory("flow_replay");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));
  DF_CHECK(driver.Register().ok());

  df::CreatePlanPayload payload;
  payload.asset = df::AssetId::FromValue(kAsset);
  payload.rationale = "retire";

  const auto first = driver.SubmitWithAttempt(df::RequestKind::create_plan, payload, 4242U);
  DF_CHECK(first.ok());
  DF_CHECK(first.value().applied);
  DF_CHECK(first.value().replayed == false);
  const df::CommitSequence after_first = engine.value().commit_sequence();
  const df::PlanFence fence_after_first = driver.Case().value().record.fence;

  // A lost response replayed with the identical attempt identity and identical
  // content must be recognised as a replay, not applied again, and must report
  // the ORIGINAL commit sequence.
  const auto second = driver.SubmitWithAttempt(df::RequestKind::create_plan, payload, 4242U);
  DF_CHECK(second.ok());
  DF_CHECK(second.value().applied == false);
  DF_CHECK(second.value().replayed);
  DF_CHECK(second.value().committed_sequence == first.value().committed_sequence);
  DF_CHECK(engine.value().commit_sequence() == after_first);
  DF_CHECK(driver.Case().value().record.fence == fence_after_first);

  // The same attempt identity used for DIFFERENT content is a conflict, not a
  // replay: honouring it would apply a second, different mutation under an
  // identity the caller already spent.
  auto assessment = df::AssessDependenciesPayload{};
  assessment.authority = "dep-authority";
  assessment.reference = "DEP-1";
  DF_CHECK_CODE(driver.SubmitWithAttempt(df::RequestKind::assess_dependencies, assessment, 4242U),
                df::ErrorCode::already_issued);

  // And the same attempt identity for the same kind but different content.
  df::CreatePlanPayload different;
  different.asset = df::AssetId::FromValue(kAsset);
  different.rationale = "something else entirely";
  DF_CHECK_CODE(driver.SubmitWithAttempt(df::RequestKind::create_plan, different, 4242U),
                df::ErrorCode::already_issued);
}

DF_TEST(Flow_ReopenedStoreDoesNotReDispatchDestructiveRequests) {
  const TempDir directory("flow_restart");
  df::CommitSequence sequence_before;

  {
    auto engine = OpenEngine(directory);
    DF_CHECK(engine.ok());
    Driver driver(engine.value(), df::AssetId::FromValue(kAsset));
    DF_CHECK(driver.Register().ok());
    DF_CHECK(driver.CreatePlan().ok());
    DF_CHECK(driver.Assess({Finding(df::DrainKind::asi_workload)}).ok());
    sequence_before = engine.value().commit_sequence();
  }

  // A second process (here, a second engine handle) recovers the generation and
  // replays the identical request. It must not re-issue anything.
  {
    auto engine = OpenEngine(directory);
    DF_CHECK(engine.ok());
    DF_CHECK(engine.value().commit_sequence() == sequence_before);
    Driver driver(engine.value(), df::AssetId::FromValue(kAsset));
    DF_CHECK(driver.Phase() == df::Phase::dependency_assessment);

    auto view = driver.Case();
    DF_CHECK(view.ok());
    // Recovered evidence is not fresh live evidence.
    for (const df::EvidenceRef& evidence : view.value().record.evidence) {
      DF_CHECK(evidence.freshness == df::EvidenceFreshness::recovered);
    }

    df::CreatePlanPayload payload;
    payload.asset = df::AssetId::FromValue(kAsset);
    payload.rationale = "retire";
    const auto replayed = driver.SubmitWithAttempt(df::RequestKind::create_plan, payload, 1U);
    DF_CHECK(replayed.ok());
    DF_CHECK(replayed.value().replayed);
    DF_CHECK(replayed.value().applied == false);
    DF_CHECK(engine.value().commit_sequence() == sequence_before);
  }
}

DF_TEST(Flow_ReplanningFencesThePreviousLifecycleGeneration) {
  const TempDir directory("flow_replan");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));

  DF_CHECK(driver.Register().ok());
  DF_CHECK(driver.CreatePlan().ok());
  auto view = driver.Case();
  DF_CHECK(view.ok());
  const df::PlanFence first_fence = view.value().record.fence;
  const df::CaseKey first_key = view.value().record.key;

  df::CancelPlanPayload cancel;
  cancel.reason = "changed our mind";
  DF_CHECK(driver.Submit(df::RequestKind::cancel_plan, cancel).ok());
  DF_CHECK(driver.Phase() == df::Phase::cancelled);

  // Re-planning creates a NEW case at the next lifecycle generation.
  DF_CHECK(driver.CreatePlan("second attempt").ok());
  view = driver.Case();
  DF_CHECK(view.ok());
  DF_CHECK(view.value().record.phase == df::Phase::requested);
  DF_CHECK(view.value().record.key.generation.value() == first_key.generation.value() + 1U);
  DF_CHECK(view.value().record.plan != first_fence.plan);

  // The old generation's evidence is preserved for audit, and its fence is
  // superseded rather than inherited.
  const auto old_case = engine.value().GetCase(first_key);
  DF_CHECK(old_case.ok());
  DF_CHECK(old_case.value().record.phase == df::Phase::cancelled);

  // The previous generation is closed and keeps its own evidence; it accepts no
  // further mutation, and the new plan is bound to a different plan identity.
  df::AssessDependenciesPayload assessment;
  assessment.authority = "dep-authority";
  assessment.reference = "DEP-1";
  const auto refused =
      driver.SubmitAgainst(df::RequestKind::assess_dependencies, assessment, first_fence);
  DF_CHECK(refused.ok() == false);
  DF_CHECK(refused.error().stage == df::ValidationStage::fence ||
           refused.error().stage == df::ValidationStage::phase_predicate);
  DF_CHECK(old_case.value().record.phase == df::Phase::cancelled);

  // A live plan cannot be silently replaced.
  const auto second = driver.CreatePlan("third attempt");
  DF_CHECK_CODE(second, df::ErrorCode::case_already_open);
}

DF_TEST(Flow_BlockedIsAFirstClassPhaseNotALoss) {
  const TempDir directory("flow_blocked");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));

  DF_CHECK(driver.Register().ok());
  DF_CHECK(driver.CreatePlan().ok());
  DF_CHECK(driver.Assess({Finding(df::DrainKind::asi_workload)}).ok());
  const std::vector<df::ObligationId> obligations = driver.Obligations();
  DF_CHECK(driver.Satisfy(obligations[0], df::DrainKind::asi_workload).ok());
  DF_CHECK(driver.Drains().ok());
  DF_CHECK(driver.Phase() == df::Phase::draining);

  df::BlockPlanPayload block;
  block.reason = df::BlockerReason::policy_violation;
  block.detail = "change freeze";
  block.required_action = "wait for the freeze window to close";
  DF_CHECK(driver.Submit(df::RequestKind::block_plan, block).ok());
  auto view = driver.Case();
  DF_CHECK(view.ok());
  DF_CHECK(view.value().record.phase == df::Phase::blocked);
  DF_CHECK(view.value().record.resume_phase == df::Phase::draining);
  DF_CHECK(view.value().record.blocker.reason == df::BlockerReason::policy_violation);

  auto blockers = engine.value().ExplainBlockers(view.value().record.key);
  DF_CHECK(blockers.ok());
  DF_CHECK(blockers.value().blockers.empty() == false);
  DF_CHECK(blockers.value().blockers.front().reason == df::BlockerReason::policy_violation);
  DF_CHECK(blockers.value().blockers.front().required_action.empty() == false);
  DF_CHECK(blockers.value().ready_to_advance == false);

  // A blocked plan refuses ordinary progress but accepts an unblock.
  DF_CHECK_CODE(driver.ConcludeDraining(), df::ErrorCode::phase_does_not_permit);
  df::ResumePlanPayload resume;
  resume.detail = "freeze lifted";
  DF_CHECK(driver.Submit(df::RequestKind::resume_plan, resume).ok());
  view = driver.Case();
  DF_CHECK(view.ok());
  DF_CHECK(view.value().record.phase == df::Phase::draining);
  DF_CHECK(view.value().record.resume_phase == df::Phase::unknown);
  DF_CHECK(view.value().record.blocker.is_set() == false);
}

DF_TEST(Flow_CancellationIsImpossibleAfterRemovalIsAuthorized) {
  const TempDir directory("flow_cancel_boundary");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));
  ReachIsolationReady(driver);
  DF_CHECK(driver.AuthorizeRemoval().ok());

  df::CancelPlanPayload cancel;
  cancel.reason = "too late";
  const auto refused = driver.Submit(df::RequestKind::cancel_plan, cancel);
  DF_CHECK_CODE(refused, df::ErrorCode::phase_does_not_permit);
  DF_CHECK(driver.Phase() == df::Phase::removal_authorized);
}

DF_TEST(Flow_ExplainBlockersAgreesWithTheRefusalExactly) {
  const TempDir directory("flow_explain");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));

  DF_CHECK(driver.Register().ok());
  DF_CHECK(driver.CreatePlan().ok());
  DF_CHECK(driver.Assess({Finding(df::DrainKind::asi_workload),
                          Finding(df::DrainKind::dfi_route),
                          Finding(df::DrainKind::power_dependency)})
               .ok());
  const std::vector<df::ObligationId> obligations = driver.Obligations();
  DF_CHECK(obligations.size() == 3U);
  DF_CHECK(driver.Satisfy(obligations[2], df::DrainKind::power_dependency).ok());
  DF_CHECK(driver.Drains().ok());

  auto view = driver.Case();
  DF_CHECK(view.ok());
  auto blockers = engine.value().ExplainBlockers(view.value().record.key);
  DF_CHECK(blockers.ok());
  DF_CHECK(blockers.value().blockers.size() == 2U);
  DF_CHECK(blockers.value().ready_to_advance == false);

  const auto refused = driver.ConcludeDraining();
  DF_CHECK(refused.ok() == false);
  // The explanation and the refusal come from the same predicate, so the
  // explanation's leading blocker must be exactly the refusal's reason.
  DF_CHECK(refused.error().code == blockers.value().blockers.front().code);
  DF_CHECK(*refused.error().find("reason") ==
           std::string(df::ToString(blockers.value().blockers.front().reason)));

  // The primary blocker is always the LOWEST blocking obligation identity, no
  // matter what order the obligations were created in.
  DF_CHECK(blockers.value().blockers.front().observed.front().key == "obligation");
  DF_CHECK(blockers.value().blockers.front().observed.front().value == obligations[0].to_hex());

  // Once the outstanding drains are satisfied, the explanation agrees again.
  DF_CHECK(driver.Satisfy(obligations[0], df::DrainKind::asi_workload).ok());
  DF_CHECK(driver.Satisfy(obligations[1], df::DrainKind::dfi_route).ok());
  blockers = engine.value().ExplainBlockers(driver.Case().value().record.key);
  DF_CHECK(blockers.ok());
  DF_CHECK(blockers.value().blockers.empty());
  DF_CHECK(blockers.value().ready_to_advance);
  DF_CHECK(driver.ConcludeDraining().ok());
}

DF_TEST(Flow_UnknownResidualOnlyClosesThroughAnAttributedException) {
  const TempDir directory("flow_residual_exception");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));

  DF_CHECK(driver.Register().ok());
  DF_CHECK(driver.CreatePlan().ok());
  DF_CHECK(driver.Assess({Finding(df::DrainKind::asi_workload)}).ok());
  const std::vector<df::ObligationId> obligations = driver.Obligations();
  DF_CHECK(driver.Satisfy(obligations[0], df::DrainKind::asi_workload).ok());
  DF_CHECK(driver.Drains().ok());
  DF_CHECK(driver.RevokeAll().ok());
  DF_CHECK(driver.ConcludeDraining().ok());
  DF_CHECK(driver.ConcludeAuthority().ok());

  // A residual item whose disposition nobody could establish blocks closure
  // outright; a waived disposition may not be reached by a bare disposition set.
  DF_CHECK_CODE(driver.Residual(df::ResidualCategory::persistent_media,
                                df::ResidualDisposition::unknown),
                df::ErrorCode::malformed_request);
  DF_CHECK_CODE(driver.Residual(df::ResidualCategory::persistent_media,
                                df::ResidualDisposition::waived),
                df::ErrorCode::exception_required);

  DF_CHECK(driver.Residual(df::ResidualCategory::persistent_media,
                           df::ResidualDisposition::pending)
               .ok());

  // A category nobody has spoken about is a DIFFERENT blocker from a category
  // that was spoken about and left pending. Both block, and they are reported
  // distinctly so an operator knows which one to act on.
  DF_CHECK_CODE(driver.Isolation(), df::ErrorCode::residual_checklist_incomplete);
  DF_CHECK(driver.FillResidual().ok());
  DF_CHECK_CODE(driver.Isolation(), df::ErrorCode::unresolved_residual);

  auto view = driver.Case();
  DF_CHECK(view.ok());
  DF_CHECK(view.value().record.residual.size() == df::kResidualCategoryCount - 1U);

  // An exception must be attributable: empty authority, reference or rationale
  // is refused rather than recorded.
  df::RecordPolicyExceptionPayload blank;
  blank.item = view.value().record.residual[0].id;
  blank.authority = "facility-policy-board";
  blank.reference = "EXC-1";
  blank.rationale = "";
  DF_CHECK_CODE(driver.Submit(df::RequestKind::record_policy_exception, blank),
                df::ErrorCode::missing_field);

  df::RecordPolicyExceptionPayload exception;
  exception.item = view.value().record.residual[0].id;
  exception.authority = "facility-policy-board";
  exception.reference = "EXC-1";
  exception.rationale = "media is retained under a separate legal hold owned by another system";
  DF_CHECK(driver.Submit(df::RequestKind::record_policy_exception, exception).ok());

  view = driver.Case();
  DF_CHECK(view.ok());
  DF_CHECK(view.value().record.residual[0].disposition == df::ResidualDisposition::waived);
  DF_CHECK(view.value().record.residual[0].waiver.is_set());
  const df::PolicyException* recorded =
      df::FindException(view.value().record, view.value().record.residual[0].waiver);
  DF_CHECK(recorded != nullptr);
  DF_CHECK(recorded->authority == "facility-policy-board");
  DF_CHECK(recorded->rationale.empty() == false);

  // With every other category decided and this one waived by an attributed
  // exception, closure is permitted and the exception is what carried it.
  DF_CHECK(driver.Isolation().ok());
  DF_CHECK(driver.Phase() == df::Phase::isolation_ready);
}

DF_TEST(Flow_RegistrationIsIdempotentAndGenerationChangeIsAnnounced) {
  const TempDir directory("flow_register");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));

  const auto first = driver.Register(3U, 7U);
  DF_CHECK(first.ok());
  DF_CHECK(first.value().applied);
  DF_CHECK(first.value().replayed == false);
  const df::CommitSequence after_first = engine.value().commit_sequence();

  // Registering exactly the same asset again is a no-op, not a new generation.
  const auto again = driver.Register(3U, 7U);
  DF_CHECK(again.ok());
  DF_CHECK(again.value().applied == false);
  DF_CHECK(again.value().replayed);
  DF_CHECK(engine.value().commit_sequence() == after_first);

  // A generation change is a real mutation and says so.
  const auto changed = driver.Register(3U, 8U);
  DF_CHECK(changed.ok());
  DF_CHECK(changed.value().applied);
  DF_CHECK(engine.value().commit_sequence() != after_first);
  bool announced = false;
  for (const df::RecordedNote& note : changed.value().notes) {
    if (note.code == "generation_advanced") {
      announced = true;
    }
  }
  DF_CHECK(announced);
}

DF_TEST(Flow_UnknownAssetAndUnknownCaseAreDistinctRefusals) {
  const TempDir directory("flow_unknown");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());

  df::RegisterAssetRequest registration;
  registration.id = df::AssetId::FromValue(kAsset);
  registration.site = df::SiteId::FromValue(0x2001U);
  registration.rack = df::RackId::FromValue(0x3001U);
  registration.hardware_generation = df::HardwareGeneration::FromValue(1);
  registration.firmware_generation = df::FirmwareGeneration::FromValue(1);
  registration.active_authority = df::AuthorityMask{df::kAllAuthorityBits};
  registration.incarnation = df::CurrentIncarnation();
  registration.at = df::Timestamp{df::ManualClock::kDefaultStartNanos};
  DF_CHECK(engine.value().RegisterAsset(registration).ok());

  // An asset with no plan is not an asset that failed.
  DF_CHECK_CODE(engine.value().GetLatestCase(df::AssetId::FromValue(kAsset)),
                df::ErrorCode::unknown_case);
  DF_CHECK_CODE(engine.value().GetAsset(df::AssetId::FromValue(0xBEEFU)),
                df::ErrorCode::unknown_asset);

  // An unset generation in a registration is refused, not defaulted.
  df::RegisterAssetRequest blank = registration;
  blank.id = df::AssetId::FromValue(0x2002U);
  blank.hardware_generation = df::HardwareGeneration{};
  DF_CHECK_CODE(engine.value().RegisterAsset(blank), df::ErrorCode::unset_generation);
}

DF_TEST(Flow_AuthorityMaskCountsAndOnlyKnownDomainsAreAccepted) {
  const TempDir directory("flow_mask");
  auto engine = OpenEngine(directory);
  DF_CHECK(engine.ok());

  df::RegisterAssetRequest registration;
  registration.id = df::AssetId::FromValue(kAsset);
  registration.site = df::SiteId::FromValue(0x2001U);
  registration.rack = df::RackId::FromValue(0x3001U);
  registration.hardware_generation = df::HardwareGeneration::FromValue(1);
  registration.firmware_generation = df::FirmwareGeneration::FromValue(1);
  registration.active_authority = df::AuthorityMask{0xFFFFFFFFU};
  registration.incarnation = df::CurrentIncarnation();
  registration.at = df::Timestamp{df::ManualClock::kDefaultStartNanos};
  DF_CHECK_CODE(engine.value().RegisterAsset(registration), df::ErrorCode::out_of_range);

  df::AuthorityMask mask{df::kAllAuthorityBits};
  DF_CHECK(mask.count() == df::kAuthorityDomainCount);
  DF_CHECK(mask.only_known_domains());
  DF_CHECK(mask.without(df::AuthorityDomain::power_control).count() ==
           df::kAuthorityDomainCount - 1U);
}

DF_TEST_MAIN()

// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Engine queries, shared predicates, and lock-order enforcement.
//
// Every predicate in this file is used by BOTH the validator in engine.cpp and
// the blocker explanation below. That is deliberate: a blocking explanation that
// could disagree with a refusal would make the refusal unauditable.

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

#include "decommissioning_fabric/engine.hpp"
#include "engine_impl.hpp"

namespace decommissioning_fabric {

// ---------------------------------------------------------------------------
// Lock order
// ---------------------------------------------------------------------------

bool LockOrderValidator::would_invert(int level) const noexcept {
  const ThreadState& state = State();
  return state.depth != 0U && level >= state.stack[state.depth - 1U];
}

void LockOrderValidator::Acquire(int level) {
  ThreadState& state = State();
  if (state.depth != 0U && level >= state.stack[state.depth - 1U]) {
    ++state.inversions;
#if !defined(NDEBUG)
    std::fprintf(stderr,
                 "decommissioning_fabric: lock-order inversion - acquiring level %d while "
                 "holding level %d\n",
                 level, state.stack[state.depth - 1U]);
    std::fflush(stderr);
    std::abort();
#endif
  }
  if (state.depth < kMaxDepth) {
    state.stack[state.depth] = level;
    ++state.depth;
  }
}

void LockOrderValidator::Release(int level) {
  ThreadState& state = State();
  if (state.depth == 0U) {
    return;
  }
  if (state.stack[state.depth - 1U] == level) {
    --state.depth;
    return;
  }
  // Out-of-order release: unwind to the matching entry rather than leaving a
  // stale frame that would misreport every later acquisition.
  for (std::size_t i = state.depth; i > 0U; --i) {
    if (state.stack[i - 1U] == level) {
      state.depth = i - 1U;
      return;
    }
  }
}

int LockOrderValidator::depth() const noexcept {
  return static_cast<int>(State().depth);
}

int LockOrderValidator::top() const noexcept {
  const ThreadState& state = State();
  return state.depth == 0U ? 0 : state.stack[state.depth - 1U];
}

std::size_t LockOrderValidator::recorded_inversions() const noexcept {
  return State().inversions;
}

// ---------------------------------------------------------------------------
// Shared predicates
// ---------------------------------------------------------------------------

Timestamp NowOf(const EngineImpl& impl) {
  if (impl.clock != nullptr) {
    return impl.clock->Now();
  }
  return impl.fallback_clock.Now();
}

AuthorityReport AuthorityOf(const RetirementCase& record) {
  return ComputeAuthorityReport(record.active_authority,
                                BindingDigest(record.fence.binding()),
                                record.receipts.data(), record.receipts.size());
}

bool AllRequiredObligationsResolved(const RetirementCase& record) {
  for (const DrainObligation& obligation : record.obligations) {
    if (obligation.blocks_progress()) {
      return false;
    }
  }
  return true;
}

const PolicyException* ResidualWaiver(const RetirementCase& record,
                                      const ResidualItem& item) {
  if (item.disposition != ResidualDisposition::waived) {
    return nullptr;
  }
  const PolicyException* exception = FindException(record, item.waiver);
  if (exception == nullptr) {
    return nullptr;
  }
  return exception;
}

bool ExceptionStillBinds(const RetirementCase& record, const PolicyException& exception) {
  return exception.binding_digest == BindingDigest(record.fence.binding()) &&
         exception.policy_generation == record.fence.policy_generation &&
         exception.plan == record.plan;
}

bool ResidualChecklistComplete(const RetirementCase& record) {
  // Every category this runtime knows about must carry a recorded decision. An
  // empty or partial checklist is NOT evidence that nothing remains: it is
  // absence of evidence, and absence is never converted into "nothing to
  // handle". A category nobody has spoken about is unknown, and unknown residual
  // state blocks final closure.
  for (const ResidualCategory category : kResidualCategoryOrder) {
    if (category == ResidualCategory::unknown) {
      continue;
    }
    bool recorded = false;
    for (const ResidualItem& item : record.residual) {
      if (item.category == category) {
        recorded = true;
        break;
      }
    }
    if (!recorded) {
      return false;
    }
  }

  for (const ResidualItem& item : record.residual) {
    if (IsUnresolvedResidual(item.disposition)) {
      return false;
    }
    if (item.disposition == ResidualDisposition::waived && ResidualWaiver(record, item) == nullptr) {
      return false;
    }
  }
  return true;
}

EvidenceKind RequiredEvidenceKind(const DrainObligation& obligation) {
  (void)obligation;
  // Every drain obligation is satisfied by drain satisfaction evidence whose
  // subject kind equals the obligation's kind. The kind check lives in the
  // subject_kind field, not in a per-kind enumerator, so a report about a
  // different drain can never satisfy this one.
  return EvidenceKind::drain_satisfaction;
}

PrerequisiteNeeds NeedsForPhaseClosure(Phase phase) {
  PrerequisiteNeeds needs;
  switch (phase) {
    case Phase::draining:
      needs.obligations = true;
      break;
    case Phase::authority_revocation:
      needs.authority = true;
      break;
    case Phase::residual_handling:
      needs.obligations = true;
      needs.residual = true;
      break;
    case Phase::isolation_ready:
      needs.obligations = true;
      needs.authority = true;
      needs.residual = true;
      break;
    case Phase::removed_observed:
      needs.obligations = true;
      needs.authority = true;
      needs.residual = true;
      break;
    default:
      break;
  }
  return needs;
}

PrerequisiteNeeds NeedsForRequest(RequestKind kind) {
  switch (kind) {
    case RequestKind::conclude_draining:
      return NeedsForPhaseClosure(Phase::draining);
    case RequestKind::conclude_authority_revocation:
      return NeedsForPhaseClosure(Phase::authority_revocation);
    case RequestKind::declare_isolation_ready:
      return NeedsForPhaseClosure(Phase::residual_handling);
    case RequestKind::authorize_removal:
      return NeedsForPhaseClosure(Phase::isolation_ready);
    case RequestKind::finalize_decommissioning:
      return NeedsForPhaseClosure(Phase::removed_observed);
    default:
      return PrerequisiteNeeds{};
  }
}

void CollectPrerequisiteBlockers(const RetirementCase& record,
                                 const AuthorityReport& authority,
                                 const PrerequisiteNeeds& needs,
                                 std::vector<Blocker>& out) {
  if (needs.obligations) {
    for (const DrainObligation& obligation : record.obligations) {
      if (!obligation.blocks_progress()) {
        continue;
      }
      Blocker blocker;
      blocker.code = obligation.state == ObligationState::unknown
                         ? ErrorCode::unmet_obligation
                         : ErrorCode::unmet_obligation;
      blocker.observed_phase = record.phase;
      blocker.blocked_at = record.phase;
      blocker.observed.push_back(
          ErrorDetail{"obligation", obligation.id.to_hex()});
      blocker.observed.push_back(
          ErrorDetail{"kind", std::string(ToString(obligation.kind))});
      blocker.observed.push_back(
          ErrorDetail{"state", std::string(ToString(obligation.state))});
      blocker.observed.push_back(
          ErrorDetail{"issued_sequence", std::to_string(obligation.issued_sequence.value())});
      if (!obligation.issued_to.empty()) {
        blocker.observed.push_back(ErrorDetail{"issued_to", obligation.issued_to});
      }
      if (obligation.state == ObligationState::acknowledged) {
        blocker.reason = BlockerReason::drain_acknowledged_not_satisfied;
        blocker.detail = "drain obligation '" + std::string(ToString(obligation.kind)) +
                         "' was acknowledged but no completion has been reported";
        blocker.required_action =
            "obtain attributable evidence from the drain authority with kind '" +
            std::string(ToString(obligation.kind)) + "' and record it";
      } else if (obligation.state == ObligationState::unknown) {
        blocker.reason = BlockerReason::dependencies_unresolved;
        blocker.detail = "dependency '" + std::string(ToString(obligation.kind)) +
                         "' could not be evaluated; an unevaluated dependency is not an absent one";
        blocker.required_action =
            "obtain a dependency assessment for '" + std::string(ToString(obligation.kind)) +
            "' or mark it not-required with an attributed exception";
      } else {
        blocker.reason = BlockerReason::drain_outstanding;
        blocker.detail = "drain obligation '" + std::string(ToString(obligation.kind)) +
                         "' is outstanding";
        blocker.required_action = "request the drain from the responsible authority and record "
                                  "its completion evidence";
      }
      out.push_back(std::move(blocker));
    }
  }

  if (needs.authority) {
    for (std::size_t index = 0; index < kAuthorityDomainCount; ++index) {
      const DomainAssessment& assessment = authority.domains[index];
      if (assessment.status == DomainStatus::revoked) {
        continue;
      }
      Blocker blocker;
      blocker.code = assessment.status == DomainStatus::active ? ErrorCode::authority_active
                                                               : ErrorCode::authority_unknown;
      blocker.reason = assessment.status == DomainStatus::active ? BlockerReason::authority_active
                                                                 : BlockerReason::authority_unknown;
      blocker.observed_phase = record.phase;
      blocker.blocked_at = record.phase;
      blocker.observed.push_back(
          ErrorDetail{"domain", std::string(ToString(assessment.domain))});
      blocker.observed.push_back(
          ErrorDetail{"status", std::string(ToString(assessment.status))});
      blocker.observed.push_back(
          ErrorDetail{"authority_bit_present", assessment.status == DomainStatus::active ? "true"
                                                                                         : "false"});
      if (assessment.stale_receipt_present) {
        blocker.observed.push_back(ErrorDetail{"stale_receipt_present", "true"});
      }
      if (assessment.status == DomainStatus::active) {
        blocker.detail = "authority domain '" + std::string(ToString(assessment.domain)) +
                         "' is still held by the asset";
        blocker.required_action = "obtain a revocation receipt for '" +
                                  std::string(ToString(assessment.domain)) +
                                  "' from the authority that owns it";
      } else {
        blocker.detail = "authority domain '" + std::string(ToString(assessment.domain)) +
                         "' has no revocation receipt bound to the current generation binding";
        blocker.required_action =
            "record a revocation receipt for '" + std::string(ToString(assessment.domain)) +
            "' bound to the current facility epoch and policy generation";
      }
      out.push_back(std::move(blocker));
    }
  }

  if (needs.residual) {
    // Categories with no recorded decision at all come first: they are the most
    // fundamental form of unknown residual state.
    for (const ResidualCategory category : kResidualCategoryOrder) {
      if (category == ResidualCategory::unknown) {
        continue;
      }
      bool recorded = false;
      for (const ResidualItem& item : record.residual) {
        if (item.category == category) {
          recorded = true;
          break;
        }
      }
      if (recorded) {
        continue;
      }
      Blocker blocker;
      blocker.reason = BlockerReason::residual_unknown;
      blocker.code = ErrorCode::residual_checklist_incomplete;
      blocker.observed_phase = record.phase;
      blocker.blocked_at = record.phase;
      blocker.observed.push_back(
          ErrorDetail{"category", std::string(ToString(category))});
      blocker.observed.push_back(ErrorDetail{"disposition", "not_recorded"});
      blocker.detail = "no disposition has been recorded for residual category '" +
                       std::string(ToString(category)) +
                       "'; an unrecorded category is unknown, not absent";
      blocker.required_action =
          "record a disposition for '" + std::string(ToString(category)) +
          "', or an attributed policy exception if policy permits leaving it in place";
      out.push_back(std::move(blocker));
    }

    for (const ResidualItem& item : record.residual) {
      if (!IsUnresolvedResidual(item.disposition)) {
        continue;
      }
      Blocker blocker;
      blocker.code = ErrorCode::unresolved_residual;
      blocker.observed_phase = record.phase;
      blocker.blocked_at = record.phase;
      blocker.observed.push_back(ErrorDetail{"item", item.id.to_hex()});
      blocker.observed.push_back(
          ErrorDetail{"category", std::string(ToString(item.category))});
      blocker.observed.push_back(
          ErrorDetail{"disposition", std::string(ToString(item.disposition))});
      if (item.disposition == ResidualDisposition::unknown) {
        blocker.reason = BlockerReason::residual_unknown;
        blocker.detail = "residual item '" + std::string(ToString(item.category)) +
                         "' has an unknown disposition";
        blocker.required_action =
            "record a disposition for '" + std::string(ToString(item.category)) +
            "' with the authority that reported it, or record an attributed policy exception";
      } else {
        blocker.reason = BlockerReason::residual_pending;
        blocker.detail = "residual item '" + std::string(ToString(item.category)) +
                         "' is still pending";
        blocker.required_action = "complete the residual handling for '" +
                                  std::string(ToString(item.category)) +
                                  "' and record the completing authority";
      }
      out.push_back(std::move(blocker));
    }

    for (const ResidualItem& item : record.residual) {
      if (item.disposition != ResidualDisposition::waived) {
        continue;
      }
      const PolicyException* exception = ResidualWaiver(record, item);
      if (exception != nullptr && ExceptionStillBinds(record, *exception)) {
        continue;
      }
      Blocker blocker;
      blocker.reason = BlockerReason::exception_required;
      blocker.code = ErrorCode::unresolved_residual;
      blocker.observed_phase = record.phase;
      blocker.blocked_at = record.phase;
      blocker.observed.push_back(ErrorDetail{"item", item.id.to_hex()});
      blocker.observed.push_back(
          ErrorDetail{"category", std::string(ToString(item.category))});
      blocker.observed.push_back(ErrorDetail{"disposition", "waived"});
      blocker.observed.push_back(ErrorDetail{"exception", item.waiver.to_hex()});
      blocker.detail = exception == nullptr
                           ? "waived residual item has no recorded exception"
                           : "waived residual item's exception no longer binds the current "
                             "generation binding or policy generation";
      blocker.required_action =
          "record an attributed policy exception bound to the current generation binding";
      out.push_back(std::move(blocker));
    }
  }
}

void CollectPolicyBlockers(const RetirementCase& record, const AuthorityReport& authority,
                           RequestKind kind, std::vector<Blocker>& out) {
  (void)authority;
  switch (kind) {
    case RequestKind::authorize_removal:
    case RequestKind::finalize_decommissioning:
    case RequestKind::declare_isolation_ready:
      break;
    default:
      return;
  }

  for (const DrainObligation& obligation : record.obligations) {
    if (!obligation.required || !obligation.is_protected()) {
      continue;
    }
    if (obligation.state == ObligationState::waived) {
      Blocker blocker;
      blocker.reason = BlockerReason::protected_service_unresolved;
      blocker.code = ErrorCode::protected_service_unresolved;
      blocker.observed_phase = record.phase;
      blocker.blocked_at = record.phase;
      blocker.observed.push_back(ErrorDetail{"obligation", obligation.id.to_hex()});
      blocker.observed.push_back(
          ErrorDetail{"kind", std::string(ToString(obligation.kind))});
      blocker.observed.push_back(
          ErrorDetail{"protected_class", std::string(ToString(obligation.protected_class))});
      blocker.observed.push_back(ErrorDetail{"state", "waived"});
      blocker.detail = "protected obligation '" + std::string(ToString(obligation.kind)) +
                       "' was waived; facility policy does not permit waiving a protected service";
      blocker.required_action = "obtain completion evidence for '" +
                                std::string(ToString(obligation.kind)) +
                                "' from the authority that owns it";
      out.push_back(std::move(blocker));
    }
  }
}

Phase NextForwardPhase(const RetirementCase& record) {
  switch (record.phase) {
    case Phase::commissioned: return Phase::requested;
    case Phase::requested: return Phase::dependency_assessment;
    case Phase::dependency_assessment: return Phase::drain_required;
    case Phase::drain_required: return Phase::draining;
    case Phase::draining: return Phase::authority_revocation;
    case Phase::authority_revocation: return Phase::residual_handling;
    case Phase::residual_handling: return Phase::isolation_ready;
    case Phase::isolation_ready: return Phase::removal_authorized;
    case Phase::removal_authorized: return Phase::removed_observed;
    case Phase::removed_observed: return Phase::decommissioned;
    case Phase::blocked: return record.resume_phase;
    default: return Phase::unknown;
  }
}

std::string NextRequiredAction(const RetirementCase& record) {
  switch (record.phase) {
    case Phase::requested:
      return "assess dependencies: 'dfab dependencies assess'";
    case Phase::dependency_assessment:
      return "record the required drains: 'dfab drain require'";
    case Phase::drain_required:
      return "begin draining: 'dfab drain begin'";
    case Phase::draining:
      return "satisfy every required drain, then conclude draining";
    case Phase::authority_revocation:
      return "record a revocation receipt for every authority domain, then conclude";
    case Phase::residual_handling:
      return "record a disposition for every residual category, then declare isolation ready";
    case Phase::isolation_ready:
      return "authorize removal: 'dfab removal authorize'";
    case Phase::removal_authorized:
      return "observe the physical removal: 'dfab removal observe'";
    case Phase::removed_observed:
      return "finalize decommissioning: 'dfab plan finalize'";
    case Phase::blocked:
      return "clear the blocker, then resume the plan: 'dfab plan resume'";
    case Phase::decommissioned:
      return "nothing: the asset is decommissioned";
    case Phase::cancelled:
      return "nothing: the plan was cancelled; re-plan to start a new lifecycle generation";
    case Phase::failed:
      return "nothing: the plan failed; re-plan to start a new lifecycle generation";
    default:
      return "register the asset and create a plan";
  }
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

CommitSequence Engine::commit_sequence() const {
  if (impl_ == nullptr) {
    return CommitSequence{};
  }
  const std::shared_lock<std::shared_mutex> lock(impl_->index_mu);
  return impl_->state.sequence;
}

CommitStatistics Engine::last_commit() const {
  if (impl_ == nullptr) {
    return CommitStatistics{};
  }
  const std::shared_lock<std::shared_mutex> lock(impl_->index_mu);
  return impl_->last_commit;
}

const RecoveryReport& Engine::recovery() const {
  static const RecoveryReport kEmpty{};
  if (impl_ == nullptr) {
    return kEmpty;
  }
  return impl_->store.recovery();
}

FacilityGenerations Engine::generations() const {
  if (impl_ == nullptr) {
    return FacilityGenerations{};
  }
  const std::shared_lock<std::shared_mutex> lock(impl_->index_mu);
  return impl_->state.generations;
}

std::string Engine::store_directory() const {
  return impl_ == nullptr ? std::string() : impl_->store.directory();
}

std::vector<AssetView> Engine::ListAssets() const {
  std::vector<AssetView> out;
  if (impl_ == nullptr) {
    return out;
  }
  const std::shared_lock<std::shared_mutex> lock(impl_->index_mu);
  out.reserve(impl_->state.fleet.size());
  for (const auto& entry : impl_->state.fleet) {
    AssetView view;
    view.asset = entry.second;
    const RetirementCase* record = impl_->state.CurrentCase(entry.first);
    if (record != nullptr) {
      view.has_case = true;
      view.case_key = record->key;
      view.phase = record->phase;
    }
    out.push_back(std::move(view));
  }
  return out;
}

Result<AssetView> Engine::GetAsset(AssetId id) const {
  if (impl_ == nullptr) {
    return MakeError(ErrorCode::internal_error, "engine is not open");
  }
  const std::shared_lock<std::shared_mutex> lock(impl_->index_mu);
  const FleetAsset* asset = impl_->state.FindAsset(id);
  if (asset == nullptr) {
    return ErrorBuilder(ErrorCode::unknown_asset, "no such asset is registered")
        .With("asset", id.to_hex())
        .Build();
  }
  AssetView view;
  view.asset = *asset;
  const RetirementCase* record = impl_->state.CurrentCase(id);
  if (record != nullptr) {
    view.has_case = true;
    view.case_key = record->key;
    view.phase = record->phase;
  }
  return view;
}

std::vector<CaseKey> Engine::ListCases() const {
  std::vector<CaseKey> out;
  if (impl_ == nullptr) {
    return out;
  }
  const std::shared_lock<std::shared_mutex> lock(impl_->index_mu);
  out.reserve(impl_->state.cases.size());
  for (const auto& entry : impl_->state.cases) {
    out.push_back(entry.first);
  }
  return out;
}

Result<CaseView> Engine::GetCase(const CaseKey& key) const {
  if (impl_ == nullptr) {
    return MakeError(ErrorCode::internal_error, "engine is not open");
  }
  const std::shared_lock<std::shared_mutex> lock(impl_->index_mu);
  const RetirementCase* record = impl_->state.FindCase(key);
  if (record == nullptr) {
    return ErrorBuilder(ErrorCode::unknown_case, "no such retirement case exists")
        .With("asset", key.asset.to_hex())
        .With("generation", static_cast<std::uint64_t>(key.generation.value()))
        .Build();
  }
  CaseView view;
  view.record = *record;
  view.authority = AuthorityOf(*record);
  view.fence_token = EncodeFenceToken(record->fence);
  return view;
}

Result<CaseView> Engine::GetCurrentCase(AssetId id) const {
  if (impl_ == nullptr) {
    return MakeError(ErrorCode::internal_error, "engine is not open");
  }
  const std::shared_lock<std::shared_mutex> lock(impl_->index_mu);
  const RetirementCase* record = impl_->state.CurrentCase(id);
  if (record == nullptr) {
    return ErrorBuilder(ErrorCode::unknown_case, "asset has no open retirement case")
        .With("asset", id.to_hex())
        .Build();
  }
  CaseView view;
  view.record = *record;
  view.authority = AuthorityOf(*record);
  view.fence_token = EncodeFenceToken(record->fence);
  return view;
}

Result<CaseView> Engine::GetLatestCase(AssetId id) const {
  if (impl_ == nullptr) {
    return MakeError(ErrorCode::internal_error, "engine is not open");
  }
  const std::shared_lock<std::shared_mutex> lock(impl_->index_mu);
  const LifecycleGeneration latest = impl_->state.LatestGeneration(id);
  if (latest.is_unset()) {
    return ErrorBuilder(ErrorCode::unknown_case, "asset has no retirement case at all")
        .With("asset", id.to_hex())
        .Build();
  }
  const RetirementCase* record = impl_->state.FindCase(CaseKey{id, latest});
  if (record == nullptr) {
    return ErrorBuilder(ErrorCode::unknown_case, "asset has no retirement case at all")
        .With("asset", id.to_hex())
        .Build();
  }
  CaseView view;
  view.record = *record;
  view.authority = AuthorityOf(*record);
  view.fence_token = EncodeFenceToken(record->fence);
  return view;
}

Result<BlockerReport> Engine::ExplainBlockers(const CaseKey& key) const {
  if (impl_ == nullptr) {
    return MakeError(ErrorCode::internal_error, "engine is not open");
  }
  const std::shared_lock<std::shared_mutex> lock(impl_->index_mu);
  const RetirementCase* record = impl_->state.FindCase(key);
  if (record == nullptr) {
    return ErrorBuilder(ErrorCode::unknown_case, "no such retirement case exists")
        .With("asset", key.asset.to_hex())
        .With("generation", static_cast<std::uint64_t>(key.generation.value()))
        .Build();
  }

  BlockerReport report;
  report.key = record->key;
  report.plan = record->plan;
  report.phase = record->phase;
  report.resume_phase = record->resume_phase;
  report.authority = AuthorityOf(*record);
  report.next_phase = NextForwardPhase(*record);
  report.total_obligations = record->obligations.size();
  report.total_residual = record->residual.size();
  for (const DrainObligation& obligation : record->obligations) {
    if (obligation.is_open()) {
      ++report.open_obligations;
    }
  }
  for (const ResidualItem& item : record->residual) {
    if (IsUnresolvedResidual(item.disposition)) {
      ++report.unresolved_residual;
    }
    if (item.disposition == ResidualDisposition::unknown) {
      ++report.unknown_residual;
    }
  }

  CollectPrerequisiteBlockers(*record, report.authority, NeedsForPhaseClosure(record->phase),
                              report.blockers);
  CollectPolicyBlockers(*record, report.authority, RequestKind::finalize_decommissioning,
                        report.blockers);

  if (record->phase == Phase::blocked && record->blocker.is_set()) {
    Blocker explicit_blocker = record->blocker;
    explicit_blocker.observed.push_back(
        ErrorDetail{"recorded_resume_phase", std::string(ToString(record->resume_phase))});
    report.blockers.insert(report.blockers.begin(), std::move(explicit_blocker));
  }

  report.ready_to_advance =
      report.blockers.empty() && report.next_phase != Phase::unknown && !IsTerminal(record->phase);
  report.next_action = NextRequiredAction(*record);
  return report;
}

Result<std::string> Engine::FenceToken(const CaseKey& key) const {
  auto view = GetCase(key);
  if (!view.ok()) {
    return view.error();
  }
  return view.value().fence_token;
}

void Engine::InvokeForTesting(const std::function<void()>& action) const {
  if (impl_ == nullptr) {
    return;
  }
  const LockOrderGuard guard(&impl_->lock_order, kLockLevelMutationSerialiser);
  // Actually take the serialiser. A guard that only told the validator it had
  // taken the lock would make the callback-not-under-lock proof a claim about the
  // validator rather than about the engine.
  const std::unique_lock<std::mutex> lock(impl_->mutation_mu);
  action();
}

}  // namespace decommissioning_fabric

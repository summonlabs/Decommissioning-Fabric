// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Seeded randomized state-machine test over the real engine and the real
// durable store.
//
// Forty seeds are derived from one fixed base seed. Each seed opens its own
// temporary store, registers one asset, and then applies forty randomly chosen
// actions to that asset's retirement case: well formed requests, deliberately
// malformed ones, and requests that are legal only in a phase the case may or
// may not be in. An action is allowed to be refused. The proof is not that
// every action succeeds but that a fixed set of model invariants holds after
// EVERY step, which is what makes it impossible to reach a state the model says
// is impossible:
//
//   1. an applied mutation strictly advances the durable commit sequence, and a
//      refusal leaves it exactly unchanged: a refusal is not an effect;
//   2. an applied mutation to an existing case strictly advances its revision;
//   3. a case is never in Phase::unknown;
//   4. a terminal case is absorbing: no later action applies a mutation to it,
//      and every submit fenced against it is refused;
//   5. observed removal implies an authorization to remove;
//   6. canonical deletion is never claimed, at any step;
//   7. a satisfied obligation names evidence that exists on the case, that
//      postdates the obligation, and that names the obligation it satisfies;
//   8. a waived obligation names an exception that exists on the case;
//   9. a waived residual item names an exception that exists on the case;
//  10. the authority report classifies every domain exactly once;
//  11. the fence obligation count and digest equal the required-unresolved set;
//  12. the state recovered from a reopened store matches the in-memory view on
//      phase, revision, obligation identities and states, residual categories
//      and dispositions, and receipt count;
//  13. after a terminal phase, ten more random actions apply nothing to it.
//
// Nothing here is synthetic: every check runs against the real engine and a real
// durable store in a real temporary directory, and every seed ends by destroying
// the engine and reopening the store.

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "decommissioning_fabric/engine.hpp"
#include "decommissioning_fabric/hash.hpp"
#include "fixture.hpp"
#include "harness.hpp"

namespace df = decommissioning_fabric;

using df_fixture::Driver;
using df_fixture::Finding;
using df_fixture::OpenEngine;
using df_fixture::TempDir;

namespace {

// ---------------------------------------------------------------------------
// Deterministic randomness and the action set
// ---------------------------------------------------------------------------

/// The one fixed base seed. Every seed below is derived from this value with
/// df::SplitMix64Next, so the whole test is a pure function of it and a failure
/// is reproducible from the reported step alone.
constexpr std::uint64_t kBaseSeed = 0x5EEDFA8B10C0FFEEULL;

constexpr std::size_t kSeedCount = 40;
constexpr std::size_t kActionsPerSeed = 40;
constexpr std::size_t kTerminalWindowActions = 10;

/// The randomly drawn action set. The two indices past it are deterministic
/// coverage actions, never drawn: they exist so that terminal absorption is
/// exercised even when the random walk never reaches a terminal phase.
constexpr std::size_t kActionCount = 22;
constexpr std::size_t kCancelActionIndex = kActionCount;
constexpr std::size_t kFailActionIndex = kActionCount + 1U;

/// One SplitMix64 stream per seed. Every draw in the seed comes from here.
class Random {
 public:
  explicit Random(std::uint64_t state) noexcept : state_(state) {}

  [[nodiscard]] std::uint64_t Next() noexcept { return df::SplitMix64Next(state_); }

  [[nodiscard]] std::size_t Below(std::size_t bound) noexcept {
    if (bound == 0U) {
      return 0U;
    }
    return static_cast<std::size_t>(Next() % static_cast<std::uint64_t>(bound));
  }

  [[nodiscard]] bool Flag() noexcept { return (Next() & 1ULL) != 0ULL; }

 private:
  std::uint64_t state_;
};

/// Drain kinds that name a real dependency. Unknown is excluded here because a
/// finding that names no drain is refused before it can create an obligation.
constexpr df::DrainKind kDrainKinds[] = {
    df::DrainKind::asi_workload,       df::DrainKind::dfi_route,
    df::DrainKind::tenant_service,     df::DrainKind::power_dependency,
    df::DrainKind::cooling_dependency, df::DrainKind::maintenance_window,
    df::DrainKind::protected_service,  df::DrainKind::external_dependency};
constexpr std::size_t kDrainKindListCount = sizeof(kDrainKinds) / sizeof(kDrainKinds[0]);

/// Evidence kinds an unbound ingestion may name. Unknown is excluded because a
/// report that names no kind is malformed rather than evidence.
///
/// drain_satisfaction is deliberately absent from this pool. IngestEvidencePayload
/// carries no subject obligation and no drain kind, so ingesting that kind stores
/// an unbound satisfaction record, and the durable reader refuses exactly that
/// record ("drain satisfaction evidence does not name its obligation and drain
/// kind"). The engine accepts and commits the request anyway, which leaves a
/// store that cannot be reopened, so the round trip below would fail on state
/// the runtime itself wrote. That defect is recorded here rather than hidden:
/// once the engine refuses (or carries a subject for) an unbound satisfaction
/// report, this pool can name every evidence kind again.
constexpr df::EvidenceKind kIngestibleEvidenceKinds[] = {
    df::EvidenceKind::dependency_assessment,
    df::EvidenceKind::drain_request_acknowledgement,
    df::EvidenceKind::authority_revocation,
    df::EvidenceKind::residual_disposition,
    df::EvidenceKind::policy_exception,
    df::EvidenceKind::isolation_observation,
    df::EvidenceKind::removal_authorization,
    df::EvidenceKind::removal_observation};
constexpr std::size_t kIngestibleEvidenceKindCount =
    sizeof(kIngestibleEvidenceKinds) / sizeof(kIngestibleEvidenceKinds[0]);

/// Blocker reasons a block request may carry. None is excluded: a block that
/// names no reason is malformed rather than a block.
constexpr df::BlockerReason kBlockReasons[] = {
    df::BlockerReason::dependencies_unresolved, df::BlockerReason::authority_unknown,
    df::BlockerReason::residual_pending, df::BlockerReason::policy_violation,
    df::BlockerReason::evidence_stale};
constexpr std::size_t kBlockReasonCount = sizeof(kBlockReasons) / sizeof(kBlockReasons[0]);

/// Facility generations a random advance may target.
constexpr df::GenerationKind kGenerationKinds[] = {
    df::GenerationKind::facility_epoch, df::GenerationKind::policy,
    df::GenerationKind::dependency,     df::GenerationKind::capacity,
    df::GenerationKind::topology,       df::GenerationKind::maintenance};
constexpr std::size_t kGenerationKindListCount =
    sizeof(kGenerationKinds) / sizeof(kGenerationKinds[0]);

/// Dispositions a plain disposition set may assert. Unknown is excluded, and
/// waived is deliberately absent: a waiver must arrive through an attributed
/// policy exception instead.
constexpr df::ResidualDisposition kResidualDispositions[] = {
    df::ResidualDisposition::handled, df::ResidualDisposition::not_applicable,
    df::ResidualDisposition::pending};
constexpr std::size_t kResidualDispositionCount =
    sizeof(kResidualDispositions) / sizeof(kResidualDispositions[0]);

constexpr std::uint32_t CurrentGeneration(const df::FacilityGenerations& generations,
                                          df::GenerationKind kind) noexcept {
  switch (kind) {
    case df::GenerationKind::facility_epoch: return generations.facility_epoch.value();
    case df::GenerationKind::policy: return generations.policy_generation.value();
    case df::GenerationKind::dependency: return generations.dependency_generation.value();
    case df::GenerationKind::capacity: return generations.capacity_generation.value();
    case df::GenerationKind::topology: return generations.topology_generation.value();
    case df::GenerationKind::maintenance: return generations.maintenance_generation.value();
  }
  return 0U;
}

// ---------------------------------------------------------------------------
// Action outcomes
// ---------------------------------------------------------------------------

/// What one action did. A skipped action never reached the engine at all,
/// because the payload it needs (an obligation, a residual item) does not exist
/// yet; skipping is not a refusal and is not an effect either.
struct Outcome {
  bool attempted{false};
  bool applied{false};
  bool case_scoped{false};
  bool created_case{false};
  df::LifecycleGeneration generation;
};

[[nodiscard]] Outcome OutcomeOf(const df::Result<df::Decision>& result, bool case_scoped,
                                bool creates_case = false) {
  Outcome outcome;
  outcome.attempted = true;
  outcome.case_scoped = case_scoped;
  if (result.ok()) {
    outcome.applied = result.value().applied;
    outcome.generation = result.value().lifecycle_generation;
    // The action kind is taken from the caller rather than from the decision:
    // an applied create_plan does not set Decision::kind, so the decision alone
    // cannot tell a created case from any other accepted mutation.
    outcome.created_case = outcome.applied && creates_case;
  }
  return outcome;
}

// ---------------------------------------------------------------------------
// One action
// ---------------------------------------------------------------------------

[[nodiscard]] Outcome DoCreatePlan(Driver& driver, Random& random) {
  const std::string rationale = random.Flag() ? "state machine plan" : "state machine replan";
  return OutcomeOf(driver.CreatePlan(rationale), true, true);
}

[[nodiscard]] Outcome DoAssess(Driver& driver, Random& random) {
  const std::size_t count = random.Below(4U);
  std::vector<df::DependencyFinding> findings;
  findings.reserve(count);
  for (std::size_t index = 0; index < count; ++index) {
    const df::DrainKind kind = kDrainKinds[random.Below(kDrainKindListCount)];
    const df::ProtectedServiceClass service =
        df::kProtectedServiceClassOrder[random.Below(df::kProtectedServiceClassCount)];
    findings.push_back(Finding(kind, service, random.Flag(), random.Flag()));
  }
  return OutcomeOf(driver.Assess(std::move(findings)), true);
}

[[nodiscard]] Outcome DoSetDrainRequirement(Driver& driver, Random& random) {
  df::SetDrainRequirementPayload payload;
  payload.kind = kDrainKinds[random.Below(kDrainKindListCount)];
  payload.protected_class =
      df::kProtectedServiceClassOrder[random.Below(df::kProtectedServiceClassCount)];
  payload.required = random.Flag();
  payload.issued_to = "drain-authority";
  payload.detail = "state machine requirement";
  return OutcomeOf(driver.Submit(df::RequestKind::set_drain_requirement, payload), true);
}

/// The obligations of the case currently owning the asset, or an empty vector.
[[nodiscard]] std::vector<df::DrainObligation> CurrentObligations(Driver& driver) {
  const df::Result<df::CaseView> view = driver.Case();
  if (!view.ok()) {
    return {};
  }
  return view.value().record.obligations;
}

[[nodiscard]] Outcome DoAcknowledge(Driver& driver, Random& random) {
  const std::vector<df::DrainObligation> obligations = CurrentObligations(driver);
  if (obligations.empty()) {
    return Outcome{};
  }
  const df::ObligationId obligation = obligations[random.Below(obligations.size())].id;
  return OutcomeOf(driver.Acknowledge(obligation), true);
}

[[nodiscard]] Outcome DoSatisfy(Driver& driver, Random& random) {
  const std::vector<df::DrainObligation> obligations = CurrentObligations(driver);
  if (obligations.empty()) {
    return Outcome{};
  }
  const df::DrainObligation& obligation = obligations[random.Below(obligations.size())];
  // The reported drain is the obligation's own kind: evidence about a different
  // drain satisfies nothing, and that refusal is already covered elsewhere.
  return OutcomeOf(driver.Satisfy(obligation.id, obligation.kind), true);
}

[[nodiscard]] Outcome DoWaive(Driver& driver, Random& random) {
  const std::vector<df::DrainObligation> obligations = CurrentObligations(driver);
  if (obligations.empty()) {
    return Outcome{};
  }
  df::WaiveDrainPayload payload;
  payload.obligation = obligations[random.Below(obligations.size())].id;
  payload.authority = "state-machine-waiver-authority";
  payload.reference = "WM-1";
  payload.rationale = "a waiver recorded by the randomized state machine";
  return OutcomeOf(driver.Submit(df::RequestKind::waive_drain, payload), true);
}

[[nodiscard]] Outcome DoRecordRevocation(Driver& driver, Random& random) {
  std::vector<df::AuthorityDomain> domains;
  for (const df::AuthorityDomain domain : df::kAuthorityDomains) {
    if (random.Flag()) {
      domains.push_back(domain);
    }
  }
  // An empty subset is not a revocation at all, so it is replaced by the whole
  // set rather than submitted as a malformed request.
  if (domains.empty() || random.Below(4U) == 0U) {
    domains.clear();
    for (const df::AuthorityDomain domain : df::kAuthorityDomains) {
      domains.push_back(domain);
    }
  }
  return OutcomeOf(driver.RevokeDomains(domains), true);
}

[[nodiscard]] Outcome DoSetResidual(Driver& driver, Random& random) {
  const df::ResidualCategory category =
      df::kResidualCategoryOrder[random.Below(df::kResidualCategoryCount)];
  const df::ResidualDisposition disposition =
      kResidualDispositions[random.Below(kResidualDispositionCount)];
  return OutcomeOf(driver.Residual(category, disposition), true);
}

[[nodiscard]] Outcome DoPolicyException(Driver& driver, Random& random) {
  const df::Result<df::CaseView> view = driver.Case();
  if (!view.ok() || view.value().record.residual.empty()) {
    return Outcome{};
  }
  const std::vector<df::ResidualItem>& items = view.value().record.residual;
  df::RecordPolicyExceptionPayload payload;
  payload.item = items[random.Below(items.size())].id;
  payload.authority = "facility-policy-board";
  payload.reference = "EXC-1";
  payload.rationale = "an attributed departure recorded by the randomized state machine";
  return OutcomeOf(driver.Submit(df::RequestKind::record_policy_exception, payload), true);
}

[[nodiscard]] Outcome DoCancel(Driver& driver) {
  df::CancelPlanPayload payload;
  payload.reason = "state machine cancellation";
  return OutcomeOf(driver.Submit(df::RequestKind::cancel_plan, payload), true);
}

[[nodiscard]] Outcome DoFail(Driver& driver) {
  df::FailPlanPayload payload;
  payload.reason = "state machine failure";
  return OutcomeOf(driver.Submit(df::RequestKind::fail_plan, payload), true);
}

[[nodiscard]] Outcome DoBlock(Driver& driver, Random& random) {
  df::BlockPlanPayload payload;
  payload.reason = kBlockReasons[random.Below(kBlockReasonCount)];
  payload.detail = "state machine block";
  payload.required_action = "wait for the state machine to resume the plan";
  return OutcomeOf(driver.Submit(df::RequestKind::block_plan, payload), true);
}

[[nodiscard]] Outcome DoResume(Driver& driver) {
  df::ResumePlanPayload payload;
  payload.detail = "state machine resume";
  return OutcomeOf(driver.Submit(df::RequestKind::resume_plan, payload), true);
}

[[nodiscard]] Outcome DoIngestEvidence(Driver& driver, Random& random) {
  df::IngestEvidencePayload payload;
  payload.kind = kIngestibleEvidenceKinds[random.Below(kIngestibleEvidenceKindCount)];
  payload.observer = "state-machine-observer";
  payload.reference = "EV-1";
  payload.detail = "state machine evidence";
  return OutcomeOf(driver.Submit(df::RequestKind::ingest_evidence, payload), true);
}

/// A facility generation advance. It is not a mutation of the case, but it is a
/// real durable mutation: it fences every plan bound to the previous value, so
/// later case requests are refused rather than applied.
[[nodiscard]] Outcome DoAdvanceGeneration(df::Engine& engine, Random& random) {
  const df::GenerationKind kind = kGenerationKinds[random.Below(kGenerationKindListCount)];
  df::GenerationAdvanceRequest request;
  request.kind = kind;
  request.expected_current = CurrentGeneration(engine.generations(), kind);
  request.incarnation = df::CurrentIncarnation();
  request.at = df::Timestamp{df::ManualClock::kDefaultStartNanos +
                             static_cast<std::int64_t>(1000000U + random.Below(1000000U))};
  request.reason = "state machine generation advance";
  const df::Result<df::Decision> result = engine.AdvanceGeneration(request);

  Outcome outcome;
  outcome.attempted = true;
  outcome.case_scoped = false;
  outcome.applied = result.ok() && result.value().applied;
  return outcome;
}

[[nodiscard]] Outcome DoAction(std::size_t index, df::Engine& engine, Driver& driver,
                               Random& random) {
  switch (index) {
    case 0: return DoCreatePlan(driver, random);
    case 1: return DoAssess(driver, random);
    case 2: return DoSetDrainRequirement(driver, random);
    case 3: return DoAcknowledge(driver, random);
    case 4: return DoSatisfy(driver, random);
    case 5: return DoWaive(driver, random);
    case 6: return OutcomeOf(driver.Drains(), true);
    case 7: return OutcomeOf(driver.ConcludeDraining(), true);
    case 8: return DoRecordRevocation(driver, random);
    case 9: return OutcomeOf(driver.ConcludeAuthority(), true);
    case 10: return DoSetResidual(driver, random);
    case 11: return DoPolicyException(driver, random);
    case 12: return OutcomeOf(driver.Isolation(), true);
    case 13: return OutcomeOf(driver.AuthorizeRemoval(), true);
    case 14: return OutcomeOf(driver.ObserveRemoval(), true);
    case 15: return OutcomeOf(driver.Finalize(), true);
    case 16: return DoCancel(driver);
    case 17: return DoFail(driver);
    case 18: return DoBlock(driver, random);
    case 19: return DoResume(driver);
    case 20: return DoIngestEvidence(driver, random);
    case 21: return DoAdvanceGeneration(engine, random);
    case kCancelActionIndex: return DoCancel(driver);
    case kFailActionIndex: return DoFail(driver);
    default: break;
  }
  return Outcome{};
}

// ---------------------------------------------------------------------------
// Invariant machinery
// ---------------------------------------------------------------------------

/// The last observed shape of one case generation. A case is never destroyed, so
/// this map only ever grows, and comparing against it after every step is what
/// turns "a refusal is not an effect" into a checked property.
struct CaseSnapshot {
  df::Revision revision;
  df::Phase phase{df::Phase::unknown};
  bool terminal{false};
};

using SnapshotMap = std::map<std::uint32_t, CaseSnapshot>;

/// What the action that just ran claimed to do.
struct SweepInput {
  bool applied{false};
  bool case_scoped{false};
  bool created_case{false};
  std::uint32_t generation{0};
};

[[nodiscard]] std::vector<df::CaseKey> CasesOf(df::Engine& engine, df::AssetId asset) {
  std::vector<df::CaseKey> keys;
  for (const df::CaseKey& key : engine.ListCases()) {
    if (key.asset == asset) {
      keys.push_back(key);
    }
  }
  return keys;
}

[[nodiscard]] std::vector<std::uint32_t> TerminalGenerations(df::Engine& engine,
                                                             df::AssetId asset) {
  std::vector<std::uint32_t> generations;
  for (const df::CaseKey& key : CasesOf(engine, asset)) {
    const df::Result<df::CaseView> view = engine.GetCase(key);
    if (view.ok() && df::IsTerminal(view.value().record.phase)) {
      generations.push_back(key.generation.value());
    }
  }
  return generations;
}

[[nodiscard]] bool ContainsGeneration(const std::vector<std::uint32_t>& generations,
                                      std::uint32_t value) {
  for (const std::uint32_t candidate : generations) {
    if (candidate == value) {
      return true;
    }
  }
  return false;
}

/// Counters that make the coverage of the randomized walk itself checkable: a
/// proof whose deep branches are never reached passes vacuously.
struct SeedStats {
  std::size_t applied{0};
  std::size_t refused{0};
  std::size_t skipped{0};
  std::size_t satisfied{0};
  std::size_t waived_obligations{0};
  std::size_t waived_residual{0};
  std::size_t terminal_windows{0};
  std::size_t terminal_probes{0};
};

/// Every invariant that is a statement about one case record, checked against
/// the live engine view. Nothing here is cached: the view is recomputed by the
/// engine from its own state on every read.
void SweepCaseRecord(const df::CaseView& view, const std::string& context, SeedStats& stats) {
  const df::RetirementCase& record = view.record;

  // 3. A case exists, so its phase is known.
  DF_CHECK_MSG(record.phase != df::Phase::unknown,
               context + ": a case is never in the unknown phase");

  // 5. Observation of removal implies an authorization to remove.
  DF_CHECK_MSG(!record.removal.observed || record.removal_authorized,
               context + ": observed removal implies an authorization to remove");

  // 6. This runtime never claims canonical deletion, at any step.
  DF_CHECK_MSG(record.removal.canonical_deletion == false,
               context + ": canonical deletion is never claimed");

  // 10. The authority report classifies every domain exactly once.
  const df::AuthorityReport& authority = view.authority;
  const std::uint32_t classified =
      authority.active_count + authority.revoked_count + authority.unknown_count;
  DF_CHECK_EQ(classified, df::kAuthorityDomainCount);
  DF_CHECK_MSG(authority.active == record.active_authority,
               context + ": the report's active mask is the case's live belief");

  // 7, 8, and the obligation half of 11.
  std::uint32_t unresolved = 0;
  for (const df::DrainObligation& obligation : record.obligations) {
    if (obligation.blocks_progress()) {
      ++unresolved;
    }
    if (obligation.state == df::ObligationState::satisfied) {
      ++stats.satisfied;
      DF_CHECK_MSG(obligation.satisfaction_evidence.is_set(),
                   context + ": a satisfied obligation names its evidence");
      const df::EvidenceRef* evidence = df::FindEvidence(record, obligation.satisfaction_evidence);
      DF_CHECK_MSG(evidence != nullptr, context + ": satisfaction evidence exists on the case");
      if (evidence != nullptr) {
        DF_CHECK_MSG(evidence->observation_sequence.value() > obligation.issued_sequence.value(),
                     context + ": satisfaction postdates the obligation it satisfies");
        DF_CHECK_MSG(evidence->subject_obligation == obligation.id,
                     context + ": satisfaction evidence names the obligation it satisfies");
        DF_CHECK_MSG(evidence->subject_kind == obligation.kind,
                     context + ": satisfaction evidence names the drain kind it reports");
      }
    }
    if (obligation.state == df::ObligationState::waived) {
      ++stats.waived_obligations;
      DF_CHECK_MSG(obligation.waiver.is_set(),
                   context + ": a waived obligation names an exception");
      DF_CHECK_MSG(df::FindException(record, obligation.waiver) != nullptr,
                   context + ": the obligation's exception exists on the case");
    }
  }

  // 11. The fence obligation binding is exactly the required-unresolved set.
  DF_CHECK_EQ(record.fence.active_obligation_count, unresolved);
  DF_CHECK_MSG(record.fence.active_obligation_digest ==
                   df::ActiveObligationDigest(record.obligations),
               context + ": the fence obligation digest is the required-unresolved digest");

  // 9. A waived residual item names an exception that exists.
  for (const df::ResidualItem& item : record.residual) {
    DF_CHECK_MSG(item.category != df::ResidualCategory::unknown,
                 context + ": a residual item always names a category");
    if (item.disposition == df::ResidualDisposition::waived) {
      ++stats.waived_residual;
      DF_CHECK_MSG(item.waiver.is_set(),
                   context + ": a waived residual item names an exception");
      DF_CHECK_MSG(df::FindException(record, item.waiver) != nullptr,
                   context + ": the residual item's exception exists on the case");
    }
  }

  // The recorded proofs themselves name evidence that exists.
  if (record.isolation_observed) {
    DF_CHECK_MSG(df::FindEvidence(record, record.isolation_evidence) != nullptr,
                 context + ": isolation evidence exists on the case");
  }
  if (record.removal.observed) {
    DF_CHECK_MSG(df::FindEvidence(record, record.removal.evidence) != nullptr,
                 context + ": removal evidence exists on the case");
  }
  if (record.removal_authorized) {
    DF_CHECK_MSG(df::FindEvidence(record, record.removal_authorization_evidence) != nullptr,
                 context + ": removal authorization evidence exists on the case");
  }
}

/// Checks every case of the asset against its last observed snapshot, then
/// against the record invariants, then records the new snapshot.
void Sweep(df::Engine& engine, df::AssetId asset, SnapshotMap& known, const SweepInput& input,
           const std::string& context, SeedStats& stats) {
  const std::vector<df::CaseKey> keys = CasesOf(engine, asset);

  if (input.applied && input.case_scoped) {
    bool present = false;
    for (const df::CaseKey& key : keys) {
      if (key.generation.value() == input.generation) {
        present = true;
      }
    }
    DF_CHECK_MSG(present, context + ": an applied mutation names a case that exists");
  }

  for (const df::CaseKey& key : keys) {
    const df::Result<df::CaseView> view = engine.GetCase(key);
    DF_CHECK_MSG(view.ok(), context + ": a listed case is readable");
    if (!view.ok()) {
      continue;
    }
    const df::RetirementCase& record = view.value().record;
    const std::uint32_t generation = key.generation.value();
    const auto prior = known.find(generation);
    const bool existed = prior != known.end();

    if (existed) {
      const CaseSnapshot before = prior->second;
      const bool mutated = input.applied && input.case_scoped && input.generation == generation;
      if (before.terminal) {
        // 4. Terminal absorption, checked on every step, for every case.
        DF_CHECK_MSG(!mutated, context + ": a terminal case absorbs every later mutation");
        DF_CHECK_MSG(record.phase == before.phase,
                     context + ": a terminal case never changes phase");
        DF_CHECK_MSG(record.fence.revision.value() == before.revision.value(),
                     context + ": a terminal case never changes revision");
      } else if (mutated) {
        // 2. An applied mutation to an existing case advances its revision.
        DF_CHECK_MSG(record.fence.revision.value() > before.revision.value(),
                     context + ": an applied mutation strictly advances the case revision");
      } else {
        // 1. A request that did not apply is not an effect on the case either.
        DF_CHECK_MSG(record.fence.revision.value() == before.revision.value(),
                     context + ": a request that did not apply does not change the revision");
        DF_CHECK_MSG(record.phase == before.phase,
                     context + ": a request that did not apply does not move the phase");
      }
    } else {
      DF_CHECK_MSG(record.fence.revision.is_set(),
                   context + ": a case starts at a set revision");
      if (input.created_case && input.generation == generation) {
        DF_CHECK_MSG(record.phase == df::Phase::requested,
                     context + ": a newly created case starts in the requested phase");
      }
    }

    SweepCaseRecord(view.value(), context, stats);
    known[generation] = CaseSnapshot{record.fence.revision, record.phase,
                                     df::IsTerminal(record.phase)};
  }

  DF_CHECK_MSG(known.size() == keys.size(),
               context + ": every case ever created still exists");
}

/// Runs one action, then proves that it was either a real effect or no effect at
/// all, then sweeps every invariant over every case of the asset.
Outcome RunOneAction(std::size_t action_index, df::Engine& engine, Driver& driver,
                     df::AssetId asset, Random& random, SnapshotMap& known, SeedStats& stats,
                     const std::string& context) {
  const std::size_t cases_before = CasesOf(engine, asset).size();
  const df::CommitSequence sequence_before = engine.commit_sequence();

  const Outcome outcome = DoAction(action_index, engine, driver, random);

  const df::CommitSequence sequence_after = engine.commit_sequence();
  if (!outcome.attempted) {
    ++stats.skipped;
    DF_CHECK_MSG(sequence_after.value() == sequence_before.value(),
                 context + ": a skipped action is not an effect either");
    return outcome;
  }

  if (outcome.applied) {
    // 1. An applied mutation strictly advances the durable commit sequence.
    ++stats.applied;
    DF_CHECK_MSG(sequence_after.value() > sequence_before.value(),
                 context + ": an applied mutation strictly advances the commit sequence");
  } else {
    // 1. A refusal is not an effect: the commit sequence is exactly unchanged.
    ++stats.refused;
    DF_CHECK_MSG(sequence_after.value() == sequence_before.value(),
                 context + ": a refusal is not an effect: the commit sequence is unchanged");
  }

  SweepInput input;
  input.applied = outcome.applied;
  input.case_scoped = outcome.case_scoped;
  input.created_case = outcome.created_case;
  input.generation = outcome.generation.value();
  Sweep(engine, asset, known, input, context, stats);

  const std::size_t cases_after = CasesOf(engine, asset).size();
  if (outcome.created_case) {
    DF_CHECK_MSG(cases_after == cases_before + 1U,
                 context + ": create_plan creates exactly one case");
  } else {
    DF_CHECK_MSG(cases_after == cases_before,
                 context + ": only create_plan ever creates a case");
  }
  return outcome;
}

/// Submits against every terminal case with its own live fence. A terminal case
/// must refuse the request, and must refuse it on the phase predicate or on the
/// fence, never by applying something.
void ProbeTerminalCases(df::Engine& engine, Driver& driver, df::AssetId asset, SeedStats& stats) {
  for (const df::CaseKey& key : CasesOf(engine, asset)) {
    const df::Result<df::CaseView> view = engine.GetCase(key);
    if (!view.ok() || !df::IsTerminal(view.value().record.phase)) {
      continue;
    }
    df::DeclareIsolationReadyPayload payload;
    payload.observer = "state-machine-probe";
    payload.reference = "PROBE-1";
    payload.detail = "a submit fenced against a terminal case must be refused";
    const df::Result<df::Decision> probe = driver.SubmitAgainst(
        df::RequestKind::declare_isolation_ready, std::move(payload), view.value().record.fence);
    ++stats.terminal_probes;
    DF_CHECK_MSG(!probe.ok(), "a submit fenced against a terminal case is always refused");
    if (!probe.ok()) {
      const df::ErrorCode code = probe.error().code;
      DF_CHECK_MSG(code == df::ErrorCode::phase_terminal || code == df::ErrorCode::fence_stale,
                   "a terminal case refuses on the phase or on the fence, never by applying");
    }
  }
}

/// Diagnostic text for a store that refuses to reopen: every evidence record
/// with the subject binding the durable reader validates, and every obligation
/// state. It is only ever included in a failure message, and it turns a
/// store_corrupt refusal into a one-run diagnosis.
[[nodiscard]] std::string DescribeEvidence(df::Engine& engine, df::AssetId asset) {
  std::string text;
  for (const df::CaseKey& key : CasesOf(engine, asset)) {
    const df::Result<df::CaseView> view = engine.GetCase(key);
    if (!view.ok()) {
      continue;
    }
    for (const df::EvidenceRef& evidence : view.value().record.evidence) {
      text += " [evidence=" + std::to_string(evidence.id.value()) +
              " kind=" + std::to_string(static_cast<std::uint32_t>(evidence.kind)) +
              " subject_kind=" +
              std::to_string(static_cast<std::uint32_t>(evidence.subject_kind)) +
              " subject_obligation=" + std::to_string(evidence.subject_obligation.value()) + "]";
    }
    for (const df::DrainObligation& obligation : view.value().record.obligations) {
      text += " [obligation=" + std::to_string(obligation.id.value()) + " state=" +
              std::to_string(static_cast<std::uint32_t>(obligation.state)) + "]";
    }
  }
  return text;
}

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

/// The fields the round trip compares. Evidence freshness is deliberately not
/// one of them: recovered evidence is marked recovered on every open, which is a
/// statement about the incarnation rather than about the record.
struct CaseSummary {
  df::Phase phase{df::Phase::unknown};
  std::uint64_t revision{0};
  std::vector<std::uint64_t> obligation_ids;
  std::vector<std::uint32_t> obligation_states;
  std::vector<std::uint32_t> residual_categories;
  std::vector<std::uint32_t> residual_dispositions;
  std::size_t receipt_count{0};
  std::size_t evidence_count{0};
};

[[nodiscard]] CaseSummary Summarize(const df::RetirementCase& record) {
  CaseSummary summary;
  summary.phase = record.phase;
  summary.revision = record.fence.revision.value();
  for (const df::DrainObligation& obligation : record.obligations) {
    summary.obligation_ids.push_back(obligation.id.value());
    summary.obligation_states.push_back(static_cast<std::uint32_t>(obligation.state));
  }
  for (const df::ResidualItem& item : record.residual) {
    summary.residual_categories.push_back(static_cast<std::uint32_t>(item.category));
    summary.residual_dispositions.push_back(static_cast<std::uint32_t>(item.disposition));
  }
  summary.receipt_count = record.receipts.size();
  summary.evidence_count = record.evidence.size();
  return summary;
}

void CheckRoundTrip(const CaseSummary& memory, const CaseSummary& recovered,
                    const std::string& context) {
  DF_CHECK_MSG(memory.phase == recovered.phase, context + ": the recovered phase matches");
  DF_CHECK_EQ(recovered.revision, memory.revision);
  DF_CHECK_EQ(recovered.obligation_ids.size(), memory.obligation_ids.size());
  const std::size_t obligations = memory.obligation_ids.size() < recovered.obligation_ids.size()
                                      ? memory.obligation_ids.size()
                                      : recovered.obligation_ids.size();
  for (std::size_t index = 0; index < obligations; ++index) {
    DF_CHECK_EQ(recovered.obligation_ids[index], memory.obligation_ids[index]);
    DF_CHECK_EQ(recovered.obligation_states[index], memory.obligation_states[index]);
  }
  DF_CHECK_EQ(recovered.residual_categories.size(), memory.residual_categories.size());
  const std::size_t residual =
      memory.residual_categories.size() < recovered.residual_categories.size()
          ? memory.residual_categories.size()
          : recovered.residual_categories.size();
  for (std::size_t index = 0; index < residual; ++index) {
    DF_CHECK_EQ(recovered.residual_categories[index], memory.residual_categories[index]);
    DF_CHECK_EQ(recovered.residual_dispositions[index], memory.residual_dispositions[index]);
  }
  DF_CHECK_EQ(recovered.receipt_count, memory.receipt_count);
  DF_CHECK_EQ(recovered.evidence_count, memory.evidence_count);
}

// ---------------------------------------------------------------------------
// One seed
// ---------------------------------------------------------------------------

void RunSeed(std::uint64_t seed, SeedStats& stats) {
  const std::string label = "seed " + std::to_string(seed);
  const TempDir directory("sm_" + std::to_string(seed));
  const df::AssetId asset = df::AssetId::FromValue(0x100000ULL + (seed % 0xEFFFFFULL));
  Random random(seed);
  SnapshotMap known;
  std::map<std::uint32_t, CaseSummary> memory;
  std::string evidence_dump;
  std::uint64_t sequence_before_reopen = 0;

  {
    df::Result<df::Engine> opened = OpenEngine(directory);
    DF_CHECK_MSG(opened.ok(), label + ": the engine opens a fresh durable store");
    df::Engine& engine = opened.value();
    Driver driver(engine, asset);

    // The prologue is the one mutation the design fixes rather than draws: every
    // other action needs a registered asset to act on.
    const df::Result<df::Decision> registration = driver.Register();
    DF_CHECK_MSG(registration.ok(), label + ": the asset registers");
    if (registration.ok()) {
      DF_CHECK_MSG(registration.value().applied, label + ": registration is a real mutation");
    }

    for (std::size_t step = 0; step < kActionsPerSeed; ++step) {
      const std::string context = label + " step " + std::to_string(step);
      RunOneAction(random.Below(kActionCount), engine, driver, asset, random, known, stats,
                   context);
    }

    // Coverage: a random walk may never reach a terminal phase, and terminal
    // absorption is the invariant most worth exercising, so one deterministic
    // attempt with the live fence is made first. It is a real action with the
    // same bookkeeping as any other.
    if (TerminalGenerations(engine, asset).empty()) {
      RunOneAction(kCancelActionIndex, engine, driver, asset, random, known, stats,
                   label + " terminal coverage cancel");
    }
    if (TerminalGenerations(engine, asset).empty()) {
      RunOneAction(kFailActionIndex, engine, driver, asset, random, known, stats,
                   label + " terminal coverage fail");
    }

    // 13. After a terminal phase, ten more random actions may not apply anything
    // to that case, and every submit fenced against it must be refused.
    const std::vector<std::uint32_t> terminal_generations = TerminalGenerations(engine, asset);
    if (!terminal_generations.empty()) {
      ++stats.terminal_windows;
      for (std::size_t step = 0; step < kTerminalWindowActions; ++step) {
        const std::string context = label + " terminal step " + std::to_string(step);
        const Outcome outcome = RunOneAction(random.Below(kActionCount), engine, driver, asset,
                                             random, known, stats, context);
        if (outcome.applied && outcome.case_scoped) {
          DF_CHECK_MSG(!ContainsGeneration(terminal_generations, outcome.generation.value()),
                       context + ": nothing applies to a terminal case after it terminated");
        }
        ProbeTerminalCases(engine, driver, asset, stats);
      }
    }

    evidence_dump = DescribeEvidence(engine, asset);
    sequence_before_reopen = engine.commit_sequence().value();
    for (const df::CaseKey& key : CasesOf(engine, asset)) {
      const df::Result<df::CaseView> view = engine.GetCase(key);
      DF_CHECK_MSG(view.ok(), label + ": the case is readable before the reopen");
      if (view.ok()) {
        memory[key.generation.value()] = Summarize(view.value().record);
      }
    }
  }

  // 12. Destroy the engine, reopen the store, and compare field for field.
  {
    df::Result<df::Engine> reopened = OpenEngine(directory);
    DF_CHECK_MSG(reopened.ok(),
                 label + ": the durable store reopens after the engine is gone" +
                     (reopened.ok()
                          ? std::string()
                          : " [" + reopened.error().to_string() + "]" + evidence_dump));
    df::Engine& engine = reopened.value();
    DF_CHECK_EQ(engine.commit_sequence().value(), sequence_before_reopen);

    std::map<std::uint32_t, CaseSummary> recovered;
    for (const df::CaseKey& key : CasesOf(engine, asset)) {
      const df::Result<df::CaseView> view = engine.GetCase(key);
      DF_CHECK_MSG(view.ok(), label + ": the recovered case is readable");
      if (view.ok()) {
        recovered[key.generation.value()] = Summarize(view.value().record);
      }
    }
    DF_CHECK_MSG(recovered.size() == memory.size(),
                 label + ": the recovered store keeps every case");
    for (const auto& entry : memory) {
      const auto found = recovered.find(entry.first);
      DF_CHECK_MSG(found != recovered.end(),
                   label + ": the recovered store keeps the lifecycle generation");
      if (found != recovered.end()) {
        CheckRoundTrip(entry.second, found->second, label + " reopen");
      }
    }

    // The recovered state is a state of the same model, so it satisfies every
    // case invariant too.
    SnapshotMap fresh;
    SweepInput input;
    Sweep(engine, asset, fresh, input, label + " recovered", stats);
  }
}

}  // namespace

DF_TEST(StateMachine_RandomActionsCannotReachAnImpossibleState) {
  SeedStats stats;
  std::uint64_t seed_state = kBaseSeed;
  for (std::size_t index = 0; index < kSeedCount; ++index) {
    const std::uint64_t seed = df::SplitMix64Next(seed_state);
    RunSeed(seed, stats);
  }

  // Coverage. A randomized proof that never applies anything, never refuses
  // anything, or never reaches a terminal phase would pass vacuously, so the
  // generator's own coverage is asserted too. The counts are in every failure
  // detail so a degenerate generator is diagnosable in one run.
  const std::string counts =
      " (applied=" + std::to_string(stats.applied) + ", refused=" + std::to_string(stats.refused) +
      ", skipped=" + std::to_string(stats.skipped) +
      ", satisfied=" + std::to_string(stats.satisfied) +
      ", waived obligations=" + std::to_string(stats.waived_obligations) +
      ", waived residual=" + std::to_string(stats.waived_residual) +
      ", terminal windows=" + std::to_string(stats.terminal_windows) +
      ", terminal probes=" + std::to_string(stats.terminal_probes) + ")";

  DF_CHECK_MSG(stats.applied >= kSeedCount,
               std::string("the walk must apply real mutations") + counts);
  DF_CHECK_MSG(stats.refused >= kSeedCount,
               std::string("the walk must be refused as well as applied") + counts);
  DF_CHECK_MSG(stats.skipped > 0U,
               std::string("an action that needs an artifact that does not exist must be skipped") +
                   counts);
  DF_CHECK_MSG(stats.satisfied >= kSeedCount,
               std::string("the walk must observe obligations satisfied by evidence") + counts);
  DF_CHECK_MSG(stats.waived_obligations > 0U,
               std::string("the walk must observe an obligation resolved by a policy exception") +
                   counts);
  DF_CHECK_MSG(stats.waived_residual > 0U,
               std::string("the walk must observe a residual item resolved by an exception") +
                   counts);
  DF_CHECK_MSG(stats.terminal_windows >= kSeedCount / 4U,
               std::string("terminal absorption must be exercised by many seeds") + counts);
  DF_CHECK_MSG(stats.terminal_probes >= stats.terminal_windows * kTerminalWindowActions,
               std::string("every post-terminal step must probe a terminal case") + counts);
}

DF_TEST_MAIN()

// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Property tests for the two invariants the error model rests on:
//
//   * Determinism  - the same (state, request) pair always resolves to the same
//                    (stage, code, message, details), so a refusal is a fact
//                    about the request rather than about scheduling or map
//                    iteration order.
//   * Monotonicity - a request carrying several defects is reported at exactly
//                    the MINIMUM stage among the defects actually present, so
//                    adding a defect at a later stage can never change the
//                    verdict of an earlier one.
//
// One base state is prepared on one engine and then probed with 20000 seeded
// subsets of five independently applicable defects, each carrying its own
// nominal stage. Nothing in the loop mutates anything: a refusal is not an
// effect, and the durable commit sequence is asserted to be unchanged.
//
// Stage coverage, one witness each:
//   parse_shape      - the shape defect alone
//   bounds_limits    - a revocation naming more domains than exist
//   identity         - the identity defect alone
//   request_registry - the registry defect alone
//   asset_existence  - a fence whose lifecycle generation has no case
//   fence            - the fence defect alone
//   phase_predicate  - the phase defect alone
//   prerequisite     - the base request, refused on its outstanding obligation
//   policy           - a waive_drain against a protected service obligation
//   ok               - a fully valid request, accepted and committed

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "decommissioning_fabric/engine.hpp"
#include "decommissioning_fabric/errors.hpp"
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
// The five independently applicable defects, each with a nominal stage
// ---------------------------------------------------------------------------

constexpr unsigned kShapeDefect = 1U << 0U;     // stage 1: parse_shape
constexpr unsigned kIdentityDefect = 1U << 1U;  // stage 3: identity
constexpr unsigned kRegistryDefect = 1U << 2U;  // stage 4: request_registry
constexpr unsigned kFenceDefect = 1U << 3U;     // stage 6: fence
constexpr unsigned kPhaseDefect = 1U << 4U;     // stage 7: phase_predicate

constexpr std::uint64_t kAsset = 0x1001ULL;
constexpr std::uint64_t kPolicyAsset = 0x1002ULL;

/// The attempt the base request is submitted under when no defect applies. It is
/// never spent, because a refusal is not an effect.
constexpr std::uint64_t kFreshAttempt = 4242ULL;

/// The attempt the base state spends on an acknowledge_drain, so a request that
/// reuses it is a registry conflict rather than a replay.
constexpr std::uint64_t kSpentAttempt = 777ULL;

constexpr std::uint64_t kSeed = 0x5EED1234ABCD9876ULL;
constexpr unsigned kIterations = 20000U;
constexpr std::int64_t kRequestAt = df::ManualClock::kDefaultStartNanos + 1000000LL;

// ---------------------------------------------------------------------------
// Base state: one asset draining, with its one required obligation still open
// ---------------------------------------------------------------------------

struct BaseState {
  df::PlanFence fence;
  df::ObligationId obligation;
};

/// Registers one asset, creates its plan, assesses exactly one asi_workload
/// finding, reaches the draining phase, and acknowledges the resulting
/// obligation under attempt 777. The acknowledgement is metadata, so the
/// obligation stays open and the base request has exactly one defect: an unmet
/// prerequisite.
BaseState PrepareBaseState(Driver& driver) {
  DF_CHECK_MSG(driver.Register().ok(), "the fixture asset must register");
  DF_CHECK_MSG(driver.CreatePlan().ok(), "the fixture plan must be created");
  DF_CHECK_MSG(driver.Assess({Finding(df::DrainKind::asi_workload)}).ok(),
               "one asi_workload finding must be assessed");
  DF_CHECK_MSG(driver.Drains().ok(), "begin_draining must be accepted");
  DF_CHECK_MSG(driver.Phase() == df::Phase::draining,
               "begin_draining must leave the case in the draining phase");

  const std::vector<df::ObligationId> obligations = driver.Obligations();
  DF_CHECK_MSG(obligations.size() == 1U, "the assessment must create exactly one obligation");

  df::AcknowledgeDrainPayload acknowledgement;
  acknowledgement.obligation = obligations[0];
  acknowledgement.acknowledged_by = "drain-authority";
  acknowledgement.reference = "ACK-1";
  acknowledgement.detail = "acknowledged, not completed";
  const auto acknowledged = driver.SubmitWithAttempt(df::RequestKind::acknowledge_drain,
                                                     acknowledgement, kSpentAttempt);
  DF_CHECK_MSG(acknowledged.ok(),
               "the acknowledgement must be accepted so attempt 777 is in the registry");

  const auto view = driver.Case();
  DF_CHECK_MSG(view.ok(), "the case must be readable after the acknowledgement");

  const df::DrainObligation* obligation = df::FindObligation(view.value().record, obligations[0]);
  DF_CHECK_MSG(obligation != nullptr, "the acknowledged obligation must exist on the case");
  DF_CHECK_MSG(obligation->state == df::ObligationState::acknowledged,
               "acknowledgement is metadata: the obligation must not be satisfied by it");
  DF_CHECK_MSG(obligation->blocks_progress(),
               "an acknowledged required obligation must still block progress");

  BaseState base;
  base.fence = view.value().record.fence;
  base.obligation = obligations[0];

  // The fence defect lowers the revision by one, so the live revision must be
  // past the first one for that defect to be a revision behind rather than an
  // unset, malformed revision.
  DF_CHECK_MSG(base.fence.revision.value() > 1U,
               "the case revision must have advanced past the first revision");
  return base;
}

/// The base request: a well-formed conclude_draining against the live fence with
/// a fresh attempt. It has no defect at all, so its verdict is the prerequisite
/// stage, which is where the property search starts.
df::Request BaseRequest(const BaseState& base) {
  df::Request request;
  request.kind = df::RequestKind::conclude_draining;
  request.attempt = df::AttemptId::FromValue(kFreshAttempt);
  request.incarnation = df::CurrentIncarnation();
  request.at = df::Timestamp{kRequestAt};
  request.fence = base.fence;
  request.payload = df::ConcludeDrainingPayload{"property test"};
  return request;
}

/// Applies the defects in the bit set to the base request. Defects are applied
/// lowest stage last where two of them write the same field, so the request
/// really contains every defect the bit set claims:
///
///   * the identity defect dominates the registry defect, because an unset
///     attempt is reported before the registry is consulted;
///   * the shape defect is applied after the phase defect, so the payload stays
///     mismatched even once the kind has changed.
df::Request RequestWithDefects(const BaseState& base, unsigned defects) {
  df::Request request = BaseRequest(base);

  if ((defects & kRegistryDefect) != 0U) {
    request.attempt = df::AttemptId::FromValue(kSpentAttempt);
  }
  if ((defects & kIdentityDefect) != 0U) {
    request.attempt = df::AttemptId{};
  }
  if ((defects & kFenceDefect) != 0U) {
    request.fence.revision = base.fence.revision.Prev();
  }
  if ((defects & kPhaseDefect) != 0U) {
    request.kind = df::RequestKind::finalize_decommissioning;
    request.payload = df::FinalizeDecommissioningPayload{"property test"};
  }
  if ((defects & kShapeDefect) != 0U) {
    request.payload = df::BeginDrainingPayload{"property test"};
  }
  return request;
}

/// The minimum nominal stage among the applied defects, lowered from the
/// prerequisite stage the defect-free request fails at.
df::ValidationStage NominalStage(unsigned defects) {
  df::ValidationStage stage = df::ValidationStage::prerequisite;
  const auto lower = [&stage](df::ValidationStage candidate) {
    if (static_cast<std::uint32_t>(candidate) < static_cast<std::uint32_t>(stage)) {
      stage = candidate;
    }
  };
  if ((defects & kShapeDefect) != 0U) {
    lower(df::ValidationStage::parse_shape);
  }
  if ((defects & kIdentityDefect) != 0U) {
    lower(df::ValidationStage::identity);
  }
  if ((defects & kRegistryDefect) != 0U) {
    lower(df::ValidationStage::request_registry);
  }
  if ((defects & kFenceDefect) != 0U) {
    lower(df::ValidationStage::fence);
  }
  if ((defects & kPhaseDefect) != 0U) {
    lower(df::ValidationStage::phase_predicate);
  }
  return stage;
}

/// The code a lone defect must produce. Only called with a single bit.
df::ErrorCode NominalCode(unsigned defect) {
  switch (defect) {
    case kShapeDefect: return df::ErrorCode::malformed_request;
    case kIdentityDefect: return df::ErrorCode::unset_attempt;
    case kRegistryDefect: return df::ErrorCode::already_issued;
    case kFenceDefect: return df::ErrorCode::fence_revision_behind;
    case kPhaseDefect: return df::ErrorCode::phase_does_not_permit;
    default: return df::ErrorCode::internal_error;
  }
}

std::string SubsetText(unsigned defects) {
  std::string text;
  const auto add = [&text](const char* name) {
    if (!text.empty()) {
      text += "+";
    }
    text += name;
  };
  if ((defects & kShapeDefect) != 0U) {
    add("shape");
  }
  if ((defects & kIdentityDefect) != 0U) {
    add("identity");
  }
  if ((defects & kRegistryDefect) != 0U) {
    add("registry");
  }
  if ((defects & kFenceDefect) != 0U) {
    add("fence");
  }
  if ((defects & kPhaseDefect) != 0U) {
    add("phase");
  }
  return text.empty() ? std::string("none") : text;
}

std::string ContextText(unsigned iteration, unsigned defects, df::ValidationStage expected) {
  std::string text = "iteration=" + std::to_string(iteration);
  text += " subset=";
  text += SubsetText(defects);
  text += " expected_stage=";
  text += std::string(df::ToString(expected));
  return text;
}

std::string DescribeFailure(unsigned iteration, unsigned defects, df::ValidationStage expected,
                            const df::Error& error) {
  std::string text = ContextText(iteration, defects, expected);
  text += " actual_stage=";
  text += std::string(df::ToString(error.stage));
  text += " actual_code=";
  text += std::string(df::ToString(error.code));
  text += " error=";
  text += error.to_string();
  return text;
}

}  // namespace

// ---------------------------------------------------------------------------
// The base request is refused at its prerequisite, and that refusal is stable
// ---------------------------------------------------------------------------

DF_TEST(ValidationPrecedence_BaseRequestIsRefusedAtItsPrerequisite) {
  const TempDir directory("validation_base");
  auto engine = OpenEngine(directory);
  DF_CHECK_MSG(engine.ok(), "the engine must open on a fresh temporary store");
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));
  const BaseState base = PrepareBaseState(driver);

  const std::uint64_t committed = engine.value().commit_sequence().value();
  const df::Request request = BaseRequest(base);
  const auto outcome = engine.value().Submit(request);

  DF_CHECK_MSG(!outcome.ok(),
               "conclude_draining must be refused while the one required obligation is outstanding");
  const df::Error& error = outcome.error();
  DF_CHECK_EQ(error.stage, df::ValidationStage::prerequisite);
  DF_CHECK_CODE(outcome, df::ErrorCode::unmet_obligation);
  DF_CHECK_MSG(!error.message.empty(), "a refusal must carry a message");
  DF_CHECK_MSG(error.stage == df::StageOf(error.code),
               "a reported stage must be the stage its code belongs to");

  // Determinism, directly: the identical request resolves identically even
  // though nothing about the case changed in between.
  const auto repeated = engine.value().Submit(request);
  DF_CHECK_MSG(!repeated.ok(), "the identical request must be refused again");
  const df::Error& again = repeated.error();
  DF_CHECK_EQ(again.stage, error.stage);
  DF_CHECK_EQ(again.code, error.code);
  DF_CHECK_MSG(again.message == error.message, "the refusal message must be byte identical");
  DF_CHECK_MSG(again.details == error.details, "the refusal details must be identical");
  DF_CHECK_MSG(again.to_string() == error.to_string(), "the refusal rendering must be byte identical");
  DF_CHECK_MSG(engine.value().commit_sequence().value() == committed,
               "a refusal is not an effect: the commit sequence must not move");
}

// ---------------------------------------------------------------------------
// Each defect alone is reported at exactly its own nominal stage
// ---------------------------------------------------------------------------

DF_TEST(ValidationPrecedence_EachDefectAloneReportsItsOwnNominalStage) {
  const TempDir directory("validation_single");
  auto engine = OpenEngine(directory);
  DF_CHECK_MSG(engine.ok(), "the engine must open on a fresh temporary store");
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));
  const BaseState base = PrepareBaseState(driver);

  const unsigned singles[5] = {kShapeDefect, kIdentityDefect, kRegistryDefect, kFenceDefect,
                               kPhaseDefect};
  for (const unsigned defect : singles) {
    const df::Request request = RequestWithDefects(base, defect);
    const auto outcome = engine.value().Submit(request);
    DF_CHECK_MSG(!outcome.ok(), "defect " + SubsetText(defect) + " must be refused");
    const df::Error& error = outcome.error();
    const std::string context = "defect=" + SubsetText(defect) + " error=" + error.to_string();

    // Exactly its own nominal stage, not a neighbouring one.
    DF_CHECK_MSG(error.stage == NominalStage(defect), context);
    DF_CHECK_MSG(error.stage != df::ValidationStage::prerequisite,
                 context + " (a defect must be reported at its own stage, not at the prerequisite)");
    DF_CHECK_MSG(error.stage != df::ValidationStage::ok, context);
    DF_CHECK_CODE(outcome, NominalCode(defect));
    DF_CHECK_MSG(!error.message.empty(), context);
    DF_CHECK_MSG(error.stage == df::StageOf(error.code), context);
  }
}

// ---------------------------------------------------------------------------
// The property: 20000 seeded subsets, minimum stage, byte-identical repeats
// ---------------------------------------------------------------------------

DF_TEST(ValidationPrecedence_MonotonicPrecedenceOverSeededSubsets) {
  const TempDir directory("validation_property");
  auto engine = OpenEngine(directory);
  DF_CHECK_MSG(engine.ok(), "the engine must open on a fresh temporary store");
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));
  const BaseState base = PrepareBaseState(driver);

  const std::uint64_t committed = engine.value().commit_sequence().value();
  std::uint64_t random = kSeed;

  for (unsigned iteration = 0; iteration < kIterations; ++iteration) {
    const unsigned defects = static_cast<unsigned>(df::SplitMix64Next(random) & 0x1FU);
    const df::ValidationStage expected = NominalStage(defects);
    const df::Request request = RequestWithDefects(base, defects);

    const df::Result<df::Decision> first = engine.value().Submit(request);
    if (first.ok()) {
      DF_CHECK_MSG(false, ContextText(iteration, defects, expected) + " outcome=accepted");
    }
    const df::Error& error = first.error();
    const std::string context = DescribeFailure(iteration, defects, expected, error);

    // The reported stage is exactly the minimum stage among the defects present.
    DF_CHECK_MSG(error.stage == expected, context);
    DF_CHECK_MSG(error.stage == df::StageOf(error.code), context);
    DF_CHECK_MSG(df::IsValidationCode(error.code), context);
    DF_CHECK_MSG(!error.message.empty(), context);
    DF_CHECK_MSG(engine.value().commit_sequence().value() == committed,
                 context + " (a refusal moved the commit sequence)");

    // Determinism: the identical request, against an unchanged state, produces a
    // byte-identical fingerprint of stage, code, rendering and details.
    const df::Result<df::Decision> repeated = engine.value().Submit(request);
    if (repeated.ok()) {
      DF_CHECK_MSG(false, context + " outcome=accepted on the identical second submit");
    }
    const df::Error& again = repeated.error();
    DF_CHECK_MSG(again.stage == error.stage,
                 context + " (the stage changed between identical submits)");
    DF_CHECK_MSG(again.code == error.code,
                 context + " (the code changed between identical submits)");
    DF_CHECK_MSG(again.message == error.message,
                 context + " (the message changed between identical submits)");
    DF_CHECK_MSG(again.details == error.details,
                 context + " (the details changed between identical submits)");
    DF_CHECK_MSG(again.to_string() == error.to_string(),
                 context + " (the rendering changed between identical submits: " + again.to_string() +
                     ")");
  }

  DF_CHECK_MSG(engine.value().commit_sequence().value() == committed,
               "no refusal in the property loop may advance the durable commit sequence");
  DF_CHECK(driver.Phase() == df::Phase::draining);
}

// ---------------------------------------------------------------------------
// The remaining stages, each with a direct witness
// ---------------------------------------------------------------------------

DF_TEST(ValidationPrecedence_EveryRemainingStageHasAWitness) {
  const TempDir directory("validation_witness");
  auto engine = OpenEngine(directory);
  DF_CHECK_MSG(engine.ok(), "the engine must open on a fresh temporary store");
  Driver driver(engine.value(), df::AssetId::FromValue(kAsset));
  const BaseState base = PrepareBaseState(driver);
  const std::uint64_t committed = engine.value().commit_sequence().value();

  // bounds_limits: one authority domain more than the domain count. The count is
  // a statement about the envelope, so it is reported before identity is read.
  {
    df::RecordRevocationPayload revocation;
    revocation.domains.assign(df::kAuthorityDomains.begin(), df::kAuthorityDomains.end());
    revocation.domains.push_back(df::kAuthorityDomains[0]);
    revocation.authority = "authority";
    revocation.reference = "REV-1";
    revocation.detail = "reported by the owning authority";
    DF_CHECK(revocation.domains.size() > static_cast<std::size_t>(df::kAuthorityDomainCount));

    df::Request request = BaseRequest(base);
    request.kind = df::RequestKind::record_revocation;
    request.payload = revocation;
    const auto outcome = engine.value().Submit(request);
    DF_CHECK_MSG(!outcome.ok(), "a revocation naming 11 domains must be refused");
    DF_CHECK_EQ(outcome.error().stage, df::ValidationStage::bounds_limits);
    DF_CHECK_CODE(outcome, df::ErrorCode::too_many_items);
  }

  // asset_existence: a well-formed fence whose lifecycle generation has no case.
  {
    df::Request request = BaseRequest(base);
    request.fence.lifecycle_generation = base.fence.lifecycle_generation.Next();
    const auto outcome = engine.value().Submit(request);
    DF_CHECK_MSG(!outcome.ok(), "a fence naming a generation with no case must be refused");
    DF_CHECK_EQ(outcome.error().stage, df::ValidationStage::asset_existence);
    DF_CHECK_CODE(outcome, df::ErrorCode::unknown_case);
  }

  // policy: a protected service obligation is never waivable, and that is a
  // statement about policy rather than about the prerequisite.
  {
    Driver policy(engine.value(), df::AssetId::FromValue(kPolicyAsset));
    DF_CHECK(policy.Register().ok());
    DF_CHECK(policy.CreatePlan().ok());
    DF_CHECK(policy
                 .Assess({Finding(df::DrainKind::protected_service,
                                  df::ProtectedServiceClass::safety)})
                 .ok());
    DF_CHECK(policy.Drains().ok());
    const std::vector<df::ObligationId> obligations = policy.Obligations();
    DF_CHECK(obligations.size() == 1U);

    df::WaiveDrainPayload waiver;
    waiver.obligation = obligations[0];
    waiver.authority = "policy-authority";
    waiver.reference = "EXC-1";
    waiver.rationale = "requested by operations";
    const auto outcome = policy.Submit(df::RequestKind::waive_drain, waiver);
    DF_CHECK_MSG(!outcome.ok(), "waiving a protected service obligation must be refused");
    DF_CHECK_EQ(outcome.error().stage, df::ValidationStage::policy);
    DF_CHECK_CODE(outcome, df::ErrorCode::exception_not_permitted);
  }

  // The successful verdict is a stage of its own and is outside the failure
  // precedence.
  DF_CHECK_EQ(df::StageOf(df::ErrorCode::ok), df::ValidationStage::ok);
  DF_CHECK(!df::IsValidationCode(df::ErrorCode::ok));

  // ok: once the one required drain is satisfied by attributable evidence, the
  // very request that was refused at the prerequisite is accepted and committed.
  {
    const auto satisfied = driver.Satisfy(base.obligation, df::DrainKind::asi_workload);
    DF_CHECK_MSG(satisfied.ok(), "completion evidence for the outstanding obligation must be accepted");
    DF_CHECK_MSG(satisfied.value().applied, "an accepted request must be an applied mutation");
    DF_CHECK_MSG(engine.value().commit_sequence().value() > committed,
                 "an accepted request is an effect: the commit sequence must advance");

    const auto concluded = driver.ConcludeDraining();
    DF_CHECK_MSG(concluded.ok(), "conclude_draining must now be accepted");
    DF_CHECK(driver.Phase() == df::Phase::authority_revocation);
  }
}

DF_TEST_MAIN()

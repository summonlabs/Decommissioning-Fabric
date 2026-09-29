// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// lifecycle.hpp proof obligations.
//
// The transition table is the whole truth about what may follow what, so these
// tests check it exhaustively rather than by example: every (from, to, resume)
// triple is compared against an independently written rule set, the terminal and
// cancellation predicates are checked for every phase, and the blocker rendering
// is required to name the reason, the detail, the required action and every
// observed value.

#include "decommissioning_fabric/lifecycle.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "harness.hpp"

namespace {

using namespace decommissioning_fabric;

/// The actionable phases, written out here rather than read from the header so
/// the expectation is independent of the implementation under test.
constexpr std::array<Phase, 9> kExpectedActionable = {
    Phase::requested,        Phase::dependency_assessment, Phase::drain_required,
    Phase::draining,         Phase::authority_revocation,  Phase::residual_handling,
    Phase::isolation_ready,  Phase::removal_authorized,    Phase::removed_observed};

/// Cancellation is permitted strictly before removal is authorized.
constexpr std::array<Phase, 7> kExpectedCancellable = {
    Phase::requested,      Phase::dependency_assessment, Phase::drain_required,
    Phase::draining,       Phase::authority_revocation,  Phase::residual_handling,
    Phase::isolation_ready};

[[nodiscard]] bool ExpectedActionable(Phase phase) {
  for (const Phase candidate : kExpectedActionable) {
    if (candidate == phase) {
      return true;
    }
  }
  return false;
}

[[nodiscard]] bool ExpectedCancellable(Phase phase) {
  for (const Phase candidate : kExpectedCancellable) {
    if (candidate == phase) {
      return true;
    }
  }
  return false;
}

[[nodiscard]] bool ExpectedTerminal(Phase phase) {
  return phase == Phase::decommissioned || phase == Phase::failed || phase == Phase::cancelled;
}

[[nodiscard]] bool StaticEdgeExists(Phase from, Phase to) {
  for (const TransitionRule& rule : kLifecycleTransitions) {
    if (rule.from == from && rule.to == to) {
      return true;
    }
  }
  return false;
}

/// The complete legality rule, restated independently of IsLegalTransition.
[[nodiscard]] bool ExpectedLegal(Phase from, Phase to, Phase resume) {
  if (from == to) {
    return false;
  }
  if (ExpectedTerminal(from)) {
    return false;
  }
  if (from == Phase::unknown) {
    return false;
  }
  if (to == Phase::blocked) {
    return ExpectedActionable(from);
  }
  if (from == Phase::blocked) {
    if (to == Phase::failed) {
      return ExpectedActionable(resume);
    }
    if (to == Phase::cancelled) {
      return ExpectedCancellable(resume);
    }
    return to == resume && ExpectedActionable(resume);
  }
  if (to == Phase::failed) {
    return ExpectedActionable(from);
  }
  if (to == Phase::cancelled) {
    return ExpectedCancellable(from);
  }
  return StaticEdgeExists(from, to);
}

[[nodiscard]] std::string Triple(Phase from, Phase to, Phase resume) {
  return std::string(ToString(from)) + " -> " + std::string(ToString(to)) + " with resume " +
         std::string(ToString(resume));
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

DF_TEST(Lifecycle_EveryPhaseHasADistinctNameThatRoundTrips) {
  DF_CHECK_EQ(kPhaseOrder.size(), kPhaseCount);
  DF_CHECK_EQ(kPhaseCount, static_cast<std::size_t>(15));
  for (std::size_t i = 0; i < kPhaseOrder.size(); ++i) {
    const Phase phase = kPhaseOrder[i];
    // Fixed iteration order is the enum's declaration order, so the array is a
    // complete enumeration rather than a sample.
    DF_CHECK_EQ(static_cast<std::uint32_t>(phase), static_cast<std::uint32_t>(i));
    const std::string_view name = ToString(phase);
    DF_CHECK_MSG(!name.empty(), "phase name is empty");
    DF_CHECK_EQ(PhaseFromString(name), phase);
    for (std::size_t j = i + 1U; j < kPhaseOrder.size(); ++j) {
      DF_CHECK_NE(name, ToString(kPhaseOrder[j]));
    }
  }
}

DF_TEST(Lifecycle_PhaseFromString_RejectsUnrecognisedNames) {
  DF_CHECK_EQ(PhaseFromString("bogus"), Phase::unknown);
  DF_CHECK_EQ(PhaseFromString(""), Phase::unknown);
  DF_CHECK_EQ(PhaseFromString("Draining"), Phase::unknown);
  DF_CHECK_EQ(PhaseFromString("drain-required"), Phase::unknown);
  DF_CHECK_EQ(PhaseFromString("draining "), Phase::unknown);
  DF_CHECK_EQ(PhaseFromString(" draining"), Phase::unknown);
  DF_CHECK_EQ(PhaseFromString("decommissioned_x"), Phase::unknown);
  // The sentinel's own name maps back to the sentinel, so a caller that reads a
  // name must decide what an unrecognised phase means.
  DF_CHECK_EQ(PhaseFromString("unknown"), Phase::unknown);
  DF_CHECK_NE(PhaseFromString("removed_observed"), Phase::unknown);
  DF_CHECK_NE(PhaseFromString("commissioned"), Phase::unknown);
}

// ---------------------------------------------------------------------------
// Exhaustive transition legality
// ---------------------------------------------------------------------------

DF_TEST(Lifecycle_IsLegalTransition_IsExhaustivelyCorrect) {
  for (const Phase from : kPhaseOrder) {
    for (const Phase to : kPhaseOrder) {
      for (const Phase resume : kPhaseOrder) {
        const bool actual = IsLegalTransition(from, to, resume);
        DF_CHECK_MSG(actual == ExpectedLegal(from, to, resume),
                     "illegal verdict for " + Triple(from, to, resume));
        if (ExpectedTerminal(from)) {
          DF_CHECK_MSG(!actual, "a terminal phase accepted a transition: " +
                                    Triple(from, to, resume));
        }
        if (from == to) {
          DF_CHECK_MSG(!actual, "a phase transitioned to itself: " + Triple(from, to, resume));
        }
        if (from == Phase::unknown) {
          DF_CHECK_MSG(!actual, "the unknown phase accepted a transition: " +
                                    Triple(from, to, resume));
        }
      }
    }
  }
}

DF_TEST(Lifecycle_EveryStaticEdgeIsHonoured) {
  DF_CHECK_EQ(kLifecycleTransitions.size(), static_cast<std::size_t>(17));
  for (const TransitionRule& rule : kLifecycleTransitions) {
    DF_CHECK_MSG(IsLegalTransition(rule.from, rule.to, Phase::unknown),
                 "static edge was refused: " + std::string(ToString(rule.from)) + " -> " +
                     std::string(ToString(rule.to)));
  }
  // Exactly the table: no static edge exists that the table does not carry.
  for (const Phase from : kPhaseOrder) {
    for (const Phase to : kPhaseOrder) {
      if (from == to || ExpectedTerminal(from) || from == Phase::unknown ||
          to == Phase::blocked || to == Phase::failed || to == Phase::cancelled) {
        continue;
      }
      if (from == Phase::blocked) {
        continue;
      }
      DF_CHECK_EQ(IsLegalTransition(from, to, Phase::unknown), StaticEdgeExists(from, to));
    }
  }
}

DF_TEST(Lifecycle_RegressionEdgesAreLegal) {
  DF_CHECK(IsLegalTransition(Phase::draining, Phase::drain_required, Phase::unknown));
  DF_CHECK(IsLegalTransition(Phase::authority_revocation, Phase::drain_required, Phase::unknown));
  DF_CHECK(IsLegalTransition(Phase::residual_handling, Phase::drain_required, Phase::unknown));
  DF_CHECK(IsLegalTransition(Phase::isolation_ready, Phase::drain_required, Phase::unknown));
  DF_CHECK(IsLegalTransition(Phase::removed_observed, Phase::removal_authorized, Phase::unknown));

  // A regression is a real edge in the table, not a special case in the
  // predicate: removing it from the table would make it illegal.
  DF_CHECK(StaticEdgeExists(Phase::draining, Phase::drain_required));
  DF_CHECK(StaticEdgeExists(Phase::authority_revocation, Phase::drain_required));
  DF_CHECK(StaticEdgeExists(Phase::residual_handling, Phase::drain_required));
  DF_CHECK(StaticEdgeExists(Phase::isolation_ready, Phase::drain_required));
  DF_CHECK(StaticEdgeExists(Phase::removed_observed, Phase::removal_authorized));

  // The forward path never regresses by accident.
  DF_CHECK(!IsLegalTransition(Phase::draining, Phase::isolation_ready, Phase::unknown));
  DF_CHECK(!IsLegalTransition(Phase::drain_required, Phase::authority_revocation, Phase::unknown));
}

// ---------------------------------------------------------------------------
// Blocked is a first-class phase
// ---------------------------------------------------------------------------

DF_TEST(Lifecycle_AnyActionablePhaseMayEnterBlocked) {
  for (const Phase from : kPhaseOrder) {
    const bool expected = ExpectedActionable(from);
    DF_CHECK_MSG(IsLegalTransition(from, Phase::blocked, Phase::unknown) == expected,
                 "blocked entry disagreed for " + std::string(ToString(from)));
  }
  for (const Phase from : kExpectedActionable) {
    DF_CHECK(IsLegalTransition(from, Phase::blocked, Phase::unknown));
  }
  DF_CHECK(!IsLegalTransition(Phase::commissioned, Phase::blocked, Phase::unknown));
  DF_CHECK(!IsLegalTransition(Phase::blocked, Phase::blocked, Phase::unknown));
  DF_CHECK(!IsLegalTransition(Phase::unknown, Phase::blocked, Phase::unknown));
  DF_CHECK(!IsLegalTransition(Phase::failed, Phase::blocked, Phase::unknown));
}

DF_TEST(Lifecycle_LeavingBlockedIsLegalOnlyTowardsResumeFailedOrCancelled) {
  for (const Phase resume : kPhaseOrder) {
    for (const Phase to : kPhaseOrder) {
      const bool relevant =
          to == resume || to == Phase::failed || to == Phase::cancelled;
      if (!relevant) {
        DF_CHECK_MSG(!IsLegalTransition(Phase::blocked, to, resume),
                     "blocked escaped to an unrelated phase: " + Triple(Phase::blocked, to, resume));
      }
    }
    if (ExpectedActionable(resume)) {
      DF_CHECK_EQ(IsLegalTransition(Phase::blocked, resume, resume), true);
      DF_CHECK_EQ(IsLegalTransition(Phase::blocked, Phase::failed, resume), true);
      DF_CHECK_EQ(IsLegalTransition(Phase::blocked, Phase::cancelled, resume),
                  ExpectedCancellable(resume));
    } else {
      for (const Phase to : kPhaseOrder) {
        DF_CHECK_MSG(!IsLegalTransition(Phase::blocked, to, resume),
                     "blocked left a non-actionable resume phase: " +
                         Triple(Phase::blocked, to, resume));
      }
    }
  }
  // An actionable but non-cancellable resume phase still refuses cancellation.
  DF_CHECK(!IsLegalTransition(Phase::blocked, Phase::cancelled, Phase::removal_authorized));
  DF_CHECK(!IsLegalTransition(Phase::blocked, Phase::cancelled, Phase::removed_observed));
  DF_CHECK(IsLegalTransition(Phase::blocked, Phase::cancelled, Phase::residual_handling));
  DF_CHECK(IsLegalTransition(Phase::blocked, Phase::failed, Phase::drain_required));
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

DF_TEST(Lifecycle_CancellationIsLegalExactlyBeforeRemovalAuthorization) {
  for (const Phase from : kPhaseOrder) {
    DF_CHECK_MSG(IsLegalTransition(from, Phase::cancelled, Phase::unknown) ==
                     ExpectedCancellable(from),
                 "cancellation verdict disagreed for " + std::string(ToString(from)));
  }
  for (const Phase from : kExpectedCancellable) {
    DF_CHECK(IsLegalTransition(from, Phase::cancelled, Phase::unknown));
  }
  DF_CHECK(!IsLegalTransition(Phase::removal_authorized, Phase::cancelled, Phase::unknown));
  DF_CHECK(!IsLegalTransition(Phase::removed_observed, Phase::cancelled, Phase::unknown));
  DF_CHECK(!IsLegalTransition(Phase::decommissioned, Phase::cancelled, Phase::unknown));
  DF_CHECK(!IsLegalTransition(Phase::commissioned, Phase::cancelled, Phase::unknown));
  DF_CHECK(!IsLegalTransition(Phase::failed, Phase::cancelled, Phase::unknown));
  DF_CHECK(!IsLegalTransition(Phase::cancelled, Phase::cancelled, Phase::unknown));
}

// ---------------------------------------------------------------------------
// Terminal predicates
// ---------------------------------------------------------------------------

DF_TEST(Lifecycle_TerminalAndRetirementCompletePredicates) {
  for (const Phase phase : kPhaseOrder) {
    DF_CHECK_MSG(IsTerminal(phase) == ExpectedTerminal(phase),
                 "IsTerminal disagreed for " + std::string(ToString(phase)));
    DF_CHECK_MSG(IsRetirementComplete(phase) == (phase == Phase::decommissioned),
                 "IsRetirementComplete disagreed for " + std::string(ToString(phase)));
  }
  DF_CHECK(IsTerminal(Phase::decommissioned));
  DF_CHECK(IsTerminal(Phase::failed));
  DF_CHECK(IsTerminal(Phase::cancelled));
  DF_CHECK(!IsTerminal(Phase::removed_observed));
  DF_CHECK(!IsTerminal(Phase::isolation_ready));

  DF_CHECK(IsRetirementComplete(Phase::decommissioned));
  DF_CHECK(!IsRetirementComplete(Phase::removed_observed));
  DF_CHECK(!IsRetirementComplete(Phase::failed));
  DF_CHECK(!IsRetirementComplete(Phase::cancelled));
}

// ---------------------------------------------------------------------------
// Blocker rendering
// ---------------------------------------------------------------------------

DF_TEST(Lifecycle_BlockerToString_NamesReasonDetailActionAndObservations) {
  Blocker blocker;
  blocker.reason = BlockerReason::drain_outstanding;
  blocker.code = ErrorCode::unmet_obligation;
  blocker.observed_phase = Phase::draining;
  blocker.blocked_at = Phase::drain_required;
  blocker.detail = "obligation is still outstanding";
  blocker.observed.push_back(ErrorDetail{"obligation", "0000000000000005"});
  blocker.observed.push_back(ErrorDetail{"state", "outstanding"});
  blocker.observed.push_back(ErrorDetail{"issued_to", "cooling-owner"});
  blocker.required_action = "record external drain satisfaction evidence";

  DF_CHECK(blocker.is_set());
  const std::string text = blocker.to_string();
  DF_CHECK_MSG(text.find(std::string(ToString(blocker.reason))) != std::string::npos,
               "blocker rendering omits the reason name");
  DF_CHECK_MSG(text.find(blocker.detail) != std::string::npos,
               "blocker rendering omits the detail");
  DF_CHECK_MSG(text.find(blocker.required_action) != std::string::npos,
               "blocker rendering omits the required action");
  for (const ErrorDetail& observed : blocker.observed) {
    DF_CHECK_MSG(text.find(observed.key) != std::string::npos,
                 "blocker rendering omits an observed key: " + observed.key);
    DF_CHECK_MSG(text.find(observed.key + "=" + observed.value) != std::string::npos,
                 "blocker rendering omits an observed value: " + observed.key);
  }
  DF_CHECK_EQ(blocker.to_string(), text);
}

DF_TEST(Lifecycle_BlockerToString_RendersAnUnsetBlocker) {
  const Blocker unset;
  DF_CHECK(!unset.is_set());
  DF_CHECK_EQ(std::string(ToString(unset.reason)), std::string("none"));
  const std::string text = unset.to_string();
  DF_CHECK(text.find("none") != std::string::npos);
  DF_CHECK_EQ(text, std::string("blocked[none]: "));
}

}  // namespace

DF_TEST_MAIN()

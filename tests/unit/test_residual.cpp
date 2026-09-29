// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// residual.hpp and obligations.hpp proof obligations.
//
// Residual disposition and drain state are the two places where a claim can be
// recorded without being true, so these tests pin the predicates that decide
// whether a claim closes a checklist or blocks progress, and the names that make
// those verdicts auditable.

#include "decommissioning_fabric/residual.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "decommissioning_fabric/obligations.hpp"
#include "harness.hpp"

namespace {

using namespace decommissioning_fabric;

/// Every discrete disposition, written out so the expectation does not come
/// from the implementation under test.
struct DispositionExpectation {
  ResidualDisposition disposition;
  bool closes_checklist;
  bool unresolved;
};

constexpr std::array<DispositionExpectation, 5> kDispositionExpectations = {
    DispositionExpectation{ResidualDisposition::unknown, false, true},
    DispositionExpectation{ResidualDisposition::pending, false, true},
    DispositionExpectation{ResidualDisposition::handled, true, false},
    DispositionExpectation{ResidualDisposition::not_applicable, true, false},
    DispositionExpectation{ResidualDisposition::waived, false, false}};

constexpr std::array<ResidualDisposition, 5> kAllDispositions = {
    ResidualDisposition::unknown, ResidualDisposition::pending, ResidualDisposition::handled,
    ResidualDisposition::not_applicable, ResidualDisposition::waived};

constexpr std::array<ObligationState, 6> kAllObligationStates = {
    ObligationState::unknown, ObligationState::outstanding, ObligationState::acknowledged,
    ObligationState::satisfied, ObligationState::waived, ObligationState::failed};

struct StateExpectation {
  ObligationState state;
  bool open;
  bool resolved;
};

constexpr std::array<StateExpectation, 6> kStateExpectations = {
    StateExpectation{ObligationState::unknown, true, false},
    StateExpectation{ObligationState::outstanding, true, false},
    StateExpectation{ObligationState::acknowledged, true, false},
    StateExpectation{ObligationState::satisfied, false, true},
    StateExpectation{ObligationState::waived, false, true},
    StateExpectation{ObligationState::failed, false, false}};

// ---------------------------------------------------------------------------
// Residual categories and dispositions
// ---------------------------------------------------------------------------

DF_TEST(Residual_EveryCategoryHasADistinctNameThatRoundTrips) {
  DF_CHECK_EQ(kResidualCategoryCount, static_cast<std::size_t>(9));
  for (std::size_t i = 0; i < kResidualCategoryCount; ++i) {
    const ResidualCategory category = kResidualCategoryOrder[i];
    DF_CHECK_EQ(static_cast<std::uint32_t>(category), static_cast<std::uint32_t>(i));
    const std::string_view name = ToString(category);
    DF_CHECK_MSG(!name.empty(), "residual category name is empty");
    DF_CHECK_EQ(ResidualCategoryFromString(name), category);
    for (std::size_t j = i + 1U; j < kResidualCategoryCount; ++j) {
      DF_CHECK_NE(name, ToString(kResidualCategoryOrder[j]));
    }
  }
  DF_CHECK_EQ(ResidualCategoryFromString("bogus"), ResidualCategory::unknown);
  DF_CHECK_EQ(ResidualCategoryFromString(""), ResidualCategory::unknown);
  DF_CHECK_EQ(ResidualCategoryFromString("Persistent_Media"), ResidualCategory::unknown);
  DF_CHECK_EQ(ResidualCategoryFromString("persistent-media"), ResidualCategory::unknown);
  DF_CHECK_EQ(ResidualCategoryFromString("persistent_media "), ResidualCategory::unknown);
  DF_CHECK_EQ(ResidualCategoryFromString("unknown"), ResidualCategory::unknown);
  DF_CHECK_NE(ResidualCategoryFromString("persistent_media"), ResidualCategory::unknown);
}

DF_TEST(Residual_EveryDispositionHasADistinctNameThatRoundTrips) {
  for (std::size_t i = 0; i < kAllDispositions.size(); ++i) {
    const std::string_view name = ToString(kAllDispositions[i]);
    DF_CHECK_MSG(!name.empty(), "residual disposition name is empty");
    DF_CHECK_EQ(ResidualDispositionFromString(name), kAllDispositions[i]);
    for (std::size_t j = i + 1U; j < kAllDispositions.size(); ++j) {
      DF_CHECK_NE(name, ToString(kAllDispositions[j]));
    }
  }
  DF_CHECK_EQ(ResidualDispositionFromString("bogus"), ResidualDisposition::unknown);
  DF_CHECK_EQ(ResidualDispositionFromString(""), ResidualDisposition::unknown);
  DF_CHECK_EQ(ResidualDispositionFromString("Handled"), ResidualDisposition::unknown);
  DF_CHECK_EQ(ResidualDispositionFromString("not-applicable"), ResidualDisposition::unknown);
  DF_CHECK_EQ(ResidualDispositionFromString("unknown"), ResidualDisposition::unknown);
  DF_CHECK_NE(ResidualDispositionFromString("not_applicable"), ResidualDisposition::unknown);
}

DF_TEST(Residual_ChecklistClosureAndUnresolvedPredicatesAreExhaustive) {
  for (const DispositionExpectation& expected : kDispositionExpectations) {
    const std::string label(ToString(expected.disposition));
    DF_CHECK_MSG(ClosesResidualChecklist(expected.disposition) == expected.closes_checklist,
                 "ClosesResidualChecklist disagreed for " + label);
    DF_CHECK_MSG(IsUnresolvedResidual(expected.disposition) == expected.unresolved,
                 "IsUnresolvedResidual disagreed for " + label);
    // A waived item neither closes the checklist nor counts as unresolved: its
    // exception is what must resolve.
    if (expected.disposition == ResidualDisposition::waived) {
      DF_CHECK(!ClosesResidualChecklist(expected.disposition));
      DF_CHECK(!IsUnresolvedResidual(expected.disposition));
    }
  }
  DF_CHECK(ClosesResidualChecklist(ResidualDisposition::handled));
  DF_CHECK(ClosesResidualChecklist(ResidualDisposition::not_applicable));
  DF_CHECK(!ClosesResidualChecklist(ResidualDisposition::pending));
  DF_CHECK(!ClosesResidualChecklist(ResidualDisposition::unknown));
  DF_CHECK(!ClosesResidualChecklist(ResidualDisposition::waived));
  DF_CHECK(IsUnresolvedResidual(ResidualDisposition::unknown));
  DF_CHECK(IsUnresolvedResidual(ResidualDisposition::pending));
  DF_CHECK(!IsUnresolvedResidual(ResidualDisposition::handled));
  DF_CHECK(!IsUnresolvedResidual(ResidualDisposition::not_applicable));
}

// ---------------------------------------------------------------------------
// Drain kinds and protected service classes
// ---------------------------------------------------------------------------

DF_TEST(Obligations_EveryDrainKindHasADistinctNameThatRoundTrips) {
  DF_CHECK_EQ(kDrainKindCount, static_cast<std::size_t>(9));
  for (std::size_t i = 0; i < kDrainKindCount; ++i) {
    const DrainKind kind = kDrainKindOrder[i];
    DF_CHECK_EQ(static_cast<std::uint32_t>(kind), static_cast<std::uint32_t>(i));
    const std::string_view name = ToString(kind);
    DF_CHECK_MSG(!name.empty(), "drain kind name is empty");
    DF_CHECK_EQ(DrainKindFromString(name), kind);
    for (std::size_t j = i + 1U; j < kDrainKindCount; ++j) {
      DF_CHECK_NE(name, ToString(kDrainKindOrder[j]));
    }
  }
  DF_CHECK_EQ(DrainKindFromString("bogus"), DrainKind::unknown);
  DF_CHECK_EQ(DrainKindFromString(""), DrainKind::unknown);
  DF_CHECK_EQ(DrainKindFromString("ASI_WORKLOAD"), DrainKind::unknown);
  DF_CHECK_EQ(DrainKindFromString("asi-workload"), DrainKind::unknown);
  DF_CHECK_EQ(DrainKindFromString("asi_workload "), DrainKind::unknown);
  DF_CHECK_EQ(DrainKindFromString("unknown"), DrainKind::unknown);
  DF_CHECK_NE(DrainKindFromString("protected_service"), DrainKind::unknown);
}

DF_TEST(Obligations_EveryProtectedServiceClassHasADistinctNameThatRoundTrips) {
  DF_CHECK_EQ(kProtectedServiceClassCount, static_cast<std::size_t>(6));
  for (std::size_t i = 0; i < kProtectedServiceClassCount; ++i) {
    const ProtectedServiceClass service = kProtectedServiceClassOrder[i];
    DF_CHECK_EQ(static_cast<std::uint32_t>(service), static_cast<std::uint32_t>(i));
    const std::string_view name = ToString(service);
    DF_CHECK_MSG(!name.empty(), "protected service class name is empty");
    DF_CHECK_EQ(ProtectedServiceClassFromString(name), service);
    for (std::size_t j = i + 1U; j < kProtectedServiceClassCount; ++j) {
      DF_CHECK_NE(name, ToString(kProtectedServiceClassOrder[j]));
    }
  }
  // The unrecognised answer is the none sentinel, which is also a legal name.
  DF_CHECK_EQ(ProtectedServiceClassFromString("bogus"), ProtectedServiceClass::none);
  DF_CHECK_EQ(ProtectedServiceClassFromString(""), ProtectedServiceClass::none);
  DF_CHECK_EQ(ProtectedServiceClassFromString("Safety"), ProtectedServiceClass::none);
  DF_CHECK_EQ(ProtectedServiceClassFromString("control-plane"), ProtectedServiceClass::none);
  DF_CHECK_EQ(ProtectedServiceClassFromString("none"), ProtectedServiceClass::none);
  DF_CHECK_NE(ProtectedServiceClassFromString("data_integrity"), ProtectedServiceClass::none);
}

// ---------------------------------------------------------------------------
// Obligation state names
// ---------------------------------------------------------------------------

DF_TEST(Obligations_EveryStateNameRoundTrips) {
  for (std::size_t i = 0; i < kAllObligationStates.size(); ++i) {
    const ObligationState state = kAllObligationStates[i];
    DF_CHECK_EQ(static_cast<std::uint32_t>(state), static_cast<std::uint32_t>(i));
    const std::string_view name = ToString(state);
    DF_CHECK_MSG(!name.empty(), "obligation state name is empty");
    DF_CHECK_EQ(ObligationStateFromString(name), state);
    for (std::size_t j = i + 1U; j < kAllObligationStates.size(); ++j) {
      DF_CHECK_NE(name, ToString(kAllObligationStates[j]));
    }
  }
  DF_CHECK_EQ(ObligationStateFromString("bogus"), ObligationState::unknown);
  DF_CHECK_EQ(ObligationStateFromString(""), ObligationState::unknown);
  DF_CHECK_EQ(ObligationStateFromString("Outstanding"), ObligationState::unknown);
  DF_CHECK_EQ(ObligationStateFromString("satisfied "), ObligationState::unknown);
  DF_CHECK_EQ(ObligationStateFromString("unknown"), ObligationState::unknown);
  DF_CHECK_NE(ObligationStateFromString("failed"), ObligationState::unknown);
}

// ---------------------------------------------------------------------------
// DrainObligation predicates
// ---------------------------------------------------------------------------

DF_TEST(Obligations_OpenAndResolvedAreExhaustiveOverEveryState) {
  for (const StateExpectation& expected : kStateExpectations) {
    const std::string label(ToString(expected.state));
    DrainObligation obligation;
    obligation.kind = DrainKind::asi_workload;
    obligation.state = expected.state;
    obligation.required = true;
    DF_CHECK_MSG(obligation.is_open() == expected.open, "is_open disagreed for " + label);
    DF_CHECK_MSG(obligation.is_resolved() == expected.resolved,
                 "is_resolved disagreed for " + label);
    DF_CHECK_MSG(obligation.blocks_progress() == !expected.resolved,
                 "blocks_progress disagreed for a required obligation in state " + label);
    // Only a failed obligation is neither open nor resolved.
    DF_CHECK_MSG(obligation.is_open() || obligation.is_resolved() ||
                     expected.state == ObligationState::failed,
                 "state is neither open nor resolved: " + label);

    obligation.required = false;
    DF_CHECK_MSG(!obligation.blocks_progress(),
                 "a non-required obligation blocked progress in state " + label);
  }
}

DF_TEST(Obligations_BlocksProgressRequiresRequiredAndUnresolved) {
  for (const ObligationState state : kAllObligationStates) {
    for (int required = 0; required < 2; ++required) {
      DrainObligation obligation;
      obligation.state = state;
      obligation.required = required != 0;
      const bool resolved =
          state == ObligationState::satisfied || state == ObligationState::waived;
      DF_CHECK_EQ(obligation.blocks_progress(), obligation.required && !resolved);
    }
  }
  DrainObligation blocking;
  blocking.state = ObligationState::acknowledged;
  blocking.required = true;
  DF_CHECK(blocking.blocks_progress());
  // Acknowledgement is metadata and never satisfies: resolving it clears the
  // block, acknowledging it does not.
  blocking.state = ObligationState::satisfied;
  DF_CHECK(!blocking.blocks_progress());
  blocking.state = ObligationState::waived;
  DF_CHECK(!blocking.blocks_progress());
  blocking.state = ObligationState::failed;
  DF_CHECK(blocking.blocks_progress());
}

DF_TEST(Obligations_IsProtectedIsExhaustiveOverKindsAndClasses) {
  for (const DrainKind kind : kDrainKindOrder) {
    for (const ProtectedServiceClass service : kProtectedServiceClassOrder) {
      DrainObligation obligation;
      obligation.kind = kind;
      obligation.protected_class = service;
      const bool expected =
          kind == DrainKind::protected_service || service != ProtectedServiceClass::none;
      DF_CHECK_MSG(obligation.is_protected() == expected,
                   "is_protected disagreed for kind " + std::string(ToString(kind)) +
                       " and class " + std::string(ToString(service)));
    }
  }
  DrainObligation kind_only;
  kind_only.kind = DrainKind::protected_service;
  DF_CHECK(kind_only.is_protected());
  DF_CHECK_EQ(kind_only.protected_class, ProtectedServiceClass::none);

  DrainObligation class_only;
  class_only.kind = DrainKind::external_dependency;
  class_only.protected_class = ProtectedServiceClass::safety;
  DF_CHECK(class_only.is_protected());

  DrainObligation ordinary;
  ordinary.kind = DrainKind::dfi_route;
  ordinary.protected_class = ProtectedServiceClass::none;
  DF_CHECK(!ordinary.is_protected());
}

DF_TEST(Obligations_IsWaivableRefusesEveryProtectedForm) {
  DrainObligation ordinary;
  ordinary.kind = DrainKind::asi_workload;
  ordinary.protected_class = ProtectedServiceClass::none;
  DF_CHECK(!ordinary.is_protected());
  DF_CHECK(IsWaivable(ordinary));

  DrainObligation protected_kind;
  protected_kind.kind = DrainKind::protected_service;
  protected_kind.protected_class = ProtectedServiceClass::none;
  DF_CHECK(!IsWaivable(protected_kind));

  DrainObligation protected_class;
  protected_class.kind = DrainKind::power_dependency;
  protected_class.protected_class = ProtectedServiceClass::regulatory;
  DF_CHECK(!IsWaivable(protected_class));

  DrainObligation both;
  both.kind = DrainKind::protected_service;
  both.protected_class = ProtectedServiceClass::data_integrity;
  DF_CHECK(!IsWaivable(both));

  // Waivability is exactly the negation of protection for every combination.
  for (const DrainKind kind : kDrainKindOrder) {
    for (const ProtectedServiceClass service : kProtectedServiceClassOrder) {
      DrainObligation obligation;
      obligation.kind = kind;
      obligation.protected_class = service;
      DF_CHECK_EQ(IsWaivable(obligation), !obligation.is_protected());
    }
  }
}

// ---------------------------------------------------------------------------
// ResidualItem shape
// ---------------------------------------------------------------------------

DF_TEST(Residual_WaivedItemCarriesAnExceptionAndClosesNothing) {
  ResidualItem item;
  item.id = ResidualItemId::FromValue(1U);
  item.category = ResidualCategory::credential_reference;
  item.disposition = ResidualDisposition::waived;
  item.observed_sequence = ObservationSequence::FromValue(7U);
  item.recorded_at = Timestamp{1767225600000000000LL};
  item.detail = "key reference outlives the asset";
  item.authority = "security-board";
  item.reference = "SEC-7";
  DF_CHECK(item.waiver.is_unset());
  DF_CHECK(!IsUnresolvedResidual(item.disposition));
  DF_CHECK(!ClosesResidualChecklist(item.disposition));

  item.waiver = ExceptionId::FromValue(2U);
  DF_CHECK_EQ(item.waiver.value(), 2ULL);
  DF_CHECK(item.waiver.is_set());
}

}  // namespace

DF_TEST_MAIN()

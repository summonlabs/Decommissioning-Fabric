// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Residual state and policy exceptions.
//
// Residual state is everything an asset leaves behind that this runtime does NOT
// own the removal of: workload and state residue, persistent media, credential
// and key references, network identity, reservations, monitoring and alerting
// bindings, and facility references. The runtime records a disposition and who
// reported it. It never claims that media was erased or that a key was destroyed.
//
// Unknown residual state blocks final closure. It can only be passed by an
// attributed, audited policy exception.

#ifndef DECOMMISSIONING_FABRIC_RESIDUAL_HPP
#define DECOMMISSIONING_FABRIC_RESIDUAL_HPP

#include <cstdint>
#include <string>
#include <string_view>

#include "decommissioning_fabric/hash.hpp"
#include "decommissioning_fabric/ids.hpp"
#include "decommissioning_fabric/time.hpp"

namespace decommissioning_fabric {

enum class ResidualCategory : std::uint32_t {
  unknown = 0,
  workload_state = 1,
  persistent_media = 2,
  credential_reference = 3,
  network_identity = 4,
  reservation = 5,
  monitoring_binding = 6,
  facility_reference = 7,
  physical_asset = 8,
};

inline constexpr std::size_t kResidualCategoryCount = 9;

/// Fixed order: every checklist is rendered in this order regardless of the
/// order in which items were discovered.
inline constexpr ResidualCategory kResidualCategoryOrder[kResidualCategoryCount] = {
    ResidualCategory::unknown,       ResidualCategory::workload_state,
    ResidualCategory::persistent_media, ResidualCategory::credential_reference,
    ResidualCategory::network_identity, ResidualCategory::reservation,
    ResidualCategory::monitoring_binding, ResidualCategory::facility_reference,
    ResidualCategory::physical_asset};

[[nodiscard]] constexpr std::string_view ToString(ResidualCategory category) noexcept {
  switch (category) {
    case ResidualCategory::unknown: return "unknown";
    case ResidualCategory::workload_state: return "workload_state";
    case ResidualCategory::persistent_media: return "persistent_media";
    case ResidualCategory::credential_reference: return "credential_reference";
    case ResidualCategory::network_identity: return "network_identity";
    case ResidualCategory::reservation: return "reservation";
    case ResidualCategory::monitoring_binding: return "monitoring_binding";
    case ResidualCategory::facility_reference: return "facility_reference";
    case ResidualCategory::physical_asset: return "physical_asset";
  }
  return "unknown";
}

[[nodiscard]] ResidualCategory ResidualCategoryFromString(std::string_view name) noexcept;

enum class ResidualDisposition : std::uint32_t {
  unknown = 0,
  pending = 1,
  handled = 2,
  not_applicable = 3,
  waived = 4,
};

[[nodiscard]] constexpr std::string_view ToString(ResidualDisposition disposition) noexcept {
  switch (disposition) {
    case ResidualDisposition::unknown: return "unknown";
    case ResidualDisposition::pending: return "pending";
    case ResidualDisposition::handled: return "handled";
    case ResidualDisposition::not_applicable: return "not_applicable";
    case ResidualDisposition::waived: return "waived";
  }
  return "unknown";
}

[[nodiscard]] ResidualDisposition ResidualDispositionFromString(std::string_view name) noexcept;

struct ResidualItem {
  ResidualItemId id;
  ResidualCategory category{ResidualCategory::unknown};
  ResidualDisposition disposition{ResidualDisposition::unknown};

  ObservationSequence observed_sequence;
  Timestamp recorded_at;

  std::string detail;

  /// The external authority that reported or decided the disposition. Required
  /// to be non-empty for handled, not_applicable and waived dispositions.
  std::string authority;
  std::string reference;

  /// Set when disposition == waived. The exception is what makes the waiver
  /// attributable and auditable.
  ExceptionId waiver;

  friend bool operator==(const ResidualItem&, const ResidualItem&) = default;
};

/// True when the item's disposition is sufficient on its own to close the
/// checklist. A waived item still requires its exception to resolve, and an
/// unknown or pending item always blocks.
[[nodiscard]] constexpr bool ClosesResidualChecklist(ResidualDisposition disposition) noexcept {
  return disposition == ResidualDisposition::handled ||
         disposition == ResidualDisposition::not_applicable;
}

/// A disposition that has been asserted but cannot be accepted yet.
[[nodiscard]] constexpr bool IsUnresolvedResidual(ResidualDisposition disposition) noexcept {
  return disposition == ResidualDisposition::unknown ||
         disposition == ResidualDisposition::pending;
}

/// An attributed, audited departure from facility policy. Every field is
/// required: an exception with an empty authority, reference, or rationale is
/// rejected rather than recorded, because an unattributable exception is exactly
/// the thing that makes a decommissioning decision unauditable.
struct PolicyException {
  ExceptionId id;

  /// The residual item this exception passes, if any.
  ResidualItemId item;

  /// The obligation this exception passes, if any.
  ObligationId obligation;

  /// The plan and generation binding the exception was granted under. An
  /// exception granted against a superseded binding does not carry forward.
  PlanId plan;
  Revision revision;
  Digest binding_digest;
  PolicyGeneration policy_generation;

  std::string authority;
  std::string reference;
  std::string rationale;

  Timestamp recorded_at;
  IncarnationId recorded_by;

  friend bool operator==(const PolicyException&, const PolicyException&) = default;
};

}  // namespace decommissioning_fabric

#endif  // DECOMMISSIONING_FABRIC_RESIDUAL_HPP

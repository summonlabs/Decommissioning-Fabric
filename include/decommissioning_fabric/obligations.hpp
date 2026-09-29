// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Drain and dependency obligations.
//
// An obligation is a typed request to an authority this runtime does not own:
// ASI, DFI, a tenant, power, cooling, a maintenance window, or a protected
// service class. Creating one is a REQUEST. Acknowledging one is METADATA. Only
// attributable external evidence with the matching kind and a strictly later
// observation sequence satisfies one.

#ifndef DECOMMISSIONING_FABRIC_OBLIGATIONS_HPP
#define DECOMMISSIONING_FABRIC_OBLIGATIONS_HPP

#include <cstdint>
#include <string>
#include <string_view>

#include "decommissioning_fabric/ids.hpp"
#include "decommissioning_fabric/time.hpp"

namespace decommissioning_fabric {

enum class DrainKind : std::uint32_t {
  unknown = 0,
  asi_workload = 1,
  dfi_route = 2,
  tenant_service = 3,
  power_dependency = 4,
  cooling_dependency = 5,
  maintenance_window = 6,
  protected_service = 7,
  external_dependency = 8,
};

inline constexpr std::size_t kDrainKindCount = 9;

inline constexpr DrainKind kDrainKindOrder[kDrainKindCount] = {
    DrainKind::unknown,       DrainKind::asi_workload,
    DrainKind::dfi_route,     DrainKind::tenant_service,
    DrainKind::power_dependency, DrainKind::cooling_dependency,
    DrainKind::maintenance_window, DrainKind::protected_service,
    DrainKind::external_dependency};

[[nodiscard]] constexpr std::string_view ToString(DrainKind kind) noexcept {
  switch (kind) {
    case DrainKind::unknown: return "unknown";
    case DrainKind::asi_workload: return "asi_workload";
    case DrainKind::dfi_route: return "dfi_route";
    case DrainKind::tenant_service: return "tenant_service";
    case DrainKind::power_dependency: return "power_dependency";
    case DrainKind::cooling_dependency: return "cooling_dependency";
    case DrainKind::maintenance_window: return "maintenance_window";
    case DrainKind::protected_service: return "protected_service";
    case DrainKind::external_dependency: return "external_dependency";
  }
  return "unknown";
}

[[nodiscard]] DrainKind DrainKindFromString(std::string_view name) noexcept;

/// Service classes that policy protects. A protected obligation can never be
/// waived; it must be satisfied by external evidence or the retirement fails.
enum class ProtectedServiceClass : std::uint32_t {
  none = 0,
  safety = 1,
  regulatory = 2,
  revenue = 3,
  control_plane = 4,
  data_integrity = 5,
};

inline constexpr std::size_t kProtectedServiceClassCount = 6;

inline constexpr ProtectedServiceClass kProtectedServiceClassOrder[kProtectedServiceClassCount] = {
    ProtectedServiceClass::none,          ProtectedServiceClass::safety,
    ProtectedServiceClass::regulatory,    ProtectedServiceClass::revenue,
    ProtectedServiceClass::control_plane, ProtectedServiceClass::data_integrity};

[[nodiscard]] constexpr std::string_view ToString(ProtectedServiceClass service) noexcept {
  switch (service) {
    case ProtectedServiceClass::none: return "none";
    case ProtectedServiceClass::safety: return "safety";
    case ProtectedServiceClass::regulatory: return "regulatory";
    case ProtectedServiceClass::revenue: return "revenue";
    case ProtectedServiceClass::control_plane: return "control_plane";
    case ProtectedServiceClass::data_integrity: return "data_integrity";
  }
  return "none";
}

[[nodiscard]] ProtectedServiceClass ProtectedServiceClassFromString(std::string_view name) noexcept;

enum class ObligationState : std::uint32_t {
  unknown = 0,
  outstanding = 1,
  acknowledged = 2,
  satisfied = 3,
  waived = 4,
  failed = 5,
};

[[nodiscard]] constexpr std::string_view ToString(ObligationState state) noexcept {
  switch (state) {
    case ObligationState::unknown: return "unknown";
    case ObligationState::outstanding: return "outstanding";
    case ObligationState::acknowledged: return "acknowledged";
    case ObligationState::satisfied: return "satisfied";
    case ObligationState::waived: return "waived";
    case ObligationState::failed: return "failed";
  }
  return "unknown";
}

[[nodiscard]] ObligationState ObligationStateFromString(std::string_view name) noexcept;

struct DrainObligation {
  ObligationId id;
  DrainKind kind{DrainKind::unknown};

  /// The asset or downstream asset the drain concerns. For facility dependencies
  /// this is the asset being retired; for tenant services it may be another asset
  /// whose drain must complete first.
  AssetId target;

  ProtectedServiceClass protected_class{ProtectedServiceClass::none};

  /// A required obligation blocks progression while unresolved. A non-required
  /// obligation is recorded and reported but does not gate a phase change.
  bool required{true};

  ObligationState state{ObligationState::unknown};

  ObservationSequence issued_sequence;
  Timestamp issued_at;

  /// The external authority asked to perform the drain. Non-empty.
  std::string issued_to;

  std::string detail;

  // --- acknowledgement: metadata only, never satisfies --------------------
  ObservationSequence acknowledged_sequence;
  Timestamp acknowledged_at;
  std::string acknowledged_by;

  // --- satisfaction -------------------------------------------------------
  EvidenceId satisfaction_evidence;
  ObservationSequence satisfied_sequence;
  Timestamp satisfied_at;
  std::string satisfied_by;

  // --- resolution without evidence ----------------------------------------
  /// Set when the obligation was waived. Waiving requires an attributed policy
  /// exception and is refused outright for protected obligations.
  ExceptionId waiver;

  /// Set when the obligation was recorded as failed (the drain cannot complete).
  std::string failure_reason;

  [[nodiscard]] bool is_open() const noexcept {
    return state == ObligationState::unknown || state == ObligationState::outstanding ||
           state == ObligationState::acknowledged;
  }
  [[nodiscard]] bool is_resolved() const noexcept {
    return state == ObligationState::satisfied || state == ObligationState::waived;
  }
  [[nodiscard]] bool blocks_progress() const noexcept { return required && !is_resolved(); }

  [[nodiscard]] bool is_protected() const noexcept {
    return kind == DrainKind::protected_service || protected_class != ProtectedServiceClass::none;
  }

  friend bool operator==(const DrainObligation&, const DrainObligation&) = default;
};

/// A protected obligation is never waivable, and neither is any obligation whose
/// kind is protected_service.
[[nodiscard]] bool IsWaivable(const DrainObligation& obligation) noexcept;

}  // namespace decommissioning_fabric

#endif  // DECOMMISSIONING_FABRIC_OBLIGATIONS_HPP

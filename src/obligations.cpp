// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0

#include "decommissioning_fabric/obligations.hpp"

namespace decommissioning_fabric {

DrainKind DrainKindFromString(std::string_view name) noexcept {
  for (const DrainKind kind : kDrainKindOrder) {
    if (ToString(kind) == name) {
      return kind;
    }
  }
  return DrainKind::unknown;
}

ProtectedServiceClass ProtectedServiceClassFromString(std::string_view name) noexcept {
  for (const ProtectedServiceClass service : kProtectedServiceClassOrder) {
    if (ToString(service) == name) {
      return service;
    }
  }
  return ProtectedServiceClass::none;
}

ObligationState ObligationStateFromString(std::string_view name) noexcept {
  if (name == "outstanding") {
    return ObligationState::outstanding;
  }
  if (name == "acknowledged") {
    return ObligationState::acknowledged;
  }
  if (name == "satisfied") {
    return ObligationState::satisfied;
  }
  if (name == "waived") {
    return ObligationState::waived;
  }
  if (name == "failed") {
    return ObligationState::failed;
  }
  return ObligationState::unknown;
}

bool IsWaivable(const DrainObligation& obligation) noexcept {
  return !obligation.is_protected();
}

}  // namespace decommissioning_fabric

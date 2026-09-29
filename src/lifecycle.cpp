// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0

#include "decommissioning_fabric/lifecycle.hpp"

namespace decommissioning_fabric {

Phase PhaseFromString(std::string_view name) noexcept {
  for (const Phase phase : kPhaseOrder) {
    if (ToString(phase) == name) {
      return phase;
    }
  }
  return Phase::unknown;
}

bool IsLegalTransition(Phase from, Phase to, Phase resume_phase) noexcept {
  if (from == to) {
    return false;
  }
  if (IsTerminal(from)) {
    return false;
  }
  if (from == Phase::unknown) {
    return false;
  }

  // Entering Blocked is legal from any actionable phase.
  if (to == Phase::blocked) {
    return IsActionable(from);
  }

  // Leaving Blocked is legal only towards the phase that was interrupted, plus
  // the two terminal escapes.
  if (from == Phase::blocked) {
    if (to == Phase::failed) {
      return IsActionable(resume_phase);
    }
    if (to == Phase::cancelled) {
      return IsCancellable(resume_phase);
    }
    return to == resume_phase && IsActionable(resume_phase);
  }

  if (to == Phase::failed) {
    return IsActionable(from);
  }
  if (to == Phase::cancelled) {
    return IsCancellable(from);
  }

  for (const TransitionRule& rule : kLifecycleTransitions) {
    if (rule.from == from && rule.to == to) {
      return true;
    }
  }
  return false;
}

std::string Blocker::to_string() const {
  std::string out;
  out += "blocked[";
  out += ToString(reason);
  out += "]: ";
  out += detail;
  if (!required_action.empty()) {
    out += " | required: ";
    out += required_action;
  }
  for (const ErrorDetail& detail_entry : observed) {
    out += ' ';
    out += detail_entry.key;
    out += '=';
    out += detail_entry.value;
  }
  return out;
}

}  // namespace decommissioning_fabric

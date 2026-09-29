// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0

#include "decommissioning_fabric/evidence.hpp"

namespace decommissioning_fabric {

bool IsAttributable(const EvidenceRef& evidence) noexcept {
  return !evidence.observer.empty() && !evidence.reference.empty() &&
         evidence.observation_sequence.is_set() &&
         evidence.provenance == EvidenceProvenance::external_authority;
}

}  // namespace decommissioning_fabric

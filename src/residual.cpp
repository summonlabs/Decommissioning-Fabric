// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0

#include "decommissioning_fabric/residual.hpp"

namespace decommissioning_fabric {

ResidualCategory ResidualCategoryFromString(std::string_view name) noexcept {
  for (const ResidualCategory category : kResidualCategoryOrder) {
    if (ToString(category) == name) {
      return category;
    }
  }
  return ResidualCategory::unknown;
}

ResidualDisposition ResidualDispositionFromString(std::string_view name) noexcept {
  if (name == "pending") {
    return ResidualDisposition::pending;
  }
  if (name == "handled") {
    return ResidualDisposition::handled;
  }
  if (name == "not_applicable") {
    return ResidualDisposition::not_applicable;
  }
  if (name == "waived") {
    return ResidualDisposition::waived;
  }
  return ResidualDisposition::unknown;
}

}  // namespace decommissioning_fabric

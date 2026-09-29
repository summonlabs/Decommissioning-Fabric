// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Build provenance for the Decommissioning Fabric runtime.
//
// The values below are substituted by CMake at configure time. They identify
// the exact source revision a binary was built from so that a running process
// can state its provenance instead of being taken on trust.

#ifndef DECOMMISSIONING_FABRIC_VERSION_HPP
#define DECOMMISSIONING_FABRIC_VERSION_HPP

#include <cstdint>
#include <string_view>

namespace decommissioning_fabric {

inline constexpr std::uint32_t kVersionMajor = 1;
inline constexpr std::uint32_t kVersionMinor = 0;
inline constexpr std::uint32_t kVersionPatch = 0;

inline constexpr std::string_view kVersionString = "1.0.0";

#if defined(DF_GIT_COMMIT)
inline constexpr std::string_view kBuildCommit = DF_GIT_COMMIT;
#else
inline constexpr std::string_view kBuildCommit = "unknown";
#endif

#if defined(DF_GIT_DIRTY)
inline constexpr std::string_view kBuildDirty = DF_GIT_DIRTY;
#else
inline constexpr std::string_view kBuildDirty = "unknown";
#endif

/// DCCP repository ordinal for this component.
inline constexpr std::uint32_t kRepositoryOrdinal = 34;
inline constexpr std::uint32_t kRepositoryTotal = 72;

/// Tranche 5 is the physical fleet lifecycle tranche of the DCCP programme.
inline constexpr std::string_view kTrancheName = "Tranche 5 - Physical Fleet Lifecycle";

/// Vendor-neutral implementation identity. This runtime transmits no telemetry
/// and holds no vendor coupling.
inline constexpr std::string_view kVendorNeutralStatement =
    "vendor-neutral; no telemetry transmission";

}  // namespace decommissioning_fabric

#endif  // DECOMMISSIONING_FABRIC_VERSION_HPP

// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Authority domains and revocation receipts.
//
// An asset is "live" only while it holds authority in some domain: ASI may still
// schedule onto it, DFI may still route to it, power may still feed it. Retirement
// revokes those domains. This runtime never performs a revocation; it records an
// external authority's receipt of one.
//
// Absence of an authority bit is NOT proof of revocation. A domain is revoked
// only when the bit is absent AND a receipt bound to the current generation
// binding covers it. Otherwise the domain is unknown, and unknown authority
// blocks final closure.

#ifndef DECOMMISSIONING_FABRIC_AUTHORITY_HPP
#define DECOMMISSIONING_FABRIC_AUTHORITY_HPP

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include "decommissioning_fabric/hash.hpp"
#include "decommissioning_fabric/ids.hpp"
#include "decommissioning_fabric/time.hpp"

namespace decommissioning_fabric {

/// The ten independent ways an asset can still be live. A retirement is only
/// complete when every one of them is demonstrably revoked.
enum class AuthorityDomain : std::uint32_t {
  none = 0,
  asi_execution = 1U << 0U,
  dfi_network = 1U << 1U,
  power_control = 1U << 2U,
  cooling_control = 1U << 3U,
  tenant_lease = 1U << 4U,
  inventory_record = 1U << 5U,
  monitoring_binding = 1U << 6U,
  credential_scope = 1U << 7U,
  reservation_hold = 1U << 8U,
  maintenance_window = 1U << 9U,
};

inline constexpr std::uint32_t kAuthorityDomainCount = 10;

/// Fixed iteration order. Every report, checklist, and rendering walks this
/// array, never a bit scan, so output is identical across hosts and runs.
inline constexpr std::array<AuthorityDomain, kAuthorityDomainCount> kAuthorityDomains = {
    AuthorityDomain::asi_execution,   AuthorityDomain::dfi_network,
    AuthorityDomain::power_control,   AuthorityDomain::cooling_control,
    AuthorityDomain::tenant_lease,    AuthorityDomain::inventory_record,
    AuthorityDomain::monitoring_binding, AuthorityDomain::credential_scope,
    AuthorityDomain::reservation_hold,   AuthorityDomain::maintenance_window};

inline constexpr std::uint32_t kAllAuthorityBits = 0x000003FFU;

[[nodiscard]] constexpr std::uint32_t BitOf(AuthorityDomain domain) noexcept {
  return static_cast<std::uint32_t>(domain);
}

[[nodiscard]] constexpr std::string_view ToString(AuthorityDomain domain) noexcept {
  switch (domain) {
    case AuthorityDomain::none: return "none";
    case AuthorityDomain::asi_execution: return "asi_execution";
    case AuthorityDomain::dfi_network: return "dfi_network";
    case AuthorityDomain::power_control: return "power_control";
    case AuthorityDomain::cooling_control: return "cooling_control";
    case AuthorityDomain::tenant_lease: return "tenant_lease";
    case AuthorityDomain::inventory_record: return "inventory_record";
    case AuthorityDomain::monitoring_binding: return "monitoring_binding";
    case AuthorityDomain::credential_scope: return "credential_scope";
    case AuthorityDomain::reservation_hold: return "reservation_hold";
    case AuthorityDomain::maintenance_window: return "maintenance_window";
  }
  return "none";
}

/// Parses a domain name exactly; returns AuthorityDomain::none for anything
/// unrecognised so a caller must test for it rather than receive a default.
[[nodiscard]] AuthorityDomain AuthorityDomainFromString(std::string_view name) noexcept;

struct AuthorityMask {
  std::uint32_t bits{0};

  [[nodiscard]] constexpr bool has(AuthorityDomain domain) const noexcept {
    return (bits & BitOf(domain)) != 0U;
  }
  [[nodiscard]] constexpr std::uint32_t count() const noexcept {
    std::uint32_t n = 0;
    for (const AuthorityDomain domain : kAuthorityDomains) {
      if (has(domain)) {
        ++n;
      }
    }
    return n;
  }
  [[nodiscard]] constexpr std::uint32_t count_of(std::uint32_t rhs) const noexcept {
    std::uint32_t n = 0;
    for (const AuthorityDomain domain : kAuthorityDomains) {
      if (has(domain) && (rhs & BitOf(domain)) != 0U) {
        ++n;
      }
    }
    return n;
  }
  [[nodiscard]] constexpr AuthorityMask with(AuthorityDomain domain) const noexcept {
    return AuthorityMask{bits | BitOf(domain)};
  }
  [[nodiscard]] constexpr AuthorityMask without(AuthorityDomain domain) const noexcept {
    return AuthorityMask{bits & ~BitOf(domain)};
  }
  /// True when every bit outside the ten known domains is clear. A mask with
  /// unknown bits set is malformed rather than merely surprising.
  [[nodiscard]] constexpr bool only_known_domains() const noexcept {
    return (bits & ~kAllAuthorityBits) == 0U;
  }

  friend constexpr bool operator==(AuthorityMask, AuthorityMask) noexcept = default;
  friend constexpr auto operator<=>(AuthorityMask, AuthorityMask) noexcept = default;
};

/// The state of one domain with respect to the current generation binding.
enum class DomainStatus : std::uint32_t {
  unknown = 0,
  active = 1,
  revoked = 2,
};

[[nodiscard]] constexpr std::string_view ToString(DomainStatus status) noexcept {
  switch (status) {
    case DomainStatus::unknown: return "unknown";
    case DomainStatus::active: return "active";
    case DomainStatus::revoked: return "revoked";
  }
  return "unknown";
}

/// An external authority's receipt of a revocation.
///
/// The receipt binds to a generation binding digest, not to a plan revision:
/// adding a drain obligation must not un-revoke power, but advancing the facility
/// epoch or the policy generation must force the authority to be re-established.
struct RevocationReceipt {
  ReceiptId id;
  AuthorityDomain domain{AuthorityDomain::none};
  Digest binding_digest;

  /// External authority that reported the revocation. Non-empty.
  std::string authority;

  /// That authority's own handle for the revocation. Non-empty.
  std::string reference;

  std::string detail;

  ObservationSequence observation_sequence;
  Timestamp recorded_at;
  IncarnationId recorded_by;

  /// The plan and revision the receipt was recorded under. Provenance only: it
  /// does not participate in coverage.
  PlanId recorded_under_plan;
  Revision recorded_under_revision;

  friend bool operator==(const RevocationReceipt&, const RevocationReceipt&) = default;
};

struct DomainAssessment {
  AuthorityDomain domain{AuthorityDomain::none};
  DomainStatus status{DomainStatus::unknown};

  /// Set only when status == revoked: the receipt that covers the domain.
  ReceiptId covering_receipt;

  /// True when at least one receipt exists for this domain but is bound to a
  /// different generation binding. Distinguishes "nobody reported" from
  /// "somebody reported under a fence that no longer applies".
  bool stale_receipt_present{false};
};

struct AuthorityReport {
  std::array<DomainAssessment, kAuthorityDomainCount> domains{};
  AuthorityMask active{};
  std::uint32_t active_count{0};
  std::uint32_t revoked_count{0};
  std::uint32_t unknown_count{0};

  [[nodiscard]] bool fully_revoked() const noexcept {
    return revoked_count == kAuthorityDomainCount;
  }
  /// True when any domain is still active or of unknown state, which is exactly
  /// the condition that blocks final closure.
  [[nodiscard]] bool blocks_closure() const noexcept {
    return active_count != 0U || unknown_count != 0U;
  }
};

/// Computes the authority report for a binding. Deterministic: iterates
/// kAuthorityDomains and, within a domain, the receipts in their stored
/// (ASCENDING ReceiptId) order, so the covering receipt is always the same one.
[[nodiscard]] AuthorityReport ComputeAuthorityReport(const AuthorityMask& active,
                                                     const Digest& binding_digest,
                                                     const RevocationReceipt* receipts,
                                                     std::size_t receipt_count);

}  // namespace decommissioning_fabric

#endif  // DECOMMISSIONING_FABRIC_AUTHORITY_HPP

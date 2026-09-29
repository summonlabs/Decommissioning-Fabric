// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0

#include "decommissioning_fabric/authority.hpp"

namespace decommissioning_fabric {

AuthorityDomain AuthorityDomainFromString(std::string_view name) noexcept {
  for (const AuthorityDomain domain : kAuthorityDomains) {
    if (ToString(domain) == name) {
      return domain;
    }
  }
  return AuthorityDomain::none;
}

AuthorityReport ComputeAuthorityReport(const AuthorityMask& active,
                                       const Digest& binding_digest,
                                       const RevocationReceipt* receipts,
                                       std::size_t receipt_count) {
  AuthorityReport report;
  report.active = active;

  for (std::size_t i = 0; i < kAuthorityDomainCount; ++i) {
    const AuthorityDomain domain = kAuthorityDomains[i];
    DomainAssessment& assessment = report.domains[i];
    assessment.domain = domain;

    if (active.has(domain)) {
      assessment.status = DomainStatus::active;
      ++report.active_count;
      continue;
    }

    // Deterministic covering receipt: the lowest ReceiptId whose domain matches
    // and whose binding digest is exact. Stored order is ascending ReceiptId, so
    // a linear scan finds the same receipt on every host and every run.
    const RevocationReceipt* covering = nullptr;
    for (std::size_t r = 0; r < receipt_count; ++r) {
      const RevocationReceipt& receipt = receipts[r];
      if (receipt.domain != domain) {
        continue;
      }
      if (receipt.binding_digest == binding_digest) {
        if (covering == nullptr || receipt.id < covering->id) {
          covering = &receipt;
        }
      } else {
        assessment.stale_receipt_present = true;
      }
    }

    if (covering == nullptr) {
      assessment.status = DomainStatus::unknown;
      ++report.unknown_count;
    } else {
      assessment.status = DomainStatus::revoked;
      assessment.covering_receipt = covering->id;
      ++report.revoked_count;
    }
  }

  return report;
}

}  // namespace decommissioning_fabric

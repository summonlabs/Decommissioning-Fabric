// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// authority.hpp proof obligations.
//
// Absence of a bit is not proof of revocation: a domain is revoked only when the
// bit is clear AND a receipt bound to the current binding covers it. These tests
// pin that distinction, the deterministic choice of covering receipt, and the two
// closure predicates.

#include "decommissioning_fabric/authority.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "harness.hpp"

namespace {

using namespace decommissioning_fabric;

[[nodiscard]] std::size_t IndexOf(AuthorityDomain domain) {
  for (std::size_t i = 0; i < kAuthorityDomains.size(); ++i) {
    if (kAuthorityDomains[i] == domain) {
      return i;
    }
  }
  return kAuthorityDomains.size();
}

[[nodiscard]] const DomainAssessment& AssessmentOf(const AuthorityReport& report,
                                                   AuthorityDomain domain) {
  const std::size_t index = IndexOf(domain);
  DF_CHECK_MSG(index < kAuthorityDomains.size(), "domain is absent from kAuthorityDomains");
  const std::size_t safe = index < kAuthorityDomains.size() ? index : 0U;
  return report.domains[safe];
}

[[nodiscard]] RevocationReceipt MakeReceipt(std::uint64_t id, AuthorityDomain domain,
                                            const Digest& binding) {
  RevocationReceipt receipt;
  receipt.id = ReceiptId::FromValue(id);
  receipt.domain = domain;
  receipt.binding_digest = binding;
  receipt.authority = "external-authority";
  receipt.reference = "REV-" + std::to_string(id);
  receipt.detail = "revocation reported";
  receipt.observation_sequence = ObservationSequence::FromValue(id + 100U);
  receipt.recorded_at = Timestamp{1767225600000000000LL};
  receipt.recorded_by = IncarnationId::FromValue(0x9001U);
  receipt.recorded_under_plan = PlanId::FromValue(0x5001U);
  receipt.recorded_under_revision = Revision::FromValue(4U);
  return receipt;
}

void CheckReportsEquivalent(const AuthorityReport& actual, const AuthorityReport& expected) {
  DF_CHECK_EQ(actual.active.bits, expected.active.bits);
  DF_CHECK_EQ(actual.active_count, expected.active_count);
  DF_CHECK_EQ(actual.revoked_count, expected.revoked_count);
  DF_CHECK_EQ(actual.unknown_count, expected.unknown_count);
  for (std::size_t i = 0; i < kAuthorityDomainCount; ++i) {
    DF_CHECK_EQ(actual.domains[i].domain, expected.domains[i].domain);
    DF_CHECK_EQ(actual.domains[i].status, expected.domains[i].status);
    DF_CHECK_EQ(actual.domains[i].covering_receipt.value(),
                expected.domains[i].covering_receipt.value());
    DF_CHECK_EQ(actual.domains[i].stale_receipt_present,
                expected.domains[i].stale_receipt_present);
  }
}

// ---------------------------------------------------------------------------
// The ten domains
// ---------------------------------------------------------------------------

DF_TEST(Authority_TenDomainsCoverEveryBitWithoutOverlap) {
  DF_CHECK_EQ(kAuthorityDomainCount, 10U);
  DF_CHECK_EQ(kAuthorityDomains.size(), static_cast<std::size_t>(kAuthorityDomainCount));
  DF_CHECK_EQ(kAllAuthorityBits, 0x3FFU);

  std::uint32_t union_bits = 0U;
  std::uint32_t sum_bits = 0U;
  for (std::size_t i = 0; i < kAuthorityDomains.size(); ++i) {
    const std::uint32_t bit = BitOf(kAuthorityDomains[i]);
    DF_CHECK_MSG(bit != 0U, "a domain has no bit");
    // Exactly one bit per domain: a multi-bit entry would overlap another entry.
    DF_CHECK_MSG((bit & (bit - 1U)) == 0U, "a domain bit is not a single bit");
    DF_CHECK_MSG((union_bits & bit) == 0U, "two domains share a bit");
    union_bits |= bit;
    sum_bits += bit;
    for (std::size_t j = i + 1U; j < kAuthorityDomains.size(); ++j) {
      DF_CHECK_NE(kAuthorityDomains[i], kAuthorityDomains[j]);
    }
  }
  // No overlap and no uncovered bit: the union and the arithmetic sum agree.
  DF_CHECK_EQ(union_bits, kAllAuthorityBits);
  DF_CHECK_EQ(sum_bits, kAllAuthorityBits);

  AuthorityMask all{kAllAuthorityBits};
  DF_CHECK_EQ(all.count(), 10U);
  DF_CHECK(all.only_known_domains());
}

DF_TEST(Authority_MaskCountingWithAndWithout) {
  const AuthorityMask empty{};
  DF_CHECK_EQ(empty.count(), 0U);
  DF_CHECK_EQ(empty.bits, 0U);
  DF_CHECK(!empty.has(AuthorityDomain::asi_execution));
  DF_CHECK(empty.only_known_domains());

  const AuthorityMask three = empty.with(AuthorityDomain::asi_execution)
                                  .with(AuthorityDomain::power_control)
                                  .with(AuthorityDomain::reservation_hold);
  DF_CHECK_EQ(three.count(), 3U);
  DF_CHECK_EQ(three.bits, BitOf(AuthorityDomain::asi_execution) |
                              BitOf(AuthorityDomain::power_control) |
                              BitOf(AuthorityDomain::reservation_hold));
  DF_CHECK(three.has(AuthorityDomain::asi_execution));
  DF_CHECK(three.has(AuthorityDomain::power_control));
  DF_CHECK(three.has(AuthorityDomain::reservation_hold));
  DF_CHECK(!three.has(AuthorityDomain::dfi_network));
  DF_CHECK(!three.has(AuthorityDomain::maintenance_window));

  // count_of restricts the count to the nominated bits.
  DF_CHECK_EQ(three.count_of(kAllAuthorityBits), 3U);
  DF_CHECK_EQ(three.count_of(BitOf(AuthorityDomain::asi_execution) |
                             BitOf(AuthorityDomain::dfi_network)),
              1U);
  DF_CHECK_EQ(three.count_of(0U), 0U);

  const AuthorityMask two = three.without(AuthorityDomain::power_control);
  DF_CHECK_EQ(two.count(), 2U);
  DF_CHECK(!two.has(AuthorityDomain::power_control));
  DF_CHECK(two.has(AuthorityDomain::asi_execution));
  DF_CHECK(two.has(AuthorityDomain::reservation_hold));
  // with/without are pure: the receiver is unchanged.
  DF_CHECK_EQ(three.count(), 3U);
  DF_CHECK(three.has(AuthorityDomain::power_control));

  // Idempotent re-addition does not inflate the count.
  DF_CHECK_EQ(three.with(AuthorityDomain::asi_execution).count(), 3U);
  DF_CHECK_EQ(two.without(AuthorityDomain::power_control).count(), 2U);
}

DF_TEST(Authority_MaskRejectsBitsOutsideTheKnownDomains) {
  DF_CHECK(AuthorityMask{0U}.only_known_domains());
  DF_CHECK(AuthorityMask{kAllAuthorityBits}.only_known_domains());
  DF_CHECK(!AuthorityMask{kAllAuthorityBits | 0x400U}.only_known_domains());
  DF_CHECK(!AuthorityMask{0x80000000U}.only_known_domains());
  DF_CHECK_EQ(AuthorityMask{kAllAuthorityBits | 0x400U}.count(), 10U);
}

// ---------------------------------------------------------------------------
// ComputeAuthorityReport
// ---------------------------------------------------------------------------

DF_TEST(Authority_SetBitIsActiveRegardlessOfReceipts) {
  const Digest binding = Sha256::Of("binding-a");
  std::vector<RevocationReceipt> receipts;
  receipts.push_back(MakeReceipt(4U, AuthorityDomain::dfi_network, binding));
  const AuthorityMask active = AuthorityMask{}.with(AuthorityDomain::dfi_network);

  const AuthorityReport report =
      ComputeAuthorityReport(active, binding, receipts.data(), receipts.size());
  DF_CHECK_EQ(report.active_count, 1U);
  DF_CHECK_EQ(report.revoked_count, 0U);
  DF_CHECK_EQ(report.unknown_count, 9U);
  DF_CHECK_EQ(report.active.bits, active.bits);
  const DomainAssessment& dfi = AssessmentOf(report, AuthorityDomain::dfi_network);
  DF_CHECK_EQ(dfi.status, DomainStatus::active);
  DF_CHECK(dfi.covering_receipt.is_unset());
  DF_CHECK(!dfi.stale_receipt_present);

  for (const AuthorityDomain domain : kAuthorityDomains) {
    if (domain != AuthorityDomain::dfi_network) {
      DF_CHECK_EQ(AssessmentOf(report, domain).status, DomainStatus::unknown);
    }
  }
}

DF_TEST(Authority_ClearBitWithoutReceiptIsUnknown) {
  const Digest binding = Sha256::Of("binding-a");
  const AuthorityReport report = ComputeAuthorityReport(AuthorityMask{}, binding, nullptr, 0U);
  DF_CHECK_EQ(report.active_count, 0U);
  DF_CHECK_EQ(report.revoked_count, 0U);
  DF_CHECK_EQ(report.unknown_count, 10U);
  DF_CHECK_EQ(report.domains[0].domain, kAuthorityDomains[0]);
  for (const AuthorityDomain domain : kAuthorityDomains) {
    const DomainAssessment& assessment = AssessmentOf(report, domain);
    DF_CHECK_EQ(assessment.status, DomainStatus::unknown);
    DF_CHECK(assessment.covering_receipt.is_unset());
    DF_CHECK(!assessment.stale_receipt_present);
  }
  // Unknown authority is not a synonym for closure.
  DF_CHECK(report.blocks_closure());
  DF_CHECK(!report.fully_revoked());
}

DF_TEST(Authority_MatchingReceiptRevokesAndNamesTheLowestReceiptId) {
  const Digest binding = Sha256::Of("binding-a");
  std::vector<RevocationReceipt> receipts;
  receipts.push_back(MakeReceipt(9U, AuthorityDomain::power_control, binding));
  receipts.push_back(MakeReceipt(3U, AuthorityDomain::power_control, binding));
  receipts.push_back(MakeReceipt(7U, AuthorityDomain::power_control, binding));
  receipts.push_back(MakeReceipt(1U, AuthorityDomain::dfi_network, binding));

  const AuthorityReport report =
      ComputeAuthorityReport(AuthorityMask{}, binding, receipts.data(), receipts.size());
  DF_CHECK_EQ(report.revoked_count, 2U);
  DF_CHECK_EQ(report.unknown_count, 8U);
  DF_CHECK_EQ(report.active_count, 0U);

  const DomainAssessment& power = AssessmentOf(report, AuthorityDomain::power_control);
  DF_CHECK_EQ(power.status, DomainStatus::revoked);
  DF_CHECK_EQ(power.covering_receipt.value(), 3ULL);
  DF_CHECK(!power.stale_receipt_present);

  const DomainAssessment& dfi = AssessmentOf(report, AuthorityDomain::dfi_network);
  DF_CHECK_EQ(dfi.status, DomainStatus::revoked);
  DF_CHECK_EQ(dfi.covering_receipt.value(), 1ULL);

  DF_CHECK(!report.fully_revoked());
  DF_CHECK(report.blocks_closure());
}

DF_TEST(Authority_ReceiptBoundElsewhereDoesNotCoverAndIsReportedStale) {
  const Digest binding = Sha256::Of("binding-a");
  const Digest other_binding = Sha256::Of("binding-b");
  DF_CHECK(binding != other_binding);

  std::vector<RevocationReceipt> receipts;
  receipts.push_back(MakeReceipt(2U, AuthorityDomain::power_control, other_binding));
  receipts.push_back(MakeReceipt(5U, AuthorityDomain::cooling_control, binding));

  const AuthorityReport report =
      ComputeAuthorityReport(AuthorityMask{}, binding, receipts.data(), receipts.size());
  const DomainAssessment& power = AssessmentOf(report, AuthorityDomain::power_control);
  DF_CHECK_EQ(power.status, DomainStatus::unknown);
  DF_CHECK(power.covering_receipt.is_unset());
  DF_CHECK(power.stale_receipt_present);

  const DomainAssessment& cooling = AssessmentOf(report, AuthorityDomain::cooling_control);
  DF_CHECK_EQ(cooling.status, DomainStatus::revoked);
  DF_CHECK_EQ(cooling.covering_receipt.value(), 5ULL);
  DF_CHECK(!cooling.stale_receipt_present);

  DF_CHECK_EQ(report.revoked_count, 1U);
  DF_CHECK_EQ(report.unknown_count, 9U);

  // A stale receipt alongside a covering one leaves the domain revoked but
  // still marks the stale report, so an operator sees both facts.
  receipts.push_back(MakeReceipt(8U, AuthorityDomain::cooling_control, other_binding));
  const AuthorityReport mixed =
      ComputeAuthorityReport(AuthorityMask{}, binding, receipts.data(), receipts.size());
  const DomainAssessment& mixed_cooling = AssessmentOf(mixed, AuthorityDomain::cooling_control);
  DF_CHECK_EQ(mixed_cooling.status, DomainStatus::revoked);
  DF_CHECK_EQ(mixed_cooling.covering_receipt.value(), 5ULL);
  DF_CHECK(mixed_cooling.stale_receipt_present);
}

DF_TEST(Authority_FullyRevokedOnlyWhenAllTenAreRevoked) {
  const Digest binding = Sha256::Of("binding-a");
  std::vector<RevocationReceipt> receipts;
  std::uint64_t id = 1U;
  for (const AuthorityDomain domain : kAuthorityDomains) {
    receipts.push_back(MakeReceipt(id, domain, binding));
    ++id;
  }

  const AuthorityReport complete =
      ComputeAuthorityReport(AuthorityMask{}, binding, receipts.data(), receipts.size());
  DF_CHECK_EQ(complete.revoked_count, 10U);
  DF_CHECK_EQ(complete.unknown_count, 0U);
  DF_CHECK_EQ(complete.active_count, 0U);
  DF_CHECK(complete.fully_revoked());
  DF_CHECK(!complete.blocks_closure());

  // One domain still active blocks closure and prevents full revocation.
  const AuthorityReport with_active =
      ComputeAuthorityReport(AuthorityMask{}.with(AuthorityDomain::maintenance_window), binding,
                             receipts.data(), receipts.size());
  DF_CHECK_EQ(with_active.revoked_count, 9U);
  DF_CHECK_EQ(with_active.active_count, 1U);
  DF_CHECK(!with_active.fully_revoked());
  DF_CHECK(with_active.blocks_closure());
  DF_CHECK_EQ(AssessmentOf(with_active, AuthorityDomain::maintenance_window).status,
              DomainStatus::active);

  // One domain with no receipt at all blocks closure as unknown.
  const AuthorityReport missing =
      ComputeAuthorityReport(AuthorityMask{}, binding, receipts.data(), receipts.size() - 1U);
  DF_CHECK_EQ(missing.revoked_count, 9U);
  DF_CHECK_EQ(missing.unknown_count, 1U);
  DF_CHECK(!missing.fully_revoked());
  DF_CHECK(missing.blocks_closure());
  DF_CHECK_EQ(AssessmentOf(missing, kAuthorityDomains[kAuthorityDomainCount - 1U]).status,
              DomainStatus::unknown);
}

DF_TEST(Authority_CoveringReceiptDoesNotDependOnAppendOrder) {
  const Digest binding = Sha256::Of("binding-a");
  const Digest other_binding = Sha256::Of("binding-b");

  // The same set of receipts, appended in three different orders.
  std::vector<RevocationReceipt> ascending;
  ascending.push_back(MakeReceipt(2U, AuthorityDomain::power_control, binding));
  ascending.push_back(MakeReceipt(4U, AuthorityDomain::power_control, other_binding));
  ascending.push_back(MakeReceipt(6U, AuthorityDomain::power_control, binding));
  ascending.push_back(MakeReceipt(9U, AuthorityDomain::power_control, binding));

  std::vector<RevocationReceipt> descending(ascending.rbegin(), ascending.rend());
  std::vector<RevocationReceipt> interleaved = {ascending[2], ascending[0], ascending[3],
                                                ascending[1]};

  const AuthorityMask active = AuthorityMask{}.with(AuthorityDomain::dfi_network);
  const AuthorityReport first =
      ComputeAuthorityReport(active, binding, ascending.data(), ascending.size());
  const AuthorityReport second =
      ComputeAuthorityReport(active, binding, descending.data(), descending.size());
  const AuthorityReport third =
      ComputeAuthorityReport(active, binding, interleaved.data(), interleaved.size());

  CheckReportsEquivalent(second, first);
  CheckReportsEquivalent(third, first);

  const DomainAssessment& power = AssessmentOf(first, AuthorityDomain::power_control);
  DF_CHECK_EQ(power.status, DomainStatus::revoked);
  DF_CHECK_EQ(power.covering_receipt.value(), 2ULL);
  DF_CHECK(power.stale_receipt_present);
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

DF_TEST(Authority_DomainNamesMapExactlyAndUnknownNamesAreNone) {
  for (std::size_t i = 0; i < kAuthorityDomains.size(); ++i) {
    const std::string_view name = ToString(kAuthorityDomains[i]);
    DF_CHECK_MSG(!name.empty(), "domain name is empty");
    DF_CHECK_EQ(AuthorityDomainFromString(name), kAuthorityDomains[i]);
    for (std::size_t j = i + 1U; j < kAuthorityDomains.size(); ++j) {
      DF_CHECK_NE(name, ToString(kAuthorityDomains[j]));
    }
  }
  DF_CHECK_EQ(std::string(ToString(AuthorityDomain::none)), std::string("none"));
  DF_CHECK_EQ(AuthorityDomainFromString("none"), AuthorityDomain::none);
  DF_CHECK_EQ(AuthorityDomainFromString(""), AuthorityDomain::none);
  DF_CHECK_EQ(AuthorityDomainFromString("ASI_EXECUTION"), AuthorityDomain::none);
  DF_CHECK_EQ(AuthorityDomainFromString("asi-execution"), AuthorityDomain::none);
  DF_CHECK_EQ(AuthorityDomainFromString("asi_execution "), AuthorityDomain::none);
  DF_CHECK_EQ(AuthorityDomainFromString("unknown"), AuthorityDomain::none);
  DF_CHECK_EQ(AuthorityDomainFromString("power"), AuthorityDomain::none);
  DF_CHECK_NE(AuthorityDomainFromString("power_control"), AuthorityDomain::none);
}

DF_TEST(Authority_DomainStatusNamesAreDistinct) {
  DF_CHECK_EQ(std::string(ToString(DomainStatus::unknown)), std::string("unknown"));
  DF_CHECK_EQ(std::string(ToString(DomainStatus::active)), std::string("active"));
  DF_CHECK_EQ(std::string(ToString(DomainStatus::revoked)), std::string("revoked"));
  DF_CHECK_NE(ToString(DomainStatus::active), ToString(DomainStatus::revoked));
  DF_CHECK_NE(ToString(DomainStatus::unknown), ToString(DomainStatus::active));
}

}  // namespace

DF_TEST_MAIN()

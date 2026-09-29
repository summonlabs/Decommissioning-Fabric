// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// The fence is the compare-and-swap token that binds every mutation to the exact
// identity, generation, epoch, and revision it was planned against. These tests
// pin the classification ORDER, because an order change silently changes which
// error an operator sees for a given mistake.

#include <string>
#include <vector>

#include "decommissioning_fabric/plan.hpp"
#include "harness.hpp"

namespace df = decommissioning_fabric;

namespace {

[[nodiscard]] df::PlanFence WellFormed() {
  df::PlanFence fence;
  fence.asset = df::AssetId::FromValue(0x1001U);
  fence.site = df::SiteId::FromValue(0x2001U);
  fence.rack = df::RackId::FromValue(0x3001U);
  fence.lifecycle_generation = df::LifecycleGeneration::FromValue(4);
  fence.hardware_generation = df::HardwareGeneration::FromValue(3);
  fence.firmware_generation = df::FirmwareGeneration::FromValue(7);
  fence.facility_epoch = df::FacilityEpoch::FromValue(11);
  fence.policy_generation = df::PolicyGeneration::FromValue(12);
  fence.dependency_generation = df::DependencyGeneration::FromValue(13);
  fence.capacity_generation = df::CapacityGeneration::FromValue(14);
  fence.topology_generation = df::TopologyGeneration::FromValue(15);
  fence.maintenance_generation = df::MaintenanceGeneration::FromValue(16);
  fence.active_obligation_count = 2;
  fence.active_obligation_digest = df::Sha256::Of("obligations");
  fence.plan = df::PlanId::FromValue(0x5001U);
  fence.revision = df::Revision::FromValue(9);
  return fence;
}

}  // namespace

DF_TEST(Fence_WellFormedIsCurrent) {
  const df::PlanFence fence = WellFormed();
  DF_CHECK(fence.all_required_set());
  DF_CHECK(fence.first_unset_field() == df::FenceField::none);
  const df::FenceComparison comparison = df::ClassifyFence(fence, fence);
  DF_CHECK(comparison.classification == df::FenceClass::current);
  DF_CHECK(comparison.code() == df::ErrorCode::ok);
}

DF_TEST(Fence_DifferentAssetIsSupersededNotStale) {
  df::PlanFence requested = WellFormed();
  const df::PlanFence current = WellFormed();
  requested.asset = df::AssetId::FromValue(0x9999U);
  // Two defects are present at once; supersession wins because asset identity is
  // checked first and belongs to the superseded class, not the stale class.
  requested.hardware_generation = df::HardwareGeneration::FromValue(99);
  const df::FenceComparison comparison = df::ClassifyFence(requested, current);
  DF_CHECK(comparison.classification == df::FenceClass::superseded);
  DF_CHECK(comparison.first_mismatch == df::FenceField::asset);
  DF_CHECK(comparison.code() == df::ErrorCode::fence_superseded);
}

DF_TEST(Fence_UnsetUnitIsMalformedAndNamesTheFirstUnsetField) {
  df::PlanFence requested = WellFormed();
  const df::PlanFence current = WellFormed();
  requested.policy_generation = df::PolicyGeneration{};
  requested.capacity_generation = df::CapacityGeneration{};
  const df::FenceComparison comparison = df::ClassifyFence(requested, current);
  DF_CHECK(comparison.classification == df::FenceClass::malformed);
  // kFenceFieldOrder places policy_generation before capacity_generation.
  DF_CHECK(comparison.first_mismatch == df::FenceField::policy_generation);
  DF_CHECK(comparison.code() == df::ErrorCode::fence_malformed);
  DF_CHECK(requested.all_required_set() == false);
  DF_CHECK(requested.first_unset_field() == df::FenceField::policy_generation);
}

DF_TEST(Fence_MalformedBeatsStaleBecauseAnUnsetUnitIsNotAComparison) {
  df::PlanFence requested = WellFormed();
  const df::PlanFence current = WellFormed();
  requested.hardware_generation = df::HardwareGeneration{};
  requested.topology_generation = df::TopologyGeneration::FromValue(999);
  const df::FenceComparison comparison = df::ClassifyFence(requested, current);
  DF_CHECK(comparison.classification == df::FenceClass::malformed);
}

DF_TEST(Fence_StaleNamesTheFirstFieldInTheDocumentedOrder) {
  // Every binding field differs at once. The reported field must be the first in
  // kFenceFieldOrder, and it must be the same one on every run.
  df::PlanFence requested = WellFormed();
  const df::PlanFence current = WellFormed();
  requested.site = df::SiteId::FromValue(0xAAAAU);
  requested.rack = df::RackId::FromValue(0xBBBBU);
  requested.hardware_generation = df::HardwareGeneration::FromValue(1);
  requested.firmware_generation = df::FirmwareGeneration::FromValue(1);
  requested.lifecycle_generation = df::LifecycleGeneration::FromValue(1);
  requested.dependency_generation = df::DependencyGeneration::FromValue(1);
  requested.policy_generation = df::PolicyGeneration::FromValue(1);
  requested.capacity_generation = df::CapacityGeneration::FromValue(1);
  requested.topology_generation = df::TopologyGeneration::FromValue(1);
  requested.maintenance_generation = df::MaintenanceGeneration::FromValue(1);
  requested.facility_epoch = df::FacilityEpoch::FromValue(1);
  requested.active_obligation_digest = df::Sha256::Of("other");

  for (int repeat = 0; repeat < 8; ++repeat) {
    const df::FenceComparison comparison = df::ClassifyFence(requested, current);
    DF_CHECK(comparison.classification == df::FenceClass::stale);
    DF_CHECK(comparison.first_mismatch == df::FenceField::site);
    DF_CHECK(comparison.code() == df::ErrorCode::fence_stale);
    DF_CHECK(comparison.requested_value == requested.site.to_hex());
    DF_CHECK(comparison.current_value == current.site.to_hex());
  }

  // Remove the earlier mismatches one at a time and watch the reported field walk
  // forward through kFenceFieldOrder.
  const df::FenceField expected_order[] = {
      df::FenceField::hardware_generation, df::FenceField::firmware_generation,
      df::FenceField::lifecycle_generation, df::FenceField::dependency_generation,
      df::FenceField::policy_generation, df::FenceField::capacity_generation,
      df::FenceField::topology_generation, df::FenceField::maintenance_generation,
      df::FenceField::facility_epoch, df::FenceField::active_obligation_digest};
  df::PlanFence walk = requested;
  walk.site = current.site;
  walk.rack = current.rack;
  for (const df::FenceField expected : expected_order) {
    const df::FenceComparison comparison = df::ClassifyFence(walk, current);
    DF_CHECK(comparison.first_mismatch == expected);
    switch (expected) {
      case df::FenceField::hardware_generation: walk.hardware_generation = current.hardware_generation; break;
      case df::FenceField::firmware_generation: walk.firmware_generation = current.firmware_generation; break;
      case df::FenceField::lifecycle_generation: walk.lifecycle_generation = current.lifecycle_generation; break;
      case df::FenceField::dependency_generation: walk.dependency_generation = current.dependency_generation; break;
      case df::FenceField::policy_generation: walk.policy_generation = current.policy_generation; break;
      case df::FenceField::capacity_generation: walk.capacity_generation = current.capacity_generation; break;
      case df::FenceField::topology_generation: walk.topology_generation = current.topology_generation; break;
      case df::FenceField::maintenance_generation: walk.maintenance_generation = current.maintenance_generation; break;
      case df::FenceField::facility_epoch: walk.facility_epoch = current.facility_epoch; break;
      case df::FenceField::active_obligation_digest: walk.active_obligation_digest = current.active_obligation_digest; break;
      default: break;
    }
  }
  DF_CHECK(df::ClassifyFence(walk, current).classification == df::FenceClass::current);
}

DF_TEST(Fence_OlderRevisionIsRevisionBehindAndNewerRevisionIsStale) {
  df::PlanFence requested = WellFormed();
  df::PlanFence current = WellFormed();

  current.revision = df::Revision::FromValue(20);
  df::FenceComparison comparison = df::ClassifyFence(requested, current);
  DF_CHECK(comparison.classification == df::FenceClass::revision_behind);
  DF_CHECK(comparison.first_mismatch == df::FenceField::revision);
  DF_CHECK(comparison.code() == df::ErrorCode::fence_revision_behind);

  // A revision this runtime never published is not "the caller is ahead of us";
  // it is a fence that does not correspond to any generation we produced.
  requested.revision = df::Revision::FromValue(21);
  comparison = df::ClassifyFence(requested, current);
  DF_CHECK(comparison.classification == df::FenceClass::stale);
  DF_CHECK(comparison.first_mismatch == df::FenceField::revision);
  DF_CHECK(comparison.code() == df::ErrorCode::fence_stale);
}

DF_TEST(Fence_ZeroRevisionIsMalformed) {
  df::PlanFence requested = WellFormed();
  requested.revision = df::Revision{};
  const df::FenceComparison comparison = df::ClassifyFence(requested, WellFormed());
  DF_CHECK(comparison.classification == df::FenceClass::malformed);
}

DF_TEST(Fence_BindingExcludesRevisionPlanAndObligationDigest) {
  // A receipt binds to the generation binding, so adding a drain obligation or
  // advancing the revision must not change it. If the binding digest moved on
  // every revision, no revocation receipt would ever keep covering the plan.
  df::PlanFence fence = WellFormed();
  const df::Digest first = df::BindingDigest(fence.binding());
  fence.revision = df::Revision::FromValue(500);
  fence.plan = df::PlanId::FromValue(0x7777U);
  fence.active_obligation_count = 17;
  fence.active_obligation_digest = df::Sha256::Of("something else");
  DF_CHECK(df::BindingDigest(fence.binding()) == first);

  // But a generation change must move it.
  fence.policy_generation = df::PolicyGeneration::FromValue(999);
  DF_CHECK(df::BindingDigest(fence.binding()) != first);
}

DF_TEST(Fence_TokenRoundTripsExactly) {
  const df::PlanFence fence = WellFormed();
  const std::string token = df::EncodeFenceToken(fence);
  DF_CHECK(token.empty() == false);
  DF_CHECK(token.size() % 2U == 0U);

  auto decoded = df::DecodeFenceToken(token);
  DF_CHECK(decoded.ok());
  DF_CHECK(decoded.value() == fence);

  // Encoding is canonical: decode then re-encode produces the same token.
  DF_CHECK(df::EncodeFenceToken(decoded.value()) == token);
}

DF_TEST(Fence_TokenRoundTripsForExtremes) {
  df::PlanFence fence = WellFormed();
  fence.asset = df::AssetId::FromValue(0xFFFFFFFFFFFFFFFFULL);
  fence.site = df::SiteId::FromValue(0xFFFFFFFFFFFFFFFFULL);
  fence.rack = df::RackId::FromValue(0xFFFFFFFFFFFFFFFFULL);
  fence.lifecycle_generation = df::LifecycleGeneration::Max();
  fence.facility_epoch = df::FacilityEpoch::Max();
  fence.active_obligation_count = 0xFFFFFFFFU;
  fence.active_obligation_digest = df::Sha256::Of("");
  fence.plan = df::PlanId::FromValue(0xFFFFFFFFFFFFFFFFULL);
  fence.revision = df::Revision::Max();

  auto decoded = df::DecodeFenceToken(df::EncodeFenceToken(fence));
  DF_CHECK(decoded.ok());
  DF_CHECK(decoded.value() == fence);
}

DF_TEST(Fence_TokenRejectsMalformedInput) {
  const std::string valid = df::EncodeFenceToken(WellFormed());

  DF_CHECK(df::DecodeFenceToken("").ok() == false);
  DF_CHECK(df::DecodeFenceToken("zz").ok() == false);          // non-hex
  DF_CHECK(df::DecodeFenceToken("abc").ok() == false);         // odd length
  DF_CHECK(df::DecodeFenceToken(valid + "00").ok() == false);  // trailing content
  DF_CHECK(df::DecodeFenceToken(valid.substr(0, valid.size() - 4U)).ok() == false);
  DF_CHECK(df::DecodeFenceToken(std::string(600, 'a')).ok() == false);  // too long

  // A well-formed hex string whose plain text has too few fields.
  const std::string few = df::HexEncode("0000000000001001:0000000000002001");
  DF_CHECK(df::DecodeFenceToken(few).ok() == false);

  // A field of the wrong width is rejected rather than zero padded.
  std::string plain(239, '0');
  for (std::size_t index = 0; index < plain.size(); ++index) {
    plain[index] = ((index % 17U) == 0U) ? ':' : '0';
  }
  const std::string wrong_width = df::HexEncode(plain);
  auto decoded = df::DecodeFenceToken(wrong_width);
  DF_CHECK(decoded.ok() == false);
}

DF_TEST(Fence_FieldNamesAndRenderingsAreStable) {
  const df::PlanFence fence = WellFormed();
  DF_CHECK(df::ToString(df::FenceField::active_obligation_digest) ==
           std::string_view("active_obligation_digest"));
  DF_CHECK(df::ToString(df::FenceField::facility_epoch) == std::string_view("facility_epoch"));
  DF_CHECK(df::ToString(df::FenceField::none) == std::string_view("none"));
  DF_CHECK(df::RenderFenceField(fence, df::FenceField::asset) == fence.asset.to_hex());
  DF_CHECK(df::RenderFenceField(fence, df::FenceField::revision) == "0000000000000009");
  DF_CHECK(df::RenderFenceField(fence, df::FenceField::hardware_generation) == "00000003");
  DF_CHECK(df::RenderFenceField(fence, df::FenceField::active_obligation_count) == "2");
  DF_CHECK(df::RenderFenceField(fence, df::FenceField::active_obligation_digest) ==
           fence.active_obligation_digest.to_hex());
  // kFenceFieldOrder is a fixed table, not a bit scan.
  DF_CHECK(df::kFenceFieldOrder[0] == df::FenceField::asset);
  DF_CHECK(df::kFenceFieldOrder[df::kFenceFieldOrderCount - 1U] ==
           df::FenceField::active_obligation_digest);
}

DF_TEST(Fence_ActiveObligationDigestIgnoresInsertionOrder) {
  auto make = [](std::uint64_t id, df::ObligationState state) {
    df::DrainObligation obligation;
    obligation.id = df::ObligationId::FromValue(id);
    obligation.kind = df::DrainKind::asi_workload;
    obligation.state = state;
    obligation.required = true;
    obligation.issued_sequence = df::ObservationSequence::FromValue(1);
    return obligation;
  };

  std::vector<df::DrainObligation> forward;
  forward.push_back(make(3, df::ObligationState::outstanding));
  forward.push_back(make(1, df::ObligationState::outstanding));
  forward.push_back(make(2, df::ObligationState::outstanding));

  std::vector<df::DrainObligation> reverse(forward.rbegin(), forward.rend());
  DF_CHECK(df::ActiveObligationDigest(forward) == df::ActiveObligationDigest(reverse));

  // Resolving one obligation must change the digest: it is the fence that says
  // "the set of things still blocking this plan has changed".
  std::vector<df::DrainObligation> resolved = forward;
  resolved[1].state = df::ObligationState::satisfied;
  resolved[1].satisfaction_evidence = df::EvidenceId::FromValue(1);
  resolved[1].satisfied_sequence = df::ObservationSequence::FromValue(9);
  DF_CHECK(df::ActiveObligationDigest(resolved) != df::ActiveObligationDigest(forward));

  // A non-required obligation never participates.
  std::vector<df::DrainObligation> optional = forward;
  optional[0].required = false;
  DF_CHECK(df::ActiveObligationDigest(optional) != df::ActiveObligationDigest(forward));
  DF_CHECK(df::ActiveObligationDigest({}).is_zero() == false);
}

DF_TEST_MAIN()

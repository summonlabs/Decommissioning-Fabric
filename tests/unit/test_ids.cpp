// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Proof obligations for include/decommissioning_fabric/ids.hpp.
//
// The claims under test: an identity is unset exactly when it is zero;
// monotonic allocation never wraps, never silently reuses a value, and never
// steps below zero; the fixed-width hex rendering and the hi/lo codec round
// trip exactly; and ordering plus std::hash agree with the underlying integer
// so that standard containers behave.

#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "decommissioning_fabric/ids.hpp"
#include "harness.hpp"

namespace {

using decommissioning_fabric::AssetId;
using decommissioning_fabric::CommitSequence;
using decommissioning_fabric::FacilityEpoch;
using decommissioning_fabric::LifecycleGeneration;
using decommissioning_fabric::ObservationSequence;
using decommissioning_fabric::PlanId;
using decommissioning_fabric::RackId;
using decommissioning_fabric::Revision;

constexpr std::uint64_t kU64Max = std::numeric_limits<std::uint64_t>::max();
constexpr std::uint32_t kU32Max = std::numeric_limits<std::uint32_t>::max();

/// to_hex() is documented as exactly 16 lowercase hexadecimal digits, zero
/// padded, so it is verified digit by digit rather than only by length.
template <typename Strong>
void CheckFixedHex(const Strong& value, std::string_view expected) {
  const std::string hex = value.to_hex();
  DF_CHECK_EQ(hex.size(), std::size_t{16});
  DF_CHECK_EQ(hex, std::string(expected));
  for (const char digit : hex) {
    const bool is_lower_hex = (digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f');
    DF_CHECK_MSG(is_lower_hex, "to_hex() must be lowercase hexadecimal, got: " + hex);
  }
}

}  // namespace

DF_TEST(Ids_UnsetIsExactlyZeroAndSetIsExactlyNonZero) {
  const AssetId unset;
  DF_CHECK(unset.is_unset());
  DF_CHECK(!unset.is_set());
  DF_CHECK_EQ(unset.value(), std::uint64_t{0});

  const AssetId one = AssetId::FromValue(1);
  DF_CHECK(one.is_set());
  DF_CHECK(!one.is_unset());

  DF_CHECK(AssetId::FromValue(kU64Max).is_set());

  // A 32-bit counter draws the same line at its own width.
  const FacilityEpoch epoch_unset;
  DF_CHECK(epoch_unset.is_unset());
  DF_CHECK(!epoch_unset.is_set());
  DF_CHECK(FacilityEpoch::FromValue(kU32Max).is_set());
}

DF_TEST(Ids_FirstIsOneAndMaxIsAllOnes) {
  DF_CHECK_EQ(AssetId::First().value(), std::uint64_t{1});
  DF_CHECK(AssetId::First().is_set());
  DF_CHECK_EQ(AssetId::Max().value(), kU64Max);
  DF_CHECK(AssetId::Max().at_max());
  DF_CHECK(!AssetId::First().at_max());
  DF_CHECK(!AssetId::FromValue(kU64Max - 1U).at_max());
  DF_CHECK(!AssetId{}.at_max());

  DF_CHECK_EQ(FacilityEpoch::First().value(), std::uint32_t{1});
  DF_CHECK_EQ(FacilityEpoch::Max().value(), kU32Max);
  DF_CHECK(FacilityEpoch::Max().at_max());
  DF_CHECK(!FacilityEpoch::FromValue(kU32Max - 1U).at_max());
}

DF_TEST(Ids_NextSaturatesAtMaxAndNeverWrapsToZero) {
  DF_CHECK_EQ(AssetId::Max().Next().value(), kU64Max);
  DF_CHECK(AssetId::Max().Next().at_max());
  DF_CHECK_MSG(AssetId::Max().Next().is_set(),
               "the saturating successor of the maximum identity must not wrap to zero");
  DF_CHECK_NE(AssetId::Max().Next().value(), std::uint64_t{0});
  DF_CHECK_EQ(AssetId::FromValue(kU64Max - 1U).Next().value(), kU64Max);

  DF_CHECK_EQ(AssetId{}.Next().value(), std::uint64_t{1});
  DF_CHECK_EQ(AssetId::First().Next().value(), std::uint64_t{2});
  DF_CHECK_EQ(PlanId::FromValue(41).Next().value(), std::uint64_t{42});

  // Saturation is idempotent: no number of advances can re-enter the value space.
  AssetId cursor = AssetId::Max();
  for (int step = 0; step < 4; ++step) {
    cursor = cursor.Next();
  }
  DF_CHECK_EQ(cursor.value(), kU64Max);

  DF_CHECK_EQ(FacilityEpoch::Max().Next().value(), kU32Max);
  DF_CHECK(FacilityEpoch::Max().Next().is_set());
  DF_CHECK_EQ(FacilityEpoch::FromValue(kU32Max - 1U).Next().value(), kU32Max);
}

DF_TEST(Ids_SuccessorCheckedStepsExactlyAndThrowsAtMax) {
  DF_CHECK_EQ(AssetId{}.SuccessorChecked().value(), std::uint64_t{1});
  DF_CHECK_EQ(AssetId::FromValue(41).SuccessorChecked().value(), std::uint64_t{42});
  DF_CHECK_EQ(AssetId::FromValue(kU64Max - 1U).SuccessorChecked().value(), kU64Max);
  DF_CHECK_EQ(FacilityEpoch::FromValue(kU32Max - 1U).SuccessorChecked().value(), kU32Max);

  bool threw_at_asset_max = false;
  std::string what;
  try {
    (void)AssetId::Max().SuccessorChecked();
  } catch (const std::overflow_error& overflow) {
    threw_at_asset_max = true;
    what = overflow.what();
  }
  DF_CHECK_MSG(threw_at_asset_max,
               "SuccessorChecked() at the maximum identity must throw std::overflow_error");
  DF_CHECK_MSG(!what.empty(), "the overflow_error must carry a diagnostic message");

  bool threw_at_epoch_max = false;
  try {
    (void)FacilityEpoch::Max().SuccessorChecked();
  } catch (const std::overflow_error&) {
    threw_at_epoch_max = true;
  }
  DF_CHECK_MSG(threw_at_epoch_max,
               "SuccessorChecked() at the maximum 32-bit generation must throw std::overflow_error");
}

DF_TEST(Ids_PrevStopsAtZeroAndNeverUnderflows) {
  DF_CHECK(AssetId{}.Prev().is_unset());
  DF_CHECK_EQ(AssetId{}.Prev().value(), std::uint64_t{0});
  DF_CHECK_EQ(AssetId::FromValue(1).Prev().value(), std::uint64_t{0});
  DF_CHECK_EQ(AssetId::FromValue(2).Prev().value(), std::uint64_t{1});
  DF_CHECK(AssetId::First().Prev().is_unset());
  DF_CHECK_EQ(AssetId::Max().Prev().value(), kU64Max - 1U);
  DF_CHECK_EQ(FacilityEpoch{}.Prev().value(), std::uint32_t{0});

  // Repeated decrements from zero stay at zero instead of underflowing.
  AssetId cursor;
  for (int step = 0; step < 8; ++step) {
    cursor = cursor.Prev();
  }
  DF_CHECK(cursor.is_unset());
  DF_CHECK_EQ(cursor.value(), std::uint64_t{0});
}

DF_TEST(Ids_ToHexIsSixteenLowercaseZeroPaddedDigits) {
  CheckFixedHex(AssetId{}, "0000000000000000");
  CheckFixedHex(AssetId::FromValue(1), "0000000000000001");
  CheckFixedHex(AssetId::Max(), "ffffffffffffffff");
  CheckFixedHex(AssetId::FromValue(0x0123456789ABCDEFULL), "0123456789abcdef");
  CheckFixedHex(AssetId::FromValue(0xDEADBEEFULL), "00000000deadbeef");
  CheckFixedHex(AssetId::FromValue(0x0000000100000000ULL), "0000000100000000");
  CheckFixedHex(PlanId::FromValue(9), "0000000000000009");
  CheckFixedHex(Revision::FromValue(0x00000000000000FFULL), "00000000000000ff");
  CheckFixedHex(ObservationSequence::FromValue(kU64Max), "ffffffffffffffff");
  CheckFixedHex(CommitSequence::FromValue(0x8000000000000001ULL), "8000000000000001");
  // A 32-bit counter is still rendered at the fixed 16-digit width.
  CheckFixedHex(FacilityEpoch{}, "0000000000000000");
  CheckFixedHex(FacilityEpoch::FromValue(kU32Max), "00000000ffffffff");
  CheckFixedHex(LifecycleGeneration::FromValue(0xABCDEFU), "0000000000abcdef");
}

DF_TEST(Ids_HighLowAndFromPartsRoundTrip) {
  const std::uint64_t values[] = {
      0ULL,
      1ULL,
      0x0123456789ABCDEFULL,
      0xFFFFFFFFFFFFFFFFULL,
      0x00000000FFFFFFFFULL,
      0xFFFFFFFF00000000ULL,
      0x0000000100000000ULL,
      0xDEADBEEFCAFEBABEULL,
      0x8000000000000000ULL,
  };
  for (const std::uint64_t value : values) {
    const AssetId identity = AssetId::FromValue(value);
    DF_CHECK_EQ(identity.high(), static_cast<std::uint32_t>(value >> 32U));
    DF_CHECK_EQ(identity.low(), static_cast<std::uint32_t>(value & 0xFFFFFFFFULL));
    DF_CHECK_EQ(AssetId::FromParts(identity.high(), identity.low()).value(), value);
    // The hi/lo codec is checked on other 64-bit identities too, so a copy in
    // one type cannot drift from another.
    DF_CHECK_EQ(PlanId::FromParts(identity.high(), identity.low()).value(), value);
    DF_CHECK_EQ(Revision::FromParts(identity.high(), identity.low()).value(), value);
    DF_CHECK_EQ(ObservationSequence::FromParts(identity.high(), identity.low()).value(), value);
    DF_CHECK_EQ(CommitSequence::FromParts(identity.high(), identity.low()).to_hex(),
                identity.to_hex());
  }

  DF_CHECK_EQ(AssetId::FromValue(0x0123456789ABCDEFULL).high(), std::uint32_t{0x01234567U});
  DF_CHECK_EQ(AssetId::FromValue(0x0123456789ABCDEFULL).low(), std::uint32_t{0x89ABCDEFU});
  DF_CHECK_EQ(AssetId::FromParts(0x01234567U, 0x89ABCDEFU).value(), 0x0123456789ABCDEFULL);
  DF_CHECK_EQ(AssetId::FromParts(0U, 0U).value(), std::uint64_t{0});
  DF_CHECK_EQ(AssetId::FromParts(0U, 0U).is_unset(), true);
  DF_CHECK_EQ(AssetId::FromParts(0xFFFFFFFFU, 0xFFFFFFFFU).value(), kU64Max);

  // A 32-bit generation keeps its own width: the high half is always zero and
  // FromParts(0, low) returns the same value.
  const FacilityEpoch epoch = FacilityEpoch::FromValue(0x89ABCDEFU);
  DF_CHECK_EQ(epoch.high(), std::uint32_t{0});
  DF_CHECK_EQ(epoch.low(), std::uint32_t{0x89ABCDEFU});
  DF_CHECK_EQ(FacilityEpoch::FromParts(0U, epoch.low()).value(), std::uint32_t{0x89ABCDEFU});
  DF_CHECK_EQ(FacilityEpoch::FromParts(0U, kU32Max).value(), kU32Max);
}

DF_TEST(Ids_OrderingAgreesWithTheUnderlyingIntegers) {
  const AssetId ordered[] = {
      AssetId::FromValue(0),
      AssetId::FromValue(1),
      AssetId::FromValue(2),
      AssetId::FromValue(0x00000000FFFFFFFFULL),
      AssetId::FromValue(0x0000000100000000ULL),
      AssetId::FromValue(0x7FFFFFFFFFFFFFFFULL),
      AssetId::FromValue(0x8000000000000000ULL),
      AssetId::Max(),
  };
  const std::size_t count = sizeof(ordered) / sizeof(ordered[0]);
  for (std::size_t i = 0; i < count; ++i) {
    for (std::size_t j = 0; j < count; ++j) {
      const AssetId& lhs = ordered[i];
      const AssetId& rhs = ordered[j];
      DF_CHECK_EQ(lhs == rhs, lhs.value() == rhs.value());
      DF_CHECK_EQ(lhs != rhs, lhs.value() != rhs.value());
      DF_CHECK_EQ(lhs < rhs, lhs.value() < rhs.value());
      DF_CHECK_EQ(lhs > rhs, lhs.value() > rhs.value());
      DF_CHECK_EQ(lhs <= rhs, lhs.value() <= rhs.value());
      DF_CHECK_EQ(lhs >= rhs, lhs.value() >= rhs.value());
      DF_CHECK_EQ((lhs <=> rhs) == std::strong_ordering::less, lhs.value() < rhs.value());
      DF_CHECK_EQ((lhs <=> rhs) == std::strong_ordering::equal, lhs.value() == rhs.value());
      DF_CHECK_EQ((lhs <=> rhs) == std::strong_ordering::greater, lhs.value() > rhs.value());
    }
  }

  // Ordering is by value, not by object identity: two equal identities from
  // different construction paths compare equal.
  DF_CHECK(AssetId::FromParts(0U, 7U) == AssetId::FromValue(7));
  DF_CHECK(!(AssetId::FromValue(7) < AssetId::FromParts(0U, 7U)));
  DF_CHECK(AssetId::Max() > AssetId::First());
  DF_CHECK(FacilityEpoch::FromValue(2) > FacilityEpoch::FromValue(1));
}

DF_TEST(Ids_MapAndSetOrderKeysByIdentityValue) {
  std::map<AssetId, std::string> by_asset;
  by_asset[AssetId::FromValue(0x0000000100000000ULL)] = "high-word";
  by_asset[AssetId::FromValue(2)] = "two";
  by_asset[AssetId::FromValue(1)] = "one";
  by_asset[AssetId::Max()] = "max";
  by_asset[AssetId::FromValue(0x00000000FFFFFFFFULL)] = "low-word";
  DF_CHECK_EQ(by_asset.size(), std::size_t{5});

  const std::uint64_t expected_order[] = {1ULL, 2ULL, 0x00000000FFFFFFFFULL,
                                          0x0000000100000000ULL, kU64Max};
  std::size_t index = 0;
  for (const auto& entry : by_asset) {
    DF_CHECK_MSG(index < 5U, "the map yielded more keys than were inserted");
    if (index < 5U) {
      DF_CHECK_EQ(entry.first.value(), expected_order[index]);
    }
    ++index;
  }
  DF_CHECK_EQ(index, std::size_t{5});

  DF_CHECK_EQ(by_asset.at(AssetId::FromValue(2)), std::string("two"));
  DF_CHECK_EQ(by_asset.at(AssetId::Max()), std::string("max"));
  DF_CHECK(by_asset.find(AssetId::FromValue(3)) == by_asset.end());
  DF_CHECK(by_asset.find(AssetId::Max()) != by_asset.end());

  std::set<PlanId> plans;
  DF_CHECK(plans.insert(PlanId::FromValue(5)).second);
  DF_CHECK(!plans.insert(PlanId::FromValue(5)).second);
  DF_CHECK(plans.insert(PlanId::FromValue(1)).second);
  DF_CHECK(plans.insert(PlanId::FromValue(kU64Max)).second);
  DF_CHECK_EQ(plans.size(), std::size_t{3});
  DF_CHECK_EQ(plans.begin()->value(), std::uint64_t{1});
  DF_CHECK_EQ(plans.rbegin()->value(), kU64Max);
  DF_CHECK(plans.count(PlanId::FromValue(5)) == std::size_t{1});
  DF_CHECK(plans.count(PlanId::FromValue(6)) == std::size_t{0});
}

DF_TEST(Ids_StdHashMatchesTheUnderlyingValueHash) {
  const std::uint64_t samples[] = {0ULL, 1ULL, 42ULL, 0x0123456789ABCDEFULL,
                                   0x0000000100000000ULL, kU64Max};
  for (const std::uint64_t value : samples) {
    DF_CHECK_EQ(std::hash<AssetId>{}(AssetId::FromValue(value)),
                std::hash<std::uint64_t>{}(value));
    DF_CHECK_EQ(std::hash<PlanId>{}(PlanId::FromValue(value)),
                std::hash<std::uint64_t>{}(value));
    DF_CHECK_EQ(std::hash<Revision>{}(Revision::FromValue(value)),
                std::hash<std::uint64_t>{}(value));
    DF_CHECK_EQ(std::hash<ObservationSequence>{}(ObservationSequence::FromValue(value)),
                std::hash<std::uint64_t>{}(value));
    DF_CHECK_EQ(std::hash<CommitSequence>{}(CommitSequence::FromValue(value)),
                std::hash<std::uint64_t>{}(value));
    DF_CHECK_EQ(std::hash<RackId>{}(RackId::FromValue(value)), std::hash<std::uint64_t>{}(value));
  }

  const std::uint32_t epochs[] = {0U, 1U, 0x01234567U, kU32Max};
  for (const std::uint32_t value : epochs) {
    DF_CHECK_EQ(std::hash<FacilityEpoch>{}(FacilityEpoch::FromValue(value)),
                std::hash<std::uint32_t>{}(value));
    DF_CHECK_EQ(std::hash<LifecycleGeneration>{}(LifecycleGeneration::FromValue(value)),
                std::hash<std::uint32_t>{}(value));
  }

  // Equal identities hash equally, so unordered containers deduplicate them.
  std::unordered_set<ObservationSequence> seen;
  DF_CHECK(seen.insert(ObservationSequence::FromValue(7)).second);
  DF_CHECK(!seen.insert(ObservationSequence::FromValue(7)).second);
  DF_CHECK(!seen.insert(ObservationSequence::FromParts(0U, 7U)).second);
  DF_CHECK(seen.insert(ObservationSequence::FromValue(8)).second);
  DF_CHECK_EQ(seen.size(), std::size_t{2});
  DF_CHECK(seen.count(ObservationSequence::FromValue(7)) == std::size_t{1});
  DF_CHECK(seen.count(ObservationSequence::FromValue(9)) == std::size_t{0});
}

DF_TEST_MAIN()

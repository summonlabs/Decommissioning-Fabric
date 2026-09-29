// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Proof obligations for include/decommissioning_fabric/time.hpp.
//
// The claims under test: the ISO 8601 rendering is exact, proleptic Gregorian,
// correct for sub-second values and for pre-epoch instants, and always
// millisecond precision; the manual clock does not move on its own and moves by
// exactly the requested amount; and the host clock produces a set,
// non-decreasing wall-clock reading.

#include <cstddef>
#include <cstdint>
#include <string>

#include "decommissioning_fabric/time.hpp"
#include "harness.hpp"

namespace {

using decommissioning_fabric::kNanosPerMillisecond;
using decommissioning_fabric::kNanosPerSecond;
using decommissioning_fabric::ManualClock;
using decommissioning_fabric::MonotonicCounter;
using decommissioning_fabric::SystemClock;
using decommissioning_fabric::Timestamp;

constexpr std::int64_t k2024LeapDayNoon = 1709210096789000000LL;  // 2024-02-29T12:34:56.789Z

}  // namespace

DF_TEST(Time_Iso8601RendersTheUnixEpoch) {
  const Timestamp epoch{0};
  DF_CHECK(!epoch.is_set());
  DF_CHECK_EQ(epoch.unix_nanos, std::int64_t{0});
  DF_CHECK_EQ(epoch.to_iso8601_utc(), std::string("1970-01-01T00:00:00.000Z"));
  DF_CHECK_EQ(epoch.to_iso8601_utc().size(), std::size_t{24});
}

DF_TEST(Time_Iso8601RendersKnownInstants) {
  // The manual clock's fixed start: 2026-01-01T00:00:00Z.
  const Timestamp new_year{ManualClock::kDefaultStartNanos};
  DF_CHECK(new_year.is_set());
  DF_CHECK_EQ(new_year.to_iso8601_utc(), std::string("2026-01-01T00:00:00.000Z"));

  // The last second of 1999, a known UTC instant.
  const Timestamp y2k{946684799000000000LL};
  DF_CHECK_EQ(y2k.to_iso8601_utc(), std::string("1999-12-31T23:59:59.000Z"));

  const Timestamp millenium{946684800000000000LL};
  DF_CHECK_EQ(millenium.to_iso8601_utc(), std::string("2000-01-01T00:00:00.000Z"));

  // 2000 is a leap year: 29 February exists.
  const Timestamp leap_2000{951782400000000000LL};
  DF_CHECK_EQ(leap_2000.to_iso8601_utc(), std::string("2000-02-29T00:00:00.000Z"));
}

DF_TEST(Time_Iso8601RendersTheLeapDay20240229) {
  const Timestamp leap_day{k2024LeapDayNoon};
  DF_CHECK_EQ(leap_day.to_iso8601_utc(), std::string("2024-02-29T12:34:56.789Z"));

  const Timestamp start_of_leap_day{1709164800000000000LL};
  DF_CHECK_EQ(start_of_leap_day.to_iso8601_utc(), std::string("2024-02-29T00:00:00.000Z"));

  const Timestamp end_of_leap_day{1709251199999000000LL};
  DF_CHECK_EQ(end_of_leap_day.to_iso8601_utc(), std::string("2024-02-29T23:59:59.999Z"));

  // The day after a leap day is 1 March, not 29 February again.
  const Timestamp march_first{1709251200000000000LL};
  DF_CHECK_EQ(march_first.to_iso8601_utc(), std::string("2024-03-01T00:00:00.000Z"));
}

DF_TEST(Time_Iso8601RendersPreEpochInstants) {
  const Timestamp one_second_before{ -kNanosPerSecond};
  DF_CHECK_EQ(one_second_before.to_iso8601_utc(), std::string("1969-12-31T23:59:59.000Z"));

  const Timestamp one_nano_before{-1LL};
  DF_CHECK_EQ(one_nano_before.to_iso8601_utc(), std::string("1969-12-31T23:59:59.999Z"));

  const Timestamp start_of_1969{-31536000000000000LL};
  DF_CHECK_EQ(start_of_1969.to_iso8601_utc(), std::string("1969-01-01T00:00:00.000Z"));

  const Timestamp apollo{ -14182940000000000LL};
  DF_CHECK_EQ(apollo.to_iso8601_utc(), std::string("1969-07-20T20:17:40.000Z"));

  // Ordering is by nanoseconds, so a pre-epoch instant is behind the epoch.
  DF_CHECK(one_second_before < Timestamp{0});
  DF_CHECK(one_nano_before > one_second_before);
}

DF_TEST(Time_Iso8601KeepsMillisecondPrecisionAndTruncatesBelowIt) {
  const Timestamp one_millisecond{kNanosPerMillisecond};
  DF_CHECK_EQ(one_millisecond.to_iso8601_utc(), std::string("1970-01-01T00:00:00.001Z"));

  const Timestamp one_millisecond_less_one{999999LL};
  DF_CHECK_EQ(one_millisecond_less_one.to_iso8601_utc(),
              std::string("1970-01-01T00:00:00.000Z"));

  const Timestamp sub_millisecond{k2024LeapDayNoon + 123456LL};
  DF_CHECK_EQ(sub_millisecond.to_iso8601_utc(), std::string("2024-02-29T12:34:56.789Z"));

  const Timestamp millisecond_boundary{k2024LeapDayNoon - 789000000LL};
  DF_CHECK_EQ(millisecond_boundary.to_iso8601_utc(),
              std::string("2024-02-29T12:34:56.000Z"));

  // Just before the epoch the millisecond is the floor of the instant, not a
  // remainder truncated towards zero: -1 ms is the last millisecond of 1969.
  DF_CHECK_EQ(Timestamp{ -kNanosPerMillisecond}.to_iso8601_utc(),
              std::string("1969-12-31T23:59:59.999Z"));
  DF_CHECK_EQ(Timestamp{ -kNanosPerMillisecond - 1000000LL}.to_iso8601_utc(),
              std::string("1969-12-31T23:59:59.998Z"));
  DF_CHECK_EQ(Timestamp{ -999999LL}.to_iso8601_utc(),
              std::string("1969-12-31T23:59:59.999Z"));
  DF_CHECK_EQ(Timestamp{ -1000001LL}.to_iso8601_utc(),
              std::string("1969-12-31T23:59:59.998Z"));
}

DF_TEST(Time_ManualClockIsStableUntilItIsMoved) {
  ManualClock clock;
  DF_CHECK_EQ(clock.Now().unix_nanos, ManualClock::kDefaultStartNanos);
  DF_CHECK_EQ(clock.Now().unix_nanos, ManualClock::kDefaultStartNanos);
  DF_CHECK(clock.Now().is_set());
  DF_CHECK_EQ(clock.Now().to_iso8601_utc(), std::string("2026-01-01T00:00:00.000Z"));

  // Repeated reads never advance time on their own.
  const std::int64_t before = clock.Now().unix_nanos;
  for (int read = 0; read < 16; ++read) {
    DF_CHECK_EQ(clock.Now().unix_nanos, before);
  }
  DF_CHECK_EQ(before, ManualClock::kDefaultStartNanos);

  ManualClock custom(1234567890123456789LL);
  DF_CHECK_EQ(custom.Now().unix_nanos, 1234567890123456789LL);
  DF_CHECK_EQ(custom.Now().unix_nanos, custom.Now().unix_nanos);
}

DF_TEST(Time_ManualClockAdvanceIsExact) {
  ManualClock clock;
  const std::int64_t start = ManualClock::kDefaultStartNanos;

  clock.Advance(kNanosPerMillisecond);
  DF_CHECK_EQ(clock.Now().unix_nanos, start + kNanosPerMillisecond);
  DF_CHECK_EQ(clock.Now().to_iso8601_utc(), std::string("2026-01-01T00:00:00.001Z"));

  clock.Advance(3661000000000LL);  // one hour, one minute, one second
  DF_CHECK_EQ(clock.Now().unix_nanos, start + kNanosPerMillisecond + 3661000000000LL);
  DF_CHECK_EQ(clock.Now().to_iso8601_utc(), std::string("2026-01-01T01:01:01.001Z"));

  // Advancing by zero changes nothing, and a negative advance is exact too.
  clock.Advance(0);
  DF_CHECK_EQ(clock.Now().to_iso8601_utc(), std::string("2026-01-01T01:01:01.001Z"));
  clock.Advance(-1LL);
  DF_CHECK_EQ(clock.Now().unix_nanos, start + kNanosPerMillisecond + 3661000000000LL - 1LL);
  DF_CHECK_EQ(clock.Now().to_iso8601_utc(), std::string("2026-01-01T01:01:01.000Z"));

  // A large step forward lands on the exact instant requested.
  clock.Set(1709210096789000000LL);
  DF_CHECK_EQ(clock.Now().unix_nanos, k2024LeapDayNoon);
  DF_CHECK_EQ(clock.Now().to_iso8601_utc(), std::string("2024-02-29T12:34:56.789Z"));
  clock.Advance(211000000LL);
  DF_CHECK_EQ(clock.Now().to_iso8601_utc(), std::string("2024-02-29T12:34:57.000Z"));
  DF_CHECK_EQ(clock.Now().unix_nanos, k2024LeapDayNoon + 211000000LL);

  // Set() pins the clock exactly, including back to zero and before the epoch.
  clock.Set(ManualClock::kDefaultStartNanos);
  DF_CHECK_EQ(clock.Now().unix_nanos, ManualClock::kDefaultStartNanos);
  clock.Set(0);
  DF_CHECK_EQ(clock.Now().unix_nanos, std::int64_t{0});
  DF_CHECK(!clock.Now().is_set());
  DF_CHECK_EQ(clock.Now().to_iso8601_utc(), std::string("1970-01-01T00:00:00.000Z"));
  clock.Set(-kNanosPerSecond);
  DF_CHECK_EQ(clock.Now().to_iso8601_utc(), std::string("1969-12-31T23:59:59.000Z"));
}

DF_TEST(Time_SystemClockReturnsASetNonDecreasingReading) {
  SystemClock clock;
  const Timestamp first = clock.Now();
  const Timestamp second = clock.Now();

  DF_CHECK_MSG(first.is_set(), "the host wall clock must report a non-zero instant");
  DF_CHECK_NE(first.unix_nanos, std::int64_t{0});
  DF_CHECK(second.is_set());
  DF_CHECK_MSG(second.unix_nanos >= first.unix_nanos,
               "two consecutive host clock reads must be non-decreasing");

  const std::string rendered = first.to_iso8601_utc();
  DF_CHECK_EQ(rendered.size(), std::size_t{24});
  DF_CHECK_EQ(rendered.back(), 'Z');
  DF_CHECK_EQ(rendered[4], '-');
  DF_CHECK_EQ(rendered[10], 'T');
  DF_CHECK_EQ(rendered[19], '.');
  // A host clock in this century renders a 20xx year; the format is fixed width
  // so a misplaced field would change the length or the separators above.
  DF_CHECK(rendered.compare(0, 2, "20") == 0);

  const Timestamp third = clock.Now();
  DF_CHECK(third.unix_nanos >= second.unix_nanos);
}

DF_TEST(Time_MonotonicCounterIsNonDecreasing) {
  const std::int64_t first = MonotonicCounter::NowNanos();
  const std::int64_t second = MonotonicCounter::NowNanos();
  DF_CHECK_MSG(second >= first, "steady-clock readings must be non-decreasing");
}

DF_TEST_MAIN()

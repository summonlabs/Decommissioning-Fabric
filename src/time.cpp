// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0

#include "decommissioning_fabric/time.hpp"

#include <chrono>
#include <cstdio>

namespace decommissioning_fabric {
namespace {

struct CivilDate {
  std::int64_t year;
  unsigned month;
  unsigned day;
};

/// Howard Hinnant's civil-from-days algorithm. Valid for the whole range of
/// std::int64_t days; returns a proleptic Gregorian date.
[[nodiscard]] CivilDate CivilFromDays(std::int64_t z) noexcept {
  z += 719468;
  const std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  const std::int64_t doe = z - era * 146097;
  const std::int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  const std::int64_t y = yoe + era * 400;
  const std::int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  const std::int64_t mp = (5 * doy + 2) / 153;
  const std::int64_t d = doy - (153 * mp + 2) / 5 + 1;
  const std::int64_t m = mp + (mp < 10 ? 3 : -9);
  return CivilDate{y + (m <= 2 ? 1 : 0), static_cast<unsigned>(m), static_cast<unsigned>(d)};
}

[[nodiscard]] std::int64_t FloorDiv(std::int64_t numerator, std::int64_t denominator) noexcept {
  const std::int64_t quotient = numerator / denominator;
  const std::int64_t remainder = numerator % denominator;
  return (remainder != 0 && ((remainder < 0) != (denominator < 0))) ? quotient - 1 : quotient;
}

}  // namespace

std::string Timestamp::to_iso8601_utc() const {
  const std::int64_t seconds = FloorDiv(unix_nanos, kNanosPerSecond);
  const std::int64_t sub_nanos = unix_nanos - (seconds * kNanosPerSecond);
  const std::int64_t days = FloorDiv(seconds, 86400);
  const std::int64_t second_of_day = seconds - (days * 86400);
  const std::int64_t millis = sub_nanos / kNanosPerMillisecond;

  const CivilDate date = CivilFromDays(days);
  const std::int64_t hour = second_of_day / 3600;
  const std::int64_t minute = (second_of_day % 3600) / 60;
  const std::int64_t second = second_of_day % 60;

  char buffer[48];
  const int written = std::snprintf(buffer, sizeof(buffer), "%04lld-%02u-%02uT%02lld:%02lld:%02lld.%03lldZ",
                                    static_cast<long long>(date.year), date.month, date.day,
                                    static_cast<long long>(hour), static_cast<long long>(minute),
                                    static_cast<long long>(second), static_cast<long long>(millis));
  if (written <= 0) {
    return std::string();
  }
  return std::string(buffer, static_cast<std::size_t>(written));
}

std::int64_t MonotonicCounter::NowNanos() noexcept {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
}

Clock::~Clock() = default;

Timestamp SystemClock::Now() const {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  return Timestamp{std::chrono::duration_cast<std::chrono::nanoseconds>(now).count()};
}

ManualClock::ManualClock(std::int64_t start_nanos) noexcept : now_nanos_(start_nanos) {}

Timestamp ManualClock::Now() const {
  return Timestamp{now_nanos_};
}

void ManualClock::Advance(std::int64_t nanos) noexcept {
  now_nanos_ += nanos;
}

void ManualClock::Set(std::int64_t nanos) noexcept {
  now_nanos_ = nanos;
}

}  // namespace decommissioning_fabric

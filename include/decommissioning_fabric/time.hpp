// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Time is evidence metadata, never an ordering authority.
//
// Nothing in this repository decides which of two observations is newer by
// comparing wall-clock timestamps. Ordering is carried by ObservationSequence
// and CommitSequence, which are monotonic and durable. Timestamps exist so that
// a human reading a report can see when something was recorded, and so that
// expired evidence can be recognised. A clock that moves backwards therefore
// cannot reorder or invalidate anything.

#ifndef DECOMMISSIONING_FABRIC_TIME_HPP
#define DECOMMISSIONING_FABRIC_TIME_HPP

#include <cstdint>
#include <string>

namespace decommissioning_fabric {

inline constexpr std::int64_t kNanosPerSecond = 1000000000LL;
inline constexpr std::int64_t kNanosPerMillisecond = 1000000LL;

/// A point in time expressed as nanoseconds since the Unix epoch, UTC.
struct Timestamp {
  std::int64_t unix_nanos{0};

  [[nodiscard]] constexpr bool is_set() const noexcept { return unix_nanos != 0; }

  /// RFC 3339 / ISO 8601 UTC rendering with millisecond precision, always
  /// ending in 'Z'. Deterministic and locale independent.
  [[nodiscard]] std::string to_iso8601_utc() const;

  friend constexpr bool operator==(const Timestamp& lhs, const Timestamp& rhs) noexcept {
    return lhs.unix_nanos == rhs.unix_nanos;
  }
  friend constexpr auto operator<=>(const Timestamp& lhs, const Timestamp& rhs) noexcept {
    return lhs.unix_nanos <=> rhs.unix_nanos;
  }
};

/// Monotonic elapsed time source. Used for benchmark reporting only; it is
/// never persisted and never compared against wall-clock timestamps.
class MonotonicCounter {
 public:
  [[nodiscard]] static std::int64_t NowNanos() noexcept;
};

/// Injected wall-clock source. Every component that records a timestamp takes a
/// Clock reference so that a test can pin time and produce a byte-identical
/// durable generation across runs.
class Clock {
 public:
  Clock() = default;
  virtual ~Clock();
  Clock(const Clock&) = delete;
  Clock& operator=(const Clock&) = delete;
  Clock(Clock&&) = delete;
  Clock& operator=(Clock&&) = delete;

  [[nodiscard]] virtual Timestamp Now() const = 0;
};

/// The host wall clock.
class SystemClock final : public Clock {
 public:
  SystemClock() = default;
  [[nodiscard]] Timestamp Now() const override;
};

/// A clock that only moves when a test moves it. Starts at a fixed, non-zero,
/// round value so persisted fixtures are reproducible.
class ManualClock final : public Clock {
 public:
  static constexpr std::int64_t kDefaultStartNanos = 1767225600000000000LL;  // 2026-01-01T00:00:00Z

  explicit ManualClock(std::int64_t start_nanos = kDefaultStartNanos) noexcept;

  [[nodiscard]] Timestamp Now() const override;
  void Advance(std::int64_t nanos) noexcept;
  void Set(std::int64_t nanos) noexcept;

 private:
  std::int64_t now_nanos_;
};

}  // namespace decommissioning_fabric

#endif  // DECOMMISSIONING_FABRIC_TIME_HPP

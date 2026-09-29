// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Strong identities and generations.
//
// Every identity and counter below is a distinct C++ type. Confusing an
// AssetId with a RackId, or a HardwareGeneration with a PolicyGeneration, is a
// compile error rather than a production incident. There are no implicit
// conversions to the underlying integer and no implicit construction from one.

#ifndef DECOMMISSIONING_FABRIC_IDS_HPP
#define DECOMMISSIONING_FABRIC_IDS_HPP

#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>

#include "decommissioning_fabric/hash.hpp"

namespace decommissioning_fabric {

/// Common interface implemented by every strong identity and strong counter.
template <typename Derived, typename Underlying>
class StrongValue {
 public:
  using underlying_type = Underlying;

  constexpr StrongValue() noexcept = default;
  constexpr explicit StrongValue(Underlying value) noexcept : value_(value) {}

  /// The raw integer. Named explicitly so call sites read as a deliberate
  /// unwrapping rather than an accidental conversion.
  [[nodiscard]] constexpr Underlying value() const noexcept { return value_; }

  /// True when the value is the type's identity element (zero). Zero is never
  /// a valid identity and never a valid generation; callers must decide what
  /// to do about that rather than defaulting it to something benign.
  [[nodiscard]] constexpr bool is_unset() const noexcept { return value_ == Underlying{0}; }

  /// True when the value is set (non-zero).
  [[nodiscard]] constexpr bool is_set() const noexcept { return value_ != Underlying{0}; }

  /// Zero-padded lowercase hexadecimal, 16 digits. Used for persistence and
  /// for CLI rendering; deterministic and locale independent.
  [[nodiscard]] std::string to_hex() const {
    return detail::to_hex_fixed(static_cast<std::uint64_t>(value_), 16);
  }

  /// High 32 bits of the 64-bit representation. Used by the line-oriented
  /// record codec, which stores identities as a hi/lo pair so the durable
  /// format does not depend on host endianness.
  [[nodiscard]] constexpr std::uint32_t high() const noexcept {
    return static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(value_) >> 32U) & 0xFFFFFFFFULL);
  }

  /// Low 32 bits of the 64-bit representation.
  [[nodiscard]] constexpr std::uint32_t low() const noexcept {
    return static_cast<std::uint32_t>(static_cast<std::uint64_t>(value_) & 0xFFFFFFFFULL);
  }

  [[nodiscard]] static constexpr Derived FromParts(std::uint32_t hi, std::uint32_t lo) noexcept {
    const std::uint64_t combined = (static_cast<std::uint64_t>(hi) << 32U) |
                                   static_cast<std::uint64_t>(lo);
    return Derived{static_cast<Underlying>(combined)};
  }

  // -------------------------------------------------------------------------
  // Monotonic allocation helpers. Identities and counters both need them: a
  // PlanId is allocated by advancing a durable counter, and an identity that
  // wrapped onto an already-used value would silently resurrect fenced-out
  // authority.
  // -------------------------------------------------------------------------

  /// The first value the domain considers valid. Zero is never an identity.
  [[nodiscard]] static constexpr Derived First() noexcept { return Derived{Underlying{1}}; }

  [[nodiscard]] static constexpr Derived Max() noexcept {
    return Derived{std::numeric_limits<Underlying>::max()};
  }

  [[nodiscard]] constexpr bool at_max() const noexcept {
    return value_ == std::numeric_limits<Underlying>::max();
  }

  /// Saturating successor: never wraps. Callers that must not lose a fence use
  /// SuccessorChecked, or check at_max first.
  [[nodiscard]] constexpr Derived Next() const noexcept {
    if (at_max()) {
      return static_cast<const Derived&>(*this);
    }
    return Derived{static_cast<Underlying>(value_ + Underlying{1})};
  }

  /// Exact successor: throws rather than wrapping, so a caller cannot silently
  /// reuse an identity.
  [[nodiscard]] Derived SuccessorChecked() const {
    if (at_max()) {
      throw std::overflow_error("strong value overflow");
    }
    return Derived{static_cast<Underlying>(value_ + Underlying{1})};
  }

  [[nodiscard]] constexpr Derived Prev() const noexcept {
    if (value_ == Underlying{0}) {
      return static_cast<const Derived&>(*this);
    }
    return Derived{static_cast<Underlying>(value_ - Underlying{1})};
  }

  [[nodiscard]] friend constexpr auto operator<=>(const StrongValue&,
                                                  const StrongValue&) noexcept = default;
  [[nodiscard]] friend constexpr bool operator==(const StrongValue&,
                                                 const StrongValue&) noexcept = default;

  [[nodiscard]] friend constexpr bool operator<(const StrongValue& lhs,
                                                const StrongValue& rhs) noexcept {
    return lhs.value_ < rhs.value_;
  }

 protected:
  Underlying value_{0};
};

/// Declares a strong identity type.
///
///   DF_STRONG_ID(AssetId, std::uint64_t)
#define DF_STRONG_ID(TypeName, Underlying)                                     \
  class TypeName : public ::decommissioning_fabric::StrongValue<TypeName, Underlying> { \
   public:                                                                     \
    using Base = ::decommissioning_fabric::StrongValue<TypeName, Underlying>;  \
    using Base::Base;                                                          \
    constexpr TypeName() noexcept = default;                                   \
    [[nodiscard]] static constexpr TypeName FromValue(Underlying v) noexcept { \
      return TypeName{v};                                                      \
    }                                                                          \
  }

/// Declares a strong monotonic counter / generation type.
///
/// A counter is a strong identity with a monotonic-allocation contract: it is
/// only ever advanced, never reused, and never wrapped. The allocation helpers
/// live on StrongValue, so an identity and a counter carry exactly the same
/// arithmetic and differ only in what they mean.
#define DF_STRONG_COUNTER(TypeName, Underlying) \
  DF_STRONG_ID(TypeName, Underlying)

// ---------------------------------------------------------------------------
// Physical facility identities
// ---------------------------------------------------------------------------

DF_STRONG_ID(AssetId, std::uint64_t);
DF_STRONG_ID(RackId, std::uint64_t);
DF_STRONG_ID(SiteId, std::uint64_t);
DF_STRONG_ID(TenantId, std::uint64_t);
DF_STRONG_ID(ServiceClassId, std::uint64_t);

// ---------------------------------------------------------------------------
// Plan / request identities
// ---------------------------------------------------------------------------

DF_STRONG_ID(PlanId, std::uint64_t);
DF_STRONG_ID(AttemptId, std::uint64_t);
DF_STRONG_ID(EvidenceId, std::uint64_t);
DF_STRONG_ID(ReceiptId, std::uint64_t);
DF_STRONG_ID(ObligationId, std::uint64_t);
DF_STRONG_ID(ResidualItemId, std::uint64_t);
DF_STRONG_ID(ExceptionId, std::uint64_t);
DF_STRONG_ID(IncarnationId, std::uint64_t);
DF_STRONG_ID(ObserverId, std::uint64_t);

// ---------------------------------------------------------------------------
// Counters and generations
// ---------------------------------------------------------------------------

DF_STRONG_COUNTER(Revision, std::uint64_t);
DF_STRONG_COUNTER(LifecycleGeneration, std::uint32_t);
DF_STRONG_COUNTER(HardwareGeneration, std::uint32_t);
DF_STRONG_COUNTER(FirmwareGeneration, std::uint32_t);
DF_STRONG_COUNTER(ControlEpoch, std::uint32_t);
DF_STRONG_COUNTER(FacilityEpoch, std::uint32_t);
DF_STRONG_COUNTER(PolicyGeneration, std::uint32_t);
DF_STRONG_COUNTER(DependencyGeneration, std::uint32_t);
DF_STRONG_COUNTER(CapacityGeneration, std::uint32_t);
DF_STRONG_COUNTER(TopologyGeneration, std::uint32_t);
DF_STRONG_COUNTER(MaintenanceGeneration, std::uint32_t);
DF_STRONG_COUNTER(ObservationSequence, std::uint64_t);
DF_STRONG_COUNTER(CommitSequence, std::uint64_t);
DF_STRONG_COUNTER(PlanSequence, std::uint64_t);
DF_STRONG_COUNTER(EvidenceSequence, std::uint64_t);

/// Identifies the retirement attempt for a single asset. An asset that is
/// partially retired, cancelled, and re-planned carries an incremented
/// lifecycle generation, which fences every artifact of the previous attempt.
using RetirementGeneration = LifecycleGeneration;

// ---------------------------------------------------------------------------
// std::hash specialisations: hashing the underlying value keeps unordered
// containers consistent with the explicit operator==. The macro is invoked with
// the UNQUALIFIED type name because it supplies the namespace itself.
// ---------------------------------------------------------------------------

}  // namespace decommissioning_fabric

#define DF_HASH_SPECIALISATION(TypeName)                                   \
  template <>                                                              \
  struct hash<::decommissioning_fabric::TypeName> {                        \
    [[nodiscard]] std::size_t operator()(                                  \
        const ::decommissioning_fabric::TypeName& v) const noexcept {      \
      using U = ::decommissioning_fabric::TypeName::underlying_type;       \
      return std::hash<U>{}(v.value());                                    \
    }                                                                      \
  };

namespace std {

DF_HASH_SPECIALISATION(AssetId)
DF_HASH_SPECIALISATION(RackId)
DF_HASH_SPECIALISATION(SiteId)
DF_HASH_SPECIALISATION(TenantId)
DF_HASH_SPECIALISATION(ServiceClassId)
DF_HASH_SPECIALISATION(PlanId)
DF_HASH_SPECIALISATION(AttemptId)
DF_HASH_SPECIALISATION(EvidenceId)
DF_HASH_SPECIALISATION(ReceiptId)
DF_HASH_SPECIALISATION(ObligationId)
DF_HASH_SPECIALISATION(ResidualItemId)
DF_HASH_SPECIALISATION(ExceptionId)
DF_HASH_SPECIALISATION(IncarnationId)
DF_HASH_SPECIALISATION(ObserverId)
DF_HASH_SPECIALISATION(Revision)
DF_HASH_SPECIALISATION(LifecycleGeneration)
DF_HASH_SPECIALISATION(HardwareGeneration)
DF_HASH_SPECIALISATION(FirmwareGeneration)
DF_HASH_SPECIALISATION(ControlEpoch)
DF_HASH_SPECIALISATION(FacilityEpoch)
DF_HASH_SPECIALISATION(PolicyGeneration)
DF_HASH_SPECIALISATION(DependencyGeneration)
DF_HASH_SPECIALISATION(CapacityGeneration)
DF_HASH_SPECIALISATION(TopologyGeneration)
DF_HASH_SPECIALISATION(MaintenanceGeneration)
DF_HASH_SPECIALISATION(ObservationSequence)
DF_HASH_SPECIALISATION(CommitSequence)
DF_HASH_SPECIALISATION(PlanSequence)
DF_HASH_SPECIALISATION(EvidenceSequence)

}  // namespace std

#undef DF_HASH_SPECIALISATION

#endif  // DECOMMISSIONING_FABRIC_IDS_HPP

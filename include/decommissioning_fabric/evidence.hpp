// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Observation evidence.
//
// Evidence is a RECORD OF A REPORT. This runtime never performs the thing being
// reported: it does not migrate workloads, open breakers, move air, or erase
// media. An EvidenceRef therefore carries who reported it, what they called it,
// and when this runtime recorded the report. Evidence is the only input that can
// satisfy an obligation, and evidence can never set a lifecycle phase directly:
// only a Decision produced by the engine mutates phase.

#ifndef DECOMMISSIONING_FABRIC_EVIDENCE_HPP
#define DECOMMISSIONING_FABRIC_EVIDENCE_HPP

#include <cstdint>
#include <string>
#include <string_view>

#include "decommissioning_fabric/ids.hpp"
#include "decommissioning_fabric/obligations.hpp"
#include "decommissioning_fabric/time.hpp"

namespace decommissioning_fabric {

enum class EvidenceKind : std::uint32_t {
  unknown = 0,
  dependency_assessment = 1,
  drain_request_acknowledgement = 2,
  drain_satisfaction = 3,
  authority_revocation = 4,
  residual_disposition = 5,
  policy_exception = 6,
  isolation_observation = 7,
  removal_authorization = 8,
  removal_observation = 9,
};

[[nodiscard]] constexpr std::string_view ToString(EvidenceKind kind) noexcept {
  switch (kind) {
    case EvidenceKind::unknown: return "unknown";
    case EvidenceKind::dependency_assessment: return "dependency_assessment";
    case EvidenceKind::drain_request_acknowledgement: return "drain_request_acknowledgement";
    case EvidenceKind::drain_satisfaction: return "drain_satisfaction";
    case EvidenceKind::authority_revocation: return "authority_revocation";
    case EvidenceKind::residual_disposition: return "residual_disposition";
    case EvidenceKind::policy_exception: return "policy_exception";
    case EvidenceKind::isolation_observation: return "isolation_observation";
    case EvidenceKind::removal_authorization: return "removal_authorization";
    case EvidenceKind::removal_observation: return "removal_observation";
  }
  return "unknown";
}

/// Who produced the report.
///
/// Only external_authority evidence can satisfy an obligation. runtime_self
/// evidence records something this process observed about itself (for example
/// that a durable commit landed) and is explicitly NOT accepted where an
/// external authority's report is required, so a runtime observation can never
/// masquerade as a facility action.
enum class EvidenceProvenance : std::uint32_t {
  unknown = 0,
  external_authority = 1,
  runtime_self = 2,
};

[[nodiscard]] constexpr std::string_view ToString(EvidenceProvenance provenance) noexcept {
  switch (provenance) {
    case EvidenceProvenance::unknown: return "unknown";
    case EvidenceProvenance::external_authority: return "external_authority";
    case EvidenceProvenance::runtime_self: return "runtime_self";
  }
  return "unknown";
}

/// Whether evidence recovered from durable state may be treated as fresh live
/// evidence. It may not: recovered evidence keeps freshness == recovered so that
/// every predicate which requires live evidence keeps failing until the external
/// authority reports again.
enum class EvidenceFreshness : std::uint32_t {
  unknown = 0,
  live = 1,
  recovered = 2,
};

[[nodiscard]] constexpr std::string_view ToString(EvidenceFreshness freshness) noexcept {
  switch (freshness) {
    case EvidenceFreshness::unknown: return "unknown";
    case EvidenceFreshness::live: return "live";
    case EvidenceFreshness::recovered: return "recovered";
  }
  return "unknown";
}

struct EvidenceRef {
  EvidenceId id;
  EvidenceKind kind{EvidenceKind::unknown};
  EvidenceProvenance provenance{EvidenceProvenance::unknown};
  EvidenceFreshness freshness{EvidenceFreshness::unknown};

  /// Name of the external authority that reported the observation. Required to
  /// be non-empty for any evidence that satisfies a predicate.
  std::string observer;

  /// What the report is about, when it is about a specific drain. Drain
  /// satisfaction evidence must name the drain kind it reports, and that kind
  /// must equal the obligation's kind exactly: evidence about a different drain
  /// satisfies nothing.
  DrainKind subject_kind{DrainKind::unknown};

  /// The obligation this evidence satisfies. Set for drain satisfaction
  /// evidence so that satisfaction is attributable to one obligation rather than
  /// to the case as a whole.
  ObligationId subject_obligation;

  /// The reporting authority's own identifier for the report. Required to be
  /// non-empty; a report with no external handle is not attributable.
  std::string reference;

  /// Free-form detail. Bounded in length and required to be valid UTF-8.
  std::string detail;

  /// Monotonic ordering token. Evidence only satisfies an obligation that was
  /// issued strictly before this observation.
  ObservationSequence observation_sequence;

  Timestamp recorded_at;
  IncarnationId recorded_by;

  friend bool operator==(const EvidenceRef&, const EvidenceRef&) = default;
};

/// True when the evidence is attributable enough to satisfy a predicate:
/// non-empty observer and reference, a set sequence, and external provenance.
[[nodiscard]] bool IsAttributable(const EvidenceRef& evidence) noexcept;

}  // namespace decommissioning_fabric

#endif  // DECOMMISSIONING_FABRIC_EVIDENCE_HPP

// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "decommissioning_fabric/engine.hpp"
#include "engine_impl.hpp"

namespace decommissioning_fabric {
namespace {

// ---------------------------------------------------------------------------
// Request shape helpers
// ---------------------------------------------------------------------------

[[nodiscard]] RequestKind KindOfPayload(const RequestPayload& payload) {
  return std::visit(
      [](const auto& value) -> RequestKind {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, CreatePlanPayload>) {
          return RequestKind::create_plan;
        } else if constexpr (std::is_same_v<T, AssessDependenciesPayload>) {
          return RequestKind::assess_dependencies;
        } else if constexpr (std::is_same_v<T, SetDrainRequirementPayload>) {
          return RequestKind::set_drain_requirement;
        } else if constexpr (std::is_same_v<T, AcknowledgeDrainPayload>) {
          return RequestKind::acknowledge_drain;
        } else if constexpr (std::is_same_v<T, SatisfyDrainPayload>) {
          return RequestKind::satisfy_drain;
        } else if constexpr (std::is_same_v<T, WaiveDrainPayload>) {
          return RequestKind::waive_drain;
        } else if constexpr (std::is_same_v<T, BeginDrainingPayload>) {
          return RequestKind::begin_draining;
        } else if constexpr (std::is_same_v<T, ConcludeDrainingPayload>) {
          return RequestKind::conclude_draining;
        } else if constexpr (std::is_same_v<T, RecordRevocationPayload>) {
          return RequestKind::record_revocation;
        } else if constexpr (std::is_same_v<T, ConcludeAuthorityRevocationPayload>) {
          return RequestKind::conclude_authority_revocation;
        } else if constexpr (std::is_same_v<T, SetResidualDispositionPayload>) {
          return RequestKind::set_residual_disposition;
        } else if constexpr (std::is_same_v<T, RecordPolicyExceptionPayload>) {
          return RequestKind::record_policy_exception;
        } else if constexpr (std::is_same_v<T, DeclareIsolationReadyPayload>) {
          return RequestKind::declare_isolation_ready;
        } else if constexpr (std::is_same_v<T, AuthorizeRemovalPayload>) {
          return RequestKind::authorize_removal;
        } else if constexpr (std::is_same_v<T, ObserveRemovalPayload>) {
          return RequestKind::observe_removal;
        } else if constexpr (std::is_same_v<T, FinalizeDecommissioningPayload>) {
          return RequestKind::finalize_decommissioning;
        } else if constexpr (std::is_same_v<T, CancelPlanPayload>) {
          return RequestKind::cancel_plan;
        } else if constexpr (std::is_same_v<T, FailPlanPayload>) {
          return RequestKind::fail_plan;
        } else if constexpr (std::is_same_v<T, BlockPlanPayload>) {
          return RequestKind::block_plan;
        } else if constexpr (std::is_same_v<T, ResumePlanPayload>) {
          return RequestKind::resume_plan;
        } else if constexpr (std::is_same_v<T, IngestEvidencePayload>) {
          return RequestKind::ingest_evidence;
        } else {
          return RequestKind::unknown;
        }
      },
      payload);
}

[[nodiscard]] Status CheckText(const std::string& value, const char* field, bool required) {
  if (required && value.empty()) {
    return ErrorBuilder(ErrorCode::missing_field, "a required text field is empty")
        .With(std::string(field), std::string_view("empty"))
        .Build();
  }
  if (value.size() > kMaxStringBytes) {
    return ErrorBuilder(ErrorCode::string_too_long, "a text field exceeds the maximum length")
        .With(std::string(field), static_cast<std::uint64_t>(value.size()))
        .With("limit", static_cast<std::uint64_t>(kMaxStringBytes))
        .Build();
  }
  if (!IsValidUtf8(value)) {
    return ErrorBuilder(ErrorCode::invalid_utf8, "a text field is not well-formed UTF-8")
        .With(std::string(field), std::string_view("invalid"))
        .Build();
  }
  return OkStatus();
}

/// Canonical digest of the identifying content of a request. Two requests that
/// share an attempt identity but differ in content are a conflict, not a replay.
[[nodiscard]] Digest PayloadDigest(const Request& request) {
  std::string canonical;
  canonical += ToString(request.kind);
  canonical += '|';
  canonical += request.fence.asset.to_hex();
  canonical += '|';
  canonical += std::to_string(request.fence.lifecycle_generation.value());

  std::visit(
      [&canonical](const auto& value) {
        using T = std::decay_t<decltype(value)>;
        auto add = [&canonical](std::string_view text) {
          canonical += '|';
          canonical += text;
        };
        auto add_num = [&canonical](std::uint64_t number) {
          canonical += '|';
          canonical += std::to_string(number);
        };
        if constexpr (std::is_same_v<T, CreatePlanPayload>) {
          add_num(value.asset.value());
          add_num(value.lifecycle_generation.value());
          add(value.rationale);
        } else if constexpr (std::is_same_v<T, AssessDependenciesPayload>) {
          add(value.authority);
          add(value.reference);
          for (const DependencyFinding& finding : value.findings) {
            add(ToString(finding.kind));
            add_num(finding.target.value());
            add(ToString(finding.protected_class));
            add_num(finding.required ? 1U : 0U);
            add_num(finding.evaluated ? 1U : 0U);
            add(finding.issued_to);
          }
        } else if constexpr (std::is_same_v<T, SetDrainRequirementPayload>) {
          add(ToString(value.kind));
          add_num(value.target.value());
          add(ToString(value.protected_class));
          add_num(value.required ? 1U : 0U);
          add(value.issued_to);
        } else if constexpr (std::is_same_v<T, AcknowledgeDrainPayload>) {
          add_num(value.obligation.value());
          add(value.acknowledged_by);
          add(value.reference);
        } else if constexpr (std::is_same_v<T, SatisfyDrainPayload>) {
          add_num(value.obligation.value());
          add(ToString(value.reported_kind));
          add(value.observer);
          add(value.reference);
        } else if constexpr (std::is_same_v<T, WaiveDrainPayload>) {
          add_num(value.obligation.value());
          add(value.authority);
          add(value.reference);
          add(value.rationale);
        } else if constexpr (std::is_same_v<T, RecordRevocationPayload>) {
          for (const AuthorityDomain domain : value.domains) {
            add(ToString(domain));
          }
          add(value.authority);
          add(value.reference);
        } else if constexpr (std::is_same_v<T, SetResidualDispositionPayload>) {
          add(ToString(value.category));
          add(ToString(value.disposition));
          add(value.authority);
          add(value.reference);
        } else if constexpr (std::is_same_v<T, RecordPolicyExceptionPayload>) {
          add_num(value.item.value());
          add_num(value.obligation.value());
          add(value.authority);
          add(value.reference);
          add(value.rationale);
        } else if constexpr (std::is_same_v<T, DeclareIsolationReadyPayload>) {
          add(value.observer);
          add(value.reference);
        } else if constexpr (std::is_same_v<T, AuthorizeRemovalPayload>) {
          add(value.authority);
          add(value.reference);
        } else if constexpr (std::is_same_v<T, ObserveRemovalPayload>) {
          add(value.observer);
          add(value.reference);
        } else if constexpr (std::is_same_v<T, CancelPlanPayload>) {
          add(value.reason);
        } else if constexpr (std::is_same_v<T, FailPlanPayload>) {
          add(value.reason);
        } else if constexpr (std::is_same_v<T, BlockPlanPayload>) {
          add(ToString(value.reason));
          add(value.detail);
        } else if constexpr (std::is_same_v<T, IngestEvidencePayload>) {
          add(ToString(value.kind));
          add(value.observer);
          add(value.reference);
          add(value.detail);
        } else {
          (void)value;
        }
      },
      request.payload);

  return Sha256::Of(canonical);
}

[[nodiscard]] IdempotencyKey KeyOf(const Request& request, PlanId plan, AssetId asset,
                                   LifecycleGeneration generation) {
  std::string canonical;
  canonical += plan.to_hex();
  canonical += '|';
  canonical += asset.to_hex();
  canonical += '|';
  canonical += std::to_string(generation.value());
  canonical += '|';
  canonical += request.attempt.to_hex();
  canonical += '|';
  canonical += ToString(request.kind);
  canonical += '|';
  canonical += PayloadDigest(request).to_hex();
  IdempotencyKey key;
  key.digest = Sha256::Of(canonical);
  return key;
}

// ---------------------------------------------------------------------------
// Allocation. Headroom is checked before any allocation so a saturated counter
// is reported rather than wrapped.
// ---------------------------------------------------------------------------

[[nodiscard]] Status RequireHeadroom(const StoreState& state) {
  const bool saturated = state.counters.last_plan.at_max() ||
                         state.counters.last_evidence.at_max() ||
                         state.counters.last_receipt.at_max() ||
                         state.counters.last_obligation.at_max() ||
                         state.counters.last_residual.at_max() ||
                         state.counters.last_exception.at_max() ||
                         state.counters.last_observation.at_max();
  if (saturated) {
    return MakeError(ErrorCode::value_saturated,
                     "an identity counter has reached its maximum and cannot advance");
  }
  return OkStatus();
}

[[nodiscard]] PlanId NewPlanId(StoreState& state) {
  state.counters.last_plan = state.counters.last_plan.Next();
  return state.counters.last_plan;
}
[[nodiscard]] EvidenceId NewEvidenceId(StoreState& state) {
  state.counters.last_evidence = state.counters.last_evidence.Next();
  return state.counters.last_evidence;
}
[[nodiscard]] ReceiptId NewReceiptId(StoreState& state) {
  state.counters.last_receipt = state.counters.last_receipt.Next();
  return state.counters.last_receipt;
}
[[nodiscard]] ObligationId NewObligationId(StoreState& state) {
  state.counters.last_obligation = state.counters.last_obligation.Next();
  return state.counters.last_obligation;
}
[[nodiscard]] ResidualItemId NewResidualId(StoreState& state) {
  state.counters.last_residual = state.counters.last_residual.Next();
  return state.counters.last_residual;
}
[[nodiscard]] ExceptionId NewExceptionId(StoreState& state) {
  state.counters.last_exception = state.counters.last_exception.Next();
  return state.counters.last_exception;
}
[[nodiscard]] ObservationSequence NewObservation(StoreState& state) {
  state.counters.last_observation = state.counters.last_observation.Next();
  return state.counters.last_observation;
}

[[nodiscard]] EvidenceRef MakeEvidence(StoreState& state, EvidenceKind kind,
                                       EvidenceProvenance provenance, std::string observer,
                                       std::string reference, std::string detail,
                                       DrainKind subject_kind, ObligationId subject_obligation,
                                       Timestamp now, IncarnationId incarnation) {
  EvidenceRef evidence;
  evidence.id = NewEvidenceId(state);
  evidence.kind = kind;
  evidence.provenance = provenance;
  evidence.freshness = EvidenceFreshness::live;
  evidence.subject_kind = subject_kind;
  evidence.subject_obligation = subject_obligation;
  evidence.observer = std::move(observer);
  evidence.reference = std::move(reference);
  evidence.detail = std::move(detail);
  evidence.observation_sequence = NewObservation(state);
  evidence.recorded_at = now;
  evidence.recorded_by = incarnation;
  return evidence;
}

[[nodiscard]] RecordedNote MakeNote(std::string code, std::string text, Timestamp now) {
  RecordedNote note;
  note.code = std::move(code);
  note.text = std::move(text);
  note.recorded_at = now;
  return note;
}

// ---------------------------------------------------------------------------
// Resolution: stages 1..9 in order.
// ---------------------------------------------------------------------------

struct Resolution {
  const FleetAsset* asset{nullptr};
  const RetirementCase* record{nullptr};
  const IssuedRequest* issued{nullptr};
  CaseKey key;
  bool replay{false};
  bool has_fence{false};
  AuthorityReport authority{};
  Blocker blocker;
  bool has_blocker{false};
};

[[nodiscard]] Status Stage1Shape(const Request& request) {
  if (request.kind == RequestKind::unknown) {
    return MakeError(ErrorCode::malformed_request, "request kind is unknown");
  }
  const RequestKind payload_kind = KindOfPayload(request.payload);
  if (payload_kind != request.kind) {
    return ErrorBuilder(ErrorCode::malformed_request,
                        "request payload does not match the request kind")
        .With("kind", std::string(ToString(request.kind)))
        .With("payload_kind", std::string(ToString(payload_kind)))
        .Build();
  }

  switch (request.kind) {
    case RequestKind::create_plan: {
      const auto& payload = std::get<CreatePlanPayload>(request.payload);
      DF_TRY(CheckText(payload.rationale, "rationale", false));
      break;
    }
    case RequestKind::assess_dependencies: {
      const auto& payload = std::get<AssessDependenciesPayload>(request.payload);
      DF_TRY(CheckText(payload.authority, "authority", true));
      DF_TRY(CheckText(payload.reference, "reference", true));
      DF_TRY(CheckText(payload.detail, "detail", false));
      for (const DependencyFinding& finding : payload.findings) {
        if (finding.kind == DrainKind::unknown) {
          return MakeError(ErrorCode::malformed_request,
                           "dependency finding does not name a drain kind");
        }
        DF_TRY(CheckText(finding.issued_to, "issued_to", true));
        DF_TRY(CheckText(finding.detail, "detail", false));
      }
      break;
    }
    case RequestKind::set_drain_requirement: {
      const auto& payload = std::get<SetDrainRequirementPayload>(request.payload);
      if (payload.kind == DrainKind::unknown) {
        return MakeError(ErrorCode::malformed_request, "drain requirement does not name a kind");
      }
      DF_TRY(CheckText(payload.issued_to, "issued_to", true));
      DF_TRY(CheckText(payload.detail, "detail", false));
      break;
    }
    case RequestKind::acknowledge_drain: {
      const auto& payload = std::get<AcknowledgeDrainPayload>(request.payload);
      DF_TRY(CheckText(payload.acknowledged_by, "acknowledged_by", true));
      DF_TRY(CheckText(payload.reference, "reference", true));
      DF_TRY(CheckText(payload.detail, "detail", false));
      break;
    }
    case RequestKind::satisfy_drain: {
      const auto& payload = std::get<SatisfyDrainPayload>(request.payload);
      if (payload.reported_kind == DrainKind::unknown) {
        return MakeError(ErrorCode::malformed_request,
                         "drain satisfaction does not name the drain it reports");
      }
      DF_TRY(CheckText(payload.observer, "observer", true));
      DF_TRY(CheckText(payload.reference, "reference", true));
      DF_TRY(CheckText(payload.detail, "detail", false));
      break;
    }
    case RequestKind::waive_drain: {
      const auto& payload = std::get<WaiveDrainPayload>(request.payload);
      DF_TRY(CheckText(payload.authority, "authority", true));
      DF_TRY(CheckText(payload.reference, "reference", true));
      DF_TRY(CheckText(payload.rationale, "rationale", true));
      break;
    }
    case RequestKind::record_revocation: {
      const auto& payload = std::get<RecordRevocationPayload>(request.payload);
      if (payload.domains.empty()) {
        return MakeError(ErrorCode::malformed_request, "revocation names no authority domain");
      }
      DF_TRY(CheckText(payload.authority, "authority", true));
      DF_TRY(CheckText(payload.reference, "reference", true));
      DF_TRY(CheckText(payload.detail, "detail", false));
      break;
    }
    case RequestKind::set_residual_disposition: {
      const auto& payload = std::get<SetResidualDispositionPayload>(request.payload);
      if (payload.category == ResidualCategory::unknown) {
        return MakeError(ErrorCode::malformed_request, "residual disposition names no category");
      }
      if (payload.disposition == ResidualDisposition::unknown) {
        return MakeError(ErrorCode::malformed_request,
                         "residual disposition is not a decided disposition");
      }
      DF_TRY(CheckText(payload.detail, "detail", false));
      DF_TRY(CheckText(payload.authority, "authority", true));
      DF_TRY(CheckText(payload.reference, "reference", true));
      break;
    }
    case RequestKind::record_policy_exception: {
      const auto& payload = std::get<RecordPolicyExceptionPayload>(request.payload);
      DF_TRY(CheckText(payload.authority, "authority", true));
      DF_TRY(CheckText(payload.reference, "reference", true));
      DF_TRY(CheckText(payload.rationale, "rationale", true));
      break;
    }
    case RequestKind::declare_isolation_ready: {
      const auto& payload = std::get<DeclareIsolationReadyPayload>(request.payload);
      DF_TRY(CheckText(payload.observer, "observer", true));
      DF_TRY(CheckText(payload.reference, "reference", true));
      DF_TRY(CheckText(payload.detail, "detail", false));
      break;
    }
    case RequestKind::authorize_removal: {
      const auto& payload = std::get<AuthorizeRemovalPayload>(request.payload);
      DF_TRY(CheckText(payload.authority, "authority", true));
      DF_TRY(CheckText(payload.reference, "reference", true));
      DF_TRY(CheckText(payload.detail, "detail", false));
      break;
    }
    case RequestKind::observe_removal: {
      const auto& payload = std::get<ObserveRemovalPayload>(request.payload);
      DF_TRY(CheckText(payload.observer, "observer", true));
      DF_TRY(CheckText(payload.reference, "reference", true));
      DF_TRY(CheckText(payload.detail, "detail", false));
      break;
    }
    case RequestKind::cancel_plan: {
      const auto& payload = std::get<CancelPlanPayload>(request.payload);
      DF_TRY(CheckText(payload.reason, "reason", true));
      break;
    }
    case RequestKind::fail_plan: {
      const auto& payload = std::get<FailPlanPayload>(request.payload);
      DF_TRY(CheckText(payload.reason, "reason", true));
      break;
    }
    case RequestKind::block_plan: {
      const auto& payload = std::get<BlockPlanPayload>(request.payload);
      if (payload.reason == BlockerReason::none) {
        return MakeError(ErrorCode::malformed_request, "block request does not name a reason");
      }
      DF_TRY(CheckText(payload.detail, "detail", true));
      DF_TRY(CheckText(payload.required_action, "required_action", true));
      break;
    }
    case RequestKind::ingest_evidence: {
      const auto& payload = std::get<IngestEvidencePayload>(request.payload);
      if (payload.kind == EvidenceKind::unknown) {
        return MakeError(ErrorCode::malformed_request, "evidence ingestion names no evidence kind");
      }
      // Drain satisfaction evidence is structurally required to name the
      // obligation and drain kind it reports. Plain ingestion carries neither, so
      // accepting it here would let the engine write a generation its own codec
      // refuses to read back.
      if (payload.kind == EvidenceKind::drain_satisfaction) {
        return MakeError(ErrorCode::malformed_request,
                         "drain satisfaction evidence must be recorded through satisfy_drain, "
                         "which binds it to the obligation and drain kind it reports");
      }
      DF_TRY(CheckText(payload.observer, "observer", true));
      DF_TRY(CheckText(payload.reference, "reference", true));
      DF_TRY(CheckText(payload.detail, "detail", false));
      break;
    }
    default:
      break;
  }
  return OkStatus();
}

[[nodiscard]] Status Stage3Identity(const Request& request, Resolution& out) {
  if (request.attempt.is_unset()) {
    return MakeError(ErrorCode::unset_attempt, "request has no attempt identity");
  }
  if (request.incarnation.is_unset()) {
    return MakeError(ErrorCode::unset_identity, "request has no producing incarnation");
  }
  if (request.kind == RequestKind::create_plan) {
    const auto& payload = std::get<CreatePlanPayload>(request.payload);
    if (payload.asset.is_unset()) {
      return MakeError(ErrorCode::unset_identity, "create_plan names no asset");
    }
    out.key = CaseKey{payload.asset, payload.lifecycle_generation};
    return OkStatus();
  }

  out.has_fence = true;
  if (request.fence.asset.is_unset()) {
    return MakeError(ErrorCode::unset_identity, "request fence names no asset");
  }
  if (request.fence.lifecycle_generation.is_unset()) {
    return MakeError(ErrorCode::unset_generation, "request fence has no lifecycle generation");
  }
  if (request.fence.plan.is_unset()) {
    return MakeError(ErrorCode::unset_identity, "request fence names no plan");
  }
  if (request.fence.revision.is_unset()) {
    return MakeError(ErrorCode::unset_generation, "request fence has no revision");
  }
  out.key = CaseKey{request.fence.asset, request.fence.lifecycle_generation};
  return OkStatus();
}

/// Stage 2 runs after stage 1 and before identity because a count or a length is
/// a statement about the envelope, not about identity.
[[nodiscard]] Status Stage2Bounds(const StoreState& state, const Request& request) {
  DF_TRY(RequireHeadroom(state));

  switch (request.kind) {
    case RequestKind::assess_dependencies: {
      const auto& payload = std::get<AssessDependenciesPayload>(request.payload);
      if (payload.findings.size() > kMaxObligationsPerCase) {
        return ErrorBuilder(ErrorCode::too_many_items, "too many dependency findings")
            .With("count", static_cast<std::uint64_t>(payload.findings.size()))
            .With("limit", static_cast<std::uint64_t>(kMaxObligationsPerCase))
            .Build();
      }
      break;
    }
    case RequestKind::record_revocation: {
      const auto& payload = std::get<RecordRevocationPayload>(request.payload);
      if (payload.domains.size() > kAuthorityDomainCount) {
        return ErrorBuilder(ErrorCode::too_many_items, "too many authority domains")
            .With("count", static_cast<std::uint64_t>(payload.domains.size()))
            .With("limit", static_cast<std::uint64_t>(kAuthorityDomainCount))
            .Build();
      }
      for (std::size_t i = 0; i < payload.domains.size(); ++i) {
        if (payload.domains[i] == AuthorityDomain::none) {
          return ErrorBuilder(ErrorCode::malformed_request, "revocation names the none domain")
              .With("index", static_cast<std::uint64_t>(i))
              .Build();
        }
        for (std::size_t j = i + 1U; j < payload.domains.size(); ++j) {
          if (payload.domains[i] == payload.domains[j]) {
            return ErrorBuilder(ErrorCode::duplicate_identity,
                                "revocation names the same domain twice")
                .With("domain", std::string(ToString(payload.domains[i])))
                .Build();
          }
        }
      }
      break;
    }
    default:
      break;
  }
  return OkStatus();
}

[[nodiscard]] Status Stage4Registry(const StoreState& state, const Request& request,
                                    Resolution& out) {
  const RetirementCase* record = nullptr;
  if (request.kind == RequestKind::create_plan) {
    const auto& payload = std::get<CreatePlanPayload>(request.payload);
    if (payload.lifecycle_generation.is_set()) {
      record = state.FindCase(CaseKey{payload.asset, payload.lifecycle_generation});
    } else {
      // The caller left the generation to us, so replay detection has to scan
      // the asset's cases. Map iteration is key ordered, so the scan is
      // deterministic.
      for (const auto& entry : state.cases) {
        if (entry.first.asset != payload.asset) {
          continue;
        }
        if (FindIssued(entry.second, request.attempt) != nullptr) {
          record = &entry.second;
          out.key = entry.first;
          break;
        }
      }
    }
  } else {
    record = state.FindCase(out.key);
  }

  if (record == nullptr) {
    return OkStatus();
  }
  const IssuedRequest* issued = FindIssued(*record, request.attempt);
  if (issued == nullptr) {
    return OkStatus();
  }
  if (issued->kind != request.kind) {
    return ErrorBuilder(ErrorCode::already_issued,
                        "this attempt identity was already used for a different request kind")
        .With("attempt", request.attempt.to_hex())
        .With("recorded_kind", std::string(ToString(issued->kind)))
        .With("requested_kind", std::string(ToString(request.kind)))
        .Build();
  }
  // An attempt identity with the same kind but different content is a conflict,
  // not a replay: honouring it would apply a second, different mutation under an
  // identity the caller already used.
  const IdempotencyKey key = KeyOf(request, record->plan, record->key.asset, record->key.generation);
  if (!(key == issued->key)) {
    return ErrorBuilder(ErrorCode::already_issued,
                        "this attempt identity was already applied with different content")
        .With("attempt", request.attempt.to_hex())
        .With("recorded_key", issued->key.to_hex())
        .With("requested_key", key.to_hex())
        .Build();
  }
  out.record = record;
  out.issued = issued;
  out.replay = true;
  return OkStatus();
}

[[nodiscard]] Status Stage5Existence(const StoreState& state, const Request& request,
                                     Resolution& out) {
  const AssetId asset_id =
      request.kind == RequestKind::create_plan
          ? std::get<CreatePlanPayload>(request.payload).asset
          : request.fence.asset;

  out.asset = state.FindAsset(asset_id);
  if (out.asset == nullptr) {
    return ErrorBuilder(ErrorCode::unknown_asset, "no such asset is registered")
        .With("asset", asset_id.to_hex())
        .Build();
  }

  if (request.kind == RequestKind::create_plan) {
    const RetirementCase* existing = state.CurrentCase(asset_id);
    if (existing != nullptr && !IsTerminal(existing->phase)) {
      return ErrorBuilder(ErrorCode::case_already_open,
                          "asset already has an open retirement plan")
          .With("asset", asset_id.to_hex())
          .With("plan", existing->plan.to_hex())
          .With("phase", std::string(ToString(existing->phase)))
          .Build();
    }
    const LifecycleGeneration latest = state.LatestGeneration(asset_id);
    const LifecycleGeneration expected =
        latest.is_unset() ? LifecycleGeneration::First() : latest.Next();
    const auto& payload = std::get<CreatePlanPayload>(request.payload);
    if (payload.lifecycle_generation.is_set() && payload.lifecycle_generation != expected) {
      return ErrorBuilder(ErrorCode::asset_generation_regressed,
                          "requested lifecycle generation is not the next one for this asset")
          .With("asset", asset_id.to_hex())
          .With("requested", static_cast<std::uint64_t>(payload.lifecycle_generation.value()))
          .With("expected", static_cast<std::uint64_t>(expected.value()))
          .Build();
    }
    out.key = CaseKey{asset_id, expected};
    return OkStatus();
  }

  out.record = state.FindCase(out.key);
  if (out.record == nullptr) {
    return ErrorBuilder(ErrorCode::unknown_case, "no retirement case exists for this fence")
        .With("asset", asset_id.to_hex())
        .With("generation", static_cast<std::uint64_t>(out.key.generation.value()))
        .Build();
  }
  if (out.record->plan != request.fence.plan) {
    return ErrorBuilder(ErrorCode::wrong_plan_for_asset, "fence names a plan that is not this case")
        .With("asset", asset_id.to_hex())
        .With("case_plan", out.record->plan.to_hex())
        .With("request_plan", request.fence.plan.to_hex())
        .Build();
  }

  switch (request.kind) {
    case RequestKind::acknowledge_drain:
    case RequestKind::satisfy_drain:
    case RequestKind::waive_drain: {
      const ObligationId obligation =
          request.kind == RequestKind::acknowledge_drain
              ? std::get<AcknowledgeDrainPayload>(request.payload).obligation
              : (request.kind == RequestKind::satisfy_drain
                     ? std::get<SatisfyDrainPayload>(request.payload).obligation
                     : std::get<WaiveDrainPayload>(request.payload).obligation);
      if (obligation.is_unset()) {
        return MakeError(ErrorCode::unset_identity, "request names no obligation");
      }
      if (FindObligation(*out.record, obligation) == nullptr) {
        return ErrorBuilder(ErrorCode::unknown_obligation, "no such obligation on this case")
            .With("obligation", obligation.to_hex())
            .Build();
      }
      break;
    }
    case RequestKind::record_policy_exception: {
      const auto& payload = std::get<RecordPolicyExceptionPayload>(request.payload);
      if (payload.item.is_set() && FindResidual(*out.record, payload.item) == nullptr) {
        return ErrorBuilder(ErrorCode::unknown_residual_item, "no such residual item on this case")
            .With("item", payload.item.to_hex())
            .Build();
      }
      if (payload.obligation.is_set() &&
          FindObligation(*out.record, payload.obligation) == nullptr) {
        return ErrorBuilder(ErrorCode::unknown_obligation, "no such obligation on this case")
            .With("obligation", payload.obligation.to_hex())
            .Build();
      }
      if (payload.item.is_unset() && payload.obligation.is_unset()) {
        return MakeError(ErrorCode::missing_field,
                         "policy exception names neither a residual item nor an obligation");
      }
      break;
    }
    default:
      break;
  }
  return OkStatus();
}

[[nodiscard]] PlanFence BuildFence(const StoreState& state, const FleetAsset& asset,
                                   LifecycleGeneration generation);

/// Renders a fence field for comparison and for refusal details.
[[nodiscard]] std::string FieldText(const PlanFence& fence, FenceField field) {
  return RenderFenceField(fence, field);
}

[[nodiscard]] Status Stage6Fence(const StoreState& state, const Request& request,
                                 const Resolution& out) {
  if (out.record == nullptr) {
    return MakeError(ErrorCode::internal_error,
                     "fence comparison reached without a resolved case");
  }
  const FenceComparison comparison = ClassifyFence(request.fence, out.record->fence);
  if (comparison.classification != FenceClass::current) {
    return ErrorBuilder(comparison.code(), "request fence does not match the live case fence")
        .With("classification", std::string(ToString(comparison.classification)))
        .With("field", std::string(ToString(comparison.first_mismatch)))
        .With("requested", comparison.requested_value)
        .With("current", comparison.current_value)
        .Build();
  }

  // A case does not rewrite itself when the facility advances. Without this
  // check a caller could keep operating on a fenced plan indefinitely by
  // replaying the fence it captured before the advance, and "any changed
  // generation fences the old plan" would be false.
  if (out.asset == nullptr) {
    return MakeError(ErrorCode::internal_error, "fence check reached without the fleet asset");
  }
  // Closing a plan that no longer corresponds to the facility is not a facility
  // mutation: it retires the runtime's own record so the asset can be planned
  // again. Refusing it would strand the asset forever, because a behind plan can
  // neither advance nor be replaced while it is open. Advancing a behind plan
  // remains forbidden for every other request kind.
  if (request.kind == RequestKind::cancel_plan || request.kind == RequestKind::fail_plan) {
    return OkStatus();
  }

  const PlanFence live = BuildFence(state, *out.asset, out.record->key.generation);
  for (const FenceField field : kFenceFieldOrder) {
    if (field == FenceField::active_obligation_digest) {
      continue;  // derived from the case's own obligations
    }
    if (FieldText(live, field) != FieldText(out.record->fence, field)) {
      return ErrorBuilder(ErrorCode::fence_stale,
                          "the plan's binding is no longer the facility's current binding")
          .With("field", std::string(ToString(field)))
          .With("planned", FieldText(out.record->fence, field))
          .With("current", FieldText(live, field))
          .Build();
    }
  }
  return OkStatus();
}

[[nodiscard]] bool PhasePermits(RequestKind kind, Phase phase) noexcept {
  if (IsTerminal(phase)) {
    return false;
  }
  switch (kind) {
    case RequestKind::assess_dependencies:
      return phase == Phase::requested;
    case RequestKind::set_drain_requirement:
      return phase == Phase::requested || phase == Phase::dependency_assessment ||
             phase == Phase::drain_required || phase == Phase::draining ||
             phase == Phase::authority_revocation || phase == Phase::residual_handling ||
             phase == Phase::isolation_ready;
    case RequestKind::begin_draining:
      return phase == Phase::drain_required || phase == Phase::dependency_assessment;
    case RequestKind::conclude_draining:
      return phase == Phase::draining;
    case RequestKind::conclude_authority_revocation:
      return phase == Phase::authority_revocation;
    case RequestKind::declare_isolation_ready:
      return phase == Phase::residual_handling;
    case RequestKind::authorize_removal:
      return phase == Phase::isolation_ready;
    case RequestKind::observe_removal:
      return phase == Phase::removal_authorized;
    case RequestKind::finalize_decommissioning:
      return phase == Phase::removed_observed;
    case RequestKind::cancel_plan:
      return IsCancellable(phase);
    case RequestKind::fail_plan:
    case RequestKind::block_plan:
      return IsActionable(phase);
    case RequestKind::resume_plan:
      return phase == Phase::blocked;
    case RequestKind::acknowledge_drain:
    case RequestKind::satisfy_drain:
    case RequestKind::waive_drain:
    case RequestKind::record_revocation:
    case RequestKind::set_residual_disposition:
    case RequestKind::record_policy_exception:
    case RequestKind::ingest_evidence:
      return IsActionable(phase);
    default:
      return false;
  }
}

[[nodiscard]] Status Stage7Phase(const Request& request, Resolution& out) {
  if (out.record == nullptr) {
    return MakeError(ErrorCode::internal_error,
                     "validation reached a case-scoped stage without a resolved case");
  }
  const Phase phase = out.record->phase;
  if (!PhasePermits(request.kind, phase)) {
    ErrorBuilder builder(IsTerminal(phase) ? ErrorCode::phase_terminal
                                           : ErrorCode::phase_does_not_permit,
                         IsTerminal(phase) ? "the plan is in a terminal phase"
                                           : "the current phase does not permit this request");
    builder.With("phase", std::string(ToString(phase)))
        .With("kind", std::string(ToString(request.kind)));
    if (const Phase target = BoundaryTargetPhase(request.kind); target != Phase::unknown) {
      builder.With("required_phase", std::string(ToString(target)));
    }
    return builder.Build();
  }

  // A boundary request must be a legal transition from the current phase.
  const Phase target = BoundaryTargetPhase(request.kind);
  if (target != Phase::unknown && request.kind != RequestKind::block_plan &&
      request.kind != RequestKind::fail_plan && request.kind != RequestKind::cancel_plan &&
      request.kind != RequestKind::create_plan) {
    const Phase resume = phase == Phase::blocked ? out.record->resume_phase : Phase::unknown;
    if (!IsLegalTransition(phase, target, resume)) {
      return ErrorBuilder(ErrorCode::invalid_transition,
                          "the lifecycle transition table does not permit this step")
          .With("from", std::string(ToString(phase)))
          .With("to", std::string(ToString(target)))
          .Build();
    }
  }

  // Obligation-state predicates.
  switch (request.kind) {
    case RequestKind::acknowledge_drain:
    case RequestKind::satisfy_drain:
    case RequestKind::waive_drain: {
      const ObligationId obligation =
          request.kind == RequestKind::acknowledge_drain
              ? std::get<AcknowledgeDrainPayload>(request.payload).obligation
              : (request.kind == RequestKind::satisfy_drain
                     ? std::get<SatisfyDrainPayload>(request.payload).obligation
                     : std::get<WaiveDrainPayload>(request.payload).obligation);
      const DrainObligation* found = FindObligation(*out.record, obligation);
      if (found != nullptr && found->is_resolved()) {
        return ErrorBuilder(ErrorCode::obligation_already_resolved,
                            "the obligation is already resolved")
            .With("obligation", obligation.to_hex())
            .With("state", std::string(ToString(found->state)))
            .Build();
      }
      if (found != nullptr && found->state == ObligationState::failed) {
        return ErrorBuilder(ErrorCode::phase_does_not_permit,
                            "the obligation was recorded as failed")
            .With("obligation", obligation.to_hex())
            .Build();
      }
      break;
    }
    default:
      break;
  }
  return OkStatus();
}

[[nodiscard]] Status Stage8Prerequisites(const Request& request, Resolution& out) {
  if (out.record == nullptr) {
    return MakeError(ErrorCode::internal_error,
                     "validation reached a case-scoped stage without a resolved case");
  }
  out.authority = AuthorityOf(*out.record);

  // Drain satisfaction must be evidence of the right kind.
  if (request.kind == RequestKind::satisfy_drain) {
    const auto& payload = std::get<SatisfyDrainPayload>(request.payload);
    const DrainObligation* obligation = FindObligation(*out.record, payload.obligation);
    if (obligation != nullptr && obligation->kind != payload.reported_kind) {
      return ErrorBuilder(ErrorCode::evidence_kind_mismatch,
                          "reported drain kind does not match the obligation it claims to satisfy")
          .With("obligation", obligation->id.to_hex())
          .With("obligation_kind", std::string(ToString(obligation->kind)))
          .With("reported_kind", std::string(ToString(payload.reported_kind)))
          .Build();
    }
    if (obligation != nullptr && RequiredEvidenceKind(*obligation) !=
                                     EvidenceKind::drain_satisfaction) {
      return MakeError(ErrorCode::internal_error,
                       "obligation requires an evidence kind this build cannot produce");
    }
  }

  std::vector<Blocker> blockers;
  CollectPrerequisiteBlockers(*out.record, out.authority, NeedsForRequest(request.kind),
                              blockers);
  if (!blockers.empty()) {
    out.blocker = blockers.front();
    out.has_blocker = true;
    ErrorBuilder builder(out.blocker.code, out.blocker.detail);
    for (const ErrorDetail& detail : out.blocker.observed) {
      builder.With(detail.key, detail.value);
    }
    builder.With("reason", std::string(ToString(out.blocker.reason)));
    return builder.Build();
  }
  return OkStatus();
}

[[nodiscard]] Status Stage9Policy(const Request& request, Resolution& out) {
  if (out.record == nullptr) {
    return MakeError(ErrorCode::internal_error,
                     "validation reached a case-scoped stage without a resolved case");
  }
  if (request.kind == RequestKind::waive_drain) {
    const auto& payload = std::get<WaiveDrainPayload>(request.payload);
    const DrainObligation* obligation = FindObligation(*out.record, payload.obligation);
    if (obligation != nullptr && !IsWaivable(*obligation)) {
      out.blocker.reason = BlockerReason::protected_service_unresolved;
      out.blocker.code = ErrorCode::exception_not_permitted;
      out.blocker.observed_phase = out.record->phase;
      out.blocker.detail =
          "facility policy does not permit waiving a protected service obligation";
      out.blocker.required_action =
          "obtain completion evidence for this obligation from the authority that owns it";
      out.blocker.observed.push_back(ErrorDetail{"obligation", obligation->id.to_hex()});
      out.blocker.observed.push_back(
          ErrorDetail{"kind", std::string(ToString(obligation->kind))});
      out.blocker.observed.push_back(
          ErrorDetail{"protected_class", std::string(ToString(obligation->protected_class))});
      out.has_blocker = true;
      return ErrorBuilder(out.blocker.code, out.blocker.detail)
          .With("obligation", obligation->id.to_hex())
          .With("kind", std::string(ToString(obligation->kind)))
          .With("protected_class", std::string(ToString(obligation->protected_class)))
          .Build();
    }
  }

  if (request.kind == RequestKind::set_residual_disposition) {
    const auto& payload = std::get<SetResidualDispositionPayload>(request.payload);
    if (payload.disposition == ResidualDisposition::waived) {
      out.blocker.reason = BlockerReason::exception_required;
      out.blocker.code = ErrorCode::exception_required;
      out.blocker.observed_phase = out.record->phase;
      out.blocker.detail =
          "a waived residual disposition must arrive through an attributed policy exception";
      out.blocker.required_action =
          "use 'dfab residual exception' so the waiver names its authority, reference, and "
          "rationale";
      out.blocker.observed.push_back(
          ErrorDetail{"category", std::string(ToString(payload.category))});
      out.has_blocker = true;
      return ErrorBuilder(out.blocker.code, out.blocker.detail)
          .With("category", std::string(ToString(payload.category)))
          .Build();
    }
  }

  std::vector<Blocker> blockers;
  CollectPolicyBlockers(*out.record, out.authority, request.kind, blockers);
  if (!blockers.empty()) {
    out.blocker = blockers.front();
    out.has_blocker = true;
    ErrorBuilder builder(out.blocker.code, out.blocker.detail);
    for (const ErrorDetail& detail : out.blocker.observed) {
      builder.With(detail.key, detail.value);
    }
    builder.With("reason", std::string(ToString(out.blocker.reason)));
    return builder.Build();
  }
  return OkStatus();
}

[[nodiscard]] Status Resolve(const StoreState& state, const Request& request, Resolution& out) {
  DF_TRY(Stage1Shape(request));
  DF_TRY(Stage2Bounds(state, request));
  DF_TRY(Stage3Identity(request, out));
  DF_TRY(Stage4Registry(state, request, out));
  if (out.replay) {
    return OkStatus();
  }
  DF_TRY(Stage5Existence(state, request, out));

  // create_plan has no case yet, so there is no existing fence to compare
  // against, no phase predicate to satisfy, and no accumulated obligation,
  // authority, residual, or policy state to check. Stage 5 has already
  // established that the asset exists and has no open plan. Every other request
  // kind runs the remaining stages against a case that must exist.
  if (request.kind == RequestKind::create_plan) {
    return OkStatus();
  }

  DF_TRY(Stage6Fence(state, request, out));
  DF_TRY(Stage7Phase(request, out));
  DF_TRY(Stage8Prerequisites(request, out));
  DF_TRY(Stage9Policy(request, out));
  return OkStatus();
}

}  // namespace
namespace {

// ---------------------------------------------------------------------------
// Application
// ---------------------------------------------------------------------------

[[nodiscard]] BlockerReason ReasonForError(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::fence_stale:
    case ErrorCode::fence_superseded:
    case ErrorCode::fence_revision_behind:
    case ErrorCode::fence_malformed:
      return BlockerReason::fence_stale;
    case ErrorCode::unknown_asset:
      return BlockerReason::asset_unknown;
    case ErrorCode::invalid_transition:
    case ErrorCode::phase_terminal:
    case ErrorCode::phase_does_not_permit:
      return BlockerReason::phase_does_not_permit;
    case ErrorCode::policy_violation:
    case ErrorCode::exception_not_permitted:
      return BlockerReason::policy_violation;
    case ErrorCode::protected_service_unresolved:
      return BlockerReason::protected_service_unresolved;
    case ErrorCode::exception_required:
      return BlockerReason::exception_required;
    case ErrorCode::unmet_obligation:
    case ErrorCode::obligation_already_resolved:
      return BlockerReason::drain_outstanding;
    case ErrorCode::unresolved_residual:
    case ErrorCode::residual_checklist_incomplete:
      return BlockerReason::residual_unknown;
    case ErrorCode::authority_active:
      return BlockerReason::authority_active;
    case ErrorCode::authority_unknown:
      return BlockerReason::authority_unknown;
    case ErrorCode::evidence_kind_mismatch:
      return BlockerReason::evidence_kind_mismatch;
    case ErrorCode::evidence_stale:
      return BlockerReason::evidence_stale;
    case ErrorCode::store_io_error:
    case ErrorCode::store_locked:
    case ErrorCode::store_corrupt:
      return BlockerReason::store_unavailable;
    default:
      return BlockerReason::phase_does_not_permit;
  }
}

/// True when a registration request describes exactly the asset already on
/// record. Compared field by field: the record also carries plan and lifecycle
/// state, which a re-registration does not speak about.
[[nodiscard]] bool SameRegistration(const FleetAsset& asset,
                                    const RegisterAssetRequest& request) {
  return asset.site == request.site && asset.rack == request.rack &&
         asset.hardware_generation == request.hardware_generation &&
         asset.firmware_generation == request.firmware_generation &&
         asset.active_authority == request.active_authority &&
         asset.present == request.present && asset.model == request.model &&
         asset.serial == request.serial;
}

[[nodiscard]] std::uint32_t CurrentGenerationValue(const StoreState& state,
                                                   GenerationKind kind) noexcept {
  switch (kind) {
    case GenerationKind::facility_epoch: return state.generations.facility_epoch.value();
    case GenerationKind::policy: return state.generations.policy_generation.value();
    case GenerationKind::dependency: return state.generations.dependency_generation.value();
    case GenerationKind::capacity: return state.generations.capacity_generation.value();
    case GenerationKind::topology: return state.generations.topology_generation.value();
    case GenerationKind::maintenance: return state.generations.maintenance_generation.value();
  }
  return 0;
}

void SetGenerationValue(StoreState& state, GenerationKind kind, std::uint32_t value) noexcept {
  switch (kind) {
    case GenerationKind::facility_epoch:
      state.generations.facility_epoch = FacilityEpoch::FromValue(value);
      break;
    case GenerationKind::policy:
      state.generations.policy_generation = PolicyGeneration::FromValue(value);
      break;
    case GenerationKind::dependency:
      state.generations.dependency_generation = DependencyGeneration::FromValue(value);
      break;
    case GenerationKind::capacity:
      state.generations.capacity_generation = CapacityGeneration::FromValue(value);
      break;
    case GenerationKind::topology:
      state.generations.topology_generation = TopologyGeneration::FromValue(value);
      break;
    case GenerationKind::maintenance:
      state.generations.maintenance_generation = MaintenanceGeneration::FromValue(value);
      break;
  }
}

void FillBlockerFromError(const Error& error, Blocker& blocker) {
  blocker.reason = ReasonForError(error.code);
  blocker.code = error.code;
  blocker.detail = error.message;
  blocker.observed = error.details;
}

[[nodiscard]] PlanFence BuildFence(const StoreState& state, const FleetAsset& asset,
                                   LifecycleGeneration generation) {
  PlanFence fence;
  fence.asset = asset.id;
  fence.site = asset.site;
  fence.rack = asset.rack;
  fence.lifecycle_generation = generation;
  fence.hardware_generation = asset.hardware_generation;
  fence.firmware_generation = asset.firmware_generation;
  fence.facility_epoch = state.generations.facility_epoch;
  fence.policy_generation = state.generations.policy_generation;
  fence.dependency_generation = state.generations.dependency_generation;
  fence.capacity_generation = state.generations.capacity_generation;
  fence.topology_generation = state.generations.topology_generation;
  fence.maintenance_generation = state.generations.maintenance_generation;
  fence.active_obligation_count = 0;
  fence.active_obligation_digest = ActiveObligationDigest({});
  return fence;
}

[[nodiscard]] Status ApplyCreatePlan(StoreState& candidate, const Request& request,
                                     const CaseKey& key, Timestamp now, Decision& decision) {
  const auto& payload = std::get<CreatePlanPayload>(request.payload);
  const FleetAsset* asset = candidate.FindAsset(payload.asset);
  if (asset == nullptr) {
    return MakeError(ErrorCode::unknown_asset, "asset disappeared between validation and apply");
  }

  RetirementCase record;
  record.key = key;
  record.plan = NewPlanId(candidate);
  record.fence = BuildFence(candidate, *asset, key.generation);
  record.fence.plan = record.plan;
  record.fence.revision = Revision::First();
  record.phase = Phase::commissioned;
  record.created_at = now;
  record.updated_at = now;
  record.created_by = request.incarnation;
  record.active_authority = asset->active_authority;

  record.notes.push_back(MakeNote(
      "fence",
      "plan bound to lifecycle generation " + std::to_string(key.generation.value()) +
          ", hardware generation " + std::to_string(record.fence.hardware_generation.value()) +
          ", firmware generation " + std::to_string(record.fence.firmware_generation.value()) +
          ", facility epoch " + std::to_string(record.fence.facility_epoch.value()) +
          ", policy generation " + std::to_string(record.fence.policy_generation.value()),
      now));
  if (!payload.rationale.empty()) {
    record.notes.push_back(MakeNote("rationale", payload.rationale, now));
  }

  RefreshObligationBinding(record);

  if (!IsLegalTransition(Phase::commissioned, Phase::requested, Phase::unknown)) {
    return MakeError(ErrorCode::internal_error,
                     "the transition table does not permit commissioned -> requested");
  }
  record.phase = Phase::requested;

  record.notes.push_back(MakeNote(
      "canonical_deletion_not_owned",
      "this runtime does not own canonical asset deletion; decommissioned is a governed "
      "retirement decision, not a deletion",
      now));
  record.notes.push_back(MakeNote(
      "hardware_synthetic",
      "obligations towards ASI, DFI, power, cooling, tenants, and technicians are modelled and "
      "coordinated; this runtime does not perform any of them",
      now));

  IssuedRequest issued;
  issued.attempt = request.attempt;
  issued.kind = request.kind;
  decision.key = KeyOf(request, record.plan, key.asset, key.generation);
  issued.key = decision.key;
  issued.committed_sequence = candidate.sequence;
  issued.resulting_revision = record.fence.revision;
  issued.resulting_phase = record.phase;
  issued.issued_at = now;
  record.registry.push_back(std::move(issued));

  decision.kind = request.kind;
  decision.plan = record.plan;
  decision.asset = key.asset;
  decision.lifecycle_generation = key.generation;
  decision.from_phase = Phase::commissioned;
  decision.to_phase = record.phase;
  decision.revision = record.fence.revision;
  decision.committed_sequence = candidate.sequence;
  decision.notes = record.notes;
  decision.effects.push_back(ErrorDetail{"plan", record.plan.to_hex()});
  decision.effects.push_back(
      ErrorDetail{"fence_token", EncodeFenceToken(record.fence)});

  const auto inserted = candidate.cases.emplace(record.key, std::move(record));
  if (!inserted.second) {
    return MakeError(ErrorCode::duplicate_identity, "a case already exists for this generation");
  }

  FleetAsset* fleet_asset = candidate.FindAsset(payload.asset);
  fleet_asset->lifecycle_generation = key.generation;
  fleet_asset->current_plan = inserted.first->second.plan;
  return OkStatus();
}

[[nodiscard]] Status ApplyMutation(StoreState& candidate, const Request& request,
                                   const CaseKey& key, Timestamp now, Decision& decision) {
  if (request.kind == RequestKind::create_plan) {
    return ApplyCreatePlan(candidate, request, key, now, decision);
  }

  RetirementCase* target = candidate.FindCase(key);
  if (target == nullptr) {
    return MakeError(ErrorCode::unknown_case, "case disappeared between validation and apply");
  }
  if (target->fence.revision.at_max()) {
    return MakeError(ErrorCode::value_saturated, "case revision cannot advance further");
  }

  decision.kind = request.kind;
  decision.plan = target->plan;
  decision.asset = key.asset;
  decision.lifecycle_generation = key.generation;
  decision.from_phase = target->phase;
  decision.key = KeyOf(request, target->plan, key.asset, key.generation);

  const auto& payload = request.payload;
  switch (request.kind) {
    case RequestKind::assess_dependencies: {
      const auto& body = std::get<AssessDependenciesPayload>(payload);
      EvidenceRef evidence = MakeEvidence(candidate, EvidenceKind::dependency_assessment,
                                          EvidenceProvenance::external_authority, body.authority,
                                          body.reference, body.detail, DrainKind::unknown,
                                          ObligationId{}, now, request.incarnation);
      decision.effects.push_back(ErrorDetail{"evidence", evidence.id.to_hex()});
      target->evidence.push_back(std::move(evidence));
      for (const DependencyFinding& finding : body.findings) {
        DrainObligation obligation;
        obligation.id = NewObligationId(candidate);
        obligation.kind = finding.kind;
        obligation.target = finding.target.is_set() ? finding.target : target->key.asset;
        obligation.protected_class = finding.protected_class;
        obligation.required = finding.required;
        obligation.state = finding.evaluated ? ObligationState::outstanding
                                             : ObligationState::unknown;
        obligation.issued_sequence = NewObservation(candidate);
        obligation.issued_at = now;
        obligation.issued_to = finding.issued_to;
        obligation.detail = finding.detail;
        decision.effects.push_back(
            ErrorDetail{"obligation", obligation.id.to_hex() + ":" +
                                          std::string(ToString(obligation.kind)) + ":" +
                                          std::string(ToString(obligation.state))});
        target->obligations.push_back(std::move(obligation));
      }
      target->phase = Phase::dependency_assessment;
      break;
    }
    case RequestKind::set_drain_requirement: {
      const auto& body = std::get<SetDrainRequirementPayload>(payload);
      if (target->obligations.size() >= kMaxObligationsPerCase) {
        return MakeError(ErrorCode::too_many_items, "case has reached the obligation limit");
      }
      DrainObligation obligation;
      obligation.id = NewObligationId(candidate);
      obligation.kind = body.kind;
      obligation.target = body.target.is_set() ? body.target : target->key.asset;
      obligation.protected_class = body.protected_class;
      obligation.required = body.required;
      obligation.state = ObligationState::outstanding;
      obligation.issued_sequence = NewObservation(candidate);
      obligation.issued_at = now;
      obligation.issued_to = body.issued_to;
      obligation.detail = body.detail;
      decision.effects.push_back(ErrorDetail{"obligation", obligation.id.to_hex()});
      target->obligations.push_back(std::move(obligation));
      if (target->phase != Phase::drain_required) {
        target->phase = Phase::drain_required;
      }
      break;
    }
    case RequestKind::acknowledge_drain: {
      const auto& body = std::get<AcknowledgeDrainPayload>(payload);
      DrainObligation* obligation = FindObligation(*target, body.obligation);
      if (obligation == nullptr) {
        return MakeError(ErrorCode::unknown_obligation, "obligation disappeared before apply");
      }
      // Acknowledgement is metadata. It never satisfies anything, and it is
      // recorded as its own evidence so the conflation is visible in the audit.
      EvidenceRef evidence = MakeEvidence(candidate, EvidenceKind::drain_request_acknowledgement,
                                          EvidenceProvenance::external_authority,
                                          body.acknowledged_by, body.reference, body.detail,
                                          obligation->kind, obligation->id, now,
                                          request.incarnation);
      decision.effects.push_back(ErrorDetail{"evidence", evidence.id.to_hex()});
      target->evidence.push_back(std::move(evidence));
      obligation->state = ObligationState::acknowledged;
      obligation->acknowledged_sequence = target->evidence.back().observation_sequence;
      obligation->acknowledged_at = now;
      obligation->acknowledged_by = body.acknowledged_by;
      decision.notes.push_back(MakeNote(
          "acknowledgement_is_not_effect",
          "the drain was acknowledged, not completed; a completion report is still required",
          now));
      break;
    }
    case RequestKind::satisfy_drain: {
      const auto& body = std::get<SatisfyDrainPayload>(payload);
      DrainObligation* obligation = FindObligation(*target, body.obligation);
      if (obligation == nullptr) {
        return MakeError(ErrorCode::unknown_obligation, "obligation disappeared before apply");
      }
      EvidenceRef evidence = MakeEvidence(candidate, RequiredEvidenceKind(*obligation),
                                          EvidenceProvenance::external_authority, body.observer,
                                          body.reference, body.detail, body.reported_kind,
                                          obligation->id, now, request.incarnation);
      if (evidence.observation_sequence <= obligation->issued_sequence) {
        return MakeError(ErrorCode::evidence_stale,
                         "completion evidence predates the obligation it claims to satisfy");
      }
      decision.effects.push_back(ErrorDetail{"evidence", evidence.id.to_hex()});
      obligation->state = ObligationState::satisfied;
      obligation->satisfaction_evidence = evidence.id;
      obligation->satisfied_sequence = evidence.observation_sequence;
      obligation->satisfied_at = now;
      obligation->satisfied_by = body.observer;
      target->evidence.push_back(std::move(evidence));
      break;
    }
    case RequestKind::waive_drain: {
      const auto& body = std::get<WaiveDrainPayload>(payload);
      DrainObligation* obligation = FindObligation(*target, body.obligation);
      if (obligation == nullptr) {
        return MakeError(ErrorCode::unknown_obligation, "obligation disappeared before apply");
      }
      if (target->exceptions.size() >= kMaxExceptionsPerCase) {
        return MakeError(ErrorCode::too_many_items, "case has reached the exception limit");
      }
      PolicyException exception;
      exception.id = NewExceptionId(candidate);
      exception.obligation = obligation->id;
      exception.plan = target->plan;
      exception.revision = target->fence.revision;
      exception.binding_digest = BindingDigest(target->fence.binding());
      exception.policy_generation = target->fence.policy_generation;
      exception.authority = body.authority;
      exception.reference = body.reference;
      exception.rationale = body.rationale;
      exception.recorded_at = now;
      exception.recorded_by = request.incarnation;
      decision.effects.push_back(ErrorDetail{"exception", exception.id.to_hex()});
      obligation->state = ObligationState::waived;
      obligation->waiver = exception.id;
      target->exceptions.push_back(std::move(exception));
      break;
    }
    case RequestKind::begin_draining:
      target->phase = Phase::draining;
      break;
    case RequestKind::conclude_draining:
      target->phase = Phase::authority_revocation;
      break;
    case RequestKind::record_revocation: {
      const auto& body = std::get<RecordRevocationPayload>(payload);
      const Digest binding = BindingDigest(target->fence.binding());
      for (const AuthorityDomain domain : body.domains) {
        RevocationReceipt receipt;
        receipt.id = NewReceiptId(candidate);
        receipt.domain = domain;
        receipt.binding_digest = binding;
        receipt.authority = body.authority;
        receipt.reference = body.reference;
        receipt.detail = body.detail;
        receipt.observation_sequence = NewObservation(candidate);
        receipt.recorded_at = now;
        receipt.recorded_by = request.incarnation;
        receipt.recorded_under_plan = target->plan;
        receipt.recorded_under_revision = target->fence.revision;
        decision.effects.push_back(
            ErrorDetail{"receipt", receipt.id.to_hex() + ":" + std::string(ToString(domain))});
        target->receipts.push_back(std::move(receipt));
        // The belief bit is cleared by the external authority's report, never by
        // the runtime's own reasoning.
        target->active_authority = target->active_authority.without(domain);
        if (FleetAsset* fleet_asset = candidate.FindAsset(target->key.asset);
            fleet_asset != nullptr) {
          fleet_asset->active_authority = fleet_asset->active_authority.without(domain);
        }
      }
      target->evidence.push_back(MakeEvidence(
          candidate, EvidenceKind::authority_revocation, EvidenceProvenance::external_authority,
          body.authority, body.reference, body.detail, DrainKind::unknown, ObligationId{}, now,
          request.incarnation));
      break;
    }
    case RequestKind::conclude_authority_revocation:
      target->phase = Phase::residual_handling;
      break;
    case RequestKind::set_residual_disposition: {
      const auto& body = std::get<SetResidualDispositionPayload>(payload);
      ResidualItem* item = nullptr;
      for (ResidualItem& candidate_item : target->residual) {
        if (candidate_item.category == body.category) {
          item = &candidate_item;
          break;
        }
      }
      if (item == nullptr) {
        if (target->residual.size() >= kMaxResidualPerCase) {
          return MakeError(ErrorCode::too_many_items, "case has reached the residual item limit");
        }
        ResidualItem fresh;
        fresh.id = NewResidualId(candidate);
        fresh.category = body.category;
        fresh.disposition = ResidualDisposition::unknown;
        target->residual.push_back(std::move(fresh));
        item = &target->residual.back();
      }
      item->disposition = body.disposition;
      item->detail = body.detail;
      item->authority = body.authority;
      item->reference = body.reference;
      item->observed_sequence = NewObservation(candidate);
      item->recorded_at = now;
      item->waiver = ExceptionId{};
      decision.effects.push_back(
          ErrorDetail{"residual", item->id.to_hex() + ":" +
                                      std::string(ToString(item->category)) + ":" +
                                      std::string(ToString(item->disposition))});
      break;
    }
    case RequestKind::record_policy_exception: {
      const auto& body = std::get<RecordPolicyExceptionPayload>(payload);
      if (target->exceptions.size() >= kMaxExceptionsPerCase) {
        return MakeError(ErrorCode::too_many_items, "case has reached the exception limit");
      }
      PolicyException exception;
      exception.id = NewExceptionId(candidate);
      exception.item = body.item;
      exception.obligation = body.obligation;
      exception.plan = target->plan;
      exception.revision = target->fence.revision;
      exception.binding_digest = BindingDigest(target->fence.binding());
      exception.policy_generation = target->fence.policy_generation;
      exception.authority = body.authority;
      exception.reference = body.reference;
      exception.rationale = body.rationale;
      exception.recorded_at = now;
      exception.recorded_by = request.incarnation;
      decision.effects.push_back(ErrorDetail{"exception", exception.id.to_hex()});
      if (body.item.is_set()) {
        ResidualItem* item = FindResidual(*target, body.item);
        if (item == nullptr) {
          return MakeError(ErrorCode::unknown_residual_item, "residual item disappeared");
        }
        item->disposition = ResidualDisposition::waived;
        item->waiver = exception.id;
      }
      if (body.obligation.is_set()) {
        DrainObligation* obligation = FindObligation(*target, body.obligation);
        if (obligation == nullptr) {
          return MakeError(ErrorCode::unknown_obligation, "obligation disappeared");
        }
        obligation->state = ObligationState::waived;
        obligation->waiver = exception.id;
      }
      target->exceptions.push_back(std::move(exception));
      target->evidence.push_back(MakeEvidence(
          candidate, EvidenceKind::policy_exception, EvidenceProvenance::external_authority,
          body.authority, body.reference, body.rationale, DrainKind::unknown, ObligationId{}, now,
          request.incarnation));
      break;
    }
    case RequestKind::declare_isolation_ready: {
      const auto& body = std::get<DeclareIsolationReadyPayload>(payload);
      EvidenceRef evidence = MakeEvidence(candidate, EvidenceKind::isolation_observation,
                                          EvidenceProvenance::external_authority, body.observer,
                                          body.reference, body.detail, DrainKind::unknown,
                                          ObligationId{}, now, request.incarnation);
      target->isolation_observed = true;
      target->isolation_evidence = evidence.id;
      target->isolation_sequence = evidence.observation_sequence;
      target->isolation_observer = body.observer;
      target->isolation_reference = body.reference;
      decision.effects.push_back(ErrorDetail{"evidence", evidence.id.to_hex()});
      target->evidence.push_back(std::move(evidence));
      target->phase = Phase::isolation_ready;
      break;
    }
    case RequestKind::authorize_removal: {
      const auto& body = std::get<AuthorizeRemovalPayload>(payload);
      EvidenceRef evidence = MakeEvidence(candidate, EvidenceKind::removal_authorization,
                                          EvidenceProvenance::external_authority, body.authority,
                                          body.reference, body.detail, DrainKind::unknown,
                                          ObligationId{}, now, request.incarnation);
      target->removal_authorized = true;
      target->removal_authorization_evidence = evidence.id;
      target->removal_authority = body.authority;
      target->removal_authorization_reference = body.reference;
      target->removal_authorized_at = now;
      decision.effects.push_back(ErrorDetail{"evidence", evidence.id.to_hex()});
      target->evidence.push_back(std::move(evidence));
      target->phase = Phase::removal_authorized;
      target->notes.push_back(MakeNote(
          "authorized_is_not_removed",
          "removal has been authorised; authorization is a grant and is not an observation that "
          "the asset was removed",
          now));
      break;
    }
    case RequestKind::observe_removal: {
      const auto& body = std::get<ObserveRemovalPayload>(payload);
      EvidenceRef evidence = MakeEvidence(candidate, EvidenceKind::removal_observation,
                                          EvidenceProvenance::external_authority, body.observer,
                                          body.reference, body.detail, DrainKind::unknown,
                                          ObligationId{}, now, request.incarnation);
      target->removal.observed = true;
      target->removal.evidence = evidence.id;
      target->removal.observer = body.observer;
      target->removal.reference = body.reference;
      target->removal.observation_sequence = evidence.observation_sequence;
      target->removal.observed_at = now;
      target->removal.canonical_deletion = false;
      decision.effects.push_back(ErrorDetail{"evidence", evidence.id.to_hex()});
      target->evidence.push_back(std::move(evidence));
      target->phase = Phase::removed_observed;
      target->notes.push_back(MakeNote(
          "removed_is_not_deleted",
          "physical removal was observed; canonical deletion is not owned by this runtime and "
          "remains absent",
          now));
      break;
    }
    case RequestKind::finalize_decommissioning: {
      const auto& body = std::get<FinalizeDecommissioningPayload>(payload);
      target->phase = Phase::decommissioned;
      if (!body.detail.empty()) {
        target->notes.push_back(MakeNote("finalize", body.detail, now));
      }
      decision.notes.push_back(MakeNote(
          "decommissioned",
          "the retirement decision is closed; canonical asset deletion is still owned by the "
          "inventory system and is not claimed here",
          now));
      break;
    }
    case RequestKind::cancel_plan: {
      const auto& body = std::get<CancelPlanPayload>(payload);
      target->cancel_reason = body.reason;
      if (const FleetAsset* fleet_asset = candidate.FindAsset(key.asset); fleet_asset != nullptr) {
        const PlanFence live = BuildFence(candidate, *fleet_asset, key.generation);
        if (RenderFenceField(live, FenceField::policy_generation) !=
                RenderFenceField(target->fence, FenceField::policy_generation) ||
            RenderFenceField(live, FenceField::dependency_generation) !=
                RenderFenceField(target->fence, FenceField::dependency_generation) ||
            RenderFenceField(live, FenceField::facility_epoch) !=
                RenderFenceField(target->fence, FenceField::facility_epoch) ||
            RenderFenceField(live, FenceField::hardware_generation) !=
                RenderFenceField(target->fence, FenceField::hardware_generation) ||
            RenderFenceField(live, FenceField::firmware_generation) !=
                RenderFenceField(target->fence, FenceField::firmware_generation)) {
          decision.notes.push_back(MakeNote(
              "closed_while_fenced",
              "the plan was closed rather than advanced: its binding no longer matches the "
              "facility, so no transition on it could have been authorised",
              now));
        }
      }
      target->phase = Phase::cancelled;
      break;
    }
    case RequestKind::fail_plan: {
      const auto& body = std::get<FailPlanPayload>(payload);
      target->failure_reason = body.reason;
      target->blocker.reason = BlockerReason::operator_failed;
      target->blocker.code = ErrorCode::phase_terminal;
      target->blocker.observed_phase = target->phase;
      target->blocker.detail = body.reason;
      target->blocker.required_action =
          "re-plan the asset to start a new lifecycle generation";
      target->phase = Phase::failed;
      break;
    }
    case RequestKind::block_plan: {
      const auto& body = std::get<BlockPlanPayload>(payload);
      target->resume_phase = target->phase;
      target->blocker.reason = body.reason;
      target->blocker.code = ErrorCode::phase_does_not_permit;
      target->blocker.observed_phase = target->phase;
      target->blocker.blocked_at = target->phase;
      target->blocker.detail = body.detail;
      target->blocker.required_action = body.required_action;
      target->phase = Phase::blocked;
      break;
    }
    case RequestKind::resume_plan: {
      const Phase resume = target->resume_phase;
      if (!IsActionable(resume)) {
        return MakeError(ErrorCode::invalid_transition,
                         "blocked case has no actionable resume phase");
      }
      target->phase = resume;
      target->resume_phase = Phase::unknown;
      target->blocker = Blocker{};
      break;
    }
    case RequestKind::ingest_evidence: {
      const auto& body = std::get<IngestEvidencePayload>(payload);
      EvidenceRef evidence = MakeEvidence(candidate, body.kind,
                                          EvidenceProvenance::external_authority, body.observer,
                                          body.reference, body.detail, DrainKind::unknown,
                                          ObligationId{}, now, request.incarnation);
      decision.effects.push_back(ErrorDetail{"evidence", evidence.id.to_hex()});
      target->evidence.push_back(std::move(evidence));
      break;
    }
    default:
      return MakeError(ErrorCode::not_implemented, "request kind has no application path");
  }

  // Epilogue: every accepted mutation advances the revision, refreshes the
  // obligation binding, and records the request in the registry so a lost
  // response can never cause a second application.
  target->fence.revision = target->fence.revision.Next();
  target->updated_at = now;
  RefreshObligationBinding(*target);

  if (target->registry.size() >= kMaxRegistryPerCase) {
    return MakeError(ErrorCode::too_many_items, "case has reached the request registry limit");
  }
  IssuedRequest issued;
  issued.attempt = request.attempt;
  issued.kind = request.kind;
  issued.key = decision.key;
  issued.committed_sequence = candidate.sequence;
  issued.resulting_revision = target->fence.revision;
  issued.resulting_phase = target->phase;
  issued.issued_at = now;
  target->registry.push_back(std::move(issued));

  decision.to_phase = target->phase;
  decision.revision = target->fence.revision;
  decision.committed_sequence = candidate.sequence;
  decision.effects.push_back(ErrorDetail{"fence_token", EncodeFenceToken(target->fence)});
  return OkStatus();
}

}  // namespace

// ---------------------------------------------------------------------------
// Engine lifecycle
// ---------------------------------------------------------------------------

Engine::Engine() noexcept = default;
Engine::~Engine() = default;
Engine::Engine(Engine&& other) noexcept : impl_(std::move(other.impl_)) {}
Engine& Engine::operator=(Engine&& other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
  }
  return *this;
}

Result<Engine> Engine::Open(Options options) {
  auto impl = std::make_unique<EngineImpl>();
  impl->options = options;
  impl->clock = options.clock;

  StoreState state;
  DF_TRY_DECL(DurableStore, store,
              DurableStore::Open(options.store_directory, options.store, state));
  impl->store = std::move(store);
  impl->store.options().lock_order = &impl->lock_order;
  impl->state = std::move(state);

  // Recovered persisted state is not automatically fresh live evidence. Every
  // observation that arrived here by recovery is marked as such, because this
  // incarnation has not re-verified it with the authority that reported it. The
  // annotation is applied on every open and is deliberately NOT durable state:
  // it is a statement about this incarnation, not about the record.
  for (auto& entry : impl->state.cases) {
    for (EvidenceRef& evidence : entry.second.evidence) {
      if (evidence.freshness == EvidenceFreshness::live) {
        evidence.freshness = EvidenceFreshness::recovered;
      }
    }
  }

  Engine engine;
  engine.impl_ = std::move(impl);
  return engine;
}

// ---------------------------------------------------------------------------
// Submit
// ---------------------------------------------------------------------------

Result<Decision> Engine::Submit(const Request& request) {
  if (impl_ == nullptr) {
    return MakeError(ErrorCode::internal_error, "engine is not open");
  }

  Decision decision;
  Status status = OkStatus();
  Blocker blocker;
  bool has_blocker = false;
  bool notify_decision = false;

  {
    const LockOrderGuard mutation_guard(&impl_->lock_order, kLockLevelMutationSerialiser);
    const std::unique_lock<std::mutex> writer(impl_->mutation_mu);

    StoreState candidate;
    CommitSequence base_sequence;
    Resolution resolution;
    {
      const std::shared_lock<std::shared_mutex> index_guard(impl_->index_mu);
      status = Resolve(impl_->state, request, resolution);
      base_sequence = impl_->state.sequence;
      if (status.ok() && !resolution.replay) {
        candidate = impl_->state;
      }
    }

    if (resolution.has_blocker) {
      blocker = resolution.blocker;
      has_blocker = true;
    }

    if (status.ok()) {
      const Timestamp now = request.at.is_set() ? request.at : NowOf(*impl_);
      if (resolution.replay) {
        decision.applied = false;
        decision.replayed = true;
        decision.kind = request.kind;
        decision.plan = resolution.record->plan;
        decision.asset = resolution.key.asset;
        decision.lifecycle_generation = resolution.key.generation;
        decision.revision = resolution.issued->resulting_revision;
        decision.committed_sequence = resolution.issued->committed_sequence;
        decision.from_phase = resolution.issued->resulting_phase;
        decision.to_phase = resolution.issued->resulting_phase;
        decision.key = resolution.issued->key;
        decision.notes.push_back(MakeNote(
            "idempotent_replay",
            "this attempt identity was already applied; the original outcome is reported and no "
            "second mutation was performed",
            now));
        notify_decision = true;
      } else {
        const CommitSequence next = base_sequence.Next();
        if (next == base_sequence) {
          status = MakeError(ErrorCode::value_saturated,
                             "the durable commit sequence has reached its maximum");
        } else {
          candidate.sequence = next;
          status = ApplyMutation(candidate, request, resolution.key, now, decision);
          if (status.ok()) {
            decision.applied = true;
            auto outcome = impl_->store.Commit(candidate);
            if (!outcome.ok()) {
              status = outcome.error();
              decision = Decision{};
            } else {
              decision.committed_sequence = outcome.value().sequence;
              impl_->last_commit.sequence = outcome.value().sequence;
              impl_->last_commit.record_bytes = outcome.value().record_bytes;
              impl_->last_commit.payload_bytes = outcome.value().payload_bytes;
              impl_->last_commit.used_slot_b = outcome.value().used_slot_b;
              impl_->last_commit.degraded = outcome.value().degraded;
              if (outcome.value().degraded) {
                decision.notes.push_back(MakeNote(
                    "commit_degraded",
                    "the generation was published and is authoritative, but a follow-up "
                    "durability step reported a problem: " +
                        outcome.value().degraded_reason,
                    now));
                decision.effects.push_back(ErrorDetail{"commit_degraded", "true"});
              }
              const std::unique_lock<std::shared_mutex> publish(impl_->index_mu);
              impl_->state = std::move(candidate);
              notify_decision = true;
            }
          }
        }
      }
    }

    if (!status.ok() && !has_blocker) {
      FillBlockerFromError(status.error(), blocker);
      has_blocker = true;
    }
  }

  // Callbacks run with every lock released. A throwing sink cannot corrupt state
  // and cannot escape into the caller.
  if (has_blocker && impl_->options.blocker_sink) {
    try {
      impl_->options.blocker_sink(blocker);
    } catch (...) {
      // A sink is an observer. Its failure is not the engine's.
    }
  }
  if (notify_decision && impl_->options.decision_sink) {
    try {
      impl_->options.decision_sink(decision);
    } catch (...) {
    }
  }

  if (!status.ok()) {
    return status.error();
  }
  return decision;
}

// ---------------------------------------------------------------------------
// Facility-wide mutations
// ---------------------------------------------------------------------------

Result<Decision> Engine::RegisterAsset(const RegisterAssetRequest& request) {
  if (impl_ == nullptr) {
    return MakeError(ErrorCode::internal_error, "engine is not open");
  }

  Decision decision;
  Status status = OkStatus();
  bool notify = false;

  {
    const LockOrderGuard mutation_guard(&impl_->lock_order, kLockLevelMutationSerialiser);
    const std::unique_lock<std::mutex> writer(impl_->mutation_mu);

    if (request.id.is_unset() || request.site.is_unset() || request.rack.is_unset()) {
      return ErrorBuilder(ErrorCode::unset_identity, "asset registration has an unset identity")
          .With("asset", request.id.to_hex())
          .Build();
    }
    if (request.hardware_generation.is_unset() || request.firmware_generation.is_unset()) {
      return ErrorBuilder(ErrorCode::unset_generation,
                          "asset registration has an unset generation")
          .With("asset", request.id.to_hex())
          .Build();
    }
    if (!request.active_authority.only_known_domains()) {
      return ErrorBuilder(ErrorCode::out_of_range,
                          "asset authority mask has bits outside the known domains")
          .With("asset", request.id.to_hex())
          .Build();
    }
    if (request.incarnation.is_unset()) {
      return MakeError(ErrorCode::unset_identity, "asset registration has no incarnation");
    }
    DF_TRY(CheckText(request.model, "model", false));
    DF_TRY(CheckText(request.serial, "serial", false));
    DF_TRY(CheckText(request.reason, "reason", false));

    const Timestamp now = request.at.is_set() ? request.at : NowOf(*impl_);

    StoreState candidate;
    bool changed = false;
    CommitSequence base_sequence;
    {
      const std::shared_lock<std::shared_mutex> index_guard(impl_->index_mu);
      DF_TRY(RequireHeadroom(impl_->state));
      base_sequence = impl_->state.sequence;
      const FleetAsset* existing = impl_->state.FindAsset(request.id);
      if (existing != nullptr && SameRegistration(*existing, request)) {
        decision.applied = false;
        decision.replayed = true;
        decision.asset = request.id;
        decision.notes.push_back(MakeNote(
            "idempotent_replay",
            "the asset is already registered with exactly these generations",
            now));
        notify = true;
      }
      if (!notify) {
        candidate = impl_->state;
        changed = true;
      }
    }

    if (changed) {
      const CommitSequence next = base_sequence.Next();
      if (next == base_sequence) {
        return MakeError(ErrorCode::value_saturated,
                         "the durable commit sequence has reached its maximum");
      }
      candidate.sequence = next;

      FleetAsset* existing = candidate.FindAsset(request.id);
      const bool is_new = existing == nullptr;
      if (is_new) {
        FleetAsset asset;
        asset.id = request.id;
        asset.registered_at = now;
        asset.registered_by = request.incarnation;
        asset.lifecycle_generation = LifecycleGeneration{};
        existing = &candidate.fleet.emplace(request.id, std::move(asset)).first->second;
      }
      const HardwareGeneration previous_hardware = existing->hardware_generation;
      const FirmwareGeneration previous_firmware = existing->firmware_generation;
      existing->site = request.site;
      existing->rack = request.rack;
      existing->hardware_generation = request.hardware_generation;
      existing->firmware_generation = request.firmware_generation;
      existing->active_authority = request.active_authority;
      existing->present = request.present;
      existing->model = request.model;
      existing->serial = request.serial;
      if (is_new) {
        existing->registered_at = now;
        existing->registered_by = request.incarnation;
      }

      decision.applied = true;
      decision.asset = request.id;
      decision.committed_sequence = next;
      if (is_new) {
        decision.notes.push_back(MakeNote(
            "registered",
            "asset registered with generation binding basis hardware=" +
                std::to_string(request.hardware_generation.value()) + " firmware=" +
                std::to_string(request.firmware_generation.value()),
            now));
      } else if (previous_hardware != request.hardware_generation ||
                 previous_firmware != request.firmware_generation) {
        // The asset's generation changed, so every plan bound to the previous
        // value is now stale. That is the fence working, not an accident.
        decision.notes.push_back(MakeNote(
            "generation_advanced",
            "asset generation advanced; every plan bound to the previous generation is now "
            "fenced and must be re-planned",
            now));
        decision.effects.push_back(ErrorDetail{"previous_hardware_generation",
                                               std::to_string(previous_hardware.value())});
        decision.effects.push_back(ErrorDetail{"previous_firmware_generation",
                                               std::to_string(previous_firmware.value())});
      } else {
        decision.notes.push_back(MakeNote("registration_updated",
                                          "asset registration updated without a generation change",
                                          now));
      }

      auto outcome = impl_->store.Commit(candidate);
      if (!outcome.ok()) {
        return outcome.error();
      }
      decision.committed_sequence = outcome.value().sequence;
      {
        const std::unique_lock<std::shared_mutex> publish(impl_->index_mu);
        impl_->state = std::move(candidate);
        impl_->last_commit.sequence = outcome.value().sequence;
        impl_->last_commit.record_bytes = outcome.value().record_bytes;
        impl_->last_commit.payload_bytes = outcome.value().payload_bytes;
        impl_->last_commit.used_slot_b = outcome.value().used_slot_b;
        impl_->last_commit.degraded = outcome.value().degraded;
      }
      notify = true;
    }
  }

  if (notify && impl_->options.decision_sink) {
    try {
      impl_->options.decision_sink(decision);
    } catch (...) {
    }
  }
  return decision;
}

Result<Decision> Engine::AdvanceGeneration(const GenerationAdvanceRequest& request) {
  if (impl_ == nullptr) {
    return MakeError(ErrorCode::internal_error, "engine is not open");
  }
  if (request.incarnation.is_unset()) {
    return MakeError(ErrorCode::unset_identity, "generation advance has no incarnation");
  }

  const LockOrderGuard mutation_guard(&impl_->lock_order, kLockLevelMutationSerialiser);
  const std::unique_lock<std::mutex> writer(impl_->mutation_mu);

  StoreState candidate;
  std::uint32_t current = 0;
  {
    const std::shared_lock<std::shared_mutex> index_guard(impl_->index_mu);
    current = CurrentGenerationValue(impl_->state, request.kind);
    candidate = impl_->state;
  }
  if (current != request.expected_current) {
    return ErrorBuilder(ErrorCode::value_saturated,
                        "facility generation does not match the value the caller observed")
        .With("generation", std::string(ToString(request.kind)))
        .With("expected", static_cast<std::uint64_t>(request.expected_current))
        .With("current", static_cast<std::uint64_t>(current))
        .Build();
  }
  if (current == 0xFFFFFFFFU) {
    return MakeError(ErrorCode::value_saturated, "facility generation is at its maximum");
  }

  const CommitSequence next = candidate.sequence.Next();
  if (next == candidate.sequence) {
    return MakeError(ErrorCode::value_saturated,
                     "the durable commit sequence has reached its maximum");
  }
  candidate.sequence = next;
  SetGenerationValue(candidate, request.kind, current + 1U);

  Decision decision;
  decision.applied = true;
  decision.committed_sequence = next;
  const Timestamp now = request.at.is_set() ? request.at : NowOf(*impl_);
  decision.notes.push_back(MakeNote(
      "generation_advanced",
      std::string(ToString(request.kind)) + " advanced from " + std::to_string(current) + " to " +
          std::to_string(current + 1U) +
          "; every plan bound to the previous value is now fenced and must be re-planned",
      now));
  decision.effects.push_back(ErrorDetail{"generation", std::string(ToString(request.kind))});
  decision.effects.push_back(ErrorDetail{"previous", std::to_string(current)});

  auto outcome = impl_->store.Commit(candidate);
  if (!outcome.ok()) {
    return outcome.error();
  }
  if (outcome.value().degraded) {
    decision.notes.push_back(MakeNote("commit_degraded", outcome.value().degraded_reason, now));
    decision.effects.push_back(ErrorDetail{"commit_degraded", "true"});
  }
  {
    const std::unique_lock<std::shared_mutex> publish(impl_->index_mu);
    impl_->state = std::move(candidate);
    impl_->last_commit.sequence = outcome.value().sequence;
    impl_->last_commit.record_bytes = outcome.value().record_bytes;
    impl_->last_commit.payload_bytes = outcome.value().payload_bytes;
    impl_->last_commit.used_slot_b = outcome.value().used_slot_b;
    impl_->last_commit.degraded = outcome.value().degraded;
  }

  if (impl_->options.decision_sink) {
    try {
      impl_->options.decision_sink(decision);
    } catch (...) {
    }
  }
  return decision;
}

std::string_view ToString(GenerationKind kind) noexcept {
  switch (kind) {
    case GenerationKind::facility_epoch: return "facility_epoch";
    case GenerationKind::policy: return "policy_generation";
    case GenerationKind::dependency: return "dependency_generation";
    case GenerationKind::capacity: return "capacity_generation";
    case GenerationKind::topology: return "topology_generation";
    case GenerationKind::maintenance: return "maintenance_generation";
  }
  return "facility_epoch";
}

GenerationKind GenerationKindFromString(std::string_view name) noexcept {
  for (std::uint32_t index = 0; index < static_cast<std::uint32_t>(kGenerationKindCount);
       ++index) {
    const auto kind = static_cast<GenerationKind>(index);
    if (ToString(kind) == name) {
      return kind;
    }
  }
  return GenerationKind::facility_epoch;
}

}  // namespace decommissioning_fabric


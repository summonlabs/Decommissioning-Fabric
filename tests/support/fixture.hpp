// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Shared test fixture: a real temporary store directory and a driver that walks
// the governed lifecycle one durable commit at a time.

#ifndef DECOMMISSIONING_FABRIC_TEST_FIXTURE_HPP
#define DECOMMISSIONING_FABRIC_TEST_FIXTURE_HPP

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "decommissioning_fabric/engine.hpp"
#include "decommissioning_fabric/time.hpp"
#include "harness.hpp"

namespace df_fixture {

namespace df = decommissioning_fabric;

/// Removes a unique temporary directory on destruction. Every test gets its own,
/// so tests never share durable state.
class TempDir {
 public:
  explicit TempDir(const std::string& label) {
    static std::atomic<unsigned> counter{0};
    const unsigned index = counter.fetch_add(1U);
    const std::filesystem::path base = std::filesystem::temp_directory_path();
    path_ = (base / ("dfab_" + label + "_" + std::to_string(::GetCurrentProcessId()) + "_" +
                     std::to_string(index)))
                .string();
    std::error_code error;
    std::filesystem::remove_all(path_, error);
  }

  ~TempDir() {
    std::error_code error;
    std::filesystem::remove_all(path_, error);
  }

  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  TempDir(TempDir&&) = delete;
  TempDir& operator=(TempDir&&) = delete;

  [[nodiscard]] const std::string& path() const { return path_; }

 private:
  std::string path_;
};

[[nodiscard]] inline df::Engine::Options OptionsFor(const TempDir& directory,
                                                    df::Clock* clock = nullptr) {
  df::Engine::Options options;
  options.store_directory = directory.path();
  options.store.create_if_missing = true;
  options.clock = clock;
  return options;
}

[[nodiscard]] inline df::Result<df::Engine> OpenEngine(const TempDir& directory,
                                                       df::Clock* clock = nullptr) {
  return df::Engine::Open(OptionsFor(directory, clock));
}

/// Walks one asset through the governed retirement lifecycle, always re-reading
/// the live fence before each request exactly as an operator would.
class Driver {
 public:
  Driver(df::Engine& engine, df::AssetId asset) : engine_(&engine), asset_(asset) {}

  [[nodiscard]] df::AssetId asset() const { return asset_; }
  [[nodiscard]] std::uint64_t attempts() const { return attempt_; }

  [[nodiscard]] df::Result<df::Decision> Register(std::uint32_t hardware = 3U,
                                                  std::uint32_t firmware = 7U) {
    df::RegisterAssetRequest registration;
    registration.id = asset_;
    registration.site = df::SiteId::FromValue(0x2001U);
    registration.rack = df::RackId::FromValue(0x3001U);
    registration.hardware_generation = df::HardwareGeneration::FromValue(hardware);
    registration.firmware_generation = df::FirmwareGeneration::FromValue(firmware);
    registration.active_authority = df::AuthorityMask{df::kAllAuthorityBits};
    registration.present = true;
    registration.model = "fixture";
    registration.serial = "FX-1";
    registration.incarnation = df::CurrentIncarnation();
    registration.at = df::Timestamp{df::ManualClock::kDefaultStartNanos};
    registration.reason = "test fixture";
    return engine_->RegisterAsset(registration);
  }

  /// Submits a request against the case's current fence. Never fabricates one.
  ///
  /// create_plan is the one request that has no case to fence against yet, so it
  /// is submitted without a fence exactly as the CLI submits it. Every other
  /// kind re-reads the live fence, which is what an operator does.
  [[nodiscard]] df::Result<df::Decision> Submit(df::RequestKind kind, df::RequestPayload payload) {
    if (kind == df::RequestKind::create_plan) {
      df::Request request;
      request.kind = kind;
      request.attempt = df::AttemptId::FromValue(++attempt_);
      request.incarnation = df::CurrentIncarnation();
      request.at = df::Timestamp{df::ManualClock::kDefaultStartNanos +
                                 static_cast<std::int64_t>(attempt_)};
      request.payload = std::move(payload);
      return engine_->Submit(request);
    }
    auto view = engine_->GetLatestCase(asset_);
    if (!view.ok()) {
      return view.error();
    }
    return SubmitAgainst(kind, std::move(payload), view.value().record.fence);
  }

  [[nodiscard]] df::Result<df::Decision> SubmitAgainst(df::RequestKind kind,
                                                       df::RequestPayload payload,
                                                       const df::PlanFence& fence) {
    df::Request request;
    request.kind = kind;
    request.attempt = df::AttemptId::FromValue(++attempt_);
    request.incarnation = df::CurrentIncarnation();
    request.at = df::Timestamp{df::ManualClock::kDefaultStartNanos +
                               static_cast<std::int64_t>(attempt_)};
    request.fence = fence;
    request.payload = std::move(payload);
    return engine_->Submit(request);
  }

  /// Re-submits using an explicit attempt identity so a lost-response replay can
  /// be exercised.
  [[nodiscard]] df::Result<df::Decision> SubmitWithAttempt(df::RequestKind kind,
                                                           df::RequestPayload payload,
                                                           std::uint64_t attempt) {
    df::Request request;
    request.kind = kind;
    request.attempt = df::AttemptId::FromValue(attempt);
    request.incarnation = df::CurrentIncarnation();
    request.at = df::Timestamp{df::ManualClock::kDefaultStartNanos +
                               static_cast<std::int64_t>(attempt)};
    request.payload = std::move(payload);
    if (kind != df::RequestKind::create_plan) {
      auto view = engine_->GetLatestCase(asset_);
      if (!view.ok()) {
        return view.error();
      }
      request.fence = view.value().record.fence;
    }
    return engine_->Submit(request);
  }

  [[nodiscard]] df::Result<df::Decision> CreatePlan(const std::string& rationale = "retire") {
    df::CreatePlanPayload payload;
    payload.asset = asset_;
    payload.rationale = rationale;
    return Submit(df::RequestKind::create_plan, std::move(payload));
  }

  [[nodiscard]] df::Result<df::Decision> Assess(std::vector<df::DependencyFinding> findings,
                                                const std::string& authority = "dep-authority") {
    df::AssessDependenciesPayload payload;
    payload.authority = authority;
    payload.reference = "DEP-1";
    payload.detail = "fixture assessment";
    payload.findings = std::move(findings);
    return Submit(df::RequestKind::assess_dependencies, std::move(payload));
  }

  [[nodiscard]] df::Result<df::Decision> Satisfy(df::ObligationId obligation, df::DrainKind kind,
                                                 bool wrong_kind = false) {
    df::SatisfyDrainPayload payload;
    payload.obligation = obligation;
    payload.reported_kind = wrong_kind ? df::DrainKind::external_dependency : kind;
    payload.observer = "drain-authority";
    payload.reference = "DR-1";
    payload.detail = "completed";
    return Submit(df::RequestKind::satisfy_drain, std::move(payload));
  }

  [[nodiscard]] df::Result<df::Decision> Acknowledge(df::ObligationId obligation) {
    df::AcknowledgeDrainPayload payload;
    payload.obligation = obligation;
    payload.acknowledged_by = "drain-authority";
    payload.reference = "ACK-1";
    return Submit(df::RequestKind::acknowledge_drain, std::move(payload));
  }

  [[nodiscard]] df::Result<df::Decision> Drains() {
    df::BeginDrainingPayload payload;
    payload.detail = "fixture";
    return Submit(df::RequestKind::begin_draining, std::move(payload));
  }

  [[nodiscard]] df::Result<df::Decision> ConcludeDraining() {
    df::ConcludeDrainingPayload payload;
    payload.detail = "fixture";
    return Submit(df::RequestKind::conclude_draining, std::move(payload));
  }

  [[nodiscard]] df::Result<df::Decision> RevokeAll(const std::string& authority = "authority") {
    std::vector<df::AuthorityDomain> domains;
    for (const df::AuthorityDomain domain : df::kAuthorityDomains) {
      domains.push_back(domain);
    }
    return RevokeDomains(domains, authority);
  }

  [[nodiscard]] df::Result<df::Decision> RevokeDomains(
      const std::vector<df::AuthorityDomain>& domains, const std::string& authority = "authority") {
    df::RecordRevocationPayload payload;
    payload.domains = domains;
    payload.authority = authority;
    payload.reference = "REV-1";
    payload.detail = "reported by the owning authority";
    return Submit(df::RequestKind::record_revocation, std::move(payload));
  }

  [[nodiscard]] df::Result<df::Decision> ConcludeAuthority() {
    df::ConcludeAuthorityRevocationPayload payload;
    payload.detail = "fixture";
    return Submit(df::RequestKind::conclude_authority_revocation, std::move(payload));
  }

  [[nodiscard]] df::Result<df::Decision> Residual(df::ResidualCategory category,
                                                  df::ResidualDisposition disposition) {
    df::SetResidualDispositionPayload payload;
    payload.category = category;
    payload.disposition = disposition;
    payload.detail = "fixture";
    payload.authority = "residual-authority";
    payload.reference = "RES-1";
    return Submit(df::RequestKind::set_residual_disposition, std::move(payload));
  }

  /// Records a handled disposition for every residual category that has no
  /// recorded decision yet. An already recorded category is left alone, so a
  /// deliberate waiver survives.
  [[nodiscard]] df::Status FillResidual() {
    auto view = Case();
    if (!view.ok()) {
      return view.error();
    }
    for (const df::ResidualCategory category : df::kResidualCategoryOrder) {
      if (category == df::ResidualCategory::unknown) {
        continue;
      }
      bool recorded = false;
      for (const df::ResidualItem& item : view.value().record.residual) {
        if (item.category == category) {
          recorded = true;
          break;
        }
      }
      if (recorded) {
        continue;
      }
      const df::Result<df::Decision> step = Residual(category, df::ResidualDisposition::handled);
      if (!step.ok()) {
        return step.error();
      }
    }
    return df::OkStatus();
  }

  [[nodiscard]] df::Result<df::Decision> Isolation() {
    df::DeclareIsolationReadyPayload payload;
    payload.observer = "facility-ops";
    payload.reference = "ISO-1";
    payload.detail = "isolated";
    return Submit(df::RequestKind::declare_isolation_ready, std::move(payload));
  }

  [[nodiscard]] df::Result<df::Decision> AuthorizeRemoval() {
    df::AuthorizeRemovalPayload payload;
    payload.authority = "change-board";
    payload.reference = "CRQ-1";
    payload.detail = "approved";
    return Submit(df::RequestKind::authorize_removal, std::move(payload));
  }

  [[nodiscard]] df::Result<df::Decision> ObserveRemoval() {
    df::ObserveRemovalPayload payload;
    payload.observer = "facility-ops";
    payload.reference = "OBS-1";
    payload.detail = "removed";
    return Submit(df::RequestKind::observe_removal, std::move(payload));
  }

  [[nodiscard]] df::Result<df::Decision> Finalize() {
    df::FinalizeDecommissioningPayload payload;
    payload.detail = "closed";
    return Submit(df::RequestKind::finalize_decommissioning, std::move(payload));
  }

  /// The obligation identities, in ascending identity order.
  [[nodiscard]] std::vector<df::ObligationId> Obligations() {
    std::vector<df::ObligationId> ids;
    auto view = engine_->GetLatestCase(asset_);
    if (!view.ok()) {
      return ids;
    }
    for (const df::DrainObligation& obligation : view.value().record.obligations) {
      ids.push_back(obligation.id);
    }
    return ids;
  }

  [[nodiscard]] df::Result<df::CaseView> Case() { return engine_->GetLatestCase(asset_); }

  [[nodiscard]] df::Phase Phase() {
    auto view = Case();
    return view.ok() ? view.value().record.phase : df::Phase::unknown;
  }

 private:
  df::Engine* engine_;
  df::AssetId asset_;
  std::uint64_t attempt_{0};
};

[[nodiscard]] inline df::DependencyFinding Finding(df::DrainKind kind,
                                                   df::ProtectedServiceClass protected_class =
                                                       df::ProtectedServiceClass::none,
                                                   bool required = true,
                                                   bool evaluated = true) {
  df::DependencyFinding finding;
  finding.kind = kind;
  finding.protected_class = protected_class;
  finding.required = required;
  finding.evaluated = evaluated;
  finding.issued_to = "drain-authority";
  finding.detail = "fixture";
  return finding;
}

}  // namespace df_fixture

#endif  // DECOMMISSIONING_FABRIC_TEST_FIXTURE_HPP

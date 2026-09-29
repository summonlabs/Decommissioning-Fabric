// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Crash-consistency driver. NOT installed.
//
// This program performs a deterministic sequence of durable commits and then
// exits. A test runs it with a fault plan that kills the process at a chosen
// step of a chosen commit, and then verifies that recovery yields exactly one
// authoritative generation with no merging and no torn state.
//
// Every commit this program makes is a real engine mutation through the real
// store. Nothing here shortcuts the commit protocol.

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include "decommissioning_fabric/engine.hpp"
#include "decommissioning_fabric/time.hpp"

namespace df = decommissioning_fabric;

namespace {

struct Options {
  std::string store;
  std::string faults;
  std::string scenario{"lifecycle"};
  std::uint64_t commits{0};
  bool create{false};
};

[[nodiscard]] bool Parse(int argc, char** argv, Options& options) {
  for (int index = 1; index < argc; ++index) {
    const std::string_view token(argv[index]);
    auto next = [&](std::string& target) {
      if (index + 1 >= argc) {
        return false;
      }
      target = argv[++index];
      return true;
    };
    if (token == "--store") {
      if (!next(options.store)) {
        return false;
      }
    } else if (token == "--fault-inject") {
      if (!next(options.faults)) {
        return false;
      }
    } else if (token == "--scenario") {
      if (!next(options.scenario)) {
        return false;
      }
    } else if (token == "--commits") {
      std::string text;
      if (!next(text)) {
        return false;
      }
      options.commits = std::strtoull(text.c_str(), nullptr, 10);
    } else if (token == "--create") {
      options.create = true;
    } else {
      std::fprintf(stderr, "dfab_crash_driver: unknown argument %s\n", std::string(token).c_str());
      return false;
    }
  }
  return !options.store.empty();
}

void Report(std::uint64_t index, const df::Decision& decision) {
  std::printf("COMMIT %llu %s %s\n", static_cast<unsigned long long>(index),
              std::string(df::ToString(decision.kind)).c_str(),
              std::string(df::ToString(decision.to_phase)).c_str());
  std::fflush(stdout);
}

void Fail(const df::Error& error) {
  std::fprintf(stderr, "dfab_crash_driver: %s\n", error.to_string().c_str());
  std::fflush(stderr);
  std::exit(3);
}

/// Reads the live fence of the newest case for an asset.
[[nodiscard]] df::PlanFence FenceOf(const df::Engine& engine, df::AssetId asset) {
  auto view = engine.GetLatestCase(asset);
  if (!view.ok()) {
    Fail(view.error());
  }
  return view.value().record.fence;
}

struct Runner {
  df::Engine* engine{nullptr};
  std::uint64_t index{0};

  void Check(const df::Result<df::Decision>& result) {
    if (!result.ok()) {
      Fail(result.error());
    }
    ++index;
    Report(index, result.value());
  }
};

[[nodiscard]] df::Request RequestFor(df::RequestKind kind, df::RequestPayload payload,
                                     const df::PlanFence& fence, std::uint64_t attempt) {
  df::Request request;
  request.kind = kind;
  request.attempt = df::AttemptId::FromValue(attempt);
  request.incarnation = df::CurrentIncarnation();
  request.at = df::Timestamp{df::ManualClock::kDefaultStartNanos + static_cast<std::int64_t>(attempt)};  // NOLINT
  request.fence = fence;
  request.payload = std::move(payload);
  return request;
}

/// Deterministic sequence used by the durability proof. Each step is exactly one
/// durable commit, so a kill at commit K leaves a prefix of this sequence.
void RunLifecycle(df::Engine& engine, std::uint64_t limit) {
  Runner runner;
  runner.engine = &engine;

  constexpr df::AssetId::underlying_type kAsset = 0x1001U;
  constexpr df::AssetId::underlying_type kSite = 0x2001U;
  constexpr df::AssetId::underlying_type kRack = 0x3001U;

  df::RegisterAssetRequest registration;
  registration.id = df::AssetId::FromValue(kAsset);
  registration.site = df::SiteId::FromValue(kSite);
  registration.rack = df::RackId::FromValue(kRack);
  registration.hardware_generation = df::HardwareGeneration::FromValue(3);
  registration.firmware_generation = df::FirmwareGeneration::FromValue(7);
  registration.active_authority = df::AuthorityMask{df::kAllAuthorityBits};
  registration.present = true;
  registration.model = "crash-driver";
  registration.serial = "CD-0001";
  registration.incarnation = df::CurrentIncarnation();
  registration.at = df::Timestamp{df::ManualClock::kDefaultStartNanos};
  registration.reason = "durability proof";
  runner.Check(engine.RegisterAsset(registration));
  if (limit != 0U && runner.index >= limit) {
    return;
  }

  df::CreatePlanPayload plan;
  plan.asset = df::AssetId::FromValue(kAsset);
  plan.rationale = "durability proof";
  {
    df::Request request;
    request.kind = df::RequestKind::create_plan;
    request.attempt = df::AttemptId::FromValue(1);
    request.incarnation = df::CurrentIncarnation();
    request.at = df::Timestamp{df::ManualClock::kDefaultStartNanos + 1};
    request.payload = plan;
    runner.Check(engine.Submit(request));
  }
  if (limit != 0U && runner.index >= limit) {
    return;
  }

  {
    df::AssessDependenciesPayload assessment;
    assessment.authority = "facility-dependency-authority";
    assessment.reference = "DEP-1";
    assessment.detail = "two dependencies";
    df::DependencyFinding asi;
    asi.kind = df::DrainKind::asi_workload;
    asi.issued_to = "asi";
    df::DependencyFinding dfi;
    dfi.kind = df::DrainKind::dfi_route;
    dfi.issued_to = "dfi";
    assessment.findings.push_back(asi);
    assessment.findings.push_back(dfi);
    runner.Check(engine.Submit(RequestFor(df::RequestKind::assess_dependencies, assessment,
                                           FenceOf(engine, df::AssetId::FromValue(kAsset)), 2)));
  }
  if (limit != 0U && runner.index >= limit) {
    return;
  }

  const df::AssetId asset = df::AssetId::FromValue(kAsset);
  auto case_view = engine.GetLatestCase(asset);
  if (!case_view.ok()) {
    Fail(case_view.error());
  }
  std::vector<df::ObligationId> obligations;
  for (const df::DrainObligation& obligation : case_view.value().record.obligations) {
    obligations.push_back(obligation.id);
  }

  std::uint64_t attempt = 3;
  for (std::size_t index = 0; index < obligations.size(); ++index) {
    df::SatisfyDrainPayload satisfaction;
    satisfaction.obligation = obligations[index];
    case_view = engine.GetLatestCase(asset);
    if (!case_view.ok()) {
      Fail(case_view.error());
    }
    const df::DrainObligation* obligation =
        df::FindObligation(case_view.value().record, obligations[index]);
    satisfaction.reported_kind = obligation->kind;
    satisfaction.observer = "drain-authority";
    satisfaction.reference = "DR-1";
    satisfaction.detail = "completed";
    runner.Check(engine.Submit(RequestFor(df::RequestKind::satisfy_drain, satisfaction,
                                           case_view.value().record.fence, attempt++)));
    if (limit != 0U && runner.index >= limit) {
      return;
    }
  }

  {
    auto view = engine.GetLatestCase(asset);
    if (!view.ok()) {
      Fail(view.error());
    }
    df::BeginDrainingPayload payload;
    payload.detail = "crash driver";
    runner.Check(engine.Submit(RequestFor(df::RequestKind::begin_draining, payload,
                                           view.value().record.fence, attempt++)));
  }
  if (limit != 0U && runner.index >= limit) {
    return;
  }

  {
    auto view = engine.GetLatestCase(asset);
    if (!view.ok()) {
      Fail(view.error());
    }
    df::ConcludeDrainingPayload payload;
    payload.detail = "every required drain is satisfied";
    runner.Check(engine.Submit(RequestFor(df::RequestKind::conclude_draining, payload,
                                           view.value().record.fence, attempt++)));
  }
  if (limit != 0U && runner.index >= limit) {
    return;
  }

  {
    auto view = engine.GetLatestCase(asset);
    if (!view.ok()) {
      Fail(view.error());
    }
    df::RecordRevocationPayload revocation;
    for (const df::AuthorityDomain domain : df::kAuthorityDomains) {
      revocation.domains.push_back(domain);
    }
    revocation.authority = "authority-registry";
    revocation.reference = "REV-1";
    revocation.detail = "all domains revoked by their owners";
    runner.Check(engine.Submit(
        RequestFor(df::RequestKind::record_revocation, revocation, view.value().record.fence,
                   attempt++)));
  }
  if (limit != 0U && runner.index >= limit) {
    return;
  }

  {
    auto view = engine.GetLatestCase(asset);
    if (!view.ok()) {
      Fail(view.error());
    }
    df::ConcludeAuthorityRevocationPayload payload;
    payload.detail = "crash driver";
    runner.Check(engine.Submit(RequestFor(df::RequestKind::conclude_authority_revocation, payload,
                                           view.value().record.fence, attempt++)));
  }
  if (limit != 0U && runner.index >= limit) {
    return;
  }

  for (const df::ResidualCategory category :
       {df::ResidualCategory::workload_state, df::ResidualCategory::persistent_media,
        df::ResidualCategory::credential_reference, df::ResidualCategory::network_identity,
        df::ResidualCategory::reservation, df::ResidualCategory::monitoring_binding,
        df::ResidualCategory::facility_reference, df::ResidualCategory::physical_asset}) {
    auto view = engine.GetLatestCase(asset);
    if (!view.ok()) {
      Fail(view.error());
    }
    df::SetResidualDispositionPayload payload;
    payload.category = category;
    payload.disposition = df::ResidualDisposition::handled;
    payload.detail = "handled by its owner";
    payload.authority = "residual-authority";
    payload.reference = "RES-1";
    runner.Check(engine.Submit(RequestFor(df::RequestKind::set_residual_disposition, payload,
                                           view.value().record.fence, attempt++)));
    if (limit != 0U && runner.index >= limit) {
      return;
    }
  }

  {
    auto view = engine.GetLatestCase(asset);
    if (!view.ok()) {
      Fail(view.error());
    }
    df::DeclareIsolationReadyPayload payload;
    payload.observer = "facility-operations";
    payload.reference = "ISO-1";
    payload.detail = "isolated";
    runner.Check(engine.Submit(RequestFor(df::RequestKind::declare_isolation_ready, payload,
                                           view.value().record.fence, attempt++)));
  }
  if (limit != 0U && runner.index >= limit) {
    return;
  }

  {
    auto view = engine.GetLatestCase(asset);
    if (!view.ok()) {
      Fail(view.error());
    }
    df::AuthorizeRemovalPayload payload;
    payload.authority = "facility-change-board";
    payload.reference = "CRQ-1";
    payload.detail = "removal approved";
    runner.Check(engine.Submit(
        RequestFor(df::RequestKind::authorize_removal, payload, view.value().record.fence,
                   attempt++)));
  }
  if (limit != 0U && runner.index >= limit) {
    return;
  }

  {
    auto view = engine.GetLatestCase(asset);
    if (!view.ok()) {
      Fail(view.error());
    }
    df::ObserveRemovalPayload payload;
    payload.observer = "facility-operations";
    payload.reference = "OBS-1";
    payload.detail = "asset removed from the rack";
    runner.Check(engine.Submit(
        RequestFor(df::RequestKind::observe_removal, payload, view.value().record.fence,
                   attempt++)));
  }
  if (limit != 0U && runner.index >= limit) {
    return;
  }

  {
    auto view = engine.GetLatestCase(asset);
    if (!view.ok()) {
      Fail(view.error());
    }
    df::FinalizeDecommissioningPayload payload;
    payload.detail = "closed";
    runner.Check(engine.Submit(RequestFor(df::RequestKind::finalize_decommissioning, payload,
                                           view.value().record.fence, attempt++)));
  }
}

/// Advances one facility generation per commit. Used by the crash-consistency
/// matrix, where the only thing that matters is the exact commit index.
void RunAdvance(df::Engine& engine, std::uint64_t commits) {
  Runner runner;
  runner.engine = &engine;
  for (std::uint64_t index = 0; index < commits; ++index) {
    df::GenerationAdvanceRequest advance;
    advance.kind = df::GenerationKind::facility_epoch;
    advance.expected_current = engine.generations().facility_epoch.value();
    advance.incarnation = df::CurrentIncarnation();
    advance.at = df::Timestamp{df::ManualClock::kDefaultStartNanos +
                               static_cast<std::int64_t>(index)};
    advance.reason = "crash matrix";
    runner.Check(engine.AdvanceGeneration(advance));
  }
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  if (!Parse(argc, argv, options)) {
    std::fprintf(stderr,
                 "usage: dfab_crash_driver --store DIR [--create] [--fault-inject SPEC]\n"
                 "                        [--scenario lifecycle|advance] [--commits N]\n");
    return 2;
  }

  auto faults = df::FaultPlan::FromSpec(options.faults);
  if (!faults.ok()) {
    Fail(faults.error());
  }

  df::Engine::Options engine_options;
  engine_options.store_directory = options.store;
  engine_options.store.create_if_missing = options.create;
  engine_options.store.faults = std::move(faults).value();

  auto engine = df::Engine::Open(std::move(engine_options));
  if (!engine.ok()) {
    Fail(engine.error());
  }

  if (options.scenario == "advance") {
    RunAdvance(engine.value(), options.commits == 0U ? 4U : options.commits);
  } else if (options.scenario == "lifecycle") {
    RunLifecycle(engine.value(), options.commits);
  } else {
    std::fprintf(stderr, "dfab_crash_driver: unknown scenario\n");
    return 2;
  }

  std::printf("DONE sequence=%llu\n",
              static_cast<unsigned long long>(engine.value().commit_sequence().value()));
  std::fflush(stdout);
  return 0;
}

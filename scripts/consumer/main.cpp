// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Exercises the INSTALLED Decommissioning Fabric artifact from an independent
// out-of-tree project. Everything it checks is checked against the installed
// library and the installed headers, never against the in-tree build.

#include <cstdio>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>

#include <decommissioning_fabric/engine.hpp>
#include <decommissioning_fabric/version.hpp>

namespace df = decommissioning_fabric;

namespace {

int failures = 0;

void Expect(bool condition, const char* what) {
  if (condition) {
    std::printf("ok   %s\n", what);
    return;
  }
  ++failures;
  std::printf("FAIL %s\n", what);
}

}  // namespace

int main() {
  std::printf("installed Decommissioning Fabric %s (commit %s, dirty %s)\n",
              std::string(df::kVersionString).c_str(), std::string(df::kBuildCommit).c_str(),
              std::string(df::kBuildDirty).c_str());
  Expect(df::kVersionMajor == 1U, "installed header reports major version 1");
  Expect(df::kRepositoryOrdinal == 34U && df::kRepositoryTotal == 72U,
         "installed header reports the DCCP repository ordinal");

  const std::filesystem::path directory =
      std::filesystem::temp_directory_path() / "dfab_consumer_artifact";
  std::error_code error;
  std::filesystem::remove_all(directory, error);

  df::Engine::Options options;
  options.store_directory = directory.string();
  options.store.create_if_missing = true;
  auto engine = df::Engine::Open(std::move(options));
  Expect(engine.ok(), "installed library opens a durable store");
  if (!engine.ok()) {
    std::printf("     %s\n", engine.error().to_string().c_str());
    return 1;
  }

  const df::AssetId asset = df::AssetId::FromValue(0x1001U);
  df::RegisterAssetRequest registration;
  registration.id = asset;
  registration.site = df::SiteId::FromValue(0x2001U);
  registration.rack = df::RackId::FromValue(0x3001U);
  registration.hardware_generation = df::HardwareGeneration::FromValue(1);
  registration.firmware_generation = df::FirmwareGeneration::FromValue(1);
  registration.active_authority = df::AuthorityMask{df::kAllAuthorityBits};
  registration.incarnation = df::CurrentIncarnation();
  registration.at = df::Timestamp{df::ManualClock::kDefaultStartNanos};
  Expect(engine.value().RegisterAsset(registration).ok(), "installed library registers an asset");

  df::Request request;
  request.kind = df::RequestKind::create_plan;
  request.attempt = df::AttemptId::FromValue(1);
  request.incarnation = df::CurrentIncarnation();
  request.at = df::Timestamp{df::ManualClock::kDefaultStartNanos + 1};
  df::CreatePlanPayload payload;
  payload.asset = asset;
  payload.rationale = "installed artifact check";
  request.payload = std::move(payload);
  auto decision = engine.value().Submit(request);
  Expect(decision.ok(), "installed library applies a plan creation");
  if (decision.ok()) {
    Expect(decision.value().to_phase == df::Phase::requested,
           "installed library reports the requested phase");
    Expect(decision.value().committed_sequence.value() == 2U,
           "installed library reports the durable commit sequence");
  }

  auto view = engine.value().GetLatestCase(asset);
  Expect(view.ok(), "installed library reads back the case");
  if (view.ok()) {
    Expect(view.value().fence_token.empty() == false,
           "installed library renders a compare-and-swap fence token");
    auto decoded = df::DecodeFenceToken(view.value().fence_token);
    Expect(decoded.ok(), "installed library decodes its own fence token");
    if (decoded.ok()) {
      Expect(decoded.value() == view.value().record.fence,
             "installed fence token round trips exactly");
    }
  }

  auto blockers =
      engine.value().ExplainBlockers(df::CaseKey{asset, df::LifecycleGeneration::First()});
  Expect(blockers.ok(), "installed library explains blockers");

  engine.value() = df::Engine{};
  std::filesystem::remove_all(directory, error);

  std::printf("%s\n", failures == 0 ? "consumer: ALL CHECKS PASSED" : "consumer: FAILURES");
  return failures == 0 ? 0 : 1;
}

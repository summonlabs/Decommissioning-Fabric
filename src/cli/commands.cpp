// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0

#include <cstdio>
#include <iostream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "cli.hpp"

#include "decommissioning_fabric/version.hpp"

namespace decommissioning_fabric::cli {
namespace {

struct Context {
  Args args;
  bool json{false};
  Engine* engine{nullptr};
  std::string out;
};

void Emit(Context& context, std::string text) { context.out += std::move(text); }

[[nodiscard]] Result<std::string> RequireOption(const Args& args, std::string_view name) {
  if (!args.has(name)) {
    return ErrorBuilder(ErrorCode::missing_field, "required option is absent")
        .With("option", name)
        .Build();
  }
  const std::string value = args.one(name);
  if (value.empty()) {
    return ErrorBuilder(ErrorCode::missing_field, "required option is empty")
        .With("option", name)
        .Build();
  }
  return value;
}

[[nodiscard]] Result<AssetId> RequireAsset(const Args& args) {
  DF_TRY_DECL(std::string, text, RequireOption(args, "asset"));
  DF_TRY_DECL(std::uint64_t, value, ParseHexU64(text, "asset"));
  return AssetId::FromValue(value);
}

[[nodiscard]] Result<PlanFence> RequireFence(const Args& args) {
  DF_TRY_DECL(std::string, token, RequireOption(args, "fence"));
  return DecodeFenceToken(token);
}

[[nodiscard]] Result<AttemptId> AttemptOf(const Args& args, const Engine& engine) {
  if (args.has("attempt")) {
    DF_TRY_DECL(std::uint64_t, value, args.number("attempt"));
    if (value == 0U) {
      return MakeError(ErrorCode::unset_attempt, "attempt identity must be at least 1");
    }
    return AttemptId::FromValue(value);
  }
  const CommitSequence next = engine.commit_sequence().Next();
  return AttemptId::FromValue(next.is_unset() ? 1U : next.value());
}

[[nodiscard]] Timestamp TimeOf(const Args& args) {
  if (args.has("at")) {
    const auto value = args.number("at");
    if (value.ok()) {
      return Timestamp{static_cast<std::int64_t>(value.value())};
    }
  }
  return Timestamp{};
}

[[nodiscard]] Result<CaseKey> ResolveKey(Context& context, const Args& args) {
  if (args.has("fence")) {
    DF_TRY_DECL(PlanFence, fence, RequireFence(args));
    return CaseKey{fence.asset, fence.lifecycle_generation};
  }
  DF_TRY_DECL(AssetId, asset, RequireAsset(args));
  if (args.has("lifecycle-generation")) {
    DF_TRY_DECL(std::uint64_t, generation, args.number("lifecycle-generation"));
    if (generation == 0U || generation > 0xFFFFFFFFULL) {
      return MakeError(ErrorCode::out_of_range, "lifecycle generation is out of range");
    }
    return CaseKey{asset, LifecycleGeneration::FromValue(static_cast<std::uint32_t>(generation))};
  }
  auto view = context.engine->GetLatestCase(asset);
  if (!view.ok()) {
    return view.error();
  }
  return view.value().record.key;
}

[[nodiscard]] Result<DrainKind> RequireDrainKind(const Args& args) {
  DF_TRY_DECL(std::string, text, RequireOption(args, "kind"));
  const DrainKind kind = DrainKindFromString(text);
  if (kind == DrainKind::unknown) {
    return ErrorBuilder(ErrorCode::out_of_range, "unknown drain kind")
        .With("kind", text)
        .Build();
  }
  return kind;
}

[[nodiscard]] Result<AuthorityDomain> RequireDomain(const Args& args) {
  DF_TRY_DECL(std::string, text, RequireOption(args, "domain"));
  const AuthorityDomain domain = AuthorityDomainFromString(text);
  if (domain == AuthorityDomain::none) {
    return ErrorBuilder(ErrorCode::out_of_range, "unknown authority domain")
        .With("domain", text)
        .Build();
  }
  return domain;
}

[[nodiscard]] Result<ProtectedServiceClass> OptionalProtectedClass(const Args& args) {
  if (!args.has("protected-class")) {
    return ProtectedServiceClass::none;
  }
  const std::string text = args.one("protected-class");
  const ProtectedServiceClass value = ProtectedServiceClassFromString(text);
  if (value == ProtectedServiceClass::none && text != "none") {
    return ErrorBuilder(ErrorCode::out_of_range, "unknown protected service class")
        .With("protected-class", text)
        .Build();
  }
  return value;
}

[[nodiscard]] Result<ObligationId> RequireObligation(const Args& args) {
  DF_TRY_DECL(std::string, text, RequireOption(args, "obligation"));
  DF_TRY_DECL(std::uint64_t, value, ParseHexU64(text, "obligation"));
  return ObligationId::FromValue(value);
}

[[nodiscard]] int Report(Context& context, const Result<Decision>& result) {
  if (!result.ok()) {
    Emit(context, RenderError(result.error(), context.json));
    return kExitRefused;
  }
  Emit(context, RenderDecision(result.value(), context.json));
  return kExitOk;
}

}  // namespace

void PrintUsage(std::string& out) {
  out +=
      "dfab - Decommissioning Fabric (DCCP repository 34 of 72)\n"
      "\n"
      "Usage: dfab <command> [subcommand] [options]\n"
      "\n"
      "Global options\n"
      "  --store DIR                 store directory (required for every engine command)\n"
      "  --create                    create the store directory when it does not exist\n"
      "  --fault-inject SPEC         inject commit faults (kill, truncate, bitflip,\n"
      "                              write_short, directory_flush_fail)\n"
      "  --lock-retry-millis N       retry the single-writer lock for at most N ms\n"
      "  --json                      machine readable output\n"
      "  --attempt N                 idempotency identity; re-running with the same\n"
      "                              value replays instead of mutating twice\n"
      "  --at NANOS                  request timestamp (engine clock is used when absent)\n"
      "  --fence TOKEN               compare-and-swap fence from 'plan show'\n"
      "\n"
      "Commands\n"
      "  version\n"
      "  store status\n"
      "  generation show\n"
      "  generation advance --kind facility_epoch|policy_generation|dependency_generation|\n"
      "                     capacity_generation|topology_generation|maintenance_generation\n"
      "                     --expected N\n"
      "  asset register --asset HEX --site HEX --rack HEX --hardware-generation N\n"
      "                 --firmware-generation N [--authority-mask N] [--model TEXT]\n"
      "                 [--serial TEXT] [--absent]\n"
      "  asset list | asset show --asset HEX\n"
      "  plan create --asset HEX [--lifecycle-generation N] [--rationale TEXT]\n"
      "  plan list | plan show --asset HEX [--lifecycle-generation N]\n"
      "  plan explain --asset HEX [--lifecycle-generation N]\n"
      "  plan cancel|fail|block|resume|finalize --fence TOKEN [--reason TEXT]\n"
      "  dependencies assess --fence TOKEN --authority NAME --reference TEXT\n"
      "                      [--require KIND[:CLASS][:optional][:unevaluated][:TO]]...\n"
      "  dependencies inspect --asset HEX [--lifecycle-generation N]\n"
      "  drain require --fence TOKEN --kind KIND --issued-to NAME\n"
      "                [--protected-class CLASS] [--optional] [--target HEX]\n"
      "  drain list --asset HEX [--lifecycle-generation N]\n"
      "  drain acknowledge --fence TOKEN --obligation HEX --acknowledged-by NAME --reference TEXT\n"
      "  drain satisfy --fence TOKEN --obligation HEX --kind KIND --observer NAME --reference TEXT\n"
      "  drain waive --fence TOKEN --obligation HEX --authority NAME --reference TEXT\n"
      "              --rationale TEXT\n"
      "  drain begin --fence TOKEN | drain conclude --fence TOKEN\n"
      "  authority revoke --fence TOKEN --domain DOMAIN [--domain DOMAIN]...\n"
      "                   --authority NAME --reference TEXT\n"
      "  authority status --asset HEX [--lifecycle-generation N]\n"
      "  authority conclude --fence TOKEN\n"
      "  residual list --asset HEX [--lifecycle-generation N]\n"
      "  residual set --fence TOKEN --category CATEGORY --disposition DISPOSITION\n"
      "               --authority NAME --reference TEXT [--detail TEXT]\n"
      "  residual exception --fence TOKEN --item HEX --authority NAME --reference TEXT\n"
      "                     --rationale TEXT\n"
      "  isolation declare --fence TOKEN --observer NAME --reference TEXT\n"
      "  removal authorize --fence TOKEN --authority NAME --reference TEXT\n"
      "  removal observe --fence TOKEN --observer NAME --reference TEXT\n"
      "  evidence ingest --fence TOKEN --kind KIND --observer NAME --reference TEXT\n"
      "  evidence list --asset HEX [--lifecycle-generation N]\n";
}

// ---------------------------------------------------------------------------
// Store / engine plumbing
// ---------------------------------------------------------------------------

namespace {

[[nodiscard]] Result<Engine::Options> BuildOptions(const Args& args) {
  Engine::Options options;
  DF_TRY_DECL(std::string, directory, RequireOption(args, "store"));
  options.store_directory = directory;
  options.store.create_if_missing = args.has("create");
  if (args.has("fault-inject")) {
    DF_TRY_ASSIGN(options.store.faults, FaultPlan::FromSpec(args.one("fault-inject")));
  }
  if (args.has("lock-retry-millis")) {
    options.store.lock_mode = LockMode::retry_bounded;
    DF_TRY_ASSIGN(options.store.lock_retry_millis, args.number32_or("lock-retry-millis", 0));
  }
  return options;
}

/// Runs one engine-command body with the store open.
template <typename Body>
[[nodiscard]] int WithEngine(Context& context, Body&& body) {
  auto options = BuildOptions(context.args);
  if (!options.ok()) {
    Emit(context, RenderError(options.error(), context.json));
    return kExitUsage;
  }
  auto engine = Engine::Open(std::move(options).value());
  if (!engine.ok()) {
    Emit(context, RenderError(engine.error(), context.json));
    return kExitRefused;
  }
  context.engine = &engine.value();
  auto result = body(engine.value());
  if (!result.ok()) {
    Emit(context, RenderError(result.error(), context.json));
    return kExitUsage;
  }
  return result.value();
}

[[nodiscard]] Request BuildRequest(Context& context, RequestKind kind, RequestPayload payload,
                                   const PlanFence& fence, const AttemptId attempt) {
  Request request;
  request.kind = kind;
  request.attempt = attempt;
  request.incarnation = CurrentIncarnation();
  request.at = TimeOf(context.args);
  request.fence = fence;
  request.payload = std::move(payload);
  return request;
}

}  // namespace

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

namespace {

[[nodiscard]] int CmdVersion(Context& context) {
  std::string out;
  if (context.json) {
    JsonWriter writer(out);
    writer.BeginObject();
    writer.Field("version", kVersionString);
    writer.Field("repository_ordinal", static_cast<std::uint64_t>(kRepositoryOrdinal));
    writer.Field("repository_total", static_cast<std::uint64_t>(kRepositoryTotal));
    writer.Field("tranche", kTrancheName);
    writer.Field("build_commit", kBuildCommit);
    writer.Field("build_dirty", kBuildDirty);
    writer.Field("vendor_neutral", kVendorNeutralStatement);
    writer.EndObject();
    out.push_back('\n');
  } else {
    out += "dfab ";
    out += kVersionString;
    out += "\n";
    out += "  repository      : DCCP ";
    out += std::to_string(kRepositoryOrdinal);
    out += " of ";
    out += std::to_string(kRepositoryTotal);
    out += "\n";
    out += "  tranche         : ";
    out += kTrancheName;
    out += "\n";
    out += "  build commit    : ";
    out += kBuildCommit;
    out += "\n";
    out += "  build dirty     : ";
    out += kBuildDirty;
    out += "\n";
    out += "  vendor          : ";
    out += kVendorNeutralStatement;
    out += "\n";
  }
  Emit(context, std::move(out));
  return kExitOk;
}

[[nodiscard]] int CmdStoreStatus(Context& context) {
  return WithEngine(context, [&](Engine& engine) -> Result<int> {
    Emit(context, RenderRecovery(engine.store_directory(), engine.recovery(),
                                 engine.commit_sequence(), context.json));
    return kExitOk;
  });
}

[[nodiscard]] int CmdGenerationShow(Context& context) {
  return WithEngine(context, [&](Engine& engine) -> Result<int> {
    Emit(context, RenderGenerations(engine.generations(), context.json));
    return kExitOk;
  });
}

[[nodiscard]] int CmdGenerationAdvance(Context& context) {
  return WithEngine(context, [&](Engine& engine) -> Result<int> {
    DF_TRY_DECL(std::string, kind_text, RequireOption(context.args, "kind"));
    const GenerationKind kind = GenerationKindFromString(kind_text);
    if (kind == GenerationKind::facility_epoch && kind_text != "facility_epoch") {
      Emit(context, RenderError(ErrorBuilder(ErrorCode::out_of_range,
                                             "unknown generation kind")
                                    .With("kind", kind_text)
                                    .Build(),
                                context.json));
      return kExitUsage;
    }
    GenerationAdvanceRequest request;
    request.kind = kind;
    auto expected = context.args.number("expected");
    if (!expected.ok()) {
      Emit(context, RenderError(expected.error(), context.json));
      return kExitUsage;
    }
    request.expected_current = static_cast<std::uint32_t>(expected.value() & 0xFFFFFFFFULL);
    request.incarnation = CurrentIncarnation();
    request.at = TimeOf(context.args);
    request.reason = context.args.one("reason");
    return Report(context, engine.AdvanceGeneration(request));
  });
}

[[nodiscard]] int CmdAssetRegister(Context& context) {
  return WithEngine(context, [&](Engine& engine) -> Result<int> {
    RegisterAssetRequest request;
    DF_TRY_ASSIGN(request.id, RequireAsset(context.args));
    DF_TRY_DECL(std::string, site_text, RequireOption(context.args, "site"));
    DF_TRY_DECL(std::uint64_t, site_value, ParseHexU64(site_text, "site"));
    request.site = SiteId::FromValue(site_value);
    DF_TRY_DECL(std::string, rack_text, RequireOption(context.args, "rack"));
    DF_TRY_DECL(std::uint64_t, rack_value, ParseHexU64(rack_text, "rack"));
    request.rack = RackId::FromValue(rack_value);
    auto hardware = context.args.number("hardware-generation");
    if (!hardware.ok() || hardware.value() == 0U || hardware.value() > 0xFFFFFFFFULL) {
      Emit(context, RenderError(ErrorBuilder(ErrorCode::out_of_range,
                                             "--hardware-generation must be 1..4294967295")
                                    .Build(),
                                context.json));
      return kExitUsage;
    }
    request.hardware_generation =
        HardwareGeneration::FromValue(static_cast<std::uint32_t>(hardware.value()));
    auto firmware = context.args.number("firmware-generation");
    if (!firmware.ok() || firmware.value() == 0U || firmware.value() > 0xFFFFFFFFULL) {
      Emit(context, RenderError(ErrorBuilder(ErrorCode::out_of_range,
                                             "--firmware-generation must be 1..4294967295")
                                    .Build(),
                                context.json));
      return kExitUsage;
    }
    request.firmware_generation =
        FirmwareGeneration::FromValue(static_cast<std::uint32_t>(firmware.value()));
    request.active_authority =
        AuthorityMask{context.args.has("authority-mask")
                          ? static_cast<std::uint32_t>(context.args.number("authority-mask").value())
                          : kAllAuthorityBits};
    request.present = !context.args.has("absent");
    request.model = context.args.one("model");
    request.serial = context.args.one("serial");
    request.incarnation = CurrentIncarnation();
    request.at = TimeOf(context.args);
    request.reason = context.args.one("reason");
    return Report(context, engine.RegisterAsset(request));
  });
}

[[nodiscard]] int CmdAssetList(Context& context) {
  return WithEngine(context, [&](Engine& engine) -> Result<int> {
    const std::vector<AssetView> assets = engine.ListAssets();
    if (context.json) {
      std::string out;
      JsonWriter writer(out);
      writer.BeginArray("assets");
      for (const AssetView& view : assets) {
        writer.BeginObject();
        writer.Field("asset", view.asset.id.to_hex());
        writer.Field("hardware_generation", view.asset.hardware_generation.value());
        writer.Field("firmware_generation", view.asset.firmware_generation.value());
        writer.Field("lifecycle_generation", view.asset.lifecycle_generation.value());
        writer.Field("phase", view.has_case ? ToString(view.phase) : std::string("no_case"));
        writer.EndObject();
      }
      writer.EndArray();
      out.push_back('\n');
      Emit(context, std::move(out));
      return kExitOk;
    }
    std::string out;
    out += "assets\n";
    for (const AssetView& view : assets) {
      out += "  ";
      out += view.asset.id.to_hex();
      out += "  hw=";
      out += std::to_string(view.asset.hardware_generation.value());
      out += "  fw=";
      out += std::to_string(view.asset.firmware_generation.value());
      out += "  lifecycle=";
      out += std::to_string(view.asset.lifecycle_generation.value());
      out += "  phase=";
      out += view.has_case ? ToString(view.phase) : "no_case";
      out += "\n";
    }
    if (assets.empty()) {
      out += "  (none)\n";
    }
    Emit(context, std::move(out));
    return kExitOk;
  });
}

[[nodiscard]] int CmdAssetShow(Context& context) {
  return WithEngine(context, [&](Engine& engine) -> Result<int> {
    DF_TRY_DECL(AssetId, asset, RequireAsset(context.args));
    auto view = engine.GetAsset(asset);
    if (!view.ok()) {
      Emit(context, RenderError(view.error(), context.json));
      return kExitRefused;
    }
    Emit(context, RenderAsset(view.value(), context.json));
    return kExitOk;
  });
}

[[nodiscard]] int CmdPlanCreate(Context& context) {
  return WithEngine(context, [&](Engine& engine) -> Result<int> {
    CreatePlanPayload payload;
    DF_TRY_ASSIGN(payload.asset, RequireAsset(context.args));
    if (context.args.has("lifecycle-generation")) {
      const auto generation = context.args.number("lifecycle-generation");
      if (!generation.ok() || generation.value() == 0U || generation.value() > 0xFFFFFFFFULL) {
        Emit(context, RenderError(MakeError(ErrorCode::out_of_range,
                                            "--lifecycle-generation is out of range"),
                                  context.json));
        return kExitUsage;
      }
      payload.lifecycle_generation =
          LifecycleGeneration::FromValue(static_cast<std::uint32_t>(generation.value()));
    }
    payload.rationale = context.args.one("rationale");

    Request request;
    request.kind = RequestKind::create_plan;
    DF_TRY_ASSIGN(request.attempt, AttemptOf(context.args, engine));
    request.incarnation = CurrentIncarnation();
    request.at = TimeOf(context.args);
    request.payload = std::move(payload);
    return Report(context, engine.Submit(request));
  });
}

[[nodiscard]] int CmdPlanList(Context& context) {
  return WithEngine(context, [&](Engine& engine) -> Result<int> {
    const std::vector<CaseKey> keys = engine.ListCases();
    if (context.json) {
      std::string out;
      JsonWriter writer(out);
      writer.BeginArray("cases");
      for (const CaseKey& key : keys) {
        auto view = engine.GetCase(key);
        if (!view.ok()) {
          continue;
        }
        writer.BeginObject();
        writer.Field("asset", key.asset.to_hex());
        writer.Field("lifecycle_generation", key.generation.value());
        writer.Field("plan", view.value().record.plan.to_hex());
        writer.Field("phase", ToString(view.value().record.phase));
        writer.Field("revision", view.value().record.fence.revision.value());
        writer.EndObject();
      }
      writer.EndArray();
      out.push_back('\n');
      Emit(context, std::move(out));
      return kExitOk;
    }
    std::string out;
    out += "retirement cases\n";
    for (const CaseKey& key : keys) {
      auto view = engine.GetCase(key);
      if (!view.ok()) {
        continue;
      }
      out += "  ";
      out += key.asset.to_hex();
      out += "  generation=";
      out += std::to_string(key.generation.value());
      out += "  plan=";
      out += view.value().record.plan.to_hex();
      out += "  phase=";
      out += ToString(view.value().record.phase);
      out += "  revision=";
      out += std::to_string(view.value().record.fence.revision.value());
      out += "\n";
    }
    if (keys.empty()) {
      out += "  (none)\n";
    }
    Emit(context, std::move(out));
    return kExitOk;
  });
}

[[nodiscard]] int CmdPlanShow(Context& context) {
  return WithEngine(context, [&](Engine& engine) -> Result<int> {
    DF_TRY_DECL(CaseKey, key, ResolveKey(context, context.args));
    auto view = engine.GetCase(key);
    if (!view.ok()) {
      Emit(context, RenderError(view.error(), context.json));
      return kExitRefused;
    }
    Emit(context, RenderCase(view.value(), context.json));
    return kExitOk;
  });
}

[[nodiscard]] int CmdPlanExplain(Context& context) {
  return WithEngine(context, [&](Engine& engine) -> Result<int> {
    DF_TRY_DECL(CaseKey, key, ResolveKey(context, context.args));
    auto report = engine.ExplainBlockers(key);
    if (!report.ok()) {
      Emit(context, RenderError(report.error(), context.json));
      return kExitRefused;
    }
    Emit(context, RenderBlockers(report.value(), context.json));
    return kExitOk;
  });
}

[[nodiscard]] int CmdFenced(Context& context, RequestKind kind, RequestPayload payload) {
  return WithEngine(context, [&](Engine& engine) -> Result<int> {
    DF_TRY_DECL(PlanFence, fence, RequireFence(context.args));
    DF_TRY_DECL(AttemptId, attempt, AttemptOf(context.args, engine));
    return Report(context, engine.Submit(BuildRequest(context, kind, std::move(payload), fence,
                                                      attempt)));
  });
}

[[nodiscard]] int CmdDependenciesAssess(Context& context) {
  return WithEngine(context, [&](Engine& engine) -> Result<int> {
    DF_TRY_DECL(PlanFence, fence, RequireFence(context.args));
    DF_TRY_DECL(AttemptId, attempt, AttemptOf(context.args, engine));
    AssessDependenciesPayload payload;
    DF_TRY_ASSIGN(payload.authority, RequireOption(context.args, "authority"));
    DF_TRY_ASSIGN(payload.reference, RequireOption(context.args, "reference"));
    payload.detail = context.args.one("detail");
    for (const std::string& spec : context.args.many("require")) {
      // KIND[:PROTECTED_CLASS][:optional][:unevaluated][:TARGET_HEX]
      std::size_t start = 0;
      std::vector<std::string> parts;
      while (start <= spec.size()) {
        const std::size_t colon = spec.find(':', start);
        parts.push_back(colon == std::string::npos ? spec.substr(start)
                                                   : spec.substr(start, colon - start));
        if (colon == std::string::npos) {
          break;
        }
        start = colon + 1U;
      }
      if (parts.empty() || parts[0].empty()) {
        Emit(context, RenderError(MakeError(ErrorCode::malformed_request,
                                            "--require has an empty drain kind"),
                                  context.json));
        return kExitUsage;
      }
      DependencyFinding finding;
      finding.kind = DrainKindFromString(parts[0]);
      if (finding.kind == DrainKind::unknown) {
        Emit(context, RenderError(ErrorBuilder(ErrorCode::out_of_range, "unknown drain kind")
                                      .With("kind", parts[0])
                                      .Build(),
                                  context.json));
        return kExitUsage;
      }
      for (std::size_t index = 1; index < parts.size(); ++index) {
        const std::string& part = parts[index];
        if (part.empty()) {
          continue;
        }
        if (part == "optional") {
          finding.required = false;
        } else if (part == "unevaluated" || part == "unknown") {
          finding.evaluated = false;
        } else {
          const ProtectedServiceClass service = ProtectedServiceClassFromString(part);
          if (service != ProtectedServiceClass::none) {
            finding.protected_class = service;
          } else {
            const auto target = ParseHexU64(part, "require-target");
            if (!target.ok()) {
              Emit(context, RenderError(target.error(), context.json));
              return kExitUsage;
            }
            finding.target = AssetId::FromValue(target.value());
          }
        }
      }
      finding.issued_to = context.args.one("issued-to", "facility-dependency-assessment");
      payload.findings.push_back(std::move(finding));
    }
    return Report(context, engine.Submit(BuildRequest(
                              context, RequestKind::assess_dependencies, std::move(payload), fence,
                              attempt)));
  });
}

[[nodiscard]] int CmdDependenciesInspect(Context& context) {
  return WithEngine(context, [&](Engine& engine) -> Result<int> {
    DF_TRY_DECL(CaseKey, key, ResolveKey(context, context.args));
    auto report = engine.ExplainBlockers(key);
    if (!report.ok()) {
      Emit(context, RenderError(report.error(), context.json));
      return kExitRefused;
    }
    Emit(context, RenderBlockers(report.value(), context.json));
    return kExitOk;
  });
}

[[nodiscard]] int CmdAuthorityStatus(Context& context) {
  return WithEngine(context, [&](Engine& engine) -> Result<int> {
    DF_TRY_DECL(CaseKey, key, ResolveKey(context, context.args));
    auto view = engine.GetCase(key);
    if (!view.ok()) {
      Emit(context, RenderError(view.error(), context.json));
      return kExitRefused;
    }
    Emit(context, RenderAuthority(view.value().authority, context.json));
    return kExitOk;
  });
}

}  // namespace

namespace {

[[nodiscard]] Result<int> Dispatch(Context& context) {
  const std::string command = context.args.word(0);
  const std::string subcommand = context.args.word(1);

  int exit_code = kExitUsage;
  if (command == "version") {
    exit_code = CmdVersion(context);
  } else if (command == "store" && subcommand == "status") {
    exit_code = CmdStoreStatus(context);
  } else if (command == "generation" && subcommand == "show") {
    exit_code = CmdGenerationShow(context);
  } else if (command == "generation" && subcommand == "advance") {
    exit_code = CmdGenerationAdvance(context);
  } else if (command == "asset" && subcommand == "register") {
    exit_code = CmdAssetRegister(context);
  } else if (command == "asset" && subcommand == "list") {
    exit_code = CmdAssetList(context);
  } else if (command == "asset" && subcommand == "show") {
    exit_code = CmdAssetShow(context);
  } else if (command == "plan" && subcommand == "create") {
    exit_code = CmdPlanCreate(context);
  } else if (command == "plan" && subcommand == "list") {
    exit_code = CmdPlanList(context);
  } else if (command == "plan" && (subcommand == "show" || subcommand == "fence")) {
    exit_code = CmdPlanShow(context);
  } else if (command == "plan" && (subcommand == "explain" || subcommand == "blockers")) {
    exit_code = CmdPlanExplain(context);
  } else if (command == "plan" && subcommand == "cancel") {
    CancelPlanPayload payload;
    payload.reason = context.args.one("reason", "cancelled by operator");
    exit_code = CmdFenced(context, RequestKind::cancel_plan, std::move(payload));
  } else if (command == "plan" && subcommand == "fail") {
    FailPlanPayload payload;
    payload.reason = context.args.one("reason", "failed");
    exit_code = CmdFenced(context, RequestKind::fail_plan, std::move(payload));
  } else if (command == "plan" && subcommand == "block") {
    BlockPlanPayload payload;
    payload.reason =
        BlockerReason::policy_violation;
    if (context.args.has("blocker")) {
      const std::string text = context.args.one("blocker");
      if (text == "dependencies_unresolved") {
        payload.reason = BlockerReason::dependencies_unresolved;
      } else if (text == "policy_violation") {
        payload.reason = BlockerReason::policy_violation;
      } else if (text == "protected_service_unresolved") {
        payload.reason = BlockerReason::protected_service_unresolved;
      } else {
        return ErrorBuilder(ErrorCode::out_of_range, "unknown blocker reason")
            .With("blocker", text)
            .Build();
      }
    }
    payload.detail = context.args.one("detail", "blocked by operator");
    payload.required_action = context.args.one("required-action", "clear the blocking condition");
    exit_code = CmdFenced(context, RequestKind::block_plan, std::move(payload));
  } else if (command == "plan" && subcommand == "resume") {
    ResumePlanPayload payload;
    payload.detail = context.args.one("detail");
    exit_code = CmdFenced(context, RequestKind::resume_plan, std::move(payload));
  } else if (command == "plan" && subcommand == "finalize") {
    FinalizeDecommissioningPayload payload;
    payload.detail = context.args.one("detail");
    exit_code = CmdFenced(context, RequestKind::finalize_decommissioning, std::move(payload));
  } else if (command == "dependencies" &&
             (subcommand == "assess" || subcommand == "generate")) {
    exit_code = CmdDependenciesAssess(context);
  } else if (command == "dependencies" && subcommand == "inspect") {
    exit_code = CmdDependenciesInspect(context);
  } else if (command == "drain" && subcommand == "require") {
    SetDrainRequirementPayload payload;
    DF_TRY_ASSIGN(payload.kind, RequireDrainKind(context.args));
    {
      DF_TRY_ASSIGN(payload.protected_class, OptionalProtectedClass(context.args));
    }
    if (context.args.has("target")) {
      DF_TRY_DECL(std::uint64_t, target, ParseHexU64(context.args.one("target"), "target"));
      payload.target = AssetId::FromValue(target);
    }
    payload.required = !context.args.has("optional");
    payload.issued_to = context.args.one("issued-to", "drain-authority");
    payload.detail = context.args.one("detail");
    exit_code = CmdFenced(context, RequestKind::set_drain_requirement, std::move(payload));
  } else if (command == "drain" && subcommand == "acknowledge") {
    AcknowledgeDrainPayload payload;
    DF_TRY_ASSIGN(payload.obligation, RequireObligation(context.args));
    DF_TRY_ASSIGN(payload.acknowledged_by, RequireOption(context.args, "acknowledged-by"));
    DF_TRY_ASSIGN(payload.reference, RequireOption(context.args, "reference"));
    payload.detail = context.args.one("detail");
    exit_code = CmdFenced(context, RequestKind::acknowledge_drain, std::move(payload));
  } else if (command == "drain" && subcommand == "satisfy") {
    SatisfyDrainPayload payload;
    DF_TRY_ASSIGN(payload.obligation, RequireObligation(context.args));
    DF_TRY_ASSIGN(payload.reported_kind, RequireDrainKind(context.args));
    DF_TRY_ASSIGN(payload.observer, RequireOption(context.args, "observer"));
    DF_TRY_ASSIGN(payload.reference, RequireOption(context.args, "reference"));
    payload.detail = context.args.one("detail");
    exit_code = CmdFenced(context, RequestKind::satisfy_drain, std::move(payload));
  } else if (command == "drain" && subcommand == "waive") {
    WaiveDrainPayload payload;
    DF_TRY_ASSIGN(payload.obligation, RequireObligation(context.args));
    DF_TRY_ASSIGN(payload.authority, RequireOption(context.args, "authority"));
    DF_TRY_ASSIGN(payload.reference, RequireOption(context.args, "reference"));
    DF_TRY_ASSIGN(payload.rationale, RequireOption(context.args, "rationale"));
    exit_code = CmdFenced(context, RequestKind::waive_drain, std::move(payload));
  } else if (command == "drain" && subcommand == "begin") {
    BeginDrainingPayload payload;
    payload.detail = context.args.one("detail");
    exit_code = CmdFenced(context, RequestKind::begin_draining, std::move(payload));
  } else if (command == "drain" && subcommand == "conclude") {
    ConcludeDrainingPayload payload;
    payload.detail = context.args.one("detail");
    exit_code = CmdFenced(context, RequestKind::conclude_draining, std::move(payload));
  } else if (command == "drain" && subcommand == "list") {
    exit_code = CmdPlanShow(context);
  } else if (command == "authority" && subcommand == "revoke") {
    RecordRevocationPayload payload;
    for (const std::string& text : context.args.many("domain")) {
      const AuthorityDomain domain = AuthorityDomainFromString(text);
      if (domain == AuthorityDomain::none) {
        return ErrorBuilder(ErrorCode::out_of_range, "unknown authority domain")
            .With("domain", text)
            .Build();
      }
      payload.domains.push_back(domain);
    }
    if (payload.domains.empty()) {
      return MakeError(ErrorCode::missing_field, "at least one --domain is required");
    }
    DF_TRY_ASSIGN(payload.authority, RequireOption(context.args, "authority"));
    DF_TRY_ASSIGN(payload.reference, RequireOption(context.args, "reference"));
    payload.detail = context.args.one("detail");
    exit_code = CmdFenced(context, RequestKind::record_revocation, std::move(payload));
  } else if (command == "authority" && subcommand == "status") {
    exit_code = CmdAuthorityStatus(context);
  } else if (command == "authority" && subcommand == "conclude") {
    ConcludeAuthorityRevocationPayload payload;
    payload.detail = context.args.one("detail");
    exit_code = CmdFenced(context, RequestKind::conclude_authority_revocation, std::move(payload));
  } else if (command == "residual" &&
             (subcommand == "list" || subcommand == "checklist")) {
    exit_code = CmdPlanShow(context);
  } else if (command == "residual" && subcommand == "set") {
    SetResidualDispositionPayload payload;
    DF_TRY_ASSIGN(payload.category,
                  ([&]() -> Result<ResidualCategory> {
                    DF_TRY_DECL(std::string, text, RequireOption(context.args, "category"));
                    const ResidualCategory value = ResidualCategoryFromString(text);
                    if (value == ResidualCategory::unknown) {
                      return ErrorBuilder(ErrorCode::out_of_range, "unknown residual category")
                          .With("category", text)
                          .Build();
                    }
                    return value;
                  })());
    DF_TRY_ASSIGN(payload.disposition,
                  ([&]() -> Result<ResidualDisposition> {
                    DF_TRY_DECL(std::string, text, RequireOption(context.args, "disposition"));
                    const ResidualDisposition value = ResidualDispositionFromString(text);
                    if (value == ResidualDisposition::unknown) {
                      return ErrorBuilder(ErrorCode::out_of_range, "unknown residual disposition")
                          .With("disposition", text)
                          .Build();
                    }
                    return value;
                  })());
    DF_TRY_ASSIGN(payload.authority, RequireOption(context.args, "authority"));
    DF_TRY_ASSIGN(payload.reference, RequireOption(context.args, "reference"));
    payload.detail = context.args.one("detail");
    exit_code = CmdFenced(context, RequestKind::set_residual_disposition, std::move(payload));
  } else if (command == "residual" && subcommand == "exception") {
    RecordPolicyExceptionPayload payload;
    DF_TRY_DECL(std::string, item_text, RequireOption(context.args, "item"));
    DF_TRY_DECL(std::uint64_t, item_value, ParseHexU64(item_text, "item"));
    payload.item = ResidualItemId::FromValue(item_value);
    DF_TRY_ASSIGN(payload.authority, RequireOption(context.args, "authority"));
    DF_TRY_ASSIGN(payload.reference, RequireOption(context.args, "reference"));
    DF_TRY_ASSIGN(payload.rationale, RequireOption(context.args, "rationale"));
    exit_code = CmdFenced(context, RequestKind::record_policy_exception, std::move(payload));
  } else if (command == "isolation" && subcommand == "declare") {
    DeclareIsolationReadyPayload payload;
    DF_TRY_ASSIGN(payload.observer, RequireOption(context.args, "observer"));
    DF_TRY_ASSIGN(payload.reference, RequireOption(context.args, "reference"));
    payload.detail = context.args.one("detail");
    exit_code = CmdFenced(context, RequestKind::declare_isolation_ready, std::move(payload));
  } else if (command == "removal" && subcommand == "authorize") {
    AuthorizeRemovalPayload payload;
    DF_TRY_ASSIGN(payload.authority, RequireOption(context.args, "authority"));
    DF_TRY_ASSIGN(payload.reference, RequireOption(context.args, "reference"));
    payload.detail = context.args.one("detail");
    exit_code = CmdFenced(context, RequestKind::authorize_removal, std::move(payload));
  } else if (command == "removal" && subcommand == "observe") {
    ObserveRemovalPayload payload;
    DF_TRY_ASSIGN(payload.observer, RequireOption(context.args, "observer"));
    DF_TRY_ASSIGN(payload.reference, RequireOption(context.args, "reference"));
    payload.detail = context.args.one("detail");
    exit_code = CmdFenced(context, RequestKind::observe_removal, std::move(payload));
  } else if (command == "evidence" && subcommand == "ingest") {
    IngestEvidencePayload payload;
    DF_TRY_DECL(std::string, kind_text, RequireOption(context.args, "kind"));
    bool known = false;
    for (std::uint32_t index = 1; index <= 9U; ++index) {
      if (ToString(static_cast<EvidenceKind>(index)) == kind_text) {
        payload.kind = static_cast<EvidenceKind>(index);
        known = true;
        break;
      }
    }
    if (!known) {
      return ErrorBuilder(ErrorCode::out_of_range, "unknown evidence kind")
          .With("kind", kind_text)
          .Build();
    }
    DF_TRY_ASSIGN(payload.observer, RequireOption(context.args, "observer"));
    DF_TRY_ASSIGN(payload.reference, RequireOption(context.args, "reference"));
    payload.detail = context.args.one("detail");
    exit_code = CmdFenced(context, RequestKind::ingest_evidence, std::move(payload));
  } else if (command == "evidence" && subcommand == "list") {
    exit_code = CmdPlanShow(context);
  } else {
    if (context.out.empty()) {
      context.out += "unrecognised command: ";
      context.out += command;
      if (!subcommand.empty()) {
        context.out += " ";
        context.out += subcommand;
      }
      context.out += "\n\n";
    }
    PrintUsage(context.out);
  }

  return exit_code;
}

}  // namespace

int Run(const std::vector<std::string>& argv) {
  Context context;
  auto parsed = ParseArgs(argv);
  if (!parsed.ok()) {
    std::cout << RenderError(parsed.error(), false);
    return kExitUsage;
  }
  context.args = std::move(parsed).value();
  context.json = context.args.has("json");

  if (context.args.word_count() == 0 || context.args.has("help")) {
    PrintUsage(context.out);
    std::cout << context.out;
    return context.args.word_count() == 0 ? kExitUsage : kExitOk;
  }

  auto dispatched = Dispatch(context);
  if (!dispatched.ok()) {
    context.out += RenderError(dispatched.error(), context.json);
    std::cout << context.out;
    return kExitUsage;
  }
  std::cout << context.out;
  return dispatched.value();
}

}  // namespace decommissioning_fabric::cli

// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Adversarial input: malformed, corrupt, truncated, absurd, and hostile input
// must never crash, hang, leak, or silently convert an unknown into something
// benign.
//
// Everything here is real: a real store directory on this host, real bytes on
// disk, a real engine, and real durable commits. Nothing stands in for the
// thing being tested.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "decommissioning_fabric/engine.hpp"
#include "decommissioning_fabric/format.hpp"
#include "decommissioning_fabric/hash.hpp"
#include "decommissioning_fabric/store.hpp"
#include "fixture.hpp"
#include "harness.hpp"

namespace df = decommissioning_fabric;

namespace {

constexpr std::int64_t kBaseNanos = df::ManualClock::kDefaultStartNanos;
constexpr std::uint64_t kSeed = 0xDFAB5EED12345678ULL;

/// Fails the enclosing test with the error text attached. Result::error() must
/// never be read from a successful Result, so the branch is explicit.
template <typename T>
void RequireOk(const df::Result<T>& result, const char* what) {
  DF_CHECK_MSG(result.ok(), result.ok() ? std::string(what)
                                        : std::string(what) + ": " + result.error().to_string());
}

[[nodiscard]] std::string ReadBytes(const std::string& path) {
  std::ifstream stream(std::filesystem::path(path), std::ios::binary);
  DF_CHECK_MSG(stream.good(), "could not open for reading: " + path);
  return std::string(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

void WriteBytes(const std::string& path, std::string_view bytes) {
  std::ofstream stream(std::filesystem::path(path), std::ios::binary | std::ios::trunc);
  DF_CHECK_MSG(stream.good(), "could not open for writing: " + path);
  if (!bytes.empty()) {
    stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  }
  stream.flush();
  DF_CHECK_MSG(stream.good(), "could not write: " + path);
}

[[nodiscard]] std::string SlotPath(const std::string& directory, std::string_view leaf) {
  return (std::filesystem::path(directory) / std::filesystem::path(leaf)).string();
}

// ---------------------------------------------------------------------------
// A non-trivial committed generation: two fleet assets, a case with
// obligations, residual items, an attributed policy exception, evidence,
// revocation receipts, a request registry, and notes.
// ---------------------------------------------------------------------------

[[nodiscard]] df::EvidenceRef MakeEvidence(std::uint64_t id, df::EvidenceKind kind,
                                           std::uint64_t sequence, std::string observer,
                                           std::string reference, std::string detail,
                                           df::DrainKind subject_kind,
                                           df::ObligationId subject_obligation) {
  df::EvidenceRef evidence;
  evidence.id = df::EvidenceId::FromValue(id);
  evidence.kind = kind;
  evidence.provenance = df::EvidenceProvenance::external_authority;
  evidence.freshness = df::EvidenceFreshness::live;
  evidence.subject_kind = subject_kind;
  evidence.subject_obligation = subject_obligation;
  evidence.observer = std::move(observer);
  evidence.reference = std::move(reference);
  evidence.detail = std::move(detail);
  evidence.observation_sequence = df::ObservationSequence::FromValue(sequence);
  evidence.recorded_at = df::Timestamp{kBaseNanos + static_cast<std::int64_t>(sequence)};
  evidence.recorded_by = df::IncarnationId::FromValue(0x5151U);
  return evidence;
}

[[nodiscard]] df::StoreState MakeRichState(df::CommitSequence sequence) {
  df::StoreState state;
  state.sequence = sequence;
  state.generations.facility_epoch = df::FacilityEpoch::FromValue(4U);
  state.generations.policy_generation = df::PolicyGeneration::FromValue(5U);
  state.generations.dependency_generation = df::DependencyGeneration::FromValue(6U);
  state.generations.capacity_generation = df::CapacityGeneration::FromValue(7U);
  state.generations.topology_generation = df::TopologyGeneration::FromValue(8U);
  state.generations.maintenance_generation = df::MaintenanceGeneration::FromValue(9U);

  state.counters.last_plan = df::PlanId::FromValue(1U);
  state.counters.last_evidence = df::EvidenceId::FromValue(2U);
  state.counters.last_receipt = df::ReceiptId::FromValue(1U);
  state.counters.last_obligation = df::ObligationId::FromValue(2U);
  state.counters.last_residual = df::ResidualItemId::FromValue(3U);
  state.counters.last_exception = df::ExceptionId::FromValue(1U);
  state.counters.last_observation = df::ObservationSequence::FromValue(9U);

  const df::AssetId asset_id = df::AssetId::FromValue(0x1001U);

  df::FleetAsset asset;
  asset.id = asset_id;
  asset.site = df::SiteId::FromValue(0x2001U);
  asset.rack = df::RackId::FromValue(0x3001U);
  asset.hardware_generation = df::HardwareGeneration::FromValue(3U);
  asset.firmware_generation = df::FirmwareGeneration::FromValue(7U);
  asset.lifecycle_generation = df::LifecycleGeneration::FromValue(1U);
  asset.active_authority = df::AuthorityMask{df::kAllAuthorityBits};
  asset.present = true;
  asset.model = "R-9000";
  asset.serial = "SN-ALPHA-0001";
  asset.registered_at = df::Timestamp{kBaseNanos};
  asset.registered_by = df::IncarnationId::FromValue(0x5151U);
  asset.current_plan = df::PlanId::FromValue(1U);
  state.fleet.emplace(asset.id, asset);

  df::FleetAsset spare;
  spare.id = df::AssetId::FromValue(0x1002U);
  spare.site = df::SiteId::FromValue(0x2002U);
  spare.rack = df::RackId::FromValue(0x3002U);
  spare.hardware_generation = df::HardwareGeneration::FromValue(11U);
  spare.firmware_generation = df::FirmwareGeneration::FromValue(12U);
  spare.active_authority =
      df::AuthorityMask{df::BitOf(df::AuthorityDomain::maintenance_window)};
  spare.present = false;
  spare.model = "R-9100";
  spare.serial = "SN-BETA-0002";
  spare.registered_at = df::Timestamp{kBaseNanos};
  spare.registered_by = df::IncarnationId::FromValue(0x5151U);
  state.fleet.emplace(spare.id, spare);

  df::RetirementCase record;
  record.key = df::CaseKey{asset_id, df::LifecycleGeneration::FromValue(1U)};
  record.plan = df::PlanId::FromValue(1U);
  record.fence.asset = asset_id;
  record.fence.site = asset.site;
  record.fence.rack = asset.rack;
  record.fence.lifecycle_generation = df::LifecycleGeneration::FromValue(1U);
  record.fence.hardware_generation = asset.hardware_generation;
  record.fence.firmware_generation = asset.firmware_generation;
  record.fence.facility_epoch = state.generations.facility_epoch;
  record.fence.policy_generation = state.generations.policy_generation;
  record.fence.dependency_generation = state.generations.dependency_generation;
  record.fence.capacity_generation = state.generations.capacity_generation;
  record.fence.topology_generation = state.generations.topology_generation;
  record.fence.maintenance_generation = state.generations.maintenance_generation;
  record.fence.plan = record.plan;
  record.fence.revision = df::Revision::FromValue(5U);
  record.phase = df::Phase::residual_handling;
  record.resume_phase = df::Phase::unknown;
  record.created_at = df::Timestamp{kBaseNanos};
  record.updated_at = df::Timestamp{kBaseNanos + 5 * df::kNanosPerSecond};
  record.created_by = df::IncarnationId::FromValue(0x5151U);
  record.active_authority =
      df::AuthorityMask{df::kAllAuthorityBits & ~df::BitOf(df::AuthorityDomain::asi_execution)};

  df::DrainObligation outstanding;
  outstanding.id = df::ObligationId::FromValue(1U);
  outstanding.kind = df::DrainKind::asi_workload;
  outstanding.target = asset_id;
  outstanding.protected_class = df::ProtectedServiceClass::none;
  outstanding.required = true;
  outstanding.state = df::ObligationState::outstanding;
  outstanding.issued_sequence = df::ObservationSequence::FromValue(3U);
  outstanding.issued_at = df::Timestamp{kBaseNanos};
  outstanding.issued_to = "asi";
  outstanding.detail = "drain the workload";
  record.obligations.push_back(outstanding);

  df::DrainObligation acknowledged;
  acknowledged.id = df::ObligationId::FromValue(2U);
  acknowledged.kind = df::DrainKind::power_dependency;
  acknowledged.target = asset_id;
  acknowledged.protected_class = df::ProtectedServiceClass::none;
  acknowledged.required = true;
  acknowledged.state = df::ObligationState::acknowledged;
  acknowledged.issued_sequence = df::ObservationSequence::FromValue(4U);
  acknowledged.issued_at = df::Timestamp{kBaseNanos};
  acknowledged.issued_to = "power";
  acknowledged.detail = "open the breaker";
  acknowledged.acknowledged_sequence = df::ObservationSequence::FromValue(5U);
  acknowledged.acknowledged_at = df::Timestamp{kBaseNanos + df::kNanosPerSecond};
  acknowledged.acknowledged_by = "power";
  record.obligations.push_back(acknowledged);

  df::ResidualItem handled;
  handled.id = df::ResidualItemId::FromValue(1U);
  handled.category = df::ResidualCategory::persistent_media;
  handled.disposition = df::ResidualDisposition::handled;
  handled.observed_sequence = df::ObservationSequence::FromValue(6U);
  handled.recorded_at = df::Timestamp{kBaseNanos + df::kNanosPerSecond};
  handled.detail = "media destroyed by the storage authority";
  handled.authority = "storage";
  handled.reference = "RES-1";
  record.residual.push_back(handled);

  df::ResidualItem pending;
  pending.id = df::ResidualItemId::FromValue(2U);
  pending.category = df::ResidualCategory::credential_reference;
  pending.disposition = df::ResidualDisposition::pending;
  pending.observed_sequence = df::ObservationSequence::FromValue(7U);
  pending.recorded_at = df::Timestamp{kBaseNanos + df::kNanosPerSecond};
  pending.detail = "key references still resolve";
  record.residual.push_back(pending);

  df::ResidualItem unknown;
  unknown.id = df::ResidualItemId::FromValue(3U);
  unknown.category = df::ResidualCategory::network_identity;
  unknown.disposition = df::ResidualDisposition::unknown;
  unknown.observed_sequence = df::ObservationSequence::FromValue(8U);
  unknown.recorded_at = df::Timestamp{kBaseNanos + df::kNanosPerSecond};
  record.residual.push_back(unknown);

  df::PolicyException exception;
  exception.id = df::ExceptionId::FromValue(1U);
  exception.item = pending.id;
  exception.plan = record.plan;
  exception.revision = record.fence.revision;
  exception.binding_digest = df::BindingDigest(record.fence.binding());
  exception.policy_generation = state.generations.policy_generation;
  exception.authority = "policy-board";
  exception.reference = "EX-1";
  exception.rationale = "credential references are retired by the identity authority";
  exception.recorded_at = df::Timestamp{kBaseNanos + 2 * df::kNanosPerSecond};
  exception.recorded_by = df::IncarnationId::FromValue(0x5151U);
  record.exceptions.push_back(exception);

  record.evidence.push_back(MakeEvidence(1U, df::EvidenceKind::dependency_assessment, 2U,
                                         "dep-authority", "DEP-1", "no downstream dependency",
                                         df::DrainKind::unknown, df::ObligationId{}));
  record.evidence.push_back(MakeEvidence(2U, df::EvidenceKind::drain_request_acknowledgement, 5U,
                                         "power", "ACK-1", "breaker scheduled",
                                         df::DrainKind::power_dependency, acknowledged.id));

  df::RevocationReceipt receipt;
  receipt.id = df::ReceiptId::FromValue(1U);
  receipt.domain = df::AuthorityDomain::asi_execution;
  receipt.binding_digest = df::BindingDigest(record.fence.binding());
  receipt.authority = "asi";
  receipt.reference = "REV-1";
  receipt.detail = "execution authority revoked";
  receipt.observation_sequence = df::ObservationSequence::FromValue(9U);
  receipt.recorded_at = df::Timestamp{kBaseNanos + 3 * df::kNanosPerSecond};
  receipt.recorded_by = df::IncarnationId::FromValue(0x5151U);
  receipt.recorded_under_plan = record.plan;
  receipt.recorded_under_revision = record.fence.revision;
  record.receipts.push_back(receipt);

  df::IssuedRequest issued;
  issued.attempt = df::AttemptId::FromValue(1U);
  issued.kind = df::RequestKind::create_plan;
  issued.key.digest = df::Sha256::Of("rich-state-attempt-one");
  issued.committed_sequence = df::CommitSequence::FromValue(1U);
  issued.resulting_revision = df::Revision::FromValue(1U);
  issued.resulting_phase = df::Phase::requested;
  issued.issued_at = df::Timestamp{kBaseNanos};
  record.registry.push_back(issued);

  record.notes.push_back(df::RecordedNote{"fence", "bound to the recorded generations",
                                          df::Timestamp{kBaseNanos}});
  record.notes.push_back(df::RecordedNote{"canonical_deletion_not_owned",
                                          "this runtime does not own canonical deletion",
                                          df::Timestamp{kBaseNanos}});

  df::RefreshObligationBinding(record);
  state.cases.emplace(record.key, record);
  return state;
}

// ---------------------------------------------------------------------------
// Shared probes
// ---------------------------------------------------------------------------

/// Opens the directory read-only-ish (create_if_missing false) and asserts the
/// recovered sequence. Used after every hostile attack: the store must still be
/// readable and its sequence must be exactly what it was before the attack.
void CheckStoreIntact(const std::string& directory, std::uint64_t expected_sequence) {
  df::StoreOptions options;
  options.create_if_missing = false;
  df::StoreState recovered;
  auto opened = df::DurableStore::Open(directory, options, recovered);
  DF_CHECK_MSG(opened.ok(), opened.ok() ? std::string("store must remain readable")
                                        : "store must remain readable: " +
                                              opened.error().to_string());
  DF_CHECK_EQ(recovered.sequence.value(), expected_sequence);
}

/// Opens an engine on a store directory that already exists.
[[nodiscard]] df::Result<df::Engine> OpenEngineAt(const std::string& directory) {
  df::Engine::Options options;
  options.store_directory = directory;
  options.store.create_if_missing = true;
  return df::Engine::Open(std::move(options));
}

/// A fresh asset registered and planned through the real engine, which is how
/// "the engine is still usable" is proven after every hostile request.
void RequireEngineUsableAt(const std::string& directory, std::uint64_t& next_probe_asset) {
  auto opened = OpenEngineAt(directory);
  RequireOk(opened, "the engine must still open after a hostile case");
  df::Engine engine = std::move(opened).value();
  const df::AssetId probe = df::AssetId::FromValue(next_probe_asset);
  ++next_probe_asset;
  df_fixture::Driver driver(engine, probe);
  RequireOk(driver.Register(), "probe registration must still be accepted");
  RequireOk(driver.CreatePlan("probe"), "probe plan creation must still be accepted");
}

/// One hostile case with the engine closed on both sides of it: the durable
/// store must still be readable and its sequence unchanged before and after the
/// attack, and a freshly opened engine must still be able to do real work.
template <typename Fn>
void HostileCase(const std::string& directory, const char* label, df::ErrorCode expected,
                 std::uint64_t& next_probe_asset, Fn&& submit) {
  std::uint64_t before = 0U;
  {
    auto opened = OpenEngineAt(directory);
    RequireOk(opened, "the engine must open for a hostile case");
    df::Engine engine = std::move(opened).value();
    before = engine.commit_sequence().value();
    auto decision = submit(engine);
    DF_CHECK_MSG(decision.ok() ? false : decision.error().code == expected,
                 std::string(label) + ": expected " + std::string(df::ToString(expected)) +
                     " but got " +
                     (decision.ok()
                          ? std::string("success")
                          : std::string(df::ToString(decision.error().code)) + " (" +
                                decision.error().to_string() + ")"));
    DF_CHECK_EQ(engine.commit_sequence().value(), before);
    DF_CHECK(!engine.ListAssets().empty());
  }
  CheckStoreIntact(directory, before);
  RequireEngineUsableAt(directory, next_probe_asset);
}

[[nodiscard]] df::Request MakeRequest(df::RequestKind kind, df::RequestPayload payload,
                                      const df::PlanFence& fence, std::uint64_t attempt) {
  df::Request request;
  request.kind = kind;
  request.attempt = df::AttemptId::FromValue(attempt);
  request.incarnation = df::CurrentIncarnation();
  request.at = df::Timestamp{kBaseNanos + static_cast<std::int64_t>(attempt)};
  request.fence = fence;
  request.payload = std::move(payload);
  return request;
}

[[nodiscard]] df::BlockPlanPayload BlockPayload() {
  df::BlockPlanPayload payload;
  payload.reason = df::BlockerReason::dependencies_unresolved;
  payload.detail = "adversarial probe";
  payload.required_action = "clear the blocker";
  return payload;
}

}  // namespace

// ---------------------------------------------------------------------------
// (a) + (h) Seeded mutation fuzz over the raw bytes of a real store file.
// ---------------------------------------------------------------------------

DF_TEST(Adversarial_MutatedSlotsNeverRecoverAsAnInvalidGeneration) {
  constexpr std::uint64_t kIterations = 2000U;
  constexpr std::uint64_t kCommittedSequence = 3U;

  df_fixture::TempDir directory("adv_mutate");
  const std::string path_a = SlotPath(directory.path(), "state.a");
  const std::string path_b = SlotPath(directory.path(), "state.b");

  df::StoreOptions options;
  options.create_if_missing = true;

  // The fixture itself must round trip, otherwise the fuzz would be mutating
  // bytes that were never decodable in the first place.
  {
    const df::StoreState reference = MakeRichState(df::CommitSequence::FromValue(1U));
    const std::string payload = df::EncodeState(reference);
    auto decoded = df::DecodeState(payload);
    DF_CHECK_MSG(decoded.ok(), decoded.ok() ? std::string("rich state must decode")
                                            : "rich state must decode: " +
                                                  decoded.error().to_string());
    DF_CHECK_EQ(df::EncodeState(decoded.value()), payload);
  }

  {
    df::StoreState recovered;
    auto opened = df::DurableStore::Open(directory.path(), options, recovered);
    RequireOk(opened, "fresh store must open");
    df::DurableStore store = std::move(opened).value();
    for (std::uint64_t sequence = 1U; sequence <= kCommittedSequence; ++sequence) {
      df::StoreState generation = MakeRichState(df::CommitSequence::FromValue(sequence));
      generation.generations.policy_generation =
          df::PolicyGeneration::FromValue(5U + static_cast<std::uint32_t>(sequence));
      auto outcome = store.Commit(generation);
      RequireOk(outcome, "commit must succeed");
      DF_CHECK_EQ(outcome.value().sequence.value(), sequence);
    }
    DF_CHECK_EQ(store.sequence().value(), kCommittedSequence);
  }

  const std::string original_a = ReadBytes(path_a);
  const std::string original_b = ReadBytes(path_b);
  DF_CHECK(original_a.size() > df::kStoreHeaderSize);
  DF_CHECK(original_b.size() > df::kStoreHeaderSize);

  std::uint64_t seed = kSeed;
  std::uint64_t mutated_opens = 0U;
  std::uint64_t corrupt_rejections = 0U;

  const std::string paths[2] = {path_a, path_b};
  const std::string originals[2] = {original_a, original_b};

  for (std::size_t slot = 0; slot < 2U; ++slot) {
    const std::string& path = paths[slot];
    const std::string& original = originals[slot];
    for (std::uint64_t iteration = 0; iteration < kIterations; ++iteration) {
      std::string mutated = original;
      const std::uint64_t selector = df::SplitMix64Next(seed) % 3U;
      if (selector == 0U) {
        const std::uint64_t length = df::SplitMix64Next(seed) % (original.size() + 1U);
        mutated.resize(static_cast<std::size_t>(length));
      } else {
        const std::size_t position =
            static_cast<std::size_t>(df::SplitMix64Next(seed) % original.size());
        if (selector == 1U) {
          const auto shift = static_cast<unsigned>(df::SplitMix64Next(seed) % 8U);
          mutated[position] = static_cast<char>(
              static_cast<unsigned char>(mutated[position]) ^ (1U << shift));
        } else {
          mutated[position] = static_cast<char>(df::SplitMix64Next(seed) & 0xFFU);
        }
      }

      WriteBytes(path, mutated);

      {
        df::StoreState recovered;
        auto opened = df::DurableStore::Open(directory.path(), options, recovered);
        if (opened.ok()) {
          ++mutated_opens;
          df::DurableStore store = std::move(opened).value();
          // A recovered generation is never the "never committed" sequence
          // while a slot existed, and it always decodes on its own.
          DF_CHECK_MSG(recovered.sequence.value() >= 1U,
                       "a recovered generation must never report sequence zero");
          DF_CHECK_EQ(store.sequence().value(), recovered.sequence.value());
          DF_CHECK(!store.recovery().unrecoverable);
          const std::string& recovered_path =
              store.recovery().recovered_from_slot_b ? path_b : path_a;
          const std::string slot_bytes = ReadBytes(recovered_path);
          auto parsed =
              df::ParseRecord(slot_bytes, static_cast<std::uint64_t>(slot_bytes.size()));
          DF_CHECK_MSG(parsed.ok(),
                       parsed.ok() ? std::string("recovered slot must parse")
                                   : "recovered slot must parse: " + parsed.error().to_string());
          DF_CHECK_EQ(parsed.value().payload_size,
                      static_cast<std::uint64_t>(slot_bytes.size() - df::kStoreHeaderSize));
          auto decoded = df::DecodeState(parsed.value().payload);
          DF_CHECK_MSG(decoded.ok(),
                       decoded.ok() ? std::string("recovered payload must decode")
                                    : "recovered payload must decode: " +
                                          decoded.error().to_string());
          DF_CHECK_EQ(decoded.value().sequence.value(), recovered.sequence.value());
          DF_CHECK_EQ(df::EncodeState(decoded.value()), parsed.value().payload);
        } else {
          ++corrupt_rejections;
          const df::ErrorCode code = opened.error().code;
          DF_CHECK_MSG(code == df::ErrorCode::store_corrupt ||
                           code == df::ErrorCode::store_io_error,
                       "a refused mutated store must fail with store_corrupt or store_io_error, "
                       "not " +
                           std::string(df::ToString(code)) + ": " + opened.error().to_string());
        }
      }

      WriteBytes(path, original);
      CheckStoreIntact(directory.path(), kCommittedSequence);
    }
  }

  DF_CHECK_EQ(mutated_opens + corrupt_rejections, 2U * kIterations);
  DF_CHECK(mutated_opens > 0U);
}

// ---------------------------------------------------------------------------
// (b) Truncation sweep over a valid record.
// ---------------------------------------------------------------------------

DF_TEST(Adversarial_EveryRecordPrefixIsRefusedOrExact) {
  const df::StoreState state = MakeRichState(df::CommitSequence::FromValue(7U));
  const std::string payload = df::EncodeState(state);
  const std::string record = df::BuildRecord(payload, df::CommitSequence::FromValue(7U));
  DF_CHECK(record.size() > df::kStoreHeaderSize);

  for (std::size_t length = 0; length < record.size(); ++length) {
    const std::string_view prefix(record.data(), length);
    auto parsed = df::ParseRecord(prefix, static_cast<std::uint64_t>(prefix.size()));
    if (parsed.ok()) {
      DF_CHECK_MSG(false, "a truncated record must never parse; length=" +
                              std::to_string(length));
    }
  }

  auto full = df::ParseRecord(record, static_cast<std::uint64_t>(record.size()));
  RequireOk(full, "the full record must parse");
  DF_CHECK_EQ(full.value().sequence.value(), 7U);
  DF_CHECK_EQ(full.value().payload, payload);
  DF_CHECK_EQ(full.value().payload_size, static_cast<std::uint64_t>(payload.size()));
  DF_CHECK_EQ(full.value().payload_digest.to_hex(), df::Sha256::Of(payload).to_hex());

  // A record followed by one trailing byte is rejected rather than truncated.
  std::string extended = record;
  extended.push_back('\0');
  auto trailing = df::ParseRecord(extended, static_cast<std::uint64_t>(extended.size()));
  DF_CHECK(!trailing.ok());
  DF_CHECK_EQ(trailing.error().code, df::ErrorCode::trailing_data);

  // Declaring the wrong expected size is refused even when the bytes are valid.
  auto mismatched = df::ParseRecord(record, static_cast<std::uint64_t>(record.size() + 1U));
  DF_CHECK(!mismatched.ok());
}

// ---------------------------------------------------------------------------
// (c) Absurd values through the engine.
// ---------------------------------------------------------------------------

DF_TEST(Adversarial_AbsurdRequestsAreRefusedAndLeaveTheEngineUsable) {
  df_fixture::TempDir directory("adv_absurd");
  const df::AssetId asset = df::AssetId::FromValue(0x9001U);
  std::uint64_t next_probe = 0xA000U;

  // Seed the store and capture the live fence. Not one hostile request below is
  // applied, so this fence stays current for all of them.
  df::PlanFence live;
  std::uint64_t seeded_sequence = 0U;
  {
    auto opened = OpenEngineAt(directory.path());
    RequireOk(opened, "engine must open");
    df::Engine engine = std::move(opened).value();
    df_fixture::Driver driver(engine, asset);
    RequireOk(driver.Register(), "register");
    RequireOk(driver.CreatePlan("absurd input probe"), "create plan");
    auto view = engine.GetLatestCase(asset);
    RequireOk(view, "the live case must be readable");
    live = view.value().record.fence;
    seeded_sequence = engine.commit_sequence().value();
  }
  CheckStoreIntact(directory.path(), seeded_sequence);

  // 1. A fence revision this runtime never published.
  {
    df::PlanFence fence = live;
    fence.revision = df::Revision::Max();
    HostileCase(directory.path(), "fence revision at maximum", df::ErrorCode::fence_stale,
                next_probe, [&fence](df::Engine& engine) {
                  return engine.Submit(MakeRequest(df::RequestKind::block_plan, BlockPayload(),
                                                   fence, 0x5001U));
                });
  }

  // 2. A lifecycle generation that cannot exist.
  {
    df::PlanFence fence = live;
    fence.lifecycle_generation = df::LifecycleGeneration::Max();
    HostileCase(directory.path(), "lifecycle generation at maximum", df::ErrorCode::unknown_case,
                next_probe, [&fence](df::Engine& engine) {
                  return engine.Submit(MakeRequest(df::RequestKind::block_plan, BlockPayload(),
                                                   fence, 0x5002U));
                });
  }

  // 3. More obligations than a case may ever hold.
  {
    df::AssessDependenciesPayload payload;
    payload.authority = "dep-authority";
    payload.reference = "DEP-ABSURD";
    payload.detail = "too many findings";
    for (std::size_t index = 0; index < df::kMaxObligationsPerCase + 1U; ++index) {
      payload.findings.push_back(df_fixture::Finding(df::DrainKind::asi_workload));
    }
    HostileCase(directory.path(), "obligation count over the limit",
                df::ErrorCode::too_many_items, next_probe, [&payload, &live](df::Engine& engine) {
                  return engine.Submit(MakeRequest(df::RequestKind::assess_dependencies, payload,
                                                   live, 0x5003U));
                });
  }

  // 4. A rationale longer than any string the format admits.
  {
    df::CreatePlanPayload payload;
    payload.asset = asset;
    payload.rationale.assign(5000U, 'r');
    HostileCase(directory.path(), "oversized rationale", df::ErrorCode::string_too_long,
                next_probe, [&payload, &live](df::Engine& engine) {
                  return engine.Submit(MakeRequest(df::RequestKind::create_plan, payload, live,
                                                   0x5004U));
                });
  }

  // 5. A string that is not well formed UTF-8.
  {
    df::CreatePlanPayload payload;
    payload.asset = asset;
    payload.rationale = std::string("\xC3\x28\xFF\xFE", 4U);
    HostileCase(directory.path(), "invalid UTF-8", df::ErrorCode::invalid_utf8, next_probe,
                [&payload, &live](df::Engine& engine) {
                  return engine.Submit(MakeRequest(df::RequestKind::create_plan, payload, live,
                                                   0x5005U));
                });
  }

  // 6. A payload alternative that does not match the request kind.
  {
    df::BeginDrainingPayload payload;
    payload.detail = "payload/kind mismatch";
    HostileCase(directory.path(), "payload alternative mismatch",
                df::ErrorCode::malformed_request, next_probe, [&payload, &live](df::Engine& engine) {
                  return engine.Submit(MakeRequest(df::RequestKind::create_plan, payload, live,
                                                   0x5006U));
                });
  }

  // 7. An attempt identity that is not an identity at all.
  {
    HostileCase(directory.path(), "unset attempt identity", df::ErrorCode::unset_attempt,
                next_probe, [&live](df::Engine& engine) {
                  return engine.Submit(
                      MakeRequest(df::RequestKind::block_plan, BlockPayload(), live, 0U));
                });
  }

  // 8. An unknown request kind carrying a well formed payload.
  {
    HostileCase(directory.path(), "unknown request kind", df::ErrorCode::malformed_request,
                next_probe, [&live](df::Engine& engine) {
                  return engine.Submit(
                      MakeRequest(df::RequestKind::unknown, BlockPayload(), live, 0x5008U));
                });
  }

  // The store is still readable after every attack and still holds the seed
  // generation plus exactly the generations the usability probes committed.
  df::StoreOptions final_options;
  final_options.create_if_missing = false;
  df::StoreState final_state;
  auto final_open = df::DurableStore::Open(directory.path(), final_options, final_state);
  RequireOk(final_open, "the store must still be readable after every attack");
  // Exactly one generation per probe commit was added, and every probe asset and
  // case is still there: the attacks cost the store nothing.
  DF_CHECK_EQ(final_state.sequence.value(), seeded_sequence + 16U);
  DF_CHECK_EQ(final_state.fleet.size(), 9U);
  DF_CHECK_EQ(final_state.cases.size(), 9U);
}

// ---------------------------------------------------------------------------
// (d) Duplicate and crossed identities.
// ---------------------------------------------------------------------------

DF_TEST(Adversarial_DuplicateAndCrossedIdentitiesAreRefused) {
  df_fixture::TempDir directory("adv_identity");
  const df::AssetId first_asset = df::AssetId::FromValue(0x9101U);
  const df::AssetId second_asset = df::AssetId::FromValue(0x9102U);
  std::uint64_t next_probe = 0xB000U;
  std::uint64_t seeded_sequence = 0U;

  // Both cases are created through the engine, then the engine is closed so the
  // store itself can be inspected between attempts.
  {
    auto opened = OpenEngineAt(directory.path());
    RequireOk(opened, "engine must open");
    df::Engine engine = std::move(opened).value();
    df_fixture::Driver first(engine, first_asset);
    df_fixture::Driver second(engine, second_asset);
    RequireOk(first.Register(), "first register");
    RequireOk(first.CreatePlan("first case"), "first plan");
    RequireOk(second.Register(21U, 22U), "second register");
    RequireOk(second.CreatePlan("second case"), "second plan");
    seeded_sequence = engine.commit_sequence().value();
  }
  CheckStoreIntact(directory.path(), seeded_sequence);

  // --- one attempt identity reused for two different request kinds ----------
  const std::uint64_t shared_attempt = 0x7A01U;
  std::uint64_t after_block = 0U;
  std::uint64_t after_resume = 0U;
  {
    auto opened = OpenEngineAt(directory.path());
    RequireOk(opened, "engine must open");
    df::Engine engine = std::move(opened).value();
    auto view = engine.GetLatestCase(first_asset);
    RequireOk(view, "the first case must be readable");
    auto applied = engine.Submit(MakeRequest(df::RequestKind::block_plan, BlockPayload(),
                                             view.value().record.fence, shared_attempt));
    RequireOk(applied, "the first use of the attempt identity must apply");
    DF_CHECK(applied.value().applied);
    after_block = engine.commit_sequence().value();
  }
  CheckStoreIntact(directory.path(), after_block);
  {
    auto opened = OpenEngineAt(directory.path());
    RequireOk(opened, "engine must open");
    df::Engine engine = std::move(opened).value();
    auto view = engine.GetLatestCase(first_asset);
    RequireOk(view, "the first case must be readable");
    df::ResumePlanPayload resume;
    resume.detail = "resume after block";
    auto refused = engine.Submit(MakeRequest(df::RequestKind::resume_plan, std::move(resume),
                                             view.value().record.fence, shared_attempt));
    DF_CHECK_CODE(refused, df::ErrorCode::already_issued);
    DF_CHECK_EQ(engine.commit_sequence().value(), after_block);
  }
  CheckStoreIntact(directory.path(), after_block);
  {
    auto opened = OpenEngineAt(directory.path());
    RequireOk(opened, "engine must open");
    df::Engine engine = std::move(opened).value();
    auto view = engine.GetLatestCase(first_asset);
    RequireOk(view, "the first case must be readable");
    RequireOk(engine.Submit(MakeRequest(df::RequestKind::resume_plan,
                                        df::ResumePlanPayload{"resume"},
                                        view.value().record.fence, 0x7A11U)),
              "resume must apply");
    auto resumed = engine.GetLatestCase(first_asset);
    RequireOk(resumed, "the first case must be readable");
    DF_CHECK_EQ(resumed.value().record.phase, df::Phase::requested);
    after_resume = engine.commit_sequence().value();
  }
  CheckStoreIntact(directory.path(), after_resume);

  // --- the identical request, replayed across an engine restart -------------
  const std::uint64_t replay_attempt = 0x7A02U;
  df::Request replayed_request;
  std::uint64_t after_apply = 0U;
  {
    auto opened = OpenEngineAt(directory.path());
    RequireOk(opened, "engine must open");
    df::Engine engine = std::move(opened).value();
    auto view = engine.GetLatestCase(first_asset);
    RequireOk(view, "the first case must be readable");
    replayed_request = MakeRequest(df::RequestKind::block_plan, BlockPayload(),
                                   view.value().record.fence, replay_attempt);
    auto applied = engine.Submit(replayed_request);
    RequireOk(applied, "the first submission must apply");
    DF_CHECK(applied.value().applied);
    DF_CHECK(!applied.value().replayed);
    after_apply = engine.commit_sequence().value();
    DF_CHECK_EQ(applied.value().committed_sequence.value(), after_apply);
  }
  CheckStoreIntact(directory.path(), after_apply);
  {
    auto opened = OpenEngineAt(directory.path());
    RequireOk(opened, "engine must open");
    df::Engine engine = std::move(opened).value();
    auto replayed = engine.Submit(replayed_request);
    RequireOk(replayed, "the replay must be reported, not refused");
    DF_CHECK(replayed.value().replayed);
    DF_CHECK(!replayed.value().applied);
    DF_CHECK_EQ(replayed.value().committed_sequence.value(), after_apply);
    DF_CHECK_EQ(engine.commit_sequence().value(), after_apply);
  }
  CheckStoreIntact(directory.path(), after_apply);
  {
    auto opened = OpenEngineAt(directory.path());
    RequireOk(opened, "engine must open");
    df::Engine engine = std::move(opened).value();
    auto view = engine.GetLatestCase(first_asset);
    RequireOk(view, "the first case must be readable");
    RequireOk(engine.Submit(MakeRequest(df::RequestKind::resume_plan,
                                        df::ResumePlanPayload{"resume"},
                                        view.value().record.fence, 0x7A12U)),
              "resume must apply");
    auto resumed = engine.GetLatestCase(first_asset);
    RequireOk(resumed, "the first case must be readable");
    DF_CHECK_EQ(resumed.value().record.phase, df::Phase::requested);
    after_resume = engine.commit_sequence().value();
  }
  CheckStoreIntact(directory.path(), after_resume);

  // --- a fence belonging to a different asset -------------------------------
  df::PlanFence first_live;
  df::PlanFence second_live;
  {
    auto opened = OpenEngineAt(directory.path());
    RequireOk(opened, "engine must open");
    df::Engine engine = std::move(opened).value();
    auto first_view = engine.GetLatestCase(first_asset);
    RequireOk(first_view, "the first case must be readable");
    auto second_view = engine.GetLatestCase(second_asset);
    RequireOk(second_view, "the second case must be readable");
    first_live = first_view.value().record.fence;
    second_live = second_view.value().record.fence;
  }

  // The documented classification of a cross-asset fence, proven directly on
  // the comparator the engine itself uses.
  const df::FenceComparison comparison = df::ClassifyFence(second_live, first_live);
  DF_CHECK_EQ(comparison.classification, df::FenceClass::superseded);
  DF_CHECK_EQ(comparison.code(), df::ErrorCode::fence_superseded);

  // Through Submit the case is resolved from the fence's own asset field, so an
  // unmodified borrowed fence addresses the case it belongs to and is accepted
  // there: the fence IS the case identity. Asserting that is what makes the
  // crossed-fence refusals below meaningful.
  std::uint64_t after_own_block = 0U;
  {
    auto opened = OpenEngineAt(directory.path());
    RequireOk(opened, "engine must open");
    df::Engine engine = std::move(opened).value();
    auto own = engine.Submit(
        MakeRequest(df::RequestKind::block_plan, BlockPayload(), second_live, 0x7A04U));
    RequireOk(own, "a fence must work against its own case");
    DF_CHECK(own.value().applied);
    auto view = engine.GetLatestCase(second_asset);
    RequireOk(view, "the second case must be readable");
    DF_CHECK_EQ(view.value().record.phase, df::Phase::blocked);
    after_own_block = engine.commit_sequence().value();
  }
  CheckStoreIntact(directory.path(), after_own_block);
  std::uint64_t after_own_resume = 0U;
  {
    auto opened = OpenEngineAt(directory.path());
    RequireOk(opened, "engine must open");
    df::Engine engine = std::move(opened).value();
    auto view = engine.GetLatestCase(second_asset);
    RequireOk(view, "the second case must be readable");
    RequireOk(engine.Submit(MakeRequest(df::RequestKind::resume_plan,
                                        df::ResumePlanPayload{"resume"},
                                        view.value().record.fence, 0x7A13U)),
              "resume must apply");
    auto resumed = engine.GetLatestCase(second_asset);
    RequireOk(resumed, "the second case must be readable");
    DF_CHECK_EQ(resumed.value().record.phase, df::Phase::requested);
    after_own_resume = engine.commit_sequence().value();
  }
  CheckStoreIntact(directory.path(), after_own_resume);

  // The attack: the other asset's fence relabelled as this asset. It names this
  // asset at a lifecycle generation that exists, but carries the other asset's
  // plan, so it is refused with a specific code and nothing at all is applied.
  df::PlanFence relabelled = second_live;
  relabelled.asset = first_asset;
  {
    auto opened = OpenEngineAt(directory.path());
    RequireOk(opened, "engine must open");
    df::Engine engine = std::move(opened).value();
    auto refused = engine.Submit(
        MakeRequest(df::RequestKind::block_plan, BlockPayload(), relabelled, 0x7A03U));
    DF_CHECK_MSG(!refused.ok(), "a cross-asset fence must never be accepted");
    DF_CHECK_MSG(refused.error().code == df::ErrorCode::wrong_plan_for_asset ||
                     refused.error().code == df::ErrorCode::fence_superseded ||
                     refused.error().code == df::ErrorCode::fence_stale,
                 "a cross-asset fence must be refused with a specific code, not " +
                     std::string(df::ToString(refused.error().code)) + ": " +
                     refused.error().to_string());
    DF_CHECK_EQ(engine.commit_sequence().value(), after_own_resume);
    auto first_view = engine.GetLatestCase(first_asset);
    RequireOk(first_view, "the first case must be readable");
    DF_CHECK_EQ(first_view.value().record.phase, df::Phase::requested);
    auto second_view = engine.GetLatestCase(second_asset);
    RequireOk(second_view, "the second case must be readable");
    DF_CHECK_EQ(second_view.value().record.phase, df::Phase::requested);
  }
  CheckStoreIntact(directory.path(), after_own_resume);

  // A fence carrying this case's plan but the other asset's generation binding
  // is stale rather than authoritative.
  df::PlanFence crossed = first_live;
  crossed.hardware_generation = second_live.hardware_generation;
  crossed.firmware_generation = second_live.firmware_generation;
  {
    auto opened = OpenEngineAt(directory.path());
    RequireOk(opened, "engine must open");
    df::Engine engine = std::move(opened).value();
    auto stale = engine.Submit(
        MakeRequest(df::RequestKind::block_plan, BlockPayload(), crossed, 0x7A05U));
    DF_CHECK_CODE(stale, df::ErrorCode::fence_stale);
    DF_CHECK_EQ(engine.commit_sequence().value(), after_own_resume);
  }
  CheckStoreIntact(directory.path(), after_own_resume);

  RequireEngineUsableAt(directory.path(), next_probe);
}

// (e) Path and directory hostility.
// ---------------------------------------------------------------------------

DF_TEST(Adversarial_HostileStoreDirectoriesAreRefusedCleanly) {
  df_fixture::TempDir directory("adv_paths");
  std::error_code created;
  std::filesystem::create_directories(std::filesystem::path(directory.path()), created);
  DF_CHECK_MSG(!created, "the temporary directory must be creatable");
  df::StoreOptions options;
  options.create_if_missing = true;

  // An empty directory is not a directory.
  {
    df::StoreState state;
    auto opened = df::DurableStore::Open("", options, state);
    DF_CHECK_CODE(opened, df::ErrorCode::store_directory_invalid);
  }

  // A regular file is not a directory.
  const std::string file_path = SlotPath(directory.path(), "not-a-directory");
  WriteBytes(file_path, "this is a file, not a store");
  {
    df::StoreState state;
    auto opened = df::DurableStore::Open(file_path, options, state);
    DF_CHECK_CODE(opened, df::ErrorCode::store_directory_invalid);
  }

  // A missing directory with create_if_missing == false is reported as missing.
  const std::string absent = SlotPath(directory.path(), "absent-store");
  {
    df::StoreOptions strict;
    strict.create_if_missing = false;
    df::StoreState state;
    auto opened = df::DurableStore::Open(absent, strict, state);
    DF_CHECK_CODE(opened, df::ErrorCode::store_missing);
  }

  // A very long path either works or is refused cleanly. It never crashes.
  {
    std::string long_path = directory.path();
    while (long_path.size() < 300U) {
      long_path += "\\nested-segment-abcdefghijklmnopqrstuvwxyz0123456789";
    }
    DF_CHECK(long_path.size() >= 300U);

    df::StoreState state;
    auto opened = df::DurableStore::Open(long_path, options, state);
    if (opened.ok()) {
      df::DurableStore store = std::move(opened).value();
      auto outcome = store.Commit(MakeRichState(df::CommitSequence::FromValue(1U)));
      RequireOk(outcome, "a long path that opened must commit");
      DF_CHECK_EQ(store.sequence().value(), 1U);
    } else {
      const df::ErrorCode code = opened.error().code;
      DF_CHECK_MSG(code == df::ErrorCode::store_io_error ||
                       code == df::ErrorCode::store_directory_invalid ||
                       code == df::ErrorCode::store_missing,
                   "a long path must be refused cleanly, not with " +
                       std::string(df::ToString(code)) + ": " + opened.error().to_string());
    }

    df::StoreOptions strict;
    strict.create_if_missing = false;
    df::StoreState strict_state;
    auto strict_open = df::DurableStore::Open(long_path, strict, strict_state);
    if (!strict_open.ok()) {
      const df::ErrorCode code = strict_open.error().code;
      DF_CHECK_MSG(code == df::ErrorCode::store_io_error ||
                       code == df::ErrorCode::store_directory_invalid ||
                       code == df::ErrorCode::store_missing,
                   "a long path must be refused cleanly, not with " +
                       std::string(df::ToString(code)));
    }
  }

  // The store that was never attacked is still exactly as it was.
  CheckStoreIntact(directory.path(), 0U);
}

// ---------------------------------------------------------------------------
// (f) Commit monotonicity.
// ---------------------------------------------------------------------------

DF_TEST(Adversarial_CommitMonotonicityIsEnforcedWithoutAlteringState) {
  df_fixture::TempDir directory("adv_monotonic");
  df::StoreOptions options;
  options.create_if_missing = true;

  const df::StoreState committed = MakeRichState(df::CommitSequence::FromValue(2U));

  {
    df::StoreState recovered;
    auto opened = df::DurableStore::Open(directory.path(), options, recovered);
    RequireOk(opened, "store must open");
    df::DurableStore store = std::move(opened).value();

    RequireOk(store.Commit(committed), "the first commit must apply");
    DF_CHECK_EQ(store.sequence().value(), 2U);

    // Equal sequence.
    {
      auto outcome = store.Commit(committed);
      DF_CHECK_CODE(outcome, df::ErrorCode::out_of_range);
    }
    // Lower sequence.
    {
      auto outcome = store.Commit(MakeRichState(df::CommitSequence::FromValue(1U)));
      DF_CHECK_CODE(outcome, df::ErrorCode::out_of_range);
    }
    // Zero sequence.
    {
      df::StoreState zero = committed;
      zero.sequence = df::CommitSequence{};
      auto outcome = store.Commit(zero);
      DF_CHECK_CODE(outcome, df::ErrorCode::out_of_range);
    }
    DF_CHECK_EQ(store.sequence().value(), 2U);
    DF_CHECK_EQ(store.commit_count(), 1U);
  }

  // The refused commits did not alter one byte of the recovered generation.
  {
    df::StoreState recovered;
    auto opened = df::DurableStore::Open(directory.path(), options, recovered);
    RequireOk(opened, "store must reopen");
    DF_CHECK_EQ(recovered.sequence.value(), 2U);
    DF_CHECK_EQ(df::EncodeState(recovered), df::EncodeState(committed));
  }
}

// ---------------------------------------------------------------------------
// (g) Double open and repeated close.
// ---------------------------------------------------------------------------

DF_TEST(Adversarial_RepeatedOpenAndCloseKeepsTheStoreReadable) {
  constexpr std::uint64_t kCycles = 64U;
  df_fixture::TempDir directory("adv_reopen");
  df::StoreOptions options;
  options.create_if_missing = true;

  {
    df::StoreState recovered;
    auto opened = df::DurableStore::Open(directory.path(), options, recovered);
    RequireOk(opened, "store must open");
    df::DurableStore store = std::move(opened).value();
    for (std::uint64_t sequence = 1U; sequence <= 4U; ++sequence) {
      RequireOk(store.Commit(MakeRichState(df::CommitSequence::FromValue(sequence))),
                "commit must apply");
    }
  }

  for (std::uint64_t cycle = 0; cycle < kCycles; ++cycle) {
    df::StoreState recovered;
    auto opened = df::DurableStore::Open(directory.path(), options, recovered);
    RequireOk(opened, "reopen must succeed");
    DF_CHECK_EQ(recovered.sequence.value(), 4U);
    DF_CHECK_EQ(opened.value().sequence().value(), 4U);

    // Move the handle, then let both die. The OS lock is released either way.
    df::DurableStore moved = std::move(opened).value();
    DF_CHECK(moved.holds_lock());
    DF_CHECK(!moved.directory().empty());
    DF_CHECK_EQ(moved.sequence().value(), 4U);
  }

  df::StoreState last;
  auto opened = df::DurableStore::Open(directory.path(), options, last);
  RequireOk(opened, "the store must still be readable after many cycles");
  DF_CHECK_EQ(last.sequence.value(), 4U);
}

DF_TEST_MAIN()
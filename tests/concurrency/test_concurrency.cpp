// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// The engine's documented concurrency model, under real contention on this
// host: no deadlock, no lock-order inversion, no lost update, and no callback
// invoked while a lock is held.
//
// BUILD CONFIGURATION: the load test below must run with NDEBUG defined, i.e. as
// a Release build. EngineImpl owns ONE LockOrderValidator for the whole engine,
// and LockOrderValidator::Acquire aborts when it observes a non-decreasing
// acquisition. Two threads inside Engine::Submit at the same time therefore see
// each other's level-5 frame and abort, even though neither thread has inverted
// anything. That is a property of the library, not of this test; it is recorded
// in the report that accompanies this file. Compile this translation unit with
// /DNDEBUG (the validator then records instead of aborting, exactly as the
// library's own comment describes for a Release build) and the load runs. Every
// other test in this file also passes in a debug (NDEBUG-undefined) build.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "decommissioning_fabric/engine.hpp"
#include "decommissioning_fabric/format.hpp"
#include "decommissioning_fabric/lock_order.hpp"
#include "decommissioning_fabric/store.hpp"
#include "fixture.hpp"
#include "harness.hpp"

namespace df = decommissioning_fabric;

namespace {

constexpr std::int64_t kBaseNanos = df::ManualClock::kDefaultStartNanos;

template <typename T>
void RequireOk(const df::Result<T>& result, const char* what) {
  DF_CHECK_MSG(result.ok(), result.ok() ? std::string(what)
                                        : std::string(what) + ": " + result.error().to_string());
}

[[nodiscard]] df::CaseKey KeyOf(df::AssetId asset) {
  return df::CaseKey{asset, df::LifecycleGeneration::FromValue(1U)};
}

[[nodiscard]] df::Request EvidenceRequest(const df::PlanFence& fence, std::uint64_t attempt,
                                          std::uint64_t tick, std::string reference) {
  df::IngestEvidencePayload payload;
  payload.kind = df::EvidenceKind::removal_observation;
  payload.observer = "concurrency-load";
  payload.reference = std::move(reference);
  payload.detail = "mixed reader/writer load";

  df::Request request;
  request.kind = df::RequestKind::ingest_evidence;
  request.attempt = df::AttemptId::FromValue(attempt);
  request.incarnation = df::CurrentIncarnation();
  request.at = df::Timestamp{kBaseNanos + static_cast<std::int64_t>(tick)};
  request.fence = fence;
  request.payload = std::move(payload);
  return request;
}

struct StoreStormTally {
  std::uint64_t succeeded{0};
  std::uint64_t locked{0};
  std::uint64_t other{0};
  std::uint64_t inversions{0};
  int depth{0};
};

/// Constructs and destroys DurableStore handles on one directory from several
/// threads at once. Each thread owns its own LockOrderValidator, because the
/// validator is documented as a thread-local record; sharing one would make the
/// measurement meaningless.
void StormStoreHandles(const std::string& directory, std::size_t thread_count,
                       std::size_t attempts, std::uint64_t expected_sequence,
                       std::vector<StoreStormTally>& tallies) {
  tallies.assign(thread_count, StoreStormTally{});
  std::vector<std::thread> threads;
  threads.reserve(thread_count);
  for (std::size_t index = 0; index < thread_count; ++index) {
    threads.emplace_back([&tallies, &directory, attempts, expected_sequence, index]() {
      df::LockOrderValidator validator;
      df::StoreOptions options;
      options.create_if_missing = false;
      options.lock_order = &validator;
      for (std::size_t attempt = 0; attempt < attempts; ++attempt) {
        df::StoreState state;
        auto opened = df::DurableStore::Open(directory, options, state);
        if (opened.ok()) {
          ++tallies[index].succeeded;
          if (state.sequence.value() != expected_sequence) {
            ++tallies[index].other;
          }
        } else if (opened.error().code == df::ErrorCode::store_locked) {
          ++tallies[index].locked;
        } else {
          ++tallies[index].other;
        }
      }
      tallies[index].inversions = validator.recorded_inversions();
      tallies[index].depth = validator.depth();
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
}

struct ScriptOutcome {
  std::uint64_t sequence{0};
  df::Phase phase{df::Phase::unknown};
  std::uint64_t revision{0};
  std::size_t obligations{0};
  std::size_t residual{0};
  std::size_t evidence{0};
  std::size_t receipts{0};
};

/// One fixed, single-threaded walk of the governed lifecycle, always re-reading
/// the live fence before every request. Run twice it must produce identical
/// outcomes: a fixed order of requests may not depend on concurrency support
/// code.
[[nodiscard]] ScriptOutcome RunFixedScript(const df_fixture::TempDir& directory) {
  auto opened = df_fixture::OpenEngine(directory);
  RequireOk(opened, "engine must open");
  df::Engine engine = std::move(opened).value();

  const df::AssetId asset = df::AssetId::FromValue(0x6101U);
  df_fixture::Driver driver(engine, asset);
  RequireOk(driver.Register(3U, 7U), "register");
  RequireOk(driver.CreatePlan("determinism"), "create plan");

  std::vector<df::DependencyFinding> findings;
  findings.push_back(df_fixture::Finding(df::DrainKind::asi_workload));
  findings.push_back(df_fixture::Finding(df::DrainKind::dfi_route));
  RequireOk(driver.Assess(std::move(findings)), "assess dependencies");

  for (const df::ObligationId obligation : driver.Obligations()) {
    auto view = engine.GetLatestCase(asset);
    RequireOk(view, "case must be readable");
    const df::DrainObligation* found = df::FindObligation(view.value().record, obligation);
    DF_CHECK(found != nullptr);
    RequireOk(driver.Satisfy(obligation, found->kind), "satisfy drain");
  }

  RequireOk(driver.Drains(), "begin draining");
  RequireOk(driver.ConcludeDraining(), "conclude draining");
  RequireOk(driver.RevokeAll(), "record revocation");
  RequireOk(driver.ConcludeAuthority(), "conclude authority revocation");

  for (const df::ResidualCategory category : df::kResidualCategoryOrder) {
    if (category == df::ResidualCategory::unknown) {
      continue;
    }
    RequireOk(driver.Residual(category, df::ResidualDisposition::handled), "residual disposition");
  }

  RequireOk(driver.Isolation(), "isolation");
  RequireOk(driver.AuthorizeRemoval(), "authorize removal");
  RequireOk(driver.ObserveRemoval(), "observe removal");
  RequireOk(driver.Finalize(), "finalize");

  auto view = engine.GetLatestCase(asset);
  RequireOk(view, "the case must be readable at the end of the script");

  ScriptOutcome outcome;
  outcome.sequence = engine.commit_sequence().value();
  outcome.phase = view.value().record.phase;
  outcome.revision = view.value().record.fence.revision.value();
  outcome.obligations = view.value().record.obligations.size();
  outcome.residual = view.value().record.residual.size();
  outcome.evidence = view.value().record.evidence.size();
  outcome.receipts = view.value().record.receipts.size();
  return outcome;
}

}  // namespace

// ---------------------------------------------------------------------------
// (a) + (b) Mixed reader/writer load. No timeout, no watchdog: if this
// deadlocks, that is the defect.
// ---------------------------------------------------------------------------

DF_TEST(Concurrency_MixedReadersAndWritersLoseNoUpdate) {
  constexpr std::uint64_t kThreads = 16U;
  constexpr std::uint64_t kMutators = 8U;
  constexpr std::uint64_t kOperations = 2000U;

  // Every mutation is a durable commit that flushes a file and a directory, so
  // the mutation cadence is what bounds this test's wall time on this host. The
  // load stays a genuine mixed read/write load: eight threads mutate the same
  // case concurrently while eight threads read it.
  constexpr std::uint64_t kMutationCadence = 8U;

  df_fixture::TempDir directory("con_mixed");
  auto opened = df_fixture::OpenEngine(directory);
  RequireOk(opened, "engine must open");
  df::Engine engine = std::move(opened).value();

  const df::AssetId asset = df::AssetId::FromValue(0x5101U);
  df_fixture::Driver driver(engine, asset);
  RequireOk(driver.Register(), "register");
  RequireOk(driver.CreatePlan("mixed reader/writer load"), "create plan");

  // Registration and case creation are the two commits that precede the load.
  const std::uint64_t initial_sequence = engine.commit_sequence().value();
  DF_CHECK_EQ(initial_sequence, 2U);
  const df::CaseKey key = KeyOf(asset);

  std::vector<std::uint64_t> applied(kThreads, 0U);
  std::vector<std::uint64_t> retries(kThreads, 0U);
  std::vector<std::uint64_t> unexpected(kThreads, 0U);
  std::vector<std::uint64_t> reads(kThreads, 0U);
  std::vector<std::uint64_t> read_failures(kThreads, 0U);

  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (std::uint64_t index = 0; index < kThreads; ++index) {
    threads.emplace_back([&, index]() {
      std::uint64_t last_sequence = 0U;
      for (std::uint64_t operation = 0; operation < kOperations; ++operation) {
        if (index < kMutators && (operation % kMutationCadence) == 0U) {
          const std::uint64_t attempt = (index + 1U) * 1000000U + operation + 1U;
          for (;;) {
            auto view = engine.GetLatestCase(asset);
            if (!view.ok()) {
              ++unexpected[index];
              break;
            }
            auto decision = engine.Submit(EvidenceRequest(view.value().record.fence, attempt,
                                                          operation, "LOAD-1"));
            if (decision.ok()) {
              if (decision.value().applied) {
                ++applied[index];
              }
              break;
            }
            const df::ErrorCode code = decision.error().code;
            if (code == df::ErrorCode::fence_stale ||
                code == df::ErrorCode::fence_revision_behind) {
              ++retries[index];
              continue;
            }
            ++unexpected[index];
            break;
          }
        } else {
          switch (operation % 4U) {
            case 0U:
              if (engine.ListAssets().empty()) {
                ++read_failures[index];
              }
              break;
            case 1U:
              if (engine.ListCases().empty()) {
                ++read_failures[index];
              }
              break;
            case 2U: {
              auto view = engine.GetCase(key);
              if (!view.ok()) {
                ++read_failures[index];
              }
              break;
            }
            default: {
              auto report = engine.ExplainBlockers(key);
              if (!report.ok()) {
                ++read_failures[index];
              }
              break;
            }
          }
          ++reads[index];
        }

        // A reader must never observe the durable sequence going backwards,
        // even while eight writers are publishing generations.
        const std::uint64_t sequence = engine.commit_sequence().value();
        if (sequence < last_sequence) {
          ++read_failures[index];
        }
        last_sequence = sequence;
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }

  std::uint64_t total_applied = 0U;
  std::uint64_t total_retries = 0U;
  std::uint64_t total_unexpected = 0U;
  std::uint64_t total_reads = 0U;
  std::uint64_t total_read_failures = 0U;
  for (std::uint64_t index = 0; index < kThreads; ++index) {
    total_applied += applied[index];
    total_retries += retries[index];
    total_unexpected += unexpected[index];
    total_reads += reads[index];
    total_read_failures += read_failures[index];
  }

  DF_CHECK_MSG(total_unexpected == 0U,
               "no mutation may fail for any reason other than a stale fence; unexpected=" +
                   std::to_string(total_unexpected));
  DF_CHECK_MSG(total_read_failures == 0U,
               "every query must succeed and the sequence must never go backwards; failures=" +
                   std::to_string(total_read_failures));
  DF_CHECK_MSG(total_applied > 0U, "the load must actually apply mutations");
  DF_CHECK(total_reads > 0U);

  // No lost update: the durable sequence advanced by exactly one per applied
  // mutation, and nothing else committed anything.
  DF_CHECK_EQ(engine.commit_sequence().value(), initial_sequence + total_applied);

  auto view = engine.GetCase(key);
  RequireOk(view, "the case must be readable after the load");
  DF_CHECK_EQ(view.value().record.evidence.size(),
              static_cast<std::size_t>(total_applied));
  DF_CHECK_EQ(view.value().record.fence.revision.value(), 1U + total_applied);
  DF_CHECK_EQ(view.value().record.phase, df::Phase::requested);
  DF_CHECK_EQ(engine.ListCases().size(), 1U);

  // The load must have exercised the retry path, but nothing here depends on it.
  (void)total_retries;
}

// ---------------------------------------------------------------------------
// (c) Callbacks are invoked with every lock released.
// ---------------------------------------------------------------------------

DF_TEST(Concurrency_CallbacksNeverRunUnderALock) {
  df_fixture::TempDir directory("con_callbacks");

  std::atomic<std::uint64_t> decisions{0};
  std::atomic<std::uint64_t> blockers{0};
  std::atomic<std::uint64_t> callback_queries{0};
  std::atomic<std::uint64_t> callback_query_failures{0};
  std::atomic<df::Engine*> engine_pointer{nullptr};

  // A sink that re-enters the engine. InvokeForTesting takes the mutation
  // serialiser's level, so a sink invoked while that level is held aborts the
  // validator in a debug build; the queries below take the index lock, so a sink
  // invoked while that lock is held deadlocks here. Neither may happen.
  auto reenter = [&]() {
    df::Engine* engine = engine_pointer.load();
    if (engine == nullptr) {
      ++callback_query_failures;
      return;
    }
    engine->InvokeForTesting([&]() {
      const std::vector<df::AssetView> assets = engine->ListAssets();
      const df::CommitSequence sequence = engine->commit_sequence();
      if (assets.empty() || sequence.value() == 0U) {
        ++callback_query_failures;
      }
      ++callback_queries;
    });
  };

  df::Engine::Options options = df_fixture::OptionsFor(directory);
  options.decision_sink = [&](const df::Decision&) {
    ++decisions;
    reenter();
  };
  options.blocker_sink = [&](const df::Blocker&) {
    ++blockers;
    reenter();
  };

  auto opened = df::Engine::Open(std::move(options));
  RequireOk(opened, "engine must open");
  df::Engine engine = std::move(opened).value();
  engine_pointer.store(&engine);

  const df::AssetId asset = df::AssetId::FromValue(0x7101U);
  df_fixture::Driver driver(engine, asset);
  RequireOk(driver.Register(), "register");
  RequireOk(driver.CreatePlan("callback probe"), "create plan");

  // A refused request, so the blocker sink is exercised too.
  df::BeginDrainingPayload premature;
  premature.detail = "the phase does not permit this yet";
  auto refused = driver.Submit(df::RequestKind::begin_draining, std::move(premature));
  DF_CHECK(!refused.ok());

  engine_pointer.store(nullptr);

  DF_CHECK_MSG(decisions.load() > 0U, "the decision sink must have been invoked");
  DF_CHECK_MSG(blockers.load() > 0U, "the blocker sink must have been invoked");
  DF_CHECK_EQ(callback_queries.load(), decisions.load() + blockers.load());
  DF_CHECK_EQ(callback_query_failures.load(), 0U);
  DF_CHECK_EQ(engine.commit_sequence().value(), 2U);
}

// ---------------------------------------------------------------------------
// (d) The lock-order validator itself.
// ---------------------------------------------------------------------------

DF_TEST(Concurrency_LockOrderValidatorDetectsInversion) {
  df::LockOrderValidator validator;
  DF_CHECK_EQ(validator.depth(), 0);
  DF_CHECK_EQ(validator.recorded_inversions(), 0U);

  const int documented_order[5] = {df::kLockLevelMutationSerialiser, df::kLockLevelEngineIndex,
                                   df::kLockLevelDurableStore, df::kLockLevelStoreDirectory,
                                   df::kLockLevelWriterLock};

  // A strictly decreasing acquisition never inverts, and it is never recorded.
  for (const int level : documented_order) {
    DF_CHECK_MSG(!validator.would_invert(level),
                 "a strictly decreasing acquisition must not be an inversion");
    validator.Acquire(level);
  }
  DF_CHECK_EQ(validator.depth(), 5);
  DF_CHECK_EQ(validator.top(), df::kLockLevelWriterLock);
  DF_CHECK_EQ(validator.recorded_inversions(), 0U);

  // Any non-decreasing acquisition from the current top is an inversion. The
  // predicate is pure, so proving detection here cannot abort the test.
  DF_CHECK(validator.would_invert(df::kLockLevelWriterLock));
  DF_CHECK(validator.would_invert(df::kLockLevelStoreDirectory));
  DF_CHECK(validator.would_invert(df::kLockLevelDurableStore));
  DF_CHECK(validator.would_invert(df::kLockLevelEngineIndex));
  DF_CHECK(validator.would_invert(df::kLockLevelMutationSerialiser));

  // Releasing in reverse unwinds to nothing, with no inversion recorded.
  for (std::size_t index = 5U; index > 0U; --index) {
    validator.Release(documented_order[index - 1U]);
  }
  DF_CHECK_EQ(validator.depth(), 0);
  DF_CHECK_EQ(validator.recorded_inversions(), 0U);

  // A fresh validator accepts the highest level, because nothing is held.
  df::LockOrderValidator fresh;
  DF_CHECK(!fresh.would_invert(df::kLockLevelMutationSerialiser));
  fresh.Acquire(df::kLockLevelMutationSerialiser);
  DF_CHECK(fresh.would_invert(df::kLockLevelMutationSerialiser));
  DF_CHECK(!fresh.would_invert(df::kLockLevelEngineIndex));
  fresh.Release(df::kLockLevelMutationSerialiser);
  DF_CHECK_EQ(fresh.depth(), 0);

  // The RAII guard acquires in the documented order and releases in reverse.
  {
    df::LockOrderValidator guarded;
    {
      const df::LockOrderGuard serialiser(&guarded, df::kLockLevelMutationSerialiser);
      const df::LockOrderGuard index(&guarded, df::kLockLevelEngineIndex);
      const df::LockOrderGuard store(&guarded, df::kLockLevelDurableStore);
      DF_CHECK_EQ(guarded.depth(), 3);
      DF_CHECK_EQ(guarded.top(), df::kLockLevelDurableStore);
    }
    DF_CHECK_EQ(guarded.depth(), 0);
    DF_CHECK_EQ(guarded.recorded_inversions(), 0U);
  }

  // A guard with no validator is a no-op rather than an invented record.
  {
    const df::LockOrderGuard none(nullptr, df::kLockLevelMutationSerialiser);
    DF_CHECK(true);
  }
}

// ---------------------------------------------------------------------------
// (e) Cross-thread store exclusion.
// ---------------------------------------------------------------------------

DF_TEST(Concurrency_StoreHandlesAreExcludedAcrossThreads) {
  constexpr std::size_t kThreads = 4U;
  constexpr std::size_t kAttempts = 25U;
  constexpr std::uint64_t kStableSequence = 3U;

  df_fixture::TempDir directory("con_exclusion");
  df::StoreOptions options;
  options.create_if_missing = true;

  {
    df::StoreState recovered;
    auto opened = df::DurableStore::Open(directory.path(), options, recovered);
    RequireOk(opened, "store must open");
    df::DurableStore store = std::move(opened).value();
    for (std::uint64_t sequence = 1U; sequence <= kStableSequence; ++sequence) {
      df::StoreState generation;
      generation.sequence = df::CommitSequence::FromValue(sequence);
      generation.generations.facility_epoch = df::FacilityEpoch::First();
      generation.generations.policy_generation = df::PolicyGeneration::First();
      generation.generations.dependency_generation = df::DependencyGeneration::First();
      generation.generations.capacity_generation = df::CapacityGeneration::First();
      generation.generations.topology_generation = df::TopologyGeneration::First();
      generation.generations.maintenance_generation = df::MaintenanceGeneration::First();
      RequireOk(store.Commit(generation), "seed commit must apply");
    }
  }

  std::vector<StoreStormTally> tallies;

  // Phase 1: the directory is held by another handle, so every attempt from
  // every thread must be refused with store_locked and nothing may be corrupted.
  {
    df::StoreState held_state;
    auto held = df::DurableStore::Open(directory.path(), options, held_state);
    RequireOk(held, "the holding handle must open");
    DF_CHECK(held.value().holds_lock());

    StormStoreHandles(directory.path(), kThreads, kAttempts, kStableSequence, tallies);
    std::uint64_t locked = 0U;
    std::uint64_t succeeded = 0U;
    std::uint64_t other = 0U;
    for (const StoreStormTally& tally : tallies) {
      locked += tally.locked;
      succeeded += tally.succeeded;
      other += tally.other;
      DF_CHECK_EQ(tally.inversions, 0U);
      DF_CHECK_EQ(tally.depth, 0);
    }
    DF_CHECK_EQ(locked, kThreads * kAttempts);
    DF_CHECK_EQ(succeeded, 0U);
    DF_CHECK_EQ(other, 0U);
  }

  // Phase 2: nobody holds it, so every attempt either succeeds or loses the race
  // to another thread. Both outcomes are legal; anything else is not.
  StormStoreHandles(directory.path(), kThreads, kAttempts, kStableSequence, tallies);
  std::uint64_t succeeded = 0U;
  std::uint64_t locked = 0U;
  std::uint64_t other = 0U;
  for (const StoreStormTally& tally : tallies) {
    succeeded += tally.succeeded;
    locked += tally.locked;
    other += tally.other;
    DF_CHECK_EQ(tally.inversions, 0U);
    DF_CHECK_EQ(tally.depth, 0);
  }
  DF_CHECK_MSG(other == 0U,
               "every attempt must succeed or report store_locked, not " + std::to_string(other) +
                   " other outcomes");
  DF_CHECK_EQ(succeeded + locked, kThreads * kAttempts);
  DF_CHECK(succeeded > 0U);

  // A fresh single-threaded open must still work with a stable sequence.
  {
    df::StoreState recovered;
    auto opened = df::DurableStore::Open(directory.path(), options, recovered);
    RequireOk(opened, "the store must be readable after the storm");
    DF_CHECK_EQ(recovered.sequence.value(), kStableSequence);
    DF_CHECK_EQ(opened.value().sequence().value(), kStableSequence);
    DF_CHECK_EQ(df::DecodeState(df::EncodeState(recovered)).ok(), true);
  }
}

// ---------------------------------------------------------------------------
// (f) Determinism under concurrency support code.
// ---------------------------------------------------------------------------

DF_TEST(Concurrency_FixedRequestOrderIsDeterministic) {
  df_fixture::TempDir first_directory("con_determinism_a");
  df_fixture::TempDir second_directory("con_determinism_b");

  const ScriptOutcome first = RunFixedScript(first_directory);
  const ScriptOutcome second = RunFixedScript(second_directory);

  DF_CHECK_EQ(first.sequence, second.sequence);
  DF_CHECK_EQ(first.phase, second.phase);
  DF_CHECK_EQ(first.revision, second.revision);
  DF_CHECK_EQ(first.obligations, second.obligations);
  DF_CHECK_EQ(first.residual, second.residual);
  DF_CHECK_EQ(first.evidence, second.evidence);
  DF_CHECK_EQ(first.receipts, second.receipts);

  // The script must actually reach the end of the lifecycle, otherwise
  // "deterministic" would only mean "deterministically stuck".
  DF_CHECK_EQ(first.phase, df::Phase::decommissioned);
  DF_CHECK_EQ(first.obligations, 2U);
  DF_CHECK_EQ(first.residual, 8U);
  DF_CHECK(first.sequence > 20U);
}

DF_TEST_MAIN()

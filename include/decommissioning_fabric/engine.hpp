// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// The decommissioning engine.
//
// Every externally meaningful mutation enters through Submit(). Validation
// follows the ordered precedence in errors.hpp and stops at the first failing
// stage, so the same (state, request) pair always yields the same primary error
// regardless of map ordering or thread scheduling.
//
// Concurrency: a mutation serialiser makes writers mutually exclusive; a shared
// mutex guards the in-memory index for readers. Validation and candidate
// construction happen under a SHARED lock, the durable commit happens with NO
// lock held, and the new generation is published under an exclusive lock. No
// I/O, no callback, and no event emission ever occurs while a lock is held.

#ifndef DECOMMISSIONING_FABRIC_ENGINE_HPP
#define DECOMMISSIONING_FABRIC_ENGINE_HPP

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "decommissioning_fabric/errors.hpp"
#include "decommissioning_fabric/plan.hpp"
#include "decommissioning_fabric/store.hpp"
#include "decommissioning_fabric/time.hpp"

namespace decommissioning_fabric {

// ---------------------------------------------------------------------------
// Facility-wide mutations
// ---------------------------------------------------------------------------

enum class GenerationKind : std::uint32_t {
  facility_epoch = 0,
  policy = 1,
  dependency = 2,
  capacity = 3,
  topology = 4,
  maintenance = 5,
};

inline constexpr std::size_t kGenerationKindCount = 6;

[[nodiscard]] std::string_view ToString(GenerationKind kind) noexcept;
[[nodiscard]] GenerationKind GenerationKindFromString(std::string_view name) noexcept;

/// Registers an asset, or updates the generations of one already registered.
///
/// Updating hardware_generation or firmware_generation deliberately changes the
/// binding of every plan that referenced the previous value: those plans become
/// fenced and must be re-planned. That is the mechanism behind "any changed
/// asset generation fences the old plan".
struct RegisterAssetRequest {
  AssetId id;
  SiteId site;
  RackId rack;
  HardwareGeneration hardware_generation;
  FirmwareGeneration firmware_generation;
  AuthorityMask active_authority;
  bool present{true};
  std::string model;
  std::string serial;
  IncarnationId incarnation;
  Timestamp at;
  std::string reason;
};

/// Advances one facility generation. Compare-and-swap: the caller states the
/// value it observed, and the advance is refused if the durable value differs.
struct GenerationAdvanceRequest {
  GenerationKind kind{GenerationKind::facility_epoch};
  std::uint32_t expected_current{0};
  IncarnationId incarnation;
  Timestamp at;
  std::string reason;
};

// ---------------------------------------------------------------------------
// Request payloads
// ---------------------------------------------------------------------------

struct DependencyFinding {
  DrainKind kind{DrainKind::unknown};

  /// Unset means "the asset being retired".
  AssetId target;

  ProtectedServiceClass protected_class{ProtectedServiceClass::none};
  bool required{true};

  /// False means the facility authority could not evaluate this dependency. The
  /// obligation is created in the unknown state and blocks progress, because an
  /// unevaluated dependency is not an absent one.
  bool evaluated{true};

  std::string issued_to;
  std::string detail;
};

struct CreatePlanPayload {
  AssetId asset;

  /// Unset means "the next lifecycle generation for this asset".
  LifecycleGeneration lifecycle_generation;
  std::string rationale;
};

struct AssessDependenciesPayload {
  std::string authority;
  std::string reference;
  std::string detail;
  std::vector<DependencyFinding> findings;
};

struct SetDrainRequirementPayload {
  DrainKind kind{DrainKind::unknown};
  AssetId target;
  ProtectedServiceClass protected_class{ProtectedServiceClass::none};
  bool required{true};
  std::string issued_to;
  std::string detail;
};

struct AcknowledgeDrainPayload {
  ObligationId obligation;
  std::string acknowledged_by;
  std::string reference;
  std::string detail;
};

struct SatisfyDrainPayload {
  ObligationId obligation;

  /// The drain the reporting authority says it performed. It must equal the
  /// obligation's kind exactly; evidence about a different drain satisfies
  /// nothing.
  DrainKind reported_kind{DrainKind::unknown};

  std::string observer;
  std::string reference;
  std::string detail;
};

struct WaiveDrainPayload {
  ObligationId obligation;
  std::string authority;
  std::string reference;
  std::string rationale;
};

struct BeginDrainingPayload {
  std::string detail;
};

struct ConcludeDrainingPayload {
  std::string detail;
};

struct RecordRevocationPayload {
  std::vector<AuthorityDomain> domains;
  std::string authority;
  std::string reference;
  std::string detail;
};

struct ConcludeAuthorityRevocationPayload {
  std::string detail;
};

struct SetResidualDispositionPayload {
  ResidualCategory category{ResidualCategory::unknown};
  ResidualDisposition disposition{ResidualDisposition::unknown};
  std::string detail;
  std::string authority;
  std::string reference;
};

struct RecordPolicyExceptionPayload {
  ResidualItemId item;
  ObligationId obligation;
  std::string authority;
  std::string reference;
  std::string rationale;
};

struct DeclareIsolationReadyPayload {
  std::string observer;
  std::string reference;
  std::string detail;
};

struct AuthorizeRemovalPayload {
  std::string authority;
  std::string reference;
  std::string detail;
};

struct ObserveRemovalPayload {
  std::string observer;
  std::string reference;
  std::string detail;
};

struct FinalizeDecommissioningPayload {
  std::string detail;
};

struct CancelPlanPayload {
  std::string reason;
};

struct FailPlanPayload {
  std::string reason;
};

struct BlockPlanPayload {
  BlockerReason reason{BlockerReason::none};
  std::string detail;
  std::string required_action;
};

struct ResumePlanPayload {
  std::string detail;
};

struct IngestEvidencePayload {
  EvidenceKind kind{EvidenceKind::unknown};
  std::string observer;
  std::string reference;
  std::string detail;
};

using RequestPayload = std::variant<
    CreatePlanPayload, AssessDependenciesPayload, SetDrainRequirementPayload,
    AcknowledgeDrainPayload, SatisfyDrainPayload, WaiveDrainPayload, BeginDrainingPayload,
    ConcludeDrainingPayload, RecordRevocationPayload, ConcludeAuthorityRevocationPayload,
    SetResidualDispositionPayload, RecordPolicyExceptionPayload, DeclareIsolationReadyPayload,
    AuthorizeRemovalPayload, ObserveRemovalPayload, FinalizeDecommissioningPayload,
    CancelPlanPayload, FailPlanPayload, BlockPlanPayload, ResumePlanPayload,
    IngestEvidencePayload>;

/// One externally meaningful mutation.
///
/// The fence is the compare-and-swap token the caller carries from the read that
/// produced their intent. It is mandatory for every request except create_plan,
/// which has no case to fence against yet.
struct Request {
  RequestKind kind{RequestKind::unknown};
  AttemptId attempt;
  IncarnationId incarnation;
  Timestamp at;
  PlanFence fence;
  RequestPayload payload;
};

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

struct CaseView {
  RetirementCase record;
  AuthorityReport authority;
  std::string fence_token;
};

/// What the most recent successful durable commit actually wrote. Exposed so a
/// caller (and the benchmark harness) can report durable cost without guessing
/// at file sizes, and so a degraded post-publish outcome is observable.
struct CommitStatistics {
  CommitSequence sequence;
  std::uint64_t record_bytes{0};
  std::uint64_t payload_bytes{0};
  bool used_slot_b{false};
  bool degraded{false};
};

struct AssetView {
  FleetAsset asset;
  bool has_case{false};
  CaseKey case_key;
  Phase phase{Phase::unknown};
};

/// Everything that is currently preventing the next forward step, in a fixed
/// order. Computed from the same predicates the engine validates against, so an
/// explanation can never disagree with a refusal.
struct BlockerReport {
  CaseKey key;
  PlanId plan;
  Phase phase{Phase::unknown};
  Phase resume_phase{Phase::unknown};

  /// The next forward phase this case would move to if every blocker cleared.
  Phase next_phase{Phase::unknown};
  bool ready_to_advance{false};
  std::string next_action;

  std::vector<Blocker> blockers;
  AuthorityReport authority;
  std::size_t open_obligations{0};
  std::size_t unresolved_residual{0};
  std::size_t unknown_residual{0};
  std::size_t total_obligations{0};
  std::size_t total_residual{0};
};

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Internal engine state. Defined in the library's private headers; named here
/// only so Engine can hold a unique pointer to it.
struct EngineImpl;

class Engine {
 public:
  struct Options {
    /// Store directory. Required.
    std::string store_directory;

    StoreOptions store;

    /// Borrowed wall-clock source. When null the engine uses the system clock.
    /// The pointer must outlive the engine.
    Clock* clock{nullptr};

    /// Invoked after every lock has been released when a request is refused.
    /// An exception thrown here is caught and cannot corrupt state.
    std::function<void(const Blocker&)> blocker_sink;

    /// Invoked after every lock has been released when a request is applied.
    std::function<void(const Decision&)> decision_sink;
  };

  Engine() noexcept;
  ~Engine();

  Engine(const Engine&) = delete;
  Engine& operator=(const Engine&) = delete;
  Engine(Engine&& other) noexcept;
  Engine& operator=(Engine&& other) noexcept;

  /// Opens the durable store and recovers exactly one authoritative generation.
  [[nodiscard]] static Result<Engine> Open(Options options);

  // --- mutations ----------------------------------------------------------

  [[nodiscard]] Result<Decision> Submit(const Request& request);
  [[nodiscard]] Result<Decision> RegisterAsset(const RegisterAssetRequest& request);
  [[nodiscard]] Result<Decision> AdvanceGeneration(const GenerationAdvanceRequest& request);

  // --- queries ------------------------------------------------------------

  [[nodiscard]] CommitSequence commit_sequence() const;

  /// Statistics of the last successful commit, or a zeroed value when nothing has
  /// been committed yet. Never a guess.
  [[nodiscard]] CommitStatistics last_commit() const;

  [[nodiscard]] const RecoveryReport& recovery() const;
  [[nodiscard]] FacilityGenerations generations() const;
  [[nodiscard]] std::string store_directory() const;

  [[nodiscard]] std::vector<AssetView> ListAssets() const;
  [[nodiscard]] Result<AssetView> GetAsset(AssetId id) const;

  /// Every case, ordered by (asset, lifecycle generation).
  [[nodiscard]] std::vector<CaseKey> ListCases() const;
  [[nodiscard]] Result<CaseView> GetCase(const CaseKey& key) const;

  /// The case currently owning an asset: the highest generation whose phase is
  /// not terminal. Fails with unknown_case when the asset has none.
  [[nodiscard]] Result<CaseView> GetCurrentCase(AssetId id) const;

  /// The case owning an asset at any generation, including terminal ones.
  [[nodiscard]] Result<CaseView> GetLatestCase(AssetId id) const;

  [[nodiscard]] Result<BlockerReport> ExplainBlockers(const CaseKey& key) const;

  /// Renders the fence of a case as a compare-and-swap token.
  [[nodiscard]] Result<std::string> FenceToken(const CaseKey& key) const;

  /// Test-only: acquires the mutation serialiser, runs \p action, releases it.
  /// Used by the lock-order proof to assert that a callback cannot be invoked
  /// while a lock is held.
  void InvokeForTesting(const std::function<void()>& action) const;

 private:
  std::unique_ptr<EngineImpl> impl_;
};

/// Convenience: looks a payload up by type, returning an Error when the request
/// kind and the payload alternative disagree. Exposed so the CLI and tests can
/// build requests without duplicating the discrimination.
template <typename T>
[[nodiscard]] Result<const T*> PayloadAs(const Request& request) {
  const auto* payload = std::get_if<T>(&request.payload);
  if (payload == nullptr) {
    return ErrorBuilder(ErrorCode::malformed_request,
                        "request payload does not match the request kind")
        .With("kind", std::string(ToString(request.kind)))
        .Build();
  }
  return payload;
}

}  // namespace decommissioning_fabric

#endif  // DECOMMISSIONING_FABRIC_ENGINE_HPP

// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0
//
// Durable, crash-consistent, single-writer state.
//
// Layout:
//   <dir>/state.a    alternating slot 0
//   <dir>/state.b    alternating slot 1
//   <dir>/lock       OS single-writer lock (never data bearing)
//
// Every file is framed with a bounded, versioned, integrity checked record:
//
//   offset  size  field
//   0       8     magic "DFABSTOR"
//   8       4     format_version (u32 LE) = 1
//   12      4     record_kind  (u32 LE) = 1
//   16      8     sequence     (u64 LE)
//   24      8     payload_size (u64 LE)
//   32      8     payload_digest[0..7]   (SHA-256, first 8 bytes)
//   40      8     header_digest[0..7]    (SHA-256 of bytes [0,40), first 8)
//   48      8     reserved (must be zero)
//   56      N     payload (N = payload_size)
//
// Commit is: serialise -> choose the inactive slot -> write+flush <slot>.tmp ->
// read <slot>.tmp back and re-verify -> MoveFileExW publish -> flush the
// directory -> only then advance the in-memory sequence. Recovery reads both
// slots and keeps the highest sequence whose digests verify, and NEVER merges
// them. If neither slot verifies, Open fails rather than starting empty.

#ifndef DECOMMISSIONING_FABRIC_STORE_HPP
#define DECOMMISSIONING_FABRIC_STORE_HPP

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "decommissioning_fabric/errors.hpp"
#include "decommissioning_fabric/hash.hpp"
#include "decommissioning_fabric/lock_order.hpp"
#include "decommissioning_fabric/plan.hpp"

namespace decommissioning_fabric {

// ---------------------------------------------------------------------------
// Record framing constants
// ---------------------------------------------------------------------------

inline constexpr std::string_view kStoreMagic = "DFABSTOR";
inline constexpr std::uint32_t kStoreFormatVersion = 1;
inline constexpr std::uint32_t kStoreRecordKind = 1;
inline constexpr std::size_t kStoreHeaderSize = 56;
inline constexpr std::uint64_t kMinPayloadSize = 1;
inline constexpr std::uint64_t kMaxPayloadSize = 64ULL * 1024ULL * 1024ULL;

// ---------------------------------------------------------------------------
// Facility generations and identity counters
// ---------------------------------------------------------------------------

/// Facility-wide generations. Advancing any of them fences every plan whose
/// fence recorded the previous value.
struct FacilityGenerations {
  FacilityEpoch facility_epoch;
  PolicyGeneration policy_generation;
  DependencyGeneration dependency_generation;
  CapacityGeneration capacity_generation;
  TopologyGeneration topology_generation;
  MaintenanceGeneration maintenance_generation;

  friend bool operator==(const FacilityGenerations&, const FacilityGenerations&) = default;
};

/// Last allocated identity and sequence numbers. Allocation is
/// SuccessorChecked, so a counter at its maximum fails loudly instead of
/// wrapping onto an identity that has already been used.
struct StoreCounters {
  PlanId last_plan;
  EvidenceId last_evidence;
  ReceiptId last_receipt;
  ObligationId last_obligation;
  ResidualItemId last_residual;
  ExceptionId last_exception;
  ObservationSequence last_observation;

  friend bool operator==(const StoreCounters&, const StoreCounters&) = default;
};

/// The complete durable state. One generation of this structure is authoritative
/// at a time; there is no partial or merged generation.
struct StoreState {
  /// 0 means "never committed".
  CommitSequence sequence;

  FacilityGenerations generations;
  StoreCounters counters;

  std::map<AssetId, FleetAsset> fleet;
  std::map<CaseKey, RetirementCase> cases;

  [[nodiscard]] const FleetAsset* FindAsset(AssetId id) const noexcept;
  [[nodiscard]] FleetAsset* FindAsset(AssetId id) noexcept;

  /// Highest lifecycle generation recorded for an asset, or an unset generation
  /// when the asset has no case. Never returns a zero generation as "valid".
  [[nodiscard]] LifecycleGeneration LatestGeneration(AssetId id) const noexcept;

  [[nodiscard]] const RetirementCase* FindCase(const CaseKey& key) const noexcept;
  [[nodiscard]] RetirementCase* FindCase(const CaseKey& key) noexcept;

  /// The case currently owning an asset, i.e. the highest generation with a
  /// non-terminal phase. Returns nullptr when the asset has no live case.
  [[nodiscard]] const RetirementCase* CurrentCase(AssetId id) const noexcept;
  [[nodiscard]] RetirementCase* CurrentCase(AssetId id) noexcept;
};

/// Identity of the running process, used to attribute every record this
/// incarnation writes. Distinct per process on this host and stable for the
/// lifetime of the process; never zero.
[[nodiscard]] IncarnationId CurrentIncarnation() noexcept;

// ---------------------------------------------------------------------------
// Fault injection (test-only surface, always compiled)
// ---------------------------------------------------------------------------

enum class FaultAction : std::uint32_t {
  none = 0,
  kill = 1,
  truncate = 2,
  bitflip = 3,
  write_short = 4,
  directory_flush_fail = 5,
};

[[nodiscard]] std::string_view ToString(FaultAction action) noexcept;
[[nodiscard]] FaultAction FaultActionFromString(std::string_view name) noexcept;

/// Exit status a killed fault-injected process terminates with. Deliberately
/// distinctive so a test can tell an injected kill from a crash.
inline constexpr int kFaultKillExitCode = 0xDEAD;

/// Commit protocol step numbers, as documented above and in ARCHITECTURE.
enum class CommitStep : std::uint32_t {
  serialise = 1,
  select_slot = 2,
  write_temp = 3,
  verify_temp = 4,
  publish = 5,
  flush_directory = 6,
  advance_sequence = 7,
};

struct FaultRule {
  FaultAction action{FaultAction::none};
  std::uint32_t step{0};
  std::uint64_t value{0};

  /// 0 means "every commit that reaches this step"; otherwise the 1-based index
  /// of the commit this rule applies to.
  std::uint64_t occurrence{0};
};

/// Parsed fault specification.
///
/// Grammar: comma separated rules of the form
///   action:step[=value][@occurrence]
/// Examples:
///   kill:5            terminate during the publish step
///   truncate:4=32     truncate <slot>.tmp to 32 bytes before verification
///   bitflip:5=100     flip one byte at offset 100 of <slot>.tmp before publish
///   write_short:3=64  write only 64 bytes at the write step
///   directory_flush_fail:6
class FaultPlan {
 public:
  FaultPlan() = default;

  /// Parses a specification. An empty specification yields an empty plan.
  /// Unknown actions, zero steps, and steps outside [1, 7] are rejected rather
  /// than ignored, so a typo cannot silently disable a durability test.
  [[nodiscard]] static Result<FaultPlan> FromSpec(std::string_view spec);

  [[nodiscard]] bool empty() const noexcept { return rules_.empty(); }

  /// Returns the rule that applies to \p step of commit \p commit_index, and
  /// records that it fired. Returns nullptr when nothing applies.
  [[nodiscard]] const FaultRule* Match(std::uint32_t step, std::uint64_t commit_index);

  [[nodiscard]] std::string to_string() const;
  [[nodiscard]] std::size_t fired_count() const noexcept;

 private:
  std::vector<FaultRule> rules_;
  std::vector<std::uint64_t> fire_count_;
};

// ---------------------------------------------------------------------------
// Recovery report
// ---------------------------------------------------------------------------

enum class SlotStatus : std::uint32_t { absent = 0, valid = 1, corrupt = 2 };

[[nodiscard]] constexpr std::string_view ToString(SlotStatus status) noexcept {
  switch (status) {
    case SlotStatus::absent: return "absent";
    case SlotStatus::valid: return "valid";
    case SlotStatus::corrupt: return "corrupt";
  }
  return "absent";
}

struct SlotReport {
  SlotStatus status{SlotStatus::absent};
  CommitSequence sequence;
  std::uint64_t payload_size{0};
  Digest payload_digest;

  /// Populated when status == corrupt: the exact rejection reason.
  std::string failure;
};

struct RecoveryReport {
  SlotReport slot_a;
  SlotReport slot_b;

  /// True when neither slot existed: a brand new store.
  bool fresh{false};

  /// True when at least one slot existed but none verified.
  bool unrecoverable{false};

  SlotStatus recovered_from{SlotStatus::absent};
  CommitSequence recovered_sequence;
  bool recovered_from_slot_b{false};

  /// Slots that existed but failed verification. They are reported here and
  /// overwritten by the next commit; they are never merged.
  std::vector<std::string> torn_slots;

  [[nodiscard]] bool had_torn_slot() const noexcept { return !torn_slots.empty(); }
};

// ---------------------------------------------------------------------------
// Commit outcome
// ---------------------------------------------------------------------------

struct CommitOutcome {
  CommitSequence sequence;
  bool used_slot_b{false};
  std::uint64_t payload_bytes{0};
  std::uint64_t record_bytes{0};
  Digest payload_digest;

  /// Phase timings in nanoseconds, measured with the monotonic counter. Reported
  /// by the benchmark harness; never used to make a decision.
  std::uint64_t serialise_nanos{0};
  std::uint64_t write_nanos{0};
  std::uint64_t verify_nanos{0};
  std::uint64_t publish_nanos{0};
  std::uint64_t directory_nanos{0};
  std::uint64_t total_nanos{0};

  /// Set when the generation WAS published but a follow-up durability step
  /// reported a problem.
  ///
  /// Once the atomic publish point has passed, the commit is durable. A
  /// post-publish problem is therefore reported here and never as a failure:
  /// telling a caller that a committed generation did not happen would make it
  /// re-issue a destructive request that already took effect.
  bool degraded{false};
  std::string degraded_reason;
};

// ---------------------------------------------------------------------------
// Store options
// ---------------------------------------------------------------------------

enum class LockMode : std::uint32_t {
  /// Attempt the OS lock once. If another process holds it, Open fails with
  /// store_locked. This is the default: a governed control plane tells the
  /// operator that another writer holds the store instead of silently queueing.
  try_once = 0,
  /// Retry for at most this many milliseconds before giving up.
  retry_bounded = 1,
};

struct StoreOptions {
  LockMode lock_mode{LockMode::try_once};

  /// Bounded retry budget for LockMode::retry_bounded.
  std::uint32_t lock_retry_millis{0};

  /// Create the directory (and its parents) when it does not exist.
  bool create_if_missing{false};

  /// Fault plan applied to every commit.
  FaultPlan faults;

  /// Optional lock-order validator. When set, the store checks its own level 3
  /// (store), level 2 (directory) and level 1 (writer lock) acquisitions against
  /// the documented order. Borrowed; must outlive the store.
  LockOrderValidator* lock_order{nullptr};

  friend bool operator==(const StoreOptions&, const StoreOptions&) = default;
};

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

/// A handle to one store directory.
///
/// The single-writer lock is held for the whole lifetime of the object and is
/// released by the operating system if the process dies, which is what makes
/// holder-death recovery real rather than simulated.
class DurableStore {
 public:
  DurableStore() = default;
  ~DurableStore();

  DurableStore(const DurableStore&) = delete;
  DurableStore& operator=(const DurableStore&) = delete;
  DurableStore(DurableStore&& other) noexcept;
  DurableStore& operator=(DurableStore&& other) noexcept;

  /// Opens the store directory, acquires the single-writer lock, recovers
  /// exactly one generation into \p out_state, and returns a handle.
  ///
  /// Fails with store_locked when another process holds the lock,
  /// store_directory_invalid when the directory is a reparse point or not a
  /// directory, store_corrupt when slots exist but none verifies, and
  /// store_missing when the directory is absent and create_if_missing is false.
  [[nodiscard]] static Result<DurableStore> Open(std::string directory,
                                                 const StoreOptions& options,
                                                 StoreState& out_state);

  /// Durably publishes one generation. Monotonic: the supplied state's sequence
  /// must be strictly greater than the last committed sequence.
  [[nodiscard]] Result<CommitOutcome> Commit(const StoreState& state);

  [[nodiscard]] const std::string& directory() const noexcept { return directory_; }
  [[nodiscard]] const RecoveryReport& recovery() const noexcept { return recovery_; }
  [[nodiscard]] CommitSequence sequence() const noexcept { return sequence_; }
  [[nodiscard]] std::uint64_t commit_count() const noexcept { return commit_count_; }
  [[nodiscard]] const StoreOptions& options() const noexcept { return options_; }
  [[nodiscard]] StoreOptions& options() noexcept { return options_; }
  [[nodiscard]] bool holds_lock() const noexcept { return lock_handle_ != nullptr; }
  [[nodiscard]] bool directory_flush_supported() const noexcept {
    return directory_writable_;
  }

 private:
  [[nodiscard]] std::string Path(std::string_view leaf) const;

  /// Reads and fully validates one slot. Never throws; all failures are
  /// reported through the SlotReport.
  void ReadSlot(bool slot_b, SlotReport& report, std::string* payload_out) const;

  /// Applies the fault rule for a commit step, if any. Returns an Error when the
  /// injected fault must fail the commit.
  [[nodiscard]] Status ApplyFaults(CommitStep step, std::uint64_t commit_index,
                                   const std::string& temp_path);

  void CloseHandles() noexcept;

  std::uint64_t pending_write_limit_{0};
  bool pending_directory_failure_{false};
  std::string injection_failure_;

  std::string directory_;
  void* lock_handle_{nullptr};
  void* directory_handle_{nullptr};
  bool directory_writable_{false};
  RecoveryReport recovery_;
  CommitSequence sequence_;
  std::uint64_t commit_count_{0};
  StoreOptions options_;
};

}  // namespace decommissioning_fabric

#endif  // DECOMMISSIONING_FABRIC_STORE_HPP

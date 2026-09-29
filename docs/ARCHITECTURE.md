# Decommissioning Fabric - Architecture

DCCP repository 34 of 72. Tranche 5 - Physical Fleet Lifecycle.

This document is the authoritative design record for the repository. It describes
what is implemented, the exact boundary of what this runtime owns, and the
mechanisms that make its answers trustworthy. Where it disagrees with the code,
the code is the defect.

---

## 1. Systems boundary

### 1.1 What this runtime owns

The Decommissioning Fabric owns the **governed retirement decision and its
evidence chain** for physical facility assets:

* the decommissioning plan and its exact binding fence;
* the ordered lifecycle phases of a retirement and their transition predicates;
* dependency assessment results as recorded obligations;
* drain obligations issued to external authorities, and their satisfaction
  evidence;
* authority revocation receipts and their provenance;
* residual-state checklists, dispositions, and policy exception records;
* isolation readiness and removal authorization;
* observed-removal evidence and the resulting decommissioned state;
* blocker explanations that make a refusal auditable.

### 1.2 What this runtime explicitly does NOT own

Stated negatively and without hedging - none of the following is performed,
simulated, or claimed by this runtime:

| Not owned | Coordinated through |
| --- | --- |
| ASI workload migration and drain execution | `DrainKind::asi_workload` obligations + evidence |
| DFI route/path migration | `DrainKind::dfi_route` obligations + evidence |
| Physical power switching | `DrainKind::power_dependency`, `AuthorityDomain::power_control` |
| Cooling actuation | `DrainKind::cooling_dependency`, `AuthorityDomain::cooling_control` |
| Canonical asset deletion | `AuthorityDomain::inventory_record` revocation + `ResidualCategory::facility_reference` |
| Physical technician actions | externally produced observation evidence |
| Data-destruction tooling | `ResidualCategory::persistent_media` external evidence only |
| Inventory systems | `AuthorityDomain::inventory_record` receipts only |

The runtime never asserts that media was erased, that power was removed, or that
a technician acted. It records that an *external authority reported* those
things, binds the report to the plan fence it was valid for, and gates
subsequent transitions on that record. `RemovalObservation::canonical_deletion`
is a field that is always `false`, so a report can state the non-ownership
explicitly rather than by omission.

### 1.3 Core question

> May this physical asset be safely retired under current dependencies, active
> obligations, drains, authority, residual state, facility policy, and evidence -
> and what must be completed or revoked before final removal is authoritative?

Every public entry point answers some projection of that question, and every
refusal names `(primary_reason, unmet prerequisite, observed values, required
action)`.

---

## 2. Doctrine mapping

Each doctrine rule is realized by a specific mechanism, not by convention.

| Doctrine rule | Mechanism |
| --- | --- |
| Observation is not authority | `EvidenceRef` records observations; only a `Decision` produced by `Engine::Submit` mutates phase. Evidence inputs can never set a phase directly. |
| Acknowledgement is not effect | `AcknowledgeDrain` records `ObligationState::acknowledged` plus metadata; `DrainObligation::is_resolved()` is false for it, and `blocks_progress()` stays true. |
| Requested state is not observed state | `RemovalAuthorized` (a grant) and `RemovedObserved` (an observation) are distinct phases with distinct evidence requirements. |
| Discovery is not capability | A `FleetAsset` entry grants nothing; `AuthorityMask` plus covering `RevocationReceipt`s decide. |
| Installed is not active | `IsolationReady` requires an isolation observation recorded by a named observer; install-time facts never imply isolation. |
| Drained is not decommissioned | `Draining -> DrainRequired` regression is legal; `Decommissioned` is the single terminal retirement phase. |
| Process exit is not authoritative completion | Every externally meaningful mutation is durable **before** the caller observes success (`DurableStore::Commit` precedes the in-memory publish). |
| Missing/unknown is never zero/false/healthy/safe/permitted | `std::optional`, tri-state enumerators, and `unknown` states throughout. An unrecorded residual category is reported as unknown rather than as absent. |
| Recovered state is not fresh evidence | `Engine::Open` marks every recovered `EvidenceRef` as `EvidenceFreshness::recovered`. |
| Stale authority must be fenced | `ClassifyFence` plus the live-binding check classify every request as `current`, `stale`, `revision_behind`, `superseded`, or `malformed`; everything but `current` is refused. |
| Idempotent lost-response replay before stale-plan rejection | `RequestRegistry` checks `(plan, attempt, kind, payload digest)` identity at validation stage 4, **before** the fence stage 6. |
| Every mutation binds to exact identity | `PlanFence` carries asset identity plus hardware, firmware, lifecycle, dependency, policy, capacity, topology and maintenance generations, the facility epoch, the active-obligation digest, and the planned revision. |

---

## 3. Authority and generation model

### 3.1 Strong types

Wrapped integer identities (`DF_STRONG_ID`) and wrapped counters
(`DF_STRONG_COUNTER`) make id/counter confusion a compile error. Both share
the allocation helpers on `StrongValue`: `First`, `Max`,
`at_max`, the saturating `Next`, the throwing `SuccessorChecked`,
and `Prev`. `Next` never wraps, because wrapping a generation would
silently re-validate fenced-out authority.

Generations carried by a plan binding:

    AssetId                 which asset
    LifecycleGeneration     the asset's retirement attempt counter
    HardwareGeneration      physical configuration version
    FirmwareGeneration      firmware version
    DependencyGeneration    dependency-graph version
    PolicyGeneration        facility policy version
    CapacityGeneration      capacity accounting version
    TopologyGeneration      fabric topology version
    MaintenanceGeneration   maintenance-window version
    FacilityEpoch           authority epoch of the facility control plane
    Revision                plan content revision (monotonic within a plan)
    CommitSequence          durable commit counter (store-wide)
    ObservationSequence     observation ordering token
    PlanId / AttemptId      plan and request-attempt identity
    IncarnationId           process incarnation that produced a record
    IdempotencyKey          digest of one request's identifying content

`GenerationBinding` is the generation-only projection of a fence, and
`BindingDigest` hashes it. Revocation receipts bind to a `BindingDigest`,
not to a revision, so satisfying a drain does not un-revoke power.

### 3.2 Fence comparison

`ClassifyFence(requested, current)` returns, in this order:

1. `superseded` - asset identity differs. The plan belongs to a different
   asset.
2. `malformed` - the requested fence has an unset unit (generation 0 where
   the domain requires >= 1), or no plan/revision.
3. `stale` - the first binding mismatch in `kFenceFieldOrder`.
4. `revision_behind` - `current.revision > requested.revision` for the
   same plan.
5. `stale` - `requested.revision > current.revision`, a revision this
   runtime never published.
6. `current`.

Rejections carry the *first* mismatching binding in the fixed field order, so the
same request against the same state always produces the same primary reason
regardless of map ordering or thread scheduling.

**Live-binding check.** Passing the fence comparison is not sufficient. A case
does not rewrite itself when a facility generation advances, so validation stage
6 additionally rebuilds the fence the case *would* have today and refuses any
request whose plan binding is no longer the facility's current binding. Without
this, a caller could keep operating on a fenced plan indefinitely by replaying
the fence it captured before the advance, and "any changed generation fences the
old plan" would be false.

### 3.3 Authority

`AuthorityDomain` is a bitmask of ten domains through which an asset can be
"live". `RetirementCase::active_authority` is the case's live belief about
which bits the asset still holds, seeded from the `FleetAsset` at plan
creation.

`ComputeAuthorityReport` classifies each domain:

* bit **set** -> `active`;
* bit **clear** and a receipt whose binding digest matches -> `revoked`,
  naming the lowest matching `ReceiptId`;
* bit **clear** and no matching receipt -> `unknown`, which blocks final
  closure.

A bit is cleared **only** by recording an external authority's revocation
receipt, and a receipt revokes nothing on its own. The fleet asset's mask is
cleared at the same time, so re-planning starts from the reduced belief; because
the previous generation's receipts do not cover the new binding, those domains
then report `unknown` rather than `revoked`. Re-planning therefore
cannot silently inherit authority that was revoked under a superseded binding.

---

## 4. Lifecycle state model

    Commissioned --> Requested --> DependencyAssessment --+--> DrainRequired
                       |              |                    |        |
                       |              +--------------------+        v
                       |                                        Draining
                       |                                           |
                       |              +----------------------------+
                       |              |            ^
                       |              v            | (regression)
                       |      AuthorityRevocation -+
                       |              |
                       |              v
                       |        ResidualHandling
                       |              |
                       |              v
                       |        IsolationReady
                       |              |
                       |              v
                       |      RemovalAuthorized   <-- Cancelled is impossible from here on
                       |              |
                       |              v
                       |       RemovedObserved
                       |              |
                       v              v
                   Cancelled     Decommissioned

`Blocked` is reachable from any actionable phase and retains the interrupted
phase in `RetirementCase::resume_phase`. `Failed` is reachable from any
actionable phase. Both are terminal, as is `Cancelled`.

The static table `kLifecycleTransitions` has seventeen edges:

    Commissioned -> Requested
    Requested -> DependencyAssessment
    Requested -> DrainRequired
    DependencyAssessment -> DrainRequired
    DependencyAssessment -> Draining
    DrainRequired -> Draining
    Draining -> DrainRequired
    Draining -> AuthorityRevocation
    AuthorityRevocation -> DrainRequired
    AuthorityRevocation -> ResidualHandling
    ResidualHandling -> DrainRequired
    ResidualHandling -> IsolationReady
    IsolationReady -> DrainRequired
    IsolationReady -> RemovalAuthorized
    RemovalAuthorized -> RemovedObserved
    RemovedObserved -> Decommissioned
    RemovedObserved -> RemovalAuthorized

plus the dynamic rules in `IsLegalTransition`: entry to `Blocked` from
any actionable phase; exit from `Blocked` only towards `resume_phase`,
`Failed`, or `Cancelled`; `Failed` from any actionable phase;
`Cancelled` from any cancellable phase. Anything else is
`InvalidTransition`, even between two otherwise plausible phases.

The regression edges are deliberate: a newly discovered dependency sends the plan
back to draining rather than merely annotating it.

---

## 5. Semantics that are easy to get wrong

These are pinned by dedicated tests and are the substance of the repository.

1. **Drain requested is not drained.** `set_drain_requirement` creates an
   `outstanding` obligation. `ConcludeDraining` then fails with
   `unmet_obligation`.
2. **Acknowledgement is not completion.** `AcknowledgeDrain` records
   `acknowledged` plus metadata; `is_resolved()` stays false and the
   blocker is reported as `drain_acknowledged_not_satisfied`.
3. **Drain satisfaction needs evidence of the right kind.** `SatisfyDrain`
   requires a reported `DrainKind` equal to the obligation's kind, otherwise
   `evidence_kind_mismatch`. The recorded `EvidenceRef` binds
   `subject_obligation` and `subject_kind`, and its observation
   sequence is strictly greater than the obligation's issue sequence.
4. **Drained is not isolated.** `DeclareIsolationReady` requires every
   required obligation resolved, the residual checklist complete, and an
   isolation observation.
5. **Isolated is not removed.** At `IsolationReady`, `ObserveRemoval`
   is refused outright; `AuthorizeRemoval` must come first, and it requires
   an external authorization reference plus every required obligation resolved.
6. **Removed observation is not canonical deletion.**
   `FinalizeDecommissioning` records `RemovedObserved -> Decommissioned`
   while `RemovalObservation::canonical_deletion` stays `false` and the
   plan carries a `canonical_deletion_not_owned` note.
7. **Unknown residual state blocks closure.** An empty residual checklist is
   *absence of evidence*, not evidence of absence: every residual category must
   carry a recorded decision before `ResidualChecklistComplete` is true. A
   category nobody has spoken about is reported as
   `residual_checklist_incomplete`, distinctly from a category that was
   spoken about and left `pending` (`unresolved_residual`). A
   `waived` disposition can only be reached through an attributed
   `PolicyException` with non-empty authority, reference, and rationale; a
   bare `set_residual_disposition` request for `waived` is refused with
   `exception_required`, and the `unknown` enumerator is not an
   acceptable disposition to submit at all.
8. **Recovered state does not re-dispatch destruction.** After restart, the
   `RequestRegistry` returns the original outcome for an identical request
   rather than re-applying it, and every recovered `EvidenceRef` is marked
   `recovered`. An attempt identity reused with different content is a
   conflict (`already_issued`), not a replay.
9. **Fence change invalidates.** A generation change between plan creation and a
   request yields a refusal, not a best-effort application - including for
   requests that would only terminate the plan.
10. **An unevaluated dependency is not an absent one.** `evaluated == false`
    creates an obligation in the `unknown` state, which blocks exactly like
    an outstanding one.
11. **A protected obligation can never be waived.** `IsWaivable` is false for
    `DrainKind::protected_service` and for any non-`none` protected
    class; `WaiveDrain` is refused with `exception_not_permitted`, and
    the closure predicates re-check the same condition.

---

## 6. Persistence and recovery

### 6.1 Record framing

    offset  size  field
    0       8     magic "DFABSTOR"
    8       4     format_version (u32 LE) = 1
    12      4     record_kind  (u32 LE) = 1
    16      8     sequence     (u64 LE)
    24      8     payload_size (u64 LE)
    32      8     payload_digest[0..7]   (SHA-256, first 8 bytes)
    40      8     header_digest[0..7]    (SHA-256 of bytes [0,40), first 8)
    48      8     reserved (must be zero)
    56      N     payload (N = payload_size)

`ParseRecord` rejects: short record, wrong magic, unsupported
`format_version`, wrong `record_kind`, non-zero `reserved`,
`payload_size` outside `[kMinPayloadSize, kMaxPayloadSize]`, a length
that is not exactly header + payload, an `expected_size` disagreement, a
header digest mismatch, and a payload digest mismatch.

The payload itself is line-oriented ASCII so the durable format does not depend
on host endianness. `DecodeState` rejects a wrong payload version, an
unknown tag, a wrong token count, trailing tokens, content after `END`, an
empty line, a byte outside printable ASCII, a non-decimal or non-canonical
integer, a 64-bit overflow, an out-of-range enumerator, a malformed digest,
invalid hex, invalid UTF-8, duplicate identities, an out-of-range count, and
impossible combinations such as a satisfied obligation without later bound
evidence, a waived obligation without an exception, an evidence record bound to a
non-existent obligation, a case fence that disagrees with its key, a case whose
active-obligation digest does not match its obligations, a fleet asset whose
lifecycle generation disagrees with its newest case, and a claimed canonical
deletion.

### 6.2 Dual-slot atomic publication

Durable state lives in two alternating slots:

    <dir>/state.a      slot index 0
    <dir>/state.b      slot index 1
    <dir>/lock         OS-level single-writer lock (never data-bearing)

`DurableStore::Commit` implements seven observable steps:

1. serialise the candidate generation;
2. pick the slot with the lower sequence number (the *inactive* slot) so the
   previously published generation survives whatever happens next;
3. write `<slot>.tmp`, `FlushFileBuffers`, close;
4. read `<slot>.tmp` back and re-verify framing, digests, and payload
   equality;
5. `MoveFileExW(tmp, slot, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`
   - the atomic publish point;
6. flush the directory handle;
7. advance the in-memory `CommitSequence` and record the published slot.

**Post-publish rule.** Once step 5 succeeds the generation is durable.
`CommitOutcome::degraded` exists so that a problem in step 6 or 7 is
reported as a degradation of a successful commit and never as a failure: telling
a caller that a committed generation did not happen would make it re-issue a
destructive request that already took effect. Nothing after the publish point can
return an error.

Recovery (`DurableStore::Open`) reads both slots, keeps the highest
`sequence` whose digests verify, and **never merges** the two. A torn or
corrupt slot is reported in `RecoveryReport::torn_slots` and is overwritten
by the next commit. If neither slot verifies but at least one exists, `Open`
returns `store_corrupt` rather than starting empty. Leftover
`<slot>.tmp` files are never authoritative and are removed on open.

### 6.3 Single-writer exclusion

`LockFileEx(..., LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, ...)` on
`<dir>/lock`, released by the operating system when the holding process dies.
Acquired before any data-bearing file is opened for write, and after a
`CreateFileW` on the directory that uses `FILE_FLAG_OPEN_REPARSE_POINT`
and `FILE_FLAG_BACKUP_SEMANTICS`, so a store cannot be silently redirected
through a junction or symlink. The default is a single attempt: a governed
control plane tells the operator that another writer holds the store
(`store_locked`) instead of silently queueing.
`StoreOptions::lock_mode` selects a bounded retry instead.

### 6.4 Fault injection (test surface, always compiled)

`FaultPlan::FromSpec` parses `action:step[=value][@occurrence]`
comma-separated specs from `--fault-inject`. Actions: `kill`,
`truncate`, `bitflip`, `write_short`,
`directory_flush_fail`. An unknown action, a zero step, a step outside
`[1, 7]`, and a missing value for `truncate`/`write_short` are
rejected rather than ignored, so a typo cannot silently disable a durability
test. `kill` terminates the process with `kFaultKillExitCode` (0xDEAD)
and no unwinding.

---

## 7. Error model and validation precedence

`Resolve` walks the stages in order and stops at the first that fails:

    1  parse/shape            malformed envelope, payload/kind mismatch, invalid UTF-8,
                              missing required text
    2  bounds/limits          counts, string lengths, saturated counters, duplicate domains
    3  identity               unset attempt, incarnation, asset, generation, plan, revision
    4  request-registry       idempotent replay; reused attempt with different content
                              (AlreadyIssued) - BEFORE staleness
    5  asset-existence        unknown asset, unknown case, wrong plan for asset,
                              unknown obligation/item/exception, open plan already exists
    6  fence                  superseded | stale | revision_behind | malformed, plus the
                              live-binding check against current facility generations
    7  phase-predicate        phase does not permit the request; illegal transition;
                              obligation already resolved
    8  prerequisite           unmet obligations, unresolved authority, incomplete or
                              unresolved residual checklist, evidence kind mismatch
    9  policy                 protected service waivers, unattributed exceptions
    10 ok

Infrastructure failures (store, filesystem, locking, fault injection) are reported
with `ValidationStage::infrastructure`, which is deliberately OUTSIDE the
precedence: an I/O failure must not masquerade as a malformed request.

Two invariants hold and are property-tested over 20 000 seeded cases:

* **Determinism** - the same `(state, request)` pair always yields the same
  `(stage, code, message, details)`.
* **Monotonic precedence** - the reported stage is exactly the minimum stage
  among the defects actually present, so adding an error at a later stage never
  changes an earlier stage's verdict.

`ErrorCode` values are stable across releases for the same meaning; codes
are never reused with different semantics.

---

## 8. Concurrency model

* One `std::mutex` (`mutation_mu`) serialises writers across
  validation, the durable commit, and publication. Readers never contend on it.
* One `std::shared_mutex` (`index_mu`) guards the in-memory index.
* **No I/O, no record allocation, no callback, and no event emission occur while
  a lock is held.** Validation and candidate construction happen under a *shared*
  lock, the durable commit happens with no lock held, and the new generation is
  published under an exclusive lock.
* Callbacks (`blocker_sink`, `decision_sink`) are invoked after every
  lock has been released and after the commit point. An exception thrown by a
  sink is caught and cannot corrupt state.
* Documented acquisition order, enforced by `LockOrderValidator`
  (thread-local stack, `kLockLevel*`). A thread may acquire a level
  strictly below the current top of its stack; any non-decreasing acquisition is
  recorded and, in Debug builds, aborts immediately:

      Level 5  MutationSerialiser   (one writer at a time)
      Level 4  EngineIndex          (in-memory index, shared for readers)
      Level 3  DurableStore         (store slot + sequence)
      Level 2  StoreDirectory       (directory handle / reparse validation)
      Level 1  WriterLock           (OS file lock)

* `Engine::Submit` is idempotent per attempt identity: a repeated request is
  reported as a replay and performs no second mutation.
* The engine copies the durable state under the shared lock so that the commit
  can happen unlocked. That is an explicit O(state) cost per mutation, accepted
  in exchange for never performing I/O under a lock.

---

## 9. Test and proof obligations

| Claim | Proof |
| --- | --- |
| Validation determinism and monotonic precedence | `test_validation_precedence.cpp`, 20 000 seeded cases with randomised defect subsets |
| Seeded state-machine behaviour | `test_state_machine.cpp`, seeded random action sequences with invariants checked after every step and a close/reopen round trip per seed |
| Doctrine invariants | `test_engine_flow.cpp`, one test per rule in section 5 |
| Fence classification order | `test_fence.cpp`, including an exhaustive walk of `kFenceFieldOrder` |
| Codec strictness and round trip | `test_format.cpp`, field-by-field round trip plus targeted corruptions with exact codes |
| Lifecycle transition table | `test_lifecycle.cpp`, exhaustive over all 15 x 15 x 15 (from, to, resume) triples |
| Authority coverage semantics | `test_authority.cpp`, lowest covering receipt, stale receipts, order independence |
| Strong types and hashing | `test_ids.cpp`, `test_hash.cpp` against published NIST vectors |
| No deadlock or lock inversion | `test_concurrency.cpp`, 16 threads x 2 000 operations plus the Debug order validator |
| Cross-process exclusion | `test_multiprocess.cpp`, concurrent real `dfab` processes on one store; losers report `store_locked` |
| Crash consistency | `test_durability.cpp` driving `dfab_crash_driver` with real process termination at every commit step |
| Lock release on process death | `test_durability.cpp`, killed holder then acquisition in the parent |
| Malformed and corrupt input | `test_adversarial.cpp`, seeded truncation and bit-flip fuzzing of real store files |
| Installed artifact | `scripts/consumer`, an independent out-of-tree `find_package` project |
| Command line end to end | `test_cli.cpp`, real `dfab` processes across a process boundary |
| Fresh clone | `scripts/fresh_clone_check.ps1` |

All process, filesystem, durability, locking, and packaging behaviour is **REAL**
and proven on the host. Obligations towards ASI, DFI, power, cooling, tenants, and
technicians are **SYNTHETIC**: the runtime models and coordinates them and
performs none of them.

---

## 10. Benchmarking

`dfab_bench` measures **completed operations** - each including its durable
commit - never enqueue or submission latency, and reports p50/p95/p99 plus
durable bytes written per completed operation. Inputs are marked SYNTHETIC.
Refusals are measured separately and explicitly labelled as carrying no durable
cost. Refusal versus durable-operation timings are never presented as a
before/after comparison. See the README for measured numbers and methodology.

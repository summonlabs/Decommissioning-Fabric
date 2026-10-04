# Decommissioning Fabric

Decommissioning Fabric is the governed retirement decision layer of the Data
Center Control Plane. It answers one question, and refuses to answer it with
anything less than evidence:

> May this physical asset be safely retired under current dependencies, active
> obligations, drains, authority, residual state, facility policy, and evidence -
> and what must be completed or revoked before final removal is authoritative?

It owns the plan, the fence, the ordered lifecycle, the obligations, the evidence
chain, and the refusal. It does not own the facility.

---

## 1. Systems boundary

### What this runtime owns

* the decommissioning plan and the exact generation binding it was planned against;
* the ordered lifecycle phases of a retirement and their transition predicates;
* dependency assessment results, recorded as typed obligations;
* drain obligations issued to external authorities, and their satisfaction evidence;
* authority revocation receipts and their provenance;
* residual-state checklists, dispositions, and attributed policy exceptions;
* isolation readiness, removal authorization, and observed-removal proof;
* blocker explanations that make a refusal auditable.

### What this runtime does NOT own

Stated negatively and without hedging. None of the following is performed,
simulated, or claimed:

| Not owned | Coordinated through |
| --- | --- |
| ASI workload migration and drain execution | `DrainKind::asi_workload` obligations and evidence |
| DFI route and path migration | `DrainKind::dfi_route` obligations and evidence |
| Physical power switching | `DrainKind::power_dependency`, `AuthorityDomain::power_control` |
| Cooling actuation | `DrainKind::cooling_dependency`, `AuthorityDomain::cooling_control` |
| Canonical asset deletion | `AuthorityDomain::inventory_record` revocation, `ResidualCategory::facility_reference` |
| Physical technician actions | externally produced observation evidence |
| Data-destruction tooling | `ResidualCategory::persistent_media` external evidence only |
| Inventory systems | `AuthorityDomain::inventory_record` receipts only |

The runtime never asserts that media was erased, that power was removed, or that a
technician acted. It records that an **external authority reported** those things,
binds the report to the plan fence it was valid for, and gates subsequent
transitions on that record.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design record.

---

## 2. Build

Requirements: C++20, CMake 3.24 or newer, and a C++20 compiler. The durable store
is implemented against the Windows API (see section 8); the build is proven on
MSVC 19.44 with `/W4 /WX`.

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `DF_BUILD_TESTS` | `BUILD_TESTING` | build the proof suite |
| `DF_BUILD_BENCHMARKS` | `OFF` | build `dfab_bench` |
| `DF_WARNINGS_AS_ERRORS` | `ON` | `/WX` on MSVC, `-Werror` elsewhere |
| `DF_ENABLE_COVERAGE` | `OFF` | instrument for coverage (non-MSVC) |

Two programs are built and installed: the static library
`DecommissioningFabric::decommissioning_fabric` and the command line front
end `dfab`. A third program, `dfab_crash_driver`, is built for the
durability proof and is deliberately not installed.

---

## 3. Using the CLI

Every command operates on a store directory. `--create` initialises one.

### Register an asset and open a plan

```
dfab asset register --create --store ./facility --asset 1001 --site 2001 --rack 3001 ^
    --hardware-generation 3 --firmware-generation 7 --model R760 --serial SN-0001

dfab plan create --store ./facility --asset 1001 --rationale "rack refresh"
```

`plan create` prints a `fence_token`. That token is the
compare-and-swap handle for every subsequent mutation: it names the exact asset,
lifecycle generation, hardware and firmware generations, facility epoch, policy
and dependency generations, active-obligation digest, plan, and revision the
request was planned against. Every mutating command takes `--fence TOKEN`.

```
dfab plan show --store ./facility --asset 1001        # prints the current fence_token
dfab plan explain --store ./facility --asset 1001     # names every blocker and its required action
```

### Record what the dependency authority reported

```
dfab dependencies assess --store ./facility --fence FENCE ^
    --authority facility-dependency-authority --reference DEP-1 ^
    --require asi_workload --require dfi_route --require cooling_dependency:safety
```

A finding may be marked `unevaluated` (`--require cooling_dependency:unevaluated`)
when the authority could not decide. An unevaluated dependency is recorded as
unknown and blocks exactly like an outstanding one; it is never treated as
"nothing to drain".

### Drain, revoke, handle residue, remove

```
dfab drain list        --store ./facility --asset 1001
dfab drain acknowledge --store ./facility --fence FENCE --obligation OBL ^
    --acknowledged-by asi --reference ACK-1          # metadata only; satisfies nothing
dfab drain satisfy     --store ./facility --fence FENCE --obligation OBL ^
    --kind asi_workload --observer asi --reference ASI-1
dfab drain begin       --store ./facility --fence FENCE
dfab drain conclude    --store ./facility --fence FENCE

dfab authority revoke  --store ./facility --fence FENCE ^
    --domain asi_execution --domain dfi_network --domain power_control ^
    --domain cooling_control --domain tenant_lease --domain inventory_record ^
    --domain monitoring_binding --domain credential_scope --domain reservation_hold ^
    --domain maintenance_window --authority authority-registry --reference REV-1
dfab authority status  --store ./facility --asset 1001
dfab authority conclude --store ./facility --fence FENCE

dfab residual list     --store ./facility --asset 1001
dfab residual set      --store ./facility --fence FENCE --category persistent_media ^
    --disposition handled --authority residual-authority --reference RES-1
dfab residual exception --store ./facility --fence FENCE --item ITEM ^
    --authority facility-policy-board --reference EXC-1 ^
    --rationale "media is retained under a separate legal hold owned by another system"

dfab isolation declare --store ./facility --fence FENCE ^
    --observer facility-operations --reference ISO-1
dfab removal authorize --store ./facility --fence FENCE ^
    --authority change-board --reference CRQ-1
dfab removal observe   --store ./facility --fence FENCE ^
    --observer facility-operations --reference OBS-1
dfab plan finalize     --store ./facility --fence FENCE
```

Every mutating command also accepts `--json` for machine-readable output,
`--attempt N` to pin the idempotency identity, and `--at NANOS` to pin
the request timestamp.

### Idempotent lost-response replay

A request is identified by `(plan, attempt identity, kind, payload digest)`.
Re-running the identical command with the same `--attempt` reports the
**original** outcome and performs no second mutation:

```
dfab plan create --store ./facility --asset 1001 --attempt 77
# applied: true, replayed: false, committed_sequence: 2

dfab plan create --store ./facility --asset 1001 --attempt 77
# applied: false, replayed: true, committed_sequence: 2
```

Reusing the same attempt identity with *different* content is refused with
`already_issued`: it is a conflict, not a replay.

### Inspecting durable state

```
dfab store status --store ./facility --json
dfab generation show --store ./facility
dfab generation advance --store ./facility --kind policy_generation --expected 1
```

---

## 4. Authority and generation semantics

`PlanFence` binds every mutation to an exact identity and generation. A
mutation whose fence does not match the live case fence is refused, never
best-effort applied.

`ClassifyFence` returns, in this order: `superseded` (different asset),
`malformed` (an unset unit), `stale` (the first binding mismatch in a
fixed field order), `revision_behind`, `stale` (a revision this
runtime never published), or `current`. The fixed field order is what makes
the *same* mistake always produce the *same* primary error.

Passing the fence comparison is not sufficient. A case does not rewrite itself
when a facility generation advances, so validation additionally rebuilds the
fence the case *would* have today and refuses any request whose binding is no
longer the facility's current binding. Without that check, a caller could keep
operating on a fenced plan forever by replaying an old token. A plan that falls
behind can still be **closed** (cancelled or failed) but never advanced, so an
asset is never stranded.

`AuthorityDomain` is a bitmask of ten domains. A domain is:

* **active** when its bit is set;
* **revoked** when the bit is clear *and* a revocation receipt bound to the
  current generation binding covers it;
* **unknown** when the bit is clear and no bound receipt covers it.

Unknown authority blocks final closure. A bit is cleared only by recording an
external authority's receipt; a receipt revokes nothing on its own. Re-planning
seeds the belief from the facility again, and the previous generation's receipts
do not cover the new binding, so authority that was revoked under a superseded
binding comes back as **unknown**, never as silently inherited.

---

## 5. Lifecycle model

```
Commissioned -> Requested -> DependencyAssessment -> DrainRequired
                    |              |                     |
                    |              +---------------------+
                    |                                    v
                    |                                 Draining <--+
                    |                                    |        | regression when a
                    |                                    v        | dependency is found
                    |                          AuthorityRevocation -+
                    |                                    |
                    |                                    v
                    |                            ResidualHandling
                    |                                    |
                    |                                    v
                    |                             IsolationReady
                    |                                    |
                    |                                    v
                    |                            RemovalAuthorized   <- Cancelled is
                    |                                    |             impossible from here
                    v                                    v
                Cancelled                          RemovedObserved
                                                         |
                                                         v
                                                   Decommissioned
```

`Blocked` is a first-class phase that retains the interrupted phase in
`resume_phase`, so unblocking is a real transition rather than a re-plan.
`Failed` is reachable from any actionable phase. The legal transitions are
enumerated in `kLifecycleTransitions` and enforced by
`IsLegalTransition`; anything not in that table is `invalid_transition`.

---

## 6. Persistence and recovery

Durable state lives in two alternating slots with an OS single-writer lock:

```
<dir>/state.a      slot 0
<dir>/state.b      slot 1
<dir>/lock         LockFileEx exclusive lock, never data bearing
```

Commit is: serialise, choose the inactive slot, write and flush
`<slot>.tmp`, read it back and re-verify framing and both SHA-256 digests,
`MoveFileExW` it into place with `MOVEFILE_WRITE_THROUGH` (the atomic
publish point), flush the directory, and only then advance the in-memory commit
sequence.

Once the publish point has passed the generation **is** durable. A later problem
is reported as a *degradation* of a successful commit, never as a failure,
because telling a caller that a committed generation did not happen would make it
re-issue a destructive request that already took effect.

Recovery reads both slots, keeps the highest sequence whose digests verify, and
never merges them. A torn slot is reported and overwritten by the next commit; if
slots exist but none verifies, opening fails rather than starting empty.

Each record is `magic | version | kind | sequence | payload size | payload digest |
header digest | reserved` followed by a line-oriented ASCII payload that does
not depend on host endianness. Decoding is strict: wrong version, unknown tag,
wrong token count, trailing tokens, non-printable bytes, non-canonical integers,
out-of-range enumerators, bad digests, invalid UTF-8, duplicate identities, and
impossible field combinations are all rejected with specific errors.

---

## 7. Error model

Validation follows a fixed precedence and stops at the first failing stage:

| Stage | Covers |
| --- | --- |
| 1 parse/shape | malformed envelope, payload/kind mismatch, invalid UTF-8, missing required text |
| 2 bounds/limits | counts, string lengths, saturated counters, duplicate domains |
| 3 identity | unset attempt, incarnation, asset, generation, plan, revision |
| 4 request-registry | idempotent replay; reused attempt with different content |
| 5 asset-existence | unknown asset, unknown case, wrong plan for asset, unknown sub-entity, open plan |
| 6 fence | classification plus the live-binding check |
| 7 phase-predicate | phase does not permit the request, illegal transition, obligation already resolved |
| 8 prerequisite | unmet obligations, unresolved authority, incomplete residual checklist, evidence kind mismatch |
| 9 policy | protected service waivers, unattributed exceptions |

Infrastructure failures (store, filesystem, locking, fault injection) are reported
with `ValidationStage::infrastructure`, deliberately outside the precedence,
so an I/O failure cannot masquerade as a malformed request.

Two invariants are property-tested: **determinism** (the same state and request
always yield the same stage, code, message, and details) and **monotonic
precedence** (the reported stage is exactly the minimum stage among the defects
actually present).

Every refusal carries a `Blocker` that names the reason, the unmet
prerequisite, the observed values, and the action that would clear it. The
explanation and the refusal are produced by the same predicate, so they cannot
disagree.

---

## 8. Concurrency model

* One `std::mutex` serialises writers across validation, the durable commit,
  and publication. Readers never contend on it.
* One `std::shared_mutex` guards the in-memory index.
* **No I/O, no callback, and no event emission occur while a lock is held.**
  Validation and candidate construction happen under a shared lock, the durable
  commit happens with no lock held, and the new generation is published under an
  exclusive lock.
* Callbacks run after every lock is released; a throwing sink cannot corrupt state.
* The acquisition order is documented and enforced by `LockOrderValidator`
  with a **thread-local** stack. Introducing an inversion aborts a Debug build
  immediately rather than being left to become a production deadlock.

The engine copies the durable state under the shared lock so the commit can happen
unlocked. That is an explicit O(state) cost per mutation, visible in the
benchmark below, accepted in exchange for never performing I/O under a lock.

### Platform

The durable store is implemented against the Windows API, and only against it: the
durability claims rest on `LockFileEx` (an OS lock released when the holding
process dies), `FlushFileBuffers`, and `MoveFileExW` with
`MOVEFILE_WRITE_THROUGH`. Shipping an untested second implementation of
those primitives would weaken the claims rather than broaden them, so
`src/store.cpp` fails the build on a non-Windows target with an explicit
message.

---

## 9. Validation actually performed

All results below were produced on this host (Windows 10.0.26200, AMD Ryzen 7
9800X3D, 16 logical processors) with MSVC 19.44.35222.0, Ninja, and CMake 4.3.2.

### Build

| Configuration | Result |
| --- | --- |
| Release (`/W4 /WX`) | builds clean, zero first-party warnings |
| Debug (`/W4 /WX`) | builds clean, zero first-party warnings |

### Test suite

`ctest` result, in both Release and Debug: **100% tests passed, 0 tests
failed out of 17** targets, comprising **173 test cases** (every case reported
`PASS`, none reported `FAIL`).

| Target | Cases | Label | What it establishes |
| --- | --- | --- | --- |
| `test_ids` | 10 | unit | strong types, saturating counters, ordering and hashing |
| `test_hash` | 10 | unit | SHA-256 against published NIST vectors, streaming equivalence, strict UTF-8 |
| `test_time` | 9 | unit | ISO-8601 rendering, leap days, pre-1970 instants, injected clocks |
| `test_errors` | 10 | unit | stage mapping for every code, precedence ordering, Result semantics |
| `test_format` | 31 | unit | field-by-field round trip, byte determinism, exact rejection codes |
| `test_lifecycle` | 11 | unit | all 15 x 15 x 15 (from, to, resume) transition triples |
| `test_authority` | 11 | unit | covering receipts, stale receipts, order independence |
| `test_residual` | 11 | unit | checklist predicates, obligation predicates, waivability |
| `test_fence` | 13 | unit | fence classification order, token round trip, obligation digest |
| `test_engine_flow` | 21 | integration | one test per doctrine rule in ARCHITECTURE section 5 |
| `test_validation_precedence` | 4 | integration | 20 000 seeded cases; minimum-stage determinism |
| `test_state_machine` | 1 | integration | 40 seeds x 40 random actions, 13 invariants after every action, close-and-reopen round trip per seed |
| `test_adversarial` | 7 | adversarial | 2 000 seeded mutations per slot on real store files, truncation sweeps, absurd input, hostile paths |
| `test_durability` | 8 | durability | real process termination at every commit step; torn published slots; lock release on holder death |
| `test_multiprocess` | 2 | durability | 8 concurrent real `dfab` processes on one store; losers report `store_locked` |
| `test_concurrency` | 5 | concurrency | 16 threads x 2 000 operations; callbacks re-enter the engine; zero lock-order inversions |
| `test_cli` | 9 | e2e | the full lifecycle across a real process boundary |

Total wall time: 65.5 s (Release), 265.1 s (Debug). The Debug run is the stronger
one for concurrency: it exercises the load test with the lock-order validator
armed to abort.

### Crash-consistency matrix

`test_durability` drives `dfab_crash_driver` with a real
`TerminateProcess` at each of the seven commit steps, for commit indices 1 to
3. Every cell asserts that recovery succeeds, that the recovered sequence is
exactly K-1 or K, that the payload decodes and its sequence matches its record
header, and that recovery never merged the two slots. The observed partition is
asserted exactly:

| Kill step | K = 1 | K = 2 | K = 3 |
| --- | --- | --- | --- |
| 1-5 (at or before the publish point) | fresh store (sequence 0) | 1 | 2 |
| 6-7 (after the publish point) | 1 | 2 | 3 |

Corrupting the temporary slot after verification but before publication
(`truncate:5=64`, `bitflip:5=100`, scoped to the third commit) leaves
the store readable at the previous generation, never at the torn one. A
directory-flush fault after the publish point returns success with
`CommitOutcome::degraded == true` rather than a failure, and the generation
is recovered intact.

### Packaging and downstream consumption

`scripts/package_check.ps1` performs, and verifies:

1. Release and Debug configure and build;
2. `cmake --install` into a clean prefix produces the library, the `dfab`
   executable, the public headers, and the four CMake package files
   (`DecommissioningFabricConfig.cmake`, `...ConfigVersion.cmake`,
   `...Targets.cmake`, `...Targets-release.cmake`);
3. an **independent out-of-tree project** at `scripts/consumer` configures
   with `find_package(DecommissioningFabric 1.0 REQUIRED)`, links
   `DecommissioningFabric::decommissioning_fabric`, and runs. It reported
   `consumer: ALL CHECKS PASSED` across 13 checks, including opening a store,
   registering an asset, creating a plan, reading the case back, and decoding the
   fence token the installed library printed;
4. `cpack` produces `DecommissioningFabric-1.0.0-Windows-AMD64.zip`
   (847 857 bytes).

### Fresh clone

`scripts/fresh_clone_check.ps1` clones the committed tree into a clean
directory, configures, builds, runs `ctest`, installs, and builds and runs the
consumer against that install. It exists to prove the committed tree is
self-contained.

---

## 10. Benchmarks

`dfab_bench` measures **completed operations** - the operation is finished,
including its durable commit, before the clock is stopped. Enqueue and submission
latency are never measured. Numbers below were measured on this host with the final
Release build and 1 000 completed operations per workload. They are measurements,
not comparisons: no before/after claim is made, and no workload here is presented
as an improvement over any other.

| Workload | Inputs | p50 | p95 | p99 | max | Durable bytes per completed op |
| --- | --- | --- | --- | --- | --- | --- |
| `generation_advance` (durable commit, growing state) | SYNTHETIC | 7 615 us | 8 893 us | 10 144 us | 12 111 us | 125.8 |
| `plan_create` (durable commit, state grows with each op) | SYNTHETIC | 18 170 us | 28 355 us | 30 595 us | 40 954 us | 790 511.2 |
| `refused_request` (no durable cost) | SYNTHETIC | 0.3 us | 0.4 us | 0.6 us | 5.7 us | 0 |
| `store_recovery` (open and recover a generation) | REAL | 28 277 us | 42 815 us | 52 740 us | 79 771 us | n/a |

Methodology notes, stated plainly:

* Each sample covers one completed operation including its durable commit, read
  from `Engine::last_commit()` rather than estimated from file sizes.
* `plan_create` creates a new asset and a new plan per operation, so the
  durable state grows with every completed op and the per-op cost grows with it.
  That is the documented O(state) copy-and-re-encode cost of never performing I/O
  under a lock, and it is the reason the per-op durable byte count is large and
  rising rather than constant.
* `refused_request` is measured separately and explicitly carries no durable
  cost, because a refusal is not an effect.
* Refusal timings and durable-operation timings are different things and are not
  comparable; they appear in one table only because both are completed operations.

---

## 11. SYNTHETIC versus REAL

| Claim class | Status |
| --- | --- |
| Process, filesystem, durability, locking, crash recovery | **REAL**, proven on the host with real processes, real files, and real process termination |
| Cross-process single-writer exclusion | **REAL**, proven with independent operating system processes |
| Packaging and downstream consumption of the installed artifact | **REAL**, proven with an independent out-of-tree project |
| Obligations towards ASI, DFI, power, cooling, tenants, technicians | **SYNTHETIC**: the runtime models, binds, and gates on them; it performs none of them |
| Any physical data-centre hardware behaviour | **NOT VALIDATED**: no plant hardware was exercised, and nothing here claims otherwise |

---

## 12. Installation and downstream consumption

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build --prefix /path/to/prefix
```

A consuming project needs nothing beyond the prefix:

```cmake
find_package(DecommissioningFabric 1.0 REQUIRED)
target_link_libraries(my_target PRIVATE DecommissioningFabric::decommissioning_fabric)
```

The imported target carries the C++20 requirement. The warnings interface used to
build this library is exported as `DecommissioningFabric::project_warnings` so
a consumer can opt into exactly the same strictness.

A complete worked example is in [scripts/consumer](scripts/consumer), and
[scripts/package_check.ps1](scripts/package_check.ps1) builds, installs, and runs it.

---

## 13. Repository layout

```
include/decommissioning_fabric/   public headers (strong types, fence, lifecycle,
                                  obligations, residual, evidence, store, engine)
src/                              library implementation
src/cli/                          command line front end
docs/ARCHITECTURE.md              the authoritative design record
tests/unit                        types, hashing, time, errors, codec, lifecycle,
                                  authority, residual, fence
tests/integration                 doctrine invariants, validation precedence,
                                  seeded state machine
tests/adversarial                 malformed, corrupt, truncated, hostile input
tests/durability                  crash consistency and multiprocess exclusion
tests/concurrency                 reader/writer load, callbacks, lock order
tests/e2e                         the CLI across a process boundary
tests/support                     harness, fixture, crash driver
bench/                            dfab_bench
scripts/                          packaging, fresh-clone, and consumer proofs
```

---

## 14. Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version: Apache-2.0
contributions, no CLA, zero first-party warnings, tests are proof obligations, and
a change that turns an unknown value into a benign one will be rejected.

---

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.

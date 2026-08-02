# Multimmit Thermo-Nuclear Code Quality Review

Date: 2026-08-25

Review target: `trunk()..cl/multimmit` at `f6ed89bf`

## Outcome

Not approved. The restacked change compiles in its primary configurations and the focused
cryptography tests pass, but the implementation does not meet the requested structural and
operational quality bar. The review found several resource and liveness blockers alongside major
ownership and decomposition problems.

## Restacked history

`cl/multimmit` now sits on `cl/multimmit-agg`. The competing Multimmit cryptography implementation
was removed; consensus uses the narrowed randomized verifier supplied by `cl/multimmit-agg`.

The stack is ordered as follows:

1. `[cryptography/bls12381] Add Multimmit aggregate signature scheme`
2. `[cryptography/bls12381] Narrow aggregate verification API`
3. `[runtime] Support Multimmit buffer ownership`
4. `[utils] Extend injected fault scheduling`
5. `[storage] Add Multimmit journal operations`
6. `[broadcast] Extend buffered ingress`
7. `[resolver] Support Multimmit request routing`
8. `[consensus] Add Multimmit`
9. `[glue] Adapt DKG elector construction`
10. `[deployer] Expose Multimmit system telemetry`
11. `[examples/estimator] Add Multimmit models`
12. `[examples/log-multimmit] Add distributed Multimmit example`
13. `[ci/docs] Integrate Multimmit`

The cryptography rebase required adapting consensus call sites to the aggregate branch's narrower
API. No review findings were fixed as part of the review.

## Findings

### 1. Structural blocker: the consensus change remains an unreviewable monolith

The `[consensus] Add Multimmit` revision changes 196 files with roughly 121,000 additions. It
combines public types, cryptography integration, the deterministic machine, runtime actors,
marshal, Simplex relocation, mocks, tests, fuzzing, benchmarks, and conformance.

Several newly introduced production owners are themselves extremely large:

- `consensus/src/multimmit/machine/reducer.rs`: 5,439 lines
- `consensus/src/multimmit/marshal/actors/catalog.rs`: 6,216 lines
- `consensus/src/multimmit/marshal/actors/synchronizer.rs`: 4,085 lines
- `consensus/src/multimmit/marshal/actors/resolver.rs`: 3,301 lines

The history should be split by invariant owner: shared types and schemes, deterministic machine,
actors, marshal and storage, integration and mocks, then fuzzing, benchmarks, and conformance.

The implementation also needs structural decomposition rather than merely smaller source files.
Replay, admission and verification, durability, and outbox and signing transitions should move out
of `machine/reducer.rs` into their existing invariant-owning components. The reducer should remain
a small atomic coordinator.

Primary locations:

- `consensus/src/multimmit/mod.rs:1`
- `consensus/src/multimmit/machine/reducer.rs:902`

### 2. P1: immutable archive `start_sync` is actually blocking

`consensus/src/multimmit/marshal/storage/archive.rs:270` calls `sync().await` for immutable
archives and then returns an already-complete handle. The library defaults finalized archives to
immutable, so the catalog cannot process another cut or unrelated request during that fsync. The
log-multimmit example avoids this particular default by selecting prunable finalized archives.

The immutable storage backend needs a genuine `start_sync` operation that returns ownership after
starting durability and whose handle covers every relevant metadata and freezer write. Marshal
should select policy and track the returned handle rather than emulate nonblocking behavior.

### 3. P1: cold metadata scans block the sole catalog mutation owner

`consensus/src/multimmit/marshal/actors/catalog.rs:2370` performs finalized history, header, and
output scans inline in the catalog event loop. A request can require as many as 1,024 serial archive
lookups per producer chain, and the event loop waits for the complete operation.

A valid peer request can therefore stall admission, commit completions, acknowledgements, and
unrelated producer chains. Immutable reads should run through a bounded read service backed by
snapshot or dedicated reader handles. Checkpoint transitions, pending-store mutation, pruning, and
durability state must remain exclusively owned by Catalog.

### 4. P1: the configured public mailbox bound is not a bound

`consensus/src/multimmit/marshal/mailbox.rs:210` retains every reliable overflow request in an
unbounded `VecDeque`, while `consensus/src/multimmit/marshal/config.rs:228` documents
`catalog_mailbox_size` as a bound on queued commands.

Cloned public mailboxes can accumulate unlimited requests, payloads, and reply channels while the
router or catalog is saturated. Capacity must be acquired before enqueueing, or overflow must be
rejected explicitly with a retryable pressure error. Advisory consensus hints can remain lossy.

### 5. P1: `test-utils` does not compile as an independent feature

`consensus/Cargo.toml:72` declares `test-utils` independently, but
`consensus/src/multimmit/test_utils/mod.rs:21` imports modules and types gated behind `mocks`.

The failure was reproduced with:

```sh
cargo check -p commonware-consensus --features test-utils
```

The command fails with unresolved mock-backed modules and types. Either define
`test-utils = ["mocks"]` or consistently gate the exports that require mocks. Add a feature-matrix
check so dev-dependency feature unification cannot hide the problem.

### 6. P1: the example retains unbounded full block forks

`examples/log-multimmit/src/application/actor.rs:209` stores complete block bodies by digest.
Certification removes old heights but retains every alternate digest at the current and future
heights. Valid equivocations can therefore multiply the intended body-retention window without a
byte or entry bound.

Staging should own exact live publication and verification obligations. Superseded forks should be
released, and retained bodies should have an explicit byte bound, preferably with an entry bound as
a secondary defense.

### 7. P2: bulk page-read cancellation leaks an ownership cycle

`runtime/src/utils/buffer/paged/cache.rs:390` creates the following strong ownership cycle:

```text
physical future -> fetch owners -> page futures -> physical future
```

Canceling a pending bulk read removes page-fetch registry entries but cannot release the pending
blob future, blob clone, or cache. Use weak fetch owners or independent non-owning generation
tokens. Extend cancellation coverage with a drop counter or weak reference so the test proves
resource release rather than only registry cleanup.

### 8. P2: invalid aggregate batches repeat expensive hash-to-curve work

`cryptography/src/bls12381/primitives/ops/batch.rs:356` re-hashes every term at every failed
bisection level. An adversarial all-invalid batch causes theta-N-log-N hash-to-curve operations.

Intern each distinct `(namespace, message)` and hash it once before bisection. Recursive checks
should regroup and rescale prepared group elements. Add an invalid-batch cost test or benchmark
that counts hash-to-group calls and enforces linear preparation cost.

### 9. P2: the shared elector contract weakened Simplex's safety requirement

`consensus/src/elector.rs:10` requires identical output only for identical rounds and identical
evidence. Simplex requires every valid certificate capable of unlocking the same round—including
different certificate types or quorum subsets—to elect the same leader.

The built-in electors satisfy the stronger invariant, but custom electors can now obey the
documented API while violating the voter's single-assignment assumption. Prefer a
protocol-normalized election seed or evidence type. At minimum, restore the stronger
Simplex-specific equivalence contract and add a custom-elector regression covering distinct valid
certificate paths into the same round.

### 10. P2: batched DA signing consumes only one application timing correlation

`consensus/src/multimmit/actors/voter/executor.rs:205` permits one DA vote per producer chain in a
signing batch, but `take_application_timing` removes only the first matching correlation. Other
correlations become stale, telemetry is undercounted, and repeated batches eventually cause linear
searches and `Vec::remove(0)` shifts on the serial voter.

Signing outcomes should carry one optional timing per request and consume the entire batch
atomically through keyed ownership. Tests should assert one sample per correlated request rather
than merely the existence of one sample.

### 11. P2: promotion reclamation unnecessarily becomes a global commit barrier

`consensus/src/multimmit/marshal/actors/catalog.rs:692` treats `Promoted` like installation and
pruning. It waits for commit, admission, and every durability operation to become idle before
processing a background reclamation frontier.

Represent promotion progress as a bounded latest-frontier notification with eventual retry, or move
pending-body reclamation into its own owner. Reclamation must respect pending segment pins and
admission cuts, but it should not wait for unrelated finalized commit or acknowledgement durability.

### 12. P2: the engine fuzzer heals network faults immediately

`consensus/fuzz/src/multimmit_engine.rs:323` restores both `Disconnect` and `Degrade` before the next
fuzz action. It cannot preserve a partition across a later storage reopen, combine faults on
multiple nodes, or exercise crash-plus-partition interactions despite claiming to target them.

Fault and heal operations should be distinct persistent actions, with `heal_all` reserved for the
final lossless suffix.

### 13. P2: the allocation benchmark measures fixture construction

`consensus/benches/multimmit/machine.rs:29` places fixture construction, allocation-counter
plumbing, assertions, and the target operations inside Criterion's timed iteration. The resulting
latency series is dominated by setup and can trip performance alerts after unrelated fixture
changes.

Move exact allocation baselines into ordinary regression tests. If latency is also needed, use
Criterion batched setup outside the measured region and time only the operation.

The benchmark layout should also follow the repository convention by living beside its module,
rather than splitting front ends under `consensus/benches/multimmit` from support code under
`consensus/src/multimmit/test_utils/benchmarks`.

### 14. P2: the root HTML architecture artifact has no owner

`multimmit-marshal-plan.html:1` is an unreferenced, generated, self-contained architecture document
that duplicates the canonical Markdown design documents and has no documented generator.

Delete it, or place it under an indexed documentation or asset hierarchy with its source and update
procedure.

## Runtime and storage assessment

The runtime and storage revisions should not be removed wholesale:

- The generic bulk page-read mechanism belongs in runtime and directly addresses cold-read
  amplification.
- Delayed read and sync wrappers are legitimate deterministic test infrastructure.
- Sealed-reader and bounded-replay journal operations belong in storage and are used by Multimmit.
- No protocol-specific Multimmit types leaked into runtime or storage.

The runtime bulk-read ownership cycle must be corrected. Genuine nonblocking immutable archive
synchronization should be implemented in storage, not reconstructed in marshal.

## Validation performed

- `just test -p commonware-consensus bls12381_threshold`: 61 of 61 passed.
- `cargo check -p commonware-consensus --features test-utils,mocks`: passed.
- `cargo check -p commonware-log-multimmit`: passed.
- `cargo fmt --all -- --check`: passed.
- `cargo check -p commonware-consensus --features test-utils`: failed as documented above.
- Full Clippy did not produce a clean signal because the current toolchain reports existing bitmap
  warnings in `utils` outside this diff.

Four focused delegated reviews completed across supporting crates, consensus actors, marshal, and
integration structure. The dedicated machine-only pass was stopped at the bounded review finish
line rather than allowed to continue indefinitely; machine structure was also covered by the
cross-cutting and actor reviews.

## Repository state at handoff

- Review target: `cl/multimmit` at `f6ed89bf`.
- Working copy was clean after restacking and review.
- Generated deployment directories were left untracked.
- No bookmark was pushed.
- The unrelated `cl/more-robust-glue-nits` bookmark conflict was not modified.

Confidence in the listed findings: high.

## Remediation progress

The accepted remediation scope is findings 2 through 13; finding 1 remains an acknowledged
structural constraint of the initial Multimmit import. Each completed item lives in its own
revision and received a focused reduction pass before validation.

- [x] 2: immutable archive durability is genuinely pipelined.
- [x] 3: exact cold metadata reads no longer execute in Catalog.
- [x] 4: reliable marshal ingress is bounded.
- [x] 5: `test-utils` is self-contained.
- [x] 6: the example retains only locally published bodies.
- [x] 7: canceled bulk page reads release their ownership graph.
- [x] 8: aggregate verification prepares repeated messages once.
- [x] 9: Simplex again documents and tests evidence-equivalent election.
- [x] 10: no change required. Production batch signing contains at most one DA vote; the reported
  multi-correlation leak is unreachable.
- [x] 11: promotion reclamation no longer shares the global commit barrier.
- [x] 12: fuzz network faults persist until an explicit heal action.
- [x] 13: allocation contracts are ordinary tests and Criterion measures only target work.

Finding 3 uses request-owned exact read plans. Catalog remains the sole mutation owner, captures
each plan synchronously, and only processes continuations after the prior step returns. Pruning may
advance while captured reads pin their exact storage; floor installation waits for all staged
metadata reads because it replaces archive ownership and coordinates.

The final review separated metadata-read capacity from admission cuts, allowed independent header
branches to advance as their reads complete, retained incremental metadata writes behind dependent
durability, restored the benchmark's finalization oracle, and removed an unused archive read API.
The completed tree passes all 2,944 storage tests and all 1,698 consensus tests, along with format,
all-feature consensus check, stability, and changed-crate Clippy validation.

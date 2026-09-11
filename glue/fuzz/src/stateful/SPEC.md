# Glue Stateful Fuzzing — Specification

This document is the technical specification for the glue stateful fuzzing feature.
It states *what* the feature must do and *which properties
and invariants must hold*; it deliberately omits *how* the code achieves them.

## Definitions

Used throughout this document with exactly these meanings.

- **Stateful** — the actor defined in `glue/src/stateful/mod.rs` that maintains speculative
  database state for every pending fork above the finalized tip on behalf of an inner application.
- **Application** — the trait in `glue/src/stateful/mod.rs` that Stateful drives: `genesis`,
  `propose`, `verify`, `apply`, `finalized`, `sync_targets`. The system under test is Stateful's
  handling of that trait, not the trait's implementations.
- **Identity** — one signing key in the validator set. There are four.
- **Engine** — one running node stack. There are five: three correct identities with one engine
  each, and the compromised identity with two.
- **Compromised identity** — the single identity that runs two engines, its **primary half** and
  **secondary half**, both signing with the same key and distinguished only by their storage
  partitions. This is R4's *virtual faulty node*.
- **Correct node** — an engine belonging to a non-compromised identity. All agreement claims in §8
  are about correct nodes only; both halves of the compromised identity are excluded.
- **Correct application** — the deterministic `Application` implementation run by every correct
  node and by the primary half.
- **Faulty application** — the `Application` implementation run by the secondary half, which
  deviates within the bounds of §6.
- **SimplexCertMock** — this document's name for the mock certificate scheme
  `commonware_consensus::simplex::mocks::scheme::Scheme`, whose signatures and certificates are
  synthetic identifiers recorded in shared state rather than results of signature math. R9's
  requirement is a requirement to use it.
- **Twins scenario** — a per-view assignment of which identities each half of the compromised
  identity may exchange messages with, drawn from the twins case generator in
  `commonware_consensus::simplex::mocks::twins`.
- **Prefix** — the scripted adversarial part of a run: the leading rounds for which the twins
  scenario prescribes a partition.
- **Suffix** — the part of a run after the prefix, during which the scenario prescribes no
  partition and the network is whole.
- **Measurement point** — the point at which the invariants in §8 are checked: the end of the
  suffix, or the run's bounded timeout, whichever comes first.
- **Pending tip** — a merkleized database batch Stateful holds in memory, keyed by block digest,
  representing the speculative state of one fork.
- **Lazy recovery** — Stateful's reconstruction of a missing pending tip by walking back the block
  DAG through marshal and replaying forward through `Application::apply`.
- **Restart** — abort of a correct node's engine followed by re-initialisation under the same
  identity against its retained storage.

The invariants in §8 belong to the fuzz crate. Nothing under `glue/src` or `consensus/src` is held
to them, and nothing under those trees is modified to satisfy them.

## 1. Purpose

A stateful application built on consensus must maintain speculative state for every pending chain
above the finalized tip. Stateful automates that bookkeeping: it forks batches from a parent's
pending state before each proposal and verification, stores the merkleized result as a new pending
tip, applies the winning tip on finalization, prunes dead forks, and rebuilds pending state lazily
after a restart.

The entire Commonware stack, glue included, must work in a byzantine environment.

Consensus-layer fuzzing does not cover this. The end-to-end marshal targets in `consensus/fuzz/marshal`
assert that honest nodes agree on finalized block digests; they never assert anything about the
database state those blocks produce, because at that layer there is none. A defect in which two
correct nodes finalize the same chain and arrive at different database state is invisible to every
existing target.

This feature runs a Twins cluster over the real glue stack — Simplex, marshal, Stateful, and QMDB —
in which the compromised identity's two halves run a correct and a faulty application respectively,
and checks safety: the correct nodes must agree on the chain, on the database state that chain
produces, and on whether a block verifies.

## 2. Goals

- **G1.** Provide a fuzz target for Stateful that exercises the real actor against real
  storage under byzantine pressure.
- **G2.** Apply the Twins method at the application layer: the compromised identity's two halves
  differ not only in what they are told, but in the application they run.
- **G3.** Detect disagreement among correct nodes on the chain, on database state, and on
  verification verdicts.
- **G4.** Reach the pending-tip bookkeeping that only restarts expose — fork pruning, lazy
  recovery, and replay through `apply`.
- **G5.** Achieve all of the above without modifying `glue/src`, `storage/src`, and `consensus/src`.
- **G6.** Keep the target fast enough to be worth running: throughput is an acceptance criterion,
  not an afterthought.
- **G7 — Stateful database diversity.** Exercise Stateful with every supported database-adapter
  class relevant to this feature—`any`, `current`, immutable standard and compact, and keyless
  standard and compact—so adapter-specific correctness defects are not hidden by testing only one
  database construction. This is a behavioral coverage goal, not a requirement for 100% line
  coverage.
- **G8 — Stateful floor probe.** Exercise the real Stateful `Probe` actor through discovery and
  service under adversarial peer input, ensuring that floor selection depends only on valid
  responses from distinct committee members and remains safe across retries and subscription or
  attachment ordering.

## 3. Technical requirements

- **R1 — Focused fuzz targets.** The feature MUST expose independently runnable libFuzzer targets
  for Twins safety, restart recovery, database-adapter coverage of both the restart and the Twins
  clusters, and the Stateful probe protocol.
  Targets MAY share library machinery, but each distinct search space MUST retain its own corpus so
  progress in one does not displace inputs for another.
- **R2 — Thin targets.** Every fuzz-target file MUST only instantiate libFuzzer and invoke a
  library entry point. Target files MUST contain no harness logic or fuzzing primitives; all such
  code belongs in `glue/fuzz/src/stateful`.
- **R3 — Architectural conformance.** Every target MUST follow the established fuzz-crate
  architecture: a thin `#![no_main]` target over library logic, a hand-written `Arbitrary` input
  with explicit bounded controls followed by a remaining byte tape, deterministic execution driven
  only by that tape, target-specific safety predicates implemented in the library, and a panicking
  oracle that identifies the reproducing input.
- **R4 — Twins topology.** The cluster MUST consist of five engines over four identities: three
  correct, and one virtual faulty identity composed of two engines instantiated from the real
  consensus codebase, sharing one signing key. Twins method is implemented via networking and the stateful application.
  Twins faults are not introduced via `marshal` or `simplex` as it is implemented in the fuzzer of `consensus`.
- **R5 — Correct application.** A stateful application implementing the `Application` trait MUST
  be provided and MUST be deterministic: if a correct node does not verify a block then no correct
  node verifies it, and if one correct node verifies a block then all correct nodes verify it.
  Every correct node and the Twins' primary half MUST run this application, identically configured.
- **R6 — Faulty application.** A faulty application MUST be provided that from time to time
  introduces faults through the supported interface, within the bounds of §6.
- **R7 — Twins semantics.** The compromised identity MUST comprise the correct application on one
  half and the faulty application on the other, so that the pair sometimes behaves correctly and
  sometimes does not. The two halves MUST be subject to different partitions. The message-level
  Twins logic MUST match that of `consensus/fuzz`: per-view partitions drawn from a twins scenario,
  applied by splitting each identity's channels rather than by manipulating network links.
- **R8 — Safety only.** The feature targets safety. It MUST NOT assert liveness, and a run that
  makes no progress MUST NOT be reported as a failure.
- **R9 — Mock certificate scheme.** SimplexCertMock MUST be used. No real cryptography may be used
  in the signing or certificate path, because it is too slow for fuzzing.
- **R10 — Fuzz-only implementation.** Every file changed by this feature MUST be under
  `glue/fuzz/`. No file outside that directory—including crate sources, workspace metadata, or CI
  configuration—may be modified. All exercised behavior MUST be reached through public APIs
  exposed by the existing crates.
- **R11 — Cluster node stack.** In the Twins, restart, and database-adapter targets, every engine
  MUST run the real stack: a Simplex engine, a marshal actor in the Standard `Deferred`
  configuration, the real Stateful actor, and a real QMDB-backed database selected for that target.
  Stateful is incompatible with `Inline`, which does not verify the embedded context, so `Inline`
  is excluded. Each node MUST use a single database and start with no finalized floor attached, so
  startup uses marshal reconciliation and does not enter peer state sync. The probe target is
  governed separately by R20 and R21.
- **R12 — Restart scope.** The restart targets, plain and database-adapter, MUST accept a
  fuzz-controlled schedule that can crash and restart correct identities while retaining their
  storage, so lazy recovery is exercised. All four identities MUST be correct in any run that
  exercises restarts, and at most one identity may be down at a time. The Twins targets, plain and
  database-adapter, MUST NOT restart either half of the compromised identity.
- **R13 — Bounded runs.** Every target MUST bound its node count, input consumption, event count,
  simulated duration, and allocated storage so execution remains suitable for continuous fuzzing
  and meets any applicable throughput floor in §10. Within a target, each bound MUST be fixed
  across all selected scenarios and database adapters; no configuration may receive relaxed
  limits. Cluster suffix heights and leader term length MAY vary with the fuzz input only within
  those fixed bounds.
- **R14 — Deterministic execution.** Every target MUST reproduce the same behavior and observations
  from the same input. Scheduling and randomized choices MUST depend only on the input bytes and
  execute under the deterministic runtime, without entropy-backed randomness or wall-clock time.
  Cluster targets MUST use SimplexCertMock, and no target may depend on real cryptography.
- **R15 — Deterministic regression suite.** Every fuzz target MUST have ordinary tests in the fuzz
  crate, driven by fixed representative inputs, that exercise its required modes and applicable §8
  invariants. These tests MUST use the same library entry points and oracles as libFuzzer. The suite
  is the primary regression gate; fuzzing extends it rather than replacing it.
- **R16 — Self-contained.** The feature MUST NOT depend on `commonware-consensus-fuzz-*`. The twins
  driver and channel-splitting logic are re-derived in `glue/fuzz` from the published crates. The
  corresponding code in `consensus/fuzz` is a reference to model on, not a dependency, and this
  duplication is deliberate.
- **R17 — Non-blocking peer policy.** Simulated networks carrying adversarial traffic MUST set
  `disconnect_on_block` to `false` so blocking one peer does not prevent the harness from continuing
  to explore later faulty messages.
- **R18 — Database-adapter matrix.** There are two database-adapter targets: one over the restart
  cluster of §7.2 and one over the Twins cluster of §7.1. Each one's structured input MUST select
  among `any`, `current`, immutable standard, immutable compact, keyless standard, and keyless
  compact. Each run MUST instantiate one real database of the selected class behind `Shared` and
  drive it through Stateful's genesis, batch creation and forking, application mutation,
  merkleization, apply, and finalize paths under the existing safety invariants; the restart-based
  target MUST additionally drive crash/restart recovery, and the Twins-based target MUST
  additionally subject it to the Twins adversary of §6. Merely constructing an adapter or testing
  the underlying storage directly does not satisfy this requirement.
- **R19 — Adapter-correct workload.** The fuzz application MUST respect the selected database
  model: immutable adapters receive only fresh-key inserts, keyless adapters receive appends, and
  compact adapters are not assumed to support historical reads. Every proposed or verified block
  MUST commit to the selected adapter's exact sync target. For `current`, the application MUST
  additionally commit to and verify the canonical state root separately because its sync target
  covers the operations root and range rather than the canonical root. Application behavior MUST
  remain within the `Application` contract for every adapter.
- **R20 — Real probe boundary and floor oracle.** The probe target MUST run real
  `stateful::probe::Probe` actors over the deterministic simulated network. Source probes MUST serve
  finalizations from real marshal mailboxes, and the discovering probe MUST be driven only through
  its public mailbox and P2P receiver boundary. Fuzz-controlled malformed traffic MUST enter as raw
  network bytes. The harness MUST NOT reimplement floor selection, response verification, or probe
  state transitions. Whenever the probe derives a floor `F`, at least `f + 1` distinct committee
  members MUST have contributed valid finalizations to the resolving sample, `F` MUST equal the
  highest finalization in that sample, and the modeled state of the peer that supplied `F` MUST
  contain that finalization.
- **R21 — Probe adversary program.** The probe target's structured input MUST bound and control the
  finalization held by each source, message delivery order, delay, drop and duplication, malformed
  raw payloads, participant or non-participant origin, retry advancement, subscription cancellation
  or repetition, and marshal attachment timing. Peer count, event count, message size, and simulated
  duration MUST remain bounded.
- **R22 — Shared backend machinery.** The database-adapter targets MUST reuse the existing
  deterministic restart and Twins drivers respectively, the real Stateful stack, and the safety
  predicates through a statically dispatched, harness-local backend abstraction. Adapter-specific
  code MUST be limited to database types and configuration, valid batch operations, sync-target
  construction, and canonical-commitment extraction. The feature MUST NOT duplicate the complete
  runner or node stack for each adapter or add dynamic dispatch to the exercised path.

## 4. Properties

The feature must exhibit the following qualitative guarantees. These are the audit's acceptance
criteria; the checkable predicates are enumerated in §8.

- **P1 — Correct-node symmetry.** Within each cluster run, every correct node runs the same
  application, stack, and selected database configuration. Any divergence among them is therefore
  attributable to the exercised system rather than a distinguishing harness setting. This
  property does not apply to the probe target, whose source finalizations are intentionally
  fuzz-controlled under R21.
- **P2 — Uniform per-target bounds.** Each target applies the same execution and resource bounds to
  every scenario or database adapter it can select. Distinct targets may use different bounds
  because they exercise different search spaces, but no selected configuration may receive relaxed
  limits to make it pass.
- **P3 — Adversary confinement.** In the Twins targets, plain and database-adapter,
  application-level faults occur only on the secondary half; the primary half and every correct
  node use the correct application. The restart targets, plain and database-adapter, use only
  correct applications. Probe adversarial input is confined to
  the public boundaries and controls listed in R20 and R21, without altering the recorded
  source-state model.
- **P4 — Contract-bounded application adversary.** In the Twins targets, the faulty application
  stays within what the `Application` trait permits. A run that fails only because the harness
  supplied behavior outside that contract is not a finding; §6 states the boundary and §9 records
  what is excluded.
- **P5 — Determinism and minimization.** Any failure must be reproducible from the crashing input
  and minimizable by the fuzzer, with no cross-run state leakage. The input's byte tape MUST NOT
  be printed in `Debug` output; its length may be.
- **P6 — Search-space isolation.** Adding database-adapter and probe targets MUST NOT change the
  existing Twins or restart targets' input decoding, topology, scheduling, fault model, or safety
  predicates. Shared machinery MAY be refactored only when the existing targets remain behaviorally
  equivalent and their corpora remain replayable.

## 5. Files and interfaces

### 5.1 Feature module — `glue/fuzz/src/stateful/`

The decomposition below is indicative: it records the structure the feature is expected to have
and is not itself a requirement. The target names in §5.2 are normative (R1, R2).

- `mod.rs` — module wiring; re-exports the input type and the entry function.
- `input.rs` — the fuzz input type and its hand-written `Arbitrary`.
- `network.rs` — the per-channel split forwarders and routers that realise the twins partition.
- `stack.rs` — construction of one engine: channels, broadcast, archives, marshal, Stateful, QMDB,
  and the Simplex engine, plus the restart path.
- `app.rs` — the correct application and the faulty application.
- `backend.rs` — statically dispatched database types, configurations, valid workload operations,
  and commitment conversion for the database-adapter matrix.
- `probe.rs` — deterministic Probe topology, adversarial event driver, global source-state model,
  and Probe-specific oracles.
- `runner.rs` — deterministic cluster execution and measurement shared by the Twins, restart, and
  database-adapter targets.
- `invariants.rs` — the checks in §8.

### 5.2 Fuzz targets

- `glue/fuzz/fuzz_targets/stateful_cert_mock_twins.rs`
- `glue/fuzz/fuzz_targets/stateful_cert_mock_restarts.rs`
- `glue/fuzz/fuzz_targets/stateful_cert_mock_restarts_db.rs`
- `glue/fuzz/fuzz_targets/stateful_cert_mock_twins_db.rs`
- `glue/fuzz/fuzz_targets/stateful_probe.rs`
- A corresponding `[[bin]]` entry for every target in `glue/fuzz/Cargo.toml`.
- `glue/fuzz` remains a workspace member and fuzz-matrix entry; target discovery runs each target
  with its own corpus.

### 5.3 Consumed dependencies (pre-existing; named, not defined here)

The existing infrastructure must be reused as much as possible.

- SimplexCertMock and the twins scenario generator and elector, from
  `commonware_consensus::simplex::mocks`, behind the consensus `mocks` feature.
- The simulated network and its split-channel plumbing, from `commonware_p2p::simulated`.
- The deterministic runtime and its storage, from `commonware_runtime::deterministic`.
- The database-set traits and QMDB adapters in `glue::stateful::db`, and the QMDB implementations
  they wrap in `commonware_storage::qmdb`.
- The parts of `commonware_glue::simulate`, behind the `test-utils` feature, that fit. Note the
  limit: that harness keys engines one-per-identity and does not split channels, so it cannot host
  Twins and is not the driver.

`glue` exposes no `mocks` feature, so the mocks are enabled on the consensus, cryptography, p2p and
resolver dependencies directly.

Any change to a consumed interface that alters its contract is a change to this feature's
dependencies and must be re-audited against this document.

## 6. Adversary model (normative)

Each target has a confined fault model. A1–A4 define the Twins adversary: one compromised identity
is Byzantine at the message and application layers, while correct nodes are never adversarial. The
probe adversary is limited to R20, R21, and I8. The restart targets, plain and database-adapter,
contain no Byzantine participants; their crash schedule is an environment fault. The Twins-based
database-adapter target uses the Twins adversary over the backend its input selects.

- **A1 — Message layer.** Each of the compromised identity's channels that carries
  view-addressable traffic MUST be split in two, with the twins scenario deciding, per view, which
  identities each half may send to and which half receives a given inbound message. Because both
  halves sign with the same key, this is what produces equivocation: the identity can vote one way
  in one partition and another way in the other. Traffic on a channel from which no view can be
  determined MUST be handled by a single stated rule, uniform across channels; leaving it implicit
  is a defect.
- **A2 — Application layer.** The secondary half MUST run the faulty application, which may
  deviate only where the `Application` trait permits:
  - return no verdict for a block a correct node accepts, which the trait models as permanent
    invalidity;
  - return a merkleized result that matches the block's sync targets but whose content differs
    from what the correct application would produce;
  - decline to resolve a verification, which the trait defines as abstention;
  - decline to build a proposal.

  Which of these is armed, and how often, MUST be derived from the run's input tape.
- **A3 — Excluded deviations.** The faulty application MUST NOT return a proposal whose
  commitments disagree with its merkleized result, and MUST NOT return a replay result that
  disagrees with the block being replayed. Both are documented as conditions under which Stateful
  panics deliberately. Admitting them would require allowlisting panics on the compromised
  identity, which would weaken I4 for every run in the corpus. They are recorded in §9.
- **A4 — Non-shadowing.** The two layers act on disjoint surfaces: A1 decides who hears a message,
  A2 decides what the secondary half's application computes. The primary half runs the correct
  application, so the pair's disagreement is genuine application-level equivocation under one
  identity and not an artefact of both halves being told to misbehave.

Crash and restart of correct identities is an environment fault, not adversarial behaviour; it is
specified in §7.

## 7. Run structures

Every target MUST use its bounded, deterministic structure below.

### 7.1 Twins

1. **Setup.** Four identities and five engines are constructed per R4 and R11; the Twins-based
   database-adapter target uses the backend selected by its structured input. The compromised
   identity's channels are split per A1.
2. **Prefix.** The engines execute the selected bounded Twins scenario while the secondary half's
   faulty application is active.
3. **Suffix.** After the scripted prefix, the network is whole and both compromised halves address
   every identity.
4. **Measurement.** The run ends when every correct node applies the required suffix heights or the
   bounded timeout expires. I1-I4 and I6 are checked over everything observed. A stalled run is not
   a liveness failure.

Twins observations MUST be keyed by engine because the compromised halves share an identity.

### 7.2 Restart and database-adapter targets

1. **Setup.** Four correct identities are constructed. The restart target uses its existing
   database configuration; the restart-based database-adapter target uses the backend selected by
   its structured input.
2. **Execution and restarts.** Correct nodes execute the real stack while a bounded schedule crashes
   and restarts at most one identity at a time. Storage partitions are retained, forcing
   reconciliation and lazy recovery.
3. **Measurement.** The run ends when every correct node applies the required heights or the bounded
   timeout expires. I1-I4 and I6 are checked using the same observations and predicates as before. A
   stalled run is not a liveness failure.

### 7.3 Probe target

1. **Setup.** The deterministic network is populated with real source Probe actors attached to real
   marshal mailboxes and one discovering Probe actor.
2. **Source state.** Each source marshal is seeded from the structured input, and the harness records
   the exact finalization held by each source.
3. **Adversarial execution.** The bounded event program drives subscriptions, attachment, retries,
   network delivery, and raw malformed traffic through public boundaries.
4. **Measurement.** If a floor is emitted, I7 and I8 are checked against the recorded source state
   and resolving sample. No floor is required when a sufficient valid sample was not collected. I4
   and I6 apply throughout.

## 8. Invariants (must hold at the measurement point)

At each target's measurement point, every applicable invariant below MUST hold; a violation is a
reportable defect. I1-I3 apply to correct nodes in the Twins, restart, and database-adapter targets,
with both compromised halves excluded from the Twins comparisons. I4-I6 apply to every target.
I7-I8 apply to the probe target.

- **I1 — Chain of blocks.** The finalized chains observed at the correct nodes MUST be consistent
  in the sense of the chain-of-blocks method: at most one distinct block per height across all
  correct nodes; each block's recorded parent is the block at the preceding height, rooted at
  genesis; and each node's delivery sequence advances by one height at a time from its starting
  anchor. Delivery is at-least-once and restarts make repeats normal, so an exact repeat of a
  height already delivered MUST be accepted and a differing repeat MUST NOT.
- **I2 — Database-state agreement.** For every height finalized by two or more correct nodes,
  those nodes' committed database state for that height MUST be identical. The observable is the
  per-height canonical state commitment each node reaches once the height is applied, recorded per
  node at the moment it is applied rather than sampled globally, so that nodes progressing at
  different rates are compared at the same height and not at the same instant. For `current`, this
  canonical commitment MUST remain distinct from the operations sync target described by R19.
  Application is at-least-once and restarts replay heights, so an exact repeat of a commitment
  already recorded for a height MUST be accepted and a differing repeat MUST NOT. This is the
  invariant the feature exists for; I1 holding while I2 fails is the defect class no existing
  target can see.
- **I3 — Verification-verdict agreement.** No correct node's application may accept a block that
  another correct node's application rejected. R5 makes the correct application deterministic and
  P1 makes every correct node run it identically, so a violation is attributable to Stateful
  presenting different inputs to the same deterministic function.
- **I4 — No panic.** No actor, engine, or harness task may panic. In the Twins targets, A3 keeps
  the faulty application inside the `Application` contract. In the probe target, all malformed or
  adversarial input is delivered through interfaces required to handle it safely. There is no panic
  allowlist: any panic in any target is a finding.
- **I5 — Fuzz-only change scope.** Every change introduced by this feature MUST be confined to
  `glue/fuzz/`. No file under `glue/src`, `storage/src`, `consensus/src`, or elsewhere in the
  workspace may be modified, and any pre-existing unrelated working-tree changes MUST be preserved.
- **I6 — Reproducibility.** A failing input replayed MUST fail identically. A failure that does not
  reproduce is itself a defect, in the harness rather than in glue.
- **I7 — Probe floor provenance.** If the discovering probe emits floor `F`, the oracle MUST
  establish that the resolving sample contains valid responses from at least `f + 1` distinct
  members of the solicited committee, that `F` is the highest-round finalization in that sample,
  and that the source-state model for the peer supplying `F` contains that exact finalization. A run
  that never collects a sufficient sample MAY terminate without producing a floor.
- **I8 — Probe response isolation.** Every response admitted to the sample MUST decode, meet the
  minimum epoch, have an available verifier, verify successfully, and come from a solicited
  committee member. At most one response per peer MAY contribute. A pending peer that sends
  malformed or unverifiable data, or a non-participant that sends an otherwise valid finalization,
  MUST be blocked. Stale or unjudgeable responses and traffic from an already-counted peer or after
  floor selection MUST NOT change the sample or selected floor.

An invariant MUST NOT be disabled, weakened, or narrowed to make a configuration pass. A
configuration that cannot satisfy one is either a reportable defect or an exclusion recorded in §9;
no exclusion may be introduced in code.

## 9. Out of scope

- **Fuzzers for all components of the glue.** This feature covers the Stateful module only.
- **100% coverage.**
- **Liveness.** Excluded by R8. No progress requirement is asserted, and a stalled run is healthy.
- **Contract-violating application faults.** Proposals whose commitments disagree with their
  merkleized result, and replays that disagree with the block replayed, are excluded by A3.
- **Restarting the compromised identity.** Excluded by R12.
- **Peer state sync.** No node attaches a finalized floor, so the state-sync startup path and the
  sync engines are not exercised.
- **Marshal variants other than Standard `Deferred`.** `Inline` is unsupported by Stateful; the
  coding variant is a later target.
- **Multi-database sets.** Each node manages a single database.
- **Pruning.** Periodic database and marshal pruning is disabled, so the deferred prune path is not
  exercised.
- **Real cryptography and non-deterministic runtimes.** Excluded by R9 and R14.
- **Modifying any file outside `glue/fuzz/`.** Excluded by R10.

## 10. End-to-end verification

The following sequence proves the feature works. Each step names the observable outcome an auditor
should confirm. `cargo fuzz` requires a nightly toolchain; set it as a directory override for
`glue/fuzz` rather than changing the repository's pinned default.

1. **Source tree is untouched.**
   `git status --porcelain glue/src consensus/src` prints nothing (I5, R10).

2. **The crate is registered.**
   `glue/fuzz` appears in the workspace members and in the CI fuzz matrix, and
   `cargo metadata --no-deps` lists `commonware-glue-fuzz`.

3. **The target is thin.**
   The target file contains only the libFuzzer entry point and a call into the library; a reviewer
   confirms no fuzzing logic or primitive is defined in it (R2).

4. **Everything compiles and lints clean.**
   `cargo check -p commonware-glue-fuzz --tests` succeeds and
   `cargo clippy -p commonware-glue-fuzz --tests` reports no warnings. `just lint` remains clean
   for the workspace.

5. **The regression suite passes.**
   `cargo nextest run -p commonware-glue-fuzz stateful::` runs every fixed-input scenario and
   reports all tests passing, exercising I1-I4 and I6 (R15; acceptance criterion 2).

6. **The fuzz target builds.**
   `cargo +nightly fuzz build --fuzz-dir glue/fuzz stateful_cert_mock_twins` completes with no
   warnings and no errors (acceptance criterion 1).

7. **Throughput clears the floor.**
   A short smoke run, `cargo +nightly fuzz run --fuzz-dir glue/fuzz stateful_cert_mock_twins --
   -max_total_time=8`, completes with no crash, hang, or out-of-memory, and libFuzzer's reported
   `exec/s` is above 10 (acceptance criterion 3, R13). If it is not, the run bounds in R13 are what
   move; the invariants are not.

8. **The checks are not vacuous.** A test can pass because nothing was wrong, or because nothing
   was checked. This step rules out the second case.

   Each run reports how many correct nodes were observed, how many heights were compared under I1,
   how many database-state comparisons were made under I2, how many verdict pairs were compared
   under I3, and how many restarts were executed. Across the suite every one of these counts MUST
   be above zero. A run that stalled and measured nothing MUST be reported as unmeasured, with its
   reason, and never counted as passing.

   As a negative control, an auditor perturbs the database root observed for one correct engine at
   one height, after Stateful's sync-target validation, and confirms the suite fails under I2 while
   I1 still passes. This demonstrates that the database-state check carries signal that the chain
   check does not without relying on an application-level divergence, which Stateful rejects
   earlier. `invariants.rs` MUST NOT be changed for this control: the defect is introduced at the
   observation boundary, not in the check.

Passing steps 1-7, plus the negative control in step 8, constitutes acceptance of this
specification.

## 11. Construction rules (normative)

The rules in this section are normative. The components and mechanisms they name describe the
reference implementation and may change without amending this document.

- **Correct application.** It MUST be a pure function of the context, ancestry and batches it is
  given, with all mutable state carried in those batches, so that clones invoked concurrently
  agree. It MUST commit to its execution result in the block it proposes and MUST reject a block
  whose committed state disagrees with the result of executing it. R5's agreement property then
  holds by construction of the harness, which is what makes a violation of I3 a glue defect rather
  than a harness defect.
- **Faulty application.** Its fault decisions MUST derive solely from the run's input tape, never
  from wall-clock time, task scheduling order, addresses, or iteration order over an unordered
  collection. It MUST be confined to the secondary half; sharing an instance or a fault schedule
  with any other engine is a defect under P3.
- **Channel splitting.** Every channel carrying view-addressable traffic MUST be split, and the
  split MUST derive the view from the message itself rather than from ambient state, so that
  routing a message never depends on when it is routed. Channels whose traffic carries no
  determinable view MUST follow the single stated rule required by A1.
- **Restarts.** A restart MUST retain the node's storage and MUST reuse the identity's key and
  channel registrations. The restart schedule MUST come from the input tape, and the harness MUST
  enforce R12's bound of one correct identity down at a time rather than relying on the schedule to
  respect it.
- **Observation.** The oracle MUST record what each engine actually delivered and applied, taken
  from the engine's own reporting path, and MUST NOT infer agreement from harness-side bookkeeping
  about what should have been delivered. Records MUST be keyed by engine.
- **Failure reporting.** A violated invariant MUST panic with a message naming the invariant, the
  engines involved, and the height at which they diverged, and the harness MUST print the
  reproducing input bytes before the process aborts.

# Glue Stateful Twins Fuzzing — Specification

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

Consensus-layer fuzzing does not cover this. The end-to-end marshal targets in `consensus/fuzz`
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

## 3. Technical requirements

- **R1 — One fuzz target.** The feature MUST expose one libFuzzer target exercising the Stateful
  module.
- **R2 — Thin target.** The target file MUST only instantiate the fuzzer. It MUST contain no
  fuzzing logic and no fuzzing primitives; both live in `glue/fuzz/src/stateful`.
- **R3 — Architectural conformance.** The feature MUST follow the architecture and code style of
  `consensus/fuzz`: a thin `#![no_main]` target over library logic, a hand-written `Arbitrary`
  input whose byte tape seeds both the deterministic runtime and the scenario sampler, invariants
  in a dedicated module, and a panicking oracle that prints the reproducing input.
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
- **R10 — Non-modification.** The feature MUST NOT change anything under `consensus/src`, `storage/src`, or
  `glue/src`. All code lives in the fuzz crate.
- **R11 — Node stack.** Every engine MUST run the real stack: a Simplex engine, a marshal actor in
  the Standard `Deferred` configuration, the real Stateful actor, and a real QMDB-backed database
  set. Stateful is incompatible with `Inline`, which does not verify the embedded context, so
  `Inline` is excluded. Each node MUST use a single database in the set, and MUST start with no
  finalized floor attached, so the startup path is marshal reconciliation and peer state sync is
  never entered.
- **R12 — Restarts.** The run MUST be able to crash and restart correct identities only in when
  all 4 nodes are correct, on a schedule
  drawn from the fuzz input, so that lazy recovery is exercised. Neither half of the compromised
  identity may be crashed. At most one correct identity may be down at any moment.
- **R13 — Bounded run.** The run MUST be bounded so that throughput stays above the floor in §10.
  The adversarial prefix, the number of blocks required in the suffix, and the storage buffer and
  cache sizes MUST each be a single named constant shared by every run; a value that varies per
  configuration is a defect under P2.
- **R14 — Deterministic execution.** A run MUST be fully determined by its input bytes: the same
  input reproduces the same execution, using the deterministic runtime, SimplexCertMock, and a
  `FuzzRng` instantiated from the input's raw bytes rather than from a seed. No entropy-backed
  randomness, seeds, wall-clock time, or real cryptography.
- **R15 — Deterministic regression suite.** The scenarios the target explores MUST additionally be
  executable as ordinary `#[test]`s in the fuzz crate, driven by fixed inputs instead of libFuzzer
  and checking the same invariants. This suite is the primary regression gate; the fuzz target
  extends it, it does not replace it.
- **R16 — Self-contained.** The feature MUST NOT depend on `commonware-consensus-fuzz`. The twins
  driver and channel-splitting logic are re-derived in `glue/fuzz` from the published crates. The
  corresponding code in `consensus/fuzz` is a reference to model on, not a dependency, and this
  duplication is deliberate.

## 4. Properties

The feature must exhibit the following qualitative guarantees. These are the audit's acceptance
criteria; the checkable predicates are enumerated in §8.

- **P1 — Correct-node symmetry.** Every correct node runs the same application, the same stack, and
  the same configuration. Any divergence among them is therefore attributable to glue and never to
  the harness. A correct node MUST NOT be given a distinguishing knob.
- **P2 — Uniform bounds.** Prefix length, required suffix blocks, timeout, and storage sizing are
  shared constants. No configuration may be granted a relaxed bound to make it pass.
- **P3 — Adversary confinement.** Application-level faults occur only on the secondary half. A
  correct node's application never deviates, so a violation of §8 is never explained by the
  harness having lied on a correct node's behalf.
- **P4 — Contract-bounded adversary.** The faulty application stays within what the `Application`
  trait permits. A run that fails only because the adversary exceeded that contract is not a
  finding; §6 states the boundary and §9 records what is excluded by it.
- **P5 — Determinism and minimization.** Any failure must be reproducible from the crashing input
  and minimizable by the fuzzer, with no cross-run state leakage. The input's byte tape MUST NOT
  be printed in `Debug` output; its length may be.

## 5. Files and interfaces

### 5.1 Feature module — `glue/fuzz/src/stateful/`

The decomposition below is indicative: it records the structure the feature is expected to have
and is not itself a requirement. The target name in §5.2 is normative (R1, R2).

- `mod.rs` — module wiring; re-exports the input type and the entry function.
- `input.rs` — the fuzz input type and its hand-written `Arbitrary`.
- `network.rs` — the per-channel split forwarders and routers that realise the twins partition.
- `stack.rs` — construction of one engine: channels, broadcast, archives, marshal, Stateful, QMDB,
  and the Simplex engine, plus the restart path.
- `app.rs` — the correct application and the faulty application.
- `runner.rs` — the twins driver: scenario selection, engine startup, restart scheduling, and the
  measurement point.
- `invariants.rs` — the checks in §8.

### 5.2 Fuzz target

- `glue/fuzz/fuzz_targets/stateful_cert_mock_twins.rs`
- The corresponding `[[bin]]` entry in `glue/fuzz/Cargo.toml`.
- `glue/fuzz` added to the workspace members and to the fuzz matrix in CI.

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

The adversary is the compromised identity. It is byzantine in two independent layers, and correct
nodes are never adversarial in any layer.

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

## 7. Run structure

Every run MUST proceed as follows.

1. **Setup.** Four identities and their SimplexCertMock schemes are derived from the input tape.
   Five engines are constructed per R11. The compromised identity's channels are split per A1.
2. **Prefix.** The engines run under the selected twins scenario, which prescribes a partition for
   each of a small bounded number of leading rounds. The faulty application is active throughout.
3. **Restarts.** On a schedule drawn from the input tape, correct identities are crashed and
   restarted per R12. A restart retains the node's storage, so the restarted engine reconciles its
   database set against marshal's processed anchor and comes back with an empty pending map,
   forcing lazy recovery on its next proposal or verification.
4. **Suffix.** Past the prefix the scenario prescribes no partition, so the network is whole and
   both halves address every identity.
5. **Measurement point.** The run ends when the required number of blocks has been finalized in
   the suffix, or when the run's bounded timeout expires. Because quorum is three of four, a crash
   during a partition can legitimately stall the run; termination MUST therefore be by timeout and
   MUST NOT be by a liveness wait. The invariants in §8 are then checked over whatever was observed,
   including nothing.

Observations MUST be keyed by engine, not by identity, since the two halves share a key.

## 8. Invariants (must hold at the measurement point)

At the measurement point the following MUST hold across the correct nodes; a violation is a
reportable defect. Both halves of the compromised identity are excluded from I1-I3.

- **I1 — Chain of blocks.** The finalized chains observed at the correct nodes MUST be consistent
  in the sense of the chain-of-blocks method: at most one distinct block per height across all
  correct nodes; each block's recorded parent is the block at the preceding height, rooted at
  genesis; and each node's delivery sequence advances by one height at a time from its starting
  anchor. Delivery is at-least-once and restarts make repeats normal, so an exact repeat of a
  height already delivered MUST be accepted and a differing repeat MUST NOT.
- **I2 — Database-state agreement.** For every height finalized by two or more correct nodes,
  those nodes' committed database state for that height MUST be identical. The observable is the
  per-height database commitment each node reaches once the height is applied, recorded per node
  at the moment it is applied rather than sampled globally, so that nodes progressing at different
  rates are compared at the same height and not at the same instant. This is the invariant the
  feature exists for; I1 holding while I2 fails is the defect class no existing target can see.
- **I3 — Verification-verdict agreement.** No correct node's application may accept a block that
  another correct node's application rejected. R5 makes the correct application deterministic and
  P1 makes every correct node run it identically, so a violation is attributable to Stateful
  presenting different inputs to the same deterministic function.
- **I4 — No panic.** No engine may panic. Because A3 keeps the faulty application inside the
  trait's contract, every documented panic in Stateful is unreachable in a correct implementation,
  and there is no allowlist: any panic, on any engine, correct or compromised, is a finding.
- **I5 — Source tree untouched.** `git status` over `glue/src` and `consensus/src` MUST stay clean
  across the entire feature (R10).
- **I6 — Reproducibility.** A failing input replayed MUST fail identically. A failure that does not
  reproduce is itself a defect, in the harness rather than in glue.

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
- **Modifying `glue/src` or `consensus/src`.** Excluded by R10.

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

   As a negative control, an auditor plants a defect — for example, makes one correct node's
   application write a different value for one block — and confirms the suite fails under I2 while
   I1 still passes, demonstrating that the database-state check carries signal that the chain check
   does not. `invariants.rs` MUST NOT be changed for this control: the defect goes into the state,
   not into the check.

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

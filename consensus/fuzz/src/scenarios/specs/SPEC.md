# Scenario-Based Marshal Fuzzing — Specification

This document is the technical contract for the
scenario-based marshal fuzzing feature, written for auditing and independent
verification. It states *what* the feature must do and *which properties and
invariants must hold*; it deliberately omits *how* the code achieves them.

## 1. Purpose
The marshal component provides ordered delivery of finalized blocks
by Simplex-layer to the application. It is defined in `consensus/src/marshal/mod.rs`. 
The marshal standard tests in `consensus/src/marshal/standard/mod.rs` drive the
marshal into a set of interesting semantic states (missing candidate, pending
backfill, divergent same-height certificates, pending floor anchor, view-pruning
edges, and so on). Those tests assert per-scenario behaviour under real BLS
crypto and cannot be reused for fuzzing directly.

This feature reproduces the *prefix* of each such scenario as a deterministic
script over a fast mock certificate scheme called `SimplexCertificateMock`,
stops at the interesting semantic state,
then starts the consensus engines from that state and fuzzes forward under
honest or adversarial pressure — checking marshal-layer safety and liveness from
the reproduced state. It exists to extend fuzz coverage into marshal states that
random input alone reaches rarely or never.

## 2. Goals

- **G1.** Move the system under test into a chosen interesting marshal state,
  defined by the developers in the existed tests then fuzz forward from that state.
- **G2.** Cover both Standard marshal variants — `Deferred` and `Inline` — with
  the same scenarios, adversary, and invariants.
- **G3.** Detect marshal-layer safety and liveness violations reachable from the
  reproduced states, under both an honest harness and a byzantine one.
- **G4.** Keep every scenario traceable to the `consensus/src` standard test it
  derives from, so an auditor can map fuzz coverage back to intended behaviour.
- **G5.** Achieve all of the above without modifying `consensus/src`.

## 3. Technical requirements

- **R1 — Two fuzz targets.** The feature MUST expose two libFuzzer targets, one
  per Standard variant: `marshal_scenario_standard_deferred_cert_mock` and
  `marshal_scenario_standard_inline_cert_mock`.
- **R2 — Shared logic.** Both targets MUST exercise the same setup, scenario
  prefixes, adversary, and invariants; the variant is the only difference between
  them and is fixed per target (never a fuzzed input field).
- **R3 — Deterministic execution.** A run MUST be fully determined by its input
  bytes: the same input reproduces the same execution, using the deterministic
  runtime in `runtime/src/deterministic.rs`, the mock certificate scheme, and a seeded `FuzzRng`.
  No entropy-backed randomness, wall-clock time, or real cryptography.
- **R4 — Three phases per run.** Every run MUST proceed as: (1) *setup* of a
  four-validator cluster with no engines running; (2) *prefix*, a scripted,
  engine-free program that drives the marshal mailboxes into the selected state;
  (3) *fuzzing*, in which the engines start from the reproduced state and run to a
  measurement point.
- **R5 — Input surface.** The fuzz input MUST select, at minimum: the scenario,
  the fuzzing mode (honest or adversarial), the adversary's per-layer faults, the
  network topology (partition / degradation), a forwarding policy, and a target
  run depth. Unstructured trailing bytes MUST feed the deterministic RNG.
- **R6 — Mode coverage.** The feature MUST support an honest mode (`N4F0C4`,
  four honest engines) and an adversarial mode (`N4F1C3`, node 0
  byzantine, nodes 1–3 honest).
- **R7 — Source traceability.** Each scenario MUST correspond to a named
  `consensus/src` standard test and reproduce that test's interesting *state*.
  Where the exact mechanic is not reachable through the scripting surface, the
  scenario MUST reproduce the closest sound state and MUST document the divergence
  at its definition.
- **R8 — Non-modification.** The feature MUST NOT change anything under
  `consensus/src`. All code lives in the fuzz crate.
- **R9 — Exclusion of unreproducible sources.** A standard test whose
  interesting state cannot be *soundly* reproduced through the scripting
  surface (per the eligibility criteria in §7) MUST be excluded from the
  scenario set rather than approximated, and each exclusion MUST be documented
  alongside the scenario definitions together with the constraint that forces
  it. R7's closest-sound-state fallback applies only when a sound close state
  exists.

## 4. Properties

The feature must exhibit the following qualitative guarantees. These are the
audit's acceptance criteria; the checkable predicates are enumerated in §8.

- **P1 — Composition soundness.** The reproduced prefix state must be one the real
  protocol could actually reach, so that any invariant failure during fuzzing is a
  genuine defect and never an artefact of an impossible starting state.
- **P2 — Variant symmetry.** For a given input, the Deferred and Inline targets
  run the same scenario and are held to the same invariants; neither variant may
  require relaxing an invariant that the other satisfies.
- **P3 — Adversary realism.** Byzantine behaviour must be protocol-plausible:
  messages emitted by the byzantine node must be validly signed and must not rely
  on signature-breaking byte corruption of honest traffic. No forged quorum
  certificate may be manufactured into an acceptable-and-finalizable state.
- **P4 — Honest liveness under recovery.** After adversarial or partition pressure
  is removed, the honest nodes must resume making progress.
- **P5 — Determinism and minimization.** Any failure must be reproducible from the
  crashing input and minimizable by the fuzzer, with no cross-run state leakage.

## 5. Files and interfaces

### 5.1 Feature module — `consensus/fuzz/src/scenarios/`

- `mod.rs` — module wiring; re-exports the input type and the two entry functions.
- `input.rs` — the fuzz input type and its `Arbitrary`-derived enums (scenario,
  mode, per-layer fault plan, topology, forwarding, run depth).
- `environment.rs` — the scenario scripting surface: the four-node addressing
  (`Node{A,B,C,D}`), the verbs a prefix uses to build state, and the
  handoff type describing the reproduced floor and the invariant-selection hint.
- `scenarios.rs` — the `Scenario` trait, the dispatch from input to scenario, and
  one implementation per scenario (each annotated with its source test).
- `runner.rs` — the three-phase driver, generic over the marshal variant, plus the
  two thin per-variant entry functions.
- `adversary.rs` — construction of the byzantine node's disrupters.
- `elector.rs` — the leader schedule that pins node 0 as the attack-view leader.
- `strategy.rs` — the live-view-scoped mutation strategy wrapper.

### 5.2 Fuzz targets

- `consensus/fuzz/fuzz_targets/marshal_scenario_standard_deferred_cert_mock.rs`
- `consensus/fuzz/fuzz_targets/marshal_scenario_standard_inline_cert_mock.rs`
- Their `[[bin]]` entries in `consensus/fuzz/Cargo.toml`.

### 5.3 Consumed dependencies (pre-existing; named, not defined here)

- The marshal-layer invariants in
  `consensus/fuzz/src/marshal/end_to_end/invariants.rs` (block agreement, local /
  all-block delivery, parent linkage).
- The twins marshal stack and the from-floor engine entry point in
  `consensus/fuzz/src/marshal/end_to_end/twins/stack.rs`, including the
  variant-selection abstraction over the `Deferred` / `Inline` marshals.
- The always-accept block-builder application and its delivery reporter in
  `consensus/fuzz/src/marshal/end_to_end/app.rs`.
- The mock certificate scheme and the standard-marshal harness constants
  (block-per-epoch bound) from `consensus/src/marshal/mocks`.

Any change to a consumed interface that alters its contract is a change to this
feature's dependencies and must be re-audited against this document.

## 6. Adversary model (normative)

The adversarial config (`N4F1C3`) MUST place the byzantine node at index 0
with **no marshal**, freeing the marshal channels for the adversary. The five
engine channels are: backfill (1), block dissemination (2), vote (3), certificate
(4), resolver (5). The byzantine node MUST run the dissemination-layer
disrupter (A2). The Simplex-layer disrupter (A1) is selected by the fuzz
input; when it is not selected, the byzantine node's consensus channels stay
silent (crash-silence), an admissible byzantine behavior:

- **A1 — Simplex-layer disrupter on channels 3/4/5 (input-selected).** A `LiveScope`-wrapped
  `SmallScope` strategy driving the real `Disrupter`. It MUST perform *semantic*
  mutations only (shifting proposal view/parent or tweaking payload, then
  re-signing so emitted messages are validly signed); it MUST NOT emit
  signature-breaking byte corruption. Its faulty views MUST be scheduled strictly
  **above** the attack view (the live window), and its fault density is derived
  from the run's fault parameters.
- **A2 — Dissemination-layer disrupter on channels 1/2.** As the attack-view
  leader, the byzantine node MUST be able to disseminate a faulty block with a
  matching signed notarize, choosing one block-dissemination fault of
  {`Omit`, `Partition`, `Equivocate`} on channel 2, and one backfill fault of
  {`Withhold`, `ServeError`, `Poison`} on channel 1. `Poison` MUST be a
  well-formed quorum notarization over an unavailable payload paired with a
  mismatched block: it verifies as a certificate but fails the commitment check
  and is never finalizable.
- **A3 — Non-shadowing coexistence.** When both disrupters run, they MUST NOT
  shadow each other: the dissemination leader announce is *at* the attack view while the
  Simplex-layer faults are *above* it, so their emissions occupy disjoint views.

## 7. Scenarios (normative shape)

Scenarios reproduce marshal states extracted from the standard tests. The spec
constrains their *shape*, not their count or individual construction:

- **S1 — Themed coverage.** The scenario set MUST cover four themes:
  (a) adversarial / equivocation states; (b) recovery / gap-repair states;
  (c) floor-handling states; (d) certify / verify edge states.
- **S2 — Source mapping.** Each scenario MUST derive from, and be annotated with,
  a specific `consensus/src/marshal/mod.rs` standard test (per R7).
- **S3 — State only.** A scenario MUST build only the interesting *prefix state*.
  It MUST NOT re-assert the per-scenario behavioural oracle — that assertion lives
  in the corresponding `consensus/src/marshal/mod.rs` unit test (see §9, out of scope).
- **S4 — Universality.** A scenario MUST run under both variants and both modes
  unless a documented soundness constraint prevents it; scenarios are selected by
  fuzz input, not fixed per target.
- **S5 — Honest reproduction.** Scenario prefixes script only the honest core
  {B, C, D}; node A (index 0) is reserved for the adversary, so the same prefix is
  valid in both modes.
- **S6 — Eligibility.** A standard test can be used as a scenario source only
  if its interesting state passes all four checks:
  (a) *scriptable* — the prefix can build the state with mailbox verbs alone.
  No consensus engine, no wrapper verify/certify call, no marshal restart, and
  no writing to storage before startup.
  (b) *honest-plausible* — the honest signers could really have produced every
  fabricated certificate. One leader per round, no two certificates for
  different blocks at the same height, and no certificate that contradicts the
  rest of the fabricated history.
  (c) *floor-compatible* — the whole state fits at or below the floor the
  engines start from (I1) and still makes sense there.
  (d) *durable* — the state is still there when the fuzzing phase starts. A
  race or timing window the prefix cannot hold open does not count.
- **S7 — Exclusion over approximation.** If a test fails any S6 check, it MUST
  NOT be forced in: do not fabricate an impossible artifact, and do not swap in
  a leftover state that duplicates another scenario or is already trivially
  covered. Exclude the test under R9 instead. The R7 fallback allows a
  different *mechanism*, never an unsound *state*.

## 8. Invariants (must hold at the measurement point)

A run reaches a measurement point after the fuzzing phase heals the network. At
that point the following MUST hold for every honest node; a violation is a
reportable defect.

- **I1 — Composition soundness (construction-time).** Every certificate the prefix
  fabricates sits at a view no greater than the floor the engines start from. The
  engines therefore begin strictly above every fabricated certificate, so a
  fabricated certificate can never conflict with an engine-produced one.
- **I2 — Block agreement.** No two honest nodes deliver different blocks at the
  same height. This is *block* agreement — a safety property independent of any
  certification verdict — and it MUST hold identically for both variants.
- **I3 — Parent linkage.** Every delivered block links to the previously delivered
  block; the delivered chain is internally consistent.
- **I4 — In-order delivery.** A genesis-started node delivers heights contiguously
  from genesis; a node whose marshal floor was advanced in the prefix delivers
  contiguously from that floor. No gaps, no reordering.
- **I5 — Recovery liveness.** Liveness is measured only *after* the network heals
  unconditionally. Every honest node that still has epoch headroom MUST make fresh
  forward progress within the recovery window; a node that has already completed
  the epoch's maximal work is excluded from the measurement rather than passed
  vacuously. If no node remains measurable, the run is healthy-but-unmeasurable and
  only safety is checked.
- **I6 — Bounded pre-heal loss.** Finite message loss before the heal is
  admissible; after the heal, honest nodes must not silently drop honest traffic.
- **I7 — Source tree untouched.** `git status consensus/src` MUST stay clean across
  the entire feature.

## 9. Out of scope

- **Per-scenario behavioural oracles.** The fuzzer does not re-check the specific
  behaviour each scenario is named for (e.g. "the certified copy survives view
  pruning"); those assertions remain in the `consensus/src/marshal/mod.rs` unit tests. The fuzzer
  checks only the §8 invariants and liveness, and does not use unit tests' oracles.
- **Certification-verdict agreement.** The separate certify-*verdict* agreement
  invariant used by the end-to-end twins targets is not used here (it is
  structurally trivial for Inline). Only block agreement (I2) applies.
- **Modifying `consensus/src`.** No production code, test, or harness under
  `consensus/src` is in scope for change.
- **Marshal variants other than Standard `Deferred` / `Inline`.** The coding
  variant and any non-standard marshal are excluded.
- **Real cryptography and non-deterministic runtimes.** Excluded by R3.
- **Selecting the marshal variant via fuzz input.** The variant is fixed per
  target, never fuzzed.

## 10. End-to-end verification

The following sequence proves the feature works. Each step names the observable
outcome an auditor should confirm.

1. **Source tree is untouched.**
   `git status --porcelain consensus/src` prints nothing (I7).

2. **Both targets and the runner compile.**
   `cargo check -p commonware-consensus-fuzz --features mocks --tests` succeeds,
   proving both entry functions and the variant-generic driver type-check (R1, R2).

3. **Scenario suite passes for both variants and both modes.**
   `cargo nextest run -p commonware-consensus-fuzz --features mocks scenarios::`
   runs every scenario under {honest, adversarial} × {deferred, inline} and reports
   all tests passing. This exercises I1–I6 from every reproduced state and confirms
   variant symmetry (P2): the adversarial Inline runs do not false-positive on block
   agreement (I2).

4. **Lint is clean.**
   `cargo clippy -p commonware-consensus-fuzz --features mocks --tests` reports no
   warnings.

5. **Both fuzz targets build and run.**
   `cargo +nightly fuzz build --fuzz-dir consensus/fuzz
   marshal_scenario_standard_deferred_cert_mock` (and the `inline` target) build,
   then a short `-max_total_time=8` smoke run of each completes with no crash, hang,
   or out-of-memory. Feature-coverage growth over the run confirms the scenarios
   open distinct paths (G1, G3). The adversarial Inline smoke in particular must not
   surface a block-agreement false positive (P2).

6. **A planted defect is caught.** As a negative control, an auditor may weaken one
   §8 invariant target (for example, corrupt an honest node's delivered chain) and
   confirm the scenario suite fails, demonstrating the invariants are load-bearing
   rather than vacuous.

Passing steps 1–5, plus the negative control in step 6, constitutes acceptance of
this specification.

# Scenario-Based Marshal Fuzzing — Specification

This document is the technical contract for the
scenario-based marshal fuzzing feature, written for auditing and independent
verification. It states *what* the feature must do and *which properties and
invariants must hold*; it deliberately omits *how* the code achieves them.

## Definitions

Used throughout this document with exactly these meanings.

- **Source test** — a test in `consensus/src/marshal/standard/mod.rs`. Ground
  truth. Asserts its own behaviour under real BLS crypto, checks none of the
  invariants in §8, and is never modified by this feature.
- **Scenario** — the reproduction of one source test's state-producing prefix,
  written in the fuzz crate in `consensus/fuzz/src/scenarios/`. Every requirement in this document applies to
  scenarios, never to source tests.
- **Prefix** — the scripted, engine-free part of a scenario: the operations that
  build the state, ending at handoff.
- **Defining state** — the state that gives the source test its purpose,
  including any operation the source test left in flight.
- **Handoff** — the moment the prefix ends and the consensus engines start.
- **Scenario API** — the state-building primitives a prefix calls.
- **Measurement point** — the point in the fuzzing phase, after the network
  heals, at which the invariants in §8 are checked.
- **Variant** — Standard `Deferred` or Standard `Inline`, fixed per fuzz target.
- **Mode** — honest (`N4F0C4`) or adversarial (`N4F1C3`).
- **Configuration** — one scenario in one variant in one mode.

The invariants in `consensus/fuzz/src/marshal/end_to_end/invariants.rs` belong
to the fuzz crate and are checked only on scenario runs. Source tests neither
use them nor are held to them.

## 1. Purpose
The marshal component provides at-least-once ordered delivery of finalized blocks
by Simplex-layer to the application. It is defined in `consensus/src/marshal/mod.rs`. 
The marshal standard tests under `consensus/src/marshal/standard/mod.rs` drive the marshal into
a set of interesting semantic states (missing candidate, pending backfill,
divergent same-height certificates, pending floor anchor, view-pruning edges,
and so on). Those tests are authoritative ground truth and currently assert
per-test behaviour under real BLS crypto.

This feature reproduces the *prefix* of each such source test as a deterministic
script over a fast mock certificate scheme called `SimplexCertificateMock`,
stops at the interesting semantic state,
then starts the consensus engines from that state and fuzzes forward under
honest or adversarial pressure — checking marshal-layer safety and liveness from
the reproduced state. It exists to extend fuzz coverage into marshal states that
random input alone reaches rarely or never.

## 2. Goals

- **G1.** Move the system under test into a specified interesting marshal state,
  defined by the developers in the existing unit tests in `consensus/src/marshal/standard/mod.rs`,
  then fuzz forward from that state.
- **G2.** Cover both Standard marshal variants — `Deferred` and `Inline` — with
  the same harnesses, byzantine configurations, and invariants, running each source scenario under
  every compatible variant.
- **G3.** Detect marshal-layer safety and liveness violations reachable from the
  reproduced states, under both an honest harness and a byzantine one.
- **G4.** Keep every scenario traceable to the `consensus/src/marshal/standard/mod.rs` standard test it
  derives from, so an auditor can map fuzz coverage back to intended behaviour.
- **G5.** Achieve all of the above without modifying `consensus/src`.

## 3. Technical requirements

- **R1 — Implement two fuzz targets.** The feature MUST expose two libFuzzer targets, one
  per Standard variant: `marshal_scenario_standard_deferred_cert_mock` and
  `marshal_scenario_standard_inline_cert_mock`.
- **R2 — Shared logic.** Both targets MUST exercise the same setup, scenario
  framework, adversary, and invariants; the variant is fixed per target (never a
  fuzzed input field). A source scenario runs in every variant compatible with its
  defining state, as specified in §7.
- **R3 — Deterministic execution.** A run MUST be fully determined by its input
  bytes: the same input reproduces the same execution, using the deterministic
  runtime from `runtime/src/deterministic.rs`, the mock certificate scheme, and a `FuzzRng`
  instantiated via fuzz input's `raw_bytes`, but not from a seed.
  No entropy-backed randomness, seeds, wall-clock time, or real cryptography.
- **R4 — Three phases per fuzz run.** Every run MUST proceed as: (1) *setup* of a
  four-validator cluster with no engines running; (2) *prefix*, a scripted,
  engine-free instructions that drive the marshal mailboxes, and any
  engine-recovery state the scenario requires, into the selected state;
  (3) *fuzzing*, in which the engines start from the reproduced state and run to a
  measurement point.
- **R5 — Input surface.** The fuzz input MUST select, at minimum: the scenario, raw bytes to instantiate `FuzzRng`,
  the fuzzing mode (honest or adversarial), the adversary's per-layer faults, the
  network topology (partition / degradation), a forwarding policy, and a target
  run depth.
- **R6 — Mode coverage.** The feature MUST support an honest mode (`N4F0C4`,
  four honest engines) and an adversarial mode (`N4F1C3`, node 0
  byzantine, nodes 1–3 honest). These configurations are defined in `consensus/fuzz/src/lib.rs`
- **R7 — Source fidelity.** Each scenario MUST name an authoritative test under
  `consensus/src/marshal/standard/mod.rs` and obey the reuse-or-copy requirements in §7.
  It MUST reproduce the source test's defining state at handoff. A state that is
  close but not the same does not satisfy this requirement; where the exact state
  cannot be built, the configuration is excluded under R9.
- **R8 — Non-modification.** The feature MUST NOT change anything under
  `consensus/src`. All code lives in the fuzz crate.
- **R9 — Exclusion of unreproducible source tests.** If a source test's defining state
  cannot be built and retained through handoff with the available scripting
  surface in a target configuration, it MUST be excluded from that configuration
  rather than approximated. Every exclusion MUST identify the unavailable
  capability. Inability to import the source code is not grounds for exclusion
  when a faithful copy is scriptable.
- **R10 — Deterministic scenario suite.** Every scenario, in every compatible
  variant and mode, MUST additionally be executable as an ordinary `#[test]` in the fuzz crate,
  driven by a fixed input instead of libFuzzer, checking the same invariants as a fuzz run.
  This suite is the primary regression gate; the fuzz targets extend it, they do
  not replace it.

## 4. Properties

The feature must exhibit the following qualitative guarantees. These are the
audit's acceptance criteria; the checkable predicates are enumerated in §8.

- **P1 — Source-faithful composition.** The source test's construction is
  authoritative. The reproduced prefix MUST preserve its defining state without
  adding, removing, or changing source artifacts or introducing a new
  inconsistency at engine handoff.
- **P2 — Variant symmetry.** For a scenario compatible with both variants, the
  Deferred and Inline targets run the same prefix and are held to the same
  invariants; neither variant may require relaxing an invariant that the other
  satisfies.
- **P3 — Adversary realism.** The byzantine node's behaviour is that of the
  pre-existing fuzz components named in §6; this specification does not
  define it. Any configuration of those components MUST stay within what they
  already guarantee. A run that fails only because the adversary exceeded that
  model is not a finding.
- **P4 — Honest liveness under recovery.** After adversarial or partition pressure
  is removed, the honest nodes must resume making progress.
- **P5 — Determinism and minimization.** Any failure must be reproducible from the
  crashing input and minimizable by the fuzzer, with no cross-run state leakage.

## 5. Files and interfaces

### 5.1 Feature module — `consensus/fuzz/src/scenarios/`
The decomposition below is indicative: it records the structure the feature is
expected to have and is not itself a requirement. The target names in §5.2 are
normative (R1).

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
- `adversary.rs` — construction of the byzantine nodes.
- `elector.rs` — the leader schedule that pins node 0 as the attack-view leader.
- `strategy.rs` — the live-view-scoped mutation strategy wrapper.

### 5.2 Fuzz targets

- `consensus/fuzz/fuzz_targets/marshal_scenario_standard_deferred_cert_mock.rs`
- `consensus/fuzz/fuzz_targets/marshal_scenario_standard_inline_cert_mock.rs`
- The corresponding `[[bin]]` entries in `consensus/fuzz/Cargo.toml`.

### 5.3 Consumed dependencies (pre-existing; named, not defined here)
The existing fuzzing infrastructure must be reused as much as possible.
- The marshal-layer invariants in
  `consensus/fuzz/src/marshal/end_to_end/invariants.rs` are ground truth.
- The twins marshal stack and the from-floor engine entry point in
  `consensus/fuzz/src/marshal/end_to_end/twins/stack.rs`, including the
  variant-selection abstraction over the `Deferred` / `Inline` marshals.
- The always-accept block-builder application and its delivery reporter in
  `consensus/fuzz/src/marshal/end_to_end/app.rs`.
- The mock certificate scheme and the standard-marshal harness constants
  (block-per-epoch bound) from `consensus/src/marshal/mocks`.
- The recording resolver and recording buffer used for scripted deliveries,
  exact fetch observation, and subscription observation.
- All `invariants.rs` files are ground-truth and must not be changed

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
  and is never finalizable. `Poison` relies on `SimplexCertificateMock` permitting a single node to
  construct a quorum notarization. This is a load-bearing property of the mock:
  if the scheme is replaced by one requiring genuine quorum participation,
  `Poison` becomes unconstructible and MUST be reported as an unavailable
  capability under R9 rather than silently omitted.
- **A3 — Non-shadowing coexistence.** When both disrupters run, they MUST NOT
  shadow each other: the dissemination leader announce is *at* the attack view while the
  Simplex-layer faults are *above* it, so their emissions occupy disjoint views.

## 7. Scenarios

This section states how a scenario reproduces its source test.

- **S0 — Single enumeration site.** All scenarios MUST be enumerated in one
  place, so that the enumeration checked in §10.2 is complete by construction.
- **S1 — Reuse first.** Each scenario MUST name its source test.
  For example, for a source test `test_standard_certify_missing_candidate_fetches_by_round`,
  the corresponding scenario name is `StandardCertifyMissingCandidateFetchesByRound`.
  Where existing visibility and generic bounds permit, the source test or its shared
  state-building helpers MUST be imported and instantiated with
  `SimplexCertificateMock`. This reuse requirement does not authorize changes
  under `consensus/src`. If it is not possible to import state-building helpers,
  then they may be copied and adapted to `SimplexCertificateMock` and fuzz infrastructure.
- **S2 — Faithful copy.** If direct reuse is not possible, the source test's
  state-producing prefix MUST be copied into the fuzz crate and reproduced without
  defects. Only the cryptographic backend and necessary harness plumbing may
  differ; state-producing operations, their ordering, source roles, certificates,
  and the resulting per-node handoff state MUST preserve the source semantics. A
  copied scenario MUST NOT substitute an approximate, generic, or merely similar
  state. The copy MUST be syntactically similar to the source test (see S6).
- **S3 — Verified handoff.** The prefix MUST complete before the consensus engines
  start, and the defining state MUST remain present at handoff. Construction-time
  assertions MUST demonstrate that the handoff state corresponds to the source
  test; source traceability by name or comment alone is insufficient.
  A handoff assertion MUST read the same state the source operation reads. An
  assertion that could pass while the state the source asserts is absent — because
  it queries a different index, or is answered from a cache — does not discharge
  this clause.
- **S4 — Oracle boundary.** A scenario stops at the source test's interesting
  handoff state. It need not repeat the source test's post-handoff behavioural
  assertions, which remain in the source tests.
- **S5 — Compatibility and exclusion.** A scenario MUST run under every wrapper
  variant and mode compatible with its defining state. If that state or a defining
  pending operation cannot be built and retained with the available scripting
  surface, the source test MUST be excluded from the incompatible configuration under
  R9, with the precise missing capability documented. It MUST NOT be replaced by
  a different state.
- **S6 — Syntactic correspondence.** A copied prefix MUST be written so that its
  correspondence to the source test is verifiable by inspection, not only by
  reasoning about semantics. The scenario API MUST provide primitives whose
  names, argument order, and semantics mirror those the source test uses, so
  that the copied prefix reads as the source test with the cryptographic backend
  substituted. Permitted divergences are limited to: the certificate scheme,
  node addressing, and harness plumbing required by the fuzz crate. A primitive
  that cannot be made semantically equivalent to its source counterpart MUST be
  given a different name — a same-named primitive with differing semantics is a
  defect under this clause, not a permitted divergence. Where a scenario mixes
  reuse (S1) and copy (S2), name collisions MUST be resolved by module path,
  never by shadowing. S6 governs the form of a copy that S2 permits; it is never
  itself grounds for exclusion under R9. Where the source drives its prefix
  through machinery that R4 excludes, the copy MUST mirror the source's
  operations and their ordering, and the departure from the source's calling
  surface MUST be documented at the scenario. Each scenario MUST carry a
  machine-readable reference to its source, precise enough to diff against:
  `/// Source: <path>::<test fn name>`.
- **S7 — Incidental construction.** A source test's construction contains choices
  that do not bear on what the test establishes: an arbitrary parent for its
  first block, a leader identity no assertion depends on, a timestamp. Where the
  fuzz crate's ground truth constrains such a choice — a delivered chain must be
  rooted at the cluster genesis, a leader must be a cluster participant — the
  scenario MUST adopt the constrained value and document the departure at the
  scenario. This is not a substitution of state. The test for substitution is
  whether any assertion the source makes, or any property its state exhibits,
  would change; if none would, the choice was incidental.

## 8. Invariants (must hold at the measurement point)

At the measurement point the following MUST hold for every honest node; a violation is a reportable defect.

- **I1 — Marshal-layer invariants.** Every invariant defined in
  `consensus/fuzz/src/marshal/end_to_end/invariants.rs` MUST hold at the
  measurement point, for every honest node, in both variants and both modes.
  The file is ground truth: this specification does not restate its contents,
  and an invariant added to it later applies to this feature without amendment
  here. A scenario MUST NOT disable, weaken, or narrow the scope of an
  invariant; a scenario that cannot satisfy one is a reportable defect or an
  R9 exclusion, never a reason to relax it. Exclusions, if any,
  MUST be listed in §9 with a reason; no exclusion may be
  introduced in code.
- **I2 — Recovery liveness.** Liveness is measured only *after* the network heals
  unconditionally. Every honest node that still has epoch headroom MUST make fresh
  forward progress within the recovery window; a node that has already completed
  the epoch's maximal work is excluded from the measurement rather than passed
  vacuously. The recovery window and the epoch-headroom bound MUST each be a single named
  constant shared by all scenarios, variants, and modes; a per-scenario or
  per-variant value is a defect under P2.
  If no node remains measurable, the run is healthy-but-unmeasurable and
  only safety is checked.
- **I3 — Bounded pre-heal loss.** Finite message loss before the heal is
  admissible; after the heal, honest nodes must not silently drop honest traffic.
  The heal restores every link losslessly, so a post-heal network drop is
  impossible by construction; the residual silent-drop mode, an honest node
  blocklisting an honest peer, MUST be directly observed at the measurement point
  and MUST be empty (pairs touching the byzantine node are exempt, since
  blocklisting a poison-serving adversary is correct).
- **I4 — Source tree untouched.** `git status consensus/src` MUST stay clean across
  the entire feature.
- **I5 — Composition soundness (construction-time).** No artifact the prefix
  fabricates may participate in a conflict that the engines could also produce.
  A violation of any invariant under I1 MUST therefore be attributable to
  marshal behaviour and never to the prefix's construction. A scenario MUST
  demonstrate this attribution at construction time (S3); where the defining
  state cannot be composed so that it holds, the configuration is excluded
  under R9.

## 9. Out of scope

- **Per-test behavioural oracles.** The fuzzer does not re-check the specific
  post-handoff behaviour each scenario is named for (e.g. "the certified copy
  survives view pruning"); those assertions remain in the source tests.
  Construction-time assertions proving that the handoff state faithfully matches
  the source are required by S3 and are not behavioural oracles.
- **Certification-verdict agreement.** The separate certify-*verdict* agreement
  invariant used by the end-to-end twins targets is not used here (it is
  structurally trivial for Inline).
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
   `git status --porcelain consensus/src` prints nothing (I4).

2. **Source fidelity is demonstrated.**
   Every retained scenario names its authoritative source and has a
   construction-time handoff assertion. Existing mock-compatible source logic is
   instantiated with `SimplexCertificateMock`; otherwise an audit confirms that
   the copied prefix preserves the source construction through handoff. Every
   exclusion identifies the unavailable scripting capability (R7, R9, S1-S6).
   For every copied scenario, the prefix and its `/// Source:` test are placed
   side by side; the textual difference is confined to the certificate scheme,
   addressing, and plumbing. No identifier shared by name between the scenario API
   and the source harness differs in semantics.
   `rg '^/// Source:' consensus/fuzz/src/scenarios/scenarios.rs` lists exactly
   the retained scenarios, and every named test exists in the referenced file.


3. **Both targets and the runner compile.**
   `cargo check -p commonware-consensus-fuzz --features mocks --tests` succeeds,
   proving both entry functions and the variant-generic driver type-check (R1, R2).

4. **Scenario suite passes for all compatible variants and modes.**
   `cargo nextest run -p commonware-consensus-fuzz --features mocks scenarios::`
   runs every compatible scenario/configuration combination and reports all tests
   passing. This exercises I1-I3 and I5 from every reproduced state and confirms variant
   symmetry (P2): the adversarial Inline runs do not report a false block-agreement
   violation.

5. **Lint is clean.**
   `cargo clippy -p commonware-consensus-fuzz --features mocks --tests` reports no
   warnings.

6. **Both fuzz targets build and run.**
   `cargo +nightly fuzz build --fuzz-dir consensus/fuzz
   marshal_scenario_standard_deferred_cert_mock` (and the `inline` target) build,
   then a short `-max_total_time=8` smoke run of each completes with no crash, hang,
   or out-of-memory. Feature coverage grows over the run (G1, G3). The
   adversarial Inline smoke in particular must not surface a block-agreement
   false positive (P2).

7. **The checks are not vacuous.** A test can pass because nothing was wrong, or
   because nothing was checked. This step rules out the second case.

   For each configuration, the suite reports how many nodes were checked and how
   many blocks were delivered at the measurement point. Both counts MUST be
   above zero. A configuration that was skipped MUST be reported as skipped, with
   its reason, and never counted as passing.

   As a negative control, an auditor plants a defect — for example, corrupts the
   chain one honest node delivered — and confirms that the suite fails.
   `invariants.rs` MUST NOT be changed for this control: the defect goes into the
   state, not into the check.

Passing steps 1–6, plus the negative control in step 7, constitutes acceptance of
this specification.

## 11. Reference translation of a source test into scenario

The rules in this section are normative. The components and mechanisms it names
describe the reference implementation and may change without amending this
document. `StandardCertifyMissingCandidateFetchesByRound` in
`consensus/fuzz/src/scenarios/scenarios.rs` is the reference translation and the
template for new scenarios.

- **Mapping.** Declare one source-participant-to-scenario-node permutation and
  apply it uniformly to actors, providers, leaders, signers, resolver targets,
  and block holders. A source identity MUST NOT be split across nodes.
- **DSL and order.** Mirror the source operations with semantically equivalent
  DSL primitives, preserving arguments and execution order. Harness-only
  divergences MUST be explicit; different semantics require a different name.
- **State reproduction.** Drive the real wrapper and marshal through
  `FuzzScenarioStandardHarness`; use `RecordingResolver` for scripted deliveries
  and exact fetch observation, and `RecordingBuffer` for subscription and
  broadcast observation. In the reference scenario, write each recovered
  notarization from `ScenarioHandoff::engine_journal` as an
  `Artifact::Notarization` into every honest engine's voter journal before
  `Engine::new`; startup replay installs the recovered proposal and re-drives its
  certification before the live loop, so the engine never re-enters that view.
  Journal recovery is how I5 is satisfied for a state inside the live window: an
  artifact the engine has recovered is one the engine will not contradict. A
  scenario using this route MUST show at construction time that no engine can
  produce a certificate conflicting with a fabricated one. The voter
  journal recovery surface consists of `Artifact::Notarize`,
  `Artifact::Notarization`, `Artifact::Certification`, `Artifact::Nullify`,
  `Artifact::Nullification`, `Artifact::Finalize`, and
  `Artifact::Finalization`. A translation MUST reproduce the source's exact
  variants and append order: local-vote artifacts belong only to their signer's
  journal, `Artifact::Certification` belongs only to the originating engine's
  journal, and certificate artifacts may be replayed on every honest engine.
  Build fabricated certificates through ledger-recording DSL primitives. Journal
  artifacts MUST be recorded in the same ledger, so that the I5 construction-time
  check covers them. A journal artifact that does not correspond to state the
  source test's node had recovered is a fabrication the source does not license,
  and is a defect under S2 regardless of whether any invariant fires. Use only
  the mechanisms required by the source state.
- **Handoff.** Stop at the same semantic point and mechanically assert the exact
  per-node blocks, certificates, fetches, subscriptions, and recovered state.
- **Composition.** Floors, journal artifacts, leaders/elector, and the attack
  anchor MUST form one conflict-free chain and remain valid in every compatible
  wrapper variant and fault mode; otherwise apply R9.
- **Assertion boundary.** Assertions that construct or verify `ScenarioHandoff`
  before engine startup are required S3 checks, including source assertions that
  define that state.
  After engine startup, scenarios MUST add no source-specific behavioural
  oracle; only the shared §8 checks apply.

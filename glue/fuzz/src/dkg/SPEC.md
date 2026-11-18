# Glue DKG Fuzzing: Specification

This document is the technical specification for the glue DKG fuzzing feature. It states *what*
the feature must do and *which properties and invariants must hold*; it deliberately omits *how*
the code achieves them.

## Definitions

Used throughout this document with exactly these meanings.

- **DKG module**: the code under `glue/src/dkg`: `bootstrap` (a one-shot DKG on its own Simplex
  chain), `reshare` (the per-epoch resharing actor and its application wrapper), `orchestrator`
  (one Simplex engine per epoch), `probe` (boundary discovery for joiners), and `state_sync`.
- **Ceremony**: one run of the Feldman-Desmedt protocol from
  `commonware_cryptography::bls12381::dkg::feldman_desmedt`: the single one-shot DKG of a
  bootstrap run, or the reshare of one epoch.
- **Dealer, player**: the roles of a ceremony. In a reshare the dealers are the players of the
  previous output.
- **Output**: the public result of a successful ceremony: the public sharing, the dealer and
  player sets, and the revealed set.
- **Share**: one player's private share of an output.
- **`required()`**: the number of shares needed to reconstruct the key of an output,
  `Sharing::required()`. It is 3 for a committee of 4.
- **EpochInfo**: the value the final block of an epoch carries for the next epoch: outcome,
  epoch, output, players, and next players.
- **Boundary block**: the final block of an epoch.
- **Identity**: one ed25519 signing key.
- **Committee**: the players of the current output. It always has 4 members.
- **Engine**: one running node stack.
- **Compromised identity**: the single identity that runs two engines, its **primary half** and
  **secondary half**, both signing with the same key and distinguished by their storage
  partitions and their secret stores.
- **Correct node**: an engine belonging to a non-compromised identity. All agreement claims in
  section 8 are about correct nodes only; both halves of the compromised identity are excluded.
- **Mock group**: this document's name for an implementation of the BLS `Variant` trait, defined
  in the fuzz crate, whose group is the scalar field itself. It has the same algebra as the real
  groups and performs no curve arithmetic, pairing, or hash-to-curve.
- **Mock threshold scheme**: the consensus threshold certificate scheme
  `commonware_consensus::simplex::scheme::bls12381_threshold` instantiated over the mock group.
- **Twins scenario**: a per-view assignment of which identities each half of the compromised
  identity may exchange messages with, drawn from the twins case generator in
  `commonware_consensus::simplex::mocks::twins`.
- **Prefix**: the leading views of an epoch for which the twins scenario prescribes a partition.
  The input chooses it: from 1 to 16 views, after which every view of the epoch is whole, or no
  bound, in which case the scenario partitions every view of the epoch.
- **DKG mask**: a per-epoch assignment, for the DKG channel only, of which identities exchange
  ceremony messages with which half of the compromised identity.
- **Correct application**: the deterministic application run by every correct node and by the
  primary half, wrapped by the real `reshare::Application`.
- **Faulty application**: the application run by the secondary half in the reshare Twins target,
  which deviates within the bounds of section 6.
- **Restart**: abort of a correct node's engine followed by re-initialisation under the same
  identity against its retained storage and its retained secret store.
- **Fabricated chain**: in the probe target, a chain of blocks and finalizations built by the
  harness and injected into real marshal actors, with no consensus running.
- **Joiner**: in the state-sync target, the identity that starts late and enters through the
  probe and DKG state sync.
- **Measurement point**: the points at which the invariants in section 8 are checked: each
  ceremony a correct node completes, and the end of the run.

The introduced invariants belong to the fuzz module. Nothing under `glue/src`,
`cryptography/src`, or `consensus/src` is held to them, and nothing under those trees is modified
to satisfy them.

## 1. Purpose

The DKG module enables threshold key generation without a trusted dealer,
while resharing allows validator set changes while preserving the threshold public key. It composes the
Feldman-Desmedt ceremony with p2p dealing, on-chain dealer logs, epoch transitions, crash
recovery, and state sync for late joiners. A defect in that composition can leave correct nodes
with different outputs, with shares that do not match the public key, or with a group key that
changes across a reshare. It can also leave a correct player's share published on chain. No
invariant checks that last defect since I7 was withdrawn (Choices made, item 4; section 12).

Existing fuzzing does not cover this. `cryptography/fuzz` drives the ceremony functions directly,
with no actors, network, storage, or blocks.

This feature runs the real DKG module under a Twins adversary, under crashes with lossy links,
under an adversarial probe peer program, and with a late joiner, and checks safety: the basic DKG
invariants must hold whenever a ceremony completes.

## 2. Goals

- **G1.** Provide fuzz targets that exercise the real `bootstrap`, `reshare`, `orchestrator`,
  `probe`, and `state_sync` code through their public APIs.
- **G2.** Check the basic DKG invariants at the end of every completed ceremony: any `required()`
  correct players reconstruct the private key that corresponds to the public key, and the same
  holds after every reshare.
- **G3.** Apply the Twins method to the DKG: the compromised identity deals twice under one key,
  and its two halves are told different things.
- **G4.** Reach the recovery paths that only restarts expose: journal replay, dealer and player
  resumption, and re-entry into a ceremony in each phase.
- **G5.** Exercise membership change: a reshare in which one identity joins the committee and one
  leaves, as well as a reshare over an unchanged committee.
- **G6.** Exercise the DKG probe under adversarial peer input, and DKG state sync for a late
  joiner in every phase of an epoch.
- **G7.** Achieve all of the above without modifying production code at `glue/src`,
  `cryptography/src`, or `consensus/src`, etc.
- **G8.** Adapt the targets for fuzzing: no real BLS operation may run in any target.

## 3. Technical requirements

A sentence of a requirement that carries MUST, MUST NOT, or MAY is binding. A sentence without
one explains or scopes the binding sentences beside it: it gives a reason, a consequence, or a
fact about the code under test, and it adds no obligation of its own.

- **R1. Focused fuzz targets.** The feature MUST expose independently runnable libFuzzer
  targets, listed in section 5.2: Twins over bootstrap, Twins over reshare, restarts over
  bootstrap, restarts over reshare, the probe protocol, and late-joiner state sync. Targets MAY
  share library machinery, but each MUST retain its own corpus.
  Note, that corpuses are not stored in the repo and fuzzing campaigns are started with empty corpuses.
- **R2. Thin targets.** Every fuzz-target file MUST only instantiate libFuzzer and invoke a library
  entry point. All harness logic MUST be in `glue/fuzz/src/dkg`.
- **R3. Fuzz-only implementation.** Every file changed by this feature MUST be under `glue/fuzz/`.
  A file under `glue/src`, `cryptography/src`, `consensus/src`, or elsewhere in the workspace MUST
  NOT be modified, with one exception: adding a dependency to `glue/fuzz/Cargo.toml` necessarily
  records it in the workspace `Cargo.lock`. All exercised behavior MUST be reached through public
  APIs of the existing crates.
- **R4. Deterministic execution.** Every target MUST run under `commonware_runtime::deterministic`
  runtime with its randomness supplied by `FuzzRng` over the input. Scheduling and randomized
  choices MUST depend only on the input bytes. Entropy-backed randomness and wall-clock time MUST
  NOT be used.
- **R5. Input sampling.** Each target's input MUST be decoded so that the head of the input (at
  most 8 bytes) seeds a fixed-size stream of `FuzzRng` output, the literal input overwrites that
  stream from its start, at the same offsets and as far as the stream reaches, and the structured
  controls are drawn from the stream. The rest of the stream is the run's tape, which MUST seed the
  deterministic runtime and every sampler in the harness. Every input, including an empty one, MUST
  therefore sample a complete session, and a short input MUST NOT collapse every control to its
  minimum. The tape MUST NOT be printed in `Debug` output; its length MAY be.
- **R6. Mock group.** Every target MUST instantiate the DKG module, the ceremony, and every
  threshold operation over the mock group. The mock group MUST be defined in the fuzz crate using
  only public API. It MUST preserve the algebra of the real groups, so that every check in the
  ceremony returns the verdict it would return on the real curve. Its decoder MUST reject
  non-canonical encodings and the identity, as the real groups do. A real BLS curve operation,
  pairing, or hash-to-curve MUST NOT run in any target.
- **R7. Consensus scheme.** In the reshare Twins, reshare restart, and state-sync targets,
  consensus MUST sign with the mock threshold scheme built from the `SchemeInfo` each node
  registers for each epoch. Marshal and the probe MUST verify with the certificate verifier
  derived from the group public key, which is the same for every epoch. In the probe target the
  fabricated chain MUST be signed and verified the same way. The bootstrap targets use the
  ed25519 Simplex chain that `bootstrap::Engine` owns.
- **R8. Identities.** Identity keys MUST be real ed25519 keys in every target.
- **R9. Ceremony parameters.** Every ceremony MUST use the `N3f1` fault model and `Reveal::V1`. The
  input MUST select the sharing mode among the modes the DKG module supports. All nodes of a run
  MUST use the same parameters.
- **R10. Committee.** The committee (validator set) MUST always have 4 members. The bootstrap
  targets MUST run 4 identities. The reshare and state-sync targets MUST run 5 identities; each
  epoch's committee is 4 of them, and the input MUST decide, per epoch, whether the committee stays
  the same or the outside identity replaces one member. The first committee's output MUST come from
  a trusted `deal` over the mock group.
- **R11. Session bounds.** A reshare run MUST cover a fuzz-selected number of epochs between 1 and
  3. The epoch length MUST start at 32 blocks. It MAY be reduced only after measurement shows that
  fault-free ceremonies still succeed at the shorter length. Within a target every bound (node
  count, epoch count, event count, simulated duration, storage) MUST be fixed across all inputs.
- **R12. Bootstrap stack.** In the bootstrap targets every engine MUST run the real
  `bootstrap::Engine` over the six channels it requires. The harness MUST supply only what the
  engine's configuration asks for: a secret store, a peer manager, and a blocker.
- **R13. Reshare stack.** In the reshare and state-sync targets every engine MUST run the real
  marshal actor in the Standard `Deferred` configuration, the real `reshare::Actor`, the real
  `reshare::Application` wrapper, the real `orchestrator::Actor` with its per-epoch Simplex
  engines, and the real `probe::Actor`. The block type and the inner application MUST be defined by
  the harness and MUST NOT carry state beyond what the DKG module needs. `StatefulActor` and QMDB
  MUST NOT be part of the stack.
- **R14. Harness-supplied traits.** The harness MUST implement `SecretStore`, `Registrar`,
  `ParticipantsProvider`, and the epoch-keyed scheme provider. These implementations MUST honor the
  contracts documented on the traits, so that a panic the DKG module raises on a contract violation
  can never be caused by the harness. The registrar MUST build a scheme only in the role the
  registered material names. On material no such scheme can be built from it MUST fail closed: it
  records the registration, serves no scheme for the epoch, and never resolves. I2 judges the
  record.
- **R15. Twins topology.** The Twins targets MUST run one more engine than identities: 5 engines
  over 4 identities for bootstrap, 6 over 5 for reshare. The compromised identity's two halves MUST
  be built from the real code, MUST share the identity key, and MUST each have their own storage
  partitions and their own secret store. In the reshare target both halves MUST start with the
  compromised identity's share of the first output: the input MUST select the identity outside the
  first committee among the identities other than the compromised one. The Twins targets MUST NOT
  restart any engine.
- **R16. Restart scope.** The restart targets MUST run correct nodes only and accept a
  fuzz-controlled schedule that crashes and restarts them. A restart MUST be an in-run abort and
  re-initialisation on the same deterministic runtime. All storage partitions and the node's secret
  store MUST survive it. A state-loss variant (a wiped secret store or journal, storage rolled back
  behind the secret store) MUST NOT be produced. A crash MAY fall between any two writes of a node:
  after it the secret store can be ahead of the node's journals, or behind them, by the writes that
  were in flight at the crash, and a journal can lack writes that had resolved but whose sync had
  not completed. That is not state loss: nothing that was durable when its write resolved is lost.
- **R17. Link conditions.** In the Twins targets every link MUST be fixed and lossless; the twins
  partition and the DKG mask MUST be the only network faults. In the restart targets the input MUST
  control link conditions among correct nodes: latency, jitter, delivery rate, and temporary cuts.
  Message bytes MUST NOT be corrupted on a link between correct nodes in any target.
- **R18. Safety only.** The feature targets safety. It MUST NOT assert liveness. A run that stalls,
  a ceremony that fails, and a run that reaches its simulated timeout MUST be treated as healthy
  outcomes, and the invariants MUST be checked over whatever was reached.
- **R19. Deterministic regression suite.** Every target MUST have ordinary tests in the fuzz crate,
  driven by fixed inputs, that use the same library entry points and oracles as libFuzzer. For
  every invariant in section 8 that a run checks, the suite MUST contain at least one negative
  control: a fault planted inside the harness at the observation boundary that makes exactly that
  invariant fail. An invariant that another invariant always reports first in a target MAY have its
  control in another target or over built records. I11 constrains the working tree, not a run, and
  is verified at delivery (section 10, step 1).
- **R20. Reuse of fuzzing primitives.** The implementation MUST reuse existing fuzzing primitives
  wherever one fits and MUST NOT duplicate them in `glue/fuzz`. This covers the primitives the
  published crates provide (`FuzzRng`, the twins scenario generator and elector, the simulated
  network and its split-channel plumbing, the marshal mocks, the deterministic runtime) and the
  machinery already in `glue/fuzz/src/stateful` (tape handling, the split forwarders and routers,
  the restart, panic-hook, and report helpers). New code MUST be written only for what no existing
  primitive provides: the mock group, the DKG block, applications, stores, the DKG mask, the
  drivers' DKG-specific wiring, and the invariants. A primitive that fits only after being made
  generic MUST be generalized and shared, not copied; the stateful targets MUST remain behaviorally
  equivalent, apart from the prefix their Twins targets take from the input (P5). The feature MUST
  NOT depend on `commonware-consensus-fuzz-*` or on the `test-utils` feature of `commonware-glue`.
- **R21. Probe target construction.** The probe target MUST run one discovering `dkg::probe` actor
  and three serving ones over real marshal actors seeded with a fabricated chain, plus one tracked
  identity that is not a dealer. The target MUST NOT run consensus or a ceremony. Boundary blocks
  MUST carry `EpochInfo` over the mock group: epoch 0's output MUST be a `deal` output, and each
  later epoch's MUST be a reshare of the one before through the real dealer and player state
  machines, so every epoch's output carries the group key the chain is verified with. The epoch
  length MUST be 2. A source MAY be seeded from a foreign chain built the same way from a different
  dealt key.
- **R22. Probe adversary program.** The probe target's structured input MUST bound and control
  what each source holds, the minimum epoch, and a program of events: subscribe, unsubscribe,
  attach a marshal, release a captured response, duplicate it, replay it from the non-dealer,
  truncate it, send a fragment of it from another identity, send junk, and advance time. Source
  responses MUST be captured and handled as opaque bytes, for all three response kinds the DKG
  probe has. The harness MUST NOT reimplement floor selection, response verification, or probe
  state transitions.
- **R23. Late-joiner state sync.** The state-sync target MUST run 5 correct identities. The input
  MUST select one as the joiner; the other four MUST start at genesis. The joiner MUST start once a
  fuzz-selected height has been applied, which MUST be able to fall in any phase of any epoch of
  the run. It MUST discover its boundary through the real probe, build its state-sync material from
  the probe's artifact, and start the reshare stack from it. The input MUST also control an
  optional restart of the joiner at a chosen delay after it starts and a schedule of up to three
  restarts across all nodes. Links MUST be fixed. Every node MUST start a real probe at every boot
  and attach its marshal to it.
- **R24. Joiner caller contract.** The harness plays the role the DKG module documents for its
  caller. It MUST keep the joiner's floor durable across restarts, MUST pass a persisted floor to
  the probe when it restarts, MUST pair the artifact's `EpochInfo` with the later-by-round of the
  persisted floor and the artifact's floor, and MUST start marshal from that floor. A sync that
  completed MUST NOT be repeated at a later start.
- **R25. Registration.** Every target MUST be registered as a `[[bin]]` in
  `glue/fuzz/Cargo.toml` with its own feature, and every such feature MUST be included in a
  `dkg-all` feature that is part of the default set, as the stateful targets are.
- **R26. One home for the invariants.** Every invariant in section 8 that is checked at run time
  MUST be defined in `glue/fuzz/src/dkg/invariants.rs`, as the stateful invariants are defined in
  `glue/fuzz/src/stateful/invariants.rs`. That file MUST hold the observation records the checks
  read and the checks themselves, for all six targets, the probe target included. Drivers MUST
  record observations and call into it; they MUST NOT define a check of their own.
- **R27. Network limit.** The simulated network of every target MUST refuse a message larger than
  the limit the code under test computes for itself: in the bootstrap targets the bound
  `bootstrap::max_payload_size` gives for the committee, and in every other target the largest of
  the bounds the DKG module, its orchestrator, its probe, and marshal give through their
  `max_payload_size`. A sender that hands the network a larger message panics, which I8 reports,
  so a bound too small for a message the module sends is a finding.
- **R28. Peer directory.** The bootstrap targets MUST run with the key-only directory and the
  network's key-only peer manager. Every other target MUST carry an address for every peer of an
  epoch in the epoch's `EpochInfo` and track peers through the DKG module's `AddressableManager`,
  over the peer manager of the engine's own identity, so that the peer sets one engine activates
  are not another's. The probe target's members run no engine and never restart: they MUST track
  over the network's peer manager, which gives every member the set the discovering probe
  activates. Every identity MUST start with the network's initial set of every identity, which
  keeps it reachable whatever committee it is in; an engine restarted in a run MUST start again
  from that set alone, and it activates its epochs anew. The first `EpochInfo` and the participants
  provider MUST supply a directory of exactly the epoch's dealers, players, and next players.
- **R29. Reshare mailbox.** In the reshare Twins, reshare restart, and state-sync targets the
  input MUST choose the size of the reshare actor's mailbox: one, two, or four messages in half of
  the runs, and room for a hundred in the others. A small mailbox overflows when marshal and the
  application call the actor while it is busy, so that its overflow policy runs.
- **R30. Unmeasured invariants are reported.** At its measurement point every run MUST report,
  for each invariant that section 8 applies to its target and that is checked at run time, how
  many records the check of that invariant judged. An invariant whose count is zero MUST be
  reported as unmeasured, by its id and with the reason section 8.1 fixes for it, and MUST NOT
  be reported or counted as passing. The report MUST be per invariant: the count of one
  invariant MUST NOT stand for another. An unmeasured invariant MUST NOT fail the run (R18).
  Section 8.1 states which invariants a target's report holds, what one unit of each count is,
  and the one reason each invariant gives. Section 5.4 states where the report is read and
  what a fuzz process writes.

## 4. Properties

- **P1. Correct-node symmetry.** Within a run every correct node runs the same code, the same
  application, and the same configuration. A divergence among them is attributable to the
  exercised system.
- **P2. Adversary confinement.** In the Twins targets, message-level and application-level faults
  occur only on the compromised identity. The restart and state-sync targets contain no Byzantine
  participant. Probe adversarial input enters only through the boundaries listed in R21 and R22.
- **P3. Contract-bounded harness.** A run that fails only because the harness supplied behavior
  outside a documented contract of the DKG module is not a finding. R14, R16, and R24 state the
  contracts; section 9 records what is excluded.
- **P4. Determinism and minimization.** Any failure must be reproducible from the crashing input
  and minimizable by the fuzzer, with no cross-run state.
- **P5. Search-space isolation.** Adding these targets MUST NOT change the fault model or the
  predicates of any existing target in `glue/fuzz`, nor the input decoding or topology of any
  existing target other than the stateful Twins targets. Those take the adversarial prefix from
  the input, as `glue/fuzz/src/stateful/SPEC.md` describes, where they had a fixed prefix of
  three rounds; the prefix is decoded before their fault controls, so the bytes those controls
  and the tape are drawn from move. Shared machinery MAY be refactored for R20 only when the
  existing targets otherwise remain behaviorally equivalent. No corpus compatibility is
  promised: no corpus is kept, and every campaign starts from an empty corpus (R1).

## 5. Files and interfaces

### 5.1 Feature module: `glue/fuzz/src/dkg/`

The decomposition below is indicative, except for `invariants.rs`, which R26 makes normative. The
target names in 5.2 are normative.

- `mod.rs`: module docs, wiring, shared constants, re-exports of the input types and entry
  functions.
- `input.rs`: the fuzz input types and their `Arbitrary` implementations (R5).
- `mock.rs`: the mock group (R6).
- `app.rs`: the block type, the correct application, and the faulty application.
- `store.rs`: the secret store, registrar, participants provider, and scheme provider (R14).
- `network.rs`: the split forwarders and routers that realise the twins partition and the DKG
  mask.
- `stack.rs`: construction of one bootstrap engine and one reshare engine.
- `runner.rs`: what the drivers share around a run: the entry point a fuzz target calls, the
  runtime a run executes on, and the watch a driver keeps over its correct engines until the run
  ends.
- `environment.rs`: what the restart drivers share: the crash and restart schedule, the link
  conditions, the late start of an identity, and the supervision of every engine instance across
  its restarts.
- `twins.rs`, `restarts.rs`, `probe.rs`, `state_sync.rs`: the drivers.
- `invariants.rs`: the observation records and every check in section 8 (R26).

### 5.2 Fuzz targets

- `glue/fuzz/fuzz_targets/dkg_bootstrap.rs`
- `glue/fuzz/fuzz_targets/dkg_reshare.rs`
- `glue/fuzz/fuzz_targets/dkg_bootstrap_restarts.rs`
- `glue/fuzz/fuzz_targets/dkg_reshare_restarts.rs`
- `glue/fuzz/fuzz_targets/dkg_probe.rs`
- `glue/fuzz/fuzz_targets/dkg_state_sync.rs`

The CI fuzz job discovers targets from the manifest, so no other list needs updating.

### 5.3 Consumed dependencies (pre-existing; named, not defined here)

- The DKG module's public API in `commonware_glue::dkg`.
- The ceremony, the threshold operations, and the `Variant` trait in
  `commonware_cryptography::bls12381`.
- The threshold certificate scheme and the twins scenario generator and elector in
  `commonware_consensus::simplex`.
- The marshal actor and its mocks in `commonware_consensus::marshal`.
- The simulated network in `commonware_p2p::simulated`.
- The deterministic runtime and its storage in `commonware_runtime::deterministic`.

Any change to a consumed interface that alters its contract is a change to this feature's
dependencies and must be re-audited against this document.

### 5.4 Report interface (R30)

This subsection is normative. It fixes the interface the regression tests read and what a
fuzz process writes.

- **The report of a run is a value.** The library function that runs a target, which its fuzz
  entry point and its fixed-input tests both call (R19), MUST return the run's report. The
  report MUST give, for each id its target has in the report column of section 8.1, the count
  and, where the count is zero, the reason, and it MUST say how the run ended. A regression test
  MUST read these from the returned value and MUST NOT parse printed text.
- **The smoke aggregate is a value.** The fuzz crate MUST have one function that folds the
  reports of a sequence of runs of one target into the aggregate: the number of runs and, for
  each id the target has in the report column of section 8.1, the number of runs whose count
  for it was above zero and the number of runs whose count for it was zero. The two numbers of
  an id sum to the number of runs. A test reads the aggregate from the function's value.
- **The aggregate is always written.** Every fuzz process MUST write the aggregate over the
  runs it has completed so far to standard error, whatever its environment: at intervals while
  it runs, and once more at its end. Each time it is one line,
  `[<target>] aggregate runs=<n> I1=<m>/<u> I2=<m>/<u> ...`, with one
  `I<k>=<measured>/<unmeasured>` entry for each id the target has in the report column of
  section 8.1, in ascending order of `k`. The line written at the end MUST cover every run the
  process completed. The end is one the process reaches by itself, as when libFuzzer's limit
  of runs or of time is reached. A process that is killed, or that aborts on a violation
  (section 11, Failure reporting), writes no last line, and its latest line stands. The smoke
  run of section 10, step 6 is read from its last aggregate line.
- **The report of a run is written on request.** A fuzz process writes the full report of
  each run to standard error only when the environment variable `GLUE_FUZZ_LOG` is set, the
  switch the rest of `glue/fuzz` uses. An unmeasured invariant does not make a run print: I6
  is unmeasured in most runs (12.1, rows 11 and 25). The form of that printed report is not
  fixed by this document, and no test reads it.

## 6. Adversary model (normative)

- **A1. Message layer.** In the Twins targets, each of the compromised identity's channels that
  carries view-addressable Simplex traffic MUST be split in two, with the twins scenario
  deciding, per view, which identities each half may send to and which half receives a given
  inbound message. A half's view-addressable message reaches the identities the half addressed
  that the scenario admits: a broadcast reaches every identity the scenario admits, a message to
  some identities those of them it admits, and a message to one identity it does not admit
  reaches no one. The scenario applies to the prefix of every epoch, which the input draws:
  the first 1 to 16 views, or every view. Past a bounded prefix both halves exchange
  view-addressable traffic with every identity. Traffic from which no view can be determined,
  other than the DKG channel, follows the stateful rule: it is delivered to both halves and sent
  to the recipients the engine addressed; a message that does not decode is dropped. In the
  bootstrap targets the scenario decides only the partition: `bootstrap::Engine` owns its
  elector, so the leader a scenario scripts is not used.
- **A2. DKG channel.** Dealings and acks carry an epoch and no view. For each epoch the input
  MUST choose a DKG mask that assigns every other identity to the primary half, the secondary
  half, or both. "Both" for every identity is one of the choices. Because the halves hold
  separate secret stores they deal differently under one identity, and the mask decides which
  players see which dealing.
- **A3. Application layer.** In the reshare Twins target the secondary half MUST run the faulty
  application, which may deviate only in what it proposes:
  - a dealer log in the early half of an epoch;
  - a dealer log signed by another dealer;
  - an `EpochInfo` on a block that is not the boundary block;
  - a wrong `EpochInfo`, or no payload, on the boundary block.

  Which of these is armed, and when, MUST be derived from the run's tape. The bootstrap Twins
  target has no faulty application, because `bootstrap::Engine` owns its application.
- **A4. Non-shadowing.** The primary half runs the correct application, so the pair's
  disagreement is equivocation under one identity and not an artefact of both halves being told
  to misbehave.
- **A5. Probe adversary.** Limited to R21 and R22.
- **A6. Environment faults.** Crash and restart of correct nodes and link conditions among them
  are environment faults, not adversarial behavior. They are specified in R16, R17, and
  section 7.

## 7. Run structures

### 7.1 `dkg_bootstrap`

1. **Setup.** Four identities and five engines per R12 and R15. Links are fixed.
2. **Execution.** The twins scenario partitions the prefix (A1). The DKG mask applies for the
   whole ceremony.
3. **Measurement.** The run ends when every correct engine has reported a `Completion`, when a
   correct engine stops, or when the simulated timeout expires. I1-I3, I6, I8, and I9 are
   checked (section 8.1).
   Results are compared among the correct engines that completed. With every completion the
   harness records the share the engine's secret store holds at that moment, and the store keeps
   every share it was ever given. I2 is checked at each completion against the share recorded
   with it, and at the end against the share each store holds and against every share each store
   ever held, a share later overwritten included: a share is checked wherever a correct engine
   holds or held one, whether or not that engine has reported. The agreed output is known only
   from a completion: the engine keeps the final block that carries it in its own storage and
   exposes it through no other interface. If no correct engine has reported, every share a
   correct engine held is checked against what every output I1 accepts implies: it carries the
   engine's position in the committee, no engine held two different shares (I2), and every
   `required()` of the engines' shares recover one and the same signature (I3). Whether the
   ceremony failed, after which no share may be held (I6), and whether the shares are those of
   the output it produced are then not checked, and with no more holders than `required()`, as
   with the three correct engines of this target, the I3 clause compares nothing. An engine
   reports at every start once it has stored its share, so this arises only when the run ends
   between the write of a share and the engine's next report (section 9).

### 7.2 `dkg_reshare`

1. **Setup.** Five identities and six engines per R13 and R15, with the first output from a
   trusted deal (R10). Links are fixed.
2. **Execution.** For each epoch the twins scenario partitions the prefix (A1), the DKG mask
   applies to the ceremony, and the faulty application is active on the secondary half. The
   committee schedule follows R10.
3. **Measurement.** The run ends when every correct node has processed the last boundary block of
   the selected epochs or the simulated timeout expires. I1-I6, I8, and I9 are checked at every
   boundary a correct node processed and at the end, and I18 over every finalized block a
   correct node was delivered (section 8.1).

### 7.3 `dkg_bootstrap_restarts` and `dkg_reshare_restarts`

1. **Setup.** Correct nodes only: four identities for bootstrap, five for reshare.
2. **Execution.** A bounded schedule crashes and restarts nodes per R16 while link conditions
   follow R17.
3. **Measurement.** As in 7.1 and 7.2: `dkg_bootstrap_restarts` checks the invariants 7.1
   lists, and `dkg_reshare_restarts` those 7.2 lists, I18 included (section 8.1). In
   `dkg_bootstrap_restarts` every completion of every instance of an engine is
   recorded with the share its store held then. I1 compares the engines' first completions with
   one another and every later completion with its engine's first. A crash between the write of a
   share and the completion leaves a share that no completion of that instance accompanies; the
   share is judged against the output another completion reports, or as 7.1 states if none does.

### 7.4 `dkg_probe`

1. **Setup.** Per R21. The harness records, for each source, the exact finalizations and boundary
   blocks it holds.
2. **Execution.** The bounded event program of R22 drives subscriptions, attachment, retries,
   delivery, and raw malformed traffic through public boundaries. The driver adds two
   observable boundaries, so that the oracle knows the probe's state at every delivery. When
   the program drops its last subscription, the identity that is not a dealer sends the probe
   back the request for latest finalizations the probe sent: the probe ignores it while
   discovering, answers it with nothing while serving, and looks at its subscriptions once it
   has taken it. When the responder the probe asked delivers the whole boundary block while no
   subscription is open and the probe's marshal is not attached, the driver opens a
   subscription, which the probe answers with the artifact it then holds.
3. **Measurement.** If the discovering probe emits an artifact, I12 and I13 are checked against
   the recorded source state. No artifact is required. A run without one reports I12 and I13 as
   unmeasured (R30). I14 does not depend on an artifact: it is checked at every delivery to the
   discovering probe, and its count (R30) is the number of deliveries for which it required a
   block or required that the sender not be blocked. A delivery for which nothing is required
   (Choices made, item 11) is not counted. I14 is unmeasured only when that count is zero, with
   the reason that no delivery was judged. I8 applies throughout (section 8.1).

### 7.5 `dkg_state_sync`

1. **Setup.** Per R23. Four identities start at genesis.
2. **Join.** At the selected height the joiner starts, discovers its boundary, and enters per
   R24.
3. **Crashes.** The joiner's optional restart and the general restart schedule run.
4. **Measurement.** As in 7.2, with the joiner included from its floor upward. I1-I6, I8, I9,
   I15-I17, and I18 are checked (section 8.1). A joiner whose sync never completes is a healthy
   outcome. It is reported with every invariant it left unmeasured (R30).

## 8. Invariants

I1-I3 and I6 apply to correct nodes in the four ceremony targets and the state-sync target. I4
and I5 judge the boundary of a reshare and apply to correct nodes in the targets that run one:
the reshare Twins, reshare restart, and state-sync targets. I7 is withdrawn. I8 and I10 apply
to every target. I11 constrains the working tree, not a run (R19): it holds for the feature as
a whole and is verified at delivery. I9 applies to every target that runs more than one correct
node. I12-I14 apply to the probe target and I15-I17 to the state-sync target. I18 applies to
the targets that run the reshare stack: the reshare Twins, reshare restart, and state-sync
targets. Section 8.1 gives the same sets as one table.

- **I1. Output agreement.** Any two correct nodes that completed the same ceremony MUST hold the
  same result for it: the same outcome and, for a reshare, an identical `EpochInfo`; for a
  bootstrap, an identical successful output or no output at both. A successful bootstrap result
  MUST describe the ceremony that was run: outcome `Success` for epoch 0, players and output
  players equal to the committee, no next players, and a sharing among the committee's size that
  needs the committee's quorum of shares.
- **I2. Share validity.** Every share a correct node holds or has held for an epoch MUST carry the
  node's index in that epoch's agreed output, and its public key MUST equal the output's partial
  public key at that index. A correct node at which a bootstrap completed successfully MUST hold a
  share from the moment it reports the completion.
  A correct node that has reached an epoch of a reshare run as a player of that epoch's agreed
  output MUST hold a share for that epoch; it has reached the epoch once it registered the epoch's
  scheme. After a successful reshare that share is its share of the new output. After a failed
  reshare it is the share the node held for the previous epoch, held again under the new one; a
  node that held no share for the previous epoch has none to carry. An epoch a node entered
  through state sync without playing its ceremony is exempt (I17). Every `SchemeInfo` a correct
  node registers for an epoch MUST name the players of that epoch's agreed output, carry its
  public sharing, which needs the quorum of those players, and name the node's own role: a
  verifier only outside those players, a member only under the node's own key, and a signer only
  with the node's valid share. Whenever a correct node registers the scheme of an epoch it has
  ever held a share for, the registration MUST be a signer's and carry that share.
- **I3. Reconstruction.** For every subset of exactly `required()` correct nodes that hold a
  share of an output, their partial signatures over a fixed message MUST recover to a signature
  that verifies under the output's group public key. No subset of `required() - 1` shares may
  produce one.
- **I4. Reshare continuity.** For every epoch boundary: the new players MUST equal the previous
  `EpochInfo`'s next players, and the new next players MUST equal the configured schedule. On
  success, the output's players MUST equal the previous players, the group public key MUST equal
  the previous output's, and I2 and I3 MUST hold for the new player set, whether or not the set
  changed.
- **I5. Cross-epoch isolation.** After a successful reshare, a set of `required()` shares that
  mixes shares of the previous output with shares of the new one MUST NOT recover a signature
  that verifies.
- **I6. Failed ceremony.** A failed reshare MUST carry the previous output forward unchanged, and
  every share a correct node held for the previous epoch MUST be valid under it. A correct node
  that reaches the new epoch as a player of the carried output MUST hold that share for the new
  epoch as well (I2). After a failed bootstrap no correct node may hold, or have held, an epoch-0
  share.
- **I7. Withdrawn.** It required that no correct identity appear in `Output::revealed()`. The
  number is kept so that the later invariants keep theirs. No target checks the secrecy of a
  correct player's share; see Choices made, item 4.
- **I8. No panic, except in a compromised half.** No correct engine and no harness task may
  panic, and a correct engine MUST keep running until the run ends. R14, R16, and R24 keep the
  harness inside the contracts whose violation the DKG module answers with a deliberate panic.

  A half of the compromised identity MAY panic, whatever the panic says. The halves hold
  different secrets under one identity (R15), so a half can find, in a dealer log the ceremony
  selected, an ack its twin signed for a dealing it never stored, or find the dealing it stored
  as its own contradicted by its twin's. The DKG module treats either as a node whose secret
  store is corrupt and stops it with a deliberate panic, after which the half's engine exits.

  The runtime therefore catches the panics of its tasks, and the oracle records every panic of
  the run and judges them afterwards by the engine that raised them, never by their messages.
  Every engine runs on its own runtime context, which marks the tasks spawned from it, and from
  any context derived from it, as that engine's. A panic of a half is tolerated. A panic of a
  correct engine, or of a task that belongs to no engine, is a violation. Harness code that a
  half's task calls into, such as a channel's forwarder, runs as belonging to no engine.
  The oracle also watches every correct engine, and one that stops before the run ends is a
  violation.
- **I9. Correct nodes do not block each other.** No correct node may block another correct
  identity. Blocks on or by the compromised identity are permitted. In the probe target I14
  governs blocking instead.
- **I10. Reproducibility.** A failing input replayed MUST fail identically. The regression suite
  of every target replays a fixed input and compares what the two runs measured with one shared
  check, which names I10 when they differ.
- **I11. Fuzz-only change scope.** Every change introduced by this feature MUST be confined to
  `glue/fuzz/` (R3), and pre-existing unrelated working-tree changes MUST be preserved.
- **I12. Probe floor provenance.** If the discovering probe emits an artifact, its floor MUST be
  the highest-round finalization among the valid latest-replies of exactly the first `f + 1`
  distinct dealers to deliver one since the probe's last latest-request, each sent by the source
  that built it. A valid latest-reply delivered after those MUST NOT change the floor. With 4
  dealers that is 2.
- **I13. Probe artifact consistency.** The artifact's finalization and `EpochInfo` MUST equal the
  fabricated chain's boundary finalization and the `EpochInfo` of its boundary block for the
  floor's epoch. At epoch 0 the artifact MUST carry no finalization and the configured genesis
  `EpochInfo`. Nothing from a foreign chain may appear in an artifact. A second, different
  artifact from the same probe is a violation.
- **I14. Probe response isolation.** A peer that sent only its own valid responses MUST NOT be
  blocked. A sender of a damaged response, of a valid latest-reply replayed by the non-dealer, or
  of a response that does not verify MUST be blocked, in the states where the DKG probe decodes
  and judges that message. The blocks the harness expects and the blocks the network recorded
  MUST agree in both directions.
- **I15. Single, durable state sync.** Across the joiner's starts, in order: a start that
  follows a selected floor MUST find a floor on record that is not earlier; a resumed sync MUST
  NOT move its floor to an earlier round; and once a sync has completed, every later start MUST
  find the completion on record and MUST NOT sync again. I15 is read from the records the
  joiner's caller keeps of its own starts, so it checks that the harness honours the caller
  obligations of R24. It does not observe the DKG module.
- **I16. Joiner floor provenance.** The floor the joiner starts from and the `EpochInfo` it
  pairs with it MUST be ones the nodes that started at genesis actually finalized.
- **I17. Agreement after sync.** Every block and every `EpochInfo` the joiner commits above its
  floor MUST equal what the other correct nodes committed at that height or epoch, and MUST be
  one the nodes that started at genesis have a record of, whether or not they have committed it
  yet. The joiner is
  subject to I1-I6 from its floor upward, with one exemption from I2: it is not required to
  hold a share of an output whose ceremony it did not play, which is the output of the epoch of
  a floor it entered from and, when that floor lies past the midpoint of its epoch, of the next
  epoch. The exemption does not cover an epoch whose scheme the joiner had registered before
  that entry. Of every other output it is a player of, the joiner MUST hold a share.
- **I18. Payload placement.** Every finalized block above height zero that marshal delivers to a
  correct node MUST carry its reshare payload where the epoch schedule the DKG module is
  configured with allows it: a block before the midpoint of its epoch carries no payload; a
  block from the midpoint up to, but not including, the final block of its epoch carries no
  payload or a dealer log; the final block of an epoch carries an `EpochInfo`; a block at a
  height outside every epoch carries no payload. The height-zero block is the configured one that
  carries the `EpochInfo` of epoch zero and is not judged. A block is judged by its height and the
  kind of its payload only. No dealer log is required to appear, and which dealer signed a log, how
  many logs of one dealer are on the chain, and whether a log verifies are not judged.

An invariant MUST NOT be disabled, weakened, or narrowed to make a configuration pass. A
configuration that cannot satisfy one is either a reportable defect or an exclusion recorded in
section 9.

### 8.1 Run-time invariants per target, their counts, and their reasons

This subsection is normative. It makes R30 exact: which invariants a run's report holds, what
one unit of each count is, and which reason an unmeasured invariant gives.

**Per target.** A run's report MUST hold exactly one entry for each id in the report column of
its target's row, and no entry for any other id.

| Target | In the report of every run | Counted by the replay check |
|---|---|---|
| `dkg_bootstrap`, `dkg_bootstrap_restarts` | I1-I3, I6, I8, I9 | I10 |
| `dkg_reshare`, `dkg_reshare_restarts` | I1-I6, I8, I9, I18 | I10 |
| `dkg_probe` | I8, I12-I14 | I10 |
| `dkg_state_sync` | I1-I6, I8, I9, I15-I18 | I10 |

I4 and I5 judge the boundary of a reshare, which a bootstrap run does not have. I7 is withdrawn.
I9 has no entry in the probe target, where I14 governs blocking (I9). I11 is not checked at run
time and is counted nowhere: it constrains the working tree and is verified at delivery (R19;
section 10, step 1).

I10 is checked on two runs of one fixed input, not inside a run. One unit of its count is one
comparison by the shared check, which compares the two whole reports, their R30 entries
included. The count belongs to the replay check of the regression suite, which is made after
both runs: a run's report has no I10 entry. A libFuzzer run replays nothing, so the smoke
aggregate (section 5.4) has none either. Section 10, step 7 holds for I10 in a target when the
suite of that target makes at least one replay comparison.

**Count.** These rules hold for every count.

1. One unit is one judgement: the invariant's rule applied once to the record, or to the group
   of records, that the table below names.
2. A record for which the invariant requires nothing adds no unit.
3. A record checked more than once under one invariant adds one unit.
4. A count covers the whole run: every epoch, every correct engine and, where engines restart,
   every instance of an engine.
5. An invariant is measured in a run when its count is above zero, and unmeasured when it is
   zero.

| Id | One unit | Reason when the count is zero |
|---|---|---|
| I1 | One comparison of two results of one ceremony: the result a correct engine holds, with the result of another correct engine, so that `k` engines that hold a result of one ceremony give `k - 1` units; and in `dkg_bootstrap_restarts` a later completion of an engine, with that engine's first (7.3). In the bootstrap targets, one more for an agreed successful result, which is judged against the ceremony that was run. In a reshare run the result of a ceremony is the `EpochInfo` of the epoch it leads into; the configured `EpochInfo` of epoch 0 is the result of no ceremony and adds no unit | `no result was compared` |
| I2 | One distinct share a correct engine holds or held for an epoch, judged against that epoch's agreed output or, in a bootstrap no correct engine reported, against the committee (7.1). One more for each `SchemeInfo` a correct engine registered, judged against that epoch's agreed output. A requirement to hold a share adds no unit of its own | `no share or registration was recorded` |
| I3 | One subset of exactly `required()` shares that correct engines hold of one output, whose recovered signature was judged: verified under the output's group public key or, in a bootstrap no correct engine reported, compared with that of another subset (7.1). A lone subset in that case is compared with nothing and adds no unit. The clause on `required() - 1` shares adds no unit | `too few shares of one output` |
| I4 | One epoch boundary: the `EpochInfo` the correct engines hold of an epoch past the first, judged against the one of the epoch before it. One unit for a boundary, however many engines processed it | `no ceremony completed` |
| I5 | One mixed set (Choices made, item 2) of `required()` shares after a successful reshare. It is interpolated under both sharings (item 7) and adds one unit | `no mixed set of shares` |
| I6 | One failed ceremony that a correct engine reported: a failed reshare, whose carried output is compared with the previous one and under which every share a correct engine held for the previous epoch is judged; or a failed bootstrap, after which the holdings of every correct engine are examined | `no failed ceremony was reported` |
| I8 | One for the run: its whole panic record and its watch over the correct engines, judged at the end of the run. The count is zero only for a run that executed no scenario | `nothing ran` |
| I9 | One for the run: the network's whole record of blocks, judged at the end of the run. The count is zero only for a run that executed no scenario | `nothing ran` |
| I12 | One floor: the floor of the artifact the discovering probe emitted, judged against the replies of Choices made, item 12. A probe selects one floor, so the count of a run is 0 or 1 | `no artifact was emitted` |
| I13 | One artifact the discovering probe emitted, one for each subscription it answered with an artifact: the first judged against the fabricated chain, each later one against the first | `no artifact was emitted` |
| I14 | One delivery to the discovering probe for which the check required a block or required that the sender not be blocked (7.4, step 3) | `no delivery was judged` |
| I15 | One step of the joiner's caller record that a clause of I15 judges: a start that follows a selected floor, a start that follows or finds a completion, or a floor selected after an earlier one. The joiner's first start, its first floor, and the completion itself are judged by no clause and add no unit | `no start followed a floor` |
| I16 | One entry: the floor a syncing start of the joiner entered from, with the `EpochInfo` paired with it, judged against what the nodes that started at genesis finalized | `no floor was entered` |
| I17 | One block or one `EpochInfo` the joiner committed, compared with what every other engine committed at that height or for that epoch and traced to the nodes that started at genesis. Marshal delivers the joiner nothing below its floor (Choices made, item 21) | `no sync completed` |
| I18 | One finalized block above height zero that marshal delivered to a correct engine, judged by its height and the kind of its payload. A block delivered to several engines adds one unit for each | `no block was delivered` |

**Reason.** An unmeasured invariant MUST give the reason of its row, word for word, and no
other. The reason names the record the check lacked. When several causes hold together, as when
the simulated timeout expires before any ceremony completes, each unmeasured invariant still
gives the reason of its row. How the run ended, the expiry of its simulated timeout included,
MUST be stated once in the report, for the run, and is never the reason of an invariant.

## 9. Out of scope

- **Liveness.** Excluded by R18. No progress requirement is asserted in any target.
- **The outcome of a bootstrap no correct engine reported.** The oracle reads outputs only from
  reports (section 11, Observation), and a bootstrap engine reports its outcome only in its
  completion, so when a run ends with a share written and no completion recorded, the share is
  judged without the outcome (section 7.1) and I6 is not checked.
- **Coverage targets.** No line-coverage threshold is set. Fuzzing runs until it is stopped.
- **Real BLS.** Excluded by R6. No target has a variant over `MinPk` or `MinSig`.
- **A mock identity signer.** Identities stay on ed25519 (R8). A mock signer for the targets
  whose identity type is generic is reconsidered only if measurement shows ed25519 is a visible
  share of run time. Bootstrap fixes ed25519 in `glue/src` and cannot use one.
- **Cryptographically invalid ceremony messages to correct nodes.** Both halves of the
  compromised identity run the real code, so no correct node ever receives a dealing with a bad
  share or commitment, or an ack with a bad signature, and the handling of those by a correct
  node is not exercised. The compromised halves do receive acks that are invalid for them: a
  correct player answers the second half's dealing with the ack it signed for the first, and
  that half blocks the player for it.
- **Consensus-level faults beyond the twins partition.** Vote equivocation is produced only by
  the twins split; no other Simplex deviation is introduced.
- **A failed reshare under Twins.** One compromised dealer of four cannot keep three correct
  dealers' logs out of the inclusion window by its messages alone. A ceremony of `dkg_reshare`
  fails only where the scenario scripts the leaders of the whole epoch and leaves too few
  correct dealers a view to lead (Choices made, item 22). The restart targets keep one identity
  impaired at a time (Choices made, item 1) and reach a failed ceremony on a few sampled inputs
  in a thousand.
- **A failed bootstrap under Twins.** No input of `dkg_bootstrap` is known to fail a ceremony.
  A ceremony fails when fewer than three of the four dealers get a log into a finalized block
  of the inclusion window, and a dealer posts its log in a block it proposes itself.
  `bootstrap::Engine` owns its elector, a round robin, so no scenario scripts a leader (A1)
  and every correct dealer leads views of the window. The three correct engines are a quorum
  on fixed, lossless links (R15, R17), and the DKG mask moves only the compromised identity's
  own dealings (A2). In 4,330 logged runs of the target, 2,587 on new inputs and 1,743
  replays of the corpus they left, every ceremony succeeded at all three correct engines, as
  it did in 8 fixed inputs of the regression suite, with a prefix of 1, 9, and 16 views and
  with no bound.
  This is likely and not proven: an input in which the compromised leader's equivocation
  costs a correct dealer every one of its views in the window was not found and not ruled
  out. Section 10, step 7 therefore excepts I6 in this target (Choices made, item 29).
- **State loss.** Excluded by R16.
- **Restarting the compromised identity.** Excluded by R15.
- **Corrupted bytes between correct nodes.** Excluded by R17.
- **The stateful layer.** `StatefulActor`, QMDB, and their interplay with DKG state sync are not
  part of any target (R13).
- **Other configurations.** Committee sizes other than 4 are excluded by R10. The coding marshal
  variant is excluded by R13 in the reshare and state-sync targets, which run marshal in the
  Standard `Deferred` configuration; the probe target builds its marshal actors over the same
  Standard variant. Marshal pruning is excluded with the stateful layer (R13): in a node that
  layer prunes marshal, the DKG module does not, and the harness does not prune in its place.
  Section 12.1, rows 8, 26, and 27, gives what each exclusion costs and how to lift it.
- **Modifying any file outside `glue/fuzz/`.** Excluded by R3.

## 10. Delivery and end-to-end verification

For each target, the following steps prove it works. `cargo fuzz` requires a nightly toolchain;
use the nightly pinned by CI (`nightly` under `[tools]` in `.github/toolchains.toml`).

1. **Production source tree is untouched.**
   `git status --porcelain glue/src cryptography/src consensus/src` prints nothing (I11, R3).
2. **The target is thin.** The target file contains only the libFuzzer entry point and a call
   into the library (R2).
3. **Everything compiles and lints clean.** `cargo check -p commonware-glue-fuzz --tests`
   succeeds on the stable toolchain. Stable Cargo may warn there that it does not know the
   workspace's `lints.cargo` manifest key; that warning is about the toolchain, not about this
   crate. `cargo +<clippy> clippy -p commonware-glue-fuzz --tests` reports no warnings, where
   `<clippy>` is the Clippy version pinned by CI (`clippy` under `[tools]` in
   `.github/toolchains.toml`).
4. **The regression suite passes.** `cargo nextest run -p commonware-glue-fuzz dkg::` runs every
   fixed-input scenario of the target. The suite holds the negative controls R19 requires: at least
   one for each invariant a run checks, in some target or, where R19 allows it, over built records.
5. **The fuzz target builds.** `cargo fuzz build --fuzz-dir glue/fuzz <target>` completes with no
   warnings and no errors.
6. **A smoke run is clean.** A short run of the target over its own corpus completes with no
   crash, hang, or out-of-memory, and with no invariant firing on a correct run. Executions per
   second are measured and reported. This document sets no throughput floor.
7. **The checks are not vacuous.** Each run reports, per invariant, how many records its check
   judged (R30). Across the regression suite of a target, every invariant that section 8 applies
   to that target and that is checked at run time MUST have a count above zero in at least one
   run. The one exception is I6 in `dkg_bootstrap`: no input of that target is known to fail a
   ceremony (section 9), so its regression suite MUST instead show, in at least one run, I6
   reported as unmeasured with the reason `no failed ceremony was reported` (section 8.1), and
   it MUST keep the negative control of I6 that R19 requires. `dkg_bootstrap_restarts` is not
   excepted. The smoke run of step 6 reports, per invariant, how many runs measured it and how
   many did not. The invariants of a target are the ids of its row in section 8.1. For I10 the count
   is the replay check's. The smoke run reports in the last aggregate line its process writes
   (section 5.4), which has no entry for I10.

Passing steps 1-7 for a target constitutes acceptance of that target.

## 11. Construction rules (normative)

The rules in this section are normative. The components they name describe the reference
implementation and may change without amending this document.

- **Mock group.** An element is the canonical encoding of a scalar; the generator is one; scalar
  multiplication is field multiplication; a signature verifies when it equals the product of the
  hashed message and the public key. `Variant::pairing` MUST panic with a message naming the mock
  group: nothing in the ceremony, the threshold operations, or the DKG module calls it.
- **Secret stores.** Each engine's secret store is held by the harness outside the engine, so
  that it survives a restart and can be read by the oracle. The two halves of the compromised
  identity never share one, and a bootstrap store is never reused for a reshare stack.
- **Correct application.** It MUST be a pure function of what it is given, so that every correct
  node computes the same payloads and verdicts.
- **Faulty application.** Its decisions MUST derive solely from the run's tape. It MUST be
  confined to the secondary half.
- **Channel splitting.** The split of a view-addressable channel MUST derive the view from the
  message itself. The DKG mask MUST derive the epoch from the message's channel prefix. Routing a
  message MUST NOT depend on when it is routed.
- **Restarts.** A restart MUST retain the node's storage and secret store and MUST reuse the
  identity's key and channel registrations. The schedule MUST come from the tape.
- **Observation.** The oracle MUST read outputs from what each engine reported or registered and
  shares from each engine's secret store. It MUST NOT infer agreement from harness-side
  bookkeeping about what should have happened. Records MUST be keyed by engine.
- **Probe blocking table.** The states in which a damaged or misplaced probe message must be
  blocked or must be ignored MUST be derived from the DKG probe's code, not copied from the
  stateful probe, whose rules differ.
- **Failure reporting.** A violated invariant MUST panic with a message naming the invariant, the
  engines involved, and the epoch or height, and the harness MUST print the run's structured
  controls and its tape before the process aborts. Together they rebuild the input as a
  fixed-input test; the bytes libFuzzer saves reproduce the run directly.
- **Report emission.** The aggregate a fuzz process writes MUST be the fold of section 5.4 over
  the reports of the runs the process completed, and writing it MUST NOT change what a run
  does or measures. The interval between two aggregate lines MUST be counted in completed
  runs, never in time (R4). The length of the interval, and how the process catches its own
  end, are the build's to choose. Whether libFuzzer's exit path lets the harness write at the
  end was not verified when this rule was written. A build that cannot write there is a
  finding against this document: the document changes first, and the build does not work
  around it.

## Choices made in the harness

These were not decided explicitly. Each is stated as the harness currently has it. The section
carries no number, so that Future work is section 12 and the last numbered section. Other
sections refer to it as "Choices made" and to its entries by item number.

1. **One node down at a time.** The restart schedule keeps at most one correct identity down at
   any moment, as stateful does: the fault bound is f = 1, so outages never overlap. A write held
   before a crash (item 13) belongs to that identity's outage: a write is held only while every
   identity is up, only for the identity whose crash is the next one on the schedule, only inside
   that crash's window, and no sooner than 50 ms after the restart before that crash completed. A
   link cut is not an outage and may coincide with one, and so may, in `dkg_state_sync`, a joiner
   that has started and is still syncing: neither is a Byzantine fault, and the targets assert
   safety only (R18), which must hold however many correct nodes are unavailable. A ceremony among
   correct identities then fails only when a link cut coincides with an outage or when a
   write held before a crash keeps an identity from its dealing window. Both are rare: a few
   sampled inputs in a thousand fail a ceremony, so I6 and the failure branch of I1 rest mostly on
   fixed inputs and negative controls.
2. **Mixed-set definition in I5.** A mixed set contains at least one share of each output.
3. **Negative reconstruction check in I3.** "One fewer" is checked through the recovery
   function, which must return an error. A direct interpolation of fewer shares is not checked,
   because the evaluation points it needs are private to the cryptography crate.
4. **I7 withdrawn.** It held only under synchrony: every correct ack reaches every
   correct dealer before the dealer's window closes. The DKG module closes that window at a
   block height. A correct node that the compromised identity keeps a block from sends its
   dealings late, can close its window holding some correct acks and not others, and then
   reveals a correct player. A masked half of the compromised identity can reveal the same
   player, which is the two reveals listing needs. No such run was observed in about 2,000.
   With I7 gone, a correct dealer that loses a valid ack and a correct player that fails to
   acknowledge a valid dealing are not detected.

   I7 would not have been a secrecy check even where it held. `Output::revealed()` is not a
   complete record of what the adversary knows: it lists a player only when `f + 1` selected
   dealers reveal its dealing, and in a reshare an adversary that already knew a correct
   player's previous share can work out a correct player's new share from fewer reveals, so
   that player is not listed. Since #5708 the ceremony's documentation also states the secrecy
   of the shared secret across a reshare as a conditional bound: it holds only if the adversary
   knew at most `f` correct players' previous shares before the reshare
   (`cryptography/src/bls12381/dkg/feldman_desmedt.rs`, lines 175-184, and the documentation of
   `Output::revealed`). No target checks that bound. Section 12 records what a check of it
   needs.
5. **Scenario and leaders in the reshare target.** The twins scenario is drawn over the five
   identities, not over a committee, because the committee of an epoch depends on the outcome of
   the ceremonies before it. The scenario's scripted leaders are used (A1): a scripted leader
   that is in the epoch's committee leads its view, in every epoch, and a view whose scripted
   leader is outside the committee is led by the round-robin rotation, as every view past a
   bounded prefix is. Under a prefix without a bound the script names the leader of every view
   of the epoch. The twins elector of `consensus` returns the scripted index as a committee
   position, so the harness has its own elector for this.
6. **I2 for a reshare.** A share is checked wherever a correct engine holds one. A registered scheme
   must name the agreed output's players and carry its public sharing, and a share registered with
   it must be the engine's valid share. The sharing must need the players' quorum, and the role must
   be the one the DKG module builds from the engine's key and share: a member only under the
   engine's own key, a verifier only outside the players. That is the material the harness's
   registrar builds a scheme from, so material it fails closed on (R14) is a violation at a correct
   engine. A share or a registration for an epoch that no correct engine holds a description of is a
   violation. The first cut only counted a correct engine that completed a successful ceremony as a
   player of its output and held no share of it; it was decided that this is a violation. An
   engine has completed the ceremony once it registered the scheme of the epoch the ceremony
   introduces, which the DKG module does only after it stored the share, so the check cannot fire on
   an engine that has not yet written its share. A node that enters an epoch without having played
   its ceremony, as a state-sync joiner can, is not a player that completed it. After a failed
   ceremony the same engines are held to the share the ceremony carried forward (item 8).
7. **I5 as checked.** Every set of `required()` shares with at least one share of each output is
   interpolated twice, once under each output's sharing, and neither result may verify under the
   group public key.
8. **I6 for a reshare.** Two things are checked under I6: every share a correct engine held
   for the previous epoch is valid under the output carried forward, and that output equals
   the previous one. A third is checked under I2 (`check_carried_shares_held`): a correct
   engine that registered the new epoch's scheme as a player of the carried output, and that
   held a share for the previous epoch, must hold that share for the new epoch. The DKG module
   stores it there before it registers the epoch: an engine that applies the boundary of a
   failed ceremony whose result it derived commits the new epoch with its share of the carried
   output, and an engine that starts in the epoch without a share under it reads the share
   back from the newest earlier epoch that holds one and stores it under the epoch at setup
   (`commit_epoch` in `glue/src/dkg/reshare/store.rs`, `recovered_share` in
   `glue/src/dkg/reshare/actor/setup.rs`). An engine that has not registered the new epoch is
   not judged, so a crash between deriving the failure and storing the share, or between
   storing the share and registering, leaves nothing to judge, and the engine that comes back
   stores and registers again. An epoch an engine entered through state sync is excused as in
   item 18: the module registers it from the state-sync material before it stores anything
   under it. An engine that held no share for the previous epoch has none to carry. The check
   runs in every target that checks a reshare run. A fixed input of `dkg_reshare_restarts`
   shows the store: after its failed ceremony four engines hold the share under both epochs.
   No ceremony failed in any run made while building `dkg_reshare` (about 7,400 runs and
   15,000 ceremonies), when the prefix was three views: with at most one compromised dealer
   among four, the three correct dealers are a quorum, and a prefix of a few views keeps none
   of their logs out of the inclusion window. A prefix without a bound does (item 22). The
   restart targets reach a failed ceremony as well.
9. **Payload placement (I18).** Added after the review of `dkg_reshare`: an early dealer log
   and an `EpochInfo` off the final block, two of the faulty application's deviations, had no
   oracle. Each engine's observer records the height and the kind of payload (none, dealer log,
   `EpochInfo`) of every finalized block marshal delivers to it, and the reshare measurement
   judges every record of a correct engine by the schedule every engine is configured with: the
   fixed epoch length, with the midpoint and the final block as `commonware_consensus` defines
   them. The rules are the verdicts of `reshare::Application::verify` on a block's height and
   payload kind in a continuous reshare. Off the final block it rejects an `EpochInfo`, and a
   dealer log before the midpoint. On the final block it accepts only the `EpochInfo` the node
   derived, which a reshare always has, also after a failed ceremony, and it stays unresolved
   at a node that cannot derive one.

   The rules are safety. A block is finalized by three finalize votes of four, so by two
   correct nodes at least, and a correct node votes to finalize only a block it certified. It
   certifies a block it built through the wrapper, which selects payloads by the same windows,
   or a block whose verification by the wrapper returned true. A correct node need not have
   certified the parent of a block it certifies, but the block's notarization needs three
   votes of four and so the vote of a correct node other than the proposer, which verifies a
   block only on ancestry it certified. The one exception is an epoch's final block proposed again
   later in the epoch, which is notarized again only if correct nodes certified it in one of those
   two ways before. A node that is behind is delivered the same chain. The height-zero block is
   exempt: marshal delivers it to every engine with the `EpochInfo` of epoch zero, and no node
   verifies it.

   Left out, because the DKG module does not judge a dealer log when it verifies a block, so
   the compromised identity can put such blocks on the chain: a log signed by another dealer,
   which is recorded like any other, and a second log of one dealer, a log signed by no dealer
   of the epoch, and a log that does not verify, which are ignored once finalized. Whether the
   final block's `EpochInfo` is the right one is I1 and I4. The final-block rule has
   record-level controls only: a correct engine that is given a final block without an
   `EpochInfo` panics, which I8 reports first.
10. **Registrations and held shares (I2).** The check of item 6 judges an engine by every share its
    store ever held, so it passes an engine whose restart does not find its share again, and it
    accepts a member's registration from a player that holds a share. A second check covers both:
    whenever an engine registers the scheme of an epoch its store ever held a share for, the
    registration must be a signer's and carry that share. It covers the first output, a reshared
    output, and an output a failed ceremony carried forward. The check reads the shares by the epoch
    they were stored under, so on its own it passes an engine that registers the new epoch without
    having stored the carried share under it. Item 8 requires that share under the new epoch of
    every engine that reached it, and this check then requires every registration of the epoch to
    carry it. It is sound because the DKG module builds every registration from the share it reads
    from the secret store, stores a share before it registers with it, and prunes an epoch's secrets
    only once it is two epochs past it, while a restart returns an engine at most to the epoch whose
    final block its marshal had not recorded. Every driver of the reshare stack calls the check: the
    restart and state-sync drivers, and `dkg_reshare`, whose correct engines do not restart and are
    the only ones judged.
11. **Probe blocking table (section 11, I14).** Read off `glue/src/dkg/probe`. While
    discovering, the probe decodes every message first and blocks the sender of one with no tag,
    an unknown tag, or a finalization cut short, whatever it awaits; it ignores a request. A block
    response is decoded past its epoch only from the peer the block was requested from, which is
    blocked if it is cut short; from anyone else it is ignored, whole or cut past its epoch. A
    latest reply is judged only until the floor is selected: the sender that is not a dealer is
    blocked, whatever the reply; a stale reply is set aside, from either chain; a foreign reply
    that is not stale blocks its source. The probe records no reply while it has no subscriber, so
    it selects nothing then. A boundary finalization is judged only while the boundary is awaited:
    a foreign one blocks its sender, unless the probe still holds the sender as a responder, in
    which case it is ignored. The probe holds a peer from the delivery of the peer's valid one
    until it asks another peer, or every peer, for what it asked that peer alone. The identity that
    is not a dealer is not blocked for a valid boundary finalization or block: the probe asks every
    peer for those, and takes them from it. While serving, the probe reads requests only: it
    blocks the sender of a message with no tag or an unknown tag, and of nothing else, and answers
    a request from its marshal, which holds nothing. Every other delivery must not be blocked.
    With the boundaries the driver adds (7.4), the probe's state is known at every delivery, and
    nothing is required only where a correct probe would have selected its floor or resolved its
    artifact and the run shows that it did not, which a stalled run may. Each block the probe
    places is attributed to the delivery it was processing, the probe may block only that
    delivery's sender, and the pairs the network recorded must be exactly the blocks the probe
    placed, so a block by a source is a violation too.
12. **I12 as checked.** The replies are every whole latest reply of the fabricated chain that is not
    stale, delivered by the source that built it, once per source, since the last request for latest
    finalizations and before the first subscription resolved, in the order the probe took them. Each
    reply stands for the finalization its source was recorded to hold as its latest. There must be
    at least `f + 1` of them, 2 with 4 dealers, and the floor must be the highest of exactly the
    first `f + 1`: a reply delivered after those, however high, must not change it. That is the
    moment the probe selects, as its documentation states (`glue/src/dkg/probe/mod.rs`, lines
    73-75). It records at most one valid reply per dealer since its last request, selects after
    each one it records, and the selection resolves once `f + 1` are recorded
    (`glue/src/dkg/probe/actor/discovery.rs`, lines 301-351). Once the floor is selected the probe
    judges no latest reply and sends no request for one, so the floor is final. A valid reply that
    reaches a probe with no subscriber is not recorded and discards what was (`discovery.rs`, lines
    332-335). The probe drops a closed subscription only when it next wakes, and the driver wakes
    it as soon as the program drops its last one (7.4). The replies as listed include such a reply
    all the same, which changes nothing: a probe with no subscriber records nothing, and the next
    subscription makes it ask again (`discovery.rs`, lines 201-214), from where the replies are
    listed anew. The negative control is a run in which the
    third source's higher reply is delivered after the first two and before the boundary, with that
    reply's finalization planted as the floor.
13. **Writes are held around a scheduled crash (R16, A6, 7.3).** A crash is an abort of the
    engine's tasks, and an abort takes effect only where a task is suspended. The harness secret
    store and the deterministic runtime's storage complete every write in one poll, so a crash
    never fell between two writes an engine makes one after the other, nor between a write and
    the moment the engine learns it completed. The restart targets therefore pace an engine's
    durable writes: the writes of its secret store, and the writes, resizes, and syncs of every
    blob it opens. A write the engine starts in a window before the crash the schedule holds
    for it may be held: suspended before it is applied, or after it is applied and before its
    future resolves, until 20 ms past the scheduled time of the crash, which drops it. A held
    write whose crash has not come by then completes. Reads are never held. A driver paces an
    engine by giving it a secret store paced by the run's program; the stack paces the engine's
    storage like its store, at every start. Both restart targets pace every engine, and so does
    the state-sync target (item 17). The Twins targets and the probe target pace nothing, and
    their runs are unchanged.
14. **What a held write may leave behind (R14, R16).** Only what a crash between two writes
    leaves on a store that is slow and correct. A write dropped before it was applied is absent
    as a whole. A write dropped after it was applied is as durable as the same write is once
    its future has resolved, and no more. A write of the secret store, a blob write made with
    its own sync, and a sync are in place as a whole, although the engine never saw them
    complete. A blob write made without a sync, and a resize, changed the engine's open blob
    only and are lost with it at the crash, as they are when the engine saw them complete and
    had not synced yet. A sync dropped before it was applied covers nothing, so the writes it
    was to cover are lost with the blob although their futures had resolved, which is again
    what an unsynced write comes to without pacing. What was durable when its future resolved
    is never lost: a write of the secret store, a synced write, and everything a completed
    sync covered. No write is applied in part, and none is applied after its future was
    dropped. After a crash the secret store may therefore be ahead of the engine's journals,
    or behind them, by the writes that were in flight. Nothing a restart retained before is
    wiped or rolled back, which is the state loss R16 excludes. A blob change made without a
    sync would survive if another task of the engine synced the blob while the write was held.
    The harness does not look for that.
15. **The caller's record (R24).** The DKG module leaves the floor of a state sync to its caller. A
    node with the stateful layer keeps it in that layer's startup plan, whose completion only the
    stateful actor can record, and the reshare stack has no stateful layer (R13). The harness
    therefore keeps its own record in the joiner's storage, one value under the engine's partition:
    the floor of a sync in progress, or the height of the floor of the sync that completed. The
    floor is written, with a sync, before marshal or the state-sync plan is given it. The driver
    requests state sync at every start of the joiner, and a start syncs unless a completion is on
    record. A start that syncs hands the floor on record to its probe, and enters from the later, by
    round, of that floor and the floor the probe sampled, paired with the description the probe
    returned; on a tie the floor on record stays.

    The record is written through the engine's paced storage, so a crash of the joiner can drop a
    write of it (item 17). The caller's code is the harness's and the engine's tasks run it. All of
    it, the waits on its storage included, runs as belonging to no engine, so a panic in it is
    reported as the harness's and not as the engine's (I8).

    Two of the caller's obligations make no difference to a run of this target: handing the floor on
    record to the probe, and pairing with the later floor by round. They show only when a member the
    probe samples is an epoch behind the floor on record at the joiner's restart, which this target
    does not produce. In the review, with either left out every test passed, and with both left out
    4,000 inputs gave identical reports. Each now has a unit test that fails when it is left out: a
    start whose ledger holds a floor and whose probe sampled an earlier round must enter from the
    floor on record, and the probe's configuration at a restart must carry the floor on record.
    These are tests of the harness's own caller, on the values it computes. They are not tests of
    the DKG module: what the probe does with the floor it is handed is for `dkg_probe` to check.
16. **When a sync is complete (R24, I15).** A sync is complete once its completion is on the
    caller's record, and not before. This is how the stateful plan has it: a floor stays on that
    plan, and every start syncs, until the stateful layer has recorded the completion. The caller
    records the completion once marshal has delivered the floor's block to the engine, which marshal
    does only after it has stored the floor and recorded the height below it as processed. The
    delivery is read from what the engine reports, where a block an earlier start was delivered
    counts too. Until the completion is on record every start of the joiner syncs again, through the
    probe, and may enter from a later floor. Afterwards a start gives the probe no floor, starts
    marshal from what it stored, and provides no material; the DKG module still resolves the
    material it persisted for as long as marshal is in the synced epoch. A joiner crashed after the
    completion is on record and before its caller reported it shows the completion at its next start
    (item 19).

    The first cut called a sync complete once marshal reported the floor as processed, and recorded
    that afterwards. A joiner crashed between marshal's write and the caller's had then completed
    its sync by that definition, and its next start repeated it, which R24 forbids: 10 of 4,138
    syncing starts in the review, and 11 of the 1,659 entries of 1,500 sampled runs with pacing,
    where a held write of the record widens the gap. Each of them entered from a later floor. A
    caller cannot close that gap through the public interfaces. What marshal durably holds is told
    only by the value its initialisation returns, and the initialisation takes the floor marshal
    starts from, which the caller must have chosen by then; a caller would have to initialise
    marshal twice at every start that finds a floor on record. The caller in the DKG example node
    (`examples/dkg`) does not close it either: its plan stays in progress, with marshal past the
    floor, until the stateful actor records the completion, and a restart before that selects a
    floor again. So the definition was changed and no check was: the case is an interrupted sync
    that resumes, which R24 allows. It is also a state a node reaches and the target should: the DKG
    module is started from new material while marshal and the reshare journal hold what an earlier
    floor left.
17. **Restart schedule of the state-sync target (R16, R23, item 1).** The schedule over all nodes is
    drawn from the tape with the sampler of the restart targets, over five identities, and its first
    outage is due when the input says. The joiner's own restart is one more outage. The environment
    lays them out one after another in the order they are due, at the moment the joiner starts: an
    outage that is due while another lasts, or less than 50 ms after that one's restart is due,
    starts 50 ms after that restart is due. At most one identity is down at any moment, the crash
    after a restart is due no sooner than the tape's own schedule has it, and a
    crash of the joiner's own clock is late only when another identity is down, or has just come
    back, at its time. The first outage is exempt: it may be due with the joiner's start, after
    which nothing is waited for. The driver lays out nothing and crashes nobody itself. The
    environment starts the four identities that start at genesis, starts the joiner when the
    driver's stack says that the join height has been applied, and plays every outage through the
    starts, crashes, and waits every restart target is played with.

    Every engine is paced as item 13 describes, the joiner's included, at every start. The pacing is
    laid out with the outages of the schedule and the joiner's own, and is given the times they got
    when the joiner starts, so the schedule it holds writes for is the schedule that is played.
    While it syncs the joiner makes its caller's record, the material of the state-sync plan, and
    marshal's floor durable one after another, and its own crash falls between them.

    One identity is impaired at a time here too (item 1), and the joiner counts as follows. A
    joiner that has not started is as unavailable as an identity that is down, so it is the run's
    impaired identity from the start of the run until its first start has completed: until then no
    identity is crashed and no write is held, and its span is on the pacing's trace, where the
    overlaps are counted. Once it has started it counts like any other identity, also while it
    syncs: it is impaired while it is down or has a write held, and not otherwise, so the schedule
    may crash another identity, and hold that identity's writes, while the joiner's probe discovers
    and while its marshal fetches the floor. A start is complete once the engine is spawned, and
    the joiner's first start is a first start: no write waits 50 ms for it, because this target's
    schedule puts no such distance after it. The rule counts identities that are down or slow. A
    joiner that is in the committee and has no share yet does not sign, so a crashed member beside
    it leaves two of four not signing although one identity is impaired.

    A constant in the driver, `RESTARTS_BEFORE_JOIN`, decides whether a joiner that has not started
    counts. It is off, and it does: the schedule's clock starts when the joiner starts, and until
    then the four identities that started at genesis all run. 7.5 also lists the join before the
    crashes, and the stateful state-sync target runs its schedule after its joiner has started. With
    the constant on, a joiner that has not started does not count, and the schedule's clock starts
    with the run: an outage that is due before the join height is applied crashes an identity that
    started at genesis and brings it back after its downtime, or when the join height is applied if
    that comes first and the shortest downtime of 100 ms has passed; one that names the joiner then
    does nothing; the rest keep their times. No write is held before the joiner has started in
    either position. Both positions are played by the environment and have tests. Only the off
    position is fuzzed.

    What each position costs. Off: a ceremony fails only in the ways item 1 names, so a state
    sync into an epoch whose ceremony failed, and the walk back by which the DKG module recovers a
    share for such an epoch from an earlier one (`recovered_share`), are next to unreachable; and
    after the join a member joiner without a share beside one crashed member still leaves two of
    four not signing. On: with the joiner in the committee, an outage before the join leaves two of
    four members out, which is more than the fault bound of one.
18. **I2 for the joiner (I17, item 6).** The joiner is excused a share exactly where the DKG module
    makes it register an epoch whose ceremony it did not play. For every floor the joiner entered
    from, that is the floor's epoch, which the reshare actor registers from the state-sync material
    before it applies a block. If the floor lies past the midpoint of its epoch, it is also the next
    epoch, which the actor registers as a follower from the epoch's final block. Whether the floor
    lies past the midpoint is read from the height at which marshal delivered the floor's block to
    the joiner, which happens before the joiner can apply that final block. In every other epoch the
    joiner is held to I2 like any engine: with a floor up to the midpoint it plays the ceremony of
    the floor's epoch, and with a later one the ceremony after it, and as a player of the output it
    must hold a share. The check of item 10 applies to all five engines.

    An entry excuses an epoch only if the joiner had not registered the epoch's scheme before the
    entry. A joiner syncs a second time when a crash finds the completion of its sync not on its
    caller's record (item 16), and a write of the completion that the pacing holds lets the engine
    run on until that crash: it can end a ceremony, store the share the ceremony gave it, register
    the next epoch, and then be started again from a floor in that epoch. The first cut excused
    every epoch an entry named, so a joiner that had ended a ceremony as a player without storing
    its share was excused the share by the second sync. The records now keep, with each step of the
    caller, how many schemes the engine had registered when the step was taken, and an entry excuses
    an epoch, the floor's or the one a floor past the midpoint makes the joiner follow into, only if
    none of those registrations is of that epoch.

    The narrowing asks nothing the DKG module does not give. The floors of a joiner's entries never
    move back (I15). An epoch that no entry so far excuses is therefore one the joiner reaches only
    by applying the final block of the epoch before it, as an engine that takes part in that epoch's
    ceremony: every floor so far lies at or before the midpoint of the epoch before it. A scheme
    registered for such an epoch is registered at the end of that ceremony, which the module does
    only after it stored the share the ceremony gave it, or at a start that finds the engine in the
    epoch, from the share the store holds. Either way the share is on the store's record if the
    engine is a player of the output, whatever an entry names afterwards. A registration that
    follows an entry that excuses its epoch stays excused, whichever start makes it.

    The exemption follows `reshare/actor/setup.rs` and `reshare/actor/follower.rs`: it covers the
    registrations the DKG module makes without a ceremony and no other. That is the exemption I17
    states: the joiner must hold a share of every other output it is a player of.
19. **I15 as checked.** The joiner's caller reports three kinds of step: a start, with what it found
    on record and whether it chose state sync; the material a syncing start entered from; and the
    completion. Walking them in order, a start after a floor was selected must find a floor on
    record that is not earlier; a floor selected later must not be at an earlier round; and after
    the completion every start must find it on record and must not sync. A start that finds a floor
    or a completion on record that no step reported is accepted: the engine was crashed between the
    write and the report, which a held write of the record makes common. I15 has no clause on what
    makes a start choose state sync: the driver requests state sync at every start of the joiner,
    so a request is a constant of the target and the record of a start carries none.

    Every clause of I15 reads records that the harness's own joiner writes about its own ledger. I15
    therefore checks that the harness honours R24, and it cannot detect a defect of the DKG module.
    What detects a defect of the DKG module in this target is I2, by both of its rules (items 6 and
    10), I16, I17, and I18. The review confirmed this by changing the production code in a scratch
    copy. Of four changes to the state-sync path none tripped I15, I16, or I17. An engine that
    follows from a floor at the midpoint, where it should play, was caught by the first rule of I2,
    and a state-synced engine that registers without its share by the second. Two were caught by
    nothing and are known blind spots: an engine that never follows, and a probe that picks the
    lowest reply of its sample.
20. **I16 as checked.** What the nodes that started at genesis finalized is read from what their
    marshals report: every finalized tip, with the round of its finalization and the height and
    digest of its block. The floor the joiner starts from must be one of them, at the same round
    over the same block, and what the joiner's own marshal reports does not count. This is the
    probe's own guarantee seen from the other side: the floor is the newest finalization a member of
    the first committee had stored when it answered, and marshal reports a tip whenever it stores a
    newer one. The description must be of the floor's epoch and equal the one those nodes were
    delivered in the final block of the epoch before it, or the configured one for the first epoch.
    The clause on the description's epoch never reports a run. The DKG module panics when it is
    given a floor and a description of different epochs (`state_sync::Plan::init`), the panic is the
    engine's, and I8 is judged first. The clause costs nothing and is kept, with its control over
    built records.
21. **I17 as checked.** Marshal delivers the joiner nothing below its floor, so every block and
    every description the joiner was delivered is compared with what each other engine was delivered
    at that height and for that epoch, a block also with every block another engine's marshal
    reported finalized at its height, and a second block at one height at the joiner is a
    violation. The measurement runs I8, then I15 to I17, then the reshare checks, so a description
    on which the joiner differs is reported under I17. The comparison of descriptions repeats I1,
    which compares every engine's description of every epoch, the joiner's included, and which would
    report the same defect if I17 did not come first. The comparison of blocks has no other check.

    A comparison only finds a defect where another engine was delivered the height or the epoch,
    so a block or a description only the joiner holds would pass every comparison. Each must
    therefore also be traced to the nodes that started at genesis. A block is traced if one of them
    was delivered it, its marshal reported it finalized, or its application built it or verified
    and accepted it. Each engine's application is wrapped in the reshare stack, below the reshare
    wrapper, to record the last. A description is traced if one of them was delivered it, or if the
    block that carried it to the joiner, the final block of the epoch before, is traced: a block's
    digest covers its payload. A description is judged before the blocks, so one the joiner alone
    holds is reported as a description.

    The trace never waits on another engine's marshal, so it cannot turn a run that ended early, or
    a node that is down, into a violation. A finalization needs the finalize votes of three of the
    four members of a committee, at most one of which is the joiner, and a correct member votes to
    finalize only a block it certified: one its application built, or one its application verified
    and accepted after the reshare wrapper's checks. The final block of an epoch proposed again
    later in the epoch is certified without the application, and is notarized again only by members
    that certified its first proposal or know it finalized. A block a finalized block extends was
    the certified parent of a block a correct member notarized. So every block marshal can deliver
    has a record of a node that started at genesis from before any finalization of it existed. The
    records are kept outside the engines and survive their restarts. A sweep of 2,000 decoded inputs
    of the target with the schedule's clock in each position of `RESTARTS_BEFORE_JOIN` reported
    nothing, and three of the blocks the joiners were delivered were traced by an application's
    record alone: no node that started at genesis had been delivered them or held their
    finalization when the run ended.
22. **Length of the adversarial prefix (A1).** The Twins inputs draw the prefix: each length
    from 1 to 16 views is as likely as any other, and one draw in five sets no bound. Fixed
    inputs of the regression suite use three views. The twins generator of `consensus` counts
    the scenarios of a length exactly and cannot count a sampled scenario of more than about
    twelve rounds, so a script of more than eight views is made of two generated scenarios, the
    second drawn from entropy of its own. The compromised identity is the one the first names;
    the second contributes its partitions and leaders. A sustained scenario repeats one
    partition and is generated whole at any length. Under a prefix without a bound the script
    of sixteen views starts over whenever it ends, in every epoch, so no view of the run is
    whole: the three correct identities still exchange every message among themselves, and the
    compromised identity's halves stay partitioned for the whole run. The script type and its
    draw are shared with the stateful Twins targets (`stateful/network.rs`,
    `stateful/input.rs`), which take the same prefix in leader terms.

    In `dkg_reshare` the script also names leaders (item 5). A bounded prefix scripts the
    leaders of at most sixteen of an epoch's views and the rotation leads the rest, so every
    correct dealer leads views of the inclusion window. Without a bound the script leads every
    view, and a sustained one names a single leader for the whole epoch: a correct dealer that
    leads no view after the midpoint gets no dealer log into a block, and with fewer than three
    logs the ceremony fails. Of 60 decoded inputs run through the driver, the 46 with a bounded
    prefix all completed with every ceremony successful, and of the 14 without a bound all
    completed and 6 held a failed ceremony, which I1, I2 and I6 then judge as in the restart
    targets. All 60 decoded bootstrap runs completed, at every prefix. No invariant fired.
23. **Unmeasured runs (R30).** Until this change section 9 excluded the reporting of runs that
    measured nothing: the harness did not label or count them, and the reach of the oracle was
    read from libFuzzer coverage. Withdrawn after the spec review (CR-001): a run that cannot
    measure an invariant is reported as unmeasured, never as passing. Nothing that was detected
    is lost. What is new: a campaign whose runs no longer reach a ceremony, an artifact, or a
    sync is visible.
24. **I14's count (R30, 7.4).** I14 judges deliveries, not artifacts, so a probe run without an
    artifact can still measure it. Its count is the deliveries for which the check required a
    block or required none. A delivery for which nothing is required (item 11) is left out, so
    that a run in which every delivery is of that kind reports I14 as unmeasured and not as
    passing. From the spec review (CR-007): until then 7.4 said that a run without an artifact
    reports I12-I14 as unmeasured.
25. **Units of the R30 counts (8.1).** R30 said "how many records the check judged" and fixed
    the unit for I14 only (item 24). The acceptance list for R30 (2026-11-18) could
    therefore assert zero against positive and no exact value. Section 8.1 now names one unit
    for each invariant, by the rules it states. What is worth knowing about the choices:
    - I1 counts comparisons, and leaves out the configured `EpochInfo` of epoch 0, so that a
      reshare run in which no ceremony completed does not show I1 as measured.
    - I6 counts failed ceremonies, not shares, so that a failed bootstrap, after which no share
      is held, is measured.
    - I8 and I9 forbid an event. In a target of correct nodes only, a passing run records no
      block, so a unit per recorded block could never be above zero there and section 10,
      step 7 could not pass. Their unit is the run.
    - I15 counts only the steps one of its three clauses judges. A joiner that starts once and
      completes its sync leaves I15 unmeasured. Measuring it takes a start of the joiner after
      a floor was selected.
    - I10 compares two runs, so its count is the replay check's and no report carries it.

    What the harness detects is unchanged: no check was added, removed, or changed.
26. **One reason per invariant (R30, 8.1).** Until this change R30 named the reason as "the
    reason the run gives (no ceremony completed, no artifact was emitted, no delivery was
    judged, no sync completed, the run timed out)". It did not say which invariant gives which,
    nor which one a run gives when two hold. The five also did not cover every case: a run
    whose ceremonies all succeed leaves I6 unmeasured, and none of the five is true of it.
    Section 8.1 now gives each invariant one reason, which names the record its check lacked.
    Four of the five strings stay: `no ceremony completed` (I4), `no artifact was emitted` (I12,
    I13), `no delivery was judged` (I14), and `no sync completed` (I17). "The run timed out" is
    no longer the reason of an invariant: it is true of the run and not of a check, so the
    report states it once, as how the run ended. Nothing that was reported is lost. New
    strings: those of I1-I3, I5, I6, I8, I9, I15, I16, and I18 in the table of 8.1.
27. **Report surface (5.4).** R30 fixed what is reported, not where, and 12.2, step 5 left it
    open. Section 5.4 fixes the part the regression tests need: the report is the value the run
    function returns, and the smoke aggregate is the value of one function over such reports.
    Each of the six targets already has a run function that returns a report
    (`run_dkg_bootstrap` and its five siblings), and it is what the fixed-input tests call.
    Where a fuzz process writes the report and the aggregate was a separate decision: R30 was
    accepted so that a campaign whose runs no longer reach a ceremony, an artifact, or a sync
    is visible (item 23), and the place of the output decides whether a campaign shows it. A
    first text of this item printed a run only on request, through `GLUE_FUZZ_LOG`. It was
    withdrawn the same day, before any review: a campaign run without the variable would show
    nothing. The decision of 2026-11-18 was "Compact aggregate always": every fuzz process
    always writes a short per-invariant aggregate, at intervals and at its end, and the full
    report of each run only with `GLUE_FUZZ_LOG`. Two options were not taken: writing both
    only with the variable, and printing every run that has an unmeasured invariant, as the
    stateful harness prints a run that measured nothing (`glue/fuzz/src/stateful/runner.rs`),
    which here would print nearly every run because of I6. Beside the decision, these are the
    writer's choices: standard error, where the report line of `glue/fuzz` goes today; the
    form of the aggregate line; that the end is one the process reaches by itself; and that
    the interval is counted in runs (section 11, Report emission).
28. **Per-target set of run-time invariants (7.1-7.5, 8, 8.1).** Until this change section 8
    said "I1-I6 apply to correct nodes in the four ceremony targets and the state-sync target"
    and "I8, I10, and I11 apply to every target", and the measurement steps listed "I1-I3 and
    I6-I11" (7.1), "I1-I11" (7.2), "I1-I6 and I8-I11" for both restart targets (7.3), "I8, I10,
    and I11" (7.4), and "I1-I6, I8-I11, I15-I17, and I18" (7.5). The lists put I4 and I5 on the
    bootstrap targets, which have no reshare boundary; they spanned the withdrawn I7; and they
    listed I10 and I11 as checks of a run, where I10 compares two runs and I11 constrains the
    working tree (R19). Section 8 and 7.1-7.5 now agree with the table of 8.1. The table is the
    matrix of the R30 acceptance list, which is right, with one refinement: I10 stays in
    every row, and its count is the replay check's, not a run's. No check was added or removed:
    no bootstrap target checked I4 or I5 before.
29. **I6 in `dkg_bootstrap` is excepted from section 10, step 7.** Until this change step 7
    required, for every target, a count above zero in at least one regression run for every
    invariant of its row in 8.1, I6 in `dkg_bootstrap` included. The review of items 25 to 28
    found (SR-001) that the document did not know whether a bootstrap ceremony can fail under
    that target's adversary (R15, R17, A1, A2). A check then found no failing input, in the
    4,330 runs section 9 gives, and the reason section 9 gives from the code. A failed
    bootstrap under Twins is likely unreachable and not proven so. The decision of
    2026-11-18 was "A: exclude I6 on bootstrap": step 7 excludes I6 on `dkg_bootstrap`; its
    regression suite must show I6 reported as unmeasured with its reason; I6 keeps its
    negative control there. Three options were not taken: widening the bootstrap adversary
    until a ceremony fails, which needs a change under `glue/src`; letting a planted failure
    count as the measured run, which is not a healthy run; and removing I6 from the target's
    row in 8.1, which loses the check if a failure ever becomes reachable. What is no longer
    required: a real failed ceremony in the regression suite of `dkg_bootstrap`. What stays:
    the check runs in every run of the target, its entry stays in every report (8.1), its
    negative control stays (R19), and `dkg_bootstrap_restarts` is not excepted. The exception
    is about what the regression suite must show, not about what a run reports: a run of
    `dkg_bootstrap` in which a correct engine reports a failed ceremony gives I6 a count
    above zero, as R30 and 8.1 require. Future work 12.1, row 28 records the cost.

## 12. Future work

Nothing in this section is normative. It adds no requirement, property, adversary rule, or
invariant, and it changes none. Lifting a row that names an R, P, A, or I id is a change to
that id: it starts in this document and needs a decision first.

### 12.1 Choices that narrow coverage or scope

Each choice below narrows what the targets reach or what the oracle judges. "Where" names the
id or the item that states the choice. "How to lift it" is a direction, not a design.

| # | Choice | Where | What it costs | How to lift it |
|---|---|---|---|---|
| 1 | Safety only | R18; section 9, Liveness | A stall, a ceremony that never completes, and a node that never rejoins are healthy outcomes. No defect of progress is reported | Change R18 to assert progress in a window with no fault: past a bounded prefix every view is whole (A1), and the restart schedule is bounded (7.3) |
| 2 | Runs that measured nothing are not reported | Choices made, item 23 (was section 9, Reporting of runs that measured nothing) | Lifted by R30 | Lifted by R30 |
| 3 | A bootstrap outcome is read from completions only | Section 9, The outcome of a bootstrap no correct engine reported; 7.1 | When a run ends between the write of a share and the next report, I6 is not checked, and with three holders the I3 clause compares nothing | The engine exposes its stored final block through no interface (7.1). Lifting needs a public read of it under `glue/src` (see row 20) |
| 4 | No coverage target | Section 9, Coverage targets | Nothing shows when a target stops reaching new code of `glue/src/dkg` | Track line coverage of `glue/src/dkg` per target from the campaign's coverage reports, and act on the gaps |
| 5 | Mock group only | R6, G8; section 9, Real BLS | A defect that needs the real curve (an encoding, a subgroup check, a pairing) is out of reach here. `cryptography/fuzz` runs the ceremony over `MinPk` and `MinSig`, without the DKG module (`cryptography/fuzz/fuzz_targets/bls12381_dkg_feldman_desmedt.rs`) | A variant of one ceremony target over `MinSig`, run at a low rate. It changes R6 and G8 |
| 6 | Identities stay on ed25519 | R8; section 9, A mock identity signer | Run time only. No coverage is lost | As section 9 states: reconsider when measurement shows ed25519 is a visible share of run time |
| 7 | One fault model and one reveal rule | R9 | `N5f1` (`utils/src/faults.rs`) is never run. `Reveal::V0` is never run either; it is deprecated in `feldman_desmedt.rs` | Let the input select the fault model. The committee size changes with it (row 8) |
| 8 | Committee of 4, at most 3 epochs of 32 blocks | R10, R11; section 9, Other configurations | `f` is always 1. Quorum arithmetic for `f > 1` is not exercised, and no run chains more than three reshares | A second fixed committee size with `f = 2`. Its run time per ceremony is not measured |
| 9 | The compromised identity runs real code only | A2, A3, A4; section 9, Cryptographically invalid ceremony messages to correct nodes | No correct node receives a dealing with a bad share or commitment, or an ack with a bad signature, so its handling of them is not exercised. `cryptography/fuzz` covers the ceremony functions, not the actors | A faulty dealer built in the fuzz crate that sends such messages on the DKG channel. It is a new adversary rule |
| 10 | No Simplex fault beyond the twins partition | Section 9, Consensus-level faults beyond the twins partition; R20 | The DKG module is not run under other Simplex deviations | R20 forbids a dependency on `commonware-consensus-fuzz-*`, so a deviation is either written in `glue/fuzz` or R20 changes |
| 11 | One identity impaired at a time in the restart and state-sync targets | Choices made, items 1 and 17; section 9, A failed reshare under Twins | In the restart targets a few sampled inputs in a thousand fail a ceremony (item 1), and `dkg_state_sync` fails one only in the same ways (item 17). In these targets I6 and the failure branch of I1 rest mostly on fixed inputs and negative controls. Row 25 covers `dkg_reshare` | A schedule in which a link cut coincides with an outage, or a held write keeps an identity from its dealing window, more often: the two ways item 1 names |
| 12 | No state loss | R16; section 9, State loss | A wiped or rolled-back secret store or journal is never produced, so what the DKG module does on one is not exercised | A separate target with its own oracle, since the module answers a corrupt secret store with a deliberate panic (I8). It changes R16 and P3 |
| 13 | The Twins targets restart nothing, and the restart targets run correct nodes only | R15, R16, P2; section 9, Restarting the compromised identity | No run has both a Byzantine dealer and a crash. The #5721 path is unreachable (12.2, step 3) | 12.2, step 3 |
| 14 | No corrupted bytes between correct nodes | R17; section 9, Corrupted bytes between correct nodes | A correct node's handling of bytes that do not decode on the DKG channel is not exercised in the ceremony targets | Junk on the DKG channel sent by the compromised identity, as the probe program sends junk (R22). It is a new adversary rule |
| 15 | No stateful layer | R13; section 9, The stateful layer; Choices made, items 15 and 16 | `StatefulActor`, QMDB, and the stateful startup plan are replaced by the harness's own caller record, so their interplay with DKG state sync is not run. I15 checks the harness's caller only (item 19) | A target that runs the stateful stack with the DKG module. It changes R13 |
| 16 | Bootstrap takes no scripted leader and no faulty application | A1, A3 | `bootstrap::Engine` owns its elector and its application, so the bootstrap Twins target has the partition and the DKG mask as its only faults | Needs a way to supply either from outside, which is a change under `glue/src` (row 20) |
| 17 | The "one fewer" check goes through the recovery function | Choices made, item 3 | A direct interpolation of `required() - 1` shares is not checked | The evaluation points are private to the cryptography crate. Lifting needs a public way to get them (row 20) |
| 18 | I7 withdrawn; no check of share secrecy | I7; Choices made, item 4 | A share of a correct player published on chain, a correct dealer that loses a valid ack, and a correct player that does not acknowledge a valid dealing are not detected | 12.2, steps 1 and 2 |
| 19 | Dealer logs are recorded by kind only | I18; Choices made, item 9 | Which dealer signed a log, how many logs a dealer has on chain, whether a log verifies, and what a log reveals are not judged. No check can read a selected log | Record each finalized dealer log as a whole (12.2, step 1) |
| 20 | Fuzz-only change scope | R3, G7, I11; section 9, Modifying any file outside `glue/fuzz/` | No hook or read access is added to the code under test. Rows 3, 16, and 17 cannot be lifted | Each access is a separate decision |
| 21 | An unsynced change that another task syncs is not looked for | Choices made, item 14 | A blob change made without a sync survives a crash if another task of the engine synced the blob while the write was held. The harness does not model that | Track which task synced which blob while a write is held |
| 22 | Only one position of `RESTARTS_BEFORE_JOIN` is fuzzed | Choices made, item 17 | A state sync into an epoch whose ceremony failed, and the walk back in `recovered_share`, are next to unreachable | Fuzz the other position too. Item 17 states its cost: two of four members can be out before the join |
| 23 | Two caller obligations make no difference in `dkg_state_sync` | Choices made, item 15; R24 | Handing the floor on record to the probe, and pairing with the later floor by round, are covered by unit tests of the harness's caller only | Produce a member that is an epoch behind the floor on record when the joiner restarts |
| 24 | Two known blind spots of the state-sync oracle | Choices made, item 19 | An engine that never follows, and a probe that picks the lowest reply of its sample, are caught by no invariant of `dkg_state_sync` | Not designed. For the second, I12 judges the probe's selection in `dkg_probe` |
| 25 | In `dkg_reshare` a ceremony fails only under a prefix without a bound | Choices made, items 8 and 22; section 9, A failed reshare under Twins | Of 60 decoded inputs of `dkg_reshare`, 6 held a failed ceremony: 6 of the 14 with a prefix without a bound, and none of the 46 with a bounded prefix (item 22). One draw in five sets no bound. A failed reshare is therefore reached far more often here than in the restart targets (row 11), but never next to a bounded prefix. No bootstrap ceremony is known to fail under Twins: none did in 4,330 logged runs of `dkg_bootstrap` (section 9; row 28) | Draw a prefix without a bound, or a sustained scenario, more often (item 22). Under a bounded prefix the compromised dealer cannot fail a ceremony by its messages alone (section 9), so a failure there needs a fault the Twins targets exclude: a restart (R15) or a lossy link (R17) |
| 26 | Standard marshal variant only | R13; section 9, Other configurations | The DKG module is generic over the marshal variant in the reshare actor and in the probe (`glue/src/dkg/reshare/actor/dealing.rs`, `glue/src/dkg/reshare/actor/follower.rs`, `glue/src/dkg/probe/mod.rs`). The harness builds it over the Standard variant in every target that configures marshal (`Variant` in `glue/fuzz/src/dkg/reshare_stack.rs`), so the module over the coding variant, with coded blocks and their commitments, is never run here. The module's own tests run probe discovery over the coding variant (`glue/src/dkg/probe/actor/discovery.rs`, tests) | A second stack over `marshal::coding`, chosen by the input or as targets of its own. It changes R13 |
| 27 | Marshal is never pruned | R13; section 9, Other configurations | In a node the stateful layer prunes marshal (`PruneConfig` in `glue/src/stateful/actor/core/mod.rs`), and R13 leaves that layer out. Nothing under `glue/src/dkg` and nothing in the harness calls marshal's `prune`. The DKG module documents what pruning must keep (`glue/src/dkg/mod.rs`, Marshal Retention): a restart loads the epoch's `EpochInfo` from the boundary block, serving the probe needs the boundary finalization and block of every epoch served, and no runtime check enforces the retention rule. A restart, a serving probe, and a joiner beside pruned history are never run | The harness prunes marshal in the caller's role, inside the documented retention rule so that P3 still holds. It is a new requirement beside R24 |
| 28 | I6 is excepted from the non-vacuity step in `dkg_bootstrap` | Section 10, step 7; section 9, A failed bootstrap under Twins; Choices made, item 29 | In the 4,330 observed runs of `dkg_bootstrap` (section 9), the failed-bootstrap clause of I6 was not judged: those runs leave I6 unmeasured. In the current regression suite the clause rests on its negative control (R19). A run of the target in which a correct engine reports a failed ceremony still gives I6 a count above zero (R30, 8.1). Step 7 still requires a count above zero in `dkg_bootstrap_restarts` | An input of `dkg_bootstrap` that fails a ceremony: if one is found, it joins the regression suite and the exception goes. Making one reachable by a scripted elector needs a change under `glue/src` (rows 16 and 20) |

### 12.2 Next planned steps

Steps 1 to 4 are not built. Step 5 is built and stays here as its record. Each names what it
rests on and what is still open.

1. **A bounded-exposure invariant.** This is the checkable form of the bound that Choices made,
   item 4 quotes: if the adversary knew at most `f` correct players' previous shares before a
   reshare, it knows at most `f` correct players' shares after it.
   - *What it is.* A count, with no group arithmetic. The mock group gives away every discrete
     logarithm (`glue/fuzz/src/dkg/mock.rs`, module documentation), so a check that tries a
     recovery proves nothing. The inputs are, per epoch, the selected dealers
     (`Output::dealers()`), the reveal set of each selected dealer's log
     (`DealerLog::summary()`), and the set of correct players counted as exposed, carried from
     the epoch before. The first output of a reshare run is a trusted deal (R10), so the carried
     set starts empty. The check does not read `Output::revealed()`.
   - *What it rests on.* The step from one epoch to the next was derived by hand for a
     committee of 4 with `f = 1`, and checked a second time. It is not derived for a general
     `f`, nor for a failed ceremony followed by a retry from the same shares.
   - *What it would find.* A selected log that reveals more than `f` dealings, fewer than
     `2f + 1` selected logs, and exposure that grows from reshare to reshare. It does not close
     the ack-loss gap of step 2: a reveal a correct dealer did not need stays within `f` per
     log.
   - *First.* A prototype in `cryptography/fuzz`, where the ceremony is driven directly and the
     selected logs are at hand. That is outside this feature (R3) and needs a spec of its own.
     The existing target there only calls `FuzzPlan::run`, which is defined in
     `cryptography/src/bls12381/dkg/feldman_desmedt.rs`, so the prototype either drives the
     public dealer and player interfaces from the fuzz side or needs a change under
     `cryptography/src`.
   - *Then, in this feature.* Only after the harness records the selected dealer logs. Today
     `Records::placed` keeps the payload kind of a block and drops the log
     (`glue/fuzz/src/dkg/invariants.rs`, lines 699-755), and the delivered `EpochInfo` names
     the selected dealers without their logs. The record must hold every finalized dealer log
     as a whole, and the check needs a sound rule for which log of a selected dealer the
     ceremony used, since a dealer can have more than one log on the chain (Choices made,
     item 9). The invariant would take the next free number and enter section 8 through an
     update of this document, with its negative control (R19).
2. **The ack-loss gap.** Choices made, item 4 records two defects nothing detects: a correct
   dealer that loses a valid ack, and a correct player that does not acknowledge a valid
   dealing. Both show as a correct dealer's log that reveals a correct player.
   - *Why no check is sound today.* That same log is legitimate in every ceremony target. In
     the Twins targets every input has a prefix of at least one view (A1), in which the
     compromised identity can keep a block from a correct node; that node deals late and can
     close its window, which closes at a block height, holding some correct acks and not
     others (Choices made, item 4). In the restart and state-sync targets a crash, a lossy link,
     or a cut can keep an ack from a dealer (R16, R17, R23). The harness cannot tell a needed
     reveal from an unneeded one.
   - *What would make one possible.* Evidence, per dealer and player, that the ack reached the
     dealer before the dealer closed its window. With that evidence the rule would be: a log
     of a correct dealer that reveals a correct player whose valid ack it had received in
     time is a defect. It
     needs three records the harness does not keep: the delivery of each ack on the DKG
     channel between correct nodes, the moment each dealer closes its window, and the log
     bodies of step 1. Whether the second can be observed through public interfaces was not
     checked. A narrower form, a run with no fault at all in which no correct dealer may
     reveal anything, was not checked for soundness either: it needs a measurement that
     fault-free runs never reveal.
   - *State.* Not designed. It would be a new invariant and needs a decision.
3. **The #5721 path.** One dealer sends two different dealings in one epoch, and the correct
   player that receives them restarts between them. The property at stake is that replay never
   pairs a journaled public message with the private half of another message
   (`glue/src/dkg/reshare/store.rs`, lines 204-217).
   - *Why no target reaches it.* Only the compromised identity deals twice (A2), and only in
     the Twins targets, which restart no engine (R15). The restart and state-sync targets run
     correct nodes only (R16, R23), and a correct dealer sends the same dealing again after a
     restart, because its seed is durable before it deals (`commit_epoch` in
     `glue/src/dkg/reshare/store.rs`, and the actor's order of calls). The probe target runs no
     ceremony (R21).
   - *What covers it instead.* The production regression `issue_5721_regression` and the test
     after it (`glue/src/dkg/reshare/store.rs`, lines 1290-1388). They interrupt a dealing at
     the secret store and before each journal mutation, for different dealings from one
     dealer, at the level of the store.
   - *What lifting it would take.* A change of R15, to restart a correct engine in a Twins
     target, or of R16 and P2, to put a dealer that deals twice into a restart target. The
     Twins targets pace no write (Choices made, item 13), so the crash would also need the
     pacing of the restart targets to fall between the two writes of one dealing. I2 and I8
     would see a consequence, not the pairing itself. Comparing a player's ack before and
     after the crash is not enough: the sequence can crash before a first ack exists.
   - *State.* Not planned. The review of the study found no reason to build it now, given the
     production regression.
4. **The `SecretStore` contract for dealings (optional text).** Since #5728 the trait documents
   that a private dealing is valid only with its own public message
   (`glue/src/dkg/mod.rs`, `put_dealing` and `get_dealing`). R14 binds the harness to that
   contract by reference and does not spell it out. The harness's store returns a private
   dealing only for the public message it was stored with, and panics when a different private
   dealing is stored again for the same epoch, dealer, and public message
   (`glue/fuzz/src/dkg/store.rs`, `put_dealing`). At a correct engine I8 reports that panic.
   The assertion is sound in the mock group:
   one public message and one player position fix one valid private dealing. A sentence for section 11,
   Secret stores, would read: "A store returns a private dealing only for the public message
   it was stored with, and storing a dealing again for the same public message cannot change
   it." It is not added there yet: section 11 is normative, and the sentence waits for the
   review of this document.
5. **Per-invariant counts in the harness (R30).** R30 and section 10, step 7 require every run
   to report, per invariant, how many records its check judged, and to report an invariant with
   a count of zero as unmeasured. The harness does this since the build of 2026-11-18.
   - *What the harness had before.* One flag per run: each of the six drivers' reports
     answered `measured()` with one `bool`, and the runner wrapped every report in `OnRequest`,
     a report printed only on request, whose `unexpected()` is `false`. One flag can hide an
     unmeasured invariant behind another that ran, which R30 forbids.
   - *What was open, and is decided.* Where a fuzz process writes the report of a run and the
     smoke aggregate, and when: R30 fixes what is reported, not where. The decision of
     2026-11-18 was "Compact aggregate always" (section 5.4; Choices made, item 27): every fuzz
     process always writes the aggregate, at intervals and at its end, and the report of each
     run only when `GLUE_FUZZ_LOG` is set. Counts per invariant will show I6 as unmeasured in
     most runs, because a failed ceremony is rare (12.1, rows 11 and 25); R30 does not fail
     such a run, and the run is not printed for it.
   - *What the build chose.* An interval of 250 completed runs between two aggregate lines
     (`AGGREGATE_INTERVAL`, `glue/fuzz/src/dkg/report.rs`), and the C library's `atexit` to
     catch the end of the process (`glue/fuzz/src/dkg/runner.rs`; section 11, Report
     emission). Measured on macOS: a process that reaches libFuzzer's limit of runs writes its
     last aggregate line, and a process ended by SIGTERM writes none. Not measured: a process
     that aborts on a violation, and Linux. The `atexit` call is the harness's one unsafe
     block. Miri cannot call `atexit`, so by the decision of 2026-11-18 ("Keep it, skip
     Miri") that one call has no Miri test.
   - *State.* Built. Every report holds one entry for each id of its target's row in 8.1
     (`Report::judged`), `fold` gives the aggregate, and `Emitter` writes it, all in
     `glue/fuzz/src/dkg/report.rs`. The acceptance tests written from this document are in
     `glue/fuzz/src/dkg/dkg_acceptance.rs` and `glue/fuzz/tests/dkg_delivery_acceptance.rs`.
     They hold one coverage test of section 10, step 7 for each of the six targets, and all
     six pass.

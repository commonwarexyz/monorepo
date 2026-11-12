# Glue DKG Fuzzing: Specification

This document is the technical specification for the glue DKG fuzzing feature. It states *what*
the feature must do and *which properties and invariants must hold*; it deliberately omits *how*
the code achieves them.

Status: all six targets are implemented: `dkg_bootstrap`, `dkg_reshare`, `dkg_bootstrap_restarts`,
`dkg_reshare_restarts`, `dkg_probe`, and `dkg_state_sync`. Section 12 records the choices made
while the targets were drafted, built, and reviewed.

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

The invariants in section 8 belong to the fuzz crate. Nothing under `glue/src`,
`cryptography/src`, or `consensus/src` is held to them, and nothing under those trees is modified
to satisfy them.

## 1. Purpose

The DKG module produces and rotates the threshold key a validator set signs with. It composes the
Feldman-Desmedt ceremony with p2p dealing, on-chain dealer logs, epoch transitions, crash
recovery, and state sync for late joiners. A defect in that composition can leave correct nodes
with different outputs, with shares that do not match the public key, with a group key that
changes across a reshare, or with a share published on chain.

Existing fuzzing does not cover this. `cryptography/fuzz` drives the ceremony functions directly,
with no actors, network, storage, or blocks. No target in `glue/fuzz` touches `glue/src/dkg`.

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
- **G8.** Keep the targets fast: no real BLS operation may run in any target.

## 3. Technical requirements

- **R1. Focused fuzz targets.** The feature MUST expose six independently runnable libFuzzer
  targets, listed in section 5.2: Twins over bootstrap, Twins over reshare, restarts over
  bootstrap, restarts over reshare, the probe protocol, and late-joiner state sync. Targets MAY
  share library machinery, but each MUST retain its own corpus.
- **R2. Thin targets.** Every fuzz-target file MUST only instantiate libFuzzer and invoke a
  library entry point. All harness logic belongs in `glue/fuzz/src/dkg`.
- **R3. Fuzz-only implementation.** Every file changed by this feature MUST be under
  `glue/fuzz/`. No file under `glue/src`, `cryptography/src`, `consensus/src`, or elsewhere in
  the workspace may be modified, with one exception: adding a dependency to
  `glue/fuzz/Cargo.toml` necessarily records it in the workspace `Cargo.lock`. All exercised
  behavior MUST be reached through public APIs of the existing crates.
- **R4. Deterministic execution.** Every target MUST run under
  `commonware_runtime::deterministic` with its randomness supplied by `FuzzRng` over the input.
  Scheduling and randomized choices MUST depend only on the input bytes. No entropy-backed
  randomness and no wall-clock time may be used.
- **R5. Input sampling.** Each target's input MUST be decoded the way the glue transfers target
  does: the head of the input (at most 8 bytes) seeds a fixed-size stream of `FuzzRng` output,
  the literal input overwrites that stream from its start, and the structured controls are drawn
  from the stream. The rest of the stream is the run's tape, which seeds the deterministic
  runtime and every sampler in the harness. Every input, including an empty one, MUST therefore
  sample a complete session, and a short input MUST NOT collapse every control to its minimum.
  The tape MUST NOT be printed in `Debug` output; its length may be.
- **R6. Mock group.** Every target MUST instantiate the DKG module, the ceremony, and every
  threshold operation over the mock group. The mock group MUST be defined in the fuzz crate using
  only public API. It MUST preserve the algebra of the real groups, so that every check in the
  ceremony returns the verdict it would return on the real curve. Its decoder MUST reject
  non-canonical encodings and the identity, as the real groups do. No real BLS curve operation,
  pairing, or hash-to-curve may run in any target.
- **R7. Consensus scheme.** In the reshare Twins, reshare restart, and state-sync targets,
  consensus MUST sign with the mock threshold scheme built from the `SchemeInfo` each node
  registers for each epoch. Marshal and the probe MUST verify with the certificate verifier
  derived from the group public key, which is the same for every epoch. In the probe target the
  fabricated chain MUST be signed and verified the same way. The bootstrap targets use the
  ed25519 Simplex chain that `bootstrap::Engine` owns.
- **R8. Identities.** Identity keys are real ed25519 keys in every target.
- **R9. Ceremony parameters.** Every ceremony MUST use the `N3f1` fault model and `Reveal::V1`.
  The input MUST select the sharing mode among the modes the DKG module supports. All nodes of a
  run use the same parameters.
- **R10. Committee.** The committee MUST always have 4 members. The bootstrap targets run 4
  identities. The reshare and state-sync targets run 5 identities; each epoch's committee is 4 of
  them, and the input MUST decide, per epoch, whether the committee stays the same or the outside
  identity replaces one member. The first committee's output comes from a trusted `deal` over the
  mock group.
- **R11. Session bounds.** A reshare run covers a fuzz-selected number of epochs between 1 and 3.
  The epoch length starts at 32 blocks. It MAY be reduced only after measurement shows that
  fault-free ceremonies still succeed at the shorter length. Within a target every bound (node
  count, epoch count, event count, simulated duration, storage) MUST be fixed across all inputs.
- **R12. Bootstrap stack.** In the bootstrap targets every engine MUST run the real
  `bootstrap::Engine` over the six channels it requires. The harness supplies only what the
  engine's configuration asks for: a secret store, a peer manager, and a blocker.
- **R13. Reshare stack.** In the reshare and state-sync targets every engine MUST run the real
  marshal actor in the Standard `Deferred` configuration, the real `reshare::Actor`, the real
  `reshare::Application` wrapper, the real `orchestrator::Actor` with its per-epoch Simplex
  engines, and the real `probe::Actor`. The block type and the inner application are defined by
  the harness and carry no state beyond what the DKG module needs. `StatefulActor` and QMDB are
  not part of the stack.
- **R14. Harness-supplied traits.** The harness MUST implement `SecretStore`, `Registrar`,
  `ParticipantsProvider`, and the epoch-keyed scheme provider. These implementations MUST honor
  the contracts documented on the traits, so that a panic the DKG module raises on a contract
  violation can never be caused by the harness.
- **R15. Twins topology.** The Twins targets MUST run one more engine than identities: 5 engines
  over 4 identities for bootstrap, 6 over 5 for reshare. The compromised identity's two halves
  are built from the real code, share the identity key, and each have their own storage
  partitions and their own secret store. In the reshare target both halves start with the
  compromised identity's share of the first output. The Twins targets MUST NOT restart any
  engine.
- **R16. Restart scope.** The restart targets MUST run correct nodes only and accept a
  fuzz-controlled schedule that crashes and restarts them. A restart is an in-run abort and
  re-initialisation on the same deterministic runtime. All storage partitions and the node's
  secret store MUST survive it. No state-loss variant (a wiped secret store or journal, storage
  rolled back behind the secret store) may be produced. A crash MAY fall between any two writes
  of a node: after it the secret store may be ahead of the node's journals, or behind them, by
  the writes that were in flight at the crash, and a journal may lack writes that had resolved
  but whose sync had not completed. That is not state loss: nothing that was durable when its
  write resolved is lost.
- **R17. Link conditions.** In the Twins targets every link MUST be fixed and lossless; the only
  network faults are the twins partition and the DKG mask. In the restart targets the input MUST
  control link conditions among correct nodes: latency, jitter, delivery rate, and temporary
  cuts. Message bytes MUST NOT be corrupted on a link between correct nodes in any target.
- **R18. Safety only.** The feature targets safety. It MUST NOT assert liveness. A run that
  stalls, a ceremony that fails, and a run that reaches its simulated timeout are healthy
  outcomes, and the invariants are checked over whatever was reached.
- **R19. Deterministic regression suite.** Every target MUST have ordinary tests in the fuzz
  crate, driven by fixed inputs, that use the same library entry points and oracles as libFuzzer.
  For every invariant in section 8 the suite MUST contain a negative control: a fault planted
  inside the harness at the observation boundary that makes exactly that invariant fail.
- **R20. Reuse of fuzzing primitives.** The implementation MUST reuse existing fuzzing primitives
  wherever one fits and MUST NOT duplicate them in `glue/fuzz`. This covers the primitives the
  published crates provide (`FuzzRng`, the twins scenario generator and elector, the simulated
  network and its split-channel plumbing, the marshal mocks, the deterministic runtime) and the
  machinery already in `glue/fuzz/src/stateful` (tape handling, the split forwarders and routers,
  the restart, panic-hook, and report helpers). New code is written only for what no existing
  primitive provides: the mock group, the DKG block, applications, stores, the DKG mask, the
  drivers' DKG-specific wiring, and the invariants. A primitive that fits only after being made
  generic MUST be generalized and shared, not copied; the stateful targets MUST remain
  behaviorally equivalent and their corpora replayable (P5). The feature MUST NOT depend on
  `commonware-consensus-fuzz-*` or on the `test-utils` feature of `commonware-glue`.
- **R21. Probe target construction.** The probe target MUST run one discovering `dkg::probe`
  actor and three serving ones over real marshal actors seeded with a fabricated chain, plus one
  tracked identity that is not a dealer. No consensus and no ceremony runs. Boundary blocks carry
  `EpochInfo` built from `deal` outputs over the mock group. The epoch length is 2. A source MAY
  be seeded from a foreign chain signed under a different dealt key.
- **R22. Probe adversary program.** The probe target's structured input MUST bound and control
  what each source holds, the minimum epoch, and a program of events: subscribe, unsubscribe,
  attach a marshal, release a captured response, duplicate it, replay it from the non-dealer,
  truncate it, send a fragment of it from another identity, send junk, and advance time. Source
  responses MUST be captured and handled as opaque bytes, for all three response kinds the DKG
  probe has. The harness MUST NOT reimplement floor selection, response verification, or probe
  state transitions.
- **R23. Late-joiner state sync.** The state-sync target MUST run 5 correct identities. The input
  selects one as the joiner; the other four start at genesis. The joiner starts once a
  fuzz-selected height has been applied, which MUST be able to fall in any phase of any epoch of
  the run. It discovers its boundary through the real probe, builds its state-sync material from
  the probe's artifact, and starts the reshare stack from it. The input MUST also control an
  optional restart of the joiner at a chosen delay after it starts and a schedule of up to three
  restarts across all nodes. Links are fixed. Every node starts a real probe at every boot and
  attaches its marshal to it.
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
  `glue/fuzz/src/stateful/invariants.rs`. That file holds the observation records the checks read
  and the checks themselves, for all six targets, the probe target included. Drivers record
  observations and call into it; they MUST NOT define a check of their own.

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
- **P5. Search-space isolation.** Adding these targets MUST NOT change the input decoding,
  topology, fault model, or predicates of any existing target in `glue/fuzz`. Shared machinery
  MAY be refactored for R20 only when the existing targets remain behaviorally equivalent and
  their corpora remain replayable.

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

## 6. Adversary model (normative)

- **A1. Message layer.** In the Twins targets, each of the compromised identity's channels that
  carries view-addressable Simplex traffic MUST be split in two, with the twins scenario
  deciding, per view, which identities each half may send to and which half receives a given
  inbound message. The scenario applies to the first 3 views of every epoch. Traffic from which
  no view can be determined, other than the DKG channel, follows the stateful rule: it is
  delivered to both halves and sent to the recipients the engine addressed; a message that does
  not decode is dropped. In the bootstrap targets the scenario decides only the partition:
  `bootstrap::Engine` owns its elector, so the leader a scenario scripts is not used.
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
2. **Execution.** The twins scenario partitions the first 3 views. The DKG mask applies for the
   whole ceremony.
3. **Measurement.** The run ends when every correct engine has reported a `Completion`, when a
   correct engine stops, or when the simulated timeout expires. I1-I3 and I6-I11 are checked.
   Results are compared among the correct engines that completed; a share is checked wherever a
   correct engine holds one, whether or not that engine has reported.

### 7.2 `dkg_reshare`

1. **Setup.** Five identities and six engines per R13 and R15, with the first output from a
   trusted deal (R10). Links are fixed.
2. **Execution.** For each epoch the twins scenario partitions the first 3 views, the DKG mask
   applies to the ceremony, and the faulty application is active on the secondary half. The
   committee schedule follows R10.
3. **Measurement.** The run ends when every correct node has processed the last boundary block of
   the selected epochs or the simulated timeout expires. I1-I11 are checked at every boundary a
   correct node processed and at the end, and I18 over every finalized block a correct node was
   delivered.

### 7.3 `dkg_bootstrap_restarts` and `dkg_reshare_restarts`

1. **Setup.** Correct nodes only: four identities for bootstrap, five for reshare.
2. **Execution.** A bounded schedule crashes and restarts nodes per R16 while link conditions
   follow R17.
3. **Measurement.** As in 7.1 and 7.2. I1-I6 and I8-I11 are checked, and I18 in the reshare
   restart target.

### 7.4 `dkg_probe`

1. **Setup.** Per R21. The harness records, for each source, the exact finalizations and boundary
   blocks it holds.
2. **Execution.** The bounded event program of R22 drives subscriptions, attachment, retries,
   delivery, and raw malformed traffic through public boundaries.
3. **Measurement.** If the discovering probe emits an artifact, I12-I14 are checked against the
   recorded source state. No artifact is required. I8, I10, and I11 apply throughout.

### 7.5 `dkg_state_sync`

1. **Setup.** Per R23. Four identities start at genesis.
2. **Join.** At the selected height the joiner starts, discovers its boundary, and enters per
   R24.
3. **Crashes.** The joiner's optional restart and the general restart schedule run.
4. **Measurement.** As in 7.2, with the joiner included from its floor upward. I1-I6, I8-I11,
   I15-I17, and I18 are checked. A joiner whose sync never completes is a healthy outcome.

## 8. Invariants (must hold at every measurement point)

I1-I6 apply to correct nodes in the four ceremony targets and the state-sync target. I7 is
withdrawn. I8, I10, and I11 apply to every target. I9 applies to every target that runs more
than one correct node. I12-I14 apply to the probe target and I15-I17 to the state-sync
target. I18 applies to the targets that run the reshare stack: the reshare Twins, reshare
restart, and state-sync targets.

- **I1. Output agreement.** Any two correct nodes that completed the same ceremony MUST hold the
  same result for it: the same outcome and, for a reshare, an identical `EpochInfo`; for a
  bootstrap, an identical successful output or no output at both. A successful bootstrap result
  MUST describe the ceremony that was run: outcome `Success` for epoch 0, players and output
  players equal to the committee, no next players, and a sharing among the committee's size that
  needs the committee's quorum of shares.
- **I2. Share validity.** Every share a correct node holds for an epoch MUST carry the node's
  index in that epoch's agreed output, and its public key MUST equal the output's partial public
  key at that index. A correct node at which a bootstrap completed successfully MUST hold a share.
  A correct node that has reached an epoch of a reshare run as a player of that epoch's agreed
  output MUST hold a share for that epoch; it has reached the epoch once it registered the epoch's
  scheme. After a successful reshare that share is its share of the new output. After a failed
  reshare it is the share the node held for the previous epoch, held again under the new one; a
  node that held no share for the previous epoch has none to carry. An epoch a node entered
  through state sync without playing its ceremony is exempt (I17). Every `SchemeInfo` a correct
  node registers for an epoch MUST name the players of that epoch's agreed output and carry its
  public sharing, and whenever a correct node registers the scheme of an epoch it has ever held a
  share for, the registration MUST be a signer's and carry that share.
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
  epoch as well (I2). After a failed bootstrap no correct node may hold an epoch-0 share.
- **I7. Withdrawn.** It required that no correct identity appear in `Output::revealed()`. The
  number is kept so that the later invariants keep theirs. No target checks the secrecy of a
  correct player's share; see section 12, item 14.
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
- **I10. Reproducibility.** A failing input replayed MUST fail identically.
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
  floor MUST equal what the other correct nodes committed at that height or epoch. The joiner is
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

## 9. Out of scope

- **Liveness.** Excluded by R18. No progress requirement is asserted in any target.
- **Reporting of runs that measured nothing.** The harness does not label or count runs in which
  no ceremony completed. Whether the oracle code is reached is read from libFuzzer coverage.
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
  dealers' logs out of the inclusion window, so no input of `dkg_reshare` makes a ceremony
  fail, and I6 and the failure branch of I1 are exercised there by negative controls only. The
  restart targets keep one identity impaired at a time (section 12, items 4 and 78) and reach
  a failed ceremony on a few sampled inputs in a thousand (items 53 and 75).
- **State loss.** Excluded by R16.
- **Restarting the compromised identity.** Excluded by R15.
- **Corrupted bytes between correct nodes.** Excluded by R17.
- **The stateful layer.** `StatefulActor`, QMDB, and their interplay with DKG state sync are not
  part of any target (R13).
- **Other configurations.** Committee sizes other than 4, the coding marshal variant, and marshal
  pruning.
- **Modifying any file outside `glue/fuzz/`.** Excluded by R3.

## 10. Delivery and end-to-end verification

The targets are built in the order of section 5.2. After each target the result is reported
(measured executions per second, the smoke-run outcome, anything an oracle flagged) and work on
the next target starts only after that report is accepted. Anything an oracle flags is reported
with its reproducing input and is never fixed under `glue/src`.

For each target, the following steps prove it works. `cargo fuzz` requires a nightly toolchain;
use the nightly pinned by CI (`NIGHTLY_VERSION` in `.github/workflows/slow.yml`).

1. **Source tree is untouched.**
   `git status --porcelain glue/src cryptography/src consensus/src` prints nothing (I11, R3).
2. **The target is thin.** The target file contains only the libFuzzer entry point and a call
   into the library (R2).
3. **Everything compiles and lints clean.** `cargo check -p commonware-glue-fuzz --tests`
   succeeds and `cargo clippy -p commonware-glue-fuzz --tests` reports no warnings.
4. **The regression suite passes.** `cargo nextest run -p commonware-glue-fuzz dkg::` runs every
   fixed-input scenario of the target, including the negative control for each invariant that
   applies to it (R19).
5. **The fuzz target builds.** `cargo fuzz build --fuzz-dir glue/fuzz <target>` completes with no
   warnings and no errors.
6. **A smoke run is clean.** A short run of the target over its own corpus completes with no
   crash, hang, or out-of-memory, and with no invariant firing on a correct run. Executions per
   second are measured and reported. This document sets no throughput floor.

Passing steps 1-6 for a target constitutes acceptance of that target.

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

## 12. Choices made while drafting (to confirm in review)

These were not decided explicitly. Each is stated as the draft currently has it.

1. **Compromised identity.** It is the identity the selected twins case names, as in stateful,
   and may rotate out of the committee in the reshare target.
2. **Threshold scheme flavour.** The reference choice is the `standard` flavour of
   `bls12381_threshold`, not `vrf`, because `vrf` has call paths into `Variant::pairing`.
3. **Blocking does not disconnect.** Simulated networks set `disconnect_on_block` to `false`, as
   stateful does, so that one block does not end the exploration of a run. Blocks are observed
   through the network's record of them.
4. **One node down at a time.** The restart schedule keeps at most one correct identity down at
   any moment, as stateful does. The user confirmed it: the fault bound is f = 1, so outages
   never overlap. A write held before a crash (item 71) belongs to that identity's outage. A
   link cut is not an outage and may coincide with one, and so may, in `dkg_state_sync`, a
   joiner that has started and is still syncing: neither is a Byzantine fault, and the targets
   assert safety only (R18), which must hold however many correct nodes are unavailable. A
   ceremony among correct identities then fails only when a link cut coincides with an outage
   (item 38) or when a write held before a crash keeps an identity from its dealing window
   (item 75). Both are rare: a few sampled inputs in a thousand fail a ceremony, so I6 and the
   failure branch of I1 rest mostly on fixed inputs and negative controls.
5. **Link-condition bounds.** R17 names the controlled quantities and leaves their ranges to be
   set after the first measurement.
6. **Simulated timeout.** Its value is set after the first measurement. It only bounds how much a
   run can reach, since reaching it is a healthy outcome.
7. **Viewless traffic.** Non-DKG traffic without a view follows the stateful rule (A1).
8. **Faulty application scope.** It deviates only in what it proposes (A3). It does not also
   reject or abstain on verification, which the stateful faulty application does.
9. **Mixed-set definition in I5.** A mixed set contains at least one share of each output.
10. **Negative reconstruction check in I3.** "One fewer" is checked through the recovery
    function, which must return an error. A direct interpolation of fewer shares is not checked,
    because the evaluation points it needs are private to the cryptography crate.
11. **Generalizing stateful helpers (R20).** Several stateful helpers are typed to stateful's own
    scheme and block, so they cannot be imported as they are. The draft has them made generic in
    place and shared by both features, which edits files under `glue/fuzz/src/stateful`. The
    alternative is to leave those files untouched and accept a DKG-typed copy of each.
12. **No dependency on the consensus fuzz crates (R20).** The draft keeps the rule stateful's
    specification has, so a primitive that exists only in `consensus/fuzz` is not reused.
13. **A compromised half may panic (I8).** Found while building `dkg_bootstrap`: with separate
    secret stores the halves reach the DKG module's deliberate panics "DKG participant must
    receive a share" at the end of most ceremonies, and less often "InvalidPersistedDealing".
    I8 was narrowed from "no panic anywhere" to "no panic outside a compromised half". The
    first cut told the halves' panics apart by their messages. The user asked that panics be
    filtered only for the compromised halves, so each engine now runs on a context that
    attributes its panics to it, and a half's panic is tolerated whatever it says. A defect
    that only ever panics inside a half is therefore not reported.
    The alternative considered was one secret store shared by both halves. The user rejected
    it. It removes the dealer equivocation the separate stores exist for, and with it the
    contradicted dealing, but not the missing share: a running engine rebuilds its player from
    its own record of dealings, so a half still lacks a dealing that only its twin received.
14. **I7 withdrawn by the user.** It held only under synchrony: every correct ack reaches every
    correct dealer before the dealer's window closes. The DKG module closes that window at a
    block height. A correct node that the compromised identity keeps a block from sends its
    dealings late, can close its window holding some correct acks and not others, and then
    reveals a correct player. A masked half of the compromised identity can reveal the same
    player, which is the two reveals listing needs. No such run was observed in about 2,000.
    With I7 gone, a correct dealer that loses a valid ack and a correct player that fails to
    acknowledge a valid dealing are not detected.
15. **Stricter I1 and I2 for a bootstrap.** Added after review, so that a missing share or a
    lowered threshold cannot pass unnoticed: a successful result must be among the committee
    with the committee's quorum, and an engine that completed successfully must hold a share.
16. **Peer set registered before the engines start.** The harness starts the simulated network
    with the committee already registered, as the in-crate e2e simulator does, although the
    bootstrap engine's documentation says to pass it an unused manager. The engine's own
    registration of the same set is then a no-op.
17. **The bootstrap DKG mask does not read the message.** A bootstrap has one epoch, so one mask
    covers every ceremony message. The per-epoch mask of `dkg_reshare` must read the epoch from
    the channel prefix, as section 11 requires.
18. **Layout of the reshare harness.** Building `dkg_reshare` added files instead of growing
    `stack.rs`, `network.rs`, and `twins.rs`: `app.rs` (block and correct application),
    `faulty.rs` (faulty application), `scheme.rs` (consensus scheme, scheme provider, registrar),
    `schedule.rs` (committee schedule and participants provider), `reshare_stack.rs`,
    `reshare_network.rs`, `reshare_input.rs`, and `reshare_twins.rs`. Section 5.1 names
    `store.rs` for the registrar and the providers and `app.rs` for the faulty application; that
    layout is indicative. The block, the correct application, the scheme provider, the schedule,
    and the stack assume no compromised identity, so the later targets can use them. Every module
    under `dkg` is compiled whenever any DKG feature is on; only the `[[bin]]` entries are gated
    per target. The one exception is `fixtures.rs`, which holds what the tests of these modules
    share and is compiled for tests only.
19. **Scenario and leaders in the reshare target.** The twins scenario is drawn over the five
    identities, not over a committee, because the committee of an epoch depends on the outcome of
    the ceremonies before it. The scenario's scripted leaders are used (A1): a scripted leader
    that is in the epoch's committee leads its view, in every epoch, and a view whose scripted
    leader is outside the committee is led by the round-robin rotation, as every later view is.
    The twins elector of `consensus` returns the scripted index as a committee position, so the
    harness has its own elector for this.
20. **Every identity stays connected.** R17 fixes the links of a Twins target, so no identity may
    lose its links because it is outside the current participant sets. Engines track one peer set
    per epoch on top of the initial set of all five identities, and the simulated network is
    configured to keep the newest eight sets. A run that completes tracks at most five; only a
    run in which the chain advances several epochs past the selected ones before the timeout
    drops the initial set. With the stateful setting of one tracked set, an identity outside an
    epoch's dealers, players, and next players is cut off at the first epoch change, and most
    runs then end at the timeout. The number is kept small because the network sizes every
    channel by it: with 64 sets a run took about a quarter longer. The user confirmed this choice.
21. **One peer manager.** Every engine is given the simulated network's own manager, whose
    record of peer sets is shared by all nodes. A production node, and the per-node manager of
    the in-crate reshare harness, sees only the sets it tracked itself. The difference shows only
    to a node that is an epoch behind, which is told the newest set by its peers' tracking. The user
    confirmed this choice.
22. **Probe channel of the compromised identity.** The DKG probe's wire types are not public, so
    the harness cannot apply A1's "a message that does not decode is dropped" to this channel.
    Both halves share the identity's sender and both receive every inbound message. No node of
    this target starts a discovery, so the channel carries nothing.
23. **What a correct engine reports in a reshare run.** Three records are kept per engine: the
    description of each epoch as marshal delivers it in the final block of the epoch before, the
    scheme material the engine's reshare actor registers, and every share its secret store was
    ever given. The store keeps the last of these outside the engine's reach, because the reshare
    actor prunes the shares of old epochs and I5 compares shares across a boundary. A ceremony
    counts as completed at an engine once the engine has registered the scheme of the next
    epoch, which it does after storing its share; the run ends when every correct engine has
    registered the epoch after the last selected one, when a correct engine stops, or at the
    timeout. Every boundary is checked once, after the runtime has stopped, over these records.
24. **I2 for a reshare.** A share is checked wherever a correct engine holds one. A registered
    scheme must name the agreed output's players and carry its public sharing, and a share
    registered with it must be the engine's valid share. A share or a registration for an epoch
    that no correct engine holds a description of is a violation. The first cut only counted a
    correct engine that completed a successful ceremony as a player of its output and held no
    share of it; the user decided that this is a violation. An engine has completed the
    ceremony once it registered the scheme of the epoch the ceremony introduces, which the DKG
    module does only after it stored the share, so the check cannot fire on an engine that has
    not yet written its share. A node that enters an epoch without having played its ceremony,
    as a state-sync joiner can, is not a player that completed it. After a failed ceremony the
    same engines are held to the share the ceremony carried forward (item 26).
25. **I5 as checked.** Every set of `required()` shares with at least one share of each output is
    interpolated twice, once under each output's sharing, and neither result may verify under the
    group public key.
26. **I6 for a reshare.** Two things are checked under I6: every share a correct engine held
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
    item 86: the module registers it from the state-sync material before it stores anything
    under it. An engine that held no share for the previous epoch has none to carry. The check
    runs in every target that checks a reshare run. A fixed input of `dkg_reshare_restarts`
    shows the store: after its failed ceremony four engines hold the share under both epochs.
    No ceremony failed in any run made while building `dkg_reshare` (about 7,400 runs and
    15,000 ceremonies), so in that target these checks are exercised by negative controls
    only: with at most one compromised dealer among four, the three correct dealers are a
    quorum, and nothing in that target keeps their logs out of the inclusion window. The
    restart targets reach a failed ceremony (item 54).
27. **Faulty application.** Each of five deviations (early dealer log, another dealer's log,
    misplaced epoch description, wrong epoch description, missing payload on the final block) is
    armed unless the tape disarms it, one time in eight each. A proposal deviates in one to four
    rounds out of eight, by the tape, and a final block in four out of eight, since it is
    proposed once an epoch. Another dealer's log is one the application saw in a block another
    identity proposed. The early dealer log is one of those or a log the harness signs before the
    run with the compromised identity's key, for the first ceremony, from a dealer no player
    acknowledged. A wrong epoch description is the newest description the application has seen
    (the ending epoch's), the right one with the other outcome, or the right one with its two
    player sets exchanged; a variant that would reproduce the right description reports the
    other outcome instead. The run's report counts the proposals that deviated.
28. **Per-epoch DKG mask.** The input carries one mask per selectable epoch. A message of a later
    epoch is not masked, and a message whose channel prefix cannot be read is dropped. The mask
    type is generic over the number of identities it covers, three for a bootstrap and four for a
    reshare.
29. **Committee schedule.** The input selects the identity outside the first committee and five
    rotations, one before each ceremony the run's epoch descriptions can name; later epochs keep
    the last set. A rotation keeps the set, in half of the draws, or replaces the member at a
    drawn position with the outside identity. The trusted deal uses the run's sharing mode.
30. **Scheme material that fits no committee.** The registrar builds a scheme only from a sharing
    that is among the registered participants with their quorum and, for a signer, a share at an
    index inside them. Otherwise it leaves the epoch without a scheme, and the engine that
    registered the material stops when it enters the epoch. A share that does not match the
    sharing yields a verifier's scheme, and I2 judges the registration.
31. **Timing of the reshare stack.** Simplex runs with the timeouts of the in-crate reshare
    harness (leader 1 s, certification 2 s, retry 500 ms, skip 5 s, fetch 2 s). The simulated
    timeout is 120 s (item 6): of 600 measured runs every one completed, in 1.6 s to 33 s of
    simulated time. The epoch length is 32 blocks.
32. **Stateful helpers changed for the DKG targets (item 11).** `runner::network_with` takes
    the link conditions and the number of peer sets the network keeps, and `runner::network`
    calls it with the fixed link and one set; `runner::restart_schedule`,
    `stack::archive_config`, and `network::shared_router` became visible to the crate. The
    panic-attribution helpers in `stateful::runner` are compiled only with a DKG target, through
    the internal `dkg` feature every DKG target feature enables.
33. **A bootstrap restart run plays its schedule out (7.3).** 7.3 measures "as in 7.1", which
    ends a run as soon as every correct engine has reported. `dkg_bootstrap_restarts` ends a run
    when the restart schedule has been played out, the latest instance of every engine has
    reported, and every engine a restart brought back has been followed (item 47); when an
    engine stops on its own; or at the timeout. Ending at the first report of every engine
    would reach a crash after the ceremony only when one engine lags, and that crash is what
    makes an engine report from its stored final block. An engine restarted after the final
    block reports as it sets itself up, and the chain has no further block for it to apply, so
    such a restart is followed for the 2.5 s of item 47. Over 3,200 decoded inputs, 1,496 runs
    held a crash past the final block. Without the follow wait they ended 50 ms after their
    last restart at the median; with it they end 2.5 s after it. 2,552 of the 6,260 engines a
    restart brought back were followed for the whole 2.5 s, and the runs took 4.9% more
    simulated time.
34. **An engine may report more than once (I1).** Every start of a bootstrap engine reports its
    completion again. The oracle keeps every report of every instance, compares the first one of
    each engine across engines, and requires every later report of an engine to equal its first.
35. **Events are brought forward once nothing is left to observe (7.3).** An event of the
    restart schedule or a cut runs at its time, or as soon as every engine that can still make
    progress has reported, if that comes first. An identity that is down, or that no peer can
    reach, is not waited for. The bootstrap chain keeps turning views after its final block, so
    waiting out the schedule cost three times the wall time per run (723 ms against 225 ms over
    800 sampled inputs, debug build). The price: the time between the end of the ceremony and a
    later crash is not explored, and a downtime or a cut that outlasts the ceremony ends when the
    other identities finish. The follow wait of item 47 delays no event: it applies once the
    schedule has been played out.
36. **Restart schedule sampling (R16, section 11).** The number of events, 1 to 4, is a
    structured control. Each event's identity and base delay come from the tape through the
    stateful sampler (50 ms to 800 ms). A fault-free ceremony takes 1.2 s to 10 s over lossless
    links and up to a minute over lossy ones, so each event also draws from the tape up to five
    doublings of its delay (at most 25.6 s) and its downtime (100 ms to 51.2 s). Over 800 sampled
    inputs 43% of the crashes found their engine in the dealing window, 15% in the inclusion
    window, and 41% past the final block.
37. **Link-condition bounds (item 5, R17).** Every directed link of a run has the same
    conditions: a mean latency of 1 ms to 100 ms, a jitter of zero up to the latency, and a
    delivery rate of 75% to 100%, with half the runs losing nothing. At 60% no fault-free
    ceremony completed inside the timeout; at 75% they do, in 40 s to 56 s. A run has up to
    three temporary cuts, one after another, each removing one identity's inbound links, its
    outbound links, both, or one directed link. A cut starts up to 8 s after the previous one
    ended and lasts 0.5 s to 8 s; one cut in four may last up to 32 s. The cuts are structured
    controls and are not drawn from the tape.
38. **Why downtimes and cuts may last half a minute.** With downtimes and cuts of a few seconds
    no ceremony among the four correct identities failed. A failing run was built by hand: one
    identity is crashed before any ack reaches it and stays down until the midpoint, so it posts
    no dealer log, and a link between two of the others is cut for as long, so each of them
    would have to reveal two shares where a log may reveal one. A single usable log remains.
    With one identity down and one link cut the midpoint comes after about 20 s. The bounds of
    items 36 and 37 admit that run, and a fixed-input test runs it. No sampled input reached it.
39. **Simulated timeout of the bootstrap restart target (item 6).** It reuses the 120 s bound of
    `dkg_bootstrap`.
40. **A restart registers the identity's channels again (section 11).** The engine owns its
    channel endpoints, and they are gone with it. A restart registers the same six channels
    under the same key, which replaces the registrations of the crashed engine, as the stateful
    restart targets and the in-crate simulator do.
41. **Instances, not engines, are watched (I8).** Under a restart schedule "a correct engine
    MUST keep running" is read per instance: an instance may leave the run only by being aborted
    by the schedule. The oracle records how every instance left, and one whose task ended
    without that abort is a violation, also when the schedule would have crashed it later.
42. **Where a crash found its engine is read from the engine's metrics.** Only for the run
    report, never for a check: the driver reads the processed height the engine's marshal
    reports in the runtime's metrics registry. No public API of the bootstrap engine exposes its
    progress.
43. **Every DKG driver is compiled under any DKG feature.** The features select which fuzz
    binaries are built, and each enables the internal `dkg` feature that gates the module. The
    module is not gated per driver, unlike `stateful`.
44. **Payload placement (I18).** Added after the review of `dkg_reshare`: an early dealer log
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
    of the epoch, and a log that does not verify, which are ignored once finalized. On the
    unmodified module a correct engine was delivered more dealer logs in an epoch than the epoch
    has dealers in 200 of the 1,115 runs of a corpus replay (the 1,114 inputs and the empty one).
    Whether the final block's `EpochInfo` is the right one is I1 and I4. The final-block rule has
    record-level controls only: a correct engine that is given a final block without an `EpochInfo`
    panics, which I8 reports first.

    The run report counts the blocks examined and how many of them carried a dealer log and an
    `EpochInfo`. With the wrapper's check off the final block removed in a scratch copy, 9 of
    the 10 fixed-input driver tests and 586 of the 1,114 corpus inputs fail, all on I18. Of the
    528 inputs that still pass, 281 make no deviating proposal, 68 make only deviations that
    check does not concern, and in 179 no misplaced proposal was finalized: the primary half's
    block of the same round was, or the view was nullified.
45. **Layout of the reshare restart harness.** Building `dkg_reshare_restarts` added three
    files and grew none of the reshare ones: `reshare_restarts_input.rs` (the session controls
    and the target's input), `reshare_cluster.rs` (the session every engine starts from, the
    cluster of correct reshare engines kept across their restarts, and the reader the oracle
    uses), and `reshare_restarts.rs` (the driver). The cluster implements the `Stack` of
    `environment.rs`, draws no schedule, and holds no adversary, so `dkg_state_sync` can run
    the same engines under its own schedule. What both restart drivers place a crash by is in
    `environment.rs`: the labels of an engine's context, the reader of the height its marshal
    has processed, and the window of an epoch that height falls in.
46. **Input of the reshare restart target (R5, R10, R17).** The session controls are the ones
    the reshare Twins input draws, in the same order: the number of epochs, the sharing mode,
    the identity outside the first committee, and five rotations (item 29). The environment
    controls are those of items 36 and 37, drawn over five identities, so a cut may name the
    identity outside the committee. The tape seeds the runtime, the trusted deal, and the
    restart schedule.
47. **A reshare restart run plays its schedule out (7.3).** 7.3 measures "as in 7.2", which
    ends a run as soon as every correct node has processed the last boundary block. As in
    item 33, `dkg_reshare_restarts` ends a run when the restart schedule has been played out,
    the latest instance of every engine has registered the scheme of the epoch after the last
    selected one, or of a later one, and every engine a restart brought back has been
    followed; when an engine stops on its own; or at the timeout. Every boundary any engine
    reached is checked once, after the runtime has stopped (item 23).

    The reshare actor registers the scheme of the epoch it is in at every start, so an engine
    restarted past the last boundary has registered as soon as it has set itself up. The
    environment therefore follows every engine whose latest instance a restart started: the
    run goes on until the height the engine's marshal has processed is past the height it had
    processed when the engine was crashed, or until 2.5 s have passed since the restart,
    whichever comes first (`FOLLOW` in `environment.rs`). Marshal dispatches one block at a
    time and records a height before it dispatches the next, so the height at the crash is the
    height the restart resumes from or one above it, and an engine past it has applied a block
    since its restart. The heights are read from the runtime's metrics every 250 ms. The wait
    asserts nothing (R18): it ends silently at its bound, and the run's timeout ends it like
    any other wait. It applies at the end of a run only. A stack opts in (`Stack::follows`),
    and the clusters of the two restart targets do.

    The bound is the time a restarted engine needs to apply a block. With the wait unbounded
    and the heights read every 20 ms, the end of a run waited for 627 restarted engines over
    1,500 sampled inputs. 626 applied a block: 363 within 0.5 s, 612 within 2.5 s, and the
    last after 5.1 s. Simplex's timeouts (item 31) set that time, not the links: of the 83
    engines over links of more than 75 ms, 80 applied a block within 2.5 s, as did 463 of the
    465 over lossless links, and 12 of the 14 that took longer ran over lossy links.

    Over 3,200 decoded inputs the same runs were made with and without the wait. Without it,
    1,116 runs ended less than 100 ms after their last restart, and in 1,080 the engine of
    that restart had applied no block; of the 959 runs with a crash past the last epoch, the
    median ended 7 ms after its last restart and 939 saw no block from the restarted engine.
    With it, 38 runs end within 100 ms of their last restart, 17 see no block, and those 959
    end 294 ms after their last restart at the median and 2.0 s at the ninth decile. The bound
    ended the wait for 36 of the 6,539 engines a restart brought back, and the runs took 0.7%
    more simulated time. A replay of 400 inputs with a bound of 3 s, read every 250 ms, made
    5.0 runs a second where it made 5.1 without the wait; `dkg_bootstrap_restarts`, whose
    restarts after the final block are followed for the whole bound (item 33), made 5.6 where
    it made 7.2. The report of both targets counts the engines a restart brought back, those
    the bound ended the wait for, and the simulated time and the blocks between the last
    restart and the end of the run.
48. **Records span the restarts of an engine (I1, I2, section 11).** Each identity has one
    secret store and one set of records for the whole run, and every instance of its engine is
    given both. The oracle therefore reads what every instance reported and every share the
    store ever held. I1 needs no check of its own for this: a description an engine is
    delivered again after a restart is recorded once if it is the same, and is a second
    description at one engine, which I1 rejects, if it differs.
49. **I2 across restarts.** The check of item 24 judges an engine by every share its store
    ever held, so it passes an engine whose restart does not find its share again. The restart
    target adds a check for that: whenever an engine registers the scheme of an epoch its
    store ever held a share for, the registration must be a signer's and carry that share. It
    covers the first output, a reshared output, and an output a failed ceremony carried
    forward. The check reads the shares by the epoch they were stored under, so on its own it
    passes an engine that registers the new epoch without having stored the carried share
    under it. Item 26 requires that share under the new epoch of every engine that reached it,
    and this check then requires every registration of the epoch to carry it. It is sound
    because the DKG module builds every
    registration from the share it reads from the secret store, stores a share before it
    registers with it, and prunes an epoch's secrets only once it is two epochs past it, while a
    restart returns an engine at most to the epoch whose final block its marshal had not
    recorded. The restart driver calls the check; it is not among the checks `dkg_reshare` runs.
    `dkg_state_sync` can apply it to the nodes that started at genesis.
50. **Leaders, peer sets, and timing of the reshare restart target.** Every epoch's Simplex
    engine elects its committee in turn, as the in-crate reshare harness does: there is no
    scenario to script leaders from. The network keeps the eight newest peer sets, for the
    reason of item 20: the links of a restart run are the input's to cut, not the
    committee's. The furthest a measured run got was its sixth boundary. Simplex runs with
    the timing of item 31. Over links that only delay by 10 ms a block takes about 50 ms and
    an epoch about 1.6 s, the first half of it the dealing window.
51. **Simulated timeout of the reshare restart target (item 6).** It reuses the 120 s bound of
    `dkg_reshare`. Of the 1,567 runs of a five-minute session 76 reached it, having checked
    the boundaries they got to, and one of those reached no boundary. Of 600 inputs decoded
    in a test, the 28 that reached it all ran over links that deliver at most 83%, where
    three epochs do not fit in the bound.
52. **Events brought forward in a reshare run (item 35).** Once every engine that can make
    progress has registered the last epoch's scheme, the events still to come run at once. A
    crash that is due later than the run's last boundary therefore lands at the instant the
    last engine registers. Such a crash often finds its engine with the next output's share
    stored and its scheme registered, and with the final block not yet recorded by its
    marshal, so the engine that comes back applies the boundary a second time. A crash after
    that restart finds its engine past the last boundary. The time between the last boundary
    and a later crash is not explored otherwise. The follow wait of item 47 delays no event.
53. **Where a crash and a restart landed (report only, item 42).** A crash is placed by the
    height the engine's marshal has processed, which is where the restarted engine resumes:
    the dealing window or the inclusion window of an epoch the run was asked to complete, the
    boundary of such an epoch (the next epoch's scheme registered, the final block not yet
    recorded), or past the last such epoch. A restart after a crash in a dealing or an
    inclusion window either re-enters that ceremony, when no peer has registered a later
    epoch, or follows an outage across an epoch boundary, when one has. A restart after a
    crash at a boundary is counted as neither: the engine had ended the ceremony itself, and
    repeats the boundary. Of the 3,794 crashes of a later five-minute session, with the write
    pacing of item 71 (1,515 runs), 53% landed in a dealing window, 19% in an inclusion
    window, 5% at a boundary, and 23% past the last epoch; 2,156 restarts re-entered a
    ceremony, 599 followed an outage across a boundary, and 181 repeated a boundary.
54. **A failed reshare is reached (I6, item 26).** Four of the 1,567 runs of an earlier
    five-minute session held a failed ceremony, eight of the 1,515 runs of the session of
    item 53 did, and so did four of the 600 decoded inputs, one of them twice.
    Each of the decoded four combines crashes with cuts. A fixed-input test builds
    one as item 38 does: a dealer is crashed before any dealing reaches it and stays down
    past the midpoint, and a link cut between two other dealers leaves each of them with two
    players unacknowledged. The same input asked for two epochs follows the failed ceremony
    with a successful one, which reshares the carried output.

    Of 3,200 decoded inputs run with the check of item 26, 20 hold a failed ceremony, one of
    them two. A sample built for failed ceremonies takes every tape whose schedule crashes its
    first identity at 50 ms and keeps it down for 25.6 s or longer, among the 65,536 fixed
    tapes and 400,000 drawn ones; of the drawn ones it takes those whose second crash is due
    27 s to 38 s into the run, where the failed ceremony ends. Each tape is run under four
    choices of the outside identity, the cut link, the number of epochs, and the latency (50
    ms to 60 ms). Of its 1,876 runs, 980 hold a failed ceremony. In those, 3,919 engines were
    required to hold the carried share under the new epoch, 321 runs had a crash drop a held
    write, 14 of the dropped writes were the write of a share, 290 crashes found their engine
    at a boundary, and no check fired. With the store of the carried share taken out of the
    final block's handling and out of setup in a scratch copy of the DKG module, all 980 runs
    are rejected, 961 by the check of item 26 and 19 by I8, on an engine that replays its
    votes without a share; 3 tests of the suite fail, each on the check of item 26; and the 20
    decoded inputs with a failed ceremony are rejected, 19 of them by that check.
55. **Negative controls of the reshare restart target (R19).** The driver plants each fault
    in a full run, at the boundary the oracle observes: an engine that stops on its own, at
    its first start and after a restart, an engine panic, and a harness panic (I8); a second
    description at another engine and at the same engine (I1); a share of another identity,
    of another output, and for an epoch no engine reached, a registration of another sharing,
    for such an epoch, and without the held share, a player whose share is not on record, a
    share pruned from an engine's own store before its last restart, so that the engine
    itself registers without it, and, on the failing input, a carried share that is not on
    record under the new epoch (I2); a schedule other than the one the engines were given
    (I4); on the failing input, a first output other than the one the engines were given,
    once with another summary and once with another sharing (I6); a block (I9). I3 and I5
    have no control of their own in a full run: the records only grow, so a share that fails
    either of them fails I2 first. Their controls are the ones over built records in
    `invariants.rs`.

    The carried share is kept off the record by handing the engine, at its restart before the
    failed ceremony ends, a copy of its secret store that the oracle does not read. Taking the
    share out of the engine's own store shows nothing: the engine stores it again at every
    start that finds it in the epoch. The engine whose share is pruned before its last restart
    is followed after that restart (item 47), so that control takes a run in which the
    engine's journal holds no vote of the epoch it comes back to: an engine that replays its
    votes under a scheme that cannot sign panics, and I8 reports that first.
56. **Layout of the probe harness.** Building `dkg_probe` added `probe_input.rs` (the input and
    its event program) and `probe.rs` (the driver). Its observation records and the checks of
    I12-I14 are in `invariants.rs`. What a probe driver watches an actor through (the receiver
    and blocker wrappers), the acknowledging application of a marshal with nothing above it, the
    prefix cut, and the certification and injection of a fabricated finalized block were moved
    out of `stateful/probe.rs` into the new `stateful/observe.rs`, made generic over the witness
    they report to, the block, the scheme, and the marshal variant, and are used by both probe
    drivers (item 11). The stateful probe's input decoding and predicates are unchanged. The
    construction of a marshal is not shared with the stateful probe: it is typed to each
    feature's block, scheme, and runtime context. Within this feature it is defined once, in
    `reshare_stack.rs`: the configuration of the backfill resolver, the two archives, and the
    configuration of the marshal itself are what a reshare engine and a member of the probe
    target are both built from.
57. **Fabricated chain (R21).** Five identities take part. Four are the dealers and the players
    of every epoch: the discovering probe and the three sources. The fifth is among the next
    players of every epoch, with the three sources, so it is tracked and is not a dealer. Blocks
    are of the reshare chain's type, at heights 1 to 5 in epochs of two blocks, and the block at
    height `h` is at view `h` of its epoch. The final block of every epoch carries the next
    epoch's description, and every description carries the output of its own trusted `deal`, so
    the descriptions of different epochs and of the two chains differ in content. Every block is
    finalized with the shares of the first deal, under the reshare chain's namespace, and the
    first deal's group public key is what every marshal and probe of that chain verifies with
    (R7). A real reshare would keep that key in every description; the probe never relates a
    description's output to its verifier, so nothing observes the difference. The foreign chain
    is the same construction over other deals. The sharing mode of the deals is an input control.
58. **What a source holds (R22).** A source holds the first `h` blocks of one chain, with `h`
    from 0 to 5: contiguous from genesis, so it holds every boundary below its height. Heights
    are drawn around a common tip. A source holds the foreign chain in a quarter of the draws. A
    source that holds a recent block and lacks an older boundary is not produced.
59. **Minimum epoch (R22).** Two controls set it: the epoch of the checkpoint the discovering
    probe bootstraps from, 0 to 2, whose participants are the fabricated chain's for that epoch,
    and an optional persisted floor, a finalization of the fabricated chain at a height from 1
    to 5. The oracle takes the minimum epoch to be the later of the two, as the probe's
    documentation states it.
60. **Event program (R22).** The target reuses the stateful target's `ProbeEvent`, with its
    bounds on payload and advance, in programs of at most 32 events. A source builds responses
    of three kinds, so the source selector of a release, replay, truncation, or fragment names
    the source by its remainder modulo three and one of that source's responses by its quotient:
    zero is the newest, and each step goes back one distinct response. The stateful target reads
    only the remainder. A duplicate repeats what the source last delivered. The program is not
    drawn uniformly, because a discovery needs its sources attached, a subscription, the latest
    finalizations of two sources, and then the boundary finalization and the block of one: it
    opens with the attachments and the subscription, each seven times in eight, and half of the
    events after that are releases of a newest response that walk the sources in a drawn order,
    three in a row each. The other half draws any event, a quarter of whose selectors go back
    one or two responses.
61. **Timing.** The network is the stateful one: lossless links of 10 ms with 1 ms of jitter that
    stay up for the whole run, and a block does not disconnect (item 3). Every event is followed by
    a settle of 100 ms. The retry timeout is the stateful probe target's, 1001 ms, which the reused
    bound of 15 steps on an `Advance` was set for: an advance of ten steps or more lets it expire on
    its own, whenever the probe last sent a request, and so do ten events in a row in which the
    probe sends nothing. Every request the probe sends restarts it, so each of the three phases of a
    discovery has ten events before it is retried. The target was first built with 2001 ms, which no
    advance the decoder draws outlasts on its own. Over the same 6,000 sampled sessions the shorter
    timeout raised the share of runs in which an advance crossed a retry from 5.7% to 16.4%, the
    share that sent more requests for the boundary and its block than the two of a plain discovery
    from 1.6% to 3.6%, and the share in which a second responder built the block from 0.9% to 1.9%;
    the share that emitted an artifact fell from 20.6% to 19.5%. The run is bounded at 60 s of
    simulated time, which no program reaches.
62. **Captured responses stay opaque (R22).** The harness never decodes a probe message. What a
    captured response answers is known from the request that drew it, which is recorded when the
    source takes it: a response to the first request the discovering probe ever sent is a latest
    finalization, a response to a request the probe addressed to a single peer is a block, and
    any other is a boundary finalization. This rests on the documented order and addressing of
    the probe's requests.
63. **Wire tags.** The one fact of the wire format the harness uses is the documented number of
    tags, six. Junk is bytes whose first is not a tag, and bytes that start with a tag are not
    sent. A truncation that leaves at most one byte is known to be cut inside the tag or right
    after it.
64. **What the oracle knows of the probe's state (R22, I14).** The oracle keeps a small model of the
    probe's state, `ProbeKnowledge` in `invariants.rs`, and advances it from what crosses the
    probe's public boundaries: what the program did to its mailbox, the requests the probe sent, and
    what was delivered to it. The model holds four things. First, which loop the probe runs: it
    certainly discovers (its marshal is not attached, or a subscription was held open ever since the
    attachment), certainly serves (its marshal was attached while no subscription was open, a
    subscription closed without an artifact, or its marshal is attached and a subscription
    resolved), or neither: after the last subscription is dropped with the marshal attached, the
    probe handles whatever next wakes it as a discovering probe and serves from then on, and the
    model does not follow its wake-ups. Second, whether the floor is certainly not selected (no
    request other than for latest finalizations was sent, no artifact was seen, and fewer than
    `f + 1` valid latest replies were delivered since the last such request) or certainly selected
    (such a request was sent, or an artifact was seen). Third, which peer the block was last
    requested from: the peer the probe's most recent request was addressed to alone. The probe
    addresses a request to one peer exactly when it starts to await that peer's block, and sends
    another request whenever it gives that peer up (`glue/src/dkg/probe/actor/discovery.rs`, lines
    493-520). Fourth, whether the boundary is certainly awaited: a request for it was sent, no
    artifact was seen, and the peer the block was requested from has not delivered the whole of it.
    The probe reads a block response past its epoch only from that peer (`discovery.rs`, lines
    453-461), so a block from anyone else, whole or cut anywhere past its epoch, changes nothing in
    the model and must not get its sender blocked.

    The model does not reproduce the probe's sample, its verification, or its queue of responders
    (R22). A delivery whose verdict would need one of them is left open: the probe may block its
    sender or not. Four kinds of delivery are left open. One on which a discovering and a serving
    probe differ, while the model does not know which the probe is. A latest reply the probe would
    refuse, once `f + 1` valid replies were delivered and neither a request for the boundary nor an
    artifact followed: the floor is then selected if it is in epoch zero and the artifact resolved
    with no subscription open, and is not if the probe dropped its sample for want of a subscriber.
    A foreign boundary finalization, or a cut block from the peer the block was requested from,
    after that peer delivered the whole block with no subscription open: whether the block resolved
    the artifact is the probe's verification. A foreign boundary finalization relayed by an identity
    that delivered a valid one: whether the probe still holds that identity as a responder is its
    queue. Of the 78,189 deliveries of a four-minute smoke run, 376 were left open.
65. **Probe blocking table (section 11, I14).** Read off `glue/src/dkg/probe`. While
    discovering, the probe decodes every message first and blocks the sender of one with no tag,
    an unknown tag, or a finalization cut short, whatever it awaits. A block response is decoded
    past its epoch only from the peer the block was requested from, which is blocked if it is cut
    short; from anyone else it is ignored, whole or cut past its epoch. A latest reply is judged
    only until the floor is selected: the sender that is not a dealer is blocked, whatever the
    reply; a stale reply is set aside, from either chain; a foreign reply that is not stale blocks
    its source. A boundary finalization is judged only while the boundary is awaited: a foreign one
    blocks its sender, unless the sender already delivered a valid one, in which case nothing is
    required. The identity that is not a dealer is not blocked for a valid boundary finalization or
    block: the probe asks every peer for those, and takes them from it. While serving, the probe
    reads requests only: it blocks the sender of a message with no tag or an unknown tag, and of
    nothing else. Every other delivery must not be blocked. Each block the probe places is
    attributed to the delivery it was processing, the probe may block only that delivery's sender,
    and the pairs the network recorded must be exactly the blocks the probe placed, so a block by a
    source is a violation too.
66. **I12 as checked.** The replies are every whole latest reply of the fabricated chain that is not
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
    332-335). The replies as listed include it all the same, which changes nothing: a probe with no
    subscriber records nothing, and the next subscription makes it ask again (`discovery.rs`, lines
    201-214), from where the replies are listed anew. The negative control is a run in which the
    third source's higher reply is delivered after the first two and before the boundary, with that
    reply's finalization planted as the floor.
67. **I13 as checked.** Beside the comparison with the fabricated chain, the artifact's floor,
    boundary finalization, and description must each differ from every one of the foreign
    chain's, and the boundary must be one that a source of the fabricated chain was seeded with.
    Artifacts are compared field by field, since the scheme they are generic over is not
    comparable.
68. **Closing subscription.** After the program the harness opens one more subscription, so that
    an artifact resolved while none was open is seen and checked. On a probe that is still
    sampling with no subscriber this sends one more request for latest finalizations.
69. **No request is sent to a source.** Every adversarial message goes to the discovering probe
    (R22). A serving probe's handling of a malformed request is therefore exercised only on the
    discovering probe once it serves, by junk and by empty messages, and a source is never asked for
    a boundary other than the one the discovering probe selected.

    It follows that every well-formed response a program delivers is one a source built for a
    request of the discovering probe, sent by that source or relayed by the identity that is not a
    dealer. No well-formed response for another epoch than the floor's is ever delivered. Nothing a
    source of the foreign chain built is ever delivered as the response the probe awaits: its
    boundary finalization fails verification, so it never becomes a responder, and only a responder
    is asked for the block and has its block read. Every whole block the probe reads is therefore
    the boundary block that its responder's finalization commits to. These lines of
    `glue/src/dkg/probe/actor/discovery.rs` never run in this target: 395-402, where a boundary
    finalization of an earlier epoch is ignored; 405-408, where one of a later epoch blocks its
    sender; 482-487, where a block that matches the responder's finalization and is not the boundary
    block blocks its sender; and the three early returns of `artifact_from_block` in 527-536 that
    reject such a block, for its height, for carrying no epoch description, and for describing
    another epoch. Reaching them takes a well-formed response the discovering probe did not ask a
    source for: a boundary finalization or a block of another epoch or height. The target delivers
    none, since it sends no request to a source and builds no response itself.
70. **Feature gating of `dkg_probe`.** The `dkg` module, and the `network` module of `stateful`
    it uses, are compiled under `dkg-probe` too. `stateful/observe.rs` is compiled in every
    build, and is unused shared support in a build with neither probe target (item 32).
71. **Writes are held around a scheduled crash (R16, A6, 7.3).** A crash is an abort of the
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
    the state-sync target (item 84). The Twins targets and the probe target pace nothing, and
    their runs are unchanged.
72. **What a held write may leave behind (R14, R16).** Only what a crash between two writes
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
    wiped or rolled back, which is the state loss R16 excludes. In the sample of item 74, 28%
    of the held writes dropped after they were applied were blob changes without a sync (203
    of 726), and 32% in `dkg_reshare_restarts` (249 of 773). Such a change would survive if
    another task of the engine synced the blob while it was held. The harness does not look
    for that, and of 450 such changes examined none was synced.
73. **Where the pacing decisions come from (R4, I10).** From the tape alone, read backwards so
    that the draws are independent of the ones the runtime and the restart schedule make from
    its start. Each scheduled crash draws how far back its window reaches (100 ms, 500 ms, 2 s,
    or 8 s) and what is held in it: nothing; one in two of the writes of the DKG module's own
    state and nothing else; those and one in four of every other write; or one in four of the
    former and one in sixteen of the latter. Each write that starts in a window, and that
    item 78 admits, draws whether it is held and at which stage. The schedule itself is not
    changed.
74. **Why a hold lasts until the crash.** A pause of a fixed length is almost never the one a
    crash lands in. Over 1,500 sampled inputs of `dkg_bootstrap_restarts` with 3,404 crashes,
    suspending every write for one millisecond, the executor's cycle, let 88 crashes (2.6%)
    drop a suspended write, one of them a write of the DKG module's own state, while 5.5
    million writes were suspended and resumed. Holding a write from where it starts until its
    engine's crash, under the rule of item 78, lets 862 of the same crashes (25%) drop a held
    write and 426 (13%) drop one of the DKG module's own state: 244 such writes before they
    were applied, 240 after they were applied and durable, and 16 after they were applied to
    a blob without a sync. No held write resumed, none was dropped by a running engine, and
    none was still held when its run ended. A third of the crashes are brought forward once
    the ceremony is over (item 35); four of those 1,152 still dropped a held write. Among the
    others, a crash that holds only the DKG module's writes dropped one of them in 7% of the
    cases with the 100 ms window, 17% with 500 ms, 49% with 2 s, and 67% with 8 s. The runs
    ended as before (1,499 completed, one at the timeout) and took 4% more simulated time.
    Before item 78 bounded the holds, 962 crashes (28%) dropped a held write and 473 (14%) one
    of the DKG module's own state, and the 8 s window reached 84%: the difference is the holds
    that began before another identity's outage was over. In `dkg_reshare_restarts` the same
    1,500 inputs hold 3,580 crashes, of which 1,011 (28%) dropped a held write and 449 (13%)
    one of the DKG module's own state; 1,426 runs completed and 74 reached the timeout, where
    1,430 and 70 did without pacing, and the runs took 3% more simulated time.
75. **Pacing makes a ceremony fail on some inputs.** An identity whose writes are held is slow
    ahead of its crash, so it is unavailable for longer than its downtime, and the ceremony
    may still be under way when the next identity is crashed. One identity is impaired at a
    time all the same (item 78). A fixed input of the bootstrap regression suite fails this
    way: the first identity is slow for 4.3 s and down for 0.6 s, the next one is crashed
    0.3 s after it came back, and the same input succeeds when nothing is held. So do 2 of
    the 120 inputs with four restarts over clean links that the suite's listing covers. Of
    the 1,500 sampled inputs, one ends in a failed ceremony in `dkg_bootstrap_restarts`,
    agreed by all four engines with no share held (I1, I6), and one other does without
    pacing. Under the first rule four did, two of them in runs in which two identities were
    impaired at once. In `dkg_reshare_restarts`, 6 of the 1,500 runs hold a failed ceremony,
    7 ceremonies in all, against 3 runs without pacing. Item 4's remark that no sampled input
    fails a ceremony predates this.
76. **What pacing does not reach.** A crash that is brought forward to before its window opens
    finds nothing held; one that is brought forward into its window drops what is held then.
    Reads are not held. A held write suspends the task that awaits it, so that task starts no
    later write before the crash. Where a task awaits several writes at once, as the reshare
    store does for the two halves of a dealing, the others go on, which is how one half of a
    dealing comes to be durable without the other. Another actor of the same engine goes on
    as well, and may have a write of its own held. A torn write is never produced: a write is
    whole or absent, in the secret store and on the runtime's storage alike. Two identities
    are never slow or down at once (item 78). The reshare store's `MissingPlayerDealing` path
    stays unreached, and should: an engine acknowledges a dealing only after both of its
    halves resolved, so only the state loss R16 excludes leaves an acknowledged dealing out
    of the secret store.

    What a blob holds is read from its partition's name, and that decides the odds its writes
    are held at (item 73) as well as how the report counts them (item 77). The DKG module's
    own state is the secret store, the reshare actor's journal (`-reshare_events`), and the
    material of a planned state sync (`_dkg_state_sync`). The Simplex journals are not: the
    bootstrap chain's (`-simplex`) and the ones the orchestrator keeps per epoch
    (`-orchestrator_consensus_` and the epoch), which are all the orchestrator stores, count
    as the chain's, with marshal's caches and archives. A partition of any other name counts
    as the chain's too. Each restart target has a test that fails when an engine opens a
    partition whose name is not known, or none that is taken for the reshare journal, so a
    partition the DKG module renames does not move to the other odds unnoticed.
    Removing a blob and creating one are not paced either, so a crash cannot fall between the
    removals of a journal prune or rewind and the write that follows them.
77. **Pacing in the run report.** The report of a restart run, in both targets, counts the
    crashes that dropped a held write; the held writes dropped before they were applied, those
    dropped after they were applied and durable, and those dropped after they were applied to
    a blob without a sync (item 72); how many of each were writes of the DKG module's own
    state; the held writes that resumed; the held writes a running engine dropped; and the
    held writes that were still held when the run ended. They are counted from the run's
    record of its held writes, which notes of each whether it had been applied when it ended.
    They feed no check.
78. **One identity is impaired at a time (item 4).** An identity with a held write is slow, so
    it is the run's one faulty identity from its first held write until its restart has
    completed. A write is therefore held only while every identity is up, only for the
    identity whose crash is the next one on the schedule, only inside that crash's window,
    and no sooner than 50 ms after the restart before that crash completed. A start, the
    first ones included, is complete once the engine is spawned. The schedule runs its events
    one after another, so until that crash and its restart are done no other identity is
    crashed, and none has a write held. The 50 ms are the shortest delay the schedule itself
    puts between the due time of a restart and the due time of the next crash (item 36). A
    crash that is brought forward can follow a completed restart sooner than that, with or
    without pacing; a held write never does, so the first held write, which is where the next
    identity becomes unavailable, keeps that distance from the completed restart. Nothing is waited
    for after the first starts of a run: the schedule has no such distance there either.

    The first cut held a write for any identity whose own next crash was within reach, and
    looked for an identity that was down only when the write started. A write of one identity
    could then stay held through the whole outage of another, and two identities could have
    writes held at once: in 90 of 1,500 sampled runs of `dkg_bootstrap_restarts`, and in 122
    of the 1,500 of `dkg_reshare_restarts` with that rule in force there.

    The property is checked as well as built. Every run records each held write (what it was,
    when its hold began and ended, and how it ended) and each outage, and derives from them
    the span in which each identity was impaired. In debug builds, which libFuzzer's are, the
    pacing asserts that no write is admitted and no identity is crashed while another is
    impaired, and at the end of the run that no two spans of different identities share a
    moment. The regression suite asserts the last over every fixed input of both restart
    drivers but the negative controls, over 48 drawn schedules under which stub engines write
    without pause and every write in a window is held, and over samples of decoded inputs.
    Over the 1,500 inputs above no run of either target has two identities impaired at once.
    The count is in no report of these two targets. The state-sync target paces its engines by
    the same rule, counts a joiner that has not started as well, and prints the count in its
    report (item 84).
79. **Layout of the state-sync harness.** Building `dkg_state_sync` added four files: the target
    file `fuzz_targets/dkg_state_sync.rs`, `joiner.rs` (the caller's side of DKG state sync: the
    durable record of an engine's floor and what one start of the engine enters from),
    `state_sync_input.rs` (the target's input), and `state_sync.rs` (the driver). The driver runs
    the cluster of `reshare_cluster.rs` under the environment of `environment.rs`. Eight existing
    files changed. `Cargo.toml`: the binary and its feature. `mod.rs`: the modules and what they
    export. `invariants.rs`: the records of the chain an engine reports and of the steps its caller
    takes, the epochs an engine entered without playing their ceremony (item 86), and the checks of
    I15 to I17. `reshare_stack.rs`: the engine's configuration says how the engine enters the chain,
    from the height-zero block or through state sync, and an engine that state syncs consults its
    caller for the probe's floor, for marshal's start, and for the material of the state-sync plan;
    the observer also records every finalized tip marshal reports and the digest of every block it
    delivers. `reshare_cluster.rs` and `reshare_twins.rs` name the entry from the height-zero block.
    `environment.rs`: a program may start one identity late. The others start with the run and the
    late one when the stack says so, through one more method of `Stack`, which has a default; the
    outages that are still to come are laid out then; and every start, crash, and wait before and
    after it goes through the code every other program is played with (item 84). The events of a
    program are played by the environment alone; `Event` is visible to the rest of the module, and
    `Program::events()` is compiled for the tests, which read a drawn schedule through them.
    `pacing.rs`: the caller's record is a partition it knows, the crashes of a schedule can be given
    their times once the run is under way, and an identity that joins late is on the trace as
    impaired until it has started. An engine that enters from the height-zero block takes no step it
    did not take before, and a program that starts no identity late is played as before: on 260
    inputs each, `dkg_reshare`, `dkg_reshare_restarts`, and `dkg_bootstrap_restarts` print the
    report lines they print on the base.
80. **Input of the state-sync target (R5, R23).** The session controls are those of item 46. The
    others are drawn after them: the joiner, any of the five identities; the join height; the
    joiner's own restart, in half the runs, as a delay of 0 to 15 steps of 10 ms doubled 0 to 6
    times (up to 9.6 s) and a downtime of 1 to 16 steps of 100 ms; the size of the schedule over all
    nodes, 0 to 3; and the delay of that schedule's first outage. The joiner's restart is drawn
    whether or not the run has one, as the doublings of the first outage are, and the epoch and the
    place of the join height are each drawn from a whole byte, so no control moves the bytes the
    later controls and the tape are drawn from: a test sets and clears the bit that decides the
    restart and finds every other field and the tape where they were. The links are fixed (R23), so
    there are no link controls and no cuts. The tape seeds the runtime, the trusted deal, the
    schedule over all nodes but for its first delay, and the pacing.

    The join height is drawn as an epoch among the ones the run is asked to complete, each equally
    likely, then one of four places in the epoch, each equally likely, then a height at that place:
    before the midpoint (16 heights), the midpoint, past the midpoint and before the final block (14
    heights), and the final block. The midpoint and the final block are where the joiner's entry
    changes (item 81), and the floor is the join height or a block or two past it. The first cut
    drew every height of an epoch equally often: of the 4,000 inputs of the review 3.6% joined at
    the midpoint and 4.0% at the final block, and 3.4% of the floors lay at the midpoint. Of 1,500
    sampled inputs now, 26% join before the midpoint, 27% at it, 25% past it, and 22% at the final
    block, and the floors lie before the midpoint in 27% of the runs, at it in 20%, past it in 26%,
    and at the final block in 27%.

    The first outage of the schedule is due 0 to 15 steps of 10 ms after the schedule's clock
    starts, not doubled in half the runs and doubled 1 to 6 times in the others (up to 9.6 s). The
    later outages keep the distances the tape draws. The sampler of item 36 draws no delay under 50
    ms, and the joiner's probe has its first replies after about 20 ms, so with the tape's own delay
    no outage took down a node the probe was asking: of 4,000 decoded inputs the tape puts the first
    outage within 100 ms of the joiner's start in 2.2% and under 50 ms in none. The input puts it
    within 100 ms in 34% of them, under 50 ms in 17%, within 20 ms in 11%, and with the joiner's
    start in 4%. In 368 of 1,500 sampled runs a crash of another identity found the joiner's engine
    running and not yet entered. These figures, and those of the paragraph before, are of the
    samples taken once the joiner's restart was drawn always and the outages kept their distance
    (item 84): 4,000 inputs decoded by `survey_first_outages`, and the first 1,500 sampled inputs
    run by `large_sample_impairs_one_identity_at_a_time`.
81. **When the joiner starts (R23, 7.5).** A height has been applied once marshal has delivered its
    block to the engine of one of the identities that started at genesis. The environment then
    starts the joiner (item 84). Height zero starts it with the run, and its probe asks again until
    the others have finalized a block. The floor its probe samples is the newest finalization two of
    the first committee report, so it is at the join height or a few blocks past it, and it is the
    floor, not the join height, that decides how the joiner enters: a floor up to the midpoint of
    its epoch lets the joiner play that epoch's ceremony, a later one makes it follow the epoch. The
    run's report gives the epoch of both and the place of each in its epoch.
82. **The caller's record (R24).** The DKG module leaves the floor of a state sync to its caller. A
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
    write of it (item 84). The caller's code is the harness's and the engine's tasks run it. All of
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
    the DKG module: what the probe does with the floor it is handed is for `dkg_probe` to check
    (item 59).
83. **When a sync is complete (R24, I15).** A sync is complete once its completion is on the
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
    (item 87).

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
84. **Restart schedule of the state-sync target (R16, R23, item 4).** The schedule over all nodes is
    drawn from the tape with the sampler of item 36, over five identities, and its first outage is
    due when the input says (item 80). The joiner's own restart is one more outage. The environment
    lays them out one after another in the order they are due, at the moment the joiner starts: an
    outage that is due while another lasts, or less than 50 ms after that one's restart is due,
    starts 50 ms after that restart is due. At most one identity is down at any moment, the crash
    after a restart is due no sooner than the tape's own schedule has it (items 36 and 78), and a
    crash of the joiner's own clock is late only when another identity is down, or has just come
    back, at its time. The first outage is exempt: it may be due with the joiner's start, after
    which nothing is waited for. The driver lays out nothing and crashes nobody itself. The
    environment starts the four identities that start at genesis, starts the joiner when the
    driver's stack says that the join height has been applied, and plays every outage through the
    starts, crashes, and waits every restart target is played with.

    The first cut started an outage that was due while another lasted at the instant that one's
    restart was due. The environment plays the two events one after the other, so the crash followed
    the completed restart at once. Over 3,000 sampled inputs (`survey_outages`, the same inputs
    under both layouts), 1,021 of the 3,435 restarts that were followed by another crash had that
    crash due at the same instant, in 854 runs, and 13 had it due less than 50 ms later; now none
    has, and the shortest distance is 50 ms. As played, and counted from the moment the restart had
    completed, 405 runs (13.5%) held a crash that came 0 ms after it; now none does. A restart takes
    15 to 38 ms of simulated time to complete, 28 ms as a rule, so a crash that is due 50 ms after a
    restart is due comes 12 ms or more after the restart completed, as it does under the schedule of
    the other restart targets, which keeps the same 50 ms between due times. A crash that is brought
    forward once the stack has settled (item 52) still follows a completed restart within
    milliseconds, in every restart target: 2,010 of the 3,435 were, 1,053 of them less than 50 ms
    after the restart completed, and 1,137 runs (37.9%) hold a crash less than 50 ms after a
    completed restart for one reason or the other, where 1,136 did. The first outage after the join
    is due with the joiner's start in 206 of the 2,651 runs that have an outage and less than 50 ms
    after it in 664, as before. No run of either layout has two identities impaired at once.

    Every engine is paced as item 71 describes, the joiner's included, at every start. The pacing is
    laid out with the outages of the schedule and the joiner's own, and is given the times they got
    when the joiner starts, so the schedule it holds writes for is the schedule that is played.
    While it syncs the joiner makes its caller's record, the material of the state-sync plan, and
    marshal's floor durable one after another, and its own crash falls between them: in the 63 runs
    of the regression suite that restart the joiner once, at 21 delays under three tapes, its crash
    dropped a held write in 38, and 20 of the dropped writes were of the caller's record and 11 of
    the plan's material.

    One identity is impaired at a time here too (item 78), and the joiner counts as follows. A
    joiner that has not started is as unavailable as an identity that is down, so it is the run's
    impaired identity from the start of the run until its first start has completed: until then no
    identity is crashed and no write is held, and its span is on the pacing's trace, where the
    overlaps are counted. Once it has started it counts like any other identity, also while it
    syncs: it is impaired while it is down or has a write held, and not otherwise, so the schedule
    may crash another identity, and hold that identity's writes, while the joiner's probe discovers
    and while its marshal fetches the floor. A start is complete once the engine is spawned, as in
    item 78, and the joiner's first start is a first start: no write waits 50 ms for it, because
    this target's schedule puts no such distance after it. The rule counts identities that are down
    or slow. A joiner that is in the committee and has no share yet does not sign, so a crashed
    member beside it leaves two of four not signing although one identity is impaired. The
    regression suite asserts that no two spans of impairment overlap over every fixed input but the
    negative controls and over a sample of decoded inputs, and no run of 10,000 sampled inputs has
    an overlap, under the layout of this item as it is now. The run's report gives what item 77
    lists, how many of the crashes that dropped a held write were the joiner's, how many crashes of
    another identity found the joiner's engine running and not yet entered, and the number of
    overlaps.

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

    What each position costs. Off: a ceremony fails only in the ways items 4 and 75 name, so a state
    sync into an epoch whose ceremony failed, and the walk back by which the DKG module recovers a
    share for such an epoch from an earlier one (`recovered_share`), are next to unreachable; and
    after the join a member joiner without a share beside one crashed member still leaves two of
    four not signing. On: with the joiner in the committee, an outage before the join leaves two of
    four members out, which is more than the fault bound of one. The review ran the same 4,000
    inputs both ways, before pacing: off, 5 runs held a failed ceremony, and in 1 of them the
    joiner's floor was in the second epoch or a later one; on, 75 and 51. No invariant fired either
    way. With pacing and the input of item 80, the same 4,000 input files: off, 34 and 2; on, 182
    and 127; again no invariant fired, and no two identities were impaired at once. With the
    joiner's restart drawn always and the distance after a restart, the same files: off, 33 and 2;
    on, 187 and 125; no invariant fired, and no two identities were impaired at once.
85. **End of a state-sync run (7.5).** A run ends when the schedule has been played out, the latest
    instance of every engine has registered the scheme of the epoch after the last one selected
    (item 47), and the joiner has completed its sync and registered the scheme of an epoch after the
    one of its floor. The last condition makes the joiner commit a boundary of its own, which I17
    compares, also when the join height is the last height of the run; the chain then goes on for up
    to one more epoch. Events are brought forward as in item 52, so the outages of a run whose join
    height is near its end land after the joiner's first boundary. A run whose joiner never
    completes its sync ends at the timeout, which is the 120 s of item 51.
86. **I2 for the joiner (I17, item 24).** The joiner is excused a share exactly where the DKG module
    makes it register an epoch whose ceremony it did not play. For every floor the joiner entered
    from, that is the floor's epoch, which the reshare actor registers from the state-sync material
    before it applies a block. If the floor lies past the midpoint of its epoch, it is also the next
    epoch, which the actor registers as a follower from the epoch's final block. Whether the floor
    lies past the midpoint is read from the height at which marshal delivered the floor's block to
    the joiner, which happens before the joiner can apply that final block. In every other epoch the
    joiner is held to I2 like any engine: with a floor up to the midpoint it plays the ceremony of
    the floor's epoch, and with a later one the ceremony after it, and as a player of the output it
    must hold a share. The check of item 49 applies to all five engines.

    An entry excuses an epoch only if the joiner had not registered the epoch's scheme before the
    entry. A joiner syncs a second time when a crash finds the completion of its sync not on its
    caller's record (item 83), and a write of the completion that the pacing holds lets the engine
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

    The controls are over built records, where an entry after a registration excuses nothing and an
    entry before it does, and in a full run. There the caller leaves the sync of the joiner's first
    start without a completion, which stands for the held write, the joiner plays the first
    ceremony, enters the second epoch, is restarted in it, and syncs again from a floor in it. With
    the joiner's secret store unread by the oracle I2 fires for the second epoch, and with it read
    the joiner is counted as a player of every output. Both tests fail under the first cut, which
    excused the second epoch, as do the two over built records. Nothing fires on 3,000 sampled
    inputs in either position of `RESTARTS_BEFORE_JOIN`, on the 1,265 inputs of the corpus in either
    position, or in the session of item 91. Of the 4,766 epochs that the entries of the 3,000 runs
    with the switch off name, none is one the joiner had registered before the entry, so on these
    inputs the narrowing excuses what the first cut did: the case needs the completion held, and no
    other write of the joiner held with it, for longer than the rest of a ceremony.

    The exemption follows `reshare/actor/setup.rs` and `reshare/actor/follower.rs`: it covers the
    registrations the DKG module makes without a ceremony and no other. That is the exemption I17
    states: the joiner must hold a share of every other output it is a player of.
87. **I15 as checked.** The joiner's caller reports three kinds of step: a start, with what it found
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
    What detects a defect of the DKG module in this target is I2, by both of its rules (items 24 and
    49), I16, I17, and I18. The review confirmed this by changing the production code in a scratch
    copy. Of four changes to the state-sync path none tripped I15, I16, or I17. An engine that
    follows from a floor at the midpoint, where it should play, was caught by the first rule of I2,
    and a state-synced engine that registers without its share by the second. Two were caught by
    nothing and are known blind spots: an engine that never follows, and a probe that picks the
    lowest reply of its sample.
88. **I16 as checked.** What the nodes that started at genesis finalized is read from what their
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
89. **I17 as checked.** Marshal delivers the joiner nothing below its floor, so every block and
    every description the joiner was delivered is compared with what each other engine was delivered
    at that height and for that epoch, and a second block at one height at the joiner is a
    violation. The measurement runs I8, then I15 to I17, then the reshare checks, so a description
    on which the joiner differs is reported under I17. The comparison of descriptions repeats I1,
    which compares every engine's description of every epoch, the joiner's included, and which would
    report the same defect if I17 did not come first. The comparison of blocks has no other check.
90. **Negative controls of the state-sync target (R19).** In a full run the driver plants: an engine
    that stops on its own, the joiner while its probe discovers and one that started at genesis, an
    engine panic, and a harness panic (I8); a start reported as syncing after the completion, and as
    finding no record of the completion, and a caller that leaves its completion off the record and
    so syncs a second time after a restart (I15); a caller that reports a floor over another block,
    and one that reports another description, than it entered from (I16); a block at the joiner that
    the others did not commit and a second description of an epoch (I17); a joiner that played a
    ceremony and has no share of its output on record, and one that played a ceremony, entered the
    next epoch, synced again from a floor in it, and has no share of that epoch's output on record
    (I2, item 86); a block (I9). The clauses of I15 about the floor of an interrupted sync, the
    floor's round and the pairing's epoch under I16, and the two-blocks clause of I17 have controls
    over built records in `invariants.rs`, as do I1 and I3 to I6 (item 55).

    A scenario test of the driver does not name the one input that shows its scenario. Where a floor
    falls and what a crash finds depend on the timing of the engines, so the test runs a small range
    of join heights, restart delays, or tapes and asserts its property on the first run that shows
    the scenario; every run it makes on the way is checked like any other. The one test that named
    an input, of the partitions the engines open, now holds every run of three join heights to what
    an engine opens in any run and one of them to all of it (item 93). The unit tests of the
    caller's logic are in `joiner.rs` and `reshare_stack.rs` (item 82), those of the late start in
    `environment.rs`, and those of what the pacing does for it in `pacing.rs`.
91. **What the first sessions of the state-sync target measured (section 10).** The first sessions
    predate pacing and the input of item 80. Three and a half minutes with the sanitizer made 258
    runs, and five and a half without it 1,643. No run crashed, reached the timeout, or stopped,
    every joiner completed its sync, 35 of the 1,643 floors lay at a midpoint, the joiner resumed an
    interrupted sync in 59 runs, and one ceremony failed.

    With pacing and the input of item 80, a session of 200 s with the sanitizer made 296 runs, and
    one of 330 s without it made 2,203 on the corpus the first had left. No run of either crashed,
    reached the timeout, or stopped, and no invariant fired. In every run the joiner entered through
    state sync, completed its sync, and committed a boundary above its floor, so I15, I16, and I17
    each compared something in every run. Of the 2,203 joiners, 1,133 entered from a floor in the
    first epoch, 715 in the second, 325 in the third, and 30 in a later one, 1,070 of them through a
    boundary their probe discovered; 557 floors lay before the midpoint of their epoch, 389 at it,
    595 past it, and 662 at the final block. The joiner was restarted in the middle of its sync and
    resumed in 238 runs, was restarted before it had a floor and synced afresh in 260, and was
    restarted after its sync, without syncing again, in 967. I17 compared 224,143 blocks and 12,357
    descriptions. 4,550 ceremonies succeeded and 16 failed, one of them in a run whose joiner had
    entered past the first epoch. The schedule crashed 4,327 engines: 1,264 in a dealing window,
    1,113 in an inclusion window, 518 at a boundary, and 1,432 past the last epoch asked for. 469
    crashes of another identity found the joiner's engine running and not yet entered. 946 crashes
    dropped a held write, 383 of them the joiner's: 634 held writes were dropped before they were
    applied, 479 after they were applied and durable, and 192 after they were applied to a blob
    without a sync, and 463 of all those were writes of the DKG module's own state or of the
    caller's record. No held write resumed, was dropped by a running engine, or was still held when
    its run ended, and no two identities were impaired at once. A run took 1.6 s to 86 s of
    simulated time, 7.6 s at the median.

    Those two sessions decoded the joiner's restart only where the run had one and laid a pushed
    outage out at the instant the one before it ended. With the restart drawn always and the
    distance after a restart (items 80 and 84), a session of 330 s without the sanitizer, from a
    copy of the 1,265 inputs, made 2,092 runs, the corpus replay included, and left 1,495 inputs. No
    run crashed, reached the timeout, or stopped, no invariant fired, and no report counts an
    overlap. In every run the joiner entered through state sync, completed its sync, and committed a
    boundary above its floor. Of the 2,092 joiners, 1,108 entered from a floor in the first epoch,
    636 in the second, 309 in the third, and 39 in a later one, 984 of them through a boundary their
    probe discovered; 539 floors lay before the midpoint of their epoch, 353 at it, 555 past it, and
    645 at the final block. The joiner was restarted in the middle of its sync and resumed in 250
    runs, was restarted before it had a floor and synced afresh in 234, and was restarted after its
    sync, without syncing again, in 950. I17 compared 217,444 blocks and 11,793 descriptions. 4,328
    ceremonies succeeded and 14 failed, one of them in a run whose joiner had entered past the first
    epoch. The schedule crashed 4,244 engines: 1,247 in a dealing window, 1,069 in an inclusion
    window, 479 at a boundary, and 1,449 past the last epoch asked for. 435 crashes of another
    identity found the joiner's engine running and not yet entered. 972 crashes dropped a held
    write, 394 of them the joiner's: 703 held writes were dropped before they were applied, 476
    after they were applied and durable, and 210 after they were applied to a blob without a sync,
    and 465 of all those were writes of the DKG module's own state or of the caller's record. No
    held write resumed, was dropped by a running engine, or was still held when its run ended. A run
    took 1.6 s to 77 s of simulated time, 7.5 s at the median. With the sanitizer, a session of 150
    s over 106 of the 1,265 inputs made 146 runs, and nothing fired.

    Over the 1,265 inputs the first two sessions left, as those sessions decoded them, the target
    alone reaches 73.57% of the lines of `glue/src/dkg`, where it reached 73.27% over the 988 inputs
    of the first sessions. `reshare/actor/setup.rs` went from 95.24% to 98.70% and
    `reshare/actor/inclusion.rs` from 87.69% to 88.27%. `state_sync.rs` (88.75%),
    `reshare/actor/follower.rs` (83.10%), and `probe/actor/discovery.rs` (78.80%) are where they
    were. Over the same 1,265 inputs as they are decoded and laid out since items 80 and 84, the
    target alone reaches 73.55% of those lines: `reshare/actor/setup.rs` 98.70%,
    `reshare/actor/inclusion.rs` 88.15%, `state_sync.rs` 88.75%, `reshare/actor/follower.rs` 83.10%,
    and `probe/actor/discovery.rs` 78.80%.
92. **Harness code in an engine's task (I8, items 13 and 82).** A panic is judged by the engine its
    task belongs to, so code of the harness that an engine's task runs must be marked as belonging
    to no engine, or a panic in it would be tolerated when the engine is a half of the compromised
    identity. The secret store, the providers of schemes and of participants, the applications, the
    forwarders, the pacing, the observer, and the caller of a joining engine are marked. The
    assembly of a reshare engine is marked as well: the engine's task builds the engine, and the
    steps of it that are the harness's own (the configurations it builds, the verifier, the
    height-zero block, the registrar, what it requires of the archives it opens, and the part of the
    caller that hands its record over) run as belonging to no engine. What the DKG module, marshal,
    and the storage do while they are constructed is not marked, so a panic of theirs stays the
    engine's. The marks are thread-local guards around calls that were made at the same places
    before, so no task and no poll is added: the five targets other than `dkg_state_sync` print the
    report lines they printed, on 300 inputs each. A bootstrap engine is assembled by the task that
    calls the stack, which is the driver's and belongs to no engine, and nothing of the harness runs
    in the engine's own tasks during it, so there was nothing to mark. Each stack has a test: an
    engine whose storage refuses the name of its partition fails where the harness requires its
    archives to open, in the engine's task, and the panic is recorded with no engine; a panic of the
    task that assembles a bootstrap engine is recorded with no engine too. One future wrapper in
    `stateful/runner.rs` attributes a future to an engine or to none, and the caller of a joining
    engine uses it in place of a wrapper of its own.
93. **Tests and the timing of the links.** The fixed links of the Twins, probe, and state-sync
    targets delay by 10 ms. A scenario test must not depend on that figure, so each recognises its
    scenario in what a run showed and looks for it in a range of inputs, or asserts what holds in
    every run. With the delay set to 14 ms and to 20 ms the regression suite of this feature passes
    as it does at 10 ms. Four tests failed before: the two of a half that stops on a contradicted
    dealing named one input each and now look for a half that says so among 96 inputs whose masks
    deal to one identity from one half only, of which 13 to 24 show it at each of the three delays;
    the test of the partitions the engines open is described in item 90; and the test of a sync
    interrupted in a later epoch looks among restart delays of up to 600 ms. Three tests of
    `dkg_reshare_restarts` (a crash before the new share is stored, and before and after old secrets
    are pruned) stay pinned to their seeds over links of 10 ms. They do not read the fixed link,
    since the restart targets take their links from the input, and their scenario shows in about one
    seed in 600 to 1,000, which is too many runs for a test to look through. One test outside this
    feature, `restart_after_completion_recovers_through_marshal` of the stateful state-sync driver,
    names one crash delay and fails at 20 ms.

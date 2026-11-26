# consensus/fuzz/experimental components

A catalog of the fuzz and test components the consensus fuzzers use, so a new
target reuses what exists instead of rebuilding it. Paths are relative to the
repository root; symbols are given by name, so `grep -rn <symbol> <path>` finds them.

Fuzz targets are one-line `fuzz_target!` wrappers around a generic entry point.
To add a simplex target start at [C1](#c1-simplex-entry-point-and-mode-dispatch);
for marshal start at [D2](#d2-marshal-end-to-end-drivers) (end-to-end) or
[D7](#d7-marshal-scenario-framework) (prefix copied from a unit test).
A harness for a new protocol is usually A1 + A2 + A13 + B3 + B4 + an oracle.

## Index

| ID | Component | Path |
|---|---|---|
| A1 | Deterministic runtime | `runtime/src/deterministic.rs` |
| A2 | Simulated p2p network | `p2p/src/simulated/` |
| A3 | Simplex honest mocks | `consensus/src/simplex/mocks/` |
| A4 | Simplex Twins campaign framework | `consensus/src/simplex/mocks/twins.rs` |
| A5 | Simplex Byzantine mock actors | `consensus/src/simplex/mocks/` |
| A6 | Certificate mock scheme and fixtures | `cryptography/src/certificate/mocks.rs` |
| A7 | Leader electors | `consensus/src/simplex/elector.rs` |
| A8 | Marshal simulation harness | `consensus/src/marshal/mocks/harness.rs` |
| A9 | Marshal mock application and block | `consensus/src/marshal/mocks/` |
| A10 | Aggregation mocks | `consensus/src/aggregation/mocks/` |
| A11 | Resolver wire types and `TargetedResolver` | `resolver/src/` |
| A12 | Trace collector | `runtime/src/telemetry/traces/collector.rs` |
| A13 | Fuzz and test RNGs | `utils/src/rng.rs` |
| B1 | `FuzzInput`, configurations, runtime config | `consensus/fuzz/experimental/core/src/lib.rs` |
| B2 | `Simplex` trait and scheme variants | `consensus/fuzz/experimental/core/src/simplex.rs`, `attributable_mock.rs` |
| B3 | Network setup and partitions | `consensus/fuzz/experimental/core/src/lib.rs`, `utils.rs` |
| B4 | Disrupter and mutation strategies | `consensus/fuzz/experimental/core/src/disrupter.rs`, `strategy.rs` |
| B5 | Honest validator builders and lifecycle | `consensus/fuzz/experimental/core/src/lib.rs` |
| B6 | Filterable block relay | `consensus/fuzz/experimental/core/src/block_relay.rs` |
| B7 | Twins driver | `consensus/fuzz/experimental/core/src/lib.rs`, `twins_network.rs` |
| B8 | Receiver filters | `consensus/fuzz/experimental/core/src/network.rs` |
| B9 | Byzantine activity counter | `consensus/fuzz/experimental/core/src/byzantine.rs` |
| B10 | Audit recorder | `consensus/fuzz/experimental/core/src/simplex_audit.rs` |
| B11 | Trusted continuation (prefix) framework | `consensus/fuzz/experimental/core/src/continuation.rs` |
| B12 | BFT reference bounds | `consensus/fuzz/experimental/core/src/bounds.rs` |
| B13 | Peer-load state bounds | `consensus/fuzz/experimental/core/src/state_bounds.rs` |
| C1 | Simplex entry point and mode dispatch | `consensus/fuzz/experimental/simplex/src/lib.rs` |
| C2 | Simplex safety invariants | `consensus/fuzz/experimental/simplex/src/invariants.rs` |
| C3 | Happens-before coverage | `consensus/fuzz/experimental/simplex/src/happens_before.rs` |
| C4 | State coverage | `consensus/fuzz/experimental/simplex/src/state_cov.rs` |
| C5 | ByzzFuzz | `consensus/fuzz/experimental/simplex/src/byzzfuzz/` |
| C6 | Mallory | `consensus/fuzz/experimental/simplex/src/mallory/` |
| C7 | Chaos and ChaosTwins | `consensus/fuzz/experimental/simplex/src/chaos/` |
| C8 | Simplex prefix entry points | `consensus/fuzz/experimental/simplex/src/trusted.rs` |
| C9 | Directed peer flood | `consensus/fuzz/experimental/simplex/src/flood.rs` |
| C10 | Equivocation evidence | `consensus/fuzz/experimental/simplex/src/evidence.rs` |
| C11 | Honest blame | `consensus/fuzz/experimental/simplex/src/blame.rs` |
| C12 | Blackout | `consensus/fuzz/experimental/simplex/src/blackout.rs` |
| C13 | Proposal switch | `consensus/fuzz/experimental/simplex/src/proposal_switch.rs` |
| D1 | Marshal store harness | `consensus/fuzz/experimental/marshal/src/marshal/store.rs` |
| D2 | Marshal end-to-end drivers | `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/` |
| D3 | Marshal coding stack and faults | `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/` |
| D4 | Marshal end-to-end invariants | `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/invariants.rs` |
| D5 | Marshal Twins backend | `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/twins/` |
| D6 | Marshal pre-GST scenarios | `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/scenario.rs` |
| D7 | Marshal scenario framework | `consensus/fuzz/experimental/marshal/src/scenarios/` |
| D8 | Marshal golden and prefix tests | `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/` |
| E1 | Aggregation engine harness | `consensus/fuzz/experimental/aggregation/src/aggregation.rs` |
| E2 | Codec round-trip targets | `consensus/fuzz/experimental/aggregation/src/aggregation_decode.rs` |
| E3 | Data-structure targets | `consensus/fuzz/experimental/structures/fuzz_targets/` |
| F1 | Run, reproduce, measure | `consensus/fuzz/experimental/justfile` |

## A. Upstream foundations

### A1. Deterministic runtime
- **Goal:** A seeded executor with simulated time. The same seed gives the same task schedule, so every fuzz input replays exactly.
- **Path:** `runtime/src/deterministic.rs` (`Runner`, `Config`, `Context`, `Auditor`)
- **When to use:** Every async harness. Seed `Config` from fuzz entropy with a timeout. `Context::auditor` returns a digest of everything the run did, for pinning or comparing runs.
- **Example:** `consensus/fuzz/experimental/core/src/lib.rs` (`bounded_fuzz_runtime_config`); `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/golden.rs` (`ordinary_marshal_runs_are_unchanged`)
- **Gotchas:** All tasks are supervised. When a task finishes or is aborted, all its descendants are aborted, so spawn short-lived tasks from `context.child(..)`, never from a context that owns engines.

### A2. Simulated p2p network
- **Goal:** An in-process network with per-link latency, jitter and success rate, dynamic links, and sender/receiver splitting. It is deterministic on A1.
- **Path:** `p2p/src/simulated/` (`Network`, `Oracle`, `Link`, `SplitForwarder`, `SplitTarget`, `SplitOrigin`, `split_with`)
- **When to use:** Any multi-node harness. `Oracle::add_link` and `remove_link` shape the topology. `split_with` on a sender or receiver intercepts one node's traffic, which is how Twins and the ByzzFuzz forwarders work.
- **Example:** `consensus/fuzz/experimental/core/src/lib.rs` (`setup_network`); `consensus/fuzz/experimental/core/src/utils.rs` (`link_peers`, `apply_partition`)
- **Gotchas:** The fuzz harnesses set `disconnect_on_block: false`, so `Control::block` does not stop delivery. Cut traffic with `remove_link` or `apply_partition`.

### A3. Simplex honest mocks
- **Goal:** An honest application (propose, verify, certify), a payload relay, and a reporter that records activity for the invariants.
- **Path:** `consensus/src/simplex/mocks/application.rs` (`Application`, `Certifier`); `consensus/src/simplex/mocks/relay.rs` (`Relay`); `consensus/src/simplex/mocks/reporter.rs` (`Reporter`)
- **When to use:** Building honest simplex validators. Usually used indirectly through B5.
- **Example:** `consensus/fuzz/experimental/core/src/lib.rs` (`build_validator`, `CertifyChoice`)
- **Gotchas:** The mock `Reporter` keeps summary maps. `finalizations` is overwritten per view, while `finalizes` is append-only. For full history use B10.

### A4. Simplex Twins campaign framework
- **Goal:** Generates Twins cases. Each round sets the recipients of a compromised identity's primary and secondary halves and picks the leader, then the run returns to all-to-all synchrony.
- **Path:** `consensus/src/simplex/mocks/twins.rs` (`Framework`, `Mode`, `cases`, `Scenario`, `Elector`)
- **When to use:** Any Twins-style target. Upstream runs campaigns in `consensus/src/simplex/mod.rs` (`twins_campaign`); the fuzzers drive the framework through B7.
- **Example:** `consensus/fuzz/experimental/core/src/lib.rs` (`run_twins_with_backend_and_hook`); `consensus/fuzz/experimental/core/src/twins_network.rs` (`twins_within_mask`)
- **Gotchas:** `Framework::participants` is at most 64 (recipient sets are `u64` masks). `Mode::Sampled` draws each round independently; `Mode::Sustained` repeats one split.

### A5. Simplex Byzantine mock actors
- **Goal:** Named Byzantine behaviors. `conflicter` sends conflicting notarize/finalize messages; `equivocator` sends different proposals to different nodes; `impersonator` sends invalid impersonated votes; `nuller` sends nullify and finalize for the same view; `outdated` sends stale votes.
- **Path:** `consensus/src/simplex/mocks/` (`conflicter`, `equivocator`, `impersonator`, `nuller`, `outdated`)
- **When to use:** You want a fixed, protocol-aware Byzantine profile instead of the random mutations of B4.
- **Example:** `consensus/fuzz/experimental/simplex/src/mallory/adversary.rs` (`AdversaryRole`, `spawn_adversary`)

### A6. Certificate mock scheme and fixtures
- **Goal:** A cheap mock certificate scheme (no real cryptography) for fast fuzzing, plus real-scheme fixtures for when signatures matter.
- **Path:** `cryptography/src/certificate/mocks.rs` (`impl_certificate_mock`, `fixture_with`); `consensus/src/simplex/mocks/scheme.rs`; `consensus/src/simplex/scheme/` (`fixture`)
- **When to use:** The mock scheme for almost every target (the `*_cert_mock*` names). The ed25519, secp256r1 and BLS fixtures for codec and reporter-filtering targets.
- **Example:** `consensus/fuzz/experimental/core/src/simplex.rs` (`SimplexCertificateMock`, `fixture_with`); `consensus/fuzz/experimental/aggregation/src/aggregation_certificate_mock.rs` (`impl_certificate_mock`); `consensus/fuzz/experimental/structures/fuzz_targets/exp_simplex_reporter_filtering.rs` (`fixture`)
- **Gotchas:** The flags in `fixture_with::<ATTRIBUTABLE, BATCHABLE, ALLOW_INVALID>` change verification behavior. Match the flags of the variant you extend. Setting `ATTRIBUTABLE` alone does not make a simplex variant attributable; use `attributable_mock::fixture` (B2).

### A7. Leader electors
- **Goal:** Leader-election configs, including multi-view terms.
- **Path:** `consensus/src/simplex/elector.rs` (`RoundRobin`, `Random`, `Scheduled`, `Terms`)
- **When to use:** Choosing a leader schedule. Wrap an elector to pin a Byzantine leader at a known view.
- **Example:** `consensus/fuzz/experimental/core/src/simplex.rs` (`ByzantineFirstLeaderRoundRobin`); `consensus/fuzz/experimental/marshal/src/scenarios/elector.rs` (`ByzantineLeaderAtView`); `consensus/fuzz/fuzz_targets/simplex_elector.rs`

### A8. Marshal simulation harness
- **Goal:** The upstream multi-node marshal test harness: network and validator setup, shared constants, and test bodies written once for the standard, inline, deferred and coding variants.
- **Path:** `consensus/src/marshal/mocks/harness.rs` (`TestHarness`, `StandardHarness`, `InlineHarness`, `DeferredHarness`, `CodingHarness`, `setup_network_with_participants`, `LINK`, `TEST_QUOTA`, `NUM_VALIDATORS`, `BLOCKS_PER_EPOCH`)
- **When to use:** Reuse its constants, network setup and genesis/test-block builders in marshal fuzzers. It is also the source of the test scenarios ported in D7.
- **Example:** `consensus/fuzz/experimental/marshal/src/marshal/store.rs` (`fuzz_marshal_actor_store`, `setup_network_with_participants`); `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/twins/stack.rs` (`setup_validator`)
- **Gotchas:** `TestHarness` hard-codes the BLS threshold scheme through its type aliases, so it cannot run with the mock certificate scheme. Use `FuzzScenarioStandardHarness` (D7) instead.

### A9. Marshal mock application and block
- **Goal:** A finalized-block sink that logs deliveries (acks can be manual), and a mock `Block` type.
- **Path:** `consensus/src/marshal/mocks/application.rs` (`Application`, `manual_ack`); `consensus/src/marshal/mocks/block.rs` (`Block`)
- **When to use:** Any marshal harness that checks delivery order or ack handling.
- **Example:** `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/invariants.rs` (`check_pending_acks`); `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/coding_stack.rs` (`setup_validator_coding`)

### A10. Aggregation mocks
- **Goal:** An application, monitor and reporter for running aggregation engines in tests.
- **Path:** `consensus/src/aggregation/mocks/` (`Application`, `Monitor`, `Reporter`)
- **When to use:** Any aggregation harness.
- **Example:** `consensus/fuzz/experimental/aggregation/src/aggregation.rs` (`spawn_engines`)

### A11. Resolver wire types and `TargetedResolver`
- **Goal:** Decode or forge resolver backfill messages, and observe or script fetches by implementing `TargetedResolver`.
- **Path:** `resolver/src/p2p/wire.rs` (`Message`, `Payload`); `resolver/src/lib.rs` (`TargetedResolver`)
- **When to use:** Poisoning, dropping or recording backfill traffic.
- **Example:** `consensus/fuzz/experimental/core/src/network.rs` (`CertificatePoison`); `consensus/fuzz/experimental/marshal/src/scenarios/recording_resolver.rs` (`RecordingResolver`)

### A12. Trace collector
- **Goal:** An in-memory tracing layer that collects spans and events.
- **Path:** `runtime/src/telemetry/traces/collector.rs` (`CollectingLayer`, `TraceStorage`)
- **When to use:** Turning WARN/DEBUG traces into coverage tokens, or asserting that an event was logged.
- **Example:** `consensus/fuzz/experimental/simplex/src/lib.rs` (`warn_trace_dispatch`, `run_with_warn_trace_collection`)
- **Gotchas:** Needs the `commonware-runtime` feature `test-utils`, which the fuzz crates already enable.

### A13. Fuzz and test RNGs
- **Goal:** Deterministic RNGs. `FuzzRng` turns fuzzer bytes into an endless stream; `TestRng` and `test_rng` give fixed seeds.
- **Path:** `utils/src/rng.rs` (`FuzzRng`, `Entropy`, `TestRng`, `test_rng`)
- **When to use:** Use `FuzzRng` for anything the fuzzer should steer (runtime seed, scenario choice). Use `TestRng` for unit tests and fixed keys.
- **Example:** `consensus/fuzz/experimental/core/src/lib.rs` (`bounded_fuzz_runtime_config`); `consensus/fuzz/fuzz_targets/attributable_map.rs` (`TestRng`)
- **Gotchas:** The `Arbitrary` impl for `Entropy` consumes all remaining bytes, so make it the last field of an input struct.

## B. Core harness library (`consensus/fuzz/experimental/core`)

### B1. `FuzzInput`, configurations, runtime config
- **Goal:** The shared libFuzzer input for simplex-based harnesses: configuration, partition, strategy, term length, engine policies, and raw entropy for the runtime.
- **Path:** `consensus/fuzz/experimental/core/src/lib.rs` (`FuzzInput`, `Configuration`, `N4F1C3`, `N4F0C4`, `N4F3C1`, `CertifyChoice`, `BlockFilterChoice`, `ReporterWiring`, `bounded_fuzz_runtime_config`, `fuzz_runtime_timeout`, `BYZANTINE_IDX`)
- **When to use:** New simplex-level targets take `FuzzInput` as is. Marshal targets define narrower inputs (D2, D7).
- **Example:** `consensus/fuzz/experimental/simplex/fuzz_targets/exp_simplex_cert_mock.rs`; `consensus/fuzz/experimental/simplex/src/lib.rs` (`run_standard_once`)
- **Gotchas:** Preset names read `N<n>F<faults>C<correct>`, and node indices `0..faults` are Byzantine (`BYZANTINE_IDX` is 0). `raw_bytes`, capped at `MAX_RAW_BYTES`, seeds the runtime.

### B2. `Simplex` trait and scheme variants
- **Goal:** Abstracts the scheme, the elector and fixture setup, so a target picks its whole cryptographic and leader setup with the type parameter `P`.
- **Path:** `consensus/fuzz/experimental/core/src/simplex.rs` (`Simplex`, `SimplexCertificateMock`, `SimplexCertificateMockAttributable`, `SimplexCertificateMockCustomRoundRobin`, `SimplexCertificateMockByzantineFirstLeader`, `SimplexEd25519`, `SimplexSecp256r1`); `consensus/fuzz/experimental/core/src/attributable_mock.rs` (`fixture`, `Scheme`, `Certificate`)
- **When to use:** Every simplex and marshal target. Add a variant here to change the elector or the scheme flags; an attributable variant takes its schemes from `attributable_mock::fixture` (see Gotchas).
- **Example:** `consensus/fuzz/experimental/simplex/fuzz_targets/exp_simplex_cert_mock_byzantine_first_leader.rs`; `consensus/fuzz/experimental/marshal/fuzz_targets/exp_marshal_e2e_standard_deferred_cert_mock_block_dissemination.rs`
- **Gotchas:** C2 decodes an attributable scheme's certificate as a signer bitmap followed by the rest. The attributable mock's certificates are opaque ids, so an attributable variant's `setup` returns `attributable_mock::fixture`, as `SimplexCertificateMockAttributable` does. `SimplexEd25519` is the production ed25519 scheme with real signatures; C10 runs on it. `SimplexSecp256r1` is the production secp256r1 scheme, not batchable; C13 runs on it.

### B3. Network setup and partitions
- **Goal:** Starts N nodes on A2 with three channels each (vote, certificate, resolver), then applies static partitions or partitions that change per view.
- **Path:** `consensus/fuzz/experimental/core/src/lib.rs` (`setup_network`, `NetworkChannels`, `network_faults`, `scheduled_partition`, `spawn_network_fault_scheduler`, `default_link`); `consensus/fuzz/experimental/core/src/utils.rs` (`SetPartition`, `Partition`, `link_peers`, `apply_partition`, `register`)
- **When to use:** Every simplex-based harness. Mallory and Chaos call `apply_partition` directly for transient faults.
- **Example:** `consensus/fuzz/experimental/simplex/src/lib.rs` (`run_standard_once`); `consensus/fuzz/experimental/simplex/src/byzzfuzz/runner.rs` (`setup_engines`)
- **Gotchas:** `SetPartition::n4` indexes the 15 set partitions of 4 nodes; index 0 is fully connected.

### B4. Disrupter and mutation strategies
- **Goal:** A Byzantine node that mutates, replays and re-signs votes, certificates and resolver messages. A `Strategy` decides the mutations and the faulty views.
- **Path:** `consensus/fuzz/experimental/core/src/disrupter.rs` (`Disrupter`); `consensus/fuzz/experimental/core/src/strategy.rs` (`Strategy`, `StrategyChoice`, `SmallScope`, `AnyScope`, `FutureScope`, `HeaderScope`, `SplitHeader`); `consensus/fuzz/experimental/core/src/lib.rs` (`start_disrupter_with_epoch`)
- **When to use:** The default Byzantine actor for Standard, FaultyNet, TwinsMutator and the marshal end-to-end targets. Implement `Strategy` to scope it differently.
- **Example:** `consensus/fuzz/experimental/marshal/src/scenarios/adversary.rs` (`start_simplex_disrupter`); `consensus/fuzz/experimental/simplex/src/byzzfuzz/mutator.rs` (`ByzzFuzzMutator`)
- **Gotchas:** The stock strategies schedule faulty views in `1..=required_containers`. For a run that starts above a prefix floor, wrap them in `LiveScope` (`consensus/fuzz/experimental/marshal/src/scenarios/strategy.rs`).

### B5. Honest validator builders and lifecycle
- **Goal:** Spawns honest simplex validators (application, reporter, engine), optionally keeping their task handles so they can be crashed or restarted.
- **Path:** `consensus/fuzz/experimental/core/src/lib.rs` (`spawn_filtered_honest_validator`, `build_validator`, `build_validator_with_reporter`, `start_validator_engine`, `ManagedValidator`, `ValidatorLifecycle`, `HarnessReporter`)
- **When to use:** `spawn_filtered_honest_validator` for nodes that run to the end. `build_validator` when the harness crashes or restarts nodes (Mallory, Chaos). `start_validator_engine`, the last step of both, when the harness brings its own blocker or reporter (C10).
- **Example:** `consensus/fuzz/experimental/simplex/src/mallory/lifecycle.rs` (`crash_stop`); `consensus/fuzz/experimental/simplex/src/chaos/runner.rs` (`run`)
- **Gotchas:** A crash must abort and await both task handles before the storage partition is reused. Otherwise the old incarnation can still send or keep its archives open. `start_validator_engine` takes the engine's `track_historical_votes`; every caller in this crate passes `false`, and only C10 sets it from its input.

### B6. Filterable block relay
- **Goal:** A mock block-dissemination application with a filter for each recipient (drop or delay), and an option to require the block before certifying.
- **Path:** `consensus/fuzz/experimental/core/src/block_relay.rs` (`Relay`, `Application`, `set_filter`, `set_certify_requires_block`)
- **When to use:** Fuzzing block availability, where honest nodes miss blocks for payloads that got notarized. It is driven by `BlockFilterChoice` in B1.
- **Example:** `consensus/fuzz/experimental/simplex/src/lib.rs` (`run_standard_once`); `consensus/fuzz/experimental/core/src/lib.rs` (`spawn_filtered_honest_validator`)

### B7. Twins driver
- **Goal:** A shared driver for Twins targets. It handles case generation (A4), iteration over compromised nodes, channel splitting and routing, twin roles, and Disrupter startup. A backend supplies the stack, the liveness wait and the invariants.
- **Path:** `consensus/fuzz/experimental/core/src/lib.rs` (`TwinsBackend`, `run_twins_with_backend`, `run_twins_with_backend_and_hook`, `TwinsSetup`); `consensus/fuzz/experimental/core/src/twins_network.rs` (`twins_within_mask`, `resolver_view`)
- **When to use:** A Twins target over a new stack only needs a `TwinsBackend` implementation.
- **Example:** `consensus/fuzz/experimental/simplex/src/lib.rs` (`MockTwinsBackend`); `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/twins/mod.rs` (`MarshalTwinsBackend`)
- **Gotchas:** Routing rejects any payload without a decodable view, since no partition can be chosen for it.

### B8. Receiver filters
- **Goal:** Receiver wrappers that reorder, drop or rewrite one node's inbound messages:
  - `ByzantineFirstReceiver` serves adversary messages first.
  - The omission receivers hide notarize votes or finalizations.
  - `CertificatePoison` forges certificate backfill answers.
  - `Wedge` models a split notarization in phases around GST.
- **Path:** `consensus/fuzz/experimental/core/src/network.rs` (`Router`, `ByzantineFirstReceiver`, `NotarizeOmissionReceiver`, `FinalizationOmissionReceiver`, `CertificatePoison`, `CertificatePoisonReceiver`, `Wedge`, `WedgeReceiver`)
- **When to use:** A fault that lives on the receiving side of one honest node.
- **Example:** `consensus/fuzz/experimental/simplex/src/lib.rs` (`run_audited_standard_once_with`); `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/runner.rs` (`run_standard_disrupter`); `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/scenario.rs` (`run_scenario`)

### B9. Byzantine activity counter
- **Goal:** Run-scoped counts, per actor, of the messages each Byzantine actor actually got onto the network, so smoke tests catch an adversary that went silent. A sibling store counts the honest events a configuration exists to reach (handoff decisions taken, votes at term starts on uncertified parents, single-certifier term starts), so a smoke test on a sampled extension cannot pass vacuously.
- **Path:** `consensus/fuzz/experimental/core/src/byzantine.rs` (`Counting`, `count`, `reset`, `record`, `twin_secondary`); `consensus/fuzz/experimental/core/src/reach.rs` (`count`, `reset`, `record`); `consensus/fuzz/experimental/core/src/block_relay.rs` (`HANDOFF_VOTE`, `HANDOFF_STAGE`)
- **When to use:** Wrap every new Byzantine actor's senders in `Counting` under its own label, and add a smoke test. Record an honest reach event under `reach`, never under `byzantine`, whose total an honest run must keep at zero.
- **Example:** `consensus/fuzz/experimental/simplex/src/lib.rs` (`adversary_smoke`, `assert_acted`, `assert_handoff_taken`); `consensus/fuzz/experimental/marshal/src/lib.rs` (`assert_adversary_acted`, `assert_adversary_silent`, `assert_reached`)
- **Gotchas:** Assert on the label of the actor the target exists for. Sends from another actor in the same run can hide a silent one.

### B10. Audit recorder
- **Goal:** An append-only per-node log of every activity and every automaton request and result. The mock reporter keeps only summaries.
- **Path:** `consensus/fuzz/experimental/core/src/simplex_audit.rs` (`RecordingReporter`, `ActivityRecorder`, `RecordingAutomaton`, `AuditLog`)
- **When to use:** Invariants that need history: ordering, or what the automaton was asked. Passing `&[RecordingReporter]` to `invariants::check` enables the audit checks. Every other simplex driver records with `ActivityRecorder`, which leaves the automaton unwrapped so the run is unchanged, for the C2 vote checks.
- **Example:** `consensus/fuzz/experimental/simplex/src/lib.rs` (`run_audited_standard_once_with`); `consensus/fuzz/experimental/simplex/src/invariants.rs` (`check_fuzz_invariants`)

### B11. Trusted continuation (prefix) framework
- **Goal:** Runs a deterministic state-building prefix (send, hold, crash and relink as the compromised identity) after the honest engines start and before the Byzantine actors and oracles do.
- **Path:** `consensus/fuzz/experimental/core/src/continuation.rs` (`Prefix`, `PrefixContext`, `Hook`, `Runner`, `ReplicaTap`)
- **When to use:** Target-state scaffolds, where the run first reaches a specific protocol state and fuzzing starts from there.
- **Example:** `consensus/fuzz/experimental/simplex/src/trusted.rs` (`fuzz_with_prefix`); `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/trusted.rs` (`release_standard`)
- **Gotchas:** With a prefix, the drivers skip the liveness wait and check safety only. A prefix sets input fields only through `Pins` (configuration, term length, lookahead, handoff decision), and each base honors the pins its domain allows (D8 for the marshal bases).

### B12. BFT reference bounds
- **Goal:** Hard-coded `max_faults` and `quorum` values for n up to 21, as a root of trust that does not depend on the code under test.
- **Path:** `consensus/fuzz/experimental/core/src/bounds.rs` (`max_faults`, `quorum`)
- **When to use:** Any invariant that needs quorum sizes.
- **Example:** `consensus/fuzz/experimental/simplex/src/invariants.rs` (`check_basic_invariants`)

### B13. Peer-load state bounds
- **Goal:** An end-of-run oracle on the state peer traffic can make one honest engine hold. It reads the voter's `current_view` and `tracked_views` gauges and the engine's audit history (B10) and checks three documented bounds: no recorded peer vote beyond the admission bound (`C6-I1`), one recorded vote per signer, kind and view (`C6-I2`), and no more tracked rounds than retention and the admission bound allow (`C6-I3`).
- **Path:** `consensus/fuzz/experimental/core/src/state_bounds.rs` (`check`, `Measurement`, `Node`, `gauge`, `admission_bound`, `peer_votes`, `second_finalization`, `check_admission`, `check_uniqueness`, `check_retention`, `VIEW_RETENTION`, `MEASURED`, `ADMISSION_CHECKED`, `UNIQUENESS_CHECKED`, `RETENTION_CHECKED`)
- **When to use:** At the end of a run, for every honest engine that ran for the whole run and reports to a recorder of B10. Standard, FaultyNet, the Standard audit and TwinsMutator call it; C9 puts it under a counted load.
- **Example:** `consensus/fuzz/experimental/simplex/src/lib.rs` (`check_state_bounds`, `whole_run_engines`); `consensus/fuzz/experimental/simplex/src/flood.rs` (`run_planted`)
- **Gotchas:** Reading the metrics is an auditor event, so call it after the auditor state a golden test pins. A gauge that is not found panics. Skip an engine that was restarted. `C6-I3` holds only inside the fault tolerance (`Configuration::can_finalize`). Each evaluation counts under its label in the B9 `reach` store.

## C. Simplex harness (`consensus/fuzz/experimental/simplex`)

### C1. Simplex entry point and mode dispatch
- **Goal:** One generic entry point, `fuzz::<P, M, C>`, for all simplex targets. `P` picks the scheme (B2), `M` the mode and `C` the coverage signal.
- **Path:** `consensus/fuzz/experimental/simplex/src/lib.rs` (`fuzz`, `FuzzMode`, `Coverage`, `Standard`, `FaultyNet`, `TwinsMutator`, `TwinsCampaign`, `Byzzfuzz`, `MalloryContainer`, `Chaos`, `ChaosTwins`, `CodeCoverage`, `StateCoverage`, `HappensBeforeCoverage`, `HappensBeforeStateCoverage`, `fuzz_audit`, `fuzz_twins_audit`); `consensus/fuzz/experimental/core/src/lib.rs` (`Mode`)
- **When to use:** A new simplex target is a `fuzz_target!` that calls `fuzz::<P, M, C>(input)`. The modes:
  - Standard: honest nodes plus a Disrupter.
  - FaultyNet: partitions per view.
  - TwinsMutator: a twin engine plus a Disrupter twin.
  - TwinsCampaign: both twins are full engines.
  - Byzzfuzz (C5), MalloryContainer (C6), Chaos and ChaosTwins (C7).
  
  `C` applies only to Standard, FaultyNet and the two Twins modes.
- **Example:** `consensus/fuzz/experimental/simplex/fuzz_targets/exp_simplex_cert_mock.rs`; `consensus/fuzz/experimental/simplex/fuzz_targets/exp_simplex_cert_mock_twins_campaign.rs`
- **Gotchas:** Register the target in `consensus/fuzz/experimental/simplex/Cargo.toml` with `required-features = ["twins"]` if its name contains `twins`, otherwise `["base"]`.

### C2. Simplex safety invariants
- **Goal:** Safety oracles over end-of-run reporter state: agreement, finalization ancestry, conflicting notarizations, certificate validity, vote equivocation and leader rules.
- **Path:** `consensus/fuzz/experimental/simplex/src/invariants.rs` (`check`, `SafetyObservations`, `check_basic_invariants`, `check_recorded_vote_invariants`, `check_recorded_vote_invariants_with_byzantine`, `check_no_invalid_reports`, `extract`)
- **When to use:** Call `check` at the end of every simplex run; the observation type decides between the basic and the audit checks. Pass every engine's recorder (B10) to `check_recorded_vote_invariants`, or to `check_recorded_vote_invariants_with_byzantine` when the Byzantine set is not `0..faults`; they run the payload checks on the summaries and the exact-proposal check on the histories.
- **Example:** `consensus/fuzz/experimental/simplex/src/byzzfuzz/runner.rs` (`run`); `consensus/fuzz/experimental/simplex/src/chaos/runner.rs` (`check_safety`)
- **Gotchas:** A panic here is a finding, never a rejected run. New checks belong in this file, not in coverage tokens (C4).

### C3. Happens-before coverage
- **Goal:** Turns an ordered stream of protocol events, each tagged with its node, into happens-before pairs. Distinct pairs become coverage tokens and Mallory's state fingerprint.
- **Path:** `consensus/fuzz/experimental/simplex/src/happens_before.rs` (`EventKind`, `Event`, `Summary`, `EventLog`, `NodeSubscriber`)
- **When to use:** `HappensBeforeCoverage` targets (`*_hb`), or any harness that wants novelty in interleavings rather than in end states.
- **Example:** `consensus/fuzz/experimental/simplex/fuzz_targets/exp_simplex_cert_mock_hb.rs`; `consensus/fuzz/experimental/simplex/src/mallory/runner.rs` (`fingerprint`)

### C4. State coverage
- **Goal:** A second feedback signal. It projects end-of-run replica state into canonical tokens and lights one counter per token in a custom SanitizerCoverage table.
- **Path:** `consensus/fuzz/experimental/simplex/src/state_cov.rs` (`reset`, `observe_tokens`, `observe_with_metrics`, `observe_trace_events`, `encode_reporter_states`)
- **When to use:** `StateCoverage` targets (`*_state_cov`), or any harness whose interesting state does not show up as code edges.
- **Example:** `consensus/fuzz/experimental/simplex/src/lib.rs` (`run_standard_once`); `consensus/fuzz/experimental/simplex/src/mallory/state.rs` (`state_descriptor`)
- **Gotchas:** Tokens are coverage only. Never put invariant or anomaly checks into them.

### C5. ByzzFuzz
- **Goal:** ByzzFuzz-style bounded fault injection. Network faults drop messages across partitions in sampled rounds. Process faults omit or semantically mutate the Byzantine sender's messages. The run then reaches GST and checks liveness.
- **Path:** `consensus/fuzz/experimental/simplex/src/byzzfuzz/` (`run`, `ByzzFuzz`, `ProcessFault`, `NetworkFault`, `ByzzFuzzInjector`, `RoundTrackingReceiver`, `SenderViewCell`)
- **When to use:** Target `exp_simplex_cert_mock_byzzfuzz`. Reuse its forwarders, which use `split_with` and key faults on the sender's round, for round-scoped network faults.
- **Example:** `consensus/fuzz/experimental/simplex/fuzz_targets/exp_simplex_cert_mock_byzzfuzz.rs`; `consensus/fuzz/experimental/simplex/src/byzzfuzz/runner.rs` (`setup_engines`)
- **Gotchas:** Read `consensus/fuzz/experimental/simplex/src/byzzfuzz/specs/INDEX.md` first; `specs/contracts/byzzfuzz-harness.md` is the wiring contract. Certificate and resolver process faults only omit messages.

### C6. Mallory
- **Goal:** An adaptive adversary. A tabular Q-learning policy over happens-before state picks a network, packet, crash or Byzantine-role fault at each step. The learned policy steers a custom libFuzzer mutator.
- **Path:** `consensus/fuzz/experimental/simplex/src/mallory/` (`run`, `Schedule`, `Fault`, `QPolicy`, `AdversaryRole`, `RoleMultiplexer`, `Topology`, `crash_stop`, `mutate`)
- **When to use:** Target `exp_simplex_cert_mock_mallory`. Reuse `crash_stop` and `Topology` inside the simplex crate for crash and partition control.
- **Example:** `consensus/fuzz/experimental/simplex/fuzz_targets/exp_simplex_cert_mock_mallory.rs` (`fuzz_mutator`); `consensus/fuzz/experimental/simplex/src/chaos/runner.rs` (`crash_stop`)
- **Gotchas:** Execution reads its whole schedule from the input, so a crash file replays exactly; the Q-table influences only mutation. The modules are `pub(crate)`.

### C7. Chaos and ChaosTwins
- **Goal:** The crash-fault axis. A schedule driven by the fuzzer crashes nodes and changes the network, and every fault gets a paired heal. Chaos runs an all-honest committee and checks safety only. ChaosTwins runs N4F1C3 with a twin leader and adds a liveness check after recovery.
- **Path:** `consensus/fuzz/experimental/simplex/src/chaos/` (`Schedule`, `Condition`, `Action`, `Checker`, `run`, `check_safety`)
- **When to use:** Targets `exp_simplex_cert_mock_chaos` and `exp_simplex_cert_mock_chaos_twins`. Reuse `Schedule` when you need faults that always heal.
- **Example:** `consensus/fuzz/experimental/simplex/src/chaos/runner.rs` (`run`); `consensus/fuzz/experimental/simplex/src/chaos/twins.rs` (`run`)

### C8. Simplex prefix entry points
- **Goal:** The simplex base drivers with a B11 prefix hook.
- **Path:** `consensus/fuzz/experimental/simplex/src/trusted.rs` (`fuzz_with_prefix`, `fuzz_audit_with_prefix`, `fuzz_twins_audit_with_prefix`)
- **When to use:** Building a target-state scaffold for simplex. No fuzz target uses it yet.
- **Example:** `consensus/fuzz/experimental/simplex/src/trusted.rs` (`runs_with_a_prefix_are_deterministic`, `ordinary_runs_are_unchanged`)
- **Gotchas:** `ordinary_runs_are_unchanged` pins the auditor states of runs without a prefix. A changed hash means the driver's behavior changed.

### C9. Directed peer flood
- **Goal:** A counted flood. Participant 0 runs no engine and sends the three honest engines bursts of votes it signs: far-future votes, one vote repeated and contradicted, and one vote of each kind across the edges of the tracked window. The run checks B13 for every honest node, that they still finalize, and the Standard safety invariants. A tap on each honest vote receiver counts the flood votes the engine took, by class.
- **Path:** `consensus/fuzz/experimental/simplex/src/flood.rs` (`FuzzInput`, `fuzz`, `run`, `run_planted`, `Report`, `Burst`, `Node`, `FloodClass`, `ClassCounts`, `Choice`, `sample_burst`, `sample_next`, `stream_at`, `Plant`, `fixed_corpus`, `check_floors`, `ACTOR`)
- **When to use:** Target `exp_simplex_cert_mock_flood`. `run` returns the report a test reads; `run_planted` plants the fault of one negative control; `check_floors` proves over `fixed_corpus` that the load was there (`C6-I5`).
- **Example:** `consensus/fuzz/experimental/simplex/fuzz_targets/exp_simplex_cert_mock_flood.rs`
- **Gotchas:** The input is its own `FuzzInput`, not B1's: its `raw_bytes` is a copy of the whole input, taken before the other fields. The first burst is always far-future votes at view 1, so the empty input floods. A run ends on a count of finalized containers, not on a view. The flooder waits out the per-peer rate limit of the simulated network, so every vote of a burst is sent. The runtime's RNG counts the bytes drawn from it, and each burst reports the count at its draws: `sample_next` and `sample_burst` on `stream_at` that count give the burst again.

### C10. Equivocation evidence
- **Goal:** A scripted equivocator on the production ed25519 scheme. Participant 0 runs no engine and sends the three honest engines pairs of conflicting votes it signs (two notarizes, two finalizes, nullify then finalize, finalize then nullify), the second vote up to six views after the first. With `track_historical_votes` on, every pair one honest engine held in full must be exported as fault evidence (`C4-I1`), pass `AttributableReporter` (`C4-I2`) and get the sender blocked (`C4-I3`); no evidence may name another signer (`C4-I4`). The Standard safety invariants run last.
- **Path:** `consensus/fuzz/experimental/simplex/src/evidence.rs` (`FuzzInput`, `fuzz`, `run`, `run_planted`, `Outcome`, `Report`, `PairKind`, `EvidenceType`, `sample_plan`, `sample_payload`, `stream_at`, `Tap`, `Raw`, `Log`, `Sequence`, `current_view`, `admits`, `certainly_admits`, `retains`, `pairs`, `obligations`, `late`, `check_exported`, `check_forwarded`, `check_blocked`, `check_honest_signers`, `evaluate`, `Plant`, `fixed_corpus`, `check_floors`, `picks`, `ACTOR`)
- **When to use:** Target `exp_simplex_ed25519_equivocation_evidence`. `run` returns the report, the logs and the equivocator's trace; `evaluate` is the oracle over the logs alone; `run_planted` plants the fault of one negative control; `check_floors` proves over `fixed_corpus` that every pair kind was measured, also after the certificate of its first vote (`C4-I5`).
- **Example:** `consensus/fuzz/experimental/simplex/fuzz_targets/exp_simplex_ed25519_equivocation_evidence.rs`
- **Gotchas:** The input is its own `FuzzInput`: its `raw_bytes` is a copy of the whole input, taken before the other fields, and one decoded input in eight runs without `track_historical_votes`, where nothing is an obligation and the late pairs without evidence are only counted. Evidence exists only when one node holds both votes, so a pair is measured per node, and only when the node recorded the first vote and was certain to admit the second: the tap stores the voter's `current_view` gauge with every message of the equivocator, read with `Metrics::encode`. A pair is found in a tap by the bytes of its two votes. The runtime's RNG counts the bytes drawn from it, and every plan and drawn payload reports the count at its draw: `sample_plan` and `sample_payload` on `stream_at` that count give them again. `Outcome::metrics` is sorted by line, because the registry encodes in no fixed order.

### C11. Honest blame
- **Goal:** A directed scenario, not a fuzz target: one scripted Byzantine participant tries to make an honest engine block another honest participant. Participant 0 runs no engine, holds all three channels and a relay handle, echoes honest votes and proposes when it leads, and applies one of 12 attacks per run: a flood on all three channels, broken vote signatures, replayed votes and forged signers, junk, certificates it assembled and rushed to one node, broken copies of honest certificates, two proposals in one view (one with a broken signature), a stale parent with lying resolver answers and guessed request ids, and a mix of them by view. Three honest engines run on the production ed25519 scheme. The block list at the end may name only participant 0 as blocked (`C7-I1`); the Standard certificate-state invariants run last.
- **Path:** `consensus/fuzz/experimental/simplex/src/blame.rs` (`Attack`, `attack_at`, `Scenario`, `fixed_scenarios`, `run`, `run_planted`, `Outcome`, `Node`, `Trace`, `Call`, `Window`, `Adversary`, `Heard`, `Sent`, `Block`, `Channel`, `Rule`, `check_blocks`, `check_floors`, `calls_on_byzantine`, `Plant`, `link`, `Recording`, `Corrupting`, `Corruption`, `block_list`, `fallbacks`, `fetched`, `ACTOR`)
- **When to use:** Regression tests over `fixed_scenarios` (144 runs: 12 attacks, 4 term settings, 3 seeds). `run` returns the block list, every call of an honest engine to its blocker, the counters and the message log of participant 0, and two metrics per honest engine. `check_floors` proves over the 12 runs of one attack that the attack reached the engine code it aims at (`C7-I2`); `run_planted` plants the fault of one negative control. Reuse `Recording` when a harness must know who an engine blocked and when, and `Corrupting` to make an honest sender emit invalid messages.
- **Example:** `consensus/fuzz/experimental/simplex/tests/consensus_c7_acceptance.rs`
- **Gotchas:** The links of participant 0 are faster than the links between honest nodes (`link`): with equal links its vote is never in an honest batch and its certificate never arrives first. Three times per run the links from the other two honest nodes into one honest node are cut for 1.5 s; without these windows no honest node checks a resolver answer of another honest node, and `F-0b` fails. A block is recorded and traffic goes on (`disconnect_on_block` is off), but an engine's resolver stops asking a peer it blocked, so the lying answers happen only in a `ResolverLies` run. `fallbacks` reads a counter the engine encodes also at zero and panics when it is missing; `fetched` reads a series the engine encodes only above zero and returns zero when it is missing. Participant 0 draws from the runtime's RNG, so adding a draw to one attack changes every later number of that run. There is no libFuzzer target: the attack list is fixed, and `run` takes everything a target would need.

### C12. Blackout
- **Goal:** Liveness after every live validator restarts inside one view. Four participants on the certificate mock scheme, participant 0 absent in seven decoded inputs of eight, so the three live validators are exactly a quorum. Up to three blackouts in sequence on one cluster: run connected, cut every link between live validators, read a cut, crash the crash set at one instant, wait, restore the links and restart the crashed validators on their storage. After the last heal (`T`) every live validator must finalize a view above the highest finalization reported up to `T` within 120 s of simulated time (`blackout-liveness`); after a settle window the Chaos safety checks run over every live validator (`blackout-safety`).
- **Path:** `consensus/fuzz/experimental/simplex/src/blackout.rs` (`FuzzInput`, `Blackout`, `fuzz`, `run`, `run_observed`, `Report`, `BlackoutReport`, `CutValue`, `Plant`, `Observation`, `Observed`, `live_validators`, `own_nullify_at`, `all_nullified`, `LIVENESS_WINDOW`)
- **When to use:** Target `exp_simplex_cert_mock_blackout`. `run` returns the report: per blackout the crash set, the `all_nullified` flag and the values the cut read; the baseline at `T` and the time from `T` to the last fresh finalization. `run_observed` also returns the script's steps with their simulated times and plants the fault of one negative control at the observation boundary of an invariant.
- **Example:** `consensus/fuzz/experimental/simplex/fuzz_targets/exp_simplex_cert_mock_blackout.rs`
- **Gotchas:** The cut reads every validator's `current_view` gauge from one `Metrics::encode` and its own nullify from its retained reporter at that view only, with no `.await` in between. The decoded isolation runs in reverse, so a short input gets the longest isolation, past the leader and certification timeouts: the empty input crashes every live validator after its nullify for view 1. The crash aborts every handle of the crash set before awaiting any. Restarts reuse Chaos's `restart_durable`, the liveness wait reuses Mallory's `FinalizationClock`, `liveness_target` and `wait_for_step_boundary`, and the end checks are Chaos's `check_safety`. Chaos itself stays safety-only.

### C13. Proposal switch
- **Goal:** No certificate may join votes verified for different proposals after the selected proposal of their round changes. One production engine (the victim) runs on the production secp256r1 scheme, which is not batchable, so every valid vote enters the batcher's verified buffer on arrival. The other three participants run no engine: they send the victim votes and certificates for views 1 and 2, signed with their own keys, on a fuzzed schedule, and drain everything it sends them. Every certificate a scripted participant receives from the victim must decode and verify for its own subject (`outbound certificate invalid:`), and the victim's reporter must count no invalid certificate after a 2 s settle (`reported invalid certificates:`). The scripted participants may equivocate freely: the victim counts only votes it verified.
- **Path:** `consensus/fuzz/experimental/simplex/src/proposal_switch.rs` (`FuzzInput`, `Step`, `Op`, `fuzz`, `run`, `run_observed`, `Options`, `Checks`, `Plant`, `Report`, `Checked`, `CertificateKind`, `Roles`, `Observation`, `Observed`, `Message`, `MessageKind`, `prop`, `assert_floor`)
- **When to use:** Target `exp_simplex_secp256r1_proposal_switch`. `run` returns the report: the steps sent with their times, every certificate the victim sent with its check, and the victim reporter's votes, certificates and invalid counters. `FuzzInput::from_steps` builds a fixed scenario without decoding bytes. `run_observed` also returns the wiring and every send and drain, plants the fault of one negative control at the observation boundary of a check, and turns either check off so the other is judged alone.
- **Example:** `consensus/fuzz/experimental/simplex/fuzz_targets/exp_simplex_secp256r1_proposal_switch.rs`
- **Gotchas:** The first five steps decode to `Op::Canonical` on an exhausted input, and the gaps decode in reverse (100 ms when exhausted), so the empty input is the fixed switch schedule: the leader of view 1 votes notarize and finalize for proposal A, a notarization switches view 1 to proposal B, then two finalize votes for B arrive. Every step decodes all four fields whatever its op, so the byte layout does not depend on the op. Roles do not depend on the seed: round robin elects by index, so the victim is the lowest index that leads neither view 1 nor view 2. Certificates decode with the scheme's `certificate_codec_config`; the default config rejects every secp256r1 certificate. Verification uses a generator of its own, so a check draws nothing from the run. The resolver probe of `run_observed` sends through the victim's network and changes later link delays, so its report differs from `run`'s.

## D. Marshal harness (`consensus/fuzz/experimental/marshal`)

### D1. Marshal store harness
- **Goal:** Fuzzes one marshal actor and its prunable archives with a sequence of operations: seed, report, get, prune, floors, hints, bursts, subscribe, deliver, restart, and direct archive access.
- **Path:** `consensus/fuzz/experimental/marshal/src/marshal/store.rs` (`StoreOp`, `MarshalActorStoreInput`, `fuzz_marshal_actor_store`, `setup_prunable_validator_cert_mock`)
- **When to use:** Target `exp_marshal_actor_standard_store_cert_mock`. Extend `StoreOp` to reach store or actor paths without running consensus.
- **Example:** `consensus/fuzz/experimental/marshal/fuzz_targets/exp_marshal_actor_standard_store_cert_mock.rs`; `consensus/fuzz/experimental/marshal/src/marshal/store.rs` (`restart_stops_a_busy_actor`)
- **Gotchas:** `Restart` must abort and await the old actor handle before reopening the same partitions. Add new operations to the existing op stream, not as a separate fixture.

### D2. Marshal end-to-end drivers
- **Goal:** An N4F1C3 cluster of real simplex engines whose reporter is marshal, with a Byzantine node 0. It checks delivery agreement and liveness. Variants add certificate-backfill poison or Byzantine block dissemination. The input samples the Simplex extensions: the term length every engine runs, the optimistic lookahead (zero for half the inputs), and the handoff decision (`Wait`, `Stage` or `Vote`) every honest application answers a term-start proposal over an uncertified parent with; the plain disrupter samples the honest application too, whose `Faulty` table rejects the last view of every term in the fault window (honest leaders skip theirs, so only a Byzantine-led term end reaches verification); the dissemination target also samples the height offset of the Byzantine leader's block and the honest application, whose `Faulty` table rejects the Byzantine leader's first view and nothing else, so the disseminated block is one the application rejects: deferred verification notarizes it and certification fails it. A handoff parent is the last block of a term without a nullification, and the Byzantine node proposes at view 1 alone, so only under a single-view term is that block also the uncertified parent of the next term's handoff (`REJECTED_PARENT_VOTE` counts that early vote); the Twins backends reach it on stable terms through their term-end faults (D5).
- **Path:** `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/runner.rs` (`fuzz_marshal_standard_disrupter`, `fuzz_marshal_standard_certificate_poison`, `fuzz_marshal_standard_block_dissemination`, `run_standard_disrupter`, `force_poison`); `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/input.rs` (`MarshalDisrupterInput`); `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/app.rs` (`ApplicationChoice`, `DeliveryReporter`, `FaultyConfig::rejecting`); `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/block_disrupter.rs` (`MarshalBroadcastFault`, `HeightOffset`, `FORGED_HEIGHT_ACTOR`); `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/poison_tape.rs` (`standard::run`, `standard::fuzz`, `Report`, `RetryCheck`, `check_retry`, `RETRY_BOUND`); `consensus/fuzz/experimental/core/src/network.rs` (`CertificatePoison::with_ledger`, `LedgerRecord`, `ActivityKind`)
- **When to use:** The default base for fuzzing marshal under consensus. `exp_marshal_e2e_standard_deferred_cert_mock_poison_tape` runs the certificate-poison cluster with the tape-first input `poison_tape::FuzzInput` and checks in every run that the poisoned node re-requests the poisoned view, or its engine reports a nullification, finalization or certification that settles it, within `RETRY_BOUND` (1 s simulated) of the poisoned answer.
- **Example:** `consensus/fuzz/experimental/marshal/fuzz_targets/exp_marshal_e2e_standard_deferred_cert_mock_disrupter.rs`; `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/runner.rs` (`disrupters_prepare_under_every_decision`, `block_dissemination_proposes_in_a_rejected_view`, `single_certifier_term_starts_are_reached`, `single_certifier_quorums_are_reached`)
- **Gotchas:** Node 0 runs only a simplex Disrupter and no marshal stack, so nothing is sent on the block-gossip channel unless the block-dissemination actor is started. Liveness is checked only under the pinned extensions (`Liveness::sampled`: `Wait`, no lookahead, single-view terms, and on the dissemination target, whose term length is pinned configuration, the always-accepting application and a zero height offset); every other sample checks safety only, since under `Vote` a stall after a Byzantine outgoing leader is allowed by contract. The poison bases keep the extensions pinned (`force_poison`), because their backfill oracle reads a stall. Under uniform sampling the liveness check runs on about one input in 25. The old poison target's backfill check runs only when the poisoned node misses its post-GST target, which the node usually avoids through other routes; the tape variant's retry check does not wait for a stall. Its ledger records the poisoned node's own outbound resolver requests (a wrapper on its resolver sender, so a retry lost on the lossy link still counts) and its engine's settling activities, in one order, timed by the run's clock (`start_ledger`, installed first in the executor closure). A run that ends less than `RETRY_BOUND` after the poisoned answer is reported as not measured.

### D3. Marshal coding stack and faults
- **Goal:** The coding marshal variant (Reed-Solomon shard dissemination; the `Marshaled` wrapper with `Commitment` payloads), plus Byzantine shard and backfill faults.
- **Path:** `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/coding_stack.rs` (`setup_validator_coding`, `start_engine_coding_with_networks`, `FaultyProposer`); `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/coding_disrupter.rs` (`CodingFaults`, `start_backfill_poison`); `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/poison_tape.rs` (`FuzzInput`, `coding::run`, `coding::fuzz`)
- **When to use:** The `marshal_e2e_coding_*` targets. `exp_marshal_e2e_coding_cert_mock_poison_tape` runs the block-poison cluster of `exp_marshal_e2e_coding_cert_mock_poison` with the tape-first input `poison_tape::FuzzInput`.
- **Example:** `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/runner.rs` (`run_coding_disrupter`, `fuzz_marshal_coding_block_poison`)
- **Gotchas:** `MarshalDisrupterInput` decodes its runtime tape after 16 to 18 bytes of configuration, so libFuzzer's first short inputs all get an empty tape. `poison_tape::FuzzInput` copies the whole input into the tape first (`Unstructured::peek_bytes`) and then decodes the same configuration from the same bytes; the decoded configuration's own tape is unused.

### D4. Marshal end-to-end invariants
- **Goal:** Checks during and at the end of a run on the marshal/application boundary: delivery order, parent linkage, cross-node agreement, ack accounting, certification agreement, and that no node delivers a finalized block its own application rejects. It also holds the per-run liveness decision and the reach labels the B9 `reach` store counts under: an honest node's application prepares by decision and its staged boundary re-proposals, a byzantine proposal offered in a rejected view, an honest leader's early vote over a rejected or corrupted parent, and term-start children notarized over a parent with one honest certifier (globally, or, after the leader's early vote, among the child's other honest voters at their vote time).
- **Path:** `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/invariants.rs` (`check_all_blocks`, `check_local_blocks`, `check_parent_linkage`, `check_no_rejected_delivery`, `check_pending_acks`, `agreement`, `CertificationAgreementInvariant`, `HeaderMismatchInvariant`, `check_certificate_backfill_retry`, `Liveness`, `PREPARE_WAIT`, `PREPARE_STAGE`, `PREPARE_VOTE`, `PREPARE_REUSE`, `REJECTED_VIEW_OFFER`, `REJECTED_PARENT_VOTE`, `CORRUPTED_PARENT_VOTE`, `SINGLE_CERTIFIER_TERM_START`, `SINGLE_CERTIFIER_QUORUM`)
- **When to use:** Every marshal end-to-end, Twins and scenario driver. Thread the `Liveness` decision and the application's rejection predicate explicitly into every caller.
- **Example:** `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/twins/mod.rs` (`check_local_blocks`, `agreement`); `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/scenario.rs` (`run_scenario`)
- **Gotchas:** The delivery checks read the sink's append-only delivery log, not the latest state. The rejected-delivery check reads a block's embedded context, which only Deferred and coding verify against; Inline verifies under the consensus context, so Inline stacks pass a never-rejecting predicate.

### D5. Marshal Twins backend
- **Goal:** A B7 backend over real marshal. The compromised identity runs a full engine plus a Disrupter twin, and the honest nodes use real marshal/application paths. The input samples the term length, the optimistic lookahead and the handoff decision as D2 does; every application, the compromised primary's included, answers the sampled decision.
- **Path:** `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/twins/` (`MarshalTwinsBackend`, `fuzz_marshal_standard_twins`, `fuzz_marshal_coding_twins`, `attack_layout`, `ObservedMarshal`, `TwinsMarshal`)
- **When to use:** The `marshal_e2e_*_twins*` targets. The split-header targets narrow the search to header-split scenarios through `attack_layout`, whose precursor and attack views are the last view of a round and the first of the next under any term length.
- **Example:** `consensus/fuzz/experimental/marshal/fuzz_targets/exp_marshal_e2e_standard_app_cert_mock_twins.rs`; `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/twins/mod.rs` (`standard_twins_prepare_under_every_decision`)
- **Gotchas:** The general Twins target uses the last byte of its raw entropy to select the application and wrapper, so all variants share one corpus. Liveness follows D2's rule: a sampled extension makes the run safety-only. The faulty application's table is indexed by round, so its faults cover the whole scripted prefix under any term length. A handoff parent is the last block of a term without a nullification, and a fault on an earlier view of the term fails that view's certification and nullifies the term, so a whole-term fault yields a handoff parent reliably only under a single-view term. The input therefore samples term-end faults: `FaultTable::RejectTermEnds` rejects only the last view of each round (the sampled table draws the same `RejectTermEnd` behavior per round), and `FaultScope::TermEnd` confines the coding proposer's fault to its term's last block. `REJECTED_PARENT_VOTE` and `CORRUPTED_PARENT_VOTE` count an honest leader's early vote over such a parent.

### D6. Marshal pre-GST scenarios
- **Goal:** Replays a templated pre-GST program that the fuzzer extends, heals the network at a fixed GST, and requires every correct node to finalize past the height it held at GST.
- **Path:** `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/scenario.rs` (`ScenarioTemplate`, `PreGstAction`, `run_scenario`, `fuzz_marshal_standard_scenarios`)
- **When to use:** Target `exp_marshal_e2e_standard_deferred_cert_mock_scenarios`. Add a template for each new pre-GST attack shape.
- **Example:** `consensus/fuzz/experimental/marshal/fuzz_targets/exp_marshal_e2e_standard_deferred_cert_mock_scenarios.rs`

### D7. Marshal scenario framework
- **Goal:** Three phases. Setup builds four validators. A prefix copied from a standard-marshal unit test drives the honest nodes to that test's state, and the handoff is verified. Live fuzzing then runs with a Byzantine node 0.
- **Path:** `consensus/fuzz/experimental/marshal/src/scenarios/` (`Scenario`, `FuzzScenarioStandardHarness`, `RecordingResolver`, `ScenarioHandoff`, `LiveScope`, `ByzantineLeaderAtView`, `fuzz_marshal_scenario_prefix_deferred`); spec in `consensus/fuzz/experimental/marshal/src/scenarios/specs/SPEC.md`
- **When to use:** Turning an existing `consensus/src/marshal` test into a starting point for fuzzing.
- **Example:** `consensus/fuzz/experimental/marshal/src/scenarios/scenarios.rs` (`StandardCertifyMissingCandidateFetchesByRound`); `consensus/fuzz/experimental/marshal/fuzz_targets/exp_marshal_scenario_standard_deferred_cert_mock.rs`
- **Gotchas:** Section 11 of `SPEC.md` shows how to translate a source test. `RecordingResolver` stands in for the source tests' `cfg(test)` resolver.

### D8. Marshal golden and prefix tests
- **Goal:** Pins the auditor state of each driver to catch unintended behavior changes, and checks that runs with a prefix are deterministic.
- **Path:** `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/golden.rs` (`ordinary_marshal_runs_are_unchanged`); `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/trusted/tests.rs` (`hooked_marshal_runs_are_deterministic`)
- **When to use:** Run after changing any marshal driver. Re-pin the hashes only for deliberate changes.
- **Example:** `consensus/fuzz/experimental/marshal/src/marshal/end_to_end/golden.rs` (`run_standard_disrupter`)
- **Gotchas:** The goldens run `Wait`, a zero lookahead and a zero height offset; every golden but the block-dissemination one (a two-view term) runs single-view terms, and two Twins goldens run the faulty application with its sampled table. A trusted continuation writes the scratch plan's term length, lookahead and handoff decision back into the base input. The scratch starts from a single-view term (on the block-dissemination base, the base's own term), a zero lookahead and `Wait`, so an input's sampled extensions never reach a run with a prefix. A prefix may pin them (`Pins::term_length` up to four views, `Pins::lookahead` up to the term length plus two, `Pins::handoff`) on every marshal base but the two poison bases, which force them. On a disrupter base (`plan` in `trusted.rs`) the application stays as the base input sets it (the poison bases force the always-accepting one) and the height offset stays zero. The reach labels (`PREPARE_VOTE`, `REJECTED_PARENT_VOTE`, ...) are public in `end_to_end`, and `commonware_consensus_fuzz_core::reach::count` reads them on the test's thread after a run. On a Twins base (`plan_twins`) the stack selector and the fault knobs stay as sampled.

## E. Aggregation and structures

### E1. Aggregation engine harness
- **Goal:** Honest aggregation engines on A1 and A2 with fuzzed links, partitions and timeouts, plus a bad-ack injector. It checks that no certificates conflict and that the target height is reached.
- **Path:** `consensus/fuzz/experimental/aggregation/src/aggregation.rs` (`FuzzInput`, `fuzz`, `spawn_engines`, `spawn_bad_ack_injector`, `check_no_conflicting_certs`)
- **When to use:** Target `exp_aggregation_cert_mock`. It is also a compact template for an engine harness outside simplex.
- **Example:** `consensus/fuzz/experimental/aggregation/fuzz_targets/exp_aggregation_cert_mock.rs`

### E2. Codec round-trip targets
- **Goal:** The pattern for wire types: build an arbitrary value, encode it, decode it and compare; also feed the raw input to `read_cfg` to reach the error paths.
- **Path:** `consensus/fuzz/experimental/aggregation/src/aggregation_decode.rs` (`fuzz`); `consensus/fuzz/experimental/structures/fuzz_targets/exp_simplex_messages.rs`
- **When to use:** Any new encoded type in consensus.
- **Example:** `consensus/fuzz/experimental/aggregation/fuzz_targets/exp_aggregation_decode.rs`
- **Gotchas:** Assert `encode().len() == encode_size()`, and decode borrowed bytes through `Copying`.

### E3. Data-structure targets
- **Goal:** Self-contained single-process targets:
  - `exp_automaton_defaults.rs`: the handoff and certification an automaton or application gets from the trait defaults.
  - `exp_simplex_reporter_filtering.rs`: reporter filtering of invalid and wrong-namespace activity, across real schemes.
  - `exp_simplex_threshold_vrf.rs`: the BLS12-381 threshold VRF scheme in every role, with faulty votes and certificates checked against a model, and its seeds and timelock encryption.
- **Path:** `consensus/fuzz/experimental/structures/fuzz_targets/` (`exp_automaton_defaults.rs`, `exp_simplex_reporter_filtering.rs`, `exp_simplex_threshold_vrf.rs`); `attributable_map.rs` and `simplex_elector.rs` run in the `consensus/fuzz` package
- **When to use:** A pure data structure or a synchronous component that needs no runtime. The package depends only on published crates.
- **Example:** `consensus/fuzz/fuzz_targets/attributable_map.rs` (`fuzz`)

## F. Workflow

### F1. Run, reproduce, measure
- **Goal:** Build, run, reproduce and measure the targets.
- **Path:** `consensus/fuzz/experimental/justfile`; `consensus/fuzz/experimental/README.md`; `consensus/fuzz/experimental/coverage.sh`
- **When to use:**
  - From `consensus/fuzz/experimental`:
    - `just list`
    - `just run <target> -- -max_total_time=<secs>`
    - `just run <target> <crash_file>`
    - `just features=twins build simplex`
  - Set `CONSENSUS_FUZZ_LOG` to print the input and the ByzzFuzz, Mallory or Chaos decision log on panic.
  - `coverage.sh` builds per-target HTML coverage for the simplex targets.
- **Example:** `cargo +nightly fuzz run --fuzz-dir consensus/fuzz/experimental/simplex exp_simplex_cert_mock`
- **Gotchas:** `consensus/fuzz/experimental` has no manifest, so a bare `cargo fuzz` fails; always pass `--fuzz-dir`. Use the nightly pinned as `nightly` under `[tools]` in `.github/toolchains.toml`.

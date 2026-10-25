# consensus/fuzz components

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
| B1 | `FuzzInput`, configurations, runtime config | `consensus/fuzz/core/src/lib.rs` |
| B2 | `Simplex` trait and scheme variants | `consensus/fuzz/core/src/simplex.rs`, `attributable_mock.rs` |
| B3 | Network setup and partitions | `consensus/fuzz/core/src/lib.rs`, `utils.rs` |
| B4 | Disrupter and mutation strategies | `consensus/fuzz/core/src/disrupter.rs`, `strategy.rs` |
| B5 | Honest validator builders and lifecycle | `consensus/fuzz/core/src/lib.rs` |
| B6 | Filterable block relay | `consensus/fuzz/core/src/block_relay.rs` |
| B7 | Twins driver | `consensus/fuzz/core/src/lib.rs`, `twins_network.rs` |
| B8 | Receiver filters | `consensus/fuzz/core/src/network.rs` |
| B9 | Byzantine activity counter | `consensus/fuzz/core/src/byzantine.rs` |
| B10 | Audit recorder | `consensus/fuzz/core/src/simplex_audit.rs` |
| B11 | Trusted continuation (prefix) framework | `consensus/fuzz/core/src/continuation.rs` |
| B12 | BFT reference bounds | `consensus/fuzz/core/src/bounds.rs` |
| C1 | Simplex entry point and mode dispatch | `consensus/fuzz/simplex/src/lib.rs` |
| C2 | Simplex safety invariants | `consensus/fuzz/simplex/src/invariants.rs` |
| C3 | Happens-before coverage | `consensus/fuzz/simplex/src/happens_before.rs` |
| C4 | State coverage | `consensus/fuzz/simplex/src/state_cov.rs` |
| C5 | ByzzFuzz | `consensus/fuzz/simplex/src/byzzfuzz/` |
| C6 | Mallory | `consensus/fuzz/simplex/src/mallory/` |
| C7 | Chaos and ChaosTwins | `consensus/fuzz/simplex/src/chaos/` |
| C8 | Simplex prefix entry points | `consensus/fuzz/simplex/src/trusted.rs` |
| D1 | Marshal store harness | `consensus/fuzz/marshal/src/marshal/store.rs` |
| D2 | Marshal end-to-end drivers | `consensus/fuzz/marshal/src/marshal/end_to_end/` |
| D3 | Marshal coding stack and faults | `consensus/fuzz/marshal/src/marshal/end_to_end/` |
| D4 | Marshal end-to-end invariants | `consensus/fuzz/marshal/src/marshal/end_to_end/invariants.rs` |
| D5 | Marshal Twins backend | `consensus/fuzz/marshal/src/marshal/end_to_end/twins/` |
| D6 | Marshal pre-GST scenarios | `consensus/fuzz/marshal/src/marshal/end_to_end/scenario.rs` |
| D7 | Marshal scenario framework | `consensus/fuzz/marshal/src/scenarios/` |
| D8 | Marshal golden and prefix tests | `consensus/fuzz/marshal/src/marshal/end_to_end/` |
| E1 | Aggregation engine harness | `consensus/fuzz/aggregation/src/aggregation.rs` |
| E2 | Codec round-trip targets | `consensus/fuzz/aggregation/src/aggregation_decode.rs` |
| E3 | Data-structure targets | `consensus/fuzz/structures/fuzz_targets/` |
| F1 | Run, reproduce, measure | `consensus/fuzz/justfile` |

## A. Upstream foundations

### A1. Deterministic runtime
- **Goal:** A seeded executor with simulated time. The same seed gives the same task schedule, so every fuzz input replays exactly.
- **Path:** `runtime/src/deterministic.rs` (`Runner`, `Config`, `Context`, `Auditor`)
- **When to use:** Every async harness. Seed `Config` from fuzz entropy with a timeout. `Context::auditor` returns a digest of everything the run did, for pinning or comparing runs.
- **Example:** `consensus/fuzz/core/src/lib.rs` (`bounded_fuzz_runtime_config`); `consensus/fuzz/marshal/src/marshal/end_to_end/golden.rs` (`ordinary_marshal_runs_are_unchanged`)
- **Gotchas:** All tasks are supervised. When a task finishes or is aborted, all its descendants are aborted, so spawn short-lived tasks from `context.child(..)`, never from a context that owns engines.

### A2. Simulated p2p network
- **Goal:** An in-process network with per-link latency, jitter and success rate, dynamic links, and sender/receiver splitting. It is deterministic on A1.
- **Path:** `p2p/src/simulated/` (`Network`, `Oracle`, `Link`, `SplitForwarder`, `SplitTarget`, `SplitOrigin`, `split_with`)
- **When to use:** Any multi-node harness. `Oracle::add_link` and `remove_link` shape the topology. `split_with` on a sender or receiver intercepts one node's traffic, which is how Twins and the ByzzFuzz forwarders work.
- **Example:** `consensus/fuzz/core/src/lib.rs` (`setup_network`); `consensus/fuzz/core/src/utils.rs` (`link_peers`, `apply_partition`)
- **Gotchas:** The fuzz harnesses set `disconnect_on_block: false`, so `Control::block` does not stop delivery. Cut traffic with `remove_link` or `apply_partition`.

### A3. Simplex honest mocks
- **Goal:** An honest application (propose, verify, certify), a payload relay, and a reporter that records activity for the invariants.
- **Path:** `consensus/src/simplex/mocks/application.rs` (`Application`, `Certifier`); `consensus/src/simplex/mocks/relay.rs` (`Relay`); `consensus/src/simplex/mocks/reporter.rs` (`Reporter`)
- **When to use:** Building honest simplex validators. Usually used indirectly through B5.
- **Example:** `consensus/fuzz/core/src/lib.rs` (`build_validator`, `CertifyChoice`)
- **Gotchas:** The mock `Reporter` keeps summary maps. `finalizations` is overwritten per view, while `finalizes` is append-only. For full history use B10.

### A4. Simplex Twins campaign framework
- **Goal:** Generates Twins cases. Each round sets the recipients of a compromised identity's primary and secondary halves and picks the leader, then the run returns to all-to-all synchrony.
- **Path:** `consensus/src/simplex/mocks/twins.rs` (`Framework`, `Mode`, `cases`, `Scenario`, `Elector`)
- **When to use:** Any Twins-style target. Upstream runs campaigns in `consensus/src/simplex/mod.rs` (`twins_campaign`); the fuzzers drive the framework through B7.
- **Example:** `consensus/fuzz/core/src/lib.rs` (`run_twins_with_backend_and_hook`); `consensus/fuzz/core/src/twins_network.rs` (`twins_within_mask`)
- **Gotchas:** `Framework::participants` is at most 64 (recipient sets are `u64` masks). `Mode::Sampled` draws each round independently; `Mode::Sustained` repeats one split.

### A5. Simplex Byzantine mock actors
- **Goal:** Named Byzantine behaviors. `conflicter` sends conflicting notarize/finalize messages; `equivocator` sends different proposals to different nodes; `impersonator` sends invalid impersonated votes; `nuller` sends nullify and finalize for the same view; `outdated` sends stale votes.
- **Path:** `consensus/src/simplex/mocks/` (`conflicter`, `equivocator`, `impersonator`, `nuller`, `outdated`)
- **When to use:** You want a fixed, protocol-aware Byzantine profile instead of the random mutations of B4.
- **Example:** `consensus/fuzz/simplex/src/mallory/adversary.rs` (`AdversaryRole`, `spawn_adversary`)

### A6. Certificate mock scheme and fixtures
- **Goal:** A cheap mock certificate scheme (no real cryptography) for fast fuzzing, plus real-scheme fixtures for when signatures matter.
- **Path:** `cryptography/src/certificate/mocks.rs` (`impl_certificate_mock`, `fixture_with`); `consensus/src/simplex/mocks/scheme.rs`; `consensus/src/simplex/scheme/` (`fixture`)
- **When to use:** The mock scheme for almost every target (the `*_cert_mock*` names). The ed25519, secp256r1 and BLS fixtures for codec and reporter-filtering targets.
- **Example:** `consensus/fuzz/core/src/simplex.rs` (`SimplexCertificateMock`, `fixture_with`); `consensus/fuzz/aggregation/src/aggregation_certificate_mock.rs` (`impl_certificate_mock`); `consensus/fuzz/structures/fuzz_targets/simplex_reporter_filtering.rs` (`fixture`)
- **Gotchas:** The flags in `fixture_with::<ATTRIBUTABLE, BATCHABLE, ALLOW_INVALID>` change verification behavior. Match the flags of the variant you extend.

### A7. Leader electors
- **Goal:** Leader-election configs, including multi-view terms.
- **Path:** `consensus/src/simplex/elector.rs` (`RoundRobin`, `Random`, `Scheduled`, `Terms`)
- **When to use:** Choosing a leader schedule. Wrap an elector to pin a Byzantine leader at a known view.
- **Example:** `consensus/fuzz/core/src/simplex.rs` (`ByzantineFirstLeaderRoundRobin`); `consensus/fuzz/marshal/src/scenarios/elector.rs` (`ByzantineLeaderAtView`); `consensus/fuzz/structures/fuzz_targets/simplex_elector.rs`

### A8. Marshal simulation harness
- **Goal:** The upstream multi-node marshal test harness: network and validator setup, shared constants, and test bodies written once for the standard, inline, deferred and coding variants.
- **Path:** `consensus/src/marshal/mocks/harness.rs` (`TestHarness`, `StandardHarness`, `InlineHarness`, `DeferredHarness`, `CodingHarness`, `setup_network_with_participants`, `LINK`, `TEST_QUOTA`, `NUM_VALIDATORS`, `BLOCKS_PER_EPOCH`)
- **When to use:** Reuse its constants, network setup and genesis/test-block builders in marshal fuzzers. It is also the source of the test scenarios ported in D7.
- **Example:** `consensus/fuzz/marshal/src/marshal/store.rs` (`fuzz_marshal_actor_store`, `setup_network_with_participants`); `consensus/fuzz/marshal/src/marshal/end_to_end/twins/stack.rs` (`setup_validator`)
- **Gotchas:** `TestHarness` hard-codes the BLS threshold scheme through its type aliases, so it cannot run with the mock certificate scheme. Use `FuzzScenarioStandardHarness` (D7) instead.

### A9. Marshal mock application and block
- **Goal:** A finalized-block sink that logs deliveries (acks can be manual), and a mock `Block` type.
- **Path:** `consensus/src/marshal/mocks/application.rs` (`Application`, `manual_ack`); `consensus/src/marshal/mocks/block.rs` (`Block`)
- **When to use:** Any marshal harness that checks delivery order or ack handling.
- **Example:** `consensus/fuzz/marshal/src/marshal/end_to_end/invariants.rs` (`check_pending_acks`); `consensus/fuzz/marshal/src/marshal/end_to_end/coding_stack.rs` (`setup_validator_coding`)

### A10. Aggregation mocks
- **Goal:** An application, monitor and reporter for running aggregation engines in tests.
- **Path:** `consensus/src/aggregation/mocks/` (`Application`, `Monitor`, `Reporter`)
- **When to use:** Any aggregation harness.
- **Example:** `consensus/fuzz/aggregation/src/aggregation.rs` (`spawn_engines`)

### A11. Resolver wire types and `TargetedResolver`
- **Goal:** Decode or forge resolver backfill messages, and observe or script fetches by implementing `TargetedResolver`.
- **Path:** `resolver/src/p2p/wire.rs` (`Message`, `Payload`); `resolver/src/lib.rs` (`TargetedResolver`)
- **When to use:** Poisoning, dropping or recording backfill traffic.
- **Example:** `consensus/fuzz/core/src/network.rs` (`CertificatePoison`); `consensus/fuzz/marshal/src/scenarios/recording_resolver.rs` (`RecordingResolver`)

### A12. Trace collector
- **Goal:** An in-memory tracing layer that collects spans and events.
- **Path:** `runtime/src/telemetry/traces/collector.rs` (`CollectingLayer`, `TraceStorage`)
- **When to use:** Turning WARN/DEBUG traces into coverage tokens, or asserting that an event was logged.
- **Example:** `consensus/fuzz/simplex/src/lib.rs` (`warn_trace_dispatch`, `run_with_warn_trace_collection`)
- **Gotchas:** Needs the `commonware-runtime` feature `test-utils`, which the fuzz crates already enable.

### A13. Fuzz and test RNGs
- **Goal:** Deterministic RNGs. `FuzzRng` turns fuzzer bytes into an endless stream; `TestRng` and `test_rng` give fixed seeds.
- **Path:** `utils/src/rng.rs` (`FuzzRng`, `Entropy`, `TestRng`, `test_rng`)
- **When to use:** Use `FuzzRng` for anything the fuzzer should steer (runtime seed, scenario choice). Use `TestRng` for unit tests and fixed keys.
- **Example:** `consensus/fuzz/core/src/lib.rs` (`bounded_fuzz_runtime_config`); `consensus/fuzz/structures/fuzz_targets/attributable_map.rs` (`TestRng`)
- **Gotchas:** The `Arbitrary` impl for `Entropy` consumes all remaining bytes, so make it the last field of an input struct.

## B. Core harness library (`consensus/fuzz/core`)

### B1. `FuzzInput`, configurations, runtime config
- **Goal:** The shared libFuzzer input for simplex-based harnesses: configuration, partition, strategy, term length, engine policies, and raw entropy for the runtime.
- **Path:** `consensus/fuzz/core/src/lib.rs` (`FuzzInput`, `Configuration`, `N4F1C3`, `N4F0C4`, `N4F3C1`, `CertifyChoice`, `BlockFilterChoice`, `ReporterWiring`, `bounded_fuzz_runtime_config`, `fuzz_runtime_timeout`, `BYZANTINE_IDX`)
- **When to use:** New simplex-level targets take `FuzzInput` as is. Marshal targets define narrower inputs (D2, D7).
- **Example:** `consensus/fuzz/simplex/fuzz_targets/simplex_cert_mock.rs`; `consensus/fuzz/simplex/src/lib.rs` (`run_standard_once`)
- **Gotchas:** Preset names read `N<n>F<faults>C<correct>`, and node indices `0..faults` are Byzantine (`BYZANTINE_IDX` is 0). `raw_bytes`, capped at `MAX_RAW_BYTES`, seeds the runtime.

### B2. `Simplex` trait and scheme variants
- **Goal:** Abstracts the scheme, the elector and fixture setup, so a target picks its whole cryptographic and leader setup with the type parameter `P`.
- **Path:** `consensus/fuzz/core/src/simplex.rs` (`Simplex`, `SimplexCertificateMock`, `SimplexCertificateMockAttributable`, `SimplexCertificateMockCustomRoundRobin`, `SimplexCertificateMockByzantineFirstLeader`); `consensus/fuzz/core/src/attributable_mock.rs` (`Scheme`, `Certificate`, `Registry`)
- **When to use:** Every simplex and marshal target. Add a variant here to change the elector or the scheme flags.
- **Example:** `consensus/fuzz/simplex/fuzz_targets/simplex_cert_mock_byzantine_first_leader.rs`; `consensus/fuzz/marshal/fuzz_targets/marshal_e2e_standard_deferred_cert_mock_block_dissemination.rs`
- **Gotchas:** C2 decodes an attributable scheme's certificate as a signer bitmap followed by the rest. The attributable mock's certificates are opaque ids, so an attributable variant wraps it in `attributable_mock::Scheme`, as `SimplexCertificateMockAttributable` does.

### B3. Network setup and partitions
- **Goal:** Starts N nodes on A2 with three channels each (vote, certificate, resolver), then applies static partitions or partitions that change per view.
- **Path:** `consensus/fuzz/core/src/lib.rs` (`setup_network`, `NetworkChannels`, `network_faults`, `scheduled_partition`, `spawn_network_fault_scheduler`, `default_link`); `consensus/fuzz/core/src/utils.rs` (`SetPartition`, `Partition`, `link_peers`, `apply_partition`, `register`)
- **When to use:** Every simplex-based harness. Mallory and Chaos call `apply_partition` directly for transient faults.
- **Example:** `consensus/fuzz/simplex/src/lib.rs` (`run_standard_once`); `consensus/fuzz/simplex/src/byzzfuzz/runner.rs` (`setup_engines`)
- **Gotchas:** `SetPartition::n4` indexes the 15 set partitions of 4 nodes; index 0 is fully connected.

### B4. Disrupter and mutation strategies
- **Goal:** A Byzantine node that mutates, replays and re-signs votes, certificates and resolver messages. A `Strategy` decides the mutations and the faulty views.
- **Path:** `consensus/fuzz/core/src/disrupter.rs` (`Disrupter`); `consensus/fuzz/core/src/strategy.rs` (`Strategy`, `StrategyChoice`, `SmallScope`, `AnyScope`, `FutureScope`, `HeaderScope`, `SplitHeader`); `consensus/fuzz/core/src/lib.rs` (`start_disrupter_with_epoch`)
- **When to use:** The default Byzantine actor for Standard, FaultyNet, TwinsMutator and the marshal end-to-end targets. Implement `Strategy` to scope it differently.
- **Example:** `consensus/fuzz/marshal/src/scenarios/adversary.rs` (`start_simplex_disrupter`); `consensus/fuzz/simplex/src/byzzfuzz/mutator.rs` (`ByzzFuzzMutator`)
- **Gotchas:** The stock strategies schedule faulty views in `1..=required_containers`. For a run that starts above a prefix floor, wrap them in `LiveScope` (`consensus/fuzz/marshal/src/scenarios/strategy.rs`).

### B5. Honest validator builders and lifecycle
- **Goal:** Spawns honest simplex validators (application, reporter, engine), optionally keeping their task handles so they can be crashed or restarted.
- **Path:** `consensus/fuzz/core/src/lib.rs` (`spawn_filtered_honest_validator`, `build_validator`, `build_validator_with_reporter`, `ManagedValidator`, `ValidatorLifecycle`, `HarnessReporter`)
- **When to use:** `spawn_filtered_honest_validator` for nodes that run to the end. `build_validator` when the harness crashes or restarts nodes (Mallory, Chaos).
- **Example:** `consensus/fuzz/simplex/src/mallory/lifecycle.rs` (`crash_stop`); `consensus/fuzz/simplex/src/chaos/runner.rs` (`run`)
- **Gotchas:** A crash must abort and await both task handles before the storage partition is reused. Otherwise the old incarnation can still send or keep its archives open.

### B6. Filterable block relay
- **Goal:** A mock block-dissemination application with a filter for each recipient (drop or delay), and an option to require the block before certifying.
- **Path:** `consensus/fuzz/core/src/block_relay.rs` (`Relay`, `Application`, `set_filter`, `set_certify_requires_block`)
- **When to use:** Fuzzing block availability, where honest nodes miss blocks for payloads that got notarized. It is driven by `BlockFilterChoice` in B1.
- **Example:** `consensus/fuzz/simplex/src/lib.rs` (`run_standard_once`); `consensus/fuzz/core/src/lib.rs` (`spawn_filtered_honest_validator`)

### B7. Twins driver
- **Goal:** A shared driver for Twins targets. It handles case generation (A4), iteration over compromised nodes, channel splitting and routing, twin roles, and Disrupter startup. A backend supplies the stack, the liveness wait and the invariants.
- **Path:** `consensus/fuzz/core/src/lib.rs` (`TwinsBackend`, `run_twins_with_backend`, `run_twins_with_backend_and_hook`, `TwinsSetup`); `consensus/fuzz/core/src/twins_network.rs` (`twins_within_mask`, `resolver_view`)
- **When to use:** A Twins target over a new stack only needs a `TwinsBackend` implementation.
- **Example:** `consensus/fuzz/simplex/src/lib.rs` (`MockTwinsBackend`); `consensus/fuzz/marshal/src/marshal/end_to_end/twins/mod.rs` (`MarshalTwinsBackend`)
- **Gotchas:** Routing rejects any payload without a decodable view, since no partition can be chosen for it.

### B8. Receiver filters
- **Goal:** Receiver wrappers that reorder, drop or rewrite one node's inbound messages:
  - `ByzantineFirstReceiver` serves adversary messages first.
  - The omission receivers hide notarize votes or finalizations.
  - `CertificatePoison` forges certificate backfill answers.
  - `Wedge` models a split notarization in phases around GST.
- **Path:** `consensus/fuzz/core/src/network.rs` (`Router`, `ByzantineFirstReceiver`, `NotarizeOmissionReceiver`, `FinalizationOmissionReceiver`, `CertificatePoison`, `CertificatePoisonReceiver`, `Wedge`, `WedgeReceiver`)
- **When to use:** A fault that lives on the receiving side of one honest node.
- **Example:** `consensus/fuzz/simplex/src/lib.rs` (`run_audited_standard_once_with`); `consensus/fuzz/marshal/src/marshal/end_to_end/runner.rs` (`run_standard_disrupter`); `consensus/fuzz/marshal/src/marshal/end_to_end/scenario.rs` (`run_scenario`)

### B9. Byzantine activity counter
- **Goal:** Run-scoped counts, per actor, of the messages each Byzantine actor actually got onto the network, so smoke tests catch an adversary that went silent.
- **Path:** `consensus/fuzz/core/src/byzantine.rs` (`Counting`, `count`, `reset`, `record`, `twin_secondary`)
- **When to use:** Wrap every new Byzantine actor's senders in `Counting` under its own label, and add a smoke test.
- **Example:** `consensus/fuzz/simplex/src/lib.rs` (`adversary_smoke`, `assert_acted`); `consensus/fuzz/marshal/src/lib.rs` (`assert_adversary_acted`, `assert_adversary_silent`)
- **Gotchas:** Assert on the label of the actor the target exists for. Sends from another actor in the same run can hide a silent one.

### B10. Audit recorder
- **Goal:** An append-only per-node log of every activity and every automaton request and result. The mock reporter keeps only summaries.
- **Path:** `consensus/fuzz/core/src/simplex_audit.rs` (`RecordingReporter`, `RecordingAutomaton`, `AuditLog`)
- **When to use:** Invariants that need history: ordering, or what the automaton was asked. Passing `&[RecordingReporter]` to `invariants::check` enables the audit checks.
- **Example:** `consensus/fuzz/simplex/src/lib.rs` (`run_audited_standard_once_with`); `consensus/fuzz/simplex/src/invariants.rs` (`check_fuzz_invariants`)

### B11. Trusted continuation (prefix) framework
- **Goal:** Runs a deterministic state-building prefix (send, hold, crash and relink as the compromised identity) after the honest engines start and before the Byzantine actors and oracles do.
- **Path:** `consensus/fuzz/core/src/continuation.rs` (`Prefix`, `PrefixContext`, `Hook`, `Runner`, `ReplicaTap`)
- **When to use:** Target-state scaffolds, where the run first reaches a specific protocol state and fuzzing starts from there.
- **Example:** `consensus/fuzz/simplex/src/trusted.rs` (`fuzz_with_prefix`); `consensus/fuzz/marshal/src/marshal/end_to_end/trusted.rs` (`release_standard`)
- **Gotchas:** With a prefix, the drivers skip the liveness wait and check safety only.

### B12. BFT reference bounds
- **Goal:** Hard-coded `max_faults` and `quorum` values for n up to 21, as a root of trust that does not depend on the code under test.
- **Path:** `consensus/fuzz/core/src/bounds.rs` (`max_faults`, `quorum`)
- **When to use:** Any invariant that needs quorum sizes.
- **Example:** `consensus/fuzz/simplex/src/invariants.rs` (`check_basic_invariants`)

## C. Simplex harness (`consensus/fuzz/simplex`)

### C1. Simplex entry point and mode dispatch
- **Goal:** One generic entry point, `fuzz::<P, M, C>`, for all simplex targets. `P` picks the scheme (B2), `M` the mode and `C` the coverage signal.
- **Path:** `consensus/fuzz/simplex/src/lib.rs` (`fuzz`, `FuzzMode`, `Coverage`, `Standard`, `FaultyNet`, `TwinsMutator`, `TwinsCampaign`, `Byzzfuzz`, `MalloryContainer`, `Chaos`, `ChaosTwins`, `CodeCoverage`, `StateCoverage`, `HappensBeforeCoverage`, `HappensBeforeStateCoverage`, `fuzz_audit`, `fuzz_twins_audit`); `consensus/fuzz/core/src/lib.rs` (`Mode`)
- **When to use:** A new simplex target is a `fuzz_target!` that calls `fuzz::<P, M, C>(input)`. The modes:
  - Standard: honest nodes plus a Disrupter.
  - FaultyNet: partitions per view.
  - TwinsMutator: a twin engine plus a Disrupter twin.
  - TwinsCampaign: both twins are full engines.
  - Byzzfuzz (C5), MalloryContainer (C6), Chaos and ChaosTwins (C7).
  
  `C` applies only to Standard, FaultyNet and the two Twins modes.
- **Example:** `consensus/fuzz/simplex/fuzz_targets/simplex_cert_mock.rs`; `consensus/fuzz/simplex/fuzz_targets/simplex_cert_mock_twins_campaign.rs`
- **Gotchas:** Register the target in `consensus/fuzz/simplex/Cargo.toml` with `required-features = ["twins"]` if its name contains `twins`, otherwise `["base"]`.

### C2. Simplex safety invariants
- **Goal:** Safety oracles over end-of-run reporter state: agreement, finalization ancestry, conflicting notarizations, certificate validity, vote equivocation and leader rules.
- **Path:** `consensus/fuzz/simplex/src/invariants.rs` (`check`, `SafetyObservations`, `check_basic_invariants`, `check_vote_invariants`, `check_vote_invariants_with_byzantine`, `check_no_invalid_reports`, `extract`)
- **When to use:** Call `check` at the end of every simplex run; the observation type decides between the basic and the audit checks. Use `check_vote_invariants_with_byzantine` when the Byzantine set is not `0..faults`.
- **Example:** `consensus/fuzz/simplex/src/byzzfuzz/runner.rs` (`run`); `consensus/fuzz/simplex/src/chaos/runner.rs` (`check_safety`)
- **Gotchas:** A panic here is a finding, never a rejected run. New checks belong in this file, not in coverage tokens (C4).

### C3. Happens-before coverage
- **Goal:** Turns an ordered stream of protocol events, each tagged with its node, into happens-before pairs. Distinct pairs become coverage tokens and Mallory's state fingerprint.
- **Path:** `consensus/fuzz/simplex/src/happens_before.rs` (`EventKind`, `Event`, `Summary`, `EventLog`, `NodeSubscriber`)
- **When to use:** `HappensBeforeCoverage` targets (`*_hb`), or any harness that wants novelty in interleavings rather than in end states.
- **Example:** `consensus/fuzz/simplex/fuzz_targets/simplex_cert_mock_hb.rs`; `consensus/fuzz/simplex/src/mallory/runner.rs` (`fingerprint`)

### C4. State coverage
- **Goal:** A second feedback signal. It projects end-of-run replica state into canonical tokens and lights one counter per token in a custom SanitizerCoverage table.
- **Path:** `consensus/fuzz/simplex/src/state_cov.rs` (`reset`, `observe_tokens`, `observe_with_metrics`, `observe_trace_events`, `encode_reporter_states`)
- **When to use:** `StateCoverage` targets (`*_state_cov`), or any harness whose interesting state does not show up as code edges.
- **Example:** `consensus/fuzz/simplex/src/lib.rs` (`run_standard_once`); `consensus/fuzz/simplex/src/mallory/state.rs` (`state_descriptor`)
- **Gotchas:** Tokens are coverage only. Never put invariant or anomaly checks into them.

### C5. ByzzFuzz
- **Goal:** ByzzFuzz-style bounded fault injection. Network faults drop messages across partitions in sampled rounds. Process faults omit or semantically mutate the Byzantine sender's messages. The run then reaches GST and checks liveness.
- **Path:** `consensus/fuzz/simplex/src/byzzfuzz/` (`run`, `ByzzFuzz`, `ProcessFault`, `NetworkFault`, `ByzzFuzzInjector`, `RoundTrackingReceiver`, `SenderViewCell`)
- **When to use:** Target `simplex_cert_mock_byzzfuzz`. Reuse its forwarders, which use `split_with` and key faults on the sender's round, for round-scoped network faults.
- **Example:** `consensus/fuzz/simplex/fuzz_targets/simplex_cert_mock_byzzfuzz.rs`; `consensus/fuzz/simplex/src/byzzfuzz/runner.rs` (`setup_engines`)
- **Gotchas:** Read `consensus/fuzz/simplex/src/byzzfuzz/specs/INDEX.md` first; `specs/contracts/byzzfuzz-harness.md` is the wiring contract. Certificate and resolver process faults only omit messages.

### C6. Mallory
- **Goal:** An adaptive adversary. A tabular Q-learning policy over happens-before state picks a network, packet, crash or Byzantine-role fault at each step. The learned policy steers a custom libFuzzer mutator.
- **Path:** `consensus/fuzz/simplex/src/mallory/` (`run`, `Schedule`, `Fault`, `QPolicy`, `AdversaryRole`, `RoleMultiplexer`, `Topology`, `crash_stop`, `mutate`)
- **When to use:** Target `simplex_cert_mock_mallory`. Reuse `crash_stop` and `Topology` inside the simplex crate for crash and partition control.
- **Example:** `consensus/fuzz/simplex/fuzz_targets/simplex_cert_mock_mallory.rs` (`fuzz_mutator`); `consensus/fuzz/simplex/src/chaos/runner.rs` (`crash_stop`)
- **Gotchas:** Execution reads its whole schedule from the input, so a crash file replays exactly; the Q-table influences only mutation. The modules are `pub(crate)`.

### C7. Chaos and ChaosTwins
- **Goal:** The crash-fault axis. A schedule driven by the fuzzer crashes nodes and changes the network, and every fault gets a paired heal. Chaos runs an all-honest committee and checks safety only. ChaosTwins runs N4F1C3 with a twin leader and adds a liveness check after recovery.
- **Path:** `consensus/fuzz/simplex/src/chaos/` (`Schedule`, `Condition`, `Action`, `Checker`, `run`, `check_safety`)
- **When to use:** Targets `simplex_cert_mock_chaos` and `simplex_cert_mock_chaos_twins`. Reuse `Schedule` when you need faults that always heal.
- **Example:** `consensus/fuzz/simplex/src/chaos/runner.rs` (`run`); `consensus/fuzz/simplex/src/chaos/twins.rs` (`run`)

### C8. Simplex prefix entry points
- **Goal:** The simplex base drivers with a B11 prefix hook.
- **Path:** `consensus/fuzz/simplex/src/trusted.rs` (`fuzz_with_prefix`, `fuzz_audit_with_prefix`, `fuzz_twins_audit_with_prefix`)
- **When to use:** Building a target-state scaffold for simplex. No fuzz target uses it yet.
- **Example:** `consensus/fuzz/simplex/src/trusted.rs` (`runs_with_a_prefix_are_deterministic`, `ordinary_runs_are_unchanged`)
- **Gotchas:** `ordinary_runs_are_unchanged` pins the auditor states of runs without a prefix. A changed hash means the driver's behavior changed.

## D. Marshal harness (`consensus/fuzz/marshal`)

### D1. Marshal store harness
- **Goal:** Fuzzes one marshal actor and its prunable archives with a sequence of operations: seed, report, get, prune, floors, hints, bursts, subscribe, deliver, restart, and direct archive access.
- **Path:** `consensus/fuzz/marshal/src/marshal/store.rs` (`StoreOp`, `MarshalActorStoreInput`, `fuzz_marshal_actor_store`, `setup_prunable_validator_cert_mock`)
- **When to use:** Target `marshal_actor_standard_store_cert_mock`. Extend `StoreOp` to reach store or actor paths without running consensus.
- **Example:** `consensus/fuzz/marshal/fuzz_targets/marshal_actor_standard_store_cert_mock.rs`; `consensus/fuzz/marshal/src/marshal/store.rs` (`restart_stops_a_busy_actor`)
- **Gotchas:** `Restart` must abort and await the old actor handle before reopening the same partitions. Add new operations to the existing op stream, not as a separate fixture.

### D2. Marshal end-to-end drivers
- **Goal:** An N4F1C3 cluster of real simplex engines whose reporter is marshal, with a Byzantine node 0. It checks delivery agreement and liveness. Variants add certificate-backfill poison or Byzantine block dissemination.
- **Path:** `consensus/fuzz/marshal/src/marshal/end_to_end/runner.rs` (`fuzz_marshal_standard_disrupter`, `fuzz_marshal_standard_certificate_poison`, `fuzz_marshal_standard_block_dissemination`, `run_standard_disrupter`, `force_poison`); `consensus/fuzz/marshal/src/marshal/end_to_end/input.rs` (`MarshalDisrupterInput`); `consensus/fuzz/marshal/src/marshal/end_to_end/app.rs` (`ApplicationChoice`, `DeliveryReporter`); `consensus/fuzz/marshal/src/marshal/end_to_end/block_disrupter.rs` (`MarshalBroadcastFault`)
- **When to use:** The default base for fuzzing marshal under consensus.
- **Example:** `consensus/fuzz/marshal/fuzz_targets/marshal_e2e_standard_deferred_cert_mock_disrupter.rs`
- **Gotchas:** Node 0 runs only a simplex Disrupter and no marshal stack, so nothing is sent on the block-gossip channel unless the block-dissemination actor is started.

### D3. Marshal coding stack and faults
- **Goal:** The coding marshal variant (Reed-Solomon shard dissemination; the `Marshaled` wrapper with `Commitment` payloads), plus Byzantine shard and backfill faults.
- **Path:** `consensus/fuzz/marshal/src/marshal/end_to_end/coding_stack.rs` (`setup_validator_coding`, `start_engine_coding_with_networks`, `FaultyProposer`); `consensus/fuzz/marshal/src/marshal/end_to_end/coding_disrupter.rs` (`CodingFaults`, `start_backfill_poison`)
- **When to use:** The `marshal_e2e_coding_*` targets.
- **Example:** `consensus/fuzz/marshal/src/marshal/end_to_end/runner.rs` (`run_coding_disrupter`, `fuzz_marshal_coding_block_poison`)

### D4. Marshal end-to-end invariants
- **Goal:** Checks during and at the end of a run on the marshal/application boundary: delivery order, parent linkage, cross-node agreement, ack accounting and certification agreement.
- **Path:** `consensus/fuzz/marshal/src/marshal/end_to_end/invariants.rs` (`check_all_blocks`, `check_local_blocks`, `check_parent_linkage`, `check_pending_acks`, `agreement`, `CertificationAgreementInvariant`, `HeaderMismatchInvariant`, `check_certificate_backfill_retry`)
- **When to use:** Every marshal end-to-end, Twins and scenario driver.
- **Example:** `consensus/fuzz/marshal/src/marshal/end_to_end/twins/mod.rs` (`check_local_blocks`, `agreement`); `consensus/fuzz/marshal/src/marshal/end_to_end/scenario.rs` (`run_scenario`)
- **Gotchas:** The delivery checks read the sink's append-only delivery log, not the latest state.

### D5. Marshal Twins backend
- **Goal:** A B7 backend over real marshal. The compromised identity runs a full engine plus a Disrupter twin, and the honest nodes use real marshal/application paths.
- **Path:** `consensus/fuzz/marshal/src/marshal/end_to_end/twins/` (`MarshalTwinsBackend`, `fuzz_marshal_standard_twins`, `fuzz_marshal_coding_twins`, `attack_layout`, `ObservedMarshal`, `TwinsMarshal`)
- **When to use:** The `marshal_e2e_*_twins*` targets. The split-header targets narrow the search to header-split scenarios through `attack_layout`.
- **Example:** `consensus/fuzz/marshal/fuzz_targets/marshal_e2e_standard_app_cert_mock_twins.rs`
- **Gotchas:** The general Twins target uses the last byte of its raw entropy to select the application and wrapper, so all variants share one corpus.

### D6. Marshal pre-GST scenarios
- **Goal:** Replays a templated pre-GST program that the fuzzer extends, heals the network at a fixed GST, and requires every correct node to finalize past the height it held at GST.
- **Path:** `consensus/fuzz/marshal/src/marshal/end_to_end/scenario.rs` (`ScenarioTemplate`, `PreGstAction`, `run_scenario`, `fuzz_marshal_standard_scenarios`)
- **When to use:** Target `marshal_e2e_standard_deferred_cert_mock_scenarios`. Add a template for each new pre-GST attack shape.
- **Example:** `consensus/fuzz/marshal/fuzz_targets/marshal_e2e_standard_deferred_cert_mock_scenarios.rs`

### D7. Marshal scenario framework
- **Goal:** Three phases. Setup builds four validators. A prefix copied from a standard-marshal unit test drives the honest nodes to that test's state, and the handoff is verified. Live fuzzing then runs with a Byzantine node 0.
- **Path:** `consensus/fuzz/marshal/src/scenarios/` (`Scenario`, `FuzzScenarioStandardHarness`, `RecordingResolver`, `ScenarioHandoff`, `LiveScope`, `ByzantineLeaderAtView`, `fuzz_marshal_scenario_prefix_deferred`); spec in `consensus/fuzz/marshal/src/scenarios/specs/SPEC.md`
- **When to use:** Turning an existing `consensus/src/marshal` test into a starting point for fuzzing.
- **Example:** `consensus/fuzz/marshal/src/scenarios/scenarios.rs` (`StandardCertifyMissingCandidateFetchesByRound`); `consensus/fuzz/marshal/fuzz_targets/marshal_scenario_standard_deferred_cert_mock.rs`
- **Gotchas:** Section 11 of `SPEC.md` shows how to translate a source test. `RecordingResolver` stands in for the source tests' `cfg(test)` resolver.

### D8. Marshal golden and prefix tests
- **Goal:** Pins the auditor state of each driver to catch unintended behavior changes, and checks that runs with a prefix are deterministic.
- **Path:** `consensus/fuzz/marshal/src/marshal/end_to_end/golden.rs` (`ordinary_marshal_runs_are_unchanged`); `consensus/fuzz/marshal/src/marshal/end_to_end/trusted/tests.rs` (`hooked_marshal_runs_are_deterministic`)
- **When to use:** Run after changing any marshal driver. Re-pin the hashes only for deliberate changes.
- **Example:** `consensus/fuzz/marshal/src/marshal/end_to_end/golden.rs` (`run_standard_disrupter`)

## E. Aggregation and structures

### E1. Aggregation engine harness
- **Goal:** Honest aggregation engines on A1 and A2 with fuzzed links, partitions and timeouts, plus a bad-ack injector. It checks that no certificates conflict and that the target height is reached.
- **Path:** `consensus/fuzz/aggregation/src/aggregation.rs` (`FuzzInput`, `fuzz`, `spawn_engines`, `spawn_bad_ack_injector`, `check_no_conflicting_certs`)
- **When to use:** Target `aggregation_cert_mock`. It is also a compact template for an engine harness outside simplex.
- **Example:** `consensus/fuzz/aggregation/fuzz_targets/aggregation_cert_mock.rs`

### E2. Codec round-trip targets
- **Goal:** The pattern for wire types: build an arbitrary value, encode it, decode it and compare; also feed the raw input to `read_cfg` to reach the error paths.
- **Path:** `consensus/fuzz/aggregation/src/aggregation_decode.rs` (`fuzz`); `consensus/fuzz/structures/fuzz_targets/simplex_messages.rs`
- **When to use:** Any new encoded type in consensus.
- **Example:** `consensus/fuzz/aggregation/fuzz_targets/aggregation_decode.rs`
- **Gotchas:** Assert `encode().len() == encode_size()`, and decode borrowed bytes through `Copying`.

### E3. Data-structure targets
- **Goal:** Self-contained single-process targets:
  - `attributable_map.rs`: `AttributableMap` inserts checked against a model.
  - `simplex_elector.rs`: elector selection.
  - `simplex_reporter_filtering.rs`: reporter filtering of invalid and wrong-namespace activity, across real schemes.
- **Path:** `consensus/fuzz/structures/fuzz_targets/` (`attributable_map.rs`, `simplex_elector.rs`, `simplex_reporter_filtering.rs`)
- **When to use:** A pure data structure or a synchronous component that needs no runtime. The package depends only on published crates.
- **Example:** `consensus/fuzz/structures/fuzz_targets/attributable_map.rs` (`fuzz`)

## F. Workflow

### F1. Run, reproduce, measure
- **Goal:** Build, run, reproduce and measure the targets.
- **Path:** `consensus/fuzz/justfile`; `consensus/fuzz/README.md`; `consensus/fuzz/coverage.sh`
- **When to use:**
  - From `consensus/fuzz`:
    - `just list`
    - `just run <target> -- -max_total_time=<secs>`
    - `just run <target> <crash_file>`
    - `just features=twins build simplex`
  - Set `CONSENSUS_FUZZ_LOG` to print the input and the ByzzFuzz, Mallory or Chaos decision log on panic.
  - `coverage.sh` builds per-target HTML coverage for the simplex targets.
- **Example:** `cargo +nightly fuzz run --fuzz-dir consensus/fuzz/simplex simplex_cert_mock`
- **Gotchas:** `consensus/fuzz` has no manifest, so a bare `cargo fuzz` fails; always pass `--fuzz-dir`. Use the nightly pinned as `NIGHTLY_VERSION` in `.github/workflows/slow.yml`.

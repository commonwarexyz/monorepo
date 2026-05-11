# Runner Liveness

## Purpose

Runner liveness orchestrates a single ByzzFuzz iteration: it coerces the harness shape, wires engines and fault machinery, runs a bounded fault phase, reaches GST when needed, checks post-GST progress, and then runs safety invariants.

## Key Files

- `consensus/fuzz/src/byzzfuzz/runner.rs` - ByzzFuzz setup, phase control, GST transition, and invariant checks.
- `consensus/fuzz/src/byzzfuzz/mod.rs` - exports `run` and defines `BYZANTINE_IDX`.
- `consensus/fuzz/src/lib.rs` - `Mode::Byzzfuzz`, `Byzzfuzz` marker type, panic hook, `setup_network`, and `spawn_honest_validator`.
- `consensus/fuzz/fuzz_targets/simplex_id_byzzfuzz.rs` - ByzzFuzz fuzz target for `SimplexId`.
- `consensus/fuzz/fuzz_targets/simplex_cert_mock_byzzfuzz.rs` - ByzzFuzz fuzz target for `SimplexCertificateMock`.

## Core Types

```rust
struct EngineSetup<P: Simplex> {
    reporters: Vec<ByzzReporter<P>>,
    byzantine_view: SenderViewCell,
    proc_schedule: Arc<Mutex<Vec<ProcessFault<PublicKeyOf<P>>>>>,
    participants: Vec<PublicKeyOf<P>>,
    post_gst_fault_views: u64,
}
```

`EngineSetup` returns already-running reporters plus the shared state needed for GST and post-GST scheduling.

```rust
pub fn run<P: Simplex>(mut input: crate::FuzzInput)
```

`run` is the ByzzFuzz mode entry point.

## Flow

```
run(input)
    |
    | input.configuration = N4F0C4
    | input.partition = Connected
    | input.degraded_network = false
    | deterministic runner uses FuzzRng(input.raw_bytes)
    v
setup_engines
    |
    | setup_network
    | sample schedules
    | install split forwarders and tracking receivers
    | spawn honest validators
    | spawn injector
    v
phase 1
    |
    | wait until all non-byzantine reporters reach required_containers
    | or BYZZFUZZ_FAULT_PHASE elapses
    |
    +-- early complete:
    |       skip GST and phase 2
    |
    v
phase 2 if needed
    |
    | subscribe baselines
    | prune and append process faults
    | reach FaultGate GST
    | require below-target reporters to reach required_containers
    | require at-target reporters to finalize above baseline
    |
    v
invariants
    |
    | check vote invariants with byzantine set
    | extract only correct reporters
    | check consensus invariants
```

## Related Invariants

- [Runner Liveness](../invariants/invariants.md#runner-liveness) - run-shape, GST, and post-GST target invariants.

## Configuration

| Parameter | Value | Source |
| --------- | ----- | ------ |
| Fault phase window | `30s` virtual time | `BYZZFUZZ_FAULT_PHASE` |
| Post-GST window | `360s` virtual time | `BYZZFUZZ_POST_GST_WINDOW` |
| Forced configuration | `N4F0C4` | `run` |
| Forced partition | `Partition::Connected` | `run` |
| Byzantine index | `0` | `BYZANTINE_IDX` |
| Validator timeouts | `1s` leader, `2s` certification | `setup_engines` |

## Extension Points

- Change phase timing by editing the runner constants and updating ADR-005 if the liveness model changes.
- Add target-specific ByzzFuzz modes through `fuzz::<P, Byzzfuzz>(input)` and keep dispatch in `Mode::Byzzfuzz`.
- Add new per-channel fault machinery in `setup_engines` only after updating network interception and forwarder/injector contracts.

## Related Specs

- [Fault Flow](../architecture/fault-flow.md) - phase and per-message ordering.
- [Fault Scheduling](fault-scheduling.md) - schedule generation and post-GST extension.
- [ByzzFuzz/Harness Contract](../contracts/byzzfuzz-harness.md) - entry point boundary.
- [ADR-005](../decisions/005-post-gst-required-container-catch-up.md) - current liveness decision.
- [ADR-003](../decisions/003-post-gst-liveness-check.md) - superseded liveness decision.

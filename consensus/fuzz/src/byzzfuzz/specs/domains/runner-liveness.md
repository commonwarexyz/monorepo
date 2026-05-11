# Runner Liveness

## Purpose

Runner liveness orchestrates a single ByzzFuzz iteration: it coerces the harness shape, wires engines and fault machinery, runs a bounded fault phase, reaches GST when needed, checks post-GST progress, and then runs safety invariants. It is the only public entry point for `Mode::Byzzfuzz`.

## Key Files

- `consensus/fuzz/src/byzzfuzz/runner.rs` - ByzzFuzz setup, phase control, GST transition, and invariant checks.
- `consensus/fuzz/src/byzzfuzz/mod.rs` - exports the entry point and the fixed byzantine index.
- `consensus/fuzz/src/lib.rs` - mode dispatch, panic hook, and shared network/validator setup helpers.
- `consensus/fuzz/fuzz_targets/simplex_id_byzzfuzz.rs`, `consensus/fuzz/fuzz_targets/simplex_cert_mock_byzzfuzz.rs` - fuzz targets that select `Mode::Byzzfuzz`.

## Core Types

| Item | Role |
| ---- | ---- |
| Run entry point | Single public function invoked by the harness for a ByzzFuzz iteration. |
| Engine setup | Internal bundle of running reporters plus the shared state needed for GST and the post-GST schedule. |

## Flow

```
run begins
    |
    | coerce harness shape (fixed 4-node connected topology)
    | seed deterministic runtime from the fuzz input bytes
    v
setup
    |
    | sample schedules
    | wire interception and the injector
    | spawn honest validators
    v
phase 1: bounded fault phase
    |
    | network and process faults are active
    |
    +-- if every correct reporter reaches required_containers:
    |       skip GST and phase 2
    |
    v
GST transition
    |
    | record per-reporter baselines
    | prune dormant pre-GST process faults
    | extend the process-fault schedule for future byzantine rounds
    | open the GST gate (partition filtering stops; process faults stay on)
    v
phase 2: bounded post-GST window
    |
    | each correct reporter below required_containers must reach it
    | each correct reporter already at or above must finalize above its baseline
    | failure to advance panics with a liveness diagnostic
    v
safety invariants
    |
    | byzantine reporter excluded from state extraction
```

## Related Invariants

- [Fault Flow](../invariants/invariants.md#fault-flow) - GST transition, phase 2 target, and post-GST scheduling.
- [Fault Scheduling](../invariants/invariants.md#fault-scheduling) - schedule shape installed by the runner.
- [Layers](../invariants/invariants.md#layers) - the run entry point owns setup and ordering.

## Configuration

| Parameter | Source | Meaning |
| --------- | ------ | ------- |
| Fault-phase length | `runner.rs` constant | Upper bound on phase 1 duration. |
| Post-GST window length | `runner.rs` constant | Upper bound on phase 2 duration. |
| Harness shape | `run` | Fixed 4-node connected topology with degraded network disabled. |
| Byzantine identity | `mod.rs` | Single fixed index used end-to-end. |
| Validator timeouts | `setup_engines` | Leader and certification timeouts passed to the Simplex engine. |

## Extension Points

- Change phase timing by editing the runner constants and updating [ADR-005](../decisions/005-post-gst-required-container-catch-up.md) if the liveness model changes.
- Add a new target by routing it through the existing fuzz-mode dispatch.
- Add new per-channel fault machinery in setup only after updating the network-interception and forwarder/injector specs.

## Related Specs

- [Fault Flow](../architecture/fault-flow.md) - phase and per-message ordering.
- [Fault Scheduling](fault-scheduling.md) - schedule generation and post-GST extension.
- [ByzzFuzz/Harness Contract](../contracts/byzzfuzz-harness.md) - entry-point boundary.
- [ADR-005](../decisions/005-post-gst-required-container-catch-up.md) - current liveness decision.
- [ADR-003](../decisions/003-post-gst-liveness-check.md) - superseded liveness decision.

# Fault Scheduling

## Purpose

Fault scheduling defines the sampled ByzzFuzz adversary: network-fault rounds, process-fault rounds, receiver sets, omit flags, and optional message-kind scopes.

## Key Files

- `consensus/fuzz/src/byzzfuzz/mod.rs` - public module entry, `run` export, and `BYZANTINE_IDX`.
- `consensus/fuzz/src/byzzfuzz/fault.rs` - `ProcessFault` and `NetworkFault` data types.
- `consensus/fuzz/src/byzzfuzz/sampling.rs` - `(c, d, r)` schedule generation.
- `consensus/fuzz/src/byzzfuzz/scope.rs` - process-fault scope variants and weighted scope sampler.
- `consensus/fuzz/src/byzzfuzz/runner.rs` - samples `(c, d, r)` bounds and post-GST process-fault views.

## Core Types

```rust
pub struct ProcessFault<P: PublicKey> {
    pub view: u64,
    pub receivers: Vec<P>,
    pub omit: bool,
    pub scope: FaultScope,
}

pub struct NetworkFault {
    pub view: View,
    pub partition: SetPartition,
}
```

`ProcessFault` targets the byzantine sender at one `rnd(m)` view. `NetworkFault` targets every channel at one sender `rnd(m)` view.

```rust
pub struct ByzzFuzz {
    pub c: u64,
    pub d: u64,
    pub r: u64,
}
```

`c` is the number of process-fault draws, `d` is the number of network-fault draws, and `r` is the total round budget.

```rust
pub enum FaultScope {
    Any,
    Vote(VoteKind),
    Certificate(CertificateKind),
}
```

`FaultScope` narrows process faults by message kind. Resolver process faults currently match only `Any`.

## Flow

```
runner::setup_engines
    |
    | choose r_bound from required_containers or required_containers * [2, 100]
    | choose r from [1, r_max]
    | choose c and d from [0, max(r / FAULT_INJECTION_RATIO, 1)]
    | force c > 0 or d > 0
    v
ByzzFuzz::new(c, d, r)
    |
    +--> network_faults:
    |       sample min(d, r) distinct views from [1, r]
    |       sample non-trivial N4 partition index from [1, 14]
    |
    +--> process_faults:
            sample c views with replacement from [1, r]
            sample non-empty receiver subset from participants[1..]
            sample omit with probability 1/4
            sample FaultScope by weights
```

At GST, `runner.rs` prunes pre-GST process faults above `byzantine_rnd` and appends fresh `FaultScope::Any` process faults for a future contiguous range of byzantine views.

## Related Invariants

- [Fault Scheduling](../invariants/invariants.md#fault-scheduling) - sampling and schedule-shape invariants.

## Configuration

| Parameter | Source | Meaning |
| --------- | ------ | ------- |
| `BYZANTINE_IDX` | `mod.rs` | Fixed byzantine participant index, currently `0`. |
| `FAULT_INJECTION_RATIO` | `consensus/fuzz/src/lib.rs` | Divides `r` to bound per-type fault counts. |
| `Any` scope weight | `scope.rs` | `50` out of `100`. |
| `Vote` scope weight | `scope.rs` | `45` out of `100`, uniform over `Notarize`, `Finalize`, `Nullify`. |
| `Certificate` scope weight | `scope.rs` | `5` out of `100`, uniform over `Notarization`, `Nullification`, `Finalization`. |
| Process omit probability | `sampling.rs` | `1/4`. |

## Extension Points

- Add a new vote or certificate kind by updating `VOTE_KINDS` or `CERTIFICATE_KINDS` and the kind extractor functions in `scope.rs`.
- Add resolver-specific scopes by extending `FaultScope`, its sampler, and `make_resolver` scope matching.
- Change schedule density in `runner.rs`, not inside `ProcessFault` or `NetworkFault` data types.

## Related Specs

- [Fault Flow](../architecture/fault-flow.md) - how sampled schedules affect messages.
- [Runner Liveness](runner-liveness.md) - how schedules are installed and extended at GST.
- [ADR-001](../decisions/001-single-byzantine-index.md) - fixed byzantine identity.

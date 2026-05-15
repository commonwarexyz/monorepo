# Fault Scheduling

## Purpose

Fault scheduling defines the sampled ByzzFuzz adversary: which views see network partitions, which views see process faults against the fixed byzantine sender, and how those faults are shaped (recipient subsets, process action, optional message-kind scope).

## Key Files

- `consensus/fuzz/src/byzzfuzz/sampling.rs` - schedule generation.
- `consensus/fuzz/src/byzzfuzz/fault.rs` - process- and network-fault data types.
- `consensus/fuzz/src/byzzfuzz/scope.rs` - process-fault message-scope variants and scope sampler.
- `consensus/fuzz/src/byzzfuzz/runner.rs` - draws schedule bounds and post-GST extension.
- `consensus/fuzz/src/byzzfuzz/mod.rs` - exposes the fixed byzantine identity.

## Core Types

| Type | Role |
| ---- | ---- |
| `ByzzFuzz` | Schedule bounds `(c, d, r)`: process-fault count, network-fault count, total round budget. |
| `ProcessFault` | One scheduled fault against the byzantine sender at one decoded message view, with a recipient subset, a process action, and a message scope. |
| `NetworkFault` | One scheduled partition active at one sender round, applied to every channel. |
| `ProcessAction` | Process-fault action: omit targeted delivery, or mutate and re-sign a vote. |
| `MessageScope` | Optional message-kind filter for process faults: any / specific vote kind / specific certificate kind. |

## Flow

```
runner samples bounds
    |
    | choose r within a small bound relative to required_containers
    | choose c and d such that at least one is non-zero
    v
network faults
    |
    | unique rounds within [1, r]
    | uniform non-trivial 4-node partition at each round
    v
process faults
    |
    | rounds drawn from [1, r] (with repetition allowed)
    | non-empty receiver subset from correct participants
    | action sampled as omit or vote mutation
    | message scope sampled with a small probability of narrowing to a specific kind
    v
runtime extends the process-fault schedule at GST
    |
    | drop dormant pre-GST faults at rounds the byzantine never reached
    | append fresh, any-kind faults for a contiguous range above byzantine_rnd
```

## Related Invariants

- [Fault Scheduling](../invariants/invariants.md#fault-scheduling) - schedule shape, byzantine-identity exclusion, view sampling rules.
- [Fault Flow](../invariants/invariants.md#fault-flow) - GST pruning and post-GST extension rules.

## Configuration

| Parameter | Source | Meaning |
| --------- | ------ | ------- |
| Byzantine identity | `mod.rs` | Fixed participant index treated as byzantine. |
| Network fault count `d`, process fault count `c`, round budget `r` | `runner.rs` | Drawn per run; at least one of `c`, `d` is non-zero. |
| Process-fault recipient candidates | `sampling.rs` | Correct participants only (byzantine identity excluded). |
| Scope distribution | `scope.rs` | Biased toward `Any`; vote- and certificate-kind narrowing are less frequent. |
| Process action distribution | `sampling.rs` | Omit is sampled with small probability; certificate-scoped faults are always omit-only. |

## Extension Points

- Add a new vote or certificate kind by updating the scope-kind lists in `scope.rs`; the weighted sampler then covers it automatically.
- Add resolver-specific scopes by extending `MessageScope`, the scope sampler, and the resolver matching predicate.
- Change schedule density in `runner.rs`, not inside the fault data types.

## Related Specs

- [Fault Flow](../architecture/fault-flow.md) - how sampled schedules affect messages.
- [Runner Liveness](runner-liveness.md) - how schedules are installed and extended at GST.
- [ADR-001](../decisions/001-process-fault-model.md) - process fault model.

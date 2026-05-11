# Network Interception

## Purpose

Network interception is the synchronous half of ByzzFuzz fault injection. It attributes each outgoing message to its sender's current protocol round, applies the active network partition before GST, and hands off matching byzantine messages to the asynchronous injector.

## Key Files

- `consensus/fuzz/src/byzzfuzz/forwarder.rs` - per-channel outbound interception.
- `consensus/fuzz/src/byzzfuzz/intercept.rs` - shared interception data types, the GST gate, the sender-round cell, and the inbound round-tracking wrapper.
- `consensus/fuzz/src/byzzfuzz/scope.rs` - scope matching for process faults.
- `consensus/fuzz/src/byzzfuzz/observed.rs` - observed-value pool populated by interception sites.

## Core Types

| Type | Role |
| ---- | ---- |
| `Intercept<P>` | One captured byzantine outgoing message paired with one matching process fault. |
| `InterceptChannel` | Distinguishes the vote, certificate, and resolver channels. |
| `FaultGate` | Shared switch turned on at GST; disables network partition filtering. |
| `SenderViewCell` | Per-sender carrier of `rnd(m)`; see [Round Tracking](round-tracking.md). |

## Flow

```
outgoing send
    |
    | attribute to rnd(m) and observe protocol values
    v
network partition active at rnd(m)?
    |
    +-- pre-GST: drop recipients outside the sender's partition block
    +-- post-GST: no partition filtering
    |
    v
byzantine sender + matching process fault (view, scope, recipients)?
    |
    +-- enqueue Intercept for the injector
    +-- remove targeted recipients from normal delivery
    |
    v
deliver remaining recipients, or drop the message if none remain
```

Inbound messages flow through a round-tracking wrapper that folds each successfully decoded view back into the sender's cell.

## Related Invariants

- [Network Interception](../../invariants/invariants.md#network-interception) - partition totality, undecodable-byte handling, byzantine-only process interception.
- [Fault Flow](../../invariants/invariants.md#fault-flow) - network filtering precedes process interception.

## Configuration

| Parameter | Source | Meaning |
| --------- | ------ | ------- |
| GST gate | runner setup | Disables partition filtering after the fault phase. |
| Network fault schedule | [Fault Scheduling](../fault-scheduling.md) | Active partitions per view. |
| Process fault schedule | [Fault Scheduling](../fault-scheduling.md) | Targeted byzantine deliveries per view, scope, and recipient subset. Honest senders receive an empty schedule. |

## Extension Points

- Add a new outbound channel by mirroring the existing factories: attribute to `rnd(m)`, apply the partition before GST, then consult the byzantine process-fault schedule.
- Add a new scope variant in [`scope.rs`](../../../scope.rs) and extend the matching predicate used by each channel.

## Related Specs

- [Round Tracking](round-tracking.md) - how `rnd(m)` is maintained.
- [Forwarder/Injector Contract](../../contracts/forwarder-injector.md) - sync-to-async handoff.
- [Fault Flow](../../architecture/fault-flow.md) - per-message phase and ordering.
- [Process Injection](../process-injection/README.md) - async consumer of intercept items.

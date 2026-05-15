# Process Injection

## Purpose

Process injection is the asynchronous half of ByzzFuzz fault injection. It consumes intercept work items produced by the byzantine sender's interception sites and executes the work item's explicit process action: either a semantically mutated vote re-signed under the byzantine identity, or a deliberate omission.

## Key Files

- `consensus/fuzz/src/byzzfuzz/injector.rs` - async injector loop and per-channel dispatch.
- `consensus/fuzz/src/byzzfuzz/mutator.rs` - vote-mutation strategy (see [Mutator](mutator.md)).
- `consensus/fuzz/src/byzzfuzz/observed.rs` - observed-value pool that grounds mutations in seen protocol state.

## Core Types

| Type | Role |
| ---- | ---- |
| `ByzzFuzzInjector` | Async consumer of intercept items; emits replacement votes through a byzantine sender that bypasses the forwarder. |
| `ByzzFuzzMutator` | Vote-mutation policy supplied to the injector. |
| `Intercept` | Work item produced by interception (see [Network Interception](../network-interception/README.md)). |

## Flow

```
intercept item arrives
    |
    +-- ProcessAction::Omit:
    |       emit nothing (the original was already dropped at interception)
    |
    +-- ProcessAction::MutateVote on vote channel:
    |       decode the intercepted vote
    |       mutate semantically (see Mutator)
    |       re-sign with the byzantine identity
    |       send only to the already partition-filtered targets
    |
    v
loop continues until the intercept channel closes at end-of-run
```

Certificate and resolver process faults are omit-only by design (see [ADR-001](../../decisions/001-process-fault-model.md)). `ProcessAction::MutateVote` is only supported on the vote channel. The injector keeps the vote *kind* of the intercepted message (a notarize stays a notarize, etc.); only its content is mutated.

## Related Invariants

- [Fault Injection](../../invariants/invariants.md#fault-injection) - vote-kind preservation, byzantine-key re-signing, omit-only channel policy, target-set rules.
- [Fault Flow](../../invariants/invariants.md#fault-flow) - process faults remain active after GST.

## Configuration

| Parameter | Source | Meaning |
| --------- | ------ | ------- |
| Byzantine signing identity | runner setup | Keys used to re-sign mutated votes. |
| Mutator policy | [Mutator](mutator.md) | What constitutes a "near" mutation. |
| Bypass vote sender | runner setup | Path that emits replacement votes without re-entering interception. |

## Extension Points

- Adding a new omit-only channel requires extending the channel discriminator and `ProcessAction::supports_channel`.
- Adding a new vote variant requires per-variant mutation dispatch and re-signing in the injector.
- Swapping the mutation policy requires only providing a different `Strategy` implementation.

## Related Specs

- [Mutator](mutator.md) - vote-mutation strategy detail.
- [Network Interception](../network-interception/README.md) - upstream producer of intercept items.
- [Forwarder/Injector Contract](../../contracts/forwarder-injector.md) - sync-to-async boundary.
- [ADR-001](../../decisions/001-process-fault-model.md) - vote-only mutation rationale.
- [ADR-004](../../decisions/004-byzzfuzz-local-small-scope-strategy.md) - mutator strategy rationale.

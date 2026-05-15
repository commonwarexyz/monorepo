# Mutator

## Role

The mutator is the vote-mutation policy used by the injector: produce a semantically plausible alternative to an intercepted vote so the recipient processes it as a Byzantine equivocation rather than discarding it as malformed.

## Key Files

- `consensus/fuzz/src/byzzfuzz/mutator.rs` - `ByzzFuzzMutator` policy.
- `consensus/fuzz/src/byzzfuzz/observed.rs` - observed-value pool the policy draws from.

## Behavior

The mutator follows a two-tier strategy:

1. **Observed-value replay.** Prefer values that have actually appeared on the wire during the current run: payloads, parent views, full proposals at the current or other views, and notarized / finalized / nullified target views for nullify mutations. Replay keeps mutated messages internally consistent and temporally close to honest traffic.
2. **Nearby fallback.** When the pool has nothing usable or replay would yield the original message, edit the proposal's view, parent view, or payload in small steps around the latest observed status views and the intercepted message's own fields.

Per vote variant:

| Variant   | What the mutator changes                                                                 |
| --------- | ---------------------------------------------------------------------------------------- |
| Notarize  | The carried proposal (view, parent view, payload, or a combination).                     |
| Finalize  | The carried proposal, same options as Notarize.                                          |
| Nullify   | The nullified view.                                                                      |

Output is guaranteed to differ from the input. Vote *variant* is preserved (the injector re-signs the same kind of vote). Cryptographic content (signatures, public keys) is produced by the injector under the byzantine identity and is not the mutator's concern.

`Strategy` methods that do not correspond to vote mutation are unreachable in ByzzFuzz: certificate and resolver process faults are omit-only per [ADR-001](../../decisions/001-process-fault-model.md), and fault scheduling lives in [Fault Scheduling](../fault-scheduling.md).

## Error Handling

The mutator is pure logic over its inputs and the observed-value pool; it has no fallible operations.

## Related Invariants

- [Fault Injection](../../invariants/invariants.md#fault-injection) - mutation output differs from original; vote variant is preserved; mutations are semantically near the protocol's recent state.

## Related Specs

- [Process Injection](README.md) - consumer of the mutator.
- [ADR-004](../../decisions/004-byzzfuzz-local-small-scope-strategy.md) - rationale for a ByzzFuzz-local strategy distinct from the generic `SmallScope`.
- [ADR-001](../../decisions/001-process-fault-model.md) - rationale for vote-only mutation.

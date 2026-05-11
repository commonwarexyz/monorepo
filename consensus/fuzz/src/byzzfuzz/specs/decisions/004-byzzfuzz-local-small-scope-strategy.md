# ADR-004: ByzzFuzz-Local Small-Scope Strategy

## Status

Accepted

## Context

The `SmallScope` strategy says: when you mutate a field, don't replace it with an arbitrary value from its domain.
Replace it with a value that is close to the correct one — close in value, or close in time.

Close in value means numeric fields get incremented or decremented by a small constant (usually ±1).
A round number r becomes r-1 or r+1. A ledger sequence i becomes i+1. A view number v becomes v+1.
The mutated value lands inside the "watermark window" or the expected-interval check that the protocol
uses to discard wildly wrong messages, so the message gets processed by the deeper logic rather than dropped at the first sanity check.

Close in time means replacing a field with a value that was valid in an adjacent protocol round.
A proposal hash for the current round gets replaced with the proposal hash from the previous round.
The mutated message is internally consistent and looks plausible — it's just temporally misplaced.

The shared fuzz crate already has a generic `SmallScope` strategy in `consensus/fuzz/src/strategy.rs`,
but ByzzFuzz mutates actual intercepted votes after the network layer has selected a byzantine process fault.
The injector only has the intercepted vote plus observed protocol values gathered by forwarders and tracking receivers.
It does not use the generic strategy's network-fault, messaging-fault, resolver-byte, certificate-byte, or repeated-proposal paths.

## Decision

Use a ByzzFuzz-local `ByzzFuzzMutator` that implements `Strategy` only for the vote mutation paths the injector needs.
Proposal mutations first try observed-value replay from `ObservedState`,
then fall back to small local edits around nearby views, parent views, and payload bits.
Nullify mutations first try observed notarized, finalized, and nullified views, then fall back to nearby context values.
Unsupported `Strategy` methods remain unreachable because ByzzFuzz samples schedules in `sampling.rs` and `runner.rs`,
and certificate/resolver process faults are omit-only.

## Consequences

ByzzFuzz keeps the useful small-scope property of producing near-context mutations while also using values seen during the current run.
Mutation choices are guided by the deterministic runtime FuzzRng,
so libfuzzer input bytes influence both scheduling and mutation.
The implementation is intentionally narrower than the generic `SmallScope`,
which keeps certificate/resolver behavior aligned with ADR-002 and avoids coupling ByzzFuzz scheduling to the generic strategy API.

The cost is that there are now two small-scope implementations with different responsibilities.
Changes to the generic `SmallScope` do not automatically change ByzzFuzz mutation behavior,
so mutation-related updates must explicitly consider `consensus/fuzz/src/byzzfuzz/mutator.rs`.

## Alternatives Considered

- Reuse the generic `SmallScope` directly. Rejected because it does not consume the ByzzFuzz observed-value pool and includes scheduling and byte-mutation paths that ByzzFuzz intentionally does not use.
- Move observed-value behavior into the shared `Strategy` trait. Rejected because the observed pool is specific to ByzzFuzz interception and would widen the generic strategy contract for other fuzz modes.
- Generate completely random replacement votes. Rejected because local, observed-context mutations preserve useful semantic proximity and tend to exercise consensus edge cases more directly.

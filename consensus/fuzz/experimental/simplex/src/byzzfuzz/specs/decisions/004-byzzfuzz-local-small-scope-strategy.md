# ADR-004: ByzzFuzz-Local Small-Scope Strategy

## Status

Accepted

## Context

ByzzFuzz mutates real intercepted votes. Mutations should stay close enough to observed protocol state that the receiver processes them beyond basic sanity checks.

## Decision

Use a ByzzFuzz-local `ByzzFuzzMutator` for vote mutation only.

Prefer values observed during the run. Fall back to small local edits around nearby views, parent views, and payload bits.

Leave non-vote `Strategy` methods unreachable because certificate and resolver process faults are omit-only.

## Consequences

Mutations are local, observed-state aware, and guided by the deterministic runtime RNG.

Changes to the generic `SmallScope` do not automatically affect ByzzFuzz mutation.

## Alternatives Considered

- Reuse generic `SmallScope`. Rejected because it lacks the ByzzFuzz observed-value pool.
- Move observed-state behavior into `Strategy`. Rejected because it would widen the shared trait for one harness.
- Generate random replacement votes. Rejected because they are less likely to reach deep consensus logic.

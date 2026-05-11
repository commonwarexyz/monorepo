# ADR-001: Single Byzantine Index

## Status

Accepted

## Context

ByzzFuzz needs a stable byzantine actor for schedule sampling, messages selection for mutation, injector key selection, and invariant exclusion. The byzzfuzz harness uses a four-node setup and treats one identity as byzantine at the network layer while still spawning honest Simplex engines.

## Decision

Use index `0` to identify a byzantine entity (actor, sender, node)  (e.g., `BYZANTINE_IDX: usize = 0`) as the single source of truth. Process-fault receiver sampling excludes `participants[0]`, runner wiring gives only index `0` a process schedule and intercept sender, the injector signs with `schemes[0]`, and liveness/state extraction excludes index `0`.

## Consequences

The schedule and wiring are simple and deterministic. Logs can refer to one stable sender index. The harness explores Byzantine behavior from a fixed identity rather than all possible identities in one target.

Changing the byzantine identity now requires changing one constant, but code must still be audited for any assumptions about participant ordering.

## Alternatives Considered

- Sample the byzantine index per run. Rejected because it adds another fuzz dimension and makes schedule/log interpretation less stable.
- Treat all validators as potentially byzantine. Rejected because ByzzFuzz currently models a single process-fault sender and liveness needs a clear correct-reporter set.

# ADR-001: Process Fault Model

## Status

Accepted

## Context

ByzzFuzz needs one stable byzantine sender, clear process-fault actions, and precise fault attribution.

## Decision

- `BYZANTINE_IDX` is the single source of truth for the fixed byzantine identity.
- Process-fault receivers exclude `BYZANTINE_IDX`.
- Network faults match the sender's current `rnd(m)`.
- Process faults match the decoded view carried by the byzantine message. Undecodable messages do not match process faults.
- `ProcessAction::Omit` drops targeted delivery without replacement.
- `ProcessAction::MutateVote` applies only to vote messages, mutates the intercepted vote, and re-signs with the byzantine key.
- Certificate and resolver process faults are omit-only.
- Forwarders enqueue intercept work before removing targets from normal delivery. If enqueue fails, original delivery is preserved.

## Consequences

Old-view retransmissions can still be affected by current-round network partitions, but they do not inherit process faults for the later round.

The schedule model separates action (`ProcessAction`) from message matching (`MessageScope`), making unsupported cert/resolver mutation unrepresentable at the handoff boundary.

## Alternatives Considered

- Sample the byzantine index per run. Rejected to keep schedules and logs stable.
- Use sender `rnd(m)` for process faults. Rejected because it can fault the wrong semantic message view.
- Keep `omit: bool` and infer behavior from channel. Rejected because action and message scope are separate concepts.

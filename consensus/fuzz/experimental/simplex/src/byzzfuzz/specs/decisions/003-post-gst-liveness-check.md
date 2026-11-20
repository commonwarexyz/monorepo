# ADR-003: Post-GST Liveness Check

## Status

Superseded by [005](./005-post-gst-required-container-catch-up.md)

## Context

A safety-only run can miss schedules where progress stops after the bounded fault phase.

## Decision

Run a bounded fault phase first. If every non-byzantine reporter reaches `required_containers`, skip GST and run safety checks.

Otherwise, open `FaultGate`, keep Byzantine process faults active, and require each non-byzantine reporter to make post-GST progress within the liveness window.

## Consequences

The harness checks safety and liveness. Network partitions stop at GST, while Byzantine process behavior remains active.

## Alternatives Considered

- Always wait for `required_containers` without GST. Rejected because partition faults can make progress impossible.
- Disable all faults at GST. Rejected because it would stop testing Byzantine process behavior during the recovery period.
- Run only safety checks. Rejected because stalled progress is a core failure mode.

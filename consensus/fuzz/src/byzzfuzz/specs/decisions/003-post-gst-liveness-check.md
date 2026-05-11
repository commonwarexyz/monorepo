# ADR-003: Post-GST Liveness Check

## Status

Superseded by [005](./005-post-gst-required-container-catch-up.md)

## Context

A pure safety-oriented fuzz run can miss schedules where the protocol stops making progress after a bounded fault window.
ByzzFuzz also needs to check liveness property: network faults stop after GST, but the byzantine process can keep omitting,
arbitrary corrupting of the messages produced by the byzantine node or sophisticated equivocating.

## Decision

Run a bounded fault phase first. If every non-byzantine reporter reaches `required_containers`
from the input of this fuzz iteration, skip GST and go directly to safety checks using the invariants.
Otherwise, record each non-byzantine reporter's baseline (its last finalized view),
reach GST by opening `FaultGate`, prune dormant pre-GST process faults above the byzantine round,
append fresh post-GST process faults for future byzantine views, and require every non-byzantine reporter
to finalize above baseline within the post-GST window at least one container or reach `required_containers`
if they were not reached before.

## Consequences

The harness checks both safety and liveness in successful ByzzFuzz runs.
Network partitions stop at GST, but the Byzantine sender is still adversarial after GST and can equivocate, be silent or send arbitrary messages.
The post-GST timeout must be calibrated conservatively to avoid false liveness failures from honest retry and recovery timers.
Current code uses a large virtual-time window.

## Alternatives Considered

- Always wait for `required_containers` without GST. Rejected because adversarial network partitions can make progress impossible and cause unbounded waits.
- Disable all faults at GST. Rejected because it would stop testing Byzantine process behavior during the recovery period.
- Run only safety checks. Rejected because stalled progress is a core failure mode for BFT protocols under eventual synchrony.

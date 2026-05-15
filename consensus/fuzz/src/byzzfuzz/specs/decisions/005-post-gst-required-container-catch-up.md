# ADR-005: Post-GST Required-Container Catch-Up

## Status

Accepted

## Context

A reporter can miss `required_containers` before GST. ADR-003 only required one fresh post-GST finalization, which could pass without catch-up.

## Decision

Run a bounded fault phase first. If every non-byzantine reporter reaches `required_containers`, skip GST and run safety checks.

Otherwise, record each non-byzantine reporter's baseline, reach GST, prune process faults with `view > byzantine_rnd`, append fresh post-GST process faults for views above `byzantine_rnd`, and wait for each reporter's target.

The target is computed per reporter:

- If `baseline < required_containers`, the target is `required_containers`.
- If `baseline >= required_containers`, the target is `baseline + 1`.

If a reporter reaches `required_containers` between Phase 1 exit and baseline capture, its target is `required_containers + 1`; Phase 2 must observe fresh progress.

## Consequences

Lagging reporters must catch up to the fuzz input target. Reporters already at or above target must show fresh post-GST progress.

Network partitions stop at GST, but Byzantine process behavior remains active.

## Alternatives Considered

- Keep ADR-003's one-container post-GST progress rule for all reporters. Rejected because it can pass when Phase 1 ended far below `required_containers`.
- Always require `required_containers + 1` after GST. Rejected because reporters below the target should first be judged against the fuzz input's target, while reporters already at or above it need fresh progress relative to their own baseline.
- Disable all faults at GST. Rejected because it would stop testing Byzantine process behavior during the recovery period.
- Run only safety checks. Rejected because stalled progress is a core failure mode.

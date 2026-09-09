# Fault Flow

## Context

ByzzFuzz combines two fault classes: network partitions that route or drop messages between partition blocks,
and process faults that target the fixed byzantine sender's outgoing messages.
Correctness depends on the order of attribution, network filtering, process interception, GST, and invariant checking.

## Phase Model

```
setup
  |
  | sample (c, d, r)
  | sample network_faults and process_faults
  | spawn four honest validators with split forwarders
  | spawn injector for byzantine vote replacements
  v
phase 1: fault phase, 30s virtual time
  |
  | network faults active by sender rnd(m)
  | byzantine process faults active by decoded byzantine message view
  |
  +--> if every non-byzantine reporter reaches required_containers:
  |        skip GST and post-GST check
  |
  v
GST transition
  |
  | record non-byzantine finalization baselines
  | prune pre-GST process faults above byzantine_rnd
  | append post-GST process faults for future byzantine views
  | reach FaultGate
  v
phase 2: post-GST window, 360s virtual time
  |
  | network partitions pass through
  | byzantine process faults can still omit or mutate byzantine messages
  |
  +--> each below-target reporter must reach required_containers
  +--> each at-target reporter must finalize above baseline
  |
  v
safety checks
```

## Per-Message Fault Flow

```
outgoing message from sender i
    |
    v
decode channel view if possible
    |
    v
update SenderViewCell(i) with decoded view
    |
    v
read rnd(m) = SenderViewCell(i).get()
    |
    +-- before GST: apply network partition faults at rnd(m)
    |       drop recipients outside sender block
    |
    +-- after GST: skip network partition filtering
    |
    v
if i == BYZANTINE_IDX and process fault matches decoded view, receiver, action, and scope:
    |
    +-- enqueue Intercept for injector
    +-- on success, remove targets from original delivery
    |
    v
deliver residual original recipients, or drop if none
```

Inbound vote, certificate, and resolver receivers also decode views and update the sender cell, so `rnd(m)` reflects the maximum sent or received view for that validator.

## Related Invariants

- [Fault Flow](../invariants/invariants.md#fault-flow) - phase and per-message fault-ordering invariants.

## Anti-Patterns

- Applying process faults before partition filtering can inject messages across a partition that should have dropped the original.
- Disabling process faults at GST weakens the post-GST Byzantine adversary.
- Treating a message's encoded view as `rnd(m)` after the sender has already advanced breaks retransmission attribution.
- Counting the byzantine reporter in the post-GST liveness requirement makes a byzantine omission look like a correct-node liveness failure.

# Invariants

## Purpose

This is the central catalog of ByzzFuzz invariants. Before changing code or specs, check the affected invariant groups and keep every applicable invariant true.

## Layers

- `byzzfuzz::run` is the only public entry point used by `Mode::Byzzfuzz`.
- `BYZANTINE_IDX` in `mod.rs` is the single source of truth for the fixed byzantine identity.
- ByzzFuzz execution stays on the deterministic runtime and runtime traits.
- `FuzzRng` seeds deterministic runs from fuzz input bytes.
- `runner.rs` owns setup of validators, forwarders, tracking receivers, and the injector.
- Forwarders run synchronously in simulated p2p split-sender plumbing.
- The injector runs asynchronously and receives only `Intercept` work items.
- The observed-value pool is shared by extractors and the vote mutator.
- Every honest validator spawned in a ByzzFuzz iteration uses the same per-iteration certify policy; the policy is sampled before the run.
- Certify-policy outcomes are deterministic across reruns.
- The certify policy preserves quorum certification: variants that reject or withhold certification responses either do so with a small per-(view, payload) probability across validators, or target only the byzantine validator so the disabled certifier coincides with the existing adversary instead of removing a correct certifier.

## Fault Flow

- Network faults always run before process interception for each outbound message.
- Network faults always apply to every p2p channel at the matching view before GST.
- Process faults always apply only to the fixed byzantine sender.
- Process fault receiver sets always exclude the byzantine identity.
- Network faults are matched against the sender's current `rnd(m)`.
- Process faults are matched against the decoded view carried by the byzantine message itself.
- After GST, network partition drops are disabled and byzantine process faults remain enabled.
- Phase 2 liveness is checked only for non-byzantine reporters.
- Safety invariants run after successful phase completion.
- `run` always forces `N4F0C4`, `Partition::Connected`, and `degraded_network = false`.
- GST pruning retains pre-GST process faults with `view <= byzantine_rnd`.
- Post-GST appended faults start at `byzantine_rnd + 1`, saturated to at least `1`.
- Phase 2 requires every non-byzantine reporter below `required_containers` at GST to reach `required_containers`.
- Phase 2 requires every non-byzantine reporter already at or above `required_containers` at GST to finalize strictly above its baseline.
- The byzantine reporter is excluded from state extraction for final consensus invariant checks.

## Fault Scheduling
- The algorithm caps the number of fault rounds (`c` for process faults, `d` for network faults, `r` the number of target views)
  at small values.
- `BYZANTINE_IDX` is always `0`.
- Process-fault receiver candidates are all participants except `BYZANTINE_IDX`.
- Process-fault receiver sets are always non-empty when participants include any correct receiver.
- Network-fault views are sampled without replacement.
- Network-fault partitions always use non-trivial `SetPartition::N4` entries at indexes `1..=14`.
- `process_faults` and `network_faults` return empty schedules when their count or round budget is zero.
- Runner setup always forces at least one of `c` or `d` to be non-zero.
- Post-GST process faults always use `MessageScope::Any`.

## Network Interception

- Forwarders always expand `Recipients` against the full participant set and exclude the sender.
- Undecodable vote and certificate bytes still consult network partitions before GST using the current sender cell.
- Undecodable vote and certificate bytes never match process-fault scopes because the message kind is unknown.
- Resolver messages consult network partitions even when no resolver view can be decoded.
- Network partitions are total at their active view and apply to vote, certificate, resolver, and undecodable traffic.
- Process interception removes targeted recipients from the original delivery path only after the intercept work item is enqueued.
- Undecodable messages never match process faults, even if the sender's current round matches a process-fault view.
- Honest senders always receive an empty process-fault schedule and no intercept sender.
- After GST, partition filtering is skipped and process interception still runs for the byzantine sender.

## Fault Injection
- Structure-aware mutation is used rather than bit-level corruption.
- Subjective adversary scope (Byzantine sender + chosen recipient subset):
  Instead of "all messages get corrupted," the model is "one specific Byzantine process sends a tampered message
  to a specifically chosen subset of recipients in a specifically chosen round.
- Certificate and resolver process faults always omit targeted delivery.
- `ProcessAction::MutateVote` is supported only on the vote channel.
- Vote process faults always preserve the intercepted vote variant when they replace.
- Mutated votes are always signed with the byzantine scheme.
- Mutated votes are sent only to the already partition-filtered `Intercept.targets`.
- Mutation entropy comes from the deterministic runtime RNG.
- The injector loop exits when the intercept receiver closes.
- The injector ignores send errors from replacement vote delivery.
- Proposal mutation returns a value that differs from the original proposal.
- Local view edits use nearby values at distance one or two when arithmetic permits.
- Parent fallback for proposal view `0` or `1` always returns parent view `0`.
- Payload tweak flips exactly one bit.
- Random payload generation returns 32 bytes wrapped as `Sha256Digest`.

## Observability

- The log retains at most `LOG_CAP` lines.
- When the cap is reached, the oldest line is removed before appending a new line.
- `take` drains the buffer in insertion order.
- `clear` empties the buffer before each ByzzFuzz run.
- Successful ByzzFuzz runs drain the buffer so later runs start clean.
- The panic hook prints the log only when `CONSENSUS_FUZZ_LOG` is present in the environment.
- The panic hook runs before the previously installed hook.

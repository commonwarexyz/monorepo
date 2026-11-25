# Automatic Secure Code Review

Part of the [Security Policy](../SECURITY.md). Here "this file" means the whole policy.

## Severity Gates

- Critical or high requires concrete adversarial reachability through a
  supported integration boundary.
- Consensus-wide impact requires an in-model schedule that remains within the
  fault budget throughout.
- Configuration-dependent or integration-dependent claims are capped at medium
  unless the attacker can force the condition under a valid configuration.
- Trusted-local prerequisites, one-process recoverable failures, and documented
  misuse are normally capped at low.
- Remaining material uncertainty must lower confidence or severity; it must
  never be resolved by assuming the worst case.

### Stability Levels

A stability level changes severity only for compatibility.

- A wire or storage break in an item below BETA is not itself a finding:
  ALPHA allows breaking wire and storage changes, and BETA and above require
  a migration path.
- A separate, reachable safety, fund-loss, or remote-crash impact is rated
  normally, whatever the level of the item.

### Contract Hazards

A contract hazard is a class of finding separate from vulnerabilities. A
precondition is a contract hazard when all three hold:

1. It is unchecked: neither the types nor a run-time check enforce it.
2. It is easy to break in a supported integration.
3. Its breach causes safety loss, fund loss, or broad unavailability.

Report it under the label "contract hazard", not as a vulnerability. A
precondition that misses one of the three is not a contract hazard. The gates
above and "Panic Severity Calibration" still rate a vulnerability claim that
needs a broken precondition; this class does not raise that rating.

### Evidence

No failing test, no finding.

- A finding of either class, a vulnerability or a contract hazard, carries a
  failing test that shows it. A traced path without a failing test is not
  reported as a finding.
- A failing test is necessary, not sufficient: rules 1 and 3 under "Never
  Assume" apply to it.
- A disagreement with this file needs no failing test. It is reported under
  ["When You Think This File Is Wrong"](how-to-read.md#when-you-think-this-file-is-wrong),
  as a defect of the file, not as a
  vulnerability.

## Findings Validation Process Lessons

- For DKG, resharing, MPC, threshold-certificate, and threshold-VRF findings,
  distinguish protocol-produced artifacts from serialized or configured
  artifacts imported from outside the protocol. Before claiming validator or
  protocol impact from malformed output, trace every in-tree construction path
  that can create the artifact and verify whether the malformed state can be
  produced by normal protocol execution or adversarial protocol messages.
- Verify that every DKG implementation produces output where
  `public.total() == players.len()`, including observer, player-finalization,
  resharing, trusted-dealer, restart, and import paths.
- Parser, codec, or durable-state harnesses that synthesize malformed
  cryptographic artifacts validate only the import boundary they exercise. Do
  not generalize those results to live DKG, resharing, consensus, or validator
  behavior unless a concrete integration path accepts the same bytes as
  adversarial input under the component's documented contract.
- Treat trusted setup files, local operator configuration, and manually supplied
  bootstrap threshold state as deployer-local inputs unless source review or
  integration validation shows that peers, Byzantine participants, or explicitly
  untrusted storage can control them.
- For cross-component limits, do not treat one inner representation fitting its
  channel as proof that the integration is valid. Identify who controls every
  relevant limit, enumerate every production representation (including recovery,
  wrappers, and variable-size certificates), and derive the intended outermost
  bound. A peer-triggered failure under an incompatible trusted configuration
  validates a configuration or API defect, not adversarial reachability under
  the primitive's intended contract.
- For trusted-setup SNARKs and related proof systems, do not report "knowledge
  of the seed/trapdoor breaks soundness" as a vulnerability by itself. First
  prove that the code or a realistic integration exposes that toxic material
  across an adversarial boundary and that accepted forged proofs reach an
  executed security-bearing state transition; otherwise treat the issue as
  trusted-setup documentation or API-hardening guidance.
- For consensus certificate-admission findings, do not treat missing local
  ancestry backfill as a vulnerability by itself when the received certificate
  is valid under the quorum threshold and the protocol intentionally supports
  certificate-based catch-up. First prove that honest signers can produce the
  certificate without the required ancestry checks, or that a documented local
  reporting, delivery, or descendant-voting contract requires the receiver to
  materialize and replay the ancestry before trusting the quorum certificate.
- For consensus liveness and state-sync findings, use one shared dynamic fault
  ledger across discovery, catch-up, and voting. Count Byzantine, silent, stale,
  lagging, and still-syncing participants against the applicable `f` budget
  whenever they are outside the documented honest synced same-view set. Do not
  compose separately passing sink, persistence, and quorum tests unless one
  integrated schedule satisfies the same budget throughout. For `f+1` floor
  samples, prove that a selected stale floor remains possible despite the
  required current honest reply, retention window, synchrony lag bound, and any
  restart re-probe before treating a local stale-floor wait as reachable.
- For storage crash-safety reviews, distinguish an interrupted sync that may
  roll back from a later operation that can destroy a previously durable
  recovery fallback. In particular, append buffers with alternating checksum,
  footer, metadata, or commit slots must track in-flight async durability
  barriers until the protected slot is durable; a later rewrite must not
  preserve a not-yet-durable slot while overwriting the last durable one. Check
  `start_sync`, `sync`, `replay`, resize, and drop/late-await handle paths with
  out-of-order plain-write durability models.

## Top 10 Lessons Learned

1. Trace the complete production path, not just the suspicious sink.
   Many claims missed an earlier guard, wrapper, ordering guarantee, deduplication step, or later validation.
   Examples include acknowledgements already checking quorum before buffering and resolver subscribers being retained elsewhere.
   Lesson: document the full input → validation → state transition → sink path.
2. Respect documented API preconditions.
   Reproductions frequently passed duplicate signers, orphaned batches, invalid indexes, or reused resources after terminal errors. The panic or corruption mechanism was real, but the caller behavior was explicitly unsupported.
   Lesson: reproduce through a compliant public caller before reporting an implementation vulnerability.
3. Prove the actor actually controls the input across an intended trust boundary.
   Local configuration, trusted setup, application subscriptions, filesystem contents, and internal reporter channels were repeatedly treated as malicious peer input.
   Lesson: name the actor, capability, ingress, and ownership of every prerequisite.
4. Use one consistent quorum and fault-budget ledger.
   Several consensus schedules silently exceeded f, required mutually impossible quorum artifacts, or ignored what honest signers prove by producing a valid certificate.
   Lesson: enumerate every Byzantine, offline, stale, lagging, and unsynchronized participant throughout the entire schedule.
5. Do not substitute a preferred design for the documented invariant.
   At-least-once redelivery, lazy verification, certificate-based catch-up, cache eviction, and retained certification work were sometimes intentional semantics rather than defects.
   Lesson: state the source-backed invariant before judging observed behavior.
6. A harness can prove a sink without proving production reachability.
   Synthetic serialized DKG output, directly populated internal maps, inconsistent test configurations, incomplete fuzz oracles, and deliberately parked synchronization contexts produced convincing failures that normal construction could not produce.
   Lesson: construct state through production constructors and real actor transitions.
7. Validate the claimed impact after all recovery and fallback paths.
   Some mechanisms produced only the expected faulty-leader delay, local hardening concern, cache miss, or recoverable retry—not permanent liveness loss, safety failure, or remote DoS.
   Lesson: demonstrate the worst claimed observable outcome, not merely an intermediate bad state.
8. Use a supported configuration and composition.
   Findings depended on explicitly disabled merge-train states, incompatible roots, non-compliant custom electors, unsafe transports, or reporter compositions different from the shipped integration.
   Lesson: establish that the exact configuration is documented or constructible by supported APIs.
9. Pin and recheck the exact revision.
   Several reports described earlier code, code absent from the recorded PR head.
   Lesson: verify every cited function and defense at the recorded revision before triage.
10. Quantify resource exhaustion against enforced bounds.
    Allocation or retention was often bounded by a trusted codec cap, peer-set size, handshake reservation, resolver coalescing, or concurrency limit.
    Lesson: record attacker cost, amplification, default maximum, concurrency, cleanup, and measured outage.

## Denial-of-Service Review Checks

Use these cross-cutting checks when reviewing any boundary that accepts peer,
storage, application, resolver, certificate, vote, proposal, shard, frame, or
codec input. They apply to CPU, memory, file descriptors, tasks, channels,
timers, storage, and protocol slots.

- Every scarce resource consumed on behalf of untrusted input must have a
  documented bound that is enforced before allocation, spawning, buffering,
  decoding, cryptographic verification, reconstruction, storage writes, or
  forwarding to another queue.
- Length prefixes, advertised counts, shard counts, peer counts, batch sizes,
  ranges, and configuration fields from untrusted input must be capped by
  trusted local configuration before they size buffers, vectors, maps, Merkle
  structures, proof arrays, task sets, or recovery work.
- Allocation up to a trusted caller-provided limit, such as a `RangeCfg`,
  message-size cap, shard-size cap, or peer-set cap, is not by itself a
  vulnerability when that limit is enforced before allocation. Treat such
  candidates as hardening or invalid unless they prove the limit is
  attacker-controlled, absent on a concrete untrusted path, misderived or
  expanded beyond the documented budget, or tied to a measured outage under a
  realistic configured maximum.
- Backpressure is preferred over unbounded buffering. When a consumer is slow,
  the producer, peer, resolver request, subscription, or application callback
  must be slowed, rejected, retried under a bounded policy, or attributed for
  blocking rather than accumulated indefinitely.
- Loops that receive untrusted requests must not spawn one task per item without
  a concurrency bound, queue one item per request into an unbounded channel, or
  retain deferred work in a grow-only collection.
- Dropping excess work is safe only when the protocol explicitly permits loss or
  retry and the drop does not silently strand consensus progress, subscriptions,
  acknowledgements, durable state, or peer attribution.
- Deferred authentication, batching, lazy decoding, and resolver repair are
  acceptable only when all pre-authentication work is cheap or bounded by
  trusted policy, and offending peers remain attributable when invalid input is
  later detected.

## Review Priority Order

### 1. Simplex-Marshal-Resolver/P2P

This should receive most review time. Prioritize variant analysis around these
exact roots:

- Bind every artifact to the complete identity tuple: namespace, committee,
  epoch, view, parent view, parent payload, payload, and scheme.
- Compare optimistic, normal, recovery, replay, and resolver-delivered paths for
  missing checks.
- Ensure no vote, certificate, report, or network transmission becomes
  externally visible before required durable persistence.
- Treat finalization, nullification, certification, and ancestry-repair messages
  as non-lossy unless an independently guaranteed retry exists.
- Verify cancellation, timeout, replacement, and finalization clean up every
  request, subscription, and retained candidate.

### 2. Resource Admission and Backpressure

Review the whole path from authenticated ingress to completed work:

receive -> decode -> authorize -> verify -> queue -> mutate state -> respond

At every transition, ask whether the previous bound still applies. Common
historical mistakes include draining a bounded mailbox into an unbounded future
pool, limiting workers but not queued jobs, removing request deadlines before
validation finishes, and dropping protocol-critical messages because an internal
channel is full. Coding Marshal deserves special attention because shard size,
participant count, Reed-Solomon allocation, decoding work, and consensus quorum
availability interact.

### 3. QMDB and Journal Authentication

This is the broadest recurring defect family. Review it as one multi-component
state machine, not separate journals and Merkle trees.

The highest-value invariants are:

- Equal length never proves equal history.
- A cached root is not enough; readable operations and metadata must be bound to
  it.
- Failed sync attempts must not leave durable hybrid state.
- Root verification must precede publication and durable adoption.
- Recovery must authenticate component relationships, not merely each component
  independently.
- Pruning must preserve every object required by retained roots, floors, and
  restart plans.
- Async sync handles must prevent later writes from destroying the last durable
  fallback.

### 4. DKG and Stateful Transitions

- Epoch-boundary persistence and registration ordering.
- Split logs or retries that can combine different resharing generations.
- Boundary and anchor retention across pruning.
- Restart behavior between "artifact accepted," "durably committed," and "scheme
  registered."
- Whether imported artifacts have stronger trust assumptions than
  protocol-produced artifacts.

### 5. Cryptographic Verification Composition

Focus less on primitive arithmetic and more on how verification is composed:

- Batch deduplication keys must match the complete signed message.
- Independent invalid equations must not cancel without verifier-generated
  random weights.
- Transcript encoding must be unambiguous and domain-separated.
- Ordered/unordered or fixed/variable schemas must be authenticated as distinct
  domains.
- DKG and threshold artifacts must be traced through their actual construction
  paths before treating malformed synthetic values as reachable.

### 6. Panic Severity Calibration

- High: An authenticated Byzantine peer can reliably panic a consensus-critical
  actor or validator using protocol-valid traffic. If the attacker then
  withholds its own vote, crashing one honest validator can prevent a 3-of-4
  quorum.
- Medium: Malicious peer input, proof bytes, or explicitly untrusted storage can
  panic one node, but restart is effective or special state is required.
- Low: Authorized configuration, extreme local state, benign operator error, or
  corruption causes a recoverable one-node panic.
- Informational/invalid: Requires violating a documented caller precondition or
  constructing an internal state no supported path can create.

A panic alone is rarely Critical unless it is remotely repeatable across many
nodes or causes persistent crash loops, corruption, or a broader safety failure.

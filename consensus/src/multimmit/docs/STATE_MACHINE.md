# Multimmit architecture and state machine

This document is the implementation contract for Multimmit's in-process state machine. The formal
protocol remains the Multimmit paper, arXiv:2607.21021v2. The implementation additionally follows
the application-custody contract below and the author's amendment to two Section 4.2 presentation
choices. Although version 2 defines a V-QC over exactly `n - f` messages, an implementation may
retain any complete attributed set in `n - f..=n` and must use every retained designated vote for
tip extraction. Although version 2 `ProposeChains` sends the selected V-QC unconditionally, a
proposal may omit that exact object when it was already forwarded. A distinct selected same-view
V-QC still accompanies the proposal; forwarding a different V-QC for the view does not satisfy that
requirement.

The paper is authoritative for protocol semantics. This guide is authoritative for the in-process
ownership, application-custody, durability, recovery, and resource contracts. `PROPERTIES.md` indexes
the in-scope consensus and marshal properties and their focused, deterministic, static, and
assumption evidence.
These Markdown documents are the persistent source of truth; rendered visual explainers are
derivative.

The state machine is synchronous and has one owner. Runtime actors and workers execute capabilities;
they never choose protocol state.

## Ownership

`Engine` is the only public signing entry point. Like Simplex, its configuration takes an `Automaton`
and a `Relay` directly; Multimmit adds no application supertrait, binding codec, lease protocol, or
bootstrap API. The traits remain concerned only with opaque digests.

Engine opens and replays consensus storage before accepting ingress. On recovery, Core derives the
bounded set of retained producer headers whose application payloads can still support a signing
reservation, publication obligation, DA-authorized suffix, proposal/vote, or successor transition.
Engine reissues ordinary `Automaton::verify(context, payload_digest)` requests for exactly those
application payloads before constructing the actors. The request may remain pending while the
separate application/relay path makes the payload and its producer-chain parent available. A `true`
result asserts application validity and availability of both objects. This call is exclusively an
application validity/availability fence, never a certificate-fetch path; consensus does not use it
to fetch either object. A `false` result or closure contradicts recovered consensus state and
terminates recovery.

`Automaton` never receives a V-QC, nullification, L-QC, leader block, or other consensus proof. Those
objects are decoded and verified by consensus, and missing view proofs are fetched through Resolver.
No producer body or application-storage metadata enters consensus state.

Fresh startup uses the same Engine path with no recovery requirements. As documented by the module's
security contract, durable signing history belongs to the validator identity; an operator must not
reuse an active-epoch key after losing its consensus store. This operational precondition is not
turned into a second application protocol.

`Batcher` owns hostile bytes, peer attribution, per-peer/per-lane bounds, decoding, canonical
artifact identification, and batched cryptographic verification. Decode and identification run as
bounded strategy jobs whose completions retain the authenticated peer. `Resolver` owns transport,
retry, and peer choice for view-proof fetches.
`Voter` owns the epoch lifecycle and one private `CoreState`. `CoreState` is the sole authority for
admission order, producer-header facts, DA choices, views, leader finality, durable events, signing
reservations, publication obligations, retention, and snapshots.

Application block bodies, body codecs, retrieval, dense total-order extraction, durable delivery,
and application acknowledgements are outside the consensus state machine. The Multimmit marshal
owns their protocol-facing custody and ordering. Consensus owns opaque application digests, signed
producer headers, DA evidence, protocol-constant leader blocks, tip commitments, and finalized leader
proofs. Reporter notifications confer no finality or delivery authority. Accepted producer headers
and L-QCs, plus locally reconstructable history openings, are best-effort latency hints. Consensus
never waits for marshal or records marshal custody; marshal repairs missed activity through its
resolver and backfill path.

A producer header carries two different digests with different owners. Its `commitment` is the opaque
application-body digest passed to `Automaton`. Its protocol identity is the hash of the complete
canonical header `(epoch, chain, height, parent, commitment)`; that is the value passed to `Relay`
and implemented by the complete transaction block's `Digestible` contract. Parent links,
`BlockRef`s, DA anchors, safe/finalized tips, broadcast lookup, and tip-history commitments always
use that header identity. Keeping these domains separate makes a producer fork unambiguous even when
the application legitimately returns the same body digest in different producer contexts.

The Multimmit marshal is the executable owner of the paper's dense `Ord`/`Emit` transition.
Consensus emits authenticated L-QCs, accepted producer headers, and available history openings
through the same best-effort `Activity` stream. Marshal validates each exact identity, persists useful
hints, and resolves missing openings or blocks by authenticated digest. Dense delivery and
application acknowledgement never enter consensus storage.

```text
application-owned producer bodies
        | propose / verify opaque digest
        v
signed producer headers + DA evidence       (consensus-owned)
        | positions, extensions, tips
        v
leader blocks -> V-QCs -> finalized leader chain + tip commitments
        |
        | best-effort authenticated Activity stream
        v
Multimmit marshal
        | resolve history/bodies + Ord/Emit + durable delivery cursor
        v
dense application delivery
```

## Canonical state

All maps and queues below are bounded by the resource rules in this document.

- **Identity:** epoch, namespace, ordered committee, producer ownership, local role, protocol limits,
  and process generation.
- **Durability:** the next event cursor, the greatest acknowledged contiguous cursor, staged event
  ranges, durable signing reservations, stable publication obligations, and the latest admissible
  snapshot cursor.
- **Admission:** monotonically increasing observation identities; decoded artifacts in observed,
  verifying, rejected, dependency-blocked, or admitted state; and exact async job identities.
- **Producer chains:** per-chain certified anchor, retained signed headers, verified/custodied facts,
  one local DA-vote choice per `(chain, height)`, DA-share pools, certificates, and the contiguous
  locally authorized suffix above the certified anchor.
- **Local production:** the local certified anchor, greatest durably chosen header, a bounded
  volatile FIFO of prepared descendants, at most one live proposal request, pacing state, and the
  exact pending signing/publication state.
- **Views:** the current view; per-retained-view proposal, vote/novote/nullify stance, authenticated
  exit proof, V-QC candidates, selected anchor, and first-forwarded V-QC/nullification facts.
- **Leader finality:** sticky per-leader vote pools selected by observation order, monotonically
  increasing finalized tips and leader floor, retained L-QC evidence, and the current tip commitment.
- **Service metadata:** bounded lane order, weights, byte/item accounting, permits, wake flags, and
  retry deadlines. This state is discardable and rebuilding it cannot change normalized protocol
  state.

There is no second semantic state in an actor, worker, scheduler, journal owner, or reporter.

### One-way control flow

The voter is a runtime shell around `CoreState`. Its select loop has one event arm. Runtime readiness
is converted to a typed `RuntimeEvent`, handled once, and admitted through a named Core transition.
Core returns typed capabilities; collaborators execute them and return correlated completions through
the same event path. A rotating readiness cursor chooses only among simultaneously ready runtime
sources; it carries no weights, cached admission state, or protocol work. Once one source wakes the
voter, the shell probes the other ready protocol lanes. When lanes compete, it stages ready inputs up
to their Core-owned ceilings before Core drains its weighted service cycle to `Idle` or
`YieldRequired`; a solitary lane gets one turn and returns to the runtime. Non-protocol control work
ends the admission burst, so inspection, publication, checkpoint, prune, and heartbeat service remain
prompt. `YieldRequired` resets Core's bounded service cycle before it resumes.

```text
peer bytes / timers / storage / application / crypto
                         |
                         v
                 bounded RuntimeEvent
                         |
                         v
              voter runtime-event handler
                         |
                         v
                  CoreState transition
                 /          |          \
          reject/no-op   domain event   typed capability
                              |               |
                              v               v
                       journal append   bounded collaborator
                              |               |
                              v               |
                    coalesced start_sync      |
                              |               |
                              +------> correlated completion
                                           (next RuntimeEvent)
```

No capability writes semantic state, no actor mirrors a Core domain, and no completion is interpreted
without its Core-owned generation/job/subject identity. Producer and leader work remain visibly
separate at the Core API:

```text
producer chain inputs                    leader chain inputs
---------------------                    -------------------
producer_wake                            leader_timer_fired
producer_build_completed                 leader_resolution_completed
producer_validated                       leader_nullification_recovered
producer_timer_fired                     leader_vqc_aggregated
producer_da_recovered                    leader_lqc_aggregated
             \                            /
              \                          /
               +---- one atomic reducer +
                     (cross-domain rules)
```

The domains meet only inside the reducer where the protocol requires an atomic decision, such as a
leader proposal reading DA-certified producer anchors or finalized leader votes advancing producer
tip floors. There is no asynchronous handoff or intermediate cross-owner state.

### Public lifecycle

Applications construct the ordinary `EngineConfig` with an `Automaton`, `Relay`, and `Reporter`, then
start the four network planes. Recovery is selected from the engine's own consensus store; there is no
application bootstrap API. The engine derives its committee identity from the role-appropriate
scheme instead of accepting a second identity field that could disagree with the signing material.

```rust,ignore
let engine = Engine::new(
    context.child("multimmit"),
    EngineConfig {
        profile,
        scheme,
        automaton,
        relay,
        reporter,
        strategy,
        blocker,
        partition_prefix,
        mailbox_size,
    },
);
let mut running = engine
    .start(data, consensus, certificates, resolver)
    .await?;
if !running.ready().await {
    return Err("engine stopped during startup".into());
}

let inspection = running.inspect().await;
running.abort();
running.join().await;
```

The `log-multimmit` example is the compiling consensus reference. `Inspection` and `serve(view)` are
diagnostic/proof-serving APIs; neither is an application delivery stream. A deployment may attach
marshal directly as its `Reporter` without changing consensus durability or progress.

### Marshal service lifecycle

Marshal is split by ownership rather than run as one protocol loop:

- `Catalog` is the sole mutable owner of finalized archives, temporary multi-archives, shared
  producer-block custody, dense output rows, and the compact checkpoint. Producer bodies and their
  compact metadata use one global append coordinate across every chain, while chain-local indexes
  retain exact ancestry and pruning semantics. Mutations and required archive syncs complete before
  checkpoint high-water exposes them. Mutable storage failure is fatal.
- The resolver adapter owns bounded exact-key fetches, checks Catalog custody before contacting a
  peer, and serves only Catalog-admitted LQCs, tip-history openings, and complete producer blocks
  through `commonware-resolver`. Producer wire keys contain only chain and header digest to avoid
  redundant bytes; request completion still compares the complete `BlockRef`, including height.
- `Synchronizer` walks recursive history commitments and producer ancestry through disk-backed
  scratch journals, applies the paper's offset-major horizontal and final sweeps, and asks Catalog
  to commit bounded batches of adjacent history openings and dense rows. Producer ancestry is
  serial within each chain and concurrent across chains up to `backfill_concurrency`; a stalled
  chain therefore does not block another chain. Once exact block references are known, missing
  bodies share one global pool at the same bound. Fetch completion order cannot affect output order
  because each result retains its canonical output position. The ancestry scheduler also verifies
  state-sync frontiers. Synchronizer owns no finalized archive handle.
- `Delivery` fills a configurable window with consecutive committed `OutputIndex` entries and
  reports each complete transaction block with an `Exact` acknowledgement. It retires only the
  ready FIFO prefix and asks Catalog to sync that prefix's high-water once. A crash before that
  sync may repeat the unpersisted window and cannot skip it.
- `Router` validates request identity, joins accepted headers with exact complete blocks from
  buffered ingress, and owns bounded command, job, ready, and missing-block sets. Under pressure, a
  later unique header retires the oldest missing-block subscription before admission. Malformed
  hints are request-local.

The service supervisor owns child lifecycles only. Catalog, Router, resolver, Synchronizer, and
Delivery are five independent state machines; storage or required-child failure stops all five.

The public `Mailbox` implements best-effort `Reporter<Activity>`. It also supports durable block
submission, eager buffered complete-block broadcast, local get, network fetch, local subscription,
authenticated floor installation, generation-bound pruning, and compact progress inspection. A
subscription waits for local admission and does not start network work; a fetch does.

Finalized LQCs, history openings, and dense producer blocks use independently configurable prunable
or immutable archives. Unfinalized same-view and same-position candidates use prunable
`MultiArchive`; successful commits and floor installation advance their prune frontier internally.
Application pruning is explicit through `Mailbox::prune(Prune::new(generation))`. Immutable final
archives retain old values and treat pruning as a no-op.

`Start::Genesis` opens or resumes the namespace at protocol genesis. `Start::Floor` seeds only an
empty namespace and trusts the caller to authenticate the application snapshot, signature, and
generation that justify the supplied floor. Runtime state sync uses `install_floor`, which verifies
  the L-QC, its opening, non-regressing ordering frontiers, and internal sweep consistency before durably installing a new
generation. Delivery resumes strictly after the application-owned emitted frontier.

## Transition system

Each external stimulus invokes one named synchronous transition. A transition either rejects without
a durable event, mutates only discardable service metadata, or applies one ordered sequence of domain
events through the same reducer used by replay. It returns typed capability commands and never a
heterogeneous effect list.

### Startup and recovery

1. Open the checkpoint and journal without starting child actors or registering ingress.
2. Decode the newest complete version-0 checkpoint and replay its contiguous journal suffix.
3. Reject wrong epoch/profile data, noncanonical data, gaps, conflicting duplicates, invalid retained
   artifacts, or any snapshot/event sequence that violates the invariants below.
4. Derive the sorted, duplicate-free, resource-bounded `(Context, payload_digest)` application
   recovery set from retained producer headers in normalized state. Certified-only roots, leader
   blocks, V-QCs, nullifications, L-QCs, fresh state, and observer state never enter this set.
5. Before constructing the actors, Engine issues normal application-payload `Automaton::verify`
   calls. A `true` result asserts that the payload and producer-chain parent are available; a
   separate application/relay path owns any retrieval needed to make that true. Consensus neither
   fetches them nor routes consensus proofs through `Automaton`. Do not release dependent
   signing/publication authority, arm timers, or register ingress before every required result is
   `true`; `false` or closure is a recovery error.
6. If replay restored at least one checkpoint interval of journal events, Engine first syncs that
   verified state as the replacement checkpoint, then rolls and prunes the covered journal. A
   crash before the checkpoint sync replays the old suffix; a crash after it uses the replacement
   checkpoint. Actors still have not started, so no new generation or authority can race this cut.
   This keeps repeated crashes after a recovery-generation sync but before its acknowledgement
   from extending the durable suffix indefinitely.
7. Construct and start the network actors. Their bounded ingress queues may begin filling, but the
   voter still owns the sole Core instance and has not entered its live event loop.
8. During gated voter startup, advance the process generation through the ordinary Core transition,
   rebuild discardable scheduling and async-job metadata, issue any recovered proof-resolution
   demand, drive the resulting journal work through its exact durability acknowledgement, and
   reissue live durable publication obligations.
9. Reconstruct the resolver's volatile prune and retained-proof custody projection, submit the
   initial producer wake, signal readiness, and only then admit queued runtime events to Core through
   the live voter loop.

No signing, producer work, timer, resolver request, or ingress is possible before step 5 succeeds.
After step 7, ingress may be received into bounded actor queues, but it cannot affect protocol state
or authority until steps 8 and 9 complete.

### Observation and admission

1. `observe` assigns an observation identity before asynchronous verification.
2. Structurally duplicate, out-of-window, over-capacity, or context-invalid input is rejected without
   a domain event. An admitted verification request records generation, job, ordered tickets, artifact
   identities, and expected count.
3. `verification_completed` first validates the complete correlation. A stale generation or retired
   job is a no-op. Any mismatched live identity/count/order is an invariant error and consumes nothing.
4. Verdicts are applied in original observation order. Invalid artifacts release their reservations;
   valid artifacts enter direct type-specific admission. Missing authenticated dependencies become
   level-triggered resolver demand, not a speculative protocol fact.
5. Admission atomically updates every affected DA, view, finality, durability, and retention index.
   No handoff object or component snapshot exists between those updates.

Worker completion order may change latency but cannot change sticky selection, transcript choice,
finality, signing authority, or durable bytes.

### Producer construction

1. A wake is eligible only when the local role owns a producer chain, work/pacing policy allows it,
   no build is live, and the next height above the prepared tail remains at most `d` above the
   certified anchor.
2. The application receives only protocol context and the parent digest. A successful `propose`
   returns a commitment and binds the proposer to verifying that exact `(context, commitment)`; it
   does not confer durability or signing authority.
3. The completion must match generation, request, context, parent, and expected height. Decline or
   cancellation authorizes no header and is retried only by normal level-triggered work/pacing.
4. Success appends the exact header to a bounded volatile prepared FIFO and requests application
   verification for its custody. Descendant construction may proceed immediately from the prepared
   tail, so body preparation and durability overlap.
5. Local `verify(true)` means the exact payload is permanently valid, locally available, and
   reconstructible after a crash. Completions may arrive out of order, but only the contiguous
   custodied FIFO prefix becomes eligible for signing. `false`, cancellation, or a live correlation
   mismatch cannot authorize a header; an unsigned prepared suffix is discarded on restart.
6. Each eligible header stages one durable producer-header signing reservation. The signature may be
   computed in parallel with journal I/O, but neither signature nor header may leave private process
   memory until the exact covering durable prefix is acknowledged.
7. After acknowledgement, signing completion self-admits the header and installs stable block-relay
   and header-publication obligations. Relay acceptance may order the first attempts, but volatile
   transport feedback never retires either obligation. Only a later durable semantic successor,
   such as a covering DA certificate, retires an obligation.

### Application verification and DA voting

1. A correctly signed remote header may enter verification once its exact parent is certified or
   has entered the application pipeline. Each chain dispatches lower heights first, preventing
   descendants that arrive early from occupying the capacity needed by their missing parent;
   requests and completions may overlap out of height order after that anchor exists. The application
   receives only context and the opaque digest. `verify(true)` means the parent and candidate are
   durably reconstructible and the candidate is permanently valid. Temporary absence keeps the
   request pending; `false` is permanent invalidity.
2. A verified/custodied header is non-authoritative until its chain path is contiguous from the
   greatest certified anchor. Earlier local DA choices on that path must already exist.
3. In increasing height order, `reserve_da_vote` may choose at most one header per `(chain, height)`
   and may not cross a gap, an unavailable predecessor, or depth `d` above the certified anchor.
4. The exact choice is staged durably before threshold-share signing. The share is exposed only after
   its covering prefix is acknowledged and is sent only to the producer that owns the chain.
5. `admit_da_share` retains the first valid share per participant and exact header. At `n - 2f`
   distinct shares the producer may request recovery of the canonical subset.
6. `da_recovered` accepts only the exact live job/transcript. The certificate is durably admitted and
   published, advances the certified anchor monotonically, retires covered block/share publications
   and obsolete validation work, and then re-evaluates the next contiguous suffix.

These rules implement the paper's one-vote-per-height, contiguous-path, and depth-`d` DA conditions.

### Proposal

1. The current scheduled leader proposes at most once. It selects a V-QC from the greatest view it
   holds. Within one view it prefers the certificate with the larger complete message transcript,
   then applies canonical byte/identity tie-breaking.
2. For each chain, the base is its highest held DA certificate above the selected V-QC tip, otherwise
   that tip's explicit `(digest, height)`. The proposal includes at most `d` consecutive locally
   DA-voted payload digests above the base.
3. The leader block includes the next tip commitment `H(previous_commitment, Tips(selected_vqc))`.
4. The exact leader block, selected parent V-QC, and whether that parent still needs transmission are
   one durable signing/publication choice. The parent is included with the proposal exactly when the
   receiver cannot rely on an earlier transmission of that same V-QC; selecting an updated V-QC
   requires transmitting it.
5. A proposal becomes externally visible only after the exact signing reservation is durable.

### Direct vote

1. A first-route proposal is eligible only when exactly one leader block from the scheduled leader is
   observed, the referenced earlier V-QC is authenticated, every skipped view has a nullification,
   chain anchors are valid relative to `Tips(V-QC)`, proposal paths are structurally well formed and
   depth bounded, and the tip commitment is correct.
   A receiver must not reject that exact valid parent merely because it already holds a V-QC from a
   higher earlier view. Greatest-held selection is leader policy, not an additional validity rule.
2. If the local stance is neither voted nor nullified, `reserve_vote` freezes positions and extensions
   from the local contiguous DA-vote history. Positions are the greatest consecutive proposed prefix;
   each extension is the longest consecutive path of at most `e` DA-voted blocks from that position.
3. The full vote subject and local stance are durably reserved before signing or exposure.
4. A current-view V-QC may authorize the paper's second voting route without repeating first-route
   validity checks. Its `2f + 1` designated votes prove that correct voters validated the proposal.

### Timeout and post-vote nullification

1. On the current timeout, a validator with no vote and no prior nullification atomically reserves a
   novote plus nullify share. Both subjects and the stance change share one durable event and are
   released only by its exact acknowledged prefix.
2. A validator that voted never emits a novote. It may reserve only a nullify share after observing
   messages from at least `2f + 1` distinct participants, each a nullify/novote or a vote for another
   leader block. The complete non-support witness is frozen before the reservation.
3. Nullify shares recover a nullification from exactly `2f + 1` distinct participants. Completion is
   correlated to the exact canonical transcript and admission is durable before publication.

### V-QC and view exit

1. A V-QC candidate accounts for between `n - f` and `n` distinct view messages, at least `2f + 1`
   of them votes for one designated proposal. Every committee member appears at most once across the
   disjoint designated-vote, other-proposal-vote, and novote categories. Votes for other proposals
   and novotes remain fully attributed; no constituent vote may be abridged.
2. Sticky transcript selection follows observation order, not verification or aggregation completion.
   The first eligible local aggregation freezes exactly `n - f` messages so view exit is not delayed.
   If more sticky messages become eligible, later jobs freeze strict supersets through at most `n`;
   every job receives one exact immutable transcript and correlation identity.
3. Only the first newly observed or assembled V-QC for a view is independently forwarded. A stronger
   same-view certificate remains durable candidate parent state. If a later proposal selects it, the
   proposal attaches that exact certificate because the receiver cannot rely on the earlier,
   different V-QC. If that exact selected certificate was already forwarded, the author amendment
   permits omitting the duplicate attachment.
4. A valid V-QC or nullification for the current view supplies one authenticated exit. If a V-QC
   arrives while the local validator has neither voted nor nullified, the second-route vote is reserved
   before the view advances.
5. `advance_view` increments exactly one view, resets only current-view volatile stance/timer state,
   retains the selected exit proof and required parent evidence, arms the next timer, and schedules the
   next leader if local. Future proofs are consumed one view at a time.
6. An admitted covering L-QC may raise the authenticated signing/view floor and derive the equivalent
   V-QC anchor without fetching its parent history. If no V-QC for that current or future view has
   yet fulfilled the first-new forwarding duty, the derived V-QC does so before the floor advances.
   A different V-QC that already fulfilled the duty is not forwarded again; the exact derived anchor
   is instead attached if a later proposal selects it. This is state synchronization for agreement,
   not dense producer ordering. The re-anchored engine then resumes ordinary proposal, production,
   and finality transitions in the same epoch.
7. Catch-up liveness uses the paper's total fault bound. Crashed or unavailable participants count
   toward `f`; with at most `f` faults, the remaining correct quorum can produce the covering L-QC.
   Above `f`, exact exits still retire at the bounded retention floor and no additional witness or
   recovery branch attempts to restore progress outside the protocol model.

### Leader finality

1. For each retained leader block, retain the first valid vote per participant. Pools are sticky by
   observation order and may continue growing after `n - f`.
2. At `n - f`, finalise the leader immediately from the pool; portable L-QC aggregation is independent
   and not a prerequisite.
3. The paper's set `S` is unbounded, but this implementation retires an unfinished pool with its
   bounded view window. It therefore does not preserve every local-finality opportunity created by
   arbitrarily late pre-GST votes. Keeping all such pools would be unbounded, while blocking view
   progress at capacity would let one Byzantine signer stall the epoch. Under the `<= f` model,
   post-GST convergence reaches a correct-leader view and a covering L-QC through the ordinary path.
4. Per chain, the finalized proposal position is the `(3f + 1)`-th greatest position. Extension carry
   applies only when that position equals the proposed tip and at least `n - f` pool votes count for
   the extension. Pool settledness uses `beta + (n - |pool|) <= f`.
5. Finalized leader and chain-tip floors are monotone. Re-running finality as the pool grows may extend
   the same prefix but may never retract or choose an incompatible tip.
6. L-QC aggregation and admission freeze the exact vote transcript. A late valid covering L-QC may
   advance floors but may not change prior sticky choices.
7. Every admitted L-QC and locally reconstructable history opening may be reported as idempotent,
   best-effort activity. Reporter feedback never gates consensus. Marshal persists useful hints and
   resolves an unavailable opening by the digest authenticated in the L-QC; later L-QCs, startup
   reconciliation, and resolver backfill repair missed activity.
8. Consensus does not materialize, store, or acknowledge the paper's dense `Emit` stream. Marshal
   owns recursive history storage and all later ordering and delivery state.

`Tips(V-QC)` uses every designated vote carried by that V-QC and remains exactly the paper's drop-`f`
position rule followed by a branch-aware `2f + 1` extension carry. A larger accepted V-QC is never
truncated to `n - f` before extraction. Finalized tips remain the drop-`3f` rule plus
unanimity/pool threshold only above a fully supported proposed tip. Tip commitments remain
consensus-critical and make historical tip sequences verifiable without replaying historical V-QCs.

The paper's Section 5.3 results divide at the consensus/marshal boundary:

- Lemma 13 (membership finality) says that a block strictly above the proposal base and counted by at
  least `3f + 1` votes of an L-QC has no incompatible certifiable block. Core's drop-`3f` position
  rule, fully-supported extension rule, and one-DA-vote-per-height invariant own that threshold.
- Theorem 3 (block inclusion, hence censorship resistance) is conditional: every correct processor
  must DA-vote the correct producer's block and the intervening path before its view vote, and the
  block must be at most `e` above `Tips(Q)`. Under those hypotheses, the block survives every
  same-view safe-tip extraction. Consensus finalizes its chain tip by the next finalized leader even
  when the current leader omits it; marshal realizes the theorem's dense ordering.
- Corollary 3 (chain-local finality) fixes one chain's contribution through its finalized tip and
  forbids later views from adding, removing, or reordering those heights. Consensus owns the
  monotone finalized tip and recursive history commitment. Marshal resolves authenticated openings,
  producer ancestry, and bodies, then durably executes the dense `Ord` and `Emit` realization.

The exact executable evidence and its limitations are indexed in `PROPERTIES.md`. In particular,
the cross-certificate algebra matrix exercises the membership threshold and compatibility of safe
and finalized tips, while the Byzantine-leader deterministic scenario exercises one schedule that
satisfies Theorem 3's hypotheses. Marshal's deterministic system harness exercises the complete
L-QC-to-dense-delivery path. None of these finite tests is a proof of the paper result.

### Persistence and publication

1. A semantic transition applies ordered domain events locally and stages one exact contiguous cursor
   range. Replay applies those same events and no actor-side projection.
2. The journal owner appends ranges in order. It may coalesce adjacent appended ranges into one
   `start_sync`, but an acknowledgement always names the exact greatest contiguous durable cursor.
3. A forwarded certificate is structurally paired with its exact persistence directive. The voter
   submits the directive, installs resolver custody, and only then releases that independently
   verifiable publication; it does not wait for fsync.
4. Core accepts only an acknowledgement covering its next expected staged prefix. Old duplicates are
   no-ops; a gap, wrong generation, wrong range, or mismatched live completion is an invariant error.
5. `durable_acknowledged` returns the exact signing releases, publication installations, proof
   retentions, and publication retirements newly authorized by that prefix. The actor never scans
   domain events to infer them.
6. Egress retries immutable bytes under a stable effect identity. Send success and feedback are
   volatile; only a durable typed semantic successor retires the obligation.
7. Exit-proof obligations from different views may coexist in any completion order and may outlive
   compacted forwarding history until a higher exit replaces them. They remain bounded by the
   durable outbox and have no second per-view family ceiling.
8. Producer-header and DA-vote signing rows are an integrity mirror of durable signing effects. The
   durable outbox is their sole capacity owner; the mirror uses that same ceiling and adds no hidden
   `chains * (d + 1)` admission rule.
9. Mutable append, sync, checkpoint, or prune failure is fatal to the engine and storage instance.

Before a transition that can stage durable work begins, Core reserves command and completion capacity
for every journal range that transition can produce. An urgent transition may close the current batch
and create a successor batch, but it cannot partially mutate state and then discover that only one of
those commands fits. A full journal lane delays admission; it is never converted into a fatal protocol
invariant after the transition has started.

Private CPU/application work may overlap an append or sync only when it cannot expose new local
authority. This is the only permitted persist/work overlap.

### Snapshot and journal lifecycle

1. When checkpoint work is due, Core closes admission of new durability-producing transitions after
   the current staged prefix. Already bounded ingress and private async work may continue, but results
   that would stage authority wait in their reserved completion slots. This fence guarantees a cut
   under continuous load rather than waiting for accidental global quiescence.
2. Only Core may mint `CheckpointCut`, and only at its acknowledged cursor after that staged prefix
   drains. The cut owns the complete durable semantic state at that cursor.
3. The journal owner treats a cut opaquely. It rolls first, so post-cut authority can append to a
   retained new section while the replacement checkpoint writes and syncs. Once the checkpoint is
   durable, Core briefly fences new durability-producing transitions until that post-cut suffix is
   idle, admits pruning of the covered sections, and immediately reopens authority while pruning
   runs behind the serialized journal owner.
4. Every journal record above the cut is retained, including data already synced by storage but not
   yet consumed by Core before the cut was minted.
5. A crash before checkpoint durability recovers the previous checkpoint plus journal. A crash after
   checkpoint durability recovers the new checkpoint plus records above it. Pruning cannot remove the
   only durable copy of an event.
6. Checkpoint and journal readers enforce the configured encoded-byte ceiling before allocating or
   decoding. A checksum-valid but malformed, noncanonical, or oversized payload is a recoverable open
   error, never an unbounded allocation or panic.
7. The version-0 schema is the initial format. Any deliberate future wire or storage change follows
   the crate's stability and migration policy.

The serial owner copies the profile-bounded durable state when it mints the immutable cut. Snapshot
encoding and physical checkpoint storage then run on a shared runtime worker. Core itself never moves
across the async boundary, so a checkpoint cannot create a second semantic owner or admit a
completion against a temporarily absent state machine.

## Async boundaries and correlations

Only these operations cross an async boundary:

| Capability | Required identity | Core-owned decision |
|---|---|---|
| batch verification | generation, cohort, ordered tickets, artifact IDs/count | observation order and admission |
| application propose | generation, build request, producer parent/context, payload digest | volatile prepared header identity |
| application verify | generation, validation or build request, exact header, payload digest | whether a producer header/DA choice may be reserved |
| sign/recover/aggregate | generation, job, exact subject/transcript | subject and canonical transcript |
| journal sync | ordered cursor range and durable prefix | releases and retirements |
| checkpoint/prune | immutable `CheckpointCut` | durable state and cut cursor |
| resolver | generation, requested view, exact proof kind | dependency demand and proof admission |
| timers | generation, exact view/production position | timeout/pacing transition |
| publication | stable effect identity and durable obligation | bytes, audience, and semantic retirement |

Cancellation only releases the matching volatile reservation. A stale completion cannot release a
current permit or mutate protocol state. Live mismatches are fatal invariant violations rather than
retries. Correct completions may arrive in any order. As in Simplex's proposal and certification
slots, the exact live slot decides whether a late result remains useful; an async worker never owns
view order, producer-chain order, or a separate semantic capacity limit.

Bulk signature verification, aggregation, recovery, and recovered-artifact verification run through
the configured `commonware_parallel::Strategy`. The voter does not perform those computations on its
serial event-loop thread. Publication retry work is selected from an indexed deadline set in a fixed
per-turn quantum; equal saturated deadlines rotate rather than favoring low effect identities, and
immutable encoded transmission batches are shared across attempts. Scalar progress needed for
control and tracing is updated with transitions, while the allocating per-chain metrics projection
is refreshed on the heartbeat.

## Invariants

The private core test harness checks these after every transition, replayed event, restore, durable
acknowledgement, and retention pass.

1. Observation and event cursors are monotone; every pending completion references one live exact
   reservation of the same generation.
2. At most one local signing subject exists for each DA `(chain,height)`, view vote/novote/nullify
   slot, leader proposal slot, and aggregate job.
3. `acknowledged <= staged <= next`; staged ranges are contiguous; no authority exposure floor exceeds
   acknowledged authority. Every staged range has pre-reserved journal command and completion capacity.
4. Every publication obligation has one stable effect identity and exact durable owner; there are no
   ownerless outbox rows or transport-owned retirements.
5. Certified and finalized tips, current view, signing floor, and leader finality floor never rewind.
6. Every DA-authorized suffix is contiguous from a certified anchor, has length at most `d`, and has
   custody plus prior DA choices for every predecessor. Speculative verified headers do not count.
7. Proposal positions and extensions are derived only from contiguous local DA-vote history; proposal
   paths are at most `d` and vote extensions at most `e`.
8. Every retained semantic object is reachable from a live view, floor, dependency, job, signing
   reservation, publication obligation, or recovery proof. Retirement removes nothing reachable.
9. Every queue, map, byte total, job class, finality pool, resolver waiter set, and work quantum stays
   within its validated bound. A mirror is bounded by the authoritative owner it mirrors, never by a
   smaller estimate that legal completion reordering can exceed.
10. Consensus snapshots and public diagnostics contain digests, headers, certificates, leader facts,
    and tip commitments only—never application bodies, body-store state, dense-order cursors, delivery
    cursors, or application acknowledgements.
11. Activity reporting owns no protocol state: feedback, closure, or loss cannot delay a transition,
    retain an artifact, or add a durability event. No application body or recursive history backlog
    is copied into consensus durability.

Marshal checks a separate invariant set after every durable commit and recovery:

1. Every archived object matches its exact key: L-QC ID, recursive history commitment, or full
   canonical producer-header `BlockRef`. A body commitment is never a producer-block identity.
2. The selected finalized LQC, history index, ordered frontier, emitted frontier, committed output,
   and acknowledged output are one canonical checkpoint. Every frontier is chain ordered and
   monotone within its generation.
3. Dense outputs are contiguous by `OutputIndex`; each index names one complete transaction block.
   History is processed oldest first, and each horizontal sweep is offset major across chains.
4. Evidence, openings, blocks, and output rows are durable before checkpoint exposure. An ordinary
   checkpoint carries its exact remaining temporary-cleanup obligation, which startup completes
   before serving reads. Delivery advances only through a contiguous FIFO prefix whose `Exact`
   acknowledgements all resolve, and Catalog syncs that prefix's high-water.
5. A runtime floor instead first persists one bounded intent containing the exact verified LQC, opening,
   target checkpoint, and cleanup floors. Catalog completes that intent before serving reads,
   keeps it durable while both finalized archives sync and temporary data is pruned, then publishes
   the target checkpoint by replacing the intent with one ready state. Delayed generation-bound
   prune requests cannot affect a newer floor.
6. Resolver fetches recheck Catalog before peer work. Deliveries are bounded, generation scoped,
   request-key exact, decoded under protocol limits, and independently verified before Catalog
   admission. Buffered broadcast is only an eager complete-block cache.
7. Every actor mailbox, router job, resolver request/subscriber set, block waiter, dense commit batch,
   and in-memory delivery window has a configured finite ceiling. Unbounded history and ancestry
   walks spill to prunable scratch archives.

## Steady-state resource proof

Let `n` be committee size, `f = floor((n - 1) / 5)`, `d` pipeline depth, `e` extension bound, and
`W` view retention. The validated profile derives every remaining ceiling before startup.

- Exactly `W + 1` current/past views are retained, plus the configured bounded future-view distance.
  Advancing a view runs one reference-safe retirement pass even if leader finality is stalled.
- Each producer has at most `d` authority-bearing uncertified headers above its certified anchor and
  each vote has at most `e` extension headers. Speculative validation is separately permit bounded.
- Artifact, future-artifact, dependency-waiter, finality-pool, forwarded-certificate, and publication
  outbox counts use `ResourceLimits`; profile construction rejects a bound too small for its retained
  live set.
- Exit-proof obligations share `max_outbox_effects`; compacted forwarding history is not their
  capacity owner. Every producer-header or DA-vote signing row owns one durable signing effect, so
  the signing mirror also shares `max_outbox_effects`. Neither path introduces a second, tighter
  capacity edge.
- Verification, application, signing, recovery, and aggregation jobs each consume a class-specific
  permit plus reserved completion capacity before becoming mandatory. Remote application work has
  `min(d, max_verification_batch)` slots per producer and that width times the producer count
  globally; per-chain rotation prevents one producer from monopolizing queued validation.
- Batcher and voter lanes have fixed item and byte ceilings. Each batcher lane derives an item and
  byte share for each of `f + 1` fault domains, so at most `f` replaying peers cannot consume the
  correct peer's admission share; active peer queues, planes, and data chains rotate service. Decode
  and canonical-identification jobs are bounded, and their saturation stops network intake while
  control and completions retain service. Fixed work quanta force a runtime reschedule.
- Public inspection and proof-serving queries use bounded admission or backpressure. They cannot enter
  a reliable mailbox's unbounded overflow, and a caller that does not drain replies retains no state
  inside the engine.
- Resolver job controls remain exact FIFO barriers. Adjacent `Retain` and `Prune` updates collapse to
  the final custody projection between those barriers, so a slow resolver does not retain every
  historical copy of a monotone retention frontier. Core emits live prune frontiers directly and
  supplies one `(retired_view, proofs)` projection when the resolver starts; the voter does not infer
  resolver ownership from metrics.
- Resolver custody shares each retained proof and caches its canonical response bytes after the
  first serve. Proof decoding, uncached encoding, and local completion materialization run through
  the configured execution strategy in one pool bounded by that strategy's manual parallelism.
  Saturating the pool pauses only resolver-handler intake; custody controls, best-effort queries,
  worker completions, and the P2P engine lifecycle remain serviceable.
- Journal command count and unsynced bytes are bounded. Fsync coalescing covers the oldest contiguous
  prefix; urgent signing work behind a sync becomes the next prefix rather than creating an unbounded
  waiter chain. A reducer poll emits at most one cursor-contiguous journal range and runs only when
  the voter has one command slot, so capacity exhaustion cannot strand a partially handed-off prefix.
- Checkpoint cadence bounds replay work and whole-section pruning bounds durable journal growth.
  The bounded cut and pre-prune fences are serviced ahead of new durability-producing transitions,
  so a continuously busy engine cannot starve compaction; checkpoint sync and pruning themselves run
  behind live post-cut authority.
- Stable publication retries retain one bounded durable row per live obligation, not one row per
  attempt. An indexed deadline and rotating tie cursor select a fixed attempt quantum without a full
  outbox scan or starvation at a saturated clock. Recovery re-reports the bounded retained-ready
  artifact set as best-effort activity before protocol service resumes. Reporter activity retains no
  state and cannot backpressure consensus.
- Dependency availability is retired by provider and consumer reachability for every artifact kind,
  including leader dependencies. Parent retirement preserves dependencies of retained leaders;
  marshal resolves an unavailable opening directly by its authenticated commitment.
- Recovery enforces encoded checkpoint and journal byte ceilings before allocation or decode; invalid
  durable input fails startup without constructing actors.
- Marshal uses bounded actor mailboxes, router jobs, resolver requests, subscriptions, and commit
  batches. Delivery holds at most `max_pending_acks` waiters; the application owns the corresponding
  complete blocks. History and ancestry walks use segmented disk scratch and discard segments as
  they are consumed, so catch-up distance does not become RAM use.
  Sparse ordering sweeps visit only real slots, and resolver completion indexes exact keys instead
  of scanning unrelated pending requests.
- Catalog admits ready producer blocks in bounded cross-chain waves. One active custody cut and one
  trailing cut coalesce body and metadata durability without delaying unrelated catalog commands.
  A cut always establishes complete custody before its block can satisfy synchronization; no timer
  or peer-controlled delay decides when durability begins.
- Catalog batches a selected L-QC, history openings, and dense outputs into one commit and syncs each
  mutated archive once before one checkpoint sync. That checkpoint also carries the exact ordinary
  cleanup marker, so a crash between publication and temporary pruning needs no second hot-path
  metadata sync. Prunable block archives append compact authenticated references and synchronize the
  already-written producer custody once; immutable block archives append complete blocks and reclaim
  temporary candidates after checkpoint publication. Catalog-issued custody tokens remove body
  rereads from this publication path. Exact duplicate L-QC and history custody avoids no-op archive
  syncs. A ready FIFO acknowledgement prefix updates only the checkpoint and requires one metadata
  sync. Runtime floor installation adds one bounded intent sync before its parallel finalized-archive
  syncs; idempotent recovery consumes that intent before ordinary synchronization. Floor cleanup
  durably advances chain-local frontiers before physical reclamation. Shared pending-block custody
  is divided into bounded append segments: each retained segment prunes through its first live row,
  and segments with no live row are deleted. A stalled chain therefore cannot pin later segments it
  does not inhabit. Cold segments are opened transiently, and cleanup touches only segments that
  lost rows in bounded concurrent waves, so work and file-descriptor use do not grow with the
  manifest. Cleanup never scans finalized history. No consensus certificate is expanded into its
  constituent votes for marshal.
- Final archives may grow with chain history. Temporary L-QC/history rows, immutable block candidates,
  and scratch storage advance internal prune frontiers after commit or floor installation. Prunable
  finalized blocks retain their authoritative bodies in producer custody until explicit application
  pruning reclaims both rows together; immutable finalized archives intentionally retain their
  complete prefix. The prunable archive backend indexes retained rows in memory, so its index grows
  with still-needed rows and contracts as the application prune frontier advances.
- Each namespace checkpoint binds the independently selected L-QC, history, and block archive
  backends; reopening with a different layout fails before any actor starts.

Therefore consensus memory and marshal's active actor/scratch working set plateau across arbitrarily
many views and finalized blocks, provided configured external network/application/storage capabilities
continue making the progress required by the protocol. Temporary marshal disk usage and its backend
index are bounded by advancement of the finality-driven prune frontier; if that frontier stalls, rows
that may still be needed remain retained. Finalized archives grow with retained chain history. A
stalled async dependency consumes its pre-reserved bounded actor slot; it cannot create new active
work beyond those storage rows.

The progress claim assumes at most `f` faulty participants in total, counting crashed and unavailable
participants. Beyond that bound the engine preserves its resource ceilings and fail-closed safety
checks, but it does not retain extra history or add recovery states solely to regain liveness.

Because application-validity/custody is an implementation fence in addition to the paper's DA
predicate, liveness also assumes that every block from a correct producer eventually becomes durably
available and returns `verify(true)` at every correct validator. Pending or permanently false results
from a correct producer are outside the paper-derived liveness claim.

## Test model

The synchronous evidence surface is private to the voter-owned Core. Core tests call production
transitions and inspect one normalized semantic projection. An attached-runtime parity test sends the
same observations through the runtime-event path and compares that projection, checking that the
voter is a delegating shell rather than a second machine. Deterministic voter and Engine tests use
real mailboxes,
stores, application attachment, timers, resolver, egress, and network actors. Focused recovery tests
derive the exact retained producer/DA payload union and exclude certificate-only roots and observers.
Engine tests hold ordinary payload verification pending before actor construction, reject false or
closed verification, keep proposal work behind that gate, then release verification and confirm ready
recovery state. The retention-gap cluster test resolves a covering L-QC, re-anchors the old epoch, then
produces and finalizes another block on every chain. Durability and checkpoint tests exercise exact
append/sync acknowledgements, semantic publication replacement, live post-cut checkpoint I/O,
oversized durable records, malformed checkpoint slots, and process-abort recovery. Injected mutable
storage failures terminate the owner and the storage instance is discarded.

Marshal unit tests cover pure ordering and ancestry, exact-key resolver behavior and adversarial
delivery boundaries, temporary multiplicity, both finalized archive backends, checkpoint codecs,
Catalog commit/reopen/install, segmented scratch, and Exact delivery. Its reusable deterministic
harness starts the real Catalog, resolver, synchronizer, delivery, buffered broadcast, and
application Reporter together. End-to-end scenarios cover local offset-major delivery, remote
terminal-LQC/two-history-link/block backfill, malformed request isolation, configured pending-ack
saturation and FIFO refill, crash redelivery until durable acknowledgement, authenticated floor
continuation, and generation pruning across all-prunable, all-immutable, and mixed archives. A
production integration attaches the marshal mailbox as Multimmit's Reporter, then restarts both
Engine and marshal and checks
cursor recovery without duplicate delivery. Another full-service case reports an L-QC without its
local opening and verifies exact history and block backfill before delivery.
Public wire keys and the changed Multimmit durable types have conformance fixtures.

Protocol, lifecycle, network, crash, recovery, and resource scenarios use the deterministic runtime.
Network coverage includes seeded runtime schedules with 200 ms one-way latency and 150 ms jitter,
continuous multi-chain production, and stable finality/resource assertions. Scripted certificate
tests additionally deliver future exits out of order across recovery. Focused Core replay tests remain
the exact evidence for durable transition predicates that cannot be observed through a transport
retention API.
The only Tokio tests in the Multimmit actors are narrow execution-strategy integration checks: they
use a real threaded Rayon pool to demonstrate that CPU work does not occupy a single async executor
thread and that worker panic is reconciled. They assert no protocol schedule or crash property; the
deterministic strategy intentionally executes inline and therefore cannot establish physical thread
placement.

Every executable test covers a finite schedule or input matrix. Static ownership and absence claims
remain code-inspection obligations. Liveness additionally depends on post-GST delivery, continuing
runtime/storage service, and eventual `verify(true)` for correct producer blocks at every correct
validator; a deterministic scenario supplies those conditions but cannot establish them for a
deployment.

[`PROPERTIES.md`](PROPERTIES.md) maps each safety, liveness, and resource property to its sole owner,
legal mutators, durable witness, exact focused and deterministic tests, and invariant predicate.

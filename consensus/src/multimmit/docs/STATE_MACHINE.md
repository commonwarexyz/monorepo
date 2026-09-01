# Multimmit state machine

This document specifies the consensus core's state, transitions, recovery sequence, invariants, and
resource bounds. The [Multimmit specification](https://arxiv.org/abs/2607.21021v5) defines the
protocol, and
[`PROPERTIES.md`](https://github.com/commonwarexyz/monorepo/blob/main/consensus/src/multimmit/docs/PROPERTIES.md)
maps its results to the implementation and its evidence. Module documentation owns the runtime
structure: `machine/mod.rs` describes the core and its capabilities, `actors/voter/mod.rs` the
runtime topology, and `marshal/mod.rs` block custody and delivery.

Protocol authority is synchronous and has one owner. Runtime actors and workers execute typed
capabilities; they never choose durable protocol state.

## Terminology

Protocol terms follow the specification.

- **n, f:** committee size and fault bound, with `f = floor((n - 1) / 5)`, so `n >= 5f + 1`.
- **GST:** global stabilization time, after which every message between correct participants
  arrives within `delta`.
- **delta:** the specification's bound on message delay after GST. The view timeout must cover
  `2 * delta` plus local admission and verification time.
- **Producer chain:** one committee member's chain of transaction blocks. A transaction block is a
  signed header naming an opaque application commitment.
- **Leader block:** the scheduled leader's proposal for one view: one anchored path per producer
  chain and the next tip commitment.
- **DA (data availability):** a validator's DA vote is a threshold share asserting that it holds and
  validated a producer block. `n - 2f` shares recover a DA certificate for that chain position.
- **Certified anchor:** a producer chain's highest DA-certified block.
- **d:** pipeline depth (`pipeline_depth`), the most blocks a producer chain may extend above its
  DA-certified anchor and the longest proposal path.
- **e:** extension bound (`extension_bound`), the most blocks a vote may carry per chain above its
  proposal position. `e = 0` disables extensions.
- **W:** view retention (`Tuning::view_retention`), the number of views retained below the current
  one.
- **Vote, novote:** a vote signs a leader block's positions and extensions. A novote is an
  attributed statement, sent with a timeout, that the signer did not vote in the view.
- **Nullify, nullification:** a nullify is a timeout share. `2f + 1` shares recover a
  nullification, which lets the view be skipped.
- **V-QC (view quorum certificate):** `n - f..=n` attributed votes and novotes for one view,
  including a designation quorum. It authorizes leaving the view and selects safe tips.
- **Designation quorum:** the `2f + 1` votes for one leader block inside a V-QC.
- **L-QC (leader quorum certificate):** `n - f` votes for one leader block. It finalizes the leader
  block and one tip per producer chain.
- **Tips:** per-chain positions. A V-QC selects safe tips; leader finality fixes finalized tips.
- **Core:** `CoreState` and the `Machine` it drives, the single owner of protocol state.
- **Capability:** a typed command the core returns for the voter to execute (`Capability`).
- **Lane:** one of the core's bounded input queues (`Lane`), distinct from an ingress lane.
- **Budget, credit:** the work one core turn may spend before the voter yields to the runtime.
- **Generation:** the counter of process lifetimes. A completion issued under an earlier generation
  is stale.
- **Cursor, batch:** a cursor is a journal event position. A batch is a run of contiguous events
  persisted together; its acknowledgement (`BarrierAck`) names the greatest durable cursor.
- **Snapshot, checkpoint:** a snapshot is the durable state at an acknowledged cursor with nothing
  staged; the checkpoint is its stored copy, and the journal is cut at its cursor.
- **Outbox, obligation:** the durable outbox holds signing requests and publications under stable
  effect identities. A publication obligation stays queued until a later durable fact discharges
  it.
- **Custody:** the application's `verify(true)` promise that a payload is valid, locally available,
  and reconstructible after a crash. Marshal body custody is a separate mechanism.
- **Chain plane:** the voter task that validates one producer chain's blocks and offers its
  eligible DA-vote runs. Each validator runs one per producer chain.
- **DA recovery task:** the producer's task that pools DA shares for its own chain and assembles
  certificates.
- **Network plane:** one of the engine's network channels, distinct from a chain plane.

## Canonical state

All maps and queues below are bounded by the resource rules in this document.

- **Identity:** epoch, namespace, ordered committee, producer ownership, local role, protocol limits,
  and process generation.
- **Durability:** the next event cursor, the greatest acknowledged contiguous cursor, staged event
  ranges, durable signing reservations, stable publication obligations, and the latest admissible
  snapshot cursor.
- **Admission:** monotonically increasing observation identities; decoded artifacts in observed,
  verifying, rejected, dependency-blocked, or admitted state; and async job identities.
- **Accountability:** authenticated producer, leader, vote, novote, and candidate DA-share claims
  within the live retention window, plus the bounded set of identities already quarantined.
- **Producer chains:** per-chain certified anchor and its DA certificate, retained signed headers,
  verified and custodied facts, one local DA-vote choice per `(chain, height)`, and the contiguous
  locally authorized suffix above the certified anchor.
- **Chain planes:** one per producer chain, holding volatile authenticated block copies,
  application-validation jobs, derived eligibility, and a read-copy of the chain's durable DA
  choices. The DA recovery task holds the producer's volatile share pools. Both are rebuilt from
  Core state after restart and cannot create authority.
- **Local production:** the local certified anchor, greatest durably chosen header, a bounded
  volatile FIFO of prepared descendants, at most one live proposal request, pacing state, and the
  pending signing and publication state.
- **Views:** the current view; per-retained-view proposal, vote/novote/nullify stance, authenticated
  exit proof, V-QC candidates, selected anchor, and first-forwarded V-QC/nullification facts. Live
  views start at one; view zero holds only the synthetic genesis leader and each producer chain's
  height-zero genesis commitment.
- **Leader finality:** sticky per-leader vote pools selected by observation order, monotonically
  increasing finalized tips and leader floor, retained L-QC evidence, and the current tip commitment.
- **Service metadata:** bounded lane order, weights, byte/item accounting, permits, wake flags, and
  retry deadlines. This state is discardable and rebuilding it cannot change normalized protocol
  state.

There is no second durable or authority-bearing protocol state in an actor, worker, scheduler,
journal owner, chain plane, DA recovery task, or reporter.

## Transition system

Each input (`Input`) runs one synchronous transition. A transition either rejects without a durable
event, mutates only discardable service metadata, or applies one ordered sequence of durable changes
through the same function replay uses. It returns typed capabilities and never a heterogeneous
effect list.

No capability writes authoritative state. Derived actor state is generation-scoped and rebuilt from
Core-owned facts, and no completion is interpreted without its Core-owned generation, job, or subject
identity. Producer-chain inputs, such as `Input::ProducerWake`, `Input::BlockBuilt`, and
`Input::BlockCustodied`, stay distinct from leader-chain inputs, such as `Input::TimerFired` and
`Input::ResolutionCompleted`. The two domains meet only inside one transition where the protocol
requires an atomic decision, such as a leader proposal reading DA-certified producer anchors or
finalized leader votes advancing producer tip floors. There is no asynchronous handoff or
intermediate cross-owner state.

### Public lifecycle

Applications construct the root `Config` with a scheme, the epoch's genesis, the operator's
`Tuning`, and an `Automaton`, `Relay`, and `Reporter`, open the engine, then start it on the four
network planes. `Engine::open` validates the configuration before touching storage: it pairs the
scheme's protocol parameters with the genesis, takes the node's role from the scheme's key
material, and derives every resource bound from the tuning, so the scheme, protocol, and role cannot
disagree. It then recovers from the engine's own consensus store and builds every actor without
spawning any; `Engine::start` only spawns them. There is no application bootstrap API.

```rust,ignore
let engine = Engine::open(
    context.child("multimmit"),
    Config {
        scheme,
        genesis,
        tuning,
        automaton,
        relay,
        reporter,
        strategy,
        critical_strategy,
        blocker,
        partition_prefix,
        page_cache,
        mailbox_size,
    },
)
.await?;
let mut running = engine.start(Planes {
    data,
    consensus,
    certificates,
    resolver,
});
running.ready().await?;

let inspection = running.inspector().inspect().await;
running.abort();
running.join().await?;
```

The `log-multimmit` example is the compiling consensus reference. `Inspection` is a diagnostic API,
not an application delivery stream. A deployment may attach marshal directly as its `Reporter`
without changing consensus durability or progress.

### Marshal service lifecycle

Marshal implements the Section 6 two-pass ordering variant. Consensus emits authenticated L-QCs,
accepted producer headers, and available history openings through one best-effort `Activity`
stream; marshal validates each identity, persists useful hints, and resolves missing openings or
blocks by authenticated digest. Dense delivery and application acknowledgement never enter
consensus storage. `marshal/mod.rs` lists the actors; each owns its own store:

- `Catalog` owns finalized archives, temporary multi-archives, shared producer-block custody, dense
  output rows, and the compact checkpoint. Producer bodies and their compact metadata use one
  global append coordinate across every chain, while chain-local indexes retain ancestry and
  pruning semantics. Mutations and required archive syncs complete before the checkpoint's
  high-water exposes them.
- `Backfill` owns bounded fetches by key, checks Catalog custody before contacting a peer, and
  serves only Catalog-admitted L-QCs, tip-history openings, and complete producer blocks through
  `commonware-resolver`. Producer wire keys contain only chain and header digest to avoid redundant
  bytes; request completion still compares the complete `BlockRef`, including height.
- `Synchronizer` walks recursive history commitments and producer ancestry through disk-backed
  scratch journals, applies the deterministic offset-major sweeps in two passes (proposed blocks,
  then extensions), and asks Catalog to commit bounded batches of adjacent history openings and
  dense rows. Producer ancestry is serial within each chain and concurrent across chains up to
  `backfill_concurrency`, so a stalled chain does not block another chain. Once block references
  are known, missing bodies share one global pool at the same bound. Fetch completion order cannot
  affect output order because each result retains its canonical output position. The ancestry
  scheduler also verifies state-sync frontiers. Synchronizer owns no finalized archive handle.
- `Delivery` owns the acknowledgement cursor. It fills a configurable window with consecutive
  committed `OutputIndex` entries and reports each complete transaction block with an `Exact`
  acknowledgement. It retires only the ready FIFO prefix and syncs that prefix to its cursor once.
  A crash before that sync may repeat the unpersisted window and cannot skip it.
- `Promoter`, with immutable block retention, owns the immutable body archive and copies committed
  bodies into it.
- `Router` validates request identity, joins accepted headers with complete blocks from buffered
  ingress, and owns bounded command, job, ready, and missing-block sets. Under pressure, a later
  unique header retires the oldest missing-block subscription before admission. Malformed hints are
  request-local.

The service supervisor owns child lifecycles only. A storage or required-child failure stops every
actor.

The public `Mailbox` implements best-effort `Reporter<Activity>`. It also supports durable block
submission, eager buffered complete-block broadcast, local get, network fetch, local subscription,
authenticated floor installation, generation-bound pruning, and compact progress inspection. A
subscription waits for local admission and does not start network work; a fetch does.

Finalized L-QCs, history openings, and dense producer blocks use independently configurable prunable
or immutable archives. Unfinalized same-view and same-position candidates use prunable
`MultiArchive`; successful commits and floor installation advance their prune frontier internally.
Application pruning is explicit through `Mailbox::prune(Prune::new(generation))`. Immutable final
archives retain old values and treat pruning as a no-op.

`Start::Genesis` opens or resumes the namespace at protocol genesis. `Start::Floor` seeds only an
empty namespace and trusts the caller to authenticate the application snapshot, signature, and
generation that justify the supplied floor. Runtime state sync uses `install_floor`, which verifies
the L-QC, its opening, non-regressing ordering frontiers, and internal sweep consistency before
durably installing a new generation. Delivery resumes strictly after the application-owned emitted
frontier.

### Startup and recovery

1. Open the checkpoint and journal without starting child actors or registering ingress.
2. Decode the newest complete version-0 checkpoint and replay its contiguous journal suffix.
3. Reject wrong epoch/profile data, noncanonical data, gaps, conflicting duplicates, invalid retained
   artifacts, or any snapshot/event sequence that violates the invariants below. Each journaled view
   advance carries the retention floor it applied, and replay applies that floor, so a restart under
   a smaller view retention replays the writer's decisions and compacts at the next live exit.
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
8. During gated voter startup, advance the process generation through `Input::RecoveryComplete`,
   rebuild discardable scheduling and async-job metadata, issue any recovered proof-resolution
   demand, drive the resulting journal work through its durability acknowledgement, and reissue
   live durable publication obligations.
9. Reconstruct the resolver's volatile prune and retained-proof custody projection, submit the
   initial producer wake, signal readiness, and only then admit queued runtime events to Core through
   the live voter loop.

No signing, producer work, timer, resolver request, or ingress is possible before step 5 succeeds.
After step 7, ingress may be received into bounded actor queues, but it cannot affect protocol state
or authority until steps 8 and 9 complete.

### Observation and admission

1. Observation (`Input::Observe`) assigns an observation identity before asynchronous verification.
2. Structurally duplicate, out-of-window, over-capacity, or context-invalid input is rejected without
   a durable event. An admitted verification request records generation, job, ordered tickets,
   artifact identities, and expected count.
3. `Input::Verified` first validates the complete correlation. A stale generation or retired job is
   a no-op. Any mismatched live identity, count, or order is an invariant error and consumes nothing.
4. Verdicts are applied in original observation order. Invalid artifacts release their reservations;
   valid artifacts enter direct type-specific admission. Missing authenticated dependencies become
   level-triggered resolver demand, not a speculative protocol fact.
5. Admission atomically updates every affected DA, view, finality, durability, and retention index.
   No handoff object or component snapshot exists between those updates.

Worker completion order may change latency but cannot change sticky selection, transcript choice,
finality, signing authority, or durable bytes.

### Objective equivocation

Core compares claims only after their signatures or aggregate transcript have passed production
verification. A V-QC or L-QC contributes every attributed vote in its validated transcript, and a
V-QC also contributes its authenticated novoters. The following pairs identify one signer without
depending on local timing or application policy:

- two producer headers for the same chain and height, or adjacent producer headers whose parent link
  disagrees;
- two leader blocks for the same view;
- two different vote bodies for the same view, or a vote and novote for the same view;
- two DA shares from the same participant for different headers at one chain and height.

DA ingress normally uses structural checks because quorum recovery authenticates the shares in one
group operation. When a possible DA equivocation appears, the verification worker checks both shares
against their individual public keys before Core treats the pair as proof. A malformed or forged half
therefore cannot frame its claimed signer.

During one Core lifetime, each proven participant is emitted at most once. The voter maps the
participant to the committee identity and asks the network blocker to quarantine that
identity. A relay that carries a signed claim is not substituted for its signer. Malformed,
wrong-context, cryptographically invalid, stale, or mismatched traffic is rejected without
quarantining its transport source.

The evidence index is volatile. View claims follow the live view window. Producer claims follow the
certified-height floor and use bounded first-in, first-out replacement, so a fresh slot remains
comparable even after earlier application-rejected headers consumed the index. Timeouts, omissions,
unresolved dependencies, canceled work, application `verify(false)`, and challenge-dependent junk
claims do not enter it.

### Producer construction

1. A wake (`Input::ProducerWake`) is eligible only when the local role owns a producer chain,
   work/pacing policy allows it, no build is live, and the next height above the prepared tail
   remains at most `d` above the certified anchor.
2. The application receives only protocol context and the parent digest. A successful `propose`
   returns a commitment and binds the proposer to verifying that `(context, commitment)`; it does
   not confer durability or signing authority.
3. The build completion (`Input::BlockBuilt`) must match generation, request, context, parent, and
   expected height. Decline or cancellation authorizes no header and is retried only by normal
   level-triggered work/pacing.
4. Success appends the header to a bounded volatile prepared FIFO and requests application
   verification for its custody. Descendant construction may proceed immediately from the prepared
   tail, so body preparation and durability overlap.
5. Local `verify(true)` (`Input::BlockCustodied`) means the payload is permanently valid, locally
   available, and reconstructible after a crash. Completions may arrive out of order, but only the
   contiguous custodied FIFO prefix becomes eligible for signing. `false`, cancellation, or a live
   correlation mismatch cannot authorize a header; an unsigned prepared suffix is discarded on
   restart.
6. Each eligible header stages one durable producer-header signing reservation. The signature may be
   computed in parallel with journal I/O, but neither signature nor header may leave private process
   memory until the covering durable prefix is acknowledged.
7. After acknowledgement, signing completion self-admits the header and installs stable block-relay
   and header-publication obligations. Relay acceptance may order the first attempts, but volatile
   transport feedback never retires either obligation. Only a later durable semantic successor,
   such as a covering DA certificate, retires an obligation.

### Application verification and DA voting

1. Core assigns the observation identity before batched signature verification. After a valid
   verdict, it admits the producer header, records ancestry and forks, then routes a
   `ValidatorCommand::Observe` (`Capability::Validator`) to the chain plane of that producer chain.
   The command carries the observation identity and order and whether local custody is already
   established.
2. The plane stores the authenticated header and schedules `Automaton::verify` in lower-height-first
   order, keyed by generation and `ValidationId`. Requests and completions may overlap once the
   parent path is present. `verify(true)` means the parent and candidate are durably reconstructible
   and the candidate is permanently valid. Temporary absence keeps the request pending; `false` is
   permanent invalidity.
3. Using Core's certified anchor and read-copy of durable DA choices, the plane derives the next
   contiguous eligible run and offers it to Core as a `DaVotesOffer` tagged with the plane's
   generation. Core applies the offer at once rather than queueing it in a lane. The plane cannot
   reserve a vote, change the anchor, or make a validation result durable. The voter never blocks
   on a plane. Its mailbox marks a block at or below the latest anchor it sent as settled, since the
   plane would settle it on arrival. Commands beyond the plane's queue capacity wait in an overflow
   that drops settled blocks and keeps at most four control commands (the latest reconfiguration
   and choices, and the highest anchor on each side of the choices) and the blocks above the queued
   anchors. A stalled plane therefore holds at most its chain's unsettled routed blocks plus those
   four commands, however often settled blocks are replayed, and delays only that chain's DA votes.
4. Core correlates the offer to the current generation and chain, rechecks it against authoritative
   ancestry, custody, anchor, and DA choices, and ignores stale work. A verified header remains
   non-authoritative until this check succeeds.
5. In increasing height order, Core reserves at most one DA vote per `(chain, height)`, and never
   across a gap, an unavailable predecessor, or depth `d` above the certified anchor.
6. The choice is staged durably before threshold-share signing. The share is exposed only after its
   covering prefix is acknowledged and is sent only to the producer that owns the chain.
7. The producer's DA recovery task pools the first share per participant and header. At `n - 2f`
   distinct shares it assembles the certificate on the shared strategy; a failed group check
   excludes the attributed signers and waits for a fresh quorum. The certificate returns to Core as
   `CryptoCompletion::DaCertificate`.
8. Core admits the certificate durably (`Change::DaCertificateAdvanced`) and publishes it, advances
   the certified anchor monotonically, retires covered block and share publications and obsolete
   validation work, sends the new anchor and choices to the chain plane, and then re-evaluates the
   next contiguous suffix.

These rules implement the specification's one-vote-per-height, contiguous-path, and depth-`d` DA
conditions without moving signing authority into the chain plane.

### Proposal

1. The current scheduled leader proposes at most once. It selects a V-QC from the greatest view it
   holds. Within one view it prefers the certificate with the larger complete message transcript,
   then applies canonical byte/identity tie-breaking.
2. For each chain, the base is its highest held DA certificate above the selected V-QC tip, otherwise
   that tip's explicit `(digest, height)`. The proposal is the base alone: fresh blocks above it
   reach voters as vote extensions, at most `e` per chain.
3. The leader block includes the next tip commitment `H(previous_commitment, Tips(selected_vqc))`.
4. The leader block, selected parent V-QC, and whether that parent still needs transmission are one
   durable signing/publication choice. The parent is included with the proposal exactly when the
   receiver cannot rely on an earlier transmission of that same V-QC; selecting an updated V-QC
   requires transmitting it.
5. A proposal becomes externally visible only after its signing reservation is durable.

Leaders follow the deterministic `LeaderSchedule`. Randomized election is not supported: an
unpredictable election needs a unique per-view value, and the ordinary exit path produces none. A
V-QC is an aggregate of ordinary signatures, which is not unique and can be ground by its assembler;
only a nullification carries a threshold signature, and it covers just the views that time out.
Randomized election therefore needs a new machine-visible seed, not a different elector.

### Direct vote

1. A first-route proposal is eligible only when exactly one leader block from the scheduled leader is
   observed, the referenced earlier V-QC is authenticated, every skipped view has a nullification,
   chain anchors are valid relative to `Tips(V-QC)`, proposal paths are structurally well formed and
   depth bounded, and the tip commitment is correct.
   A receiver must not reject that valid parent merely because it already holds a V-QC from a
   higher earlier view. Greatest-held selection is leader policy, not an additional validity rule.
2. If the local stance is neither voted nor nullified, Core freezes positions and extensions from
   the local contiguous DA-vote history. Positions are the greatest consecutive proposed prefix;
   each extension is the longest consecutive path of at most `e` DA-voted blocks from that position.
3. The full vote subject and local stance are durably reserved before signing or exposure.
4. A current-view V-QC may authorize the specification's second voting route without repeating
   first-route validity checks. Its designation quorum proves that correct voters validated the
   proposal.

### Timeout and post-vote nullification

1. On the current timeout, a validator with no vote and no prior nullification atomically reserves a
   novote plus nullify share. Both subjects and the stance change share one durable event and are
   released only by its acknowledged prefix.
2. A validator that voted never emits a novote. It may reserve only a nullify share after observing
   messages from at least `2f + 1` distinct participants, each a nullify/novote or a vote for another
   leader block. The complete non-support witness is frozen before the reservation.
3. Nullify shares recover a nullification from exactly `2f + 1` distinct participants. Completion is
   correlated to its canonical transcript and admission is durable before publication.

### V-QC and view exit

1. A V-QC candidate accounts for between `n - f` and `n` distinct view messages, at least `2f + 1`
   of them votes for one designated proposal. Every committee member appears at most once across the
   disjoint designated-vote, other-proposal-vote, and novote categories. Votes for other proposals
   and novotes remain fully attributed; no constituent vote may be abridged.
2. Sticky transcript selection follows observation order, not verification or aggregation completion.
   The first eligible local aggregation freezes exactly `n - f` messages so view exit is not delayed.
   If more sticky messages become eligible, later jobs freeze strict supersets through at most `n`;
   every job receives one immutable transcript and correlation identity.
3. Only the first newly observed or assembled V-QC for a view is independently forwarded. A stronger
   same-view certificate remains durable candidate parent state. Under the optimized anchor choice
   from Section 6 of the specification, a later proposal may select it but must disseminate that
   certificate because the receiver cannot rely on the earlier, different V-QC. A certificate
   already forwarded need not be sent twice.
4. A valid V-QC or nullification for the current view supplies one authenticated exit. If a V-QC
   arrives while the local validator has neither voted nor nullified, the second-route vote is reserved
   before the view advances.
5. The view advance (`Change::ViewAdvanced`) increments exactly one view, resets only current-view
   volatile stance/timer state, retains the selected exit proof and required parent evidence, arms
   the next timer, and schedules the next leader if local. Future proofs are consumed one view at a
   time.
6. An admitted covering L-QC may raise the authenticated signing/view floor and derive the equivalent
   V-QC anchor without fetching its parent history. If no V-QC for that current or future view has
   yet fulfilled the first-new forwarding duty, the derived V-QC does so before the floor advances.
   A different V-QC that already fulfilled the duty is not forwarded again; the derived anchor is
   instead attached if a later proposal selects it. The specification treats a certificate derivable
   from received constituents as present in local state, and reusing the L-QC aggregate keeps the
   original observation order without another cryptographic job. This is state synchronization for
   agreement, not dense producer ordering. The re-anchored engine then resumes ordinary proposal, production,
   and finality transitions in the same epoch.
7. Catch-up liveness uses the specification's total fault bound. Crashed or unavailable participants
   count toward `f`; with at most `f` faults, the remaining correct quorum can produce the covering
   L-QC. Above `f`, exits still retire at the bounded retention floor and no additional witness or
   recovery branch attempts to restore progress outside the protocol model.

### Leader finality

1. For each retained leader block, retain the first valid vote per participant. Pools are sticky by
   observation order and may continue growing after `n - f`.
2. At `n - f`, finalise the leader immediately from the pool; portable L-QC aggregation is independent
   and not a prerequisite.
3. The specification's set `S` is unbounded, but this implementation retires an unfinished pool with
   its bounded view window. It therefore does not preserve every local-finality opportunity created
   by arbitrarily late pre-GST votes. Keeping all such pools would be unbounded, while blocking view
   progress at capacity would let one Byzantine signer stall the epoch. Under the `<= f` model,
   post-GST convergence reaches a correct-leader view and a covering L-QC through the ordinary path.
4. Per chain, the finalized proposal position is the `(3f + 1)`-th greatest position. Extension carry
   applies only when that position equals the proposed tip and at least `n - f` pool votes count for
   the extension. At full proposal position, Core replaces the specification's aggregate `beta`
   settledness count with `max_child_support + (n - |pool|) <= f`, where `max_child_support` is the
   largest retained-voter count for any immediate child of the current finalized tip, or zero if no
   child is observed. This is more permissive when beyond-tip votes split across incompatible
   branches, because no single carry candidate can combine their support. Every future carry beyond
   the finalized tip must pass through one immediate child. Unseen voters and Byzantine replacements
   can add at most `(n - |pool|) + f` support to that child, leaving it below the `2f + 1` carry
   threshold. The safe-extension argument separately excludes candidates incompatible with the
   finalized tip.
5. Finalized leader and chain-tip floors are monotone. Re-running finality as the pool grows may extend
   the same prefix but may never retract or choose an incompatible tip.
6. L-QC aggregation and admission freeze the vote transcript. A late valid covering L-QC may advance
   floors but may not change prior sticky choices.
7. Every admitted L-QC and locally reconstructable history opening may be reported as idempotent,
   best-effort activity. Reporter feedback never gates consensus. Marshal persists useful hints and
   resolves an unavailable opening by the digest authenticated in the L-QC; later L-QCs, startup
   reconciliation, and marshal backfill repair missed activity.
8. Consensus does not materialize, store, or acknowledge the specification's dense `Emit` stream.
   Marshal owns recursive history storage and all later ordering and delivery state.

`Tips(V-QC)` uses every designated vote carried by that V-QC and applies the specification's drop-`f`
position rule followed by a branch-aware `2f + 1` extension carry. A larger accepted V-QC is never
truncated to `n - f` before extraction. Finalized tips remain the drop-`3f` rule plus
unanimity/pool threshold only above a fully supported proposed tip. Tip commitments remain
consensus-critical and make historical tip sequences verifiable without replaying historical V-QCs.

The complete mapping from the specification's lemmas, theorems, corollaries, and optimizations to
implementation properties is in
[Specification crosswalk](https://github.com/commonwarexyz/monorepo/blob/main/consensus/src/multimmit/docs/PROPERTIES.md#specification-crosswalk),
and [Deviations from the specification](https://github.com/commonwarexyz/monorepo/blob/main/consensus/src/multimmit/docs/PROPERTIES.md#deviations-from-the-specification)
lists the departures. Consensus owns leader-chain compatibility, safe and finalized tips, and
authenticated history commitments. Marshal owns history materialization, the selected deterministic
sweep, dense output, and durable delivery.

### Persistence and publication

1. A semantic transition applies ordered durable changes locally and stages one contiguous cursor
   range. Replay applies those same events and no actor-side projection.
2. The journal owner appends ranges in order. It may coalesce adjacent appended ranges into one
   `start_sync`, but an acknowledgement always names the greatest contiguous durable cursor.
3. A forwarded certificate is structurally paired with its persistence directive. The voter submits
   the directive, installs resolver custody, and only then releases that independently verifiable
   publication; it does not wait for fsync.
4. Core accepts only an acknowledgement covering its next expected staged prefix. Old duplicates are
   no-ops; a gap, wrong generation, wrong range, or mismatched live completion is an invariant error.
5. The acknowledgement (`Input::Persisted`) returns the signing releases, publication installations,
   proof retentions, and publication retirements newly authorized by that prefix. The actor never
   scans durable events to infer them.
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
2. Only Core may mint a checkpoint `Snapshot`, and only at its acknowledged cursor after that
   staged prefix drains. The cut owns the complete durable semantic state at that cursor.
3. The journal owner treats a cut opaquely. The voter queues its roll before any post-cut append;
   a shared task awaits the roll acknowledgement before storing the checkpoint. Runtime service
   continues during that wait. The journal processes the roll first, so post-cut authority can
   append to a retained new section while the replacement checkpoint writes and syncs. Once the
   checkpoint is durable, Core briefly fences new durability-producing transitions until that
   post-cut suffix is idle, admits pruning of the covered sections, and immediately reopens
   authority while pruning runs behind the serialized journal owner.
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

Core copies the profile-bounded durable state when it mints the immutable cut. Snapshot encoding and
physical checkpoint storage then run on a shared runtime worker. Core itself never moves across the
async boundary, so a checkpoint cannot create a second semantic owner or admit a completion against
a temporarily absent state machine.

## Async boundaries and correlations

Only these operations cross an async boundary:

| Capability | Required identity | Core-owned decision |
|---|---|---|
| batch verification | generation, cohort, ordered tickets, artifact IDs/count | observation order and admission |
| application propose | generation, build request, producer parent/context, payload digest | volatile prepared header identity |
| application verify | generation, chain plane and validation or build request, header, payload digest | local custody or a plane's eligible-run input; Core alone reserves authority |
| sign/recover/aggregate | generation, job, subject/transcript | subject and canonical transcript |
| journal sync | ordered cursor range and durable prefix | releases and retirements |
| checkpoint/prune | immutable `Snapshot` | durable state and cut cursor |
| resolver | generation, requested view, proof kind | dependency demand and proof admission |
| timers | generation, view/production position | timeout/pacing transition |
| publication | stable effect identity and durable obligation | bytes, audience, and semantic retirement |

Cancellation only releases the matching volatile reservation. A stale completion cannot release a
current permit or mutate protocol state. Live mismatches are fatal invariant violations rather than
retries. Correct completions may arrive in any order. The live slot decides whether a late result
remains useful; an async worker never owns view order, producer-chain order, or a separate semantic
capacity limit.

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

- **C-INV-01:** Observation and event cursors are monotone; every pending completion references one
  live reservation of the same generation.
- **C-INV-02:** At most one local signing subject exists for each DA `(chain,height)`, view
  vote/novote/nullify slot, leader proposal slot, and aggregate job.
- **C-INV-03:** `acknowledged <= staged <= next`; staged ranges are contiguous; no authority exposure
  floor exceeds acknowledged authority. Every staged range has pre-reserved journal command and
  completion capacity.
- **C-INV-04:** Every publication obligation has one stable effect identity and one durable owner;
  there are no ownerless outbox rows or transport-owned retirements.
- **C-INV-05:** Certified and finalized tips, current view, signing floor, and leader finality floor
  never rewind.
- **C-INV-06:** Every DA-authorized suffix is contiguous from a certified anchor, has length at most
  `d`, and has custody plus prior DA choices for every predecessor. Speculative verified headers do
  not count.
- **C-INV-07:** Proposal positions and extensions are derived only from contiguous local DA-vote
  history; proposal paths are at most `d` and vote extensions at most `e`.
- **C-INV-08:** Every retained semantic object is reachable from a live view, floor, dependency, job,
  signing reservation, publication obligation, or recovery proof. Retirement removes nothing
  reachable.
- **C-INV-09:** Every queue, map, byte total, job class, finality pool, resolver waiter set, and work
  quantum stays within its validated bound. A derived mirror is bounded by its authoritative owner,
  never by a smaller estimate that legal completion reordering can exceed.
- **C-INV-10:** Consensus snapshots and public diagnostics contain digests, headers, certificates,
  leader facts, and tip commitments only, never application bodies, body-store state, dense-order
  cursors, delivery cursors, or application acknowledgements.
- **C-INV-11:** Activity reporting owns no protocol state: feedback, closure, or loss cannot delay a
  transition, retain an artifact, or add a durability event. No application body or recursive
  history backlog is copied into consensus durability.
- **C-INV-12:** Blocking caused by protocol equivocation names only a signer supported by two
  authenticated conflicting claims. Relay identity, timing, omission, application validity, and
  unresolved work cannot supply or replace either half of the proof.

Marshal checks a separate invariant set after every durable commit and recovery:

- **M-INV-01:** Every archived object matches its key: L-QC ID, recursive history commitment, or
  full canonical producer-header `BlockRef`. A body commitment is never a producer-block identity.
- **M-INV-02:** The selected finalized L-QC, history index, ordered frontier, emitted frontier,
  committed output, and acknowledged output are one canonical checkpoint. Every frontier is chain
  ordered and monotone within its generation.
- **M-INV-03:** Dense outputs are contiguous by `OutputIndex`; each index names one complete
  transaction block. History is processed oldest first. Each sweep visits every chain's proposed
  region before any chain's extension region, preserving offset-major order within each pass.
- **M-INV-04:** Evidence, openings, blocks, and output rows are durable before checkpoint exposure. An
  ordinary checkpoint carries its remaining temporary-cleanup obligation, which startup completes
  before serving reads. Delivery advances only through a contiguous FIFO prefix whose `Exact`
  acknowledgements all resolve, and syncs that prefix to its own cursor.
- **M-INV-05:** A runtime floor first persists one bounded intent containing the verified L-QC,
  opening, target checkpoint, and cleanup floors. Catalog completes that intent before serving reads,
  keeps it durable while both finalized archives sync and temporary data is pruned, then publishes
  the target checkpoint by replacing the intent with one ready state. Delayed generation-bound prune
  requests cannot affect a newer floor.
- **M-INV-06:** Backfill fetches recheck Catalog before peer work. Deliveries are bounded,
  generation-scoped, matched to their request key, decoded under protocol limits, and independently
  verified before Catalog admission. Buffered broadcast is only an eager complete-block cache.
- **M-INV-07:** Every actor mailbox, router job, backfill request/subscriber set, block waiter, dense
  commit batch, and in-memory delivery window has a configured finite ceiling. Unbounded history and
  ancestry walks spill to prunable scratch archives.

## Steady-state resource proof

With `n`, `f`, `d`, `e`, and `W` as defined in [Terminology](#terminology), the validated profile
derives every remaining ceiling before startup.

- Exactly `W + 1` current/past views are retained, plus the configured bounded future-view distance.
  Advancing a view runs one reference-safe retirement pass even if leader finality is stalled.
- Each producer has at most `d` authority-bearing uncertified headers above its certified anchor and
  each vote has at most `e` extension headers. Speculative validation is separately permit bounded.
- Remote producer blocks and DA votes are admitted only within `2d` heights of their chain's certified
  frontier, the higher of the durable certified tip and the newest held DA certificate. A chain
  position keeps at most two verified blocks, and the derived remote cache partition holds every
  chain's full window of them while `d <= W + 13`. Only the chain's producer keeps DA votes: above
  its durable tip, one per signer for a header it holds a verified block for. Rejected traffic is
  republished until certified.
- Artifact, future-artifact, dependency-waiter, finality-pool, forwarded-certificate, and publication
  outbox counts use `ResourceLimits`; profile construction rejects a bound too small for its retained
  live set.
- Accountability claims retire with the live view and certified-height windows. Producer claims use
  first-in, first-out replacement at the artifact ceiling, and the already-quarantined set cannot
  exceed the committee size.
- Exit-proof obligations share `max_outbox_effects`; compacted forwarding history is not their
  capacity owner. Every producer-header or DA-vote signing row owns one durable signing effect, so
  the signing mirror also shares `max_outbox_effects`. Neither path introduces a second, tighter
  capacity edge.
- Own-message publications stay outstanding until their view retires, so their family bound counts
  the larger of `W + 1` and the views the durable state still holds. After a restart under a smaller
  view retention, the writer's larger window fits until the next exit compacts it.
- Verification, application, signing, recovery, and aggregation jobs each consume a class-specific
  permit plus reserved completion capacity before becoming mandatory. Remote application work has
  `min(d, max_verification_batch)` slots per producer and that width times the producer count
  globally; per-chain rotation prevents one producer from monopolizing queued validation.
- Ingress and voter lanes have fixed item and byte ceilings. Each ingress lane derives an item and
  byte share for each of `f + 1` fault domains, so at most `f` replaying peers cannot consume the
  correct peer's admission share; active peer queues, network planes, and data chains rotate
  service. Decode and canonical-identification jobs are bounded, and their saturation stops network
  intake while control and completions retain service. Fixed work quanta force a runtime reschedule.
  Ingress drops a data-availability vote whose claimed signer is not the sending peer: honest votes
  are sent only by their signer, so this keeps a forged share out of the producer's recovery pool
  and the machine's per-signer vote slot.
- Public inspection and proof-serving queries use bounded admission or backpressure. They cannot enter
  a reliable mailbox's unbounded overflow, and a caller that does not drain replies retains no state
  inside the engine.
- Resolver job controls stay in FIFO order. Adjacent `Retain` and `Prune` updates collapse to their
  final custody projection without crossing any other control, so a slow resolver does not retain
  every historical copy of a monotone retention frontier. Core emits live prune frontiers directly
  and supplies one `(retired_view, proofs)` projection when the resolver starts; the voter does not
  infer resolver ownership from metrics.
- Resolver custody shares each retained proof and caches its canonical response bytes after the
  first serve. Proof decoding, uncached encoding, and local completion materialization run through
  the configured execution strategy in one pool bounded by that strategy's manual parallelism.
  Saturating the pool pauses only resolver-handler intake; custody controls, best-effort queries,
  worker completions, and the P2P engine lifecycle remain serviceable.
- Journal command count and unsynced bytes are bounded. Fsync coalescing covers the oldest contiguous
  prefix; urgent signing work behind a sync becomes the next prefix rather than creating an unbounded
  waiter chain. A machine work pass emits at most one cursor-contiguous journal range and runs only
  when the voter has one command slot, so capacity exhaustion cannot strand a partially handed-off
  prefix.
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
- Marshal bounds its mailboxes, jobs, subscriptions, commit batches, and scratch, and its disk use
  follows the finality-driven prune frontier; the marshal storage module documentation
  (`marshal/storage/mod.rs`) gives the proof.

Therefore consensus memory and marshal's active actor/scratch working set plateau across arbitrarily
many views and finalized blocks, provided configured external network/application/storage capabilities
continue making the progress required by the protocol. A stalled async dependency consumes its
pre-reserved bounded actor slot; it cannot create new active work.

The progress claim assumes at most `f` faulty participants in total, counting crashed and unavailable
participants. Beyond that bound the engine preserves its resource ceilings and fail-closed safety
checks, but it does not retain extra history or add recovery states solely to regain liveness.

Because application-validity/custody is an implementation fence in addition to the specification's DA
predicate, liveness also assumes that every block from a correct producer eventually becomes durably
available and returns `verify(true)` at every correct validator. Pending or permanently false results
from a correct producer are outside the protocol-derived liveness claim.

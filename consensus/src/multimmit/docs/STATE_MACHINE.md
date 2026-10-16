# Multimmit state machine

This document describes the consensus core of counted-views Multimmit: its terms, its state, the
transitions that change that state, the boundaries where work leaves the core, the invariants each
component owns, and the resource bounds that hold in steady state. It is written from the code.
The counted-views Multimmit specification ("the specification" below) defines the protocol;
[`PROPERTIES.md`](https://github.com/commonwarexyz/monorepo/blob/main/consensus/src/multimmit/docs/PROPERTIES.md)
lists where the code departs from it, the evidence for each property, and a section-by-section
crosswalk, and
[`DECISIONS.md`](https://github.com/commonwarexyz/monorepo/blob/main/consensus/src/multimmit/docs/DECISIONS.md)
records the implementation decisions and the protocol issues found while building it.

Module documentation owns the runtime structure: `machine/mod.rs` describes the core and its
capabilities, `actors/voter/mod.rs` the runtime around it, and `marshal/mod.rs` ordering, block
custody, and delivery.

Protocol authority is synchronous and has one owner, the machine. Actors and workers execute the
typed capabilities it returns and never decide a protocol fact.

## Terminology

Protocol terms follow the specification. The third column names where the term lives in the code.

### Parameters

| Term | Specification | Code |
|---|---|---|
| `n`, `f` | committee size, fault bound | `f = floor((n - 1) / 5)`, so `n >= 5f + 1` (`CodecConfig::max_faults`). |
| `K` | number of chains | One producer chain per committee member (`Parameters::producers`). |
| `n - f` | V-QC and L-QC size, final-tip quorum | `CodecConfig::view_quorum`. |
| `n - 2f` | height quorum behind `h*` | `CodecConfig::height_quorum`. |
| `n - 3f` | tip and designation threshold | `CodecConfig::{tip_quorum, designation_quorum}`. |
| `n - 4f - 1` | settledness bound | `CodecConfig::settled_bound`. |
| `alpha` | adoption threshold | `CodecConfig::adoption_quorum`, default `f + 1`, validated in `f + 1..=n - 2f`. |
| `N` | cap: the window of heights above a base that tips and the pool count | `Window::cap`. |
| `D` | flow bound: how far above `h*` a chain is produced and accepted | `Window::flow`, default `6N`, which covers a correct producer's lead plus the lag of a receiver's `h*` and final height. Ready peer headers the flow or finality bound refuses are counted once per chain and height (`flow_refusals`, `finality_refusals`). |
| `D + N` | finality lead (not in the specification): the furthest above a chain's final height a header is accepted | `Window::flow + Window::cap`. |
| `D + 2N` | tip lead: the furthest a correct voter's tip sits above the view's base | `Window::max_tip_lead`; headers are held within `max(h*, finalized) + D + 2N` (the held band) and V-QC paths are at most this long. |
| `delta_max` | payload hashes one update carries per chain | `Window::delta_max`. |
| `eta` | vote interval | `Tuning::vote_interval`, a configured send rate. |
| `theta_hat` | measured per-block production interval | Per chain, the median of recent gaps between consecutive accepted heights (heights accepted together share their gap); `theta_hat` is the upper median across chains, an unsampled chain counting at the seed `Tuning::theta_initial`. |
| `delta_hat` | measured one-way delay | `(RTT - eta) / 2` for `RTT` the 90th percentile of recent own-block round trips, each from producing the block to the arrival at this node (ingress receipt, before any local queueing) of the vote that gives it `n - f` endorsers, at least `Tuning::delta_min`; the seed `Tuning::delta_initial` applies before any sample. The model's bound `Delta` has no configured value. |
| `theta` | production interval: the pace of every own block, empty or not | `Tuning::production_interval`, a constant, default 23 ms (v2 L187), at least 1 ms. |
| ceiling | backstop on every timer and estimate | `Tuning::timer_ceiling`, seconds; not a latency estimate. |
| `D_stop` | silence after which a chain is declared | `2 delta_hat + theta_hat + eta`. |
| `t_late` | how long a chain may stay open after all but `f` chains are capped or declared (rule (ii)) | `theta_hat + delta_hat`, the specification's model-safe `theta + delta`. |
| `t_max` | view bound | `N theta_hat + 2 delta_hat + eta`. |
| `t_quiet` | leader silence that skips the leader at entry (optimisation B) | `2 delta_hat + eta`, above `eta + delta` whatever the delay. |
| `t_grace` | grace before a leaderless final | Adaptive in `[2.5 delta_hat, 2 t_max]`. |
| `W` | retention window | `Tuning::view_retention`, views kept below the newest finalized view. |
| `W_back` | vote tag window | `Tuning::vote_window`: tags in `[v - W_back, v + 2]` are read. |
| `J` | anchor lag (not in the specification) | `Tuning::anchor_lag`, default `max(W / 2, 2)`: a verified floor more than `J` views ahead re-roots the node. |

`theta`, `D_stop`, `t_late`, `t_max`, `t_quiet`, and `t_grace` are fixed at view entry (`ViewTimers`
in `machine/view/timing.rs`), each capped at the timer ceiling.

### Protocol objects

- **Transaction block header:** `(epoch, chain i, height h >= 1, parent digest, payload digest)`,
  signed by the chain's producer. Consensus holds headers only; bodies are opaque and belong to
  marshal. The genesis object of chain `i` is `g_i = (i, 0, H(GENESIS, epoch, i))`.
- **Accepted:** a header on the validator's single accepted path for its chain. It is accepted
  **in full** when the application's `verify` returned `true` for its body, or **adopted** when
  `alpha` validators endorse it, without a body.
- **`h*_i`:** the greatest height on chain `i` at which one header has `n - 2f` endorsers. It never
  decreases and drives flow control.
- **Leader block `l`:** `(epoch, view v, parent q = H(Q'), history c = C(Q'))` signed by `lead(v)`,
  where `Q'` is the V-QC of view `v - 1` the leader entered on. A proposal is valid only if the
  receiver holds `Q'` with its whole parent chain and `c == C(Q')`.
- **Vote content (the signed statement):** `(view tag, leader q or none, final flag, declared set F,
  one tip per chain)`. A vote endorses each tip and its ancestors. Kinds: a vote for `l`
  (`q = Some`), a pre-vote (`q = None`, not final), a leaderless final (`q = None`, final). The
  update sequence number is not signed.
- **Vote update (what is sent):** a vote content's non-tip fields, a sequence number `k >= 1` per
  (sender, tag), and only the chains whose tip changed since update `k - 1` or `k - 2`, each with up
  to `delta_max` payload hashes so a reader can rebuild the headers below the tip. Update zero, the
  default for omitted chains at `k <= 2`, is the sender's final tips of `v - 1` (genesis at view
  one). A reader missing a predecessor fetches the sender's vote of the tag by (sender, tag); the
  sender answers with its latest update of the tag, naming every chain.
- **Declaration:** adding chain `i` to `F` at the tip height `decl(i)` it had at the first firing.
  Every later vote of the tag endorses chain `i` no higher than `decl(i)`. A chain is **capped** when
  its tip is at least `N` above a base. At a reader, a vote tagged `v` is **binding** on a chain
  when it is final, the chain is declared, or its tip is capped against `beta_v`; before `beta_v` is
  defined only the first two apply. The sender's cap (against `base(l)` or its own final tips) only
  triggers its final vote.
- **V-QC `Q`:** `(epoch, view v, parent pi = H(Q'), FinalTally, aggregate signature)` over exactly
  `n - f` final votes of view `v`. The tally stores one reference content and per-signer deviations,
  plus **resolution paths**: payload-hash paths that let any holder rebuild every recorded tip above
  the base down to the base height.
- **`base(Q)`, `Tips(Q)`:** the base of a V-QC of view `v` is `Tips(Q')` of its parent.
  `Tips(Q)_i` is the highest block extending `base_i` that `n - 3f` recorded messages endorse,
  within `N`, else `base_i`.
- **Designation:** a V-QC designates `l` when `n - 3f` of its messages vote for it; its parent must
  then be `l`'s parent, checked as `H(v, pi, C(parent)) == q`.
- **History record and commitment:** `HistoryRecord = (C(parent(Q)), Tips(Q))` hashes to
  `C(Q) = H(TIP_HISTORY, C(parent(Q)), Tips(Q))`, with `C` of the genesis V-QC derived from the
  epoch's genesis. The records of consecutive views form the tips-history chain.
- **Emission state `beta_v`:** the base every V-QC of view `v` that can be an ancestor of anything
  shares. Consensus fixes it write-once by **case (a)**, `n - f` votes for a leader block of a later
  view (the view is **pinned** by an L-QC), or **case (b)**, `n - f` final votes of `v - 1` that
  determine every chain (`Det(G)`).
- **Pool, `b*_i`, settled:** for the open view `v` with base `beta_v`, `b*_i` is the highest block
  extending `beta_i` that `n - f` validators endorse through votes tagged `<= v`. A chain is settled
  when `gamma_i + (n - phi_i) <= n - 4f - 1`, where `phi_i` counts first binding votes tagged `v` and
  `gamma_i` those binding beyond `b*_i`.
- **L-QC:** a leader block with `n - f` votes for it, final or not, and their aggregate signature.
  With the history record opening the leader block's commitment, it is a **floor**: a portable
  certificate that every correct log extends `Ord(Q')`, resuming at output index
  `sum_i ht(Tips(Q')_i)`. A floor is also an **anchor**: it fixes `H(Q')`, `C(Q')`, and
  `Tips(Q')` without `Q'`'s chain, so a node far behind re-roots consensus on it.
- **Origin:** per chain, the finalized block the accepted path starts from: genesis, or the base of
  the floor the node anchored at.
- **Linked header:** a held header whose held ancestry reaches an accepted header, the origin, or
  the header-store floor. A vote's tip counts as resolved only when it names a linked header.
- **`Horiz(B, B')`, sweep, OutputIndex:** marshal places the blocks between two consecutive views'
  tips offset-major (all chains' first block above the base, then all second blocks, and so on).
  The open view's sweep places blocks up to `b*` in the same order, skipping settled chains and
  halting at the first unsettled chain. A block's output index is its position in that order and
  equals the sum of tip heights at each resolved view.

### Runtime terms

- **Machine, core:** `Machine` (the reducer) owns all protocol state; `CoreState` queues its inputs
  in bounded lanes and meters its work.
- **Component:** one synchronous protocol part the machine drives: `Chain`, `Producer`, `View`,
  `Pool`, `Emission`, `Forwarding`, `Retention`, in that wake order (`ProtocolComponent`).
- **Capability:** a typed command the machine returns for the voter to execute.
- **Lane:** one of the core's bounded input queues: persistence completions, local completions,
  timers, resolver results, peer observations, in service order.
- **Generation:** the process-lifetime counter. Completions of an earlier generation are stale.
- **Cursor, batch, barrier:** a cursor is a journal event position; a batch is a run of contiguous
  events persisted together; its acknowledgement (`BarrierAck`) names the greatest durable cursor.
- **Snapshot, checkpoint:** the durable state at an acknowledged cursor with nothing staged, and its
  stored copy. The journal is cut at its cursor.
- **Reservation, outbox, publication, discharge:** a signing reservation advances its signing slot
  durably before the signature exists. A publication sits in the durable outbox until a later
  durable fact (`DischargeFacts` and vote watermarks) discharges it.
- **Custody:** the application's `verify(true)` promise that a body is valid, held, and survives a
  crash. Marshal's block custody is a separate mechanism.
- **Chain plane:** the voter task that runs `Automaton::verify` for one peer chain's buffered
  headers and reports verdicts. **Network plane:** one of the four channels (data, consensus,
  certificates, resolver).

## Canonical state

### Durable

`DurableState` (`machine/durability/state.rs`) is the only durable consensus state. Snapshots
serialize it and journal events (`DomainEvent` carrying `Change`s) move it.

| Field | Meaning | Rule |
|---|---|---|
| `view` | current view | advances by `ViewEntered` on a held exit proof, or jumps by `Anchored` to a verified floor's view more than `J` (`anchor_lag`) above it |
| `generation`, `cursor` | process generation, newest applied event | monotone |
| `retired_view`, `root` | retention floor; the floor view's V-QC on the entry chain with its history record (after `Anchored`, the floor's parent `Q'` with its opening) | `root` present iff a view is retired |
| `accepted` | per chain, accepted headers above the retained height (`Full` with the signed header, or `Adopted` header) | one path from the chain's `origin`; the accepted tip is always kept, and a chain retaining nothing has its origin as its tip; only `Anchored` moves a path, and only on a chain whose path lacks the finalized base |
| `origin` | per chain, the finalized block the accepted path starts from | genesis until `Anchored` sets it to the anchored base; the chain layer's tip, `h*` and final height start there |
| `produced` | newest own header height signed | slot: advances by one per production |
| `leader_blocks` | per view, the parent and commitment of the leader block this node signed | slot: write-once |
| `notarised` | per view, the leader block this node voted for | slot: write-once |
| `watermark` | per tag: seq, tips, declared set with `decl` heights, final content | slot: seq increasing, tips monotone on the accepted path, `F` add-only, one final |
| `last_final` | newest view voted final and that vote's tips (`ftip`) | monotone; the vote tag is `last_final.view + 1`; `Anchored` at `v` sets it to `(v - 1, base)` |
| `anchored_tag` | the tag of the view this node anchored at, until its next final vote | update zero of that tag is unknown, so its first two updates name every chain |
| `emission` | per view `v`: the history record of `v - 1` (whose tips are `beta_v`) and how it was fixed | write-once, consecutive views, commitment chain |
| `local` | artifacts this node signed or assembled | retired with their view |
| `signing_reservations`, `outbox` | reserved signatures and pending publications under stable effect ids | retired by discharge or retention |
| `forwarded_vqcs`, `exits` | V-QCs forwarded per view; the proof each view was exited with | bounded per view |
| `ancestors` | V-QCs on an exit proof's parent chain above the retired view that no exit, local certificate, or root keeps | retired with their view; with the exits and the root, the current entry chain is durable |

### Volatile

Every component rebuilds its volatile state from durable state at start, after replay
(`Machine::start_components`: chain, votes, V-QCs, emission, view, then producer). None of it
carries authority.

- **Chain layer** (`machine/chain/`): the header store (held headers per height on any branch
  within the band, each with its `linked` flag and endorser sets partitioned by tag; the buffer of
  producer-signed headers waiting for their parent or for `h*`), accepted tips starting at the
  origin and including unstaged acceptances, pending acceptances, `h*`, the finalized heights,
  and `lastlife` per chain.
- **Producer** (`machine/chain/producer.rs`): the head (newest built header), the outstanding build
  and the slot of the newest one, the built headers not yet reserved with their custody flags, the
  signed own headers waiting for a lower signature, and the deferral of a declined build.
- **View layer** (`machine/view/`): current view and entry time, the timers fixed at entry, the
  entry parent V-QC, `tquorum` (rule (ii)), proposals of views `v - 1..=v + 1`, pending
  declarations, the delay estimator and `t_grace`, `heard(q)` per validator, `lastvote`. `proposed`,
  `notarised`, and `finalsent` are projections of durable fields, not copies.
- **Pool** (`machine/pool/`): per (tag, sender) the highest read sequence number, the last two read
  contents, and the first binding tip per chain; per tag the voters of each leader block and the
  senders whose final was read, in read order; the L-QC assembly's latest signed vote per
  (view, sender).
- **V-QC store** (`machine/view/vqc.rs`): per held V-QC its view, id, `C(Q)`, `Tips(Q)`, record,
  and designation; orphans waiting for their parent; the discard watermark; the first L-QC per
  view.
- **Emitter** (`machine/emit/`): the finalized view, the last reported sweep, the determination
  check cursor.
- **Accountability** (`machine/accountability.rs`): the greatest authenticated statement per
  (tag, signer) within the tag window, and pending proofs.
- **Anchor** (`machine/view/anchor.rs`): the highest admitted floor that would re-root the node,
  and the one beyond-window certificate being verified as evidence that peers are far ahead.
- **Admission and resolution** (`machine/reducer/store.rs`, `machine/resolution.rs`): artifact
  states (pending verification, parked on a predecessor, waiting on a dependency, ready), waiter
  indexes, outstanding retrieval records with a count of the bounded (update and header) ones,
  and the generation each durable signing reservation's capability was issued in.
- **Service metadata:** lane queues, budget, scheduler wake flags, timer deadlines. Rebuilding it
  cannot change protocol state.

No actor, worker, chain plane, journal owner, or reporter holds a second copy of protocol state
that carries authority.

## Transition system

Each input runs one synchronous step. A step rejects without a durable event, changes only
volatile state, or stages durable changes through `Machine::apply_event`, the function replay also
uses, and returns capabilities. Components never call each other asynchronously: they stage
changes with `Machine::reserve_change` or `reserve_effect`, wake themselves with `Machine::wake`,
and arm deadlines with `Machine::arm_timer`.

| Change | Applies |
|---|---|
| `GenerationAdvanced` | enters a new process generation (start or recovery) |
| `OutboxQueued` | reserves a signature or queues a publication under a stable effect id, advancing the signing slot in the same event |
| `SignedArtifacts` | records signed headers, leader blocks, or updates and turns their reservation into a publication |
| `Accepted` | records accepted headers, lowest height first per chain |
| `EmissionResolved` | fixes `beta_v`: view must be the next one, the record must extend the previous commitment, base heights must not fall |
| `ArtifactForwarded` | marks a V-QC forwarded and queues its publication |
| `ViewEntered` | enters the next view on a durably held V-QC or L-QC of the current view, retaining the V-QCs of its parent chain no holder keeps |
| `CertificateCreated` | retains a locally assembled V-QC or L-QC |
| `RetentionAdvanced` | raises the retention floor with its root, retiring reservations, publications, and records at or below it |
| `Anchored` | re-roots the node on a verified floor more than two views ahead and above every signed tag and written emission (see [Anchoring](#anchoring)) |

Every change checks its preconditions before mutating state and refuses otherwise
(`TransitionReason`); restore checks the snapshot's cross-field invariants (`SnapshotReason`).

### Public lifecycle

`Engine::open` validates the root `Config` before touching storage, recovers the consensus store,
and builds the ingress, verifier, voter, and resolver actors without spawning them.
`Engine::start` spawns them on the four network planes.

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
```

`ready` resolves once the voter's first durability barrier is acknowledged and its producer wake
is submitted. Marshal is attached as (or alongside) the `Reporter`: consensus never waits for it.

### Startup and recovery

1. Open the checkpoint store and the safety journal (`storage/recovery.rs`).
2. Restore the newest checkpoint and replay the journal suffix through `apply_event`. A snapshot or
   event that breaks an invariant fails startup.
3. Verify every self-contained artifact the recovered state retains.
4. Prune journal sections the checkpoint covers, then compact a suffix of at least one checkpoint
   interval into a new checkpoint.
5. Build the actors. No payload is verified again: a full acceptance already rests on a `verify`
   that promised the body survives a crash, and an adoption never needed one.
6. The voter stages `RecoveryComplete` (or `Start` when fresh), which advances the generation. The
   components restore their volatile state, re-report every retained acceptance, resolution, and
   finalization, request the leader block this node voted for in the current view and any missing
   parent V-QCs above the retired view, and re-arm their timers. A node that holds no entry parent
   for its current view (durable state older than its peers' retention) requests a peer's floor.
7. Nothing is released (signatures, publications, resolver requests) until the generation barrier
   is acknowledged. The voter then seeds the resolver with the retained artifacts, starts the chain
   planes, and reports ready.

A restart counts as entering the current view at the restart time: `heard` and `lastlife` reset to
now, `lastvote` is now, so the first update waits `eta` and optimisation B cannot fire at once, and
`tquorum` is unset, so rule (ii) counts from the restart.

### Observation and admission

1. Ingress decodes each frame on a worker pool, drops vote updates whose claimed signer is not the
   sending peer, drops (and counts) frames whose decoding panics, and forwards single-plane cohorts
   while the voter grants credit; the voter's queue holds every cohort ingress may credit.
2. `Input::Observe` prechecks each artifact before hashing where possible: epoch, participant,
   byte bound, tag window `[max(1, v - W_back), v + 2]`, the future-view window, the header band,
   per-height and per-view bounds, the per-sender pending-update bound, and supersession. A V-QC or
   L-QC beyond the future-view window is refused, but one at a time is verified first: a valid one
   has a correct signer that far ahead, so the node requests a peer's floor.
3. A vote update whose content cannot be rebuilt yet parks on `RetrievalKey::Update(sender, tag)`.
   The resolver asks only the sender, which answers with its latest update of the tag naming every
   chain. That answer passes the pending-update bound (only a full update some parked update waits
   for may), and reading any update of the tag wakes the parked ones and drops those it supersedes.
   An update whose predecessor's tag lies below the read window is refused, not parked.
4. Verification runs in batches on the verifier pools. A verdict must match its job's tickets in
   order; a mismatch is fatal, an invalid item drops only that artifact and blames nobody.
5. A verified artifact waits on the first dependency its component names (a parent V-QC, a leader
   block, the next missing header below an update tip in the band) and is admitted once ready.
   Admission updates every affected component in the same step. A retrieval whose result is
   refused re-settles its waiters before the key is requested again.

Verification order changes latency only. Pool interpretation follows read order, and read order
follows sequence numbers per sender.

### Chain layer

- **Acceptance (full):** a producer-signed header whose parent is the accepted tip, at most `D`
  above `max(h*, finalized)`, at most `D + N` above `finalized`, and whose body the chain plane
  verified `true`. Each buffered header is sent to its chain plane once, speculatively, before its
  parent is accepted. Raising a chain's final height wakes acceptance held by either bound. A ready header either
  bound refuses is counted once per chain and height.
- **Adoption:** the same conditions with `alpha` endorsers in place of the verdict. A header accepted
  in full beats an adoptable one at the same height. Marshal fetches an adopted header's body; the
  delivered log waits for it.
- **Endorsements:** every read vote marks each tip and its held ancestors with the signer, under
  the lowest tag through which it endorses the header. `h*`, adoption, and `b*` read these sets.
- **Band and buffer:** headers of another producer's chain are held on any branch at heights in
  `(floor, max(h*, finalized) + D + 2N]`, at most `n + 1` per height. A producer-signed header
  above the accepted tip and within `D + 2N` of it is buffered for acceptance, at most
  `pending_branches_per_height` per height; one that cannot be buffered is held, unsigned, only
  when a stored artifact waits for it. A full height evicts an unaccepted, unendorsed header with
  its held descendants, and a producer-signed header only for another producer-signed one. Peer
  copies of the own chain are refused; it is accepted only through production.
- **Linking:** a header is linked when its parent is accepted or linked, lies at or below the
  store's floor, or is the origin (at or below the origin's height only the origin links).
  Insertion, acceptance, and a raised floor propagate the flag to held descendants.
- **Staging:** acceptances are staged as `Change::Accepted` before any update that could endorse
  them is reserved, and `HeaderAccepted` is reported when that batch is acknowledged.
- **Held back (telemetry):** a chain is held back while its next height is the greatest height
  whose ready header (verified in full or adoptable) the flow or finality bound refused. The
  state decides nothing; declarations record it as context.

### Production

A build of height `h` is allowed once `h - max(h*_own, finalized_own) <= D` (the specification's
flow bound); a rising `h*` or final height of the own chain wakes it. This bound is a safety limit,
not the pace. The machine issues every build, empty or not, at its slot: `theta` after the previous
build's slot, and at once for the first build after a start. The application answers
`Automaton::propose` at once with whatever it has to include; an empty body is an ordinary payload
and consumes the height. A build issued within `theta` of its slot keeps that slot, so late timers
and slow builds do not stretch the pace; one issued later, after the flow bound held the producer,
starts a new schedule at once, so a released producer resumes one block per `theta` rather than
in a burst. A declined build takes no height, and the next one is due no sooner than `eta` later.
A producer at `theta` runs about a round trip of blocks ahead of its final height and reaches the
flow bound only while finality stalls.

Blocks are pipelined: each build extends the newest built header without waiting for its custody
or signature, custody requests run concurrently, and signatures are reserved in height order over
the custodied prefix, so a header is never signed before its body and every lower body are held.
Reservations staged in one drive share one barrier, and the persistence actor's single prefix sync
covers every barrier appended while it runs. Signatures may complete in any order; own headers are
accepted in height order. An own header stays published until `D` later
heights are produced, since by then it has reached the height quorum. After a restart the producer
builds above the newest reserved header; signed headers above a still-reserved one wait for it.
It also recalls every own header above both `produced - D` and the chain's final height that is
reserved or signed (`AppJob::Recall`: the application is asked for the body again and the outcome
is not reported): a restart loses the relay's staged bodies, and that request is how the relay
learns them again, so publications retried after the restart carry their bodies.

### Sending votes

The vote tag is `last_final.view + 1`. `endorsed_content` builds the content: per chain the
accepted tip, or for a declared chain the block at `decl(i)`. Updates name every chain whose tip
differs from own update `k - 1` or `k - 2` (all chains when either is unknown, as after a
restart), with the payload hashes of the blocks above the tip of update `k - 2` (all `delta_max`
when it is unknown), so a reader that lost update `k - 1` rebuilds from update `k - 2`. A final
vote names every chain, so a reader that lost earlier updates of the tag still reads it.

Each update reservation records its watermark first. Repeated votes go out at most every `eta` and
only when the content changed; the vote for `l` and every final go out at once. An update
superseded before it was signed (`seq + 2 <= k`) is retired unpublished. The resolver serves this
node's latest update of each tag, naming every chain, to readers that missed earlier ones.

### Reading votes

The pool reads updates per (sender, tag) in sequence order and stops after the sender's final.
Omitted chains take the tips of read update `k - 1`, else `k - 2`, else update zero; update zero
for tag `v` is the sender's read final of `v - 1`, and while that final is unread the update parks on
the sender's vote of tag `v - 1`, whose latest full update carries it. A changed tip that is not held is rebuilt from the
payload hashes. A tip counts as resolved only when it names a linked header; otherwise, if the tip
is in the band, the update waits for the first missing header below it, fetched one parent at a
time, whichever branch it is on. A tip outside the band or on a peer's copy of the own chain is
read as endorsing nothing on that chain. A read vote is interpreted once: it endorses the held path
below each resolved tip (a tip on a branch not through `beta_i` endorses nothing in the window),
and its first binding tip per chain is kept for settledness. A tip counts as capped only against
`beta_v`; a vote read before `beta_v` is defined binds only by being final or declaring the chain,
and is never re-evaluated.

Final votes recorded inside an admitted V-QC enter the pool as read finals of their signers.

### Views

- **Entry:** a validator enters `v + 1` only on a held V-QC (or L-QC) of `v`, after its own final
  vote for `v` is reserved and the certificate is durably held. Entry fixes the timers and decides
  optimisation B once.
- **Proposal:** on entry the leader of `v` signs one leader block on its entry V-QC with
  `c = C(Q')`. A receiver keeps proposals of views `v - 1..=v + 1`; one from `lead(v)` is valid if its
  parent is a held V-QC of `v - 1` and `c` matches. Two leader blocks for one view make neither valid.
- **Vote for `l`:** sent at once for a valid proposal of the current view; `notarised` is
  write-once. The sender then caps its tips against `base(l)`.
- **Declarations:** add-only per tag with `decl` fixed at first firing. Rule (i) applies from this
  node's final vote for the previous view, so its pre-votes carry it; rules (ii) to (v) apply only
  after entry and before the view's final vote. Rule (i): an uncapped chain with no sign of life
  for `D_stop`. Rule (ii), late: `tquorum` is the first time after entry at which all but `f`
  of the `K` chains are capped (in the sender's sense, below) or declared; `t_late` after it, every
  chain still neither is declared at its accepted tip. With `K <= f` rule (ii) never fires. Rule
  (iii): every uncapped chain at `t_max`. Rule (iv): every chain when a V-QC of the view arrives
  before the final. Rule (v): every chain when, on some chain, more than `f` first binding tips sit
  at one block and more than `f` but fewer than `n - f` at a higher one, a tip at or above the
  window end counting as the window's last block. Optimisation (A) at `t_grace` without a proposal
  and (B) at entry for a silent leader declare every chain, both only while `beta_v` is undefined.
  For telemetry, every declared chain is counted by rule and by what this node knew when it declared
  it: capped, silent for `D_stop`, held back by the acceptance bounds, and the time since its last
  sign of life.
- **Final vote:** sent once, when every chain is declared or capped and either a leader block is
  notarised or `t_grace` has passed. At a view change, a node that has not sent its final sends it for
  the block the arriving V-QC designates, built from the V-QC's parent, without a validity check.
- **Timing:** `delta_hat` is the nearest-rank 90th percentile of recent own-block round trips
  (signing to the arrival at ingress of the `(n - f)`-th endorser's vote, not its processing),
  less one vote interval, halved. A sample excludes this node's ingress, verification and input
  queues, and still includes the endorser's processing and this node's own send path. The sign
  of life for rule (i) is dated when the vote is read, not when it arrived. `theta_hat` follows every
  acceptance, in full or by adoption, of every chain; restored acceptances are not sampled. Both
  estimators are volatile and start from their seeds after a restart. `t_grace` doubles once per view
  when a valid proposal arrives after this node's leaderless final, and halves once when its vote
  for a leader block is reserved.

### V-QCs

- **Assembly:** from the pool's finals of the current view in read order whose tips are all
  resolved; the first `n - f`, with canonical resolution paths (a tip on another branch gets a
  path from its ancestor at the base height, which endorses nothing). A final the assembler cannot
  resolve is omitted, never recorded as endorsing nothing. While the encoding
  exceeds `max_vqc_bytes` the most expensive vote is swapped for the next candidate. If the
  selection designates a block of another parent, the forced parent is used or its leader block
  requested. One aggregation is in flight.
- **Admission:** a V-QC waits for its parent; it is held only if the parent is of the previous view,
  `validate_vqc` accepts it against the parent's facts, and the view holds fewer than `n` V-QCs
  (V-QCs another artifact waits on are exempt). Holding rebuilds its path headers and reads its
  finals. Each V-QC is stored once, as the artifact; a leader's proposal clones its parent from it.
- **Forwarding:** each view's first held V-QC is forwarded once, after the not-yet-forwarded V-QCs
  of its parent chain whose publication duty has not ended.
- **Discard:** once a held V-QC of `v` designates a block with `n - f` pool votes, held V-QCs of
  lower views off its parent's chain are dropped.

### Emission and L-QCs

The emission drive runs one quantum at a time: stage an assembled L-QC; finalize the next L-QC
(case a); determine the next view (case b); else start the next L-QC aggregation and report the
sweep.

- **Case (a):** an L-QC of view `p` (assembled from `n - f` latest signed votes for its leader block,
  finals first, or received) that opens to its parent's record pins every view from the greatest
  defined one up to `p - 1`, walking the parent's V-QC chain. `EmissionResolved` records are written
  with `Pinned { p, lqc }`, the L-QC is made durable, and `LeaderFinalized` is reported with the
  opening. An L-QC whose parent is missing keeps that parent requested.
- **Case (b):** when some `n - f` finals of the greatest defined view agree on every chain's reach
  above `beta`, `Det(G)` fixes the next base, `Determined`.
- **Agreement:** when both cases apply to one view they must agree; a disagreement (only possible
  beyond `f` faults) fails the step.
- **Undetermined boundaries (telemetry):** when `n - f` or more finals of the greatest defined
  view fail case (b), the chains they leave undetermined are classified as unresolved (fewer than
  `n - f` tips resolve) or split (no `n - f` resolved tips share a reach). When case (a) later
  pins that view, the boundary and its chains are counted.
- **Reports:** `ViewResolved(u)` is derived from `emission[u]` and `emission[u + 1]` and reported
  when the batch holding `EmissionResolved(u + 1)` is acknowledged. `ViewSweep` is reported for the
  greatest defined view only when it changed, merged so `b*` never falls and settled chains stay
  settled. Reports keep their order. A restart re-reports the retained resolutions and
  finalizations. Each `LeaderFinalized` also makes its floor the newest one the resolver serves
  under `RetrievalKey::LatestFloor`.

### Accountability

Per (tag, signer) the greatest authenticated statement is kept and each later one compared. Two
finals of one tag with different content, votes for two leader blocks in one tag, two non-final
votes neither below the other, or a vote above the signer's final quarantine the signer once. Two
producer headers at one height and two leader blocks for one view quarantine the producer or leader.
Evidence comes from read updates, certificate tallies, headers, and leader blocks; the relay or
assembler is never blamed. Omission, late arrival, unresolvable tips, and an invalid commitment
are dropped, not punished.

### Retention

The floor is `min(finalized - W, view - 2)`. Raising it (`RetentionAdvanced`) records the floor
view's V-QC on the entry chain as the root, drops accepted headers below
`min(base of emission[floor + 1], accepted tip)`, and retires reservations, publications, slots,
exits, ancestors, and local artifacts at or below the floor. The machine then prunes its volatile stores,
sends `ResolverCommand::Prune(floor)`, and sends `SettleHeaders` for every chain whose header floor
rose.

### Anchoring

A node requests a peer's newest floor (`RetrievalKey::LatestFloor`: an L-QC with the record opening
its leader block's commitment) when a restart cannot hold its entry parent or when a V-QC or L-QC
beyond the future-view window verifies (its `n - f` signers include a correct validator that far
ahead; one such certificate is checked at a time). A verified floor of view `v > view + J`
stages `Anchored`: `view = v`, `retired_view = v - 1`, `root = (Q', opening)`, the emission of `v`
pinned by the floor, every earlier slot, emission, exit, ancestor, and view-scoped local artifact
dropped, the anchoring L-QC kept, and each chain's accepted path snapped to the base when it lacks
it (the own chain keeps its headers and `produced`). `apply` refuses a floor at or below `view + 2`,
a watermark tag, the tag after `last_final`, or a written emission, and one whose own-chain base
this node never produced, so nothing signed afterwards shares a tag, view, or own height with
anything signed before. The machine then restarts in process: it stages the next
generation (completions of earlier work become stale and outstanding effects are released again
once it is durable), cancels its retrievals, drops the peer artifacts it holds, and rebuilds the
components from durable state.

### Persistence and publication

A step's durable changes are staged into a batch. At most a bounded number of batches are staged
and in flight, and acknowledgements apply in barrier order. Nothing leaves the process before the
current generation's barrier is acknowledged; a signature's publication is released only after the
event recording it is acknowledged, and a forwarded or created certificate is served only once
every local signature it could carry is durable. Publications retire only by discharge: an update once
`watermark.seq >= seq + 2` for its tag, an update or own leader block once its view falls below the
vote window of the current view, an exit certificate once a later view was exited, any publication
of a retired view, an own header once `D` later heights were produced. Peers further behind fetch
an update or leader block from resolver custody, so the outbox stays bounded however long the
retention window. A final vote whose record is durable but whose publication is uncertain is
re-sent identically after a restart while its tag is still read.
A checkpoint is cut only at an acknowledged cursor with nothing staged.

### Marshal

Marshal consumes the activity stream (`marshal/`).

- **Router:** forwards `ViewResolved` and `LeaderFinalized` to the synchronizer in report order and
  drops facts not shaped for the epoch. Under mailbox pressure `ViewResolved` reports are retained
  in order (older and duplicate ones dropped, at most 1,024, the oldest dropped beyond that; gap
  repair recovers what was dropped), the newest `LeaderFinalized` and the furthest `ViewSweep` are
  kept, and hints drop.
- **Synchronizer:** turns resolutions and L-QCs into targets `(view, commitment, record, proofs)`
  merged to the highest view. A pass opens each view's history record (from the report, the
  catalog, or peers by commitment), checks the commitment chain back to the synchronized view, walks
  header ancestry, and commits `Horiz(beta_u, beta_{u+1})`. The open view's sweep emits a prefix of
  the next `Horiz`; the resolution must continue it. An L-QC of view `v` pins view `v - 1` and
  becomes floor material.
- **Catalog:** owns block custody, finalized rows, and the checkpoint (which records the resolved
  view); a commit makes rows durable before the checkpoint names them, and a floor install never
  reuses a history ordinal a crashed commit left. History and header walks run on the read lane in
  bounded steps.
- **Backfill:** fetches L-QCs by id, history records by commitment, and blocks by
  `(chain, digest)`, and fetches adopted bodies in the background until admitted or retired. An adoption
  carries a grace, the adopting node's `delta_hat`: a body admitted within it (normally by relay)
  needs no fetch, and the callers the adoption promotes wait out the same grace. Explicit and
  finality fetches are never deferred.
- **Delivery:** reports outputs in `OutputIndex` order and owns the acknowledgement cursor.
- **Floors:** `install_floor` verifies the L-QC and opening, checks the floor does not regress, and
  resumes at the sum of the opened tip heights; `floor_at` serves the newest retained floor at or
  below an index.

## Async boundaries and correlations

| Capability | Correlation | Machine-owned decision |
|---|---|---|
| verification | generation, job id, ordered tickets | admission in observation order |
| application build and custody | generation, build id, parent | the next own height and its reservation |
| chain-plane validation | chain, requesting generation, header | full acceptance |
| signing | effect id, the generation the reservation's capability was issued in | slot advance (already durable) |
| V-QC and L-QC aggregation | generation, one job per kind in flight | selected votes and tally |
| journal append and sync | barrier, cursor range | releases, reports, retirements |
| checkpoint and prune | snapshot at the acknowledged cursor | cut position |
| resolver | retrieval job and key | admission, then `Cancel` or `Reject` for every result |
| timers | family, held deadline | the transition a tick enables |
| publication | stable effect id | content, audience, discharge |
| quarantine | none (best effort) | the proof |

A completion of an earlier generation is stale before any component sees it. A live mismatch
(tickets, job ids) is fatal. Completion order changes latency only.

## Invariants

Consensus invariants are `C-INV`, marshal invariants `M-INV`. The
[property ledger](https://github.com/commonwarexyz/monorepo/blob/main/consensus/src/multimmit/docs/PROPERTIES.md#invariant-evidence)
gives the tests for each.

| ID | Invariant | Owner |
|---|---|---|
| C-INV-1 | Every durable mutation goes through `apply_event`; restoring a snapshot and replaying the journal reproduces the live state; restore refuses a snapshot whose fields disagree; a checkpoint is cut only at an acknowledged cursor with nothing staged. | `machine/durability/{apply,snapshot}.rs`, `machine/reducer/machine.rs` |
| C-INV-2 | Nothing leaves the process before the generation barrier is acknowledged; a signature is published only after its record is durable; staged and in-flight batches are bounded and acknowledged in order; reports wait for the batch holding their fact. | `machine/reducer/persistence.rs` |
| C-INV-3 | A signing slot advances in the durable reservation event before the signing capability exists, and a signature completes only under the generation its capability was issued in. After a crash at any journal boundary, the node releases only statements the uninterrupted run could: one leader block per view, one `q` per view, one final per tag equal to the durable one, tips and declarations never below the watermark, one digest per own height. | `machine/durability/apply.rs`, `machine/reducer/completions.rs` |
| C-INV-4 | No reservation outlives its publication duty, the outbox never holds a publication all of whose items are discharged, and own updates and leader blocks leave the outbox once their view is below the vote window, so the outbox does not grow with `W`. | `machine/durability/{apply,state,outbox}.rs` |
| C-INV-5 | Completions of an earlier generation are stale; a verification completion matches its tickets in order; a tick acts only at or after its held deadline. | `machine/reducer/{completions,observe}.rs` |
| C-INV-6 | Per chain, accepted headers form one path from the chain's origin, one per height, each within `D` of `max(h*, finalized)` and within `D + N` of `finalized`; a full acceptance beats an adoptable one; the own chain is accepted only through production, in height order; acceptances are durable before an update endorsing them is published; restart rebuilds every path. | `machine/chain/{accept,mod}.rs` |
| C-INV-7 | A held header's endorsers include its held children's, each endorser in the partition of the lowest tag through which it endorses the header; `h*` never decreases; `alpha` endorsers adopt. A header is linked iff its held ancestry reaches an accepted header, the origin, or the floor. | `machine/chain/headers.rs` |
| C-INV-8 | Every admission bound (tag window, header band and per-height bounds, pending updates per sender, V-QCs per view, artifact and certificate byte limits) rejects before allocation; rebuilt headers never lock a producer-signed header out of its height; ingress forwards an update only from its signer; chain planes bound in-flight validations; faulty senders' parked updates cannot hold every dependency waiter (`2 * pending_updates_per_sender * f < max_dependency_waiters`, checked by config). | `machine/reducer/observe.rs`, component prechecks, `machine/chain/headers.rs`, `config/profile.rs`, `actors/ingress`, `actors/voter/chain_plane.rs` |
| C-INV-9 | An update is read only after its signed content was rebuilt and verified; reads per (sender, tag) strictly increase and stop at the final; a parked update a later read passes is dropped; each vote is interpreted once and endorses only through linked tips; the first binding tip per (sender, tag, chain) is write-once and is recorded only for a final, a declared chain, or a tip capped against `beta_v`. | `machine/pool/mod.rs` |
| C-INV-10 | `b*_i(v)` and settledness equal the reference algebra over the read votes (tags `<= v` for `b*`, first binding votes of tag `v` for settledness). | `machine/pool/counts.rs` |
| C-INV-11 | Own updates name every chain changed since update `k - 1` or `k - 2`, with the payload hashes above update `k - 2`'s tip; every signed tip lies on the durable accepted path, at `decl` on a declared chain; declarations are add-only with `decl` fixed at first firing; rule (ii) counts from `tquorum`, set at most once per view, after entry and before the view's final vote, and unset at entry and at a restart; a final names every chain. | `machine/view/{endorse,declare}.rs`, `machine/durability/apply.rs` |
| C-INV-12 | The vote tag is `last_final.view + 1`; a vote for `l` goes only to the single valid block of `lead(v)` or to a designated block in the late final; the final is sent once under the trigger; entry follows the reserved final on a durably held certificate; repeated votes are spaced by `eta`, across restarts; the sender caps against `base(l)` once it voted for `l`. | `machine/view/{handlers,proposal,declare}.rs`, `machine/view/vqc.rs` |
| C-INV-13 | Timers are fixed at entry from the measured `delta_hat >= delta_min` and `theta_hat`, each at most the timer ceiling; the pace `theta` is the configured constant `production_interval`, and every own build is issued at its slot `theta` after the previous one; a `delta_hat` sample ends at the network arrival of the vote that completes it; `t_grace` stays in `[2.5 delta_hat, 2 t_max]`, doubling once per late proposal and halving once per reserved vote for a leader block. | `machine/view/timing.rs` |
| C-INV-14 | A V-QC is held only with its parent chain and only if `validate_vqc` accepts it; its tips and commitment equal the algebra's; at most `n` per view plus those an artifact waits on; each view's first V-QC is forwarded once with its unforwarded ancestors; assembly records `n - f` resolvable finals within `max_vqc_bytes`, including finals on another branch of an equivocating producer. | `machine/view/{vqc,assemble}.rs` |
| C-INV-15 | Emission states are written once per view, in view order above the root, each extending the previous commitment; case (b) writes exactly `Det(G)`; an L-QC pins back to the greatest defined view, and a disagreement with an earlier determination fails the step; `ViewResolved` and `LeaderFinalized` follow durability and keep their order; `ViewSweep` is monotone per view; a restart re-reports the retained facts. | `machine/emit/mod.rs`, `machine/pool/lqc.rs` |
| C-INV-16 | The retention floor trails the newest finalized view by `W` and the current view by two; it keeps every accepted tip, the base of the view after the floor, and the newest emission; a restart after retention holds the retained V-QCs on the root. The resolver serves no view-scoped artifact at or below its prune point except the newest L-QC, and retires headers only by their chain's settled height. | `machine/retention.rs`, `actors/resolver/actor.rs` |
| C-INV-17 | A signer is quarantined once, only on two authenticated statements matching an objective pattern; a correct sender never matches; relays and assemblers are never blamed. | `machine/accountability.rs` |
| C-INV-18 | Update and header requests share a bounded table; while it has room, every such key a stored artifact waits on is requested, and certificate and leader-block keys are always requested, so vote traffic cannot starve a parent V-QC. Every retrieval result gets a verdict; a refused one re-settles its waiters before the key is requested again; a response not providing its key never completes a job or blocks the peer; an update key is fetched only from its signer. | `machine/resolution.rs`, `machine/reducer/{observe,completions}.rs`, `actors/resolver` |
| C-INV-19 | Activity reporting never gates progress. | `actors/voter` |
| C-INV-20 | Every V-QC on the current entry V-QC's parent chain above the retired view is durably retained (exit, local, ancestor, or root); a view entry retains exactly the unkept part of its proof's chain, and a restart holds the entry parent without retrieval. | `machine/durability/{apply,state}.rs`, `machine/view/vqc.rs` |
| C-INV-21 | `Anchored` applies only to a verified floor of view `v` more than two views ahead, above every watermark tag, the tag after `last_final`, and every written emission, whose own-chain base this node produced; afterwards the node signs only tags, views, and own heights above everything it signed before; work issued before the anchor completes as stale. | `machine/durability/{apply,state}.rs`, `machine/view/anchor.rs`, `machine/reducer/step.rs` |
| C-INV-22 | Per chain the accepted path starts at the durable origin; only an anchor moves it, and only on a chain whose path lacks the anchored base. | `machine/durability/state.rs`, `machine/chain/mod.rs` |
| C-INV-23 | Telemetry the machine records (held-back chains and refusals, declaration contexts, undetermined boundaries) never feeds a protocol decision, and its counts never decrease within a process; the voter exports increments of them, and attributes its thread time by input kind, machine component, and lane. | `machine/chain/accept.rs`, `machine/view/declare.rs`, `machine/emit/mod.rs`, `actors/voter/telemetry` |
| M-INV-1 | A history record is opened only if it hashes to the target commitment or to the parent named by the previously staged record, and the chain reaches the synchronized commitment exactly at the synchronized view. | `marshal/actors/synchronizer/history.rs` |
| M-INV-2 | Output is the concatenation of `Horiz(beta_u, beta_{u+1})` over resolved views; the open sweep emits a prefix of the next `Horiz`; the output index after view `u` is the sum of its tip heights. | `marshal/protocol/order.rs`, synchronizer |
| M-INV-3 | The checkpoint view advances by one per opening, never regresses, and a floor resolves view `lqc.view - 1`. | `marshal/storage/catalog_state.rs`, `marshal/actors/catalog/validate.rs` |
| M-INV-4 | A same-view sweep never retreats within a process; a sweep never emits past its first unsettled chain above `b*`. | `marshal/actors/synchronizer/sweep.rs` |
| M-INV-5 | Floors never regress: a floor's view is not before the state's and its tips dominate both frontiers. | `marshal/protocol/floor.rs` |
| M-INV-6 | An adopted block's body is fetched, once its grace passes without it, until admitted or retired; an adoption admitted or retired within its grace issues no fetch; and adoption markers never evict callers' waiters. | `marshal/actors/backfill` |
| M-INV-7 | Router pressure keeps `ViewResolved` reports in order, drops only older or duplicate ones and, beyond 1,024 retained, the oldest; gap repair recovers any opening dropped. | `marshal/mailbox.rs`, synchronizer |
| M-INV-8 | A staged block is recoverable once its custody resolves; a commit makes rows durable before the checkpoint names them; only the durable acknowledgement cursor suppresses redelivery. | `marshal/actors/{catalog,delivery}` |

## Steady-state resource bounds

Every bound below is validated or derived when the engine opens (`Profile`, `ResourceLimits`) and
enforced before allocation.

| Resource | Bound | Owner |
|---|---|---|
| Vote tags read | `[max(1, v - W_back), v + 2]` | pool precheck |
| Unread updates | `pending_updates_per_sender` per sender, newest refused, plus one full answer per parked key; validated against the dependency-waiter budget | artifact store, config |
| Read votes | per (sender, tag): latest two contents and first binding tips; tags retired at the floor | pool |
| Held headers | per chain heights in `(floor, max(h*, finalized) + D + 2N]` on any branch, `n + 1` per height; off the acceptance buffer only headers an artifact waits for | header store |
| Buffered peer headers | `D + 2N` heights above the tip, `pending_branches_per_height` per height | chain layer |
| V-QCs | `n` per view plus referenced parents; `max_vqc_bytes` each; durable ancestors only on the entry chain above the floor | V-QC store, codec, durability |
| Leader blocks | one per view in `v - 1..=v + 1` | view layer |
| Own production | own blocks within `D` of `max(h*, finalized)`, built, in custody, or reserved; one build at a time | producer |
| Own publications | `D + 1` own headers; updates until superseded by two or below the vote window; own leader blocks until below the vote window; exits until replaced; independent of `W` | outbox |
| Durable state | views `(floor, view]`; floor `= min(finalized - W, view - 2)` | retention |
| Artifact cache | durable references plus stored artifacts within live work, `chains * (D + 2N)` accepted headers above the live base (acceptance stops `D + N` above a final height, which lies at most `N` above the live base), and per retained view `3n + 4` slots plus `chains * N` accepted headers (a V-QC raises each base at most `N`) | `Profile`, durability, artifact store |
| Retrievals | update and header requests by the machine's request bound; certificate and leader-block requests by their waiters; the latest floor one at a time; serving per peer by channel quota | resolution, resolver |
| Lanes, jobs, permits | fixed item and byte ceilings; `f + 1` peer shares per ingress lane | `CoreState`, ingress, voter |
| Marshal | bounded mailboxes, jobs, subscriptions, commit batches, and scratch; disk follows the floor prune | marshal |

While finality advances, durable state, emissions, exits, forwarding records, accepted headers,
the header store, and the V-QC store stay on a plateau. Retention is anchored to the newest
finalized view, so if finality stalls the floor stops and durable occupancy grows until capacity
checks park the components. That stays bounded but is not live; liveness assumes at most `f`
faulty, crashed, or unavailable validators, post-GST delivery within a delay `delta` with
`2.5 delta` below the timer ceiling, and an application that eventually verifies every correct
producer's block.

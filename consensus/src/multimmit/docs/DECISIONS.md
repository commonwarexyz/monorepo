# Multimmit implementation decisions and protocol issues

This document has two parts. The first records the implementation decisions behind the
counted-views Multimmit code, grouped by area, each with its reason and, where it matters, the
alternative it was chosen over. The second lists the problems found in the counted-views
specification while implementing and testing it, as feedback for its author: each with the
specification lines it concerns, the symptom, the impact, and what the code does.

[`STATE_MACHINE.md`](https://github.com/commonwarexyz/monorepo/blob/main/consensus/src/multimmit/docs/STATE_MACHINE.md)
defines the terms and
[`PROPERTIES.md`](https://github.com/commonwarexyz/monorepo/blob/main/consensus/src/multimmit/docs/PROPERTIES.md)
maps each deviation and property to its evidence. Line numbers (`L223-272`) refer to the first
version of the specification's source, `counted-spec.tex`; `v2 L951-956` refers to its second
version. Issue IDs are stable: `I-n` and `I-PD-n` came from the protocol design and its addendum,
`I-Fn`, `I-An`, `I-Cn`, and `I-D2xn` from the foundation, machine, marshal, and
integration-testing work, and `I-Vn` from the adoption of the second version.

## Part 1: implementation decisions

### Scope

- **Part I in full, plus Part II's finality evidence.** Lanes, committee change, acknowledgements
  and inclusion certificates, payments, fences, and handoff are out. Wire types carry the epoch
  and derive chain genesis as `H(GENESIS, epoch, i)` so Part II can add lanes without a format
  break.
- **Replace in place.** The counted-views protocol replaces `consensus::multimmit`. DA votes, DA
  certificates, both threshold sharings and the dealer, novotes, nullifications, chain proposals,
  anchors and positions, two-pass ordering, emitted-frontier floors, and recovery payload
  verification are gone. The module is ALPHA, so formats changed without compatibility shims.
- **Specification over rationale.** Where the specification and its companion design note
  disagree, the specification wins; the note is used only to explain.
- **Specification v2.** The code follows the second version of the specification. It adopts that
  version's rule (ii), late (D26); its view bound `t_max = N theta + 2 delta + eta`, which the code
  already used where the first version had `2 N theta`; its sizing `D = 6N` (D20) and `N = 12` (the
  example's default); and its production regime, in which every producer builds a block every
  `theta`, empty or not (D22). Part 2 opens with the status of each issue against it.

### Protocol design

| ID | Decision | Reason |
|---|---|---|
| D1 | The leader block is `(epoch, v, q = H(Q'), c = C(Q'))` with `C(Q) = H(TIP_HISTORY, C(parent(Q)), Tips(Q))` and `C` of the genesis V-QC derived from the epoch's genesis. A proposal is valid only if `c == C(Q')`. | An L-QC's votes do not pin `base(l)` (I-1). With `c` inside `H(l)`, `n - f` votes for `l` pin `Tips(Q')` and, through the hash chain, every earlier view's tips. Committing to an ordered-prefix accumulator instead would make every voter maintain the linear order. |
| D2 | A floor is an L-QC plus the history record opening its leader block's commitment; resume index `sum_i ht(Tips(Q')_i)`. No sweep beyond the base. | The smallest object that proves a point in the order final. It does not depend on which vote versions the L-QC holds and needs no headers. One view of floor lag does not matter for state sync. |
| D3 | Votes sign per chain only the endorsed tip: `H(VOTE, epoch, v, q, final, F, tips)`. No anchor, no payload paths; the update sequence `k` is not signed. | Signing `k` makes every final distinct, so a QC costs `n - f` pairings instead of one. The anchor adds nothing once a reader needs headers to interpret a vote. Equivocation is objective without `k` (D10). |
| D4 | Update zero, the `k <= 2` default for omitted chains, is the sender's final tips of `v - 1`, whatever `q` is. | Reading a vote never depends on holding a V-QC (I-5). |
| D5 | Consensus reports agreement only: `ViewResolved` (write-once, in view order), `ViewSweep` (monotone), `LeaderFinalized` (L-QC plus opening), `HeaderAccepted` (body hint, unsigned header). Marshal owns `Horiz`, the sweep, output indices, bodies, delivery, and floors. | Settledness needs consensus's first-binding-vote order; the linear order is a pure function of the vectors. This mirrors the simplex/marshal split, and nothing in consensus needs bodies. |
| D6 | Remote catch-up is by L-QC id, history record by commitment, and blocks; determined views after the newest L-QC come only from local consensus. | Remote case-(b) evidence is tens of KB per view and needs headers; the next correct leader's L-QC covers the gap through the commitment chain. |
| D7 | Full acceptance requires `Automaton::verify == true`; adoption on `alpha` endorsers does not. Custody rule: a durable header before endorsing; bodies are marshal's. No recovery re-verification. | An adopted block was verified by at least `alpha - f >= 1` correct validator, so a deterministic `verify` keeps invalid blocks from gathering `alpha`. Lost local bodies are repaired by the retrieval adoption already needs. |
| D8 | A V-QC's tally carries exactly `n - f` finals and, per chain, header paths resolving every recorded tip above the base down to the base height, whichever branch it is on. | The specification's anchor resolution, generalised to tips. |
| D9 | No timer rests on a configured latency. `delta_hat` is measured from own-block round trips (`(RTT - eta) / 2` at the 90th percentile, at least `delta_min`; each sample ends at the network arrival of the completing vote, D24); `theta_hat` is the upper median across chains of each chain's median gap between accepted heights. `D_stop = 2 delta_hat + theta_hat + eta`, `t_late = theta_hat + delta_hat` (D26), `t_max = N theta_hat + 2 delta_hat + eta`, `t_quiet = 2 delta_hat + eta`, and `t_grace` adapts within `[2.5 delta_hat, 2 t_max]`; one configured timer ceiling (default 10 s) caps all of them. Seeds apply only until samples exist. Optimisations (A) and (B) apply only while the view's emission state is undefined. | Validators produce continuously, so round-trip samples arrive steadily and do not depend on the leader; the endorser's wait for its next update is up to `eta`, not delay. A median across chains is robust to fewer than half faulty or stalled producers, and a per-chain median ignores a producer's pauses at its bounds. `t_max` is the specification's value (v2 L193). `t_quiet` must exceed `eta + delta` even where `delta < eta` (I-PTB1). The ceiling bounds what inflated measurements can cost; it is not an estimate. The vote-arrival-after-entry estimator mixes entry spread and proposal time; it fits behind the same `DeltaEstimator` trait. |
| D10 | Objective equivocation quarantines the signer: two finals of one tag with different content; votes for two leader blocks in one tag; two non-final votes of one tag neither below the other; a statement above the signer's final of the tag; two producer headers at one height; two leader blocks for one view. | Each pattern is provable from two signed statements without timing. A height-comparable regression is indistinguishable from reordering and harmless, since readers union endorsements. |
| D11 | The tip lead bound `D + 2N` (PO-9) is enforced: headers more than `D + 2N` above `max(h*, finalized)` are not held and such tips cannot enter a V-QC. | PO-9 is argued from D19, not proved (I-6). |
| D12 | A missing vote update is fetched by (sender, tag), only from the sender, which answers with its latest update of the tag naming every chain. That answer may pass the pending-update bound when a parked update of the sender waits for it, and once read it supersedes the parked updates. | Fetching by sequence number is not live once senders discharge or forget old updates (I-D2c1). Within a tag a correct sender's votes extend each other and each vote is interpreted at its first read, so skipping versions equals delay. |
| D13 | The entry chain is durable: `ViewEntered` also retains the V-QCs on the proof's parent chain above the retired view that no exit, local certificate, earlier ancestor, or root keeps. | A node may enter views on peers' V-QCs whose chains diverge from its own exits at undesignated views; without this a restart past the forwarding publication's discharge finds an orphan nobody serves (I-PD-19). Discharging forwarding by retirement instead would rebroadcast up to `W` V-QCs on restart and still miss ancestors that were never forwarded. |
| D14 | Finality anchoring: a verified floor of view `v > view + J` re-roots the node (`Change::Anchored`): view `v`, root `(Q', opening)`, emission of `v` pinned by the floor, earlier state retired, tags resumed at `v`, and each chain's accepted path snapped to the finalized base when it lacks it. The request is triggered by a restart without an entry parent or by one verified V-QC or L-QC beyond the future-view window. | The specification keeps the surviving chain forever; retention does not, so a node behind its peers' retention needs another way back (I-PD-19). A floor fixes `H(Q')`, `C(Q')`, and `Tips(Q')` without the chain. Counting unverified claimed signers as the trigger was rejected. |
| D15 | Reader-side binding by cap is measured only against `beta_v`; before `beta_v` is defined a vote binds only by being final or declaring the chain, and is never re-evaluated. The sender's cap remains its final-vote trigger. | The earlier fallbacks (the base of the notarised block, own final tips) are unsound (I-PD-20). |
| D16 | Headers of every branch within the band `(floor, max(h*, finalized) + D + 2N]` are held and fetched for resolution; a tip resolves only when its held ancestry links to an accepted header, the origin, or the floor. Off the acceptance buffer, only headers a stored artifact waits for are held. | Keeping only the own branch deadlocks assembly under one equivocating producer (I-PD-21). Holding every in-band header from gossip would let a faulty producer make every node verify and hold headers nobody names. |
| D17 | Own updates and own leader blocks leave the outbox once their view falls below the vote window; resolver custody keeps serving them until retirement. | A node reads no older tag. Tying the duty to retention made the outbox grow with `W` until a validator with a large `W` stopped signing. |
| D18 | Production is pipelined and bounded only by the flow bound. Every own block is issued at its slot, `theta` after the previous one (D22). A build of height `h` needs `h - max(h*, f) <= D` (the specification's flow bound, Ready (i), v2 L312-321), where `f` is its chain's greatest height it knows final (a resolved base or a sweep final). Builds, custody, and signing are pipelined; signatures are reserved in height order over the custodied prefix; own headers are accepted in height order. A declined build takes no height and delays the next by at least `eta`. | A producer at `theta` runs about a round trip of blocks ahead of its final height, and `D = 6N` keeps the flow bound far above that, so it binds only while finality stalls. A faulty producer is held by `D` at the producers and by the acceptance bound of D19 at the receivers. One block in flight capped a chain at one block per build-custody-sign round trip, so views ran to `t_max`; pipelining keeps `theta` sustainable. Using sweep finals as well as bases releases the next window while the view is still open. A finality-relative production bound with a slack option was tried and withdrawn (D27). |
| D19 | Acceptance also requires `h <= finalized + D + N` (I-PTA2). | Without it `h*` and the accepted lead over finality are unbounded under one producer that runs ahead, which breaks PO-9, the artifact-cache budget, and the band. `D >= N` keeps it from refusing a correct producer's block while the validator's final height lags the producer's by at most `N`. |
| D20 | `Window::new` defaults `D = 6N`, the specification's sizing (v2 L189). Ready headers that the flow bound `D` or the finality bound `D + N` refuses are counted once per chain and height (`flow_refusals`, `finality_refusals`). | A receiver checks a producer's block against its own `h*` and final height, which trail the producer's by at least a vote round trip, so `D` must cover the producer's lead plus that lag (I-PTA8). With `D = 2N` the margin was thin: at `n = 50` the top blocks of healthy chains were plausibly refused at receivers whose `h*` lagged, and endorsements of headers a receiver does not hold are no sign of life, so rule (i) declared those chains. The counters make any remaining refusal of healthy blocks visible next to the rule (i) declarations it causes. `D = 6N` widens the held band and the accepted-header budget to `chains * 8N`. |
| D21 | Rule (v) compares first binding tips within the window: a tip at or above `hgt(beta_v) + N` counts as the window's last block (until `beta_v` is resolved, the window above the base this node's votes are capped against). | Producers run past the cap, so healthy senders' first binding tips sit at different heights above it. Every V-QC of the view then has the capped block as its tip and no pin is needed, yet comparing raw heights fired rule (v) in 28% of views at `n = 6` and would fire on some chain in nearly every view at `n = 50`, ending views early and declaring chains not yet capped short of the cap (I-A38). A genuine split below the window end still fires. |
| D22 | Production is uniform and owned by the machine. Every own block, empty or not, is issued at its slot, `theta` after the previous one, and the application answers `Automaton::propose` at once with whatever it has to include. `theta` is the constant `Tuning::production_interval`, default 23 ms (v2 L187, L2267), at least 1 ms. A build issued within `theta` of its slot keeps the slot; one issued later, after the flow bound held the producer, starts a new schedule at once. After a declined build the next is due at `max(slot + theta, now + eta)`. | The specification's design regime is every producer at the pace `theta`, with empty blocks when it has nothing to include; a slower producer is faulty (v2 L134-148), and rule (ii) declares it (D26). A pace the machine owns holds for every application, mocks included, where a deadline handed to the application was a contract each application had to keep. The slot rule keeps late timers and slow builds from stretching the pace, and a released producer resumes one block per `theta` without a burst. `theta_hat` is measured but does not set the pace; it feeds `D_stop`, `t_late`, and `t_max` (D9). An adaptive pace derived from `delta_hat` and capped at `theta_hat` was withdrawn (I-V4). |
| D23 | Withdrawn. Rule (i)'s exemption for a chain at its production bound was an addition beyond the specification; rule (i) applies as specified (v2 L937-950). | With the finality-relative bound gone (D27) the only production bound is the flow bound, which `D = 6N` keeps far above a producer at `theta`, so no healthy chain pauses at a bound the exemption would cover. |
| D24 | A `delta_hat` sample ends at the ingress receipt of the vote that completes `n - f` endorsements of an own block, carried per artifact through the observation path (a V-QC's certified finals take the V-QC's receipt). Retrieval results, own votes, and restored or locally assembled V-QCs use the processing time, as does every other timing input, notably rule (i)'s sign of life. | `delta` is a network quantity. Ending samples at processing made `delta_hat` track this node's ingress, verification and input queues under load (`n = 50`: 1.3-2.5 s against 0.1 s), and every timer scales with it, so overload stretched `D_stop`, `t_max`, `t_quiet`, `t_grace`, and the production pace, feeding the overload. Rule (i) judges silence from what this node has read: dating signs of life at arrival would let a local backlog declare live chains stopped (I-PTB4). |
| D25 | An adoption report carries the adopting node's current `delta_hat` as a fetch grace. Marshal holds the adoption's body fetch, and those of the callers it promotes, until the grace passes or the body is admitted; explicit and finality fetches are never deferred. Fetches issued by adoption and adoptions that completed without one are counted. | `alpha` endorsers already hold the body, and the producer's relay is usually delivering it when adoption fires; an immediate fetch duplicated it, plausibly most of the 85-95 MB/s per node of unexplained egress at `n = 50`. Resolver fetches for one key coalesce, so a promoted caller gains nothing by fetching ahead of the marker. A relay-starved adopted block waits at most one more `delta_hat` (I-A39). |
| D26 | Rule (ii), late (v2 L951-956): `tquorum` is the first time after entry, before the view's final vote, at which all but `f` of the `K` chains are capped or declared at this node; `t_late` after it, every chain still neither is declared at its accepted tip. Capped is the sender's sense, as for rules (i) and (iii): against `base(l)` once this node voted for `l`, else its own final tips. With `K <= f` the rule is inactive. `tquorum` is volatile and unset at entry; a restart counts as entry. `t_late = theta_hat + delta_hat`, capped at the timer ceiling; a view deadline at `tquorum + t_late` wakes the drive while some chain is open. | The specification counts `n - f` chains because each of its processors produces one chain (I-V3). At most `f` chains have faulty producers, so at least `K - f` chains keep pace, and waiting for more would let faulty producers hold the rule off; with `K <= f` no chain is known to keep pace and rule (iii) alone bounds the view. Counting again from a restart only delays the rule and needs no durable state. The specification suggests `t_late` of about `0.8 delta` from the spread of cap arrivals simulated on one deployment, and names `theta + delta` as the value under which, in the model, rule (ii) never fires on a chain at pace after GST (v2 L2400-2417). `delta_hat` is a percentile estimate, not the model's `delta`, and the spread depends on the deployment, so the code takes the model-safe value: a misfire costs a pin, a larger `t_late` only a later cut of a slow chain (I-V5). The sender's sense of capped is the trigger's (v2 L1000-1011). |
| D27 | Withdrawn. The finality-relative production bound and its slack option (`Tuning::production_slack`) were additions beyond the specification; production is bounded only by the flow bound (D18). | On a 50-validator, 13-region AWS deployment (idle, before load) the adaptive pace of D22's earlier form sat at 25 ms at every node: the `theta_hat` cap is self-referential (`theta_hat` measures the capped pace, so any value at or below the median of the uncapped formula is a fixed point and the fleet locked at the bootstrap value), while the uncapped formula gave about 40-50 ms at `delta_hat` of about 200 ms. Twelve blocks at 25 ms span 300 ms, below `2 delta_hat + eta` (about 430 ms), so with slack 0 every producer sat at the finality-relative bound about 53% of the time. Observers that learned finality earlier than the producer declared those chains stopped by rule (i) while others did not: about 1,550 Stopped and 1,600 Split declarations per second cluster-wide, 90% of view ends declared, about 1.6 view timeouts per node per second. The earlier `n = 6` simulation evidence for slack 0 (signed-to-final about 200 ms against about 290 ms at slack `N`) stays an open question for the specification author (I-V6). |

### Types and wire

- `VoteContent` is `(round, leader, final, Endorsement { declared, tips })`; `Endorsement` is the
  per-signer part that tallies vary. A changed chain is named by its tip's chain, with no separate
  chain field. The sequence number is a varint `>= 1`; payload hints per change are at most
  `delta_max` and at most the tip height.
- Tallies share one core: a signer bitmap, a canonical reference signer, and per-signer deviations
  as a flags byte plus sorted tip replacements. Decoding checks the reference without expanding
  entries: the reference signer is the lowest signer without a deviation, and no group of equal
  deviations outnumbers the reference holders or ties them from a lower signer. An L-QC tally
  cannot carry leader deviations and does not store the leader digest; a V-QC tally cannot flip
  finality.
- V-QC resolution paths are sorted, deduplicated, and bounded (count `<= (n - f) K`, length
  `1..=D + 2N`) by the codec; coverage and redundancy are checked by `algebra::validate_vqc`, which
  knows the base. A V-QC's encoding is bounded by `max_vqc_bytes` (default 4 MiB).
- `LeaderBlock` and `Vqc` name their parent as a typed `CertificateId`.
- Genesis is derived from the epoch, not supplied, and has no codec because nothing persists it.
  Namespaces: `_COMMONWARE_CONSENSUS_MULTIMMIT_GENESIS` for chain genesis objects and
  `_COMMONWARE_CONSENSUS_MULTIMMIT_GENESIS_VQC` for the genesis V-QC identifier. Header digests,
  leader-block digests, and certificate identifiers hash the canonical encoding under their own
  namespaces (`_COMMONWARE_CONSENSUS_MULTIMMIT_HEADER`, `..._LEADER_BLOCK`, `..._CERTIFICATE`).
- `Floor` (L-QC plus opening) lives in `types/floor.rs` and is `Artifact::Floor`. It travels only
  as the answer to `RetrievalKey::LatestFloor`, never on a gossip plane; marshal re-exports it.
- `Activity::HeaderAccepted` carries the bare header, so adopted headers, which may have no signed
  copy, are reported too. `Activity::CommitmentsAccepted` was removed: consensus never emitted it.
- Quorums are computed locally from `f`. `alpha` defaults to `f + 1` and is validated in
  `f + 1..=n - 2f`.
- Artifact kinds and wire tags were renumbered densely (ALPHA). `Tuning` replaced the old timeout
  and proposal fields with the counted-views timers and bounds plus `anchor_lag` (default
  `max(W / 2, 2)`, at least 2). Validation requires non-zero `eta` and vote window,
  `0 < delta_min <= delta_initial <= timer_ceiling`, and
  `2 * pending_updates_per_sender * f < max_dependency_waiters`. The old finality-pool budget is
  gone.

### Machine architecture

- **Protocol-agnostic reducer, protocol components.** The reducer owns admission bounds,
  verification jobs, dependency waits, the persistence pipeline, completion correlation, and timer
  deadlines. Protocol behaviour enters only through component hooks; components stage durable facts
  through the machine, wake themselves, arm their own deadlines, and rebuild volatile state at start.
  Per-component inbox queues were rejected: a second queue, when components already own their wake
  points.
- **Dependencies are retrieval keys.** An artifact waits on the first key its component names, the
  key is requested from the resolver, and an artifact that becomes ready provides its keys and
  settles their waiters. Headers and L-QCs name no admission dependency: a missing header parent is
  buffered by the chain layer, and an L-QC verifies against the committee alone.
- **Unverified updates park in the artifact store**, indexed as waiters of
  `Update(sender, tag)`, so caching, deduplication, and retirement are shared with every other
  artifact. A pool-owned queue was rejected as a duplicate.
- **Keys made available outside admission** (a certified final, an orphan whose parent arrived) are
  settled by the forwarding drive, never inside admission, because settling is not reentrant.
- **Retrieval capacity.** Only update and header keys count toward the request bound, tracked by a
  counter; certificate and leader-block keys are always requested, bounded by their waiters.
  Counting every key let unservable vote traffic starve a parent V-QC retrieval forever (I-D2a1). A
  full table marks the state starved; once a slot frees, every bounded key a stored artifact waits
  on is requested. A result that does not provide its key is rejected, one admission refuses is
  cancelled, and either way its waiters are re-settled before the key is requested again.
- **Generation floor.** Nothing, signing requests included, is released before the generation
  barrier is acknowledged; then everything minted at or below the acknowledged cursor is released
  under the new generation. The machine keeps only the generation each durable reservation's
  capability was issued in; a signature completes only under that generation.
- **Anchoring is an in-process restart.** After staging `Anchored` the machine stages the next
  generation, cancels every retrieval, resets the artifact store and completion tables, and rebuilds
  the components, as at startup. Rebuilding the components alone was rejected: a stale build or
  aggregation completion could match a fresh job.
- **Durable occupancy.** A ledger caches each effect's artifact ids; durable references plus promised
  signatures must fit `max_cached_artifacts`, checked before every transition. A component that hits
  capacity parks until the next acknowledgement.
- **Time.** Hooks receive the pass's `Now`; durable state never records it. Each timer family holds
  one volatile deadline, re-armed on recovery.

### Durability

- **Signing slots advance in the reservation event** (`OutboxQueued`): header height = produced +
  1; one leader block per view; per tag, seq increasing, tips higher or identical, declared set
  add-only with `decl` fixed at first declaration, the notarised leader write-once, nothing after
  the final. Every update tip must lie on the durable accepted path, which makes successive tips of
  a tag extend each other.
- **Publications end by durable facts only** (`DischargeFacts` and vote watermarks): an update once
  the tag's watermark reaches `seq + 2` or the tag falls below the vote window; an own leader block
  once its view falls below the vote window; an exit proof once a later view was exited; anything
  of a retired view; an own header once `D` later heights were produced, because the producer signs
  height `p` only while `p - h* <= D`. Every event that moves these facts retires what it ends;
  `ArtifactForwarded` moves none and carries no retirement list. Making `h*` durable was rejected.
- **Superseded reservations retire in the advancing event.** The event that advances a tag's
  watermark to `k` retires every unsigned reservation of the tag with `seq <= k - 2`, live and on
  replay. Holding update `k` until `k - 2` is signed was rejected: it adds a signing and persistence
  round to the final vote's critical path.
- **Certificates are served only after the signatures they carry.** A forwarded or created V-QC or
  L-QC is retained for serving only once every local signature it could carry is durable.
- **Emission records are durable**: `emission[v]` holds the history record of `v - 1` (whose tips
  are `beta_v`) and how it was fixed, written once in consecutive views above the root, extending
  the commitment chain.
- **Retention root.** `RetentionAdvanced` carries the floor view's V-QC on the entry chain with its
  record and is refused unless durable state retains that V-QC. The record is kept even though
  `emission[floor + 1]` holds a base: for a determined view the base need not equal the V-QC's tally
  tips, which proposal validity and the entry-chain walk need.
- **Entry-chain ancestors, origin, and anchored tag** are durable (D13, D14): `ancestors` under
  `Holder::Ancestor`, retired with their view; `origin` per chain, set only by `Anchored`;
  `anchored_tag`, which makes update zero of that tag unknown until the node's next final.
- **Adopted headers are durable as headers.** An adopted header is determined by its parent and
  payload hash, so no signature is held and it does not count toward artifact occupancy.
- **Volatile by design:** `lastsent`, timers, `t_grace`, `heard` and `lastlife` (reset to now),
  `tquorum` (unset, D26), the pool's read order (rebuilt from gossip), per-V-QC history records
  (recomputed from the durable V-QCs above the root).

### Chain layer and production

- One `ChainLayer` owns the header store, accepted tips starting at the origin, pending
  acceptances, `h*`, finalized heights, and `lastlife`; it is rebuilt at start after
  replay, and after an anchor.
- `h*` and adoption read per-header endorser sets: marking walks down from a tip and stops at the
  first header already marked, and a header inserted under held children inherits their endorsers.
  Endorsers are partitioned by the lowest tag through which they endorse the header; `b*` counts
  partitions `<= v`. One full bitmap per tag was rejected: a signer reappears in every tag and each
  tag's first marking walks to the floor.
- The band is `(floor, max(h*, finalized) + D + 2N]` on any branch of another producer's chain;
  the acceptance buffer is the part above the accepted tip and within `D + 2N` of it. A full height
  evicts an unaccepted, unendorsed header with its held descendants; a producer-signed header is
  evicted only for another producer-signed one, so rebuilt branches cannot lock the producer out.
- `linked` is set at insert, on acceptance, and above a raised floor, and propagates to held
  descendants. At or below the origin's height only the origin links, because every other block
  there is off the finalized path.
- Acceptances are staged after every chain pass, in chunks within the journal decode bound, and
  reported when durable. A raised final height wakes acceptance held by the flow bound.
- Each buffered header is validated once, speculatively, before its parent is accepted; chain
  planes start from the accepted tip.
- The producer pipelines (D18): each build, issued at its slot, extends the newest built header
  without waiting for its custody or signature, custody requests overlap, and reservations follow
  the custodied prefix, so a body enters custody before its header and every lower header are
  signed. Reservations staged in one drive share a barrier, and the persistence actor's single
  prefix sync covers every barrier appended while it runs, so durability is coalesced across blocks
  and chains without a separate batching mechanism. Built blocks never reserved are built again
  after a restart; custody is never cancelled, since a built block is never superseded within a
  generation.
- The machine world also holds each node to at most one block per millisecond: with a
  zero-latency network consensus otherwise completes views in zero simulated time, which the
  world's quiescence check reads as a livelock.
- The production interval is configured: `Tuning::production_interval` is the pace `theta`, a
  constant defaulting to 23 ms (D22); `theta_hat` is measured and feeds the timers (D9).
- After a restart the producer recalls every own header still reserved or published and not yet
  final (`AppJob::Recall`: the application is asked for the body again; the outcome is not
  reported, and a missing body is not fatal). Marshal's relay serves own bodies from staging, which
  a restart loses, and relearns them from these requests; without them a header reserved or signed
  before a crash is published without its body, no peer can verify it, and the chain stops for
  good. Pipelining made this likely (up to `D` headers are in flight); the 6-node smoke
  run hit it on the first kill and restart. A custody check was rejected: its failure is fatal,
  and marshal may legitimately no longer hold an old body.
- The voter parents the spans of local work (builds, custody checks, signatures, journal barriers)
  on the current round and links them to the span that issued them. Each is issued from the
  completion of earlier local work, so nesting them made the span tree as deep as the number of
  blocks a producer built; closing such a chain recurses once per link and overflowed the stack.
  Witness:
  `multimmit::tests::local_work_spans_stay_shallow_however_many_blocks_producers_build`.
- Telemetry: `Inspection::view_ends` counts the views this node sent a final vote for by why they
  ended (every chain capped, `t_max`, or another declaration) with their total length.
- Parked updates woken while every verification job slot is taken stay parked and are checked
  again when a verification completes. One completion can read several updates, each waking parked
  ones with a job of its own, so without the deferral the machine exceeded
  `max_inflight_verifications` and the verifier stopped ingress (seen once in a 6-node soak run).
  Witness:
  `multimmit::machine::tests::pool::updates_woken_by_one_verification_stay_within_the_verification_job_bound`.

### Votes

- **Pool.** Per (tag, sender) a reader keeps the highest read seq, the last two read contents, and
  the first binding tip per chain; per tag, the voters of each leader block and the senders whose
  final was read. A read update leaves the artifact store at once; keeping read updates would fill
  the artifact cache at `n / eta` per second.
- **Update zero on the reader side** is the sender's read final of `v - 1`; while it is unread, the
  update parks on the sender's vote of `v - 1`. An update naming every chain needs no predecessor.
  An update whose predecessor's tag lies below the read window is refused rather than parked.
- **Pending bound.** At most `pending_updates_per_sender` unread updates per sender; beyond it only
  a full update that a parked update of that sender waits for is admitted. Exempting every full
  update let one sender fill the global dependency-waiter budget.
- **Tip resolution.** For each changed tip not held, payload hashes rebuild a path from a held object
  (the sender's previous tip first). A tip in the band that is not linked waits for the first
  missing header below it, one parent at a time (D16); a tip outside the band or on a peer's copy of
  the own chain is read unresolved.
- **Binding base** is `beta_v` only (D15). The sender keeps its own cap base (`base(l)`, else its
  final tips) for the final-vote trigger.
- **Sending.** One quantum evaluates the view handlers in order and requeues after a send. The vote
  for `l` and every final go out at once; repeated votes wait for `eta` and only on a change. A
  pre-vote equal to update zero is never sent. Payload hints cover the blocks above the tip of
  update `k - 2`, at most `delta_max` (I-B1).
- **A final vote names every chain**, so a reader that lost updates `k - 1` and `k - 2` still reads
  it and, through update zero, the next tag.
- **Restart.** The own latest vote of each live tag is re-read from its watermark; by tip
  monotonicity it endorses everything earlier votes did. Peers' votes return through gossip.

### Views and timing

- The view layer holds only volatile state; `proposed`, `notarised`, and `finalsent` are projections
  of durable fields. A restart counts as entering the current view at the restart time.
- The vote tag is `last_final.view + 1`, and `F` belongs to the tag. A declaration records the
  accepted tip at first firing, not at send time. A declared chain is endorsed at its recorded block
  without a header walk, so votes continue after retention drops the headers below the tip.
- Proposals are kept for views `v - 1..=v + 1` from `lead(view)` only. A block of `v - 1` that
  arrives after entry only widens `t_grace`.
- On restart, the leader block this node voted for is requested again, so `base(l)` is restored.
- Timers are fixed at entry. `t_grace` persists across views, clamped at entry; it doubles once per
  view on a valid proposal after a leaderless final and halves once per vote for a leader block,
  when the vote is reserved (a vote held back by persistence does not halve it again).
- View and liveness deadlines are armed only when earlier than the held one; the update deadline is
  exact.
- `heard(q)` is updated by every admitted signed artifact; entries start at the start time, so (B)
  does not fire right after a restart. (B) is decided once at entry; a valid proposal already held
  is voted for before (A) or (B).

### V-QCs

- The V-QC store is volatile and holds each V-QC once, as the stored artifact; a leader's proposal
  clones its parent from it. Durable per-V-QC records were rejected; a restart recomputes them from
  the durable V-QCs above the root.
- Admission waits for the parent, holds only V-QCs of the parent's next view that `validate_vqc`
  accepts, and caps a view at `n` V-QCs unless an artifact or a durable orphan waits on one. On
  restart a durable V-QC whose parent lies at or below the retired view and is not the root is
  dropped, not requested: no peer can serve it.
- Assembly is greedy over the earliest read finals whose tips all resolve, with canonical paths
  (from the ancestor at base height, which for another branch endorses nothing). While the
  encoding exceeds `max_vqc_bytes`, the costliest vote is swapped for the next candidate. A final
  the assembler cannot resolve is omitted; recording it as endorsing nothing is unsafe.
- Forwarding: each view's first held V-QC, after its unforwarded ancestors whose duty has not
  ended, only for views `>= current - 1`.

### Emission and L-QCs

- `ViewResolved(u)` is derived from `emission[u]` and `emission[u + 1]`. Case (a) at `p` writes
  `emission[u0 + 1 ..= p]`, all `Pinned { p, lqc }`; case (b) at `v` writes `emission[v]`
  `Determined`. A disagreement between the cases fails the step.
- Case (a) waits for an L-QC so the resolution can name it; a received L-QC counts like `n - f` read
  votes. A second L-QC of a view is dropped from the store.
- Case (b) groups the greatest defined view's finals by their per-chain reach above `beta`; a group
  of `n - f` is `G`.
- L-QC assembly keeps per (view, sender) the latest signed vote for a leader block, a final never
  replaced; it selects finals first, then by signer, and aggregates one at a time.
- One drive quantum: stage an assembled L-QC; else finalize the next L-QC; else determine the next
  view; else start an aggregation and report the sweep. Reports attach to the newest staged batch
  so they keep their order. Each `LeaderFinalized` also replaces the floor served under
  `LatestFloor`.
- An L-QC whose view state is undefined and whose parent is missing keeps the parent requested.
- The sweep is incremental, so a vote read costs work proportional to what it changed, not
  `O(K n N)` walks. `b*` resumes from the reported `b*`, since endorsements only accumulate. Each
  first binding tip is classified once by its window reach (`algebra::Bindings`), counted per
  distinct reach, and retried only when its chain's header revision changes. A chain's settledness
  is re-evaluated only when its `b*`, its tally, or a retried tip changed. The pool keeps
  first binding tips per (tag, chain) in read order for this. The header store answers ancestry by
  height wherever every height in range holds one header, and walks parents only across a fork.
  V-QC assembly resolves tips only once `n - f` signed final votes are read. Witnesses: the
  differential tests `sweeps_match_a_from_scratch_evaluation_as_votes_and_headers_arrive` and
  `ancestry_by_height_matches_walking_parents`, and the algebra campaign against
  `reference::settled`. On the `vote_stream` bench (`n = 50`, `N = 32`) reading an update fell
  from about 170 us to about 21 us.

### Retention

- The floor is `min(finalized - W, view - 2)`, raised when a finalization is reported, at entry,
  and at start. Using `vote_window` as `W` was rejected: it retires state the emission walk needs.
- Retained heights per chain are `min(base of emission[retired + 1], accepted tip)`, falling back
  to the origin; the tip is always kept.
- The resolver retires view-scoped artifacts and retrievals on `Prune(through)` (keeping the newest
  L-QC and the newest floor) and headers only on `SettleHeaders{chain, height}`, sent whenever a
  chain's header floor rises. The machine sends no `Cancel` for pruned jobs.

### Accountability

- Per (tag, signer) within the tag window, the greatest authenticated statement is kept and each
  later one compared. Keeping every statement was rejected as unbounded per faulty signer.
- Two non-final votes of one tag are incomparable whenever neither is below the other (higher tips
  with fewer declared chains included); a leaderless vote is below the same vote naming a leader.
- Evidence comes from read updates, superseded updates (verified only when their rebuilt content
  already conflicts), V-QC and L-QC tallies, headers, and leader blocks. Own votes are never
  checked. Proofs drain once per signer into a quarantine capability.

### Runtime actors

- **Resolver.** View-ordered key set plus per-chain height maps, so pruning visits only what it
  removes. Retained certificates are identified on the codec pool; the canonical encoding is cached
  for serving. Update keys are fetched only from their signer; header, certificate, and leader-block
  keys from any peer (the request site has no sender to target). The newest floor is kept under
  `LatestFloor`, replaced only by a higher view, and always fetched from peers.
- **Verifier.** No verified-vote cache: with tips-only content a QC verifies with one pairing per
  distinct content. L-QCs verify on the bulk pool (finality, not view progress); floors stay on the
  critical pool. A panicking worker settles every item of its job invalid.
- **Ingress.** No tag window: ingress must decode to read a tag, and the machine rejects
  out-of-window tags before hashing. Ingress drops updates whose sender is not their signer and
  frames whose decoding panics (counted). The voter's observation queue is sized by the ingress
  credit, so a credited cohort is never refused.
- **Egress.** Each update is one broadcast publication retired by discharge. Repairs start no
  earlier than an eightieth of the timer ceiling, well above `eta`. Publication retries,
  the heartbeat, and the retrieval timeout recover lost messages rather than track the delay, so
  they scale with the ceiling (a fifth, a half, and a fifth of it).
- **Voter.** Chain planes are seeded from each chain's accepted tip (`ChainCommand::Accepted`).
  Telemetry counts adoptions and resolutions by kind, records V-QC and L-QC formation latency from
  view entry, and exposes `delta_hat`, `theta_hat`, `t_grace`, parked updates, and declarations
  per rule.
- **Voter telemetry for decomposing latency.** The voter thread is the single place every vote,
  header, and certificate is processed, so its time and queues are attributed rather than summed:
  per core step by input kind (`input_processing{kind}`), per machine quantum by the component it
  drove (`work_processing{component}`, where `pool` is vote reading, `chain` header acceptance,
  `emission` the sweep), and core queueing from admission to the completing step by lane
  (`input_wait{lane}`), next to the ingress hand-off (`observation_wait`). Together they split the
  own-block round trip `delta_hat` measures into network delay and local queueing. Egress counts
  messages and bytes by artifact kind as well as by plane, and records each published update's
  and each assembled V-QC's and L-QC's encoded size separately. The machine keeps cumulative
  counters (declaration contexts, undetermined pinned boundaries) in the same
  way as view ends, and the voter exports their increments, so no per-event channel leaves the
  machine. These cost about 400 more series per node; the footprint test's budget records it.
- **Declaration context.** Each declared chain is counted by rule and by three facts known at the
  declaration (capped, silent for `D_stop`, held back by the acceptance bounds) with the summed
  silence per rule. A declaration of a chain that was alive or held back is the signature of rule
  (i) misfiring on a healthy producer (I-PTA8); held back means the chain's next height is the
  greatest one the bounds refused (D20). The per-declaration height and chain are left out to
  keep series independent of `K`.
- **Local completion lane.** The voter admits application, crypto, chain-plane, and verification
  completions only while the lane has room beyond one slot per outbox effect. Publication reports
  an effect's first delivery without that check, so the reserve is what keeps it from overflowing
  the lane, which is fatal. A 6-node local run under CPU saturation, with producers pipelining a
  window ahead, filled the lane with gated completions and stopped a voter this way.
  Witness: `multimmit::machine::core_state::tests::gated_local_completions_leave_room_for_every_outbox_delivery`.

### Marshal

- **Targets.** `ViewResolved` and `LeaderFinalized` become synchronization targets
  `(view, commitment, record, proofs)` merged to the highest view. Same-view targets pool their
  opening; different commitments at one view fail the pass. An L-QC of view `v` targets view
  `v - 1`; a pass selects each retained L-QC right after recording the opening it pins.
- **Checkpoint view.** The checkpoint records the resolved view; openings advance it by one, floors
  set it to the L-QC view minus one, and it never regresses.
- **Gap repair** walks the history chain back from the target commitment, one view per record,
  checking before each fetch that it has not passed the synchronized view, and fails unless it
  reaches the synchronized commitment there. Openings consensus reports are staged in the catalog,
  and backfill checks the catalog's history segment before peers.
- **Order generation** uses `algebra::Horiz` and `algebra::Sweep` lazily; one ancestry walk covers
  each window, and a walk that leaves the lower frontier fails closed.
- **Open sweep.** The latest `ViewSweep` is retained; a same-view retreat, or a same-view sweep
  naming another block at a retained height, fails closed. A sweep that does not cover the emitted
  prefix (possible after a consensus restart) is skipped as stale.
- **Floors** are base-only: epoch, exactly `n - f` signers, opening hash, a view not before the
  state's, and tips dominating both frontiers; the aggregate is checked by `LqcVerifier`. An install
  requires the checkpoint's ordered and emitted frontiers to equal the opening's tips and never
  reuses a history ordinal a crashed commit left.
- **Adopted bodies.** `HeaderAccepted { adopted: true }` registers a background fetch that lives until
  the block is admitted or retired by a floor; such markers never displace callers' waiters.
- **Router pressure.** `ViewResolved` reports are retained in order up to 1,024 (older and duplicate
  ones dropped at once, the oldest beyond the bound); gap repair recovers any opening dropped. The
  newest `LeaderFinalized` and the furthest `ViewSweep` are kept; hints drop.
- **Catalog walks** run on the read lane in bounded steps and resume across turns, so cuts and
  commands interleave with long history walks.

### Test support and benchmarks

- **Machine driver.** Owns the machine, a symbolic journal (append, acknowledge, crash, restore,
  replay), and a manual clock; executors are symbolic and compose.
- **World** (`machine/testing/world`): every participant runs the production machine with real
  signatures; a seeded or byte-driven schedule reorders, duplicates, drops, and delays messages,
  answers retrievals after network latency, and crashes nodes at journal cuts. Oracles read only
  published statements and reported activity. Symbolic verification is used only without Byzantine
  signers, since an update rebuilt over a twin's other half yields content its signer never signed.
- **Twins** (`twins/`): a Byzantine identity runs as two halves behind a split router; scripted
  cases cover each equivocation pattern, producer splits at `n = 6` and `n = 11`, and a silent
  leader; randomized cases cover every identity at `n = 6` and pairs at `n = 11`.
- **Clusters** (`mocks/cluster.rs`, `tests.rs`): every engine runs with its own marshal and an
  application that answers `verify` only once marshal holds the body durably, so a node that never
  receives a body must adopt. Oracles check that delivered streams agree index by index and that
  every node resolves each view to one commitment.
- **Fixtures.** `mocks::Scenario` builds admissible V-QCs, updates, and floors from the algebra.
- **Fuzz.** `multimmit_algebra` and `multimmit_marshal` compare against the reference and an
  explicit enumeration; `multimmit_machine` and `multimmit_twins` drive the world and twins;
  `multimmit_engine_{minpk,minsig}` drive clusters with cross-node agreement checks.
- **Benchmarks** follow `module::operation/key=value` naming: signature batches, tallies,
  aggregates, assembly, the algebra, machine view cycles and replay, marshal staging, and whole-engine
  block and view throughput. `consensus/tests/multimmit_allocations.rs` budgets hot-path
  allocations.
- **Vote stream** (`test_utils/bench/stream.rs`): one validator of `n = 50` in the paced regime
  (`N = 12`, `theta = eta = 25 ms`, one header per chain per tick) reads every peer's update,
  header, and V-QC. Artifacts are replayed decoded from their wire encoding and identified in
  advance, as ingress hands them over, so the figures are voter-loop work; in-memory signatures
  would re-compress a curve point on every encoding.

## Part 2: protocol issues for the author

Each entry gives the specification lines, the symptom, the impact, and what the implementation does.
Entries marked **question** need an answer from the author. Line numbers refer to the first version
of the specification unless marked v2.

### Status against specification v2

The second version of the specification (v2) changes one rule, rule (ii), and retunes the
parameters. Against the entries below:

- **Adopted:** I-PTA5. v2's `t_max = N theta + 2 delta + eta` is the code's view bound, and v2 now
  calls it a backstop and puts the steady-state view nearer `N theta - delta` (v2 L193,
  L2433-2452).
- **Moot:** I-A11. v2 deletes the carried-over rule and `lastda`; its `tquorum` is per-view state,
  which the code keeps volatile (D26).
- **Settled by following v2:** I-2 and I-PTA6. v2 makes production at the pace `theta`, with empty
  blocks when idle, the design regime and calls a slower producer faulty (v2 L134-148). The code
  now paces every block at the constant `theta` of v2 (D22; I-V4).
- **Partly addressed:** I-PTA7: the carried-over declarations are gone, rule (i) applies as
  specified (v2 L937-950; D23 withdrawn), and production is bounded only by the flow bound, so a
  producer at `theta` does not pause at a bound. I-PTA8: v2 sizes `D = 6N` (v2 L189, L2279-2298),
  which the code adopts, without stating `D >= N + lag`. I-16: v2 merges the two genesis
  symbols but not their hashes (I-V1).
- **Not adopted:** I-PTA2. `Ready` keeps only the flow and pacing conditions (v2 L312-321), which
  the code follows for production (D18); the acceptance bound of D19 is the code's own.
- **Open, text unchanged:** I-1 and I-PD-19 (the L-QC and `R` are unchanged; v2 L2795-2797 adds
  only a cross-reference), I-5 and I-13 (the update's sequence number is renamed `seq`; the signed
  content still has anchors and paths), I-D2c1 (still by sequence number, v2 L530), I-PD-20 and I-8
  ("capped either way", v2 L1010-1011), I-PD-21, I-6 (v2 L606 still gives the common-case size,
  19 KB at `N = 12`, `n = 50`), I-9, I-10, I-A12, I-A13, I-PTB2, I-PTB3, I-PTA3, I-A10, I-A39,
  I-15.
- **Open, with more at stake:** I-A38, since v2 relies on rule (v) to resolve the tips that rule
  (ii) cuts (v2 L991-994); I-PTB4, since `t_late`, `t_max`, and `t_grace` all scale with the
  measured delay. I-PTB1 stands: v2 keeps `t_quiet = 2 delta` next to its own requirement
  `t_quiet > eta + delta` (I-V2).
- **New:** I-V1 to I-V6, under [Specification v2](#specification-v2).

### Finality evidence and catch-up

**I-1: an L-QC alone does not pin the tips it finalizes.** L2688-2709, L411-427.
- Symptom: `base(l)_i = Tips(Q')_i` depends on `Q'` and its whole parent chain. A vote for `l`
  anchors on the voter's own accepted path, so a voter stranded on a losing branch, or one that
  declared a chain below the base, names a different anchor. `base_i` has at least `n - 3f` endorsers
  in `Q'`, so at least `n - 4f` correct validators hold it; an L-QC may omit `f` of them and `f`
  faulty signers can name any object at the same height, so a verifier cannot tell `n - 5f >= 1`
  honest anchors from `f` fakes.
- Impact: Part II's `R` needs the whole V-QC chain to compute `Ord` of the reference; the L-QC is not
  a self-contained finality certificate.
- Resolution: D1. The leader block carries `c = C(Q')`, a hash chain over every view's tips, so an
  L-QC plus the record opening `c` is a verifiable finalization certificate and a catch-up anchor
  (I-PD-19). This also lets the late final build `l` without a copy of it and keeps designation
  checkable from the parent chain. Suggest adding `c` to the specification.

**I-PD-19: no catch-up beyond retention and no durability rule for V-QC state.** L865-896,
L881-896, L1116-1150.
- Symptom: (1) The specification keeps the surviving chain forever ("what a processor behind on
  views retrieves"); any bounded retention leaves a node more than `W` views behind unable to hold
  any V-QC, so it never enters a view again, and its stale `h*` keeps current tips outside what it
  may hold. (2) A processor holds a V-QC "only with its parent chain", a volatile rule; persisting
  only the V-QC each view was entered on does not persist a chain, because entries can be on V-QCs
  whose parents diverge at undesignated views (L870-879). After a restart such a node held an orphan
  no peer still served and stalled.
- Impact: liveness of restarted and lagging nodes; one more crash halts an `n = 6` committee.
- Resolution: D13 makes the entry chain durable. D14 adds finality anchoring: a verified floor more
  than `J` views ahead re-roots the node, tags resume above everything signed, and each chain's
  accepted path snaps to the finalized base when it lacks it. Switching branch below a finalized
  base is safe: every window block of any later base extends the finalized base, which the old path
  did not contain, so none of the node's old votes endorses one; and snapping only happens across a
  tag boundary, where no pattern of D10 can match. It also unstrands a correct processor left on a
  losing branch of an equivocating producer, which the specification strands permanently.
  **Question:** state that the entry chain down to the retention root is durable, and adopt
  anchoring (or an equivalent) as the catch-up mechanism.

**I-3: determined views have no portable finality object.** L757-795.
- Symptom: a view resolved by case (b) has no L-QC.
- Impact: floors and remote catch-up exist only at pinned views; the gap is the run of faulty
  leaders (at most `f + 1` views after GST).
- Resolution: accepted. The next L-QC's commitment chain opens through determined views.

**I-4: case-(b) finality evidence is large and needs headers.** L2695-2703.
- Symptom: `R = (v, bot, G, P)` is `n - f` finals plus `n - f` votes plus resolutions, tens of KB,
  and evaluating it needs headers.
- Resolution: kept local (D6).

**I-15: emission order across a gap is unstated.** L1143-1150.
- Symptom: "for each view `<= v` in order" never states that `sigma_v = sigma_{v-1} ++
  Horiz(beta_{v-1}, beta_v)` also holds in case (a) when `state(v - 1)` is defined, nor how to walk a
  gap when it is not.
- Resolution: case (a) at `v` walks `Q'`'s parent chain from the greatest defined view to `v - 1` and
  fixes each base on the way (Lemma inv (i)).

**I-A21: pinning needs an L-QC object.** L757-805.
- Symptom: a resolution names its L-QC so marshal can fetch it. Votes for `l` read only inside V-QCs
  carry no individual signatures and cannot be re-aggregated.
- Impact: a node that saw `n - f` votes for `l` only through V-QCs waits for case (b) or a later
  L-QC.
- Resolution: accepted. Not taken: a V-QC whose `n - f` finals all vote for `l` carries exactly an
  L-QC's aggregate and could be converted.

**I-A22: case (a) needs the parent chain down to the greatest defined view.** L757-805.
- If `Q'`'s chain is not held down to the greatest defined view, nothing is pinned; the L-QC waits
  and its parent stays requested.

**I-A23: what to do when the cases disagree.** Lemma inv, L1452-1508.
- Disagreement is only reachable beyond `f` faults. The implementation fails the step (fatal)
  rather than continuing on either answer.

### Votes, updates, and retrieval

**I-5: the unsigned `k` and its default.** L456-470, L480-487.
- Symptom: signing `k` makes every final distinct, so a QC can no longer be verified with one
  pairing for equal contents; objective equivocation does not need `k` (D10). The `k = 1` default
  for votes for `l` makes reading a vote depend on holding `Q'`, and the default "sender's final for
  `v - 1`" needs the reader to hold a final whose sequence number it does not know (I-A5).
- Resolution: `k` is transport-only (D3); update zero is always the sender's final tips of `v - 1`
  (D4); a reader parks on the sender's vote of `v - 1` until the final is read.

**I-D2c1: retrieval by sequence number is not live.** L500-511, L1151-1166.
- Symptom: a missing update "is requested from `p_j` by sequence number". A sender that discharged
  or, across a restart, forgot update `k - 1` cannot answer, so a reader that missed two consecutive
  updates parks every later partial update of the tag; the parked updates fill the per-sender bound
  and block newer ones. Found by the engine fuzz: after reloads and a full heal all six nodes stayed
  in view 1.
- Impact: a liveness stall from ordinary message loss plus restarts.
- Resolution: D12. Retrieval is by (sender, tag), answered with the sender's latest update of the
  tag in full form, which supersedes the parked updates. **Suggest** the specification say so: a
  correct sender need retain only its latest statement per tag.

**I-13: anchors and payload paths in signed content are redundant.** L344-353.
- Once a recipient must hold headers to read a vote, the anchor adds nothing, and payload paths make
  signing cost grow with the path. Resolution: sign tips only (D3).

**I-F1: unresolvable faulty tips under tips-only votes.** L757-805, L700-702.
- The rule for a tip the reader can never resolve is unstated. Resolution: such a tip endorses
  nothing for `Tips` and `b*`, counts as beyond for `gamma`, and makes `Det` undefined for that vote.

**I-A7: losing updates `k - 1` and `k - 2`.** L473-504.
- Under retrieval by sequence number a tag stalls until the sender's next all-chain update. With
  D12 a reader fetches the sender's latest full update instead; a final vote also names every chain.

**I-A30: two superseded unsigned updates.**
- An update superseded before it is signed is never published. If updates `k` and `k + 1` of a tag
  are both superseded unsigned, a reader holding neither reads `k + 2` only through retrieval (D12)
  or the final. Only reachable with four reservations of one tag within one signing latency.

**I-A8: rebuild cost of payload hints.**
- Rebuilding a change from payload hashes tries held objects below the tip: worst case
  `(n + 1) m (m + 1) / 2` hashes per change for `m = delta_max`, paid only for verified updates
  whose tip is not held.

**I-A10: the initial pre-vote carries nothing.** Algorithm 2, line 8.
- Read literally, the first pre-vote goes out at `t = 0` equal to update zero. Skipped.

**I-A16: finals read from a V-QC have no sequence number.** L556-561.
- Recorded at the reader's current sequence number for the sender, so later updates of the tag are
  refused and the next tag's parked updates wake.

**I-B1: the overlap `kappa` does not cover one lost update.** L496-510.
- Symptom: `epsilon(i)` holds the last `k_i + kappa` blocks, `k_i` the advance since update
  `seq - 1`. A reader that lost update `seq - 1` holds the sender's tip of update `seq - 2`, which
  lies `k_i + k'_i` below the tip (`k'_i` the lost update's advance); with `k'_i > kappa`, after a
  burst, it rebuilds nothing and fetches. In the paced regime `k'_i = 1`, so `kappa = 2` sends one
  hash per chain more than any reader needs, about a quarter of a non-final update at `n = 50`,
  and a final vote naming a chain whose tip stood still still carries two hashes.
- Resolution: `epsilon(i)` holds the blocks above the tip of update `seq - 2` (at most
  `delta_max`), which is exactly what the sentence "one lost update is covered by the next" needs
  and also covers update `seq - 1`. **Suggest** the specification define `epsilon(i)` that way.

### Unbounded votes, headers, and V-QC size

**I-6: votes are not capped, so V-QC size is unbounded adversarially.** L361-365, L571-573,
L603-628.
- Symptom: "about `32NK` bytes" is the common case. Resolution paths for correct voters stranded on
  branches of equivocating producers, and for off-base tips (I-F3), add arbitrary size, and votes
  are "not capped", so tips can sit `D` or more above the base.
- Resolution: `max_vqc_bytes` with assembler substitution (an assembler always has `n - f` correct
  finals); tips more than `D + 2N` above `max(h*, finalized)` are not held and cannot be recorded
  (I-F4), which is safe only if PO-9 holds: a correct voter's tip stays within `D + 2N` of `beta_v`.
  **Question:** prove PO-9 or give the right bound.

**I-PD-21: header retention is load-bearing for liveness but only implicit.** L473-476, L531-537,
L603-628, L1151-1166.
- Symptom: the specification says a recipient holds the headers "specified by any vote it has
  read" and that the assembler's headers "cover every correct sender's path", but never as a
  requirement with a bound. An implementation that keeps only its own accepted branch above its tip
  never resolves a final on the other branch of an equivocating producer, so when one producer
  splits the correct processors so that no branch holds `n - f` of them (any split at
  `n = 5f + 1, f = 1`; a 5/4 split at `n = 11`), no V-QC ever forms. One faulty producer stalls
  consensus.
- Resolution: D16 holds and fetches every branch within the band, one parent at a time, and counts
  a tip resolved only when linked. The assembler omits a final it cannot resolve; recording it as
  "endorsing nothing" is unsafe, because a V-QC must fix what each message endorses from the V-QC
  and its chain alone, and an assembler could then drop correct endorsements below `b*` (Lemma
  safe). **Suggest** stating the requirement with its bound: per chain, headers of every branch in
  `(base of the oldest live view, h* + D + 2N]`, at most one per endorsing processor per height,
  retrievable from the sender or any endorser; and that an assembler must omit, never approximate,
  a message it cannot resolve.

**I-F2: `Det` with exactly `n - f` messages.** L753-777.
- Observation: with `|G| = n - f`, a chain is determined iff every message of `G` has the same
  window top, a cheap incremental check.

**I-12: assembly is underspecified.** L865-872.
- "A fixed rule, say greedily" plus the resolution wait lets assemblers produce different V-QCs for
  one view: safe, but it costs forwarding and up to `n` off-chain V-QCs per view. Resolution: greedy
  over the earliest resolvable finals; off-chain V-QCs bounded and discarded.

**I-A17: forwarding old ancestors.** L870-879.
- Ancestors below `current - 1` are not forwarded, because their publication duty has durably
  ended; peers retrieve them by id.

**I-A18: discard timing.** L881-896.
- Discard fires when a held V-QC designates a block that already has `n - f` pool votes; a block
  reaching `n - f` later is caught when case (a) discards. An off-chain V-QC arriving after the
  discard can be held again, bounded by `n` per view.

**I-A20: the compact V-QC form is not implemented.** L577-583.
- V-QCs travel in full form, which also sizes the durable entry-chain ancestors (I-A32).

### Pool, binding, declarations, and settledness

**I-PD-20 (I-D2b1): "binding counts it as capped either way" is unsound.** L693-702, L962-975,
L1251-1290, L1365-1388.
- Symptom: the third form of binding in Lemma binding is relative to the `beta` settledness is
  measured against. A reader that judges a vote capped against another base below `beta_v` (its own
  final tips, or the base of the block it voted for) counts a sender that can still extend its tip
  as committed. Counterexample at `n = 6, f = 1` (bound `n - 4f - 1 = 1`): reader `p`'s final tip on
  chain `i` is `x_{h-1}` while `beta_{v,i} = x_h`. Four correct senders send updates with tip
  `x_{h+N-1}` and a fifth endorses it, so `b*_i = x_{h+N-1}`. Judged capped against `x_{h-1}`, the four
  are first binding there; with `p`'s own declared vote `phi_i = 5`, `gamma_i = 0`, so
  `gamma + (n - phi) = 1 <= 1` and `p`'s sweep skips position `N`. The senders then accept
  `x_{h+N}` and their finals endorse it; any V-QC's five finals contain three of them, so
  `Tips(Q)_i = x_{h+N}` and `Horiz` fills the position `p` skipped. Observed in a twins run as two
  correct nodes' delivered orders diverging.
- Impact: safety of the delivered order.
- Resolution: D15. Binding by cap is measured only against `beta_v`; before `beta_v` is defined a
  vote binds only by being final or declaring the chain. This also answers I-8. Cost: settledness of
  a chain whose capped votes arrived before `beta_v` waits for the finals. **Question:** adopt this
  definition (or re-evaluation of retained content against `beta_v` once it is defined).

**I-8: two definitions of "capped".** L962-975, L930-937.
- Capped is relative to the sender's base on one side and the reader's base on the other; rule (v)
  says "the base of the vote `p_j` would send". Answered by I-PD-20 for the reader; the sender's
  definition stays a trigger.

**I-7: pool memory.** L676-690, L2112.
- "Interpret each vote once at first read" plus "endorsements for `v` count tags `<= v`" needs
  per-block, per-tag endorser sets, and "the pool keeps every vote" is unbounded. Resolution:
  per-tag endorser partitions; tags retire after the view resolves and leaves the window.

**I-F5: easy to mix tags.** L693-702.
- `phi` and `gamma` count votes tagged `v`; `b*` counts tags `<= v`.

**I-9: "declare every chain" overwrites `decl`.** L1133-1137 (iv), L2470-2476 (A), L2487-2496 (B).
- Resolution: add-only, `decl` fixed at first firing; Lemma binding needs it.

**I-A15: rule (v) heights.** L930-937.
- "Blocks `b < b'`" is read as `b'` strictly higher, on any branch. Rule (v) only ends views, so a
  looser reading only ends them earlier.

**I-A38: rule (v) reads endorsed tips beyond the window.** L927-935, against L657-672 and
L962-968.
- Symptom: rule (v) compares the endorsed tips of first binding votes as they stand. `Tips(Q)`
  (L657-672) counts a tip above the window as endorsing the window's last block, and L962-968
  notes that endorsed tips exceed the cap by up to the chain layer's lead. Senders whose tips
  differ only above the cap therefore agree on the chain's tip in every V-QC of the view, which is
  not the situation the rule's rationale describes, yet a literal reading fires the rule.
- Impact: with producers running ahead of the view, healthy views end by rule (v) instead of on
  count (28% of views at `n = 6`; near-certain on some chain per view at large `n`). Each such
  view declares every chain at the node's current tip, so a chain not yet capped there is declared
  short of the cap at a height other nodes do not share, which leaves the view undetermined and
  costs a pin, the "loss for nothing" the rationale of measures (A) and (B) warns about
  (L2450-2460).
- Resolution: D21. **Question:** read "endorsed tip" in rule (v) as "endorsed tip resolved to the
  window of the base", consistent with `Tips` and L962-968.

**I-A11 (moot in v2): rule (ii) after a restart.** L898-955.
- `lastda` reset to the restart time, so the first version's rule (ii) carried nothing over in the
  view a node restarted in. Conservative; rule (i) still declares stopped chains.
- v2 deletes that rule and `lastda`. Its rule (ii) counts from `tquorum`, which the code unsets at
  entry and at a restart (D26); a restart only delays it.

### Timing

**I-10: `t_grace` may exceed `t_max`.** L2528-2544, L1678-1692.
- `t_grace` can reach its cap above `t_max`; such a view lasts `t_grace` with every chain
  declared. Resolution: view length `max(t_max, t_grace)`; after GST `t_grace` halves back. The
  cap is `2 t_max` (I-PTB2), so such a view lasts at most twice the view bound.

**I-A12: empty grace range.** L2528-2544.
- When `2.5 delta_hat > 2 Delta` the range is empty. With the cap at `2 t_max >= 4 delta_hat`
  (I-PTB2) it cannot be; the timer ceiling clamps both ends alike.

**I-A13: halving on the late final.** L2528-2544 vs Algorithm 2 handler 9.
- Whether the late final for a designated block halves `t_grace` is unstated; only the handler-4 vote
  halves it, once.

**I-A9: `lastvote` after a restart.** L1015-1049.
- `lastvote` is volatile, so it is set to the restart time and the first update waits `eta`.

**I-PTB1: `t_quiet = 2 delta` needs `delta > eta`.** L171, L2403-2411, L2518-2527.
- The silent-leader rule must not fire on a correct leader, which is heard from within
  `eta + delta`, so the specification requires `t_quiet > eta + delta` and sets `t_quiet = 2 delta`.
  That holds only while `delta > eta`. v2 keeps both (I-V2). On a regional or local deployment
  (`delta` of a few ms against `eta = 25` ms) `2 delta` is shorter than the leader's update
  interval, so (B) can skip correct leaders after GST in exactly the views that need a leader block,
  delaying the resolution of a split or withheld chain without bound.
- Resolution: `t_quiet = 2 delta_hat + eta`, above `eta + delta` whatever the delay, at the cost of
  skipping a crashed leader `eta` later. The production-timing plan's `t_quiet = 2 delta_hat` was not
  adopted for this reason.

**I-PTB2: no configured `Delta`.** L2213-2228, L2528-2544.
- `Delta` enters the specification only as the cap of `t_grace`. Without a configured latency
  bound, `t_grace` is capped at `2 t_max`, and one generous configured ceiling caps every timer
  as a backstop against inflated measurements. Liveness then needs `t_grace >= 2 delta` to be
  reachable, i.e. `2 t_max >= 4 delta_hat >= 2 delta`: the measured `delta_hat` must not
  underestimate the actual delay by more than half from some view on, and `2.5 delta` must stay
  below the ceiling. Faulty endorsers can make the `(n - f)`-th endorsement the `(n - 2f)`-th
  correct one, which shortens samples only to another correct validator's round trip.

**I-PTB4: `delta_hat` must measure the network, not the measuring node.** L150-182, L2213-2228.
- Symptom: the specification measures `delta` at run time ("the implementation may well measure
  it") without saying where the clock stops. Stopping it when the endorsing vote is processed
  measures the node's own queueing; under saturation that dominates, and because every timer is a
  multiple of `delta_hat` the node lengthens its own timers and recovery paths exactly when they
  are needed.
- Impact: at `n = 50`, with a saturated voter, `delta_hat` was 1.3-2.5 s against a network delay
  of about 0.1 s, `D_stop` 3.45 s and `t_grace` 4.4 s.
- Resolution: D24. A sample ends at the vote's arrival at the node. It still includes the
  endorser's processing between receiving the block and sending its vote, and the measuring node's
  send path, so a saturated endorser inflates its peers' samples; the 90th percentile over the
  `(n - f)`-th endorsers bounds this only while fewer than `f` validators are saturated. Rule (i)'s
  silence stays on processing time, since a backlog of unread votes is no evidence that a chain
  stopped.
- **Suggest** the specification say that the measurement must exclude the measurer's queueing
  (timestamp at receipt, not at processing), and bound the estimate by something outside the
  load's feedback (a clamp, or a probe that does not queue behind consensus work).

**I-PTB3: `t_max` from the median production interval.** L150-182, L946-955.
- `t_max = N theta_hat + 2 delta_hat + eta` leaves `(delta + eta) / N` per block for a chain
  slower than `theta_hat`. With `theta_hat` the median across chains, a correct producer much
  slower than the median reaches `t_max` before its cap and rule (iii) declares it every
  view, so its blocks wait for later views. Robustness to faulty producers needs an order
  statistic; an upper one such as the `(K - f)`-th fastest chain would cover every correct chain
  that is not among the `f` slowest, matching how `delta` is the `(n - f)`-th fastest delay. The
  code uses the median, as the plan specifies. With uniform pacing (D22) every correct producer
  paces at most at `theta_hat`, which narrows the case to producers held up by slow builds or
  delivery.

### Chain layer and production

**I-2: fixed-cadence production.** L273-301, L2229-2258.
- Symptom: production every `theta` with empty blocks costs `K / theta` (about 2,200 per second at
  `K = 50`, `theta = 23` ms) header verifications and acceptances per validator regardless of load,
  plus journal traffic. A chain whose application is slow stretches the view to `t_max` for
  everyone (L946-955).
- Impact: producers lose the freedom to choose their own cadence, which the protocol otherwise
  allows in principle.
- Resolution: the code follows v2's design regime (v2 L134-148). Every block, empty or not, is
  built every `theta`, which derives from the measured delay (D22); the idle cost remains.

**I-PTA1: `Ready` bounds production by `h*`, not by finality.** L237-240, L287-302.
- Symptom: `Ready` admits height `h` while `h - h* <= D`. `h*` follows acceptance through
  uncapped votes, while at most `N` blocks of a chain above its base finalize per view (the
  `Tips` window), so an unpaced producer runs `D` ahead of what can finalize and its extra blocks
  only queue.
- Resolution: the code follows v2's `Ready`, pacing included (v2 L312-321, D22), and pipelines
  (D18). A finality-relative production bound was tried and withdrawn (D27). Acceptance is bounded
  by D19 (I-PTA2). `D = 6N` (D20).
- **Suggest** the specification state the pipelining requirement (custody before signing over a
  contiguous prefix).

**I-PTA2: `h*` and the accepted lead are unbounded under a producer running ahead.** L235-240,
L361-365.
- Symptom: a validator accepts `h` while `h - h* <= D` and endorses what it accepts; `n - 2f`
  endorsements raise `h*`, which admits `D` more. A producer that ignores the flow bound
  (faulty) raises `h*` by up to `D` per round trip while bases
  rise at most `N` per view, so accepted headers above the retained bases, held headers, and
  correct voters' tip leads above `beta_v` grow without bound. PO-9 (`D + 2N`) is false for
  such a chain, and the artifact-cache budget for accepted headers cannot be sized.
- Impact: one faulty producer can exhaust every validator's artifact cache and park it.
- Resolution: D19, `h <= finalized + D + N`. Then a correct voter in view `v` accepts at most
  `D + N` above its final height, which lies at most `N` above `beta_v` (sweep finals are window
  blocks), giving PO-9's `D + 2N`. Witness:
  `multimmit::machine::tests::chain::acceptance_stops_d_plus_n_above_the_final_height_however_high_the_height_quorum`.
  **Suggest** adding the finality-relative acceptance bound to the specification.

**I-PTA3: empty views when every chain is silent.** L898-955.
- Rule (i) measures silence from the last sign of life, not from view entry. When every chain has
  been silent for `D_stop`, each new view declares every chain at entry and ends as fast as
  messages travel, with nothing new to order, until a producer's next block arrives. Harmless for
  safety; it costs a burst of empty views (the machine world, whose network has no latency, needed
  a build rate to avoid running them in zero time).

**I-PTA4: with no slack, rule (i) declares healthy chains.** L898-955, L273-302. Superseded by
I-PTA7.
- Symptom: a producer that filled its window waits for its blocks to become final before it builds
  more. Finality needs the window's votes, which go out at most every `eta` and take a round trip,
  so the chain is silent for about `2 delta + eta` plus the time to deliver the next block, which
  exceeds `D_stop = 2 delta + theta + eta` when blocks are quick to build. Rule (i) then
  declares a healthy chain. In a 6-node cluster with 2 ms links about half the views ended by
  declaration with slack 0, and 87% ended on count with a slack of one window.
- Resolution: the slack was a finality-relative bound's option (withdrawn, D27). Production is
  bounded only by the flow bound (D18) and paced at `theta` (D22), so a producer has no such
  pause and rule (i) applies as specified.

**I-PTA6: unpaced empty blocks remove the light-load regime the latency claim rests on.** L182-207
of the design note, L1944-2000, L2232 (Table 1).
- Symptom: with empty blocks built as fast as the bounds allow, every idle chain fills its window in
  one burst, then waits at its bound for the window's finals. Every block is produced a
  window ahead of its view and placed at the next boundary, so blocks wait a view by construction;
  the idle header rate is `K N / L` whatever the load, so a slow implementation never sees a light
  phase; and the producer's pause sits inside rule (i)'s margin (I-PTA7).
- Impact: at `n = 50` (with a saturated voter) every batch waited two views and none was final in
  its signing view. The common-case bound of Lemma timely (block final about
  `2 delta + eta + theta` after dissemination, within its own view) assumes production paced so
  that `N theta` covers the leader round.
- Resolution: D22. Every block, empty or not, is paced at the constant `theta`
  (`Tuning::production_interval`), as v2 does (v2 L134-148, L187). An adaptive `theta` derived from
  `delta_hat` was tried and withdrawn (I-V4, D27). The remaining cost is inherent: count-ended views need `N`
  headers per chain per view, so header verification at idle is `K N / L` per validator, about 5,000
  per second at `n = K = 50`, `N = 32`, `L = 300` ms, and the vote stream costs `n / eta` updates
  per second at any load.

**I-PTA7: `D_stop` has no margin for a producer that pauses.** L898-955, L2338.
- Symptom: `D_stop = 2 delta + theta + eta` is sized for a chain that produces continuously; L2338
  argues that no rule declares a live chain on that basis. Any production rule that pauses a
  healthy chain for about `2 delta + eta` sits inside the margin: a production bound (the flow
  bound when a receiver's `h*` lags, I-PTA8), or a durability stall. Rule (i)
  then declares healthy chains, each node at its own height, which leaves the boundary
  undetermined and costs a pin.
- Impact: at `n = 50`, 78% of view ends included a declaration and rule (i) declared 5-10 chains
  per view per node; the next window was pinned by the leader block of the next view rather than
  determined by case (b), the second of the two views every batch waited.
- Resolution: production bounded only by the flow bound, which a producer at `theta` does not
  reach (D18, D22), and rule (i) as specified (D23 withdrawn).
- v2 removes the carried-over declarations; rule (i) is unchanged (v2 L937-950).
- **Suggest** the specification either require that a correct producer never pauses longer than
  `theta` plus jitter, or exempt from rule (i) a chain whose tip is at the observer's bound for it
  (the capped exemption already does this inside a view; the gap is before entry, when capped is
  measured against the own final tips).

**I-PTA8: `D` must cover the producer's lead plus the `h*` lag.** L235-240, L2241-2259.
- Symptom: the specification sizes `D = 4N` (v2: `6N`) so that flow control never binds a correct
  producer. A receiver accepts only within `D` of its own `h*`, which trails the producer's
  progress by a vote round trip plus any local queueing. A small `D` (the earlier validation
  `D = N + slack`) leaves no margin: the top blocks of a healthy chain are refused at a lagging
  receiver, and the votes that endorse them are no sign of life there because it does not hold
  them.
- Resolution: D20, `D = 6N`, with counters for refused ready headers.
- **Suggest** that the specification state `D >= N + lag`, with `lag` the slowest correct
  receiver's `h*` lag in blocks, about `(2 delta + eta) / theta`.

**I-PTA5: `t_max = N theta + 2 delta + eta` overestimates the view length.** L946-955.
- With sweep finals releasing the next window while a view is open, producers build the next
  view's blocks before it starts, so a healthy view lasts about the final-vote round trip, not
  `N theta` longer. Over 50 ms links views lasted 114 ms against a formula of 243 ms (witness:
  `multimmit::tests::views_last_about_the_window_of_blocks_plus_a_round_trip_over_slow_links`).
  As a bound it is safe; as a prediction of the view length it is pessimistic.
- Adopted in v2: the formula is v2's `t_max`, now a backstop behind rule (ii), and v2 puts the
  steady-state time from entry to the last cap at about `N theta - delta` (v2 L2433-2452).

**I-A39: adoption invites a duplicate body fetch.** L2385-2402.
- Symptom: adoption is meant to be the earliest acceptance (`alpha = f + 1` endorsements). When it
  fires, the `alpha` endorsers received the body about one delay earlier and the producer's relay is
  usually still delivering it here; an adopter that fetches at once retrieves the body twice.
- Impact: plausibly most of the 85-95 MB/s per node of egress at `n = 50` that the protocol's
  consensus objects and bodies do not explain (not measured directly; D25 adds the counters).
- Resolution: D25, a fetch grace of `delta_hat`.
- **Suggest** the specification say that an adopter defers the body fetch by about `delta`; safety
  is unaffected and a starved adopter waits at most one more delay.

**I-11: no application validity in acceptance.** L223-250.
- Acceptance has no application check, and adoption endorses without a body. Resolution: D7;
  adoption relies on at least `alpha - f >= 1` correct full acceptor having verified, which assumes a
  deterministic `verify`.

**I-A2: `h*` grows in steps of at most `D + 2N`.** L235-240.
- `h*` counts held headers, which are held at most `D + 2N` above `max(h*, finalized)`; with
  D19 it also stays within `D + N` of the greatest final height a correct validator knows.

**I-A3: own headers in the outbox.**
- The discharge keeps an own header published until `D` later productions, so up to `D + 1` own
  header publications are outstanding.

**I-17: verification load.** L2246-2258, L2187.
- About `n / eta` vote signatures plus `K / theta` header signatures per second per validator;
  batch verification is required for both and must isolate invalid items. Implemented.

### Crash model and retrieval bounds

**I-14: no crash model.** L1116-1150.
- What must be durable before each signature is implicit. Resolution: durable signing slots and
  replay equivalence (STATE_MACHINE, canonical state; C-INV-3), plus the entry chain (I-PD-19).

**I-18: retrieval has no bounds.** L1151-1166.
- No per-peer bounds, and nothing bounds requests caused by faulty senders naming garbage tips.
  Resolution: per-peer channel quotas, a bounded table for update and header requests, and an
  unresolvable tip parks only its sender's bounded queue.

**I-A14: `base(l)` after a restart.**
- The durable slot holds only `H(l)`; until the leader block is seen again the sender caps against
  its final tips. Timing only; the leader block is requested on restart.

**I-A25 (also I-C2): sweeps restart from gossip.**
- After a consensus restart the pool is rebuilt from gossip, so the first sweeps of the open view
  can be lower than what marshal already emitted. Marshal skips such a sweep as stale and fails
  closed only on conflicting blocks.

### Consensus to marshal seam

**I-C1: `ViewSweep` carries no base.** L757-805.
- A consumer binds a sweep to its base only through the view number. Suggestion: include the base
  commitment in `ViewSweep`.

**I-C3: `Resolution::Pinned` is redundant for marshal.**
- The L-QC also arrives as `LeaderFinalized` with its opening; marshal ignores `by` and `base`.

**I-C4: no local history query.**
- Consensus offers no history query, so a `ViewResolved` that marshal drops under pressure is
  recovered by gap repair from peers' catalogs.

### Genesis

**I-16: two genesis hashes.** L2597-2599 vs L220.
- Part I uses `H(genesis, i)`, Part II `H(start, i, e)`. The code uses `H(GENESIS, epoch, i)` from
  the start. v2 makes the two contradict each other (I-V1).

### Specification v2

**I-V1: v2 gives the genesis block two different hashes.** v2 L211-214, v2 L2688-2691.
- Part I sets `H(genesis_i) := H(genesis, i)`. Part II sets `H(genesis_{i,e}) := H(start, i, e)`
  and `genesis_i = genesis_{i,1}`, so `H(genesis_i)` is also `H(start, i, 1)`. The first version
  used two symbols (I-16); v2 identifies them without reconciling the hashes.
- Resolution: the code derives chain genesis as `H(GENESIS, epoch, i)`. **Suggest** writing Part
  I's hash as `H(start, i, 1)`, or saying that Part II replaces it.

**I-V2: `t_quiet = 2 delta` contradicts its own requirement.** v2 L196, v2 L2505-2513.
- The parameter table sets `t_quiet = 2 delta` and says it needs `t_quiet > eta + delta`; the two
  agree only while `delta > eta`. With the example's `eta = 25` ms, any deployment whose delay is
  below 25 ms breaks the requirement, and (B) can skip correct leaders (I-PTB1).
- Resolution: `t_quiet = 2 delta_hat + eta`. **Suggest** the same in the specification.

**I-V3: rule (ii)'s threshold assumes one chain per processor.** v2 L951-956, v2 L1064-1066.
- Rule (ii) waits for `n - f` chains, which in v2 are `n - f` of `n`. With `K < n` chains,
  `n - f` exceeds the `K - f` chains whose producers are known to be correct, so `f` faulty
  producers can keep the rule from firing, and with `K < n - f` it never fires.
- Resolution: D26 counts all but `f` of the `K` chains and leaves the rule inactive at `K <= f`,
  where rule (iii) alone bounds the view. **Suggest** stating the threshold as `K - f` chains.

**I-V4: one `theta` for everyone, but a measured `theta` differs per node.** v2 L134-148, v2 L187,
v2 L2300-2338.
- Symptom: v2 treats `theta` as a constant every producer shares, and rule (ii) declares a chain
  that falls behind the others. An implementation that derives `theta` from the measured delay
  (I-PTA6) gets a different `theta` at each node: a node far from the rest measures a larger
  `delta` and paces slower. Its chain falls further behind every view, and rule (ii) declares it in
  each, one pin per view, although the producer follows its own measurements.
- Resolution: the code uses the constant `Tuning::production_interval` (D22), as v2 does. An
  adaptive pace (`max(3 delta_hat / N, (2 delta_hat + eta) / (N - 1))` capped at `theta_hat`) was
  withdrawn: the cap is self-referential, since `theta_hat` measures the capped pace, and on a
  50-validator, 13-region deployment the fleet locked at the bootstrap value (D27).
  **Question:** is `theta` meant to be configured, or, if measured, how should producers agree on
  it?

**I-V5: the suggested `t_late` is below the model-safe value.** v2 L192, v2 L2400-2417.
- Symptom: v2 suggests `t_late` of about `0.8 delta`, from cap-arrival spreads simulated on the
  global deployment (36 ms median, 70 ms worst; 60 ms misfired in 1% of processor-views), and
  notes that `t_late >= theta + delta` is what guarantees in the model that rule (ii) never fires
  on a chain at pace after GST.
- Impact: each misfire costs a pin. The margin is empirical and specific to one deployment, and an
  implementation's measured delay is an estimate, not the model's `delta`.
- Resolution: D26 uses `t_late = theta_hat + delta_hat`. A view that rule (ii) ends lasts up to
  `theta + 0.2 delta` longer than with `0.8 delta`; D22 keeps `N theta >= t_late + delta + eta`,
  so the ordering still keeps pace. **Suggest** giving the model-safe value as the default and
  `0.8 delta` as a tuning for deployments whose spread was measured.

**I-V6: paced production gains lead on the views, and only the flow bound stops it.** v2 L312-321,
v2 L2279-2298, v2 L2440-2449.
- Symptom: `Ready` bounds a producer only by `D = 6N` above `h*` and by the pace `theta`. A view
  ends a round after its last cap, so a view that ends on count lasts somewhat longer than `N
  theta`, while a producer builds exactly one block per `theta`. The producer therefore gains lead
  on the views every view, and after any stall it starts ahead (v2 L2445-2447). Nothing but the
  flow bound takes the lead back, so blocks are produced views ahead of the window that finalizes
  them.
- Impact: every block of lead adds `theta` of latency. In the deterministic six-region simulation,
  a lead of up to `2N` above finality made blocks wait about a view longer than a lead of up to
  `N` (signed-to-final mean about 290 ms against 200 ms), with no fewer declarations.
- Resolution: open. The implementation follows the specification's `Ready` (D18); a
  finality-relative bound with slack zero was withdrawn after it caused rule (i) declarations on a
  wide-area deployment (D27).
- **Suggest** (question for the author): is adding `hgt(b) + 1 <= ht_i(final) + N` to `Ready`
  intended, where `ht_i(final)` is the producer's greatest height it knows final? The simulation
  above favours it, but on the 13-region deployment it held producers at the bound often (12 blocks
  at 25 ms span less than `2 delta_hat + eta`), and rule (i) then declared those chains.

### Implementation limits found along the way

These are not specification problems, but they bound what the implementation shows.

- **I-D2a1 (resolved):** a node restarting after a few missed views never rejoined, because every
  retrieval key counted toward one request bound and unservable vote and header requests starved
  the parent V-QC retrieval. Only update and header keys count now.
- **I-D2b3:** a refused retrieval whose waiter remains is requested again at network pace until the
  waiter retires. The known instances (superseded predecessor, tip passed by the accepted path, a
  full queue refusing its own drain, predecessor tag below the window) are fixed; any remaining one
  shows up only as churn.
- **I-A31 (open):** records of view-less retrieval keys (`Header`, `Vqc`, `Lqc`) outlive their last
  waiter until the resolver answers; a faulty validator naming headers nobody serves holds request
  slots until then. Closing it needs record ownership.
- **I-A24:** the sweep is recomputed per emission pass, about `K n N` ancestor steps.
- **I-A26:** retention follows finality, so a finality stall stops retention and durable state grows
  until capacity parks the components.
- **I-A27, I-A33, I-A35:** retention pauses until the floor view's V-QC on the entry chain is held;
  after the entry chain became durable, the restart-time floor request fires only for durable state
  older than peers' retention, and a node behind its peers learns it from a verified certificate
  beyond its future-view window, so a silent network delays the request.
- **I-A28:** accountability is best effort; only the greatest statement per (tag, signer) is kept.
  No false positives.
- **I-A32:** one `ViewEntered` may carry many full V-QCs as ancestors, so the journal's record
  bound scales with the artifact cache; compact V-QCs (I-A20) would shrink it.
- **I-A34:** the world has no per-node pause, so anchoring is witnessed by machine tests and one
  cluster test, not by the world's oracles.
- **I-A36:** an anchor needs room for its L-QC in the artifact cache; at the ceiling it waits for an
  acknowledgement.
- **I-A37:** the conformance fixtures do not yet cover the new durable formats.
- **I-A1, I-A4, I-A6, I-A19, I-A29** (unsigned adopted headers unreported, unbounded acceptances,
  unfetchable tips below the accepted tip, history roots across retention, re-reporting
  acceptances on restart) are resolved by the unsigned `HeaderAccepted`, retained heights, the
  header band (D16), the retention root, and restore.
- **Artifact cache sized for one header per view (fixed).** Durable state counts every accepted
  header above the oldest retained view's base against `max_cached_artifacts`, which was budgeted at
  four slots per participant per retained view. Producers then ran at their own cadence, about 19
  headers per chain per view in the example, so all engines reached the ceiling together near view
  15 and parked: no update could be reserved, nothing finalized, and retention could not free room
  before view `W`. The budget now covers `chains * (D + 2N)` headers above the live base plus
  `chains * N` per retained view (a V-QC raises each base at most `N`). Witness:
  `multimmit::tests::fast_producers_with_a_wide_window_stay_live_through_retention`. The cache count
  also bounds the artifact store, ingress lanes, crypto permits and snapshot decode caps, so the
  example's ceiling rose from 2,116 to 15,358; a separate header budget would be tighter.
- **Producer throughput was one block in flight (fixed).** Each producer built, stored durably,
  reserved its signature with an urgent journal sync, and signed before the next production timer,
  so a block took 140-290 ms on one laptop disk instead of `theta` = 50 ms and views ran to
  `t_max`. Production is now pipelined up to the flow bound (D18). In the
  6-node local smoke run (one laptop, saturated 1 KiB bodies) every chain finalizes about 67
  blocks per second (about 7 before), views last about 250 ms (3.2 s before), at about 140 views
  per minute; building to signature averages about 235 ms and building to ordered delivery about
  1.5 s.
- **Outbox ceiling for tiny committees (open).** A producer holds up to `D + 1` own header
  publications plus up to `D` signature reservations in the outbox, whose ceiling is
  `n - f + 48n + 3`. For `n = 1` and `N = 32` that ceiling (52) is below `D + 1` (65), so the
  producer can block on the outbox while discharging needs further productions. Profiles do not yet
  validate it.

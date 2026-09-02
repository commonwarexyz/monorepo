# Multimmit voter DA-plane sharding

Staged plan to move the per-producer-chain data-availability plane off the single dedicated voter
thread (`actors/voter/actor.rs:802`, `context.dedicated().spawn`) into work-stealing per-chain tasks,
so the runtime spreads chain load across worker threads and the consensus view approaches its wire
floor. Read `consensus/src/multimmit/docs/STATE_MACHINE.md` first; this plan preserves every ownership
and durability contract in it. Status: ALPHA, no wire/storage change (see Risks).

## Verified premises (each checked against code)

- Per-chain state is `Vec`-indexed in `ChainState` (`machine/chain.rs:540`), labeled *"volatile,
  rebuildable"*: `local_da_votes`, `da_voted_run`, `da_safe_through`, `data_retired_through`,
  `pending_da_votes`, `certified`, `blocks` are `Vec<_>` by chain; `vote_pools`, `recovery_jobs`,
  `certificate_candidates`, `ancestry`, `validation_jobs` are shared-by-digest/ref maps;
  `next_da_chain`/`next_validation_chain` are rotating cursors.
- The **durable** per-chain state is separate and lives in `DurableState` (`machine/durability.rs:1601`):
  `certified_tips`, `da_safety_heights`, plus the single `cursor` (`:1607`). `reserve_change`
  (`machine/reducer.rs:3777`) is the sole writer of `durable.cursor` and the staged group-commit
  pipeline (`MAX_BATCH_EVENTS=32`, `MAX_INFLIGHT_BARRIERS=4`, `reducer.rs:3755`).
- One-unacked DA-vote reservation coalescing is central and keyed on `acked` (`reducer.rs:1864`,
  `da_vote_reserved_through`, `state.rs`).
- Vote/proposal frontier is taken synchronously across all chains: `chain.ready_da_votes(chains(),1)`
  frozen into `PendingVoteDa` (`reducer.rs:2082`), and the leader pass iterates chains from a single
  reducer call (`machine/view.rs:1481`). The frozen frontier is a **lower bound** (`chain.rs:540`
  `da_voted_run` doc: "a missed extension can never hide an eligible block").
- **Correction to the task premise, load-bearing for staging:** share-pool accumulation and n-2f
  recovery run for the **own chain only** - `drive_recoveries` returns early unless `self.own_chain`
  (`chain.rs:2818`) and `refresh_recovery` only readies own-chain blocks (`chain.rs:2884`). The work
  that scales with the 50 chains is the **validator-side** plane: block validation dispatch rotates
  every chain (`schedule_ready_validations`, `chain.rs:1593`), DA-vote eligibility scans every chain
  (`ready_da_votes`, `chain.rs:2045`), and certificate admission advances every chain's anchor
  (`claim_da_certificate`/`certificate_candidates`, `chain.rs:1157`; `advance_da_certificate`,
  `reducer.rs:2470`). So the literal Stage-1 candidate (own-chain producer plane) touches the fewest
  invariants but sheds ~1/50 of the cost; the measurable latency win is Stage 2 (validator plane).
- Machine is `Send`-clean: no `RefCell`/`Rc`/`unsafe` in `machine/*.rs`.

## 1. Target architecture

Central `Machine<H,V>` (`machine/state.rs:611`) remains the **single `&mut` owner** of `DurableState`,
`ViewState`, `FinalityState`, admission indexes, the staged pipeline, and the scheduler. It never
shares `&mut` state; the only cross-task contact is message passing. Per chain, a spawned task owns a
new `PerChainDa<V, D>` struct holding the **volatile** fields lifted out of `ChainState`: `blocks`,
`validation_jobs`/`validation_reservations`, `local_da_votes`, `da_voted_run`, `da_safe_through`,
`data_retired_through`, `ancestry`, and (own chain only) `vote_pools`, `recovery_jobs`,
`ready_recoveries`, `pending_recoveries`, `certificate_candidates`. The task holds a `Strategy` clone
and dispatches its own validation/recovery crypto exactly as the executor does today
(`actors/voter/executor.rs:553`), so no per-chain crypto crosses central.

Central keeps a small **shadow** `Vec<ChainFrontier>` (per chain: `da_vote_ready_through`,
`certified_anchor`) updated only by ordered task messages; it is read synchronously at vote/proposal
time. The durable per-chain fields (`certified_tips`, `da_safety_heights`) stay in `DurableState`.

Channels use `commonware_actor::mailbox` (runtime-agnostic; `Sender: Clone`, `mailbox.rs:234`) and
`commonware_macros::select!`. Tasks spawn on the shared work-stealing pool via
`context.child("da").child(chain).spawn(..)` (Spawner, `runtime/src/lib.rs:261,316`); `.shared(true)`
only if a task later does heavy inline CPU.

**task -> central** (one MPSC `Receiver<ChainUpdate>`, a new `select!` arm and `RuntimeEvent`
variant, `actor.rs:558`/`:1394`):
- `DaVoteReady { chain, candidates: Vec<Arc<SignedTransactionBlock<V,D>>> }` - the contiguous eligible
  run `ready_da_votes` returns today; also updates the shadow's `da_vote_ready_through`.
- `CertificateReady { chain, block: BlockRef<D>, certificate: DaCertificate<V,D> }` - a promoted
  (verified) certificate ready for durable anchor advance.
- `RecoveredCertificate { block, certificate }` - own-chain recovery completion for durable
  admit + publish.

**central -> task** (one dedicated per-chain `mailbox::Sender<ChainCommand>`):
- `Observe { id, observation, artifact }` - an authenticated remote artifact routed to its chain;
  central still mints observation identity/order first (invariant 1).
- `AnchorAdvanced { certified_tip: BlockRef<D>, safety_height: Height }` - new durable anchor after
  central applies `DaCertificateAdvanced`; the task recomputes eligibility from it.
- `Retire { below: Height }` and `Reconfigure { committee, generation }` - retention/epoch.

Central never blocks on a task at vote/proposal time: it reads its own shadow.

## 2. The two central invariants

**(a) Durability funnel stays single-owner.** Tasks never touch `durable.cursor`. `DaVoteReady`,
`CertificateReady`, and `RecoveredCertificate` are *append-requests*; central alone calls
`reserve_change` (`reducer.rs:3777`). Central's existing `reserve_ready_da_votes` loop
(`reducer.rs:1860`) is unchanged except that it drains candidate runs from a central queue fed by
`DaVoteReady` instead of scanning `ChainState`. The one-unacked rule (`da_vote_reserved_through >
acked`) and safety-extension check (`da_vote_extends_durable_safety`, `reducer.rs:2489`;
`expected` batch chaining, `reducer.rs:1904`) stay central, so N chains feeding concurrently still
coalesce into one barrier per group-commit cycle: central batches all pending chains' runs into a
single `SignBatch` under the same `MAX_BATCH_EVENTS`/outbox ceilings. Fsync coalescing is unaffected
because it is a property of the staged pipeline, which no task can enter.

**(b) All-chain frontier snapshot stays atomic.** Central holds the shadow and reads it in one
synchronous pass inside the same reducer step that builds `PendingVoteDa` (`reducer.rs:2082`) or the
leader proposal (`view.rs:1481`). No torn snapshot: central is single-threaded, so the read is
instantaneous relative to any task. No lost update: each task's messages are FIFO on its MPSC sender,
central applies every queued `ChainUpdate` before the read, and the durable one-per-height choice is
still minted centrally, so the shadow can only *lag* a task by an in-flight message - a safe lower
bound (premise above). A task can never make central believe a chain is further ahead than its durable
choices, because the choice itself is central.

## 3. Staging (each a separate jj revision, green build+test after each)

**Stage 0 - `PerChainDa` extraction, data-only.** Lift the per-chain volatile fields from `ChainState`
into `Vec<PerChainDa<V,D>>`, still owned and driven inline by `Machine`. No tasks, no behavior change.
Covered by all existing `machine/tests/*` and `actors/voter/tests.rs`. New test: none needed (pure
refactor; the core invariant harness re-runs unchanged). Risk: **LOW**.

**Stage 1 - own-chain producer plane -> one task.** Move `vote_pools`, `recovery_jobs`,
`ready_recoveries`, `pending_recoveries`, and certificate assembly for the own chain into a single
task; it verifies/accumulates shares and dispatches recovery crypto (already off-thread), then sends
`RecoveredCertificate`. Central durably admits + publishes via the unchanged
`DaCertificateAdvanced` path. Proves the task<->central messaging and the durable-admit funnel with
one task and the fewest invariants (no frontier, no one-per-height choice). New deterministic test:
own-chain block reaches n-2f shares across the task boundary and the certificate is durably admitted
and published (`commonware_utils::test_rng`, deterministic runtime). Measurable but modest (1 chain).
Risk: **LOW-MED**.

**Stage 2 - remote validation + DA-vote eligibility -> N per-chain tasks.** Move `blocks`,
`validation_jobs`, `local_da_votes`, `da_voted_run`, `ancestry` per chain into tasks. Each task
receives `Observe`, dispatches validation crypto, tracks its certified anchor from `AnchorAdvanced`,
computes the contiguous depth-`d` eligible run, and sends `DaVoteReady`. Central applies one-per-height
+ safety-extension + coalesced signing (unchanged) and updates the shadow. **This is the
latency-shedding stage** (the ~67 ms). New deterministic test: multi-chain continuous production
finalizes with per-chain tasks enabled, asserting identical finality/DA outcomes to the inline path
under a seeded schedule (extend `actors/voter/tests.rs` network scenario). Risk: **MED** (frontier
shadow, eligibility messaging).

**Stage 3 - certificate admission candidates -> per-chain tasks.** Move `certificate_candidates` and
promotion (verification) into the tasks; each sends `CertificateReady`, central keeps the durable
anchor advance and `AnchorAdvanced` fan-out. New deterministic test: out-of-order certificate delivery
across chains still advances anchors monotonically and retires covered validation. Risk: **MED**.

**Stage 4 - remove production pacing hack; retune budgets.** With DA bookkeeping off-thread, delete the
pacing that gated production against the inflated view, and re-derive the `ServiceCycle` core budget
(`contracts`, `reducer.rs:5673`) for the now-lighter central quantum. Validate with the existing
resource/liveness deterministic suites and a Linux benchmark. Risk: **LOW-MED**.

## 4. Risks and ordering constraints

- **One DA vote per (chain,height)** - preserved: the durable choice is minted only by central's
  reserve loop; tasks only *offer* candidates. Two tasks cannot both vote a height because there is
  one task per chain and one central chooser.
- **Consecutive-run extends durable safety** (`reducer.rs:1904`/`:2489`) - stays central; unchanged.
- **Admission atomicity across DA/view/finality/durability** - central still applies every durable
  index update in one step; only *volatile* per-chain bookkeeping is asynchronous, and it produces no
  durable event until a `ChainUpdate` reaches central. Observation identity/order stay central.
- **Effect ordering** - durable effects (sign, admit, publish) still emit from central in its
  deterministic order. Task-local validation/recovery crypto dispatch is non-durable and order-free
  until its result returns as a fact. Under the deterministic runtime, spawned tasks are scheduled by
  seed, so reproducibility holds; keep all protocol tests on the deterministic runtime.
- **`&mut self` single-thread assumptions** - `apply_event`, `reserve_change`, and the invariant
  harness assume one `&mut Machine`; they stay central. Tasks hold a disjoint `&mut PerChainDa`. No
  shared `&mut`, so no new `Send`/aliasing hazard beyond message ownership (`Arc` clones on hot path).
- **Backpressure** - bound every mailbox; a saturated per-chain command mailbox applies backpressure
  to central admission for that chain only, mirroring today's per-chain validation permits, and must
  not become a fatal invariant.

## 5. What not to touch

V-QC/L-QC tally, finality pool, ordering sweep, view/round state, leader proposal composition, the
durability funnel, recovery/replay (stays central; tasks are re-seeded from the rebuilt volatile
projection), and the checkpoint/prune fence all remain exactly as-is on the central thread.

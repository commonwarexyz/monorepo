//! What each engine delivered, committed, and verified, and the safety checks
//! over those records.
//!
//! Records are taken from the engine's own reporting path, never from
//! harness-side bookkeeping about what should have been delivered, and are
//! keyed by engine rather than by identity because the compromised identity's
//! two halves share a key.

use super::{Digest, app::Block, marshal::Marshal};
use commonware_actor::Feedback;
use commonware_consensus::{
    Block as _, Heightable as _, Reporter,
    marshal::Update,
    types::{Height, Round, View},
};
use commonware_cryptography::Digestible as _;
use commonware_utils::{channel::mpsc, sync::Mutex};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// Whether an engine's application ever accepted or rejected a block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Verdicts {
    accepted: bool,
    rejected: bool,
}

/// How a delivered block links into the chain: what the check of I1 needs of
/// a block, independent of the commitment the block carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Linkage {
    digest: Digest,
    parent: Digest,
    /// The parent named by the block's embedded consensus context.
    context_parent: Digest,
}

#[derive(Default)]
struct Records {
    /// Arrival-ordered delivery log, so gaps, reordering, duplicates, and
    /// same-height forks all stay observable.
    delivered: Vec<(Height, Digest)>,
    /// The most recent block delivered at each height.
    blocks: BTreeMap<Height, Linkage>,
    /// The latest finalized tip reported by marshal.
    tip: Option<(Height, Digest)>,
    /// Every database commitment reached at each height. Application is
    /// at-least-once and a restart replays heights, so a height that is applied
    /// more than once contributes more than one entry, and a set with more than
    /// one member is itself a divergence.
    states: BTreeMap<Height, BTreeSet<Digest>>,
    /// Verification verdicts by block digest.
    verdicts: BTreeMap<Digest, Verdicts>,
    /// Restarts this engine completed.
    restarts: usize,
    /// The location pruning to each applied height's sync target retains
    /// from, for adapters whose retention is observable.
    floors: BTreeMap<Height, u64>,
    /// The highest height this engine has applied, across restarts.
    max_applied: Option<Height>,
    /// Every start of this engine and every height it applied, in order.
    timeline: Vec<Event>,
    /// Every height applied so far, in order, so a subscriber that arrives
    /// after the fact still sees what it missed.
    applied: Vec<(Height, View)>,
    /// Subscribers woken when a height is applied and committed.
    waiters: Vec<mpsc::UnboundedSender<(Height, View)>>,
}

/// Per-engine observations. Cloning shares one record set, so it survives a
/// restart of the engine that writes into it.
#[derive(Clone, Default)]
pub(super) struct EngineObservations(Arc<Mutex<Records>>);

impl EngineObservations {
    pub(super) fn new() -> Self {
        Self::default()
    }

    fn record_delivery<M: Marshal>(&self, block: &Block<M>) {
        let mut records = self.0.lock();
        records.delivered.push((block.height(), block.digest()));
        records
            .timeline
            .push(Event::Delivered(block.height(), block.digest()));
        records.blocks.insert(
            block.height(),
            Linkage {
                digest: block.digest(),
                parent: block.parent(),
                context_parent: block.context_parent(),
            },
        );
    }

    fn record_tip(&self, height: Height, digest: Digest) {
        self.0.lock().tip = Some((height, digest));
    }

    /// Record what the application observed once `height` was applied, and
    /// wake any waiter. Called from the application's `finalized` hook, which
    /// the stateful actor invokes strictly after the batch is applied, so a
    /// height reported here is committed rather than merely delivered.
    pub(super) fn record_applied(&self, applied: Applied) {
        let Applied {
            height,
            view,
            root,
            prune_floor,
            oldest_retained,
        } = applied;
        let mut records = self.0.lock();
        records.states.entry(height).or_default().insert(root);
        let new_max = records.max_applied.is_none_or(|max| height > max);
        if new_max {
            records.max_applied = Some(height);
        }
        if let Some(floor) = prune_floor {
            records.floors.insert(height, floor);
        }
        let max_applied = records.max_applied.expect("just recorded");
        records.timeline.push(Event::Applied(AppliedEvent {
            height,
            max_applied,
            new_max,
            oldest_retained,
        }));
        records.applied.push((height, view));
        records
            .waiters
            .retain(|waiter| waiter.send((height, view)).is_ok());
    }

    /// Subscribe to this engine's applied heights.
    ///
    /// The heights already applied are replayed into the new subscriber, so a
    /// waiter installed after the engine started still counts them. Without
    /// that, a run could satisfy its height requirement during startup and then
    /// wait out the whole timeout.
    pub(super) fn subscribe_applied(&self) -> mpsc::UnboundedReceiver<(Height, View)> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut records = self.0.lock();
        for applied in &records.applied {
            let _ = sender.send(*applied);
        }
        records.waiters.push(sender);
        receiver
    }

    pub(super) fn record_verdict(&self, digest: Digest, accepted: bool) {
        let mut records = self.0.lock();
        let entry = records.verdicts.entry(digest).or_default();
        if accepted {
            entry.accepted = true;
        } else {
            entry.rejected = true;
        }
    }

    pub(super) fn note_restart(&self) {
        self.0.lock().restarts += 1;
    }

    /// Record what the startup plan decided when the engine started.
    pub(super) fn note_startup(&self, startup: Startup) {
        self.0.lock().timeline.push(Event::Startup(startup));
    }

    fn timeline(&self) -> Vec<Event> {
        self.0.lock().timeline.clone()
    }

    /// Whether any start of this engine chose peer state sync.
    fn peer_synced(&self) -> bool {
        self.0.lock().timeline.iter().any(|event| match event {
            Event::Startup(startup) => startup.should_sync,
            Event::Delivered(..) | Event::Applied(_) => false,
        })
    }

    pub(super) fn restarts(&self) -> usize {
        self.0.lock().restarts
    }

    fn delivered(&self) -> Vec<(Height, Digest)> {
        self.0.lock().delivered.clone()
    }

    fn blocks(&self) -> BTreeMap<Height, Linkage> {
        self.0.lock().blocks.clone()
    }

    fn tip(&self) -> Option<(Height, Digest)> {
        self.0.lock().tip
    }

    fn states(&self) -> BTreeMap<Height, BTreeSet<Digest>> {
        self.0.lock().states.clone()
    }

    fn verdicts(&self) -> BTreeMap<Digest, Verdicts> {
        self.0.lock().verdicts.clone()
    }

    fn floors(&self) -> BTreeMap<Height, u64> {
        self.0.lock().floors.clone()
    }
}

/// What the application observed when one height was applied.
pub(super) struct Applied {
    pub(super) height: Height,
    pub(super) view: View,
    /// The canonical database root, the observable I2 compares.
    pub(super) root: Digest,
    /// The location pruning to this height's sync target retains from, when
    /// the adapter's retention is observable.
    pub(super) prune_floor: Option<u64>,
    /// The oldest operation location the database still retained, when the
    /// adapter's retention is observable.
    pub(super) oldest_retained: Option<u64>,
}

/// One entry of an engine's timeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    /// The engine started, and its startup plan decided this.
    Startup(Startup),
    /// Marshal delivered a finalized block to the engine.
    Delivered(Height, Digest),
    /// The engine applied a height.
    Applied(AppliedEvent),
}

/// One application of a height, with the retention observed at that moment.
///
/// Taken from the application's `finalized` hook, so a prune that ran before
/// it is visible and one that runs after it is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AppliedEvent {
    height: Height,
    /// The highest height the engine had applied, across restarts.
    max_applied: Height,
    /// Whether this application raised that maximum.
    new_max: bool,
    /// The oldest operation location the database still retained, when the
    /// adapter's retention is observable.
    oldest_retained: Option<u64>,
}

/// What the startup plan decided when an engine started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Startup {
    /// The driver requested peer state sync.
    pub(super) requested: bool,
    /// The plan chose peer state sync.
    pub(super) should_sync: bool,
    /// The plan resumed an interrupted sync from its persisted floor.
    pub(super) resumed: bool,
    /// The durable height below which this engine never peer syncs again:
    /// set by a completed peer sync, and advanced by every marshal-path
    /// startup to the anchor it reconciled the databases against.
    pub(super) sync_height: Option<Height>,
    /// The round of the floor the plan carries, when it chose to sync.
    pub(super) floor_round: Option<Round>,
}

/// The pruning bound a run was configured with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RetentionWindow {
    /// Finalized heights behind the newest applied height that pruning
    /// never reaches: the acknowledgement window plus the configured QMDB
    /// retention.
    pub(super) heights: u64,
    /// The location a fresh database retains from.
    pub(super) initial_floor: Option<u64>,
}

/// Records what marshal delivered to an engine before forwarding it to the
/// stateful actor's mailbox.
#[derive(Clone)]
pub(super) struct ObservingReporter<R> {
    observations: EngineObservations,
    inner: R,
}

impl<R> ObservingReporter<R> {
    pub(super) const fn new(observations: EngineObservations, inner: R) -> Self {
        Self {
            observations,
            inner,
        }
    }
}

impl<R, M> Reporter for ObservingReporter<R>
where
    R: Reporter<Activity = Update<Block<M>>>,
    M: Marshal,
{
    type Activity = Update<Block<M>>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match &activity {
            Update::Tip(_, height, digest) => self.observations.record_tip(*height, *digest),
            Update::Block(block, _) => self.observations.record_delivery(block.as_ref()),
        }
        self.inner.report(activity)
    }
}

/// How much each check actually compared, so a run that measured nothing is
/// never mistaken for a run that found nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Correct nodes observed.
    pub correct_nodes: usize,
    /// Distinct heights checked under I1.
    pub chain_heights: usize,
    /// Cross-node database-state comparisons made under I2.
    pub state_comparisons: usize,
    /// Cross-node verdict comparisons made under I3.
    pub verdict_comparisons: usize,
    /// Retention observations checked under I9.
    pub retention_checks: usize,
    /// Retention observations in which pruning had visibly run.
    pub prunes: usize,
    /// Engine starts at which the plan chose peer state sync.
    pub sync_starts: usize,
    /// Engines whose state sync durably completed.
    pub synced_nodes: usize,
    /// Restarts executed.
    pub restarts: usize,
}

impl Counts {
    /// Whether every check compared something.
    pub const fn measured(&self) -> bool {
        self.correct_nodes > 0
            && self.chain_heights > 0
            && self.state_comparisons > 0
            && self.verdict_comparisons > 0
    }
}

/// A correct node's observations, labelled by its engine.
pub(super) type CorrectNode<'a> = (usize, &'a EngineObservations);

/// I1: the finalized chains observed at the correct nodes are consistent in the
/// sense of the chain-of-blocks method.
///
/// At most one distinct block per height across all correct nodes; each block's
/// recorded parent is the block at the preceding height, rooted at genesis; and
/// each node's delivery sequence advances by one height at a time from its
/// starting anchor. Delivery is at-least-once and restarts make repeats normal,
/// so an exact repeat of a height already delivered is accepted and a differing
/// repeat is not. A node that peer synced starts at the floor it synced from
/// rather than at genesis; its first block must then be the child of the block
/// the other correct nodes delivered below it, and a sync resumed from a newer
/// floor restarts its sequence from that floor.
pub(super) fn check_chain_of_blocks(nodes: &[CorrectNode<'_>], genesis: Digest) -> usize {
    let mut by_height: BTreeMap<Height, Digest> = BTreeMap::new();
    for (_, observations) in nodes {
        for (height, block) in observations.blocks() {
            by_height.entry(height).or_insert(block.digest);
        }
    }
    for (engine, observations) in nodes {
        let synced = observations.peer_synced();
        check_in_order(*engine, &observations.timeline());
        check_parent_linkage(*engine, synced, &observations.blocks(), &by_height, genesis);
    }
    check_agreement(nodes)
}

/// Per-node in-order, gap-free delivery.
///
/// Delivery is at-least-once and a restart resumes from the node's durable
/// processed height, so a repeat of any height already delivered is normal and
/// is accepted when it carries the same block. Every height delivered for the
/// first time must advance the sequence by exactly one, except that a start
/// which chose peer state sync begins a new sequence at its floor: at genesis
/// or the first finalized container for a node that never synced, anywhere
/// for a node's first sync, and never below an earlier floor for a resumed
/// one, since a floor cannot move backward.
fn check_in_order(engine: usize, timeline: &[Event]) {
    let delivered: Vec<(Height, Digest)> = timeline
        .iter()
        .filter_map(|event| match event {
            Event::Delivered(height, digest) => Some((*height, *digest)),
            Event::Startup(_) | Event::Applied(_) => None,
        })
        .collect();
    let mut seen: BTreeMap<Height, Digest> = BTreeMap::new();
    let mut previous: Option<Height> = None;
    let mut lowest: Option<Height> = None;
    let mut resuming = false;
    for event in timeline {
        let (height, digest) = match event {
            Event::Startup(startup) => {
                if startup.should_sync {
                    previous = None;
                    resuming = true;
                }
                continue;
            }
            Event::Applied(_) => continue,
            Event::Delivered(height, digest) => (*height, *digest),
        };
        if let Some(first_digest) = seen.get(&height) {
            assert_eq!(
                *first_digest,
                digest,
                "I1 violated: engine{engine} redelivered height {} with a different block: \
                 {first_digest} then {digest}; sequence={delivered:?}",
                height.get(),
            );
            previous = Some(height);
            resuming = false;
            continue;
        }
        match previous {
            Some(previous) => assert!(
                previous.get().checked_add(1) == Some(height.get()),
                "I1 violated: engine{engine} delivery is out of order or has a gap: \
                 previous_height={} next_height={}; sequence={delivered:?}",
                previous.get(),
                height.get(),
            ),
            None if resuming => assert!(
                lowest.is_none_or(|lowest| height >= lowest),
                "I1 violated: engine{engine} resumed peer state sync below an earlier floor: \
                 first_height={} earlier_floor={:?}; sequence={delivered:?}",
                height.get(),
                lowest.map(Height::get),
            ),
            None => assert!(
                height.get() <= 1,
                "I1 violated: engine{engine} first delivery at height {} is neither genesis (0) \
                 nor the first finalized container (1); sequence={delivered:?}",
                height.get(),
            ),
        }
        seen.insert(height, digest);
        lowest = Some(lowest.map_or(height, |lowest| lowest.min(height)));
        previous = Some(height);
        resuming = false;
    }
}

/// Every pair of consecutively delivered blocks is parent-linked, and the chain
/// is rooted at genesis: directly, or through the block the other correct
/// nodes delivered below a peer-synced node's first one.
fn check_parent_linkage(
    engine: usize,
    synced: bool,
    blocks: &BTreeMap<Height, Linkage>,
    by_height: &BTreeMap<Height, Digest>,
    genesis: Digest,
) {
    if let Some((height, block)) = blocks.first_key_value() {
        if *height == Height::zero() {
            assert_eq!(
                block.digest, genesis,
                "I1 violated: engine{engine} delivered the wrong genesis block: digest={} \
                 expected={genesis}",
                block.digest,
            );
        } else if !synced || height.get() == 1 {
            assert_eq!(
                block.parent,
                genesis,
                "I1 violated: engine{engine} delivered a chain not rooted at genesis: \
                 first_height={} parent={} expected={genesis}",
                height.get(),
                block.parent,
            );
        } else if let Some(below) = by_height.get(&Height::new(height.get() - 1)) {
            assert_eq!(
                block.parent,
                *below,
                "I1 violated: engine{engine} synced onto a chain the other correct nodes did not \
                 deliver: first_height={} parent={} but height {} is {below}",
                height.get(),
                block.parent,
                height.get() - 1,
            );
        }
    }

    for (height, block) in blocks {
        let Some(next_height) = height.get().checked_add(1).map(Height::new) else {
            continue;
        };
        let Some(next) = blocks.get(&next_height) else {
            continue;
        };
        assert_eq!(
            next.parent,
            block.digest,
            "I1 violated: engine{engine} delivered a chain with a broken parent link: height {} \
             digest={} but height {} parent={}",
            height.get(),
            block.digest,
            next_height.get(),
            next.parent,
        );
        assert_eq!(
            next.context_parent,
            block.digest,
            "I1 violated: engine{engine} delivered a chain with a broken embedded consensus \
             parent: height {} digest={} but height {} context parent={}",
            height.get(),
            block.digest,
            next_height.get(),
            next.context_parent,
        );
    }
}

/// At most one distinct block per height across all correct nodes.
///
/// Returns the number of distinct heights compared.
fn check_agreement(nodes: &[CorrectNode<'_>]) -> usize {
    let mut seen: BTreeMap<Height, (usize, &'static str, Digest)> = BTreeMap::new();
    for (engine, observations) in nodes {
        for (height, digest) in observations.delivered() {
            record_height(&mut seen, *engine, "delivered", height, digest);
        }
        if let Some((height, digest)) = observations.tip() {
            record_height(&mut seen, *engine, "reported tip", height, digest);
        }
    }
    seen.len()
}

fn record_height(
    seen: &mut BTreeMap<Height, (usize, &'static str, Digest)>,
    engine: usize,
    source: &'static str,
    height: Height,
    digest: Digest,
) {
    if let Some((first_engine, first_source, first_digest)) = seen.get(&height) {
        assert_eq!(
            *first_digest,
            digest,
            "I1 violated: correct nodes forked at height {}: engine{first_engine} {first_source} \
             {first_digest} but engine{engine} {source} {digest}",
            height.get(),
        );
        return;
    }
    seen.insert(height, (engine, source, digest));
}

/// I2: for every height finalized by two or more correct nodes, those nodes'
/// committed database state for that height is identical.
///
/// Returns the number of cross-node comparisons made.
pub(super) fn check_state_agreement(nodes: &[CorrectNode<'_>]) -> usize {
    let mut seen: BTreeMap<Height, (usize, Digest)> = BTreeMap::new();
    let mut comparisons = 0;
    for (engine, observations) in nodes {
        for (height, roots) in observations.states() {
            let mut roots = roots.into_iter();
            let root = roots.next().expect("an applied height has a commitment");
            if let Some(other) = roots.next() {
                panic!(
                    "I2 violated: engine{engine} committed different database state on separate \
                     applications of height {}: {root} then {other}",
                    height.get(),
                );
            }
            if let Some((first_engine, first_root)) = seen.get(&height) {
                comparisons += 1;
                assert_eq!(
                    *first_root,
                    root,
                    "I2 violated: correct nodes committed different database state at height {}: \
                     engine{first_engine} committed {first_root} but engine{engine} committed \
                     {root}",
                    height.get(),
                );
                continue;
            }
            seen.insert(height, (*engine, root));
        }
    }
    comparisons
}

/// I3: no correct node's application accepts a block another correct node's
/// application rejected.
///
/// Returns the number of cross-node comparisons made.
pub(super) fn check_verdict_agreement(nodes: &[CorrectNode<'_>]) -> usize {
    let mut accepted_by: BTreeMap<Digest, BTreeSet<usize>> = BTreeMap::new();
    let mut rejected_by: BTreeMap<Digest, BTreeSet<usize>> = BTreeMap::new();
    for (engine, observations) in nodes {
        for (digest, verdicts) in observations.verdicts() {
            if verdicts.accepted {
                accepted_by.entry(digest).or_default().insert(*engine);
            }
            if verdicts.rejected {
                rejected_by.entry(digest).or_default().insert(*engine);
            }
        }
    }

    let mut comparisons = 0;
    for (digest, accepted) in &accepted_by {
        let Some(rejected) = rejected_by.get(digest) else {
            comparisons += accepted.len().saturating_sub(1);
            continue;
        };
        panic!(
            "I3 violated: correct nodes disagreed on block {digest}: accepted by {accepted:?} but \
             rejected by {rejected:?}"
        );
    }
    for (digest, rejected) in &rejected_by {
        if accepted_by.contains_key(digest) {
            continue;
        }
        comparisons += rejected.len().saturating_sub(1);
    }
    comparisons
}

/// I9: pruning never discards operations inside the retention window.
///
/// A retention observation is taken from the application's `finalized` hook,
/// which the actor awaits before it schedules the prune that finalizing the
/// same height may trigger. An observation that raises the engine's maximum
/// to `h` can therefore reflect prunes triggered by heights up to `h - 1`,
/// the newest of which targeted `h - 1 - window.heights`. An observation
/// below an existing maximum `m`, a restarted engine replaying, can reflect
/// the prune triggered by `m` itself, which ran before the crash, so its
/// bound is the floor of `m - window.heights`. Inactivity floors are monotone
/// in height, so either height's prune floor bounds the oldest retained
/// location; below the window nothing may have been pruned at all.
///
/// A database populated by peer state sync starts at the floor of the height
/// it synced to, the height below the first one the engine applied
/// afterwards, rather than at genesis; that floor bounds it until pruning
/// moves past it. Floors are chain properties, so the one recorded by any
/// correct node serves, and I2 has already established that they agree.
///
/// Returns the number of observations checked and the number in which
/// pruning had visibly run.
pub(super) fn check_retention(
    nodes: &[CorrectNode<'_>],
    window: RetentionWindow,
) -> (usize, usize) {
    let Some(initial) = window.initial_floor else {
        return (0, 0);
    };
    let mut floors: BTreeMap<Height, u64> = BTreeMap::new();
    for (engine, observations) in nodes {
        for (height, floor) in observations.floors() {
            if let Some(known) = floors.insert(height, floor) {
                assert_eq!(
                    known,
                    floor,
                    "engine{engine} recorded prune floor {floor} at height {} where another node \
                     recorded {known}",
                    height.get(),
                );
            }
        }
    }
    let floor_of = |engine: &usize, height: u64| {
        if height == 0 {
            initial
        } else {
            *floors.get(&Height::new(height)).unwrap_or_else(|| {
                panic!("engine{engine} needs a prune floor for height {height} no node recorded")
            })
        }
    };

    let mut checks = 0;
    let mut prunes = 0;
    for (engine, observations) in nodes {
        let mut baseline = initial;
        let mut syncing = false;
        for event in observations.timeline() {
            let applied = match event {
                Event::Startup(startup) => {
                    syncing |= startup.should_sync;
                    continue;
                }
                Event::Delivered(..) => continue,
                Event::Applied(applied) => applied,
            };
            if syncing {
                // The first application after a peer sync sits right above
                // the synced height.
                baseline = floor_of(engine, applied.height.get().saturating_sub(1));
                syncing = false;
            }
            let Some(oldest) = applied.oldest_retained else {
                continue;
            };
            let newest_prune = applied
                .max_applied
                .get()
                .saturating_sub(u64::from(applied.new_max));
            let prunable = newest_prune.saturating_sub(window.heights);
            let bound = floor_of(engine, prunable).max(baseline);
            assert!(
                oldest <= bound,
                "I9 violated: engine{engine} retains operations only from location {oldest} \
                 after applying height {}, but pruning may reach at most location {bound} (the \
                 floor of height {prunable}, {} heights behind, or the floor it synced to)",
                applied.max_applied.get(),
                window.heights,
            );
            checks += 1;
            if oldest > baseline {
                prunes += 1;
            }
        }
    }
    (checks, prunes)
}

/// I10: peer state sync runs at most once per engine, its durable height
/// only advances, and everything applied afterwards lies above it.
///
/// Walking an engine's starts and applications in order: the plan never
/// chooses to sync unless the driver requested it or an interrupted sync had
/// to resume; the durable sync height, once recorded, is present at every
/// later start and never decreases, and the plan never chooses to sync again;
/// a resumed sync never moves its floor backward; and every height applied
/// after a start lies above the sync height that start carried, since state
/// below it is covered by the sync or by marshal reconciliation. An engine
/// counts as peer synced once it applied a height after a start that chose
/// to sync.
///
/// Returns the number of starts at which the plan chose to sync and the
/// number of engines that peer synced.
pub(super) fn check_state_sync(nodes: &[CorrectNode<'_>]) -> (usize, usize) {
    let mut sync_starts = 0;
    let mut synced_nodes = 0;
    for (engine, observations) in nodes {
        let mut highest: Option<Height> = None;
        let mut current: Option<Height> = None;
        let mut floor: Option<Round> = None;
        let mut syncing = false;
        let mut synced = false;
        for (index, event) in observations.timeline().into_iter().enumerate() {
            match event {
                Event::Startup(startup) => {
                    assert!(
                        !startup.should_sync || startup.requested || startup.resumed,
                        "I10 violated: engine{engine} chose peer state sync at event {index} \
                         without a request or an interrupted sync to resume: {startup:?}",
                    );
                    if let Some(previous) = highest {
                        let now = startup.sync_height.unwrap_or_else(|| {
                            panic!(
                                "I10 violated: engine{engine} lost its durable sync height {} at \
                                 event {index}: {startup:?}",
                                previous.get(),
                            )
                        });
                        assert!(
                            now >= previous,
                            "I10 violated: engine{engine} moved its durable sync height backward \
                             at event {index}: {} then {}",
                            previous.get(),
                            now.get(),
                        );
                        assert!(
                            !startup.should_sync,
                            "I10 violated: engine{engine} chose peer state sync at event {index} \
                             with a durable sync height of {}: {startup:?}",
                            now.get(),
                        );
                    }
                    if startup.should_sync {
                        sync_starts += 1;
                        syncing = true;
                        let round = startup
                            .floor_round
                            .expect("a start that syncs carries a floor");
                        if let Some(previous) = floor {
                            assert!(
                                round >= previous,
                                "I10 violated: engine{engine} moved its sync floor backward at \
                                 event {index}: {previous:?} then {round:?}",
                            );
                        }
                        floor = Some(round);
                    }
                    highest = highest.max(startup.sync_height);
                    current = startup.sync_height;
                }
                Event::Delivered(..) => {}
                Event::Applied(applied) => {
                    if let Some(floor) = current {
                        assert!(
                            applied.height > floor,
                            "I10 violated: engine{engine} applied height {} at or below the \
                             durable sync height {} it started from",
                            applied.height.get(),
                            floor.get(),
                        );
                    }
                    if syncing && !synced {
                        synced = true;
                        synced_nodes += 1;
                    }
                }
            }
        }
    }
    (sync_starts, synced_nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateful::{app::Block, backend::StateCommitment, marshal::Standard};
    use commonware_consensus::{
        simplex::types::Context,
        types::{Epoch, View},
    };
    use commonware_cryptography::{Hasher, Sha256, Signer as _, ed25519, sha256};
    use commonware_storage::mmr::Location;
    use commonware_utils::non_empty_range;

    fn digest(label: &[u8]) -> Digest {
        Sha256::hash(&[label])
    }

    fn entry(height: u64, label: &[u8]) -> (Height, Digest) {
        (Height::new(height), digest(label))
    }

    fn block(height: u64, label: &[u8]) -> Block<Standard> {
        Block {
            context: Context {
                round: Round::new(Epoch::zero(), View::new(height)),
                leader: ed25519::PrivateKey::from_seed(0).public_key(),
                parent: (View::new(height.saturating_sub(1)), digest(b"parent")),
            },
            parent: digest(b"parent"),
            height: Height::new(height),
            commitment: StateCommitment {
                root: digest(label),
                sync_root: digest(label),
                range: non_empty_range!(Location::new(0), Location::new(1)),
            },
        }
    }

    /// A timeline of deliveries, optionally begun by a start that syncs.
    fn deliveries(synced: bool, entries: &[(Height, Digest)]) -> Vec<Event> {
        let mut timeline = Vec::new();
        if synced {
            timeline.push(Event::Startup(Startup {
                requested: true,
                should_sync: true,
                resumed: false,
                sync_height: None,
                floor_round: Some(Round::new(Epoch::zero(), View::new(1))),
            }));
        }
        timeline.extend(
            entries
                .iter()
                .map(|(height, digest)| Event::Delivered(*height, *digest)),
        );
        timeline
    }

    #[test]
    fn contiguous_delivery_is_accepted() {
        check_in_order(
            0,
            &deliveries(false, &[entry(1, b"a"), entry(2, b"b"), entry(3, b"c")]),
        );
    }

    /// A restart resumes from the node's durable processed height, so heights
    /// already delivered arrive again.
    #[test]
    fn restart_rewind_is_accepted() {
        check_in_order(
            0,
            &deliveries(
                false,
                &[
                    entry(1, b"a"),
                    entry(2, b"b"),
                    entry(3, b"c"),
                    entry(2, b"b"),
                    entry(3, b"c"),
                    entry(4, b"d"),
                ],
            ),
        );
    }

    #[test]
    #[should_panic(expected = "redelivered height 2 with a different block")]
    fn differing_repeat_is_rejected() {
        check_in_order(
            0,
            &deliveries(false, &[entry(1, b"a"), entry(2, b"b"), entry(2, b"other")]),
        );
    }

    #[test]
    #[should_panic(expected = "out of order or has a gap")]
    fn gap_is_rejected() {
        check_in_order(0, &deliveries(false, &[entry(1, b"a"), entry(3, b"c")]));
    }

    /// A peer-synced node may start delivering at its floor.
    #[test]
    fn synced_node_starts_at_its_floor() {
        check_in_order(0, &deliveries(true, &[entry(5, b"e"), entry(6, b"f")]));
    }

    #[test]
    #[should_panic(expected = "neither genesis (0) nor the first finalized container (1)")]
    fn unsynced_node_starting_late_is_rejected() {
        check_in_order(0, &deliveries(false, &[entry(5, b"e"), entry(6, b"f")]));
    }

    /// A sync resumed from a newer floor begins a new sequence there.
    #[test]
    fn resumed_sync_restarts_at_a_newer_floor() {
        let mut timeline = deliveries(true, &[entry(5, b"e"), entry(6, b"f")]);
        timeline.extend(deliveries(true, &[entry(11, b"k"), entry(12, b"l")]));
        check_in_order(0, &timeline);
    }

    #[test]
    #[should_panic(expected = "resumed peer state sync below an earlier floor")]
    fn resumed_sync_below_an_earlier_floor_is_rejected() {
        let mut timeline = deliveries(true, &[entry(5, b"e"), entry(6, b"f")]);
        timeline.extend(deliveries(true, &[entry(3, b"c"), entry(4, b"d")]));
        check_in_order(0, &timeline);
    }

    /// Without a sync start, a restart may only repeat or continue.
    #[test]
    #[should_panic(expected = "out of order or has a gap")]
    fn gap_after_a_plain_restart_is_rejected() {
        let mut timeline = deliveries(true, &[entry(5, b"e"), entry(6, b"f")]);
        timeline.push(Event::Startup(Startup {
            requested: true,
            should_sync: false,
            resumed: false,
            sync_height: Some(Height::new(6)),
            floor_round: None,
        }));
        timeline.extend(deliveries(false, &[entry(9, b"i")]));
        check_in_order(0, &timeline);
    }

    #[test]
    #[should_panic(expected = "correct nodes forked at height 2")]
    fn cross_node_fork_is_rejected() {
        let left = EngineObservations::new();
        let right = EngineObservations::new();
        left.record_delivery(&block(2, b"b"));
        right.record_delivery(&block(2, b"other"));
        check_agreement(&[(0, &left), (1, &right)]);
    }

    /// An application of `height` reaching `root`, with the retention the
    /// database exposed at that moment.
    fn applied(height: u64, root: &[u8], floor: u64, oldest: u64) -> Applied {
        Applied {
            height: Height::new(height),
            view: View::new(height),
            root: digest(root),
            prune_floor: Some(floor),
            oldest_retained: Some(oldest),
        }
    }

    #[test]
    #[should_panic(expected = "I2 violated")]
    fn state_divergence_is_rejected() {
        let left = EngineObservations::new();
        let right = EngineObservations::new();
        left.record_applied(applied(2, b"root", 0, 0));
        right.record_applied(applied(2, b"other", 0, 0));
        check_state_agreement(&[(0, &left), (1, &right)]);
    }

    /// A node that applies the same height twice must reach the same
    /// commitment; a replay that changes it is itself a divergence.
    #[test]
    #[should_panic(expected = "on separate applications of height 2")]
    fn replayed_height_changing_commitment_is_rejected() {
        let node = EngineObservations::new();
        node.record_applied(applied(2, b"root", 0, 0));
        node.record_applied(applied(2, b"other", 0, 0));
        check_state_agreement(&[(0, &node)]);
    }

    /// A waiter installed after the fact still sees what was already applied.
    #[test]
    fn subscription_replays_applied_heights() {
        let node = EngineObservations::new();
        node.record_applied(applied(1, b"a", 0, 0));
        node.record_applied(applied(2, b"b", 0, 0));
        let mut applied = node.subscribe_applied();
        assert_eq!(applied.try_recv(), Ok((Height::new(1), View::new(1))));
        assert_eq!(applied.try_recv(), Ok((Height::new(2), View::new(2))));
        assert!(applied.try_recv().is_err());
    }

    /// Two heights behind the newest finalized height may be pruned. The
    /// floors climb by two per height, and an observation that raises the
    /// maximum to 5 precedes the prune height 5 triggers, so the newest
    /// visible prune targeted height 2 and its floor, 4, is the bound.
    const WINDOW: RetentionWindow = RetentionWindow {
        heights: 2,
        initial_floor: Some(0),
    };

    fn pruned_node(oldest_at_five: u64) -> EngineObservations {
        let node = EngineObservations::new();
        for height in 1..=5u64 {
            node.record_applied(applied(
                height,
                b"root",
                height * 2,
                if height == 5 { oldest_at_five } else { 0 },
            ));
        }
        node
    }

    #[test]
    fn pruning_within_the_window_is_accepted() {
        let node = pruned_node(4);
        assert_eq!(check_retention(&[(0, &node)], WINDOW), (5, 1));
    }

    #[test]
    #[should_panic(expected = "I9 violated")]
    fn pruning_into_the_window_is_rejected() {
        let node = pruned_node(5);
        check_retention(&[(0, &node)], WINDOW);
    }

    /// Before the window is full nothing may be pruned, whatever the floors.
    #[test]
    #[should_panic(expected = "I9 violated")]
    fn pruning_before_the_window_fills_is_rejected() {
        let node = EngineObservations::new();
        node.record_applied(applied(1, b"root", 2, 0));
        node.record_applied(applied(2, b"root", 4, 1));
        check_retention(&[(0, &node)], WINDOW);
    }

    /// A restarted engine replaying below its previous maximum is judged
    /// against the maximum it had reached, whose own prune may have run
    /// before the crash: after reaching 5, a replay of 4 may see the floor
    /// of height 3.
    #[test]
    fn replay_below_the_maximum_keeps_the_earlier_bound() {
        let node = pruned_node(4);
        node.record_applied(applied(4, b"root", 8, 6));
        assert_eq!(check_retention(&[(0, &node)], WINDOW), (6, 2));
    }

    #[test]
    #[should_panic(expected = "I9 violated")]
    fn replay_below_the_maximum_is_still_bounded() {
        let node = pruned_node(4);
        node.record_applied(applied(4, b"root", 8, 7));
        check_retention(&[(0, &node)], WINDOW);
    }

    #[test]
    #[should_panic(expected = "I3 violated")]
    fn verdict_disagreement_is_rejected() {
        let left = EngineObservations::new();
        let right = EngineObservations::new();
        left.record_verdict(digest(b"block"), true);
        right.record_verdict(digest(b"block"), false);
        check_verdict_agreement(&[(0, &left), (1, &right)]);
    }

    /// Silences an unused-import warning when the digest alias resolves to the
    /// same type as the hasher output.
    const _: Option<sha256::Digest> = None;
}

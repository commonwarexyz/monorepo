//! What each engine delivered, committed, and verified, and the safety checks
//! over those records.
//!
//! Records are taken from the engine's own reporting path, never from
//! harness-side bookkeeping about what should have been delivered, and are
//! keyed by engine rather than by identity because the compromised identity's
//! two halves share a key.

use super::{Digest, app::Block};
use commonware_actor::Feedback;
use commonware_consensus::{
    Heightable, Reporter,
    marshal::Update,
    types::{Height, View},
};
use commonware_cryptography::Digestible;
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

#[derive(Default)]
struct Records {
    /// Arrival-ordered delivery log, so gaps, reordering, duplicates, and
    /// same-height forks all stay observable.
    delivered: Vec<(Height, Digest)>,
    /// The most recent block delivered at each height.
    blocks: BTreeMap<Height, Block>,
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
    /// Subscribers woken when a height is applied and committed.
    applied: Vec<mpsc::UnboundedSender<(Height, View)>>,
}

/// Per-engine observations. Cloning shares one record set, so it survives a
/// restart of the engine that writes into it.
#[derive(Clone, Default)]
pub(super) struct EngineObservations(Arc<Mutex<Records>>);

impl EngineObservations {
    pub(super) fn new() -> Self {
        Self::default()
    }

    fn record_delivery(&self, block: &Block) {
        let mut records = self.0.lock();
        records.delivered.push((block.height(), block.digest()));
        records.blocks.insert(block.height(), block.clone());
    }

    fn record_tip(&self, height: Height, digest: Digest) {
        self.0.lock().tip = Some((height, digest));
    }

    /// Record the commitment reached once `height` was applied, and wake any
    /// waiter. Called from the application's `finalized` hook, which the
    /// stateful actor invokes strictly after the batch is applied, so a height
    /// reported here is committed rather than merely delivered.
    pub(super) fn record_state(&self, height: Height, view: View, root: Digest) {
        let mut records = self.0.lock();
        records.states.entry(height).or_default().insert(root);
        records
            .applied
            .retain(|waiter| waiter.send((height, view)).is_ok());
    }

    /// Subscribe to this engine's applied heights.
    pub(super) fn subscribe_applied(&self) -> mpsc::UnboundedReceiver<(Height, View)> {
        let (sender, receiver) = mpsc::unbounded_channel();
        self.0.lock().applied.push(sender);
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

    pub(super) fn restarts(&self) -> usize {
        self.0.lock().restarts
    }

    fn delivered(&self) -> Vec<(Height, Digest)> {
        self.0.lock().delivered.clone()
    }

    fn blocks(&self) -> BTreeMap<Height, Block> {
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

impl<R> Reporter for ObservingReporter<R>
where
    R: Reporter<Activity = Update<Block>>,
{
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match &activity {
            Update::Tip(_, height, digest) => self.observations.record_tip(*height, *digest),
            Update::Block(block, _) => self.observations.record_delivery(block),
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
/// repeat is not.
pub(super) fn check_chain_of_blocks(nodes: &[CorrectNode<'_>], genesis: Digest) -> usize {
    for (engine, observations) in nodes {
        check_in_order(*engine, &observations.delivered());
        check_parent_linkage(*engine, &observations.blocks(), genesis);
    }
    check_agreement(nodes)
}

/// Per-node in-order, gap-free delivery.
///
/// Delivery is at-least-once and a restart resumes from the node's durable
/// processed height, so a repeat of any height already delivered is normal and
/// is accepted when it carries the same block. Every height delivered for the
/// first time must advance the sequence by exactly one.
fn check_in_order(engine: usize, delivered: &[(Height, Digest)]) {
    let first = delivered.first().map_or(0, |(height, _)| height.get());
    assert!(
        first <= 1,
        "I1 violated: engine{engine} first delivery at height {first} is neither genesis (0) nor \
         the first finalized container (1); sequence={delivered:?}"
    );
    let mut seen: BTreeMap<Height, Digest> = BTreeMap::new();
    let mut previous: Option<Height> = None;
    for (height, digest) in delivered {
        if let Some(first_digest) = seen.get(height) {
            assert_eq!(
                first_digest,
                digest,
                "I1 violated: engine{engine} redelivered height {} with a different block: \
                 {first_digest} then {digest}; sequence={delivered:?}",
                height.get(),
            );
            previous = Some(*height);
            continue;
        }
        assert!(
            previous.is_none_or(|previous| previous.get().checked_add(1) == Some(height.get())),
            "I1 violated: engine{engine} delivery is out of order or has a gap: \
             previous_height={:?} next_height={}; sequence={delivered:?}",
            previous.map(Height::get),
            height.get(),
        );
        seen.insert(*height, *digest);
        previous = Some(*height);
    }
}

/// Every pair of consecutively delivered blocks is parent-linked, and the chain
/// is rooted at genesis.
fn check_parent_linkage(engine: usize, blocks: &BTreeMap<Height, Block>, genesis: Digest) {
    if let Some((height, block)) = blocks.first_key_value() {
        if *height == Height::zero() {
            assert_eq!(
                block.digest(),
                genesis,
                "I1 violated: engine{engine} delivered the wrong genesis block: digest={} \
                 expected={genesis}",
                block.digest(),
            );
        } else {
            assert_eq!(
                block.parent,
                genesis,
                "I1 violated: engine{engine} delivered a chain not rooted at genesis: \
                 first_height={} parent={} expected={genesis}",
                height.get(),
                block.parent,
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
            block.digest(),
            "I1 violated: engine{engine} delivered a chain with a broken parent link: height {} \
             digest={} but height {} parent={}",
            height.get(),
            block.digest(),
            next_height.get(),
            next.parent,
        );
        assert_eq!(
            next.context.parent.1,
            block.digest(),
            "I1 violated: engine{engine} delivered a chain with a broken embedded consensus \
             parent: height {} digest={} but height {} context parent={}",
            height.get(),
            block.digest(),
            next_height.get(),
            next.context.parent.1,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateful::app::Block;
    use commonware_consensus::{
        simplex::types::Context,
        types::{Epoch, Round, View},
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

    fn block(height: u64, label: &[u8]) -> Block {
        Block {
            context: Context {
                round: Round::new(Epoch::zero(), View::new(height)),
                leader: ed25519::PrivateKey::from_seed(0).public_key(),
                parent: (View::new(height.saturating_sub(1)), digest(b"parent")),
            },
            parent: digest(b"parent"),
            height: Height::new(height),
            state_root: digest(label),
            range: non_empty_range!(Location::new(0), Location::new(1)),
        }
    }

    #[test]
    fn contiguous_delivery_is_accepted() {
        check_in_order(0, &[entry(1, b"a"), entry(2, b"b"), entry(3, b"c")]);
    }

    /// A restart resumes from the node's durable processed height, so heights
    /// already delivered arrive again.
    #[test]
    fn restart_rewind_is_accepted() {
        check_in_order(
            0,
            &[
                entry(1, b"a"),
                entry(2, b"b"),
                entry(3, b"c"),
                entry(2, b"b"),
                entry(3, b"c"),
                entry(4, b"d"),
            ],
        );
    }

    #[test]
    #[should_panic(expected = "redelivered height 2 with a different block")]
    fn differing_repeat_is_rejected() {
        check_in_order(0, &[entry(1, b"a"), entry(2, b"b"), entry(2, b"other")]);
    }

    #[test]
    #[should_panic(expected = "out of order or has a gap")]
    fn gap_is_rejected() {
        check_in_order(0, &[entry(1, b"a"), entry(3, b"c")]);
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

    #[test]
    #[should_panic(expected = "I2 violated")]
    fn state_divergence_is_rejected() {
        let left = EngineObservations::new();
        let right = EngineObservations::new();
        left.record_state(Height::new(2), View::new(2), digest(b"root"));
        right.record_state(Height::new(2), View::new(2), digest(b"other"));
        check_state_agreement(&[(0, &left), (1, &right)]);
    }

    /// A node that applies the same height twice must reach the same
    /// commitment; a replay that changes it is itself a divergence.
    #[test]
    #[should_panic(expected = "on separate applications of height 2")]
    fn replayed_height_changing_commitment_is_rejected() {
        let node = EngineObservations::new();
        node.record_state(Height::new(2), View::new(2), digest(b"root"));
        node.record_state(Height::new(2), View::new(2), digest(b"other"));
        check_state_agreement(&[(0, &node)]);
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

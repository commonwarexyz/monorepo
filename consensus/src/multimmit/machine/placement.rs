//! Placement of producer blocks in the canonical order as soon as local finality fixes it.
//!
//! Finality of a leader fixes a prefix of the total order: the openings of its recursive tip
//! history, oldest first, then the final sweep toward the leader's finalized tips. Each opening and
//! sweep first places the payment chains, up to their tips, in the payment pass. The sweep then
//! halts at the first ordinary chain that fell short of its proposed tip, and its extension pass at
//! the first unsettled ordinary chain, so a block below the finalized tips may wait a later view
//! for its position.
//!
//! [`PlacementState`] follows that prefix with the extraction marshal orders its output by. Each
//! history opening and each sweep reads its new blocks off its own target tip, above the heights
//! already placed, exactly as marshal reconciles them. An anchor may jump to a rival branch, so
//! the run an opening adds is only known when every opening since the last placed one is: the
//! state then names the run, and otherwise only advances its heights.
//!
//! The records whose order the state places are queued for the next verified L-QC to report
//! (see [`Activity::Proven`]): marshal stores them as the links between portable proofs.

use crate::{
    multimmit::{
        order::{FinalSweep, Lanes},
        scheme::Scheme,
        types::{Activity, BlockRef, FinalityFact, Placement, TipRecord},
    },
    types::{Height, View},
};
use commonware_cryptography::Digest;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

/// Most views whose history records or waiting facts are retained.
///
/// Views below the newest placing view are dropped first, so this bound only matters while
/// finality stalls. A dropped view's order is then placed by the next view that finalizes.
const RETAINED_VIEWS: usize = 32;

/// Most leaders per view whose history records are retained.
///
/// Only an equivocating leader proposes more than one block in a view.
const RETAINED_RECORDS: usize = 64;

/// Most leaders per view whose facts wait for a history record.
///
/// A finality quorum forms for at most one leader of a view.
const RETAINED_FACT_LEADERS: usize = 4;

/// Most mutually undominated facts retained per leader while its history record is unknown.
const RETAINED_FACTS: usize = 4;

/// Most views a fact may wait for a missing intermediate history opening.
///
/// A later leader's finality can arrive before the record of a leader between it and the last
/// placed one (that record waits on a parent V-QC this node has not observed yet). Its fact then
/// waits, so the gap is named once the record arrives. Past this span the newest waiting fact is
/// placed without naming the gap, so a record that never arrives cannot stall placement.
const STALLED_VIEWS: usize = 8;

/// Most placed history records queued for the next proof report.
///
/// Every finalized leader yields an L-QC, so the queue drains every view while finality is
/// live. Past this bound the oldest records are dropped; marshal then fetches them from peers.
/// At 64 chains a record is about 4 KiB.
const RETAINED_UNPROVEN: usize = 1024;

/// A history record and its commitment.
type Committed<D> = (D, Arc<TipRecord<D>>);

/// A retained history opening.
#[derive(Clone, Debug)]
struct Opening<D: Digest> {
    /// Newest view of a leader that committed the opening.
    view: View,
    record: Arc<TipRecord<D>>,
}

/// Tracks how far local finality has fixed the canonical order of every producer chain.
///
/// A fact fixes the order once the history record of its leader is known, matched by view and
/// leader digest; a fact that arrives first waits for that record. Records and facts below the
/// newest placing view are ignored, since their order is a prefix of that view's.
#[derive(Clone, Debug)]
pub(crate) struct PlacementState<D: Digest> {
    /// Commitment of the newest history opening whose tips are placed.
    ordered: D,
    /// Highest placed height of every chain, in chain order.
    placed: Vec<Height>,
    /// The history commitment each retained leader committed to, by view and leader digest.
    leaders: BTreeMap<View, BTreeMap<D, D>>,
    /// Retained history openings by commitment.
    openings: BTreeMap<D, Opening<D>>,
    /// Facts waiting for their leader's history record, by view and leader digest.
    waiting: BTreeMap<View, BTreeMap<D, Vec<FinalityFact<D>>>>,
    /// Facts whose leader's record is known but does not connect to the ordered opening yet,
    /// because an intermediate record is missing, by view.
    stalled: BTreeMap<View, Vec<FinalityFact<D>>>,
    /// Newest view whose leader's finality placed the order.
    floor: Option<View>,
    /// Placed records no proof report took yet, oldest first, by commitment.
    unproven: VecDeque<Committed<D>>,
    /// The epoch's payment chains, which every sweep places first.
    lanes: Lanes,
}

impl<D: Digest> PlacementState<D> {
    /// Creates a tracker whose order starts at the genesis `history` commitment and `tips`, with
    /// the payment chains of `lanes`.
    pub(crate) fn new(history: D, tips: &[BlockRef<D>], lanes: Lanes) -> Self {
        Self {
            ordered: history,
            placed: tips.iter().map(BlockRef::height).collect(),
            leaders: BTreeMap::new(),
            openings: BTreeMap::new(),
            waiting: BTreeMap::new(),
            stalled: BTreeMap::new(),
            floor: None,
            unproven: VecDeque::new(),
            lanes,
        }
    }

    /// Returns the highest placed height of every chain, in chain order.
    #[cfg(test)]
    pub(crate) fn heights(&self) -> &[Height] {
        &self.placed
    }

    /// Records the history record that the leader of `view` with digest `leader` committed to
    /// under `commitment`, and reports the placement of the facts that waited for it.
    pub(crate) fn history<S: Scheme>(
        &mut self,
        view: View,
        leader: D,
        commitment: D,
        record: &Arc<TipRecord<D>>,
        placed: &mut Vec<Activity<S, D>>,
    ) {
        if self.below_floor(view) || record.tips().len() != self.placed.len() {
            return;
        }
        let leaders = self.leaders.entry(view).or_default();
        if !leaders.contains_key(&leader) && leaders.len() >= RETAINED_RECORDS {
            return;
        }
        leaders.entry(leader).or_insert(commitment);
        self.openings
            .entry(commitment)
            .and_modify(|opening| opening.view = opening.view.max(view))
            .or_insert_with(|| Opening {
                view,
                record: Arc::clone(record),
            });
        self.bound();
        let facts = self
            .waiting
            .get_mut(&view)
            .and_then(|waiting| waiting.remove(&leader))
            .unwrap_or_default();
        for fact in facts {
            self.place(fact, placed);
        }
        // The record may be the missing link of a stalled fact.
        self.retry_stalled(placed);
    }

    /// Applies one leader-finality fact and reports the placement it advances.
    pub(crate) fn finality<S: Scheme>(
        &mut self,
        fact: &FinalityFact<D>,
        placed: &mut Vec<Activity<S, D>>,
    ) {
        let view = fact.round().view();
        if self.below_floor(view) || fact.blocks().len() != self.placed.len() {
            return;
        }
        if self.commitment(view, fact.leader()).is_some() {
            self.place(fact.clone(), placed);
            return;
        }
        let waiting = self.waiting.entry(view).or_default();
        if !waiting.contains_key(&fact.leader()) && waiting.len() >= RETAINED_FACT_LEADERS {
            return;
        }
        let facts = waiting.entry(fact.leader()).or_default();
        // A fact whose tips and settledness another one reaches places nothing more, whatever
        // the record turns out to be.
        if facts.iter().any(|kept| dominates(kept, fact)) {
            return;
        }
        facts.retain(|kept| !dominates(fact, kept));
        if facts.len() >= RETAINED_FACTS {
            facts.remove(0);
        }
        facts.push(fact.clone());
        while self.waiting.len() > RETAINED_VIEWS {
            self.waiting.pop_first();
        }
    }

    /// Places `fact`, whose leader's record is known, or stalls it while an intermediate opening
    /// is missing.
    fn place<S: Scheme>(&mut self, fact: FinalityFact<D>, placed: &mut Vec<Activity<S, D>>) {
        if self.apply(&fact, false, placed) {
            // A stalled later fact may build on what this one placed.
            self.retry_stalled(placed);
            return;
        }
        let view = fact.round().view();
        let facts = self.stalled.entry(view).or_default();
        if facts.iter().any(|kept| dominates(kept, &fact)) {
            return;
        }
        facts.retain(|kept| !dominates(&fact, kept));
        if facts.len() >= RETAINED_FACTS {
            facts.remove(0);
        }
        facts.push(fact);
        // A missing record that never arrives must not stall placement: past the span, place the
        // newest stalled facts without naming the gap.
        let (Some(oldest), Some(newest)) = (
            self.stalled.keys().next().copied(),
            self.stalled.keys().next_back().copied(),
        ) else {
            return;
        };
        if newest.get().saturating_sub(oldest.get()) < STALLED_VIEWS as u64 {
            return;
        }
        let newest = self
            .stalled
            .pop_last()
            .map(|(_, facts)| facts)
            .unwrap_or_default();
        self.stalled.clear();
        for fact in &newest {
            self.apply(fact, true, placed);
        }
    }

    /// Places every stalled fact whose openings now connect, oldest view first.
    fn retry_stalled<S: Scheme>(&mut self, placed: &mut Vec<Activity<S, D>>) {
        while let Some((view, facts)) = self.stalled.pop_first() {
            if self.below_floor(view) {
                continue;
            }
            let mut kept = Vec::new();
            for fact in facts {
                if !self.apply(&fact, false, placed) {
                    kept.push(fact);
                }
            }
            if !kept.is_empty() {
                // Later views build on this one, so they cannot connect either.
                self.stalled.insert(view, kept);
                return;
            }
        }
    }

    fn below_floor(&self, view: View) -> bool {
        self.floor.is_some_and(|floor| view < floor)
    }

    fn commitment(&self, view: View, leader: D) -> Option<D> {
        self.leaders
            .get(&view)
            .and_then(|leaders| leaders.get(&leader))
            .copied()
    }

    /// Returns the retained openings after the ordered one up to `commitment`, newest first,
    /// with their commitments, and whether they reach the ordered one. Without a missing
    /// opening, the walk stops at the first one not retained.
    fn openings_since(&self, commitment: D) -> (Vec<Committed<D>>, bool) {
        let mut openings = Vec::new();
        let mut cursor = commitment;
        while cursor != self.ordered {
            // Every retained opening appears at most once on a parent chain.
            if openings.len() >= self.openings.len() {
                return (openings, false);
            }
            let Some(opening) = self.openings.get(&cursor) else {
                return (openings, false);
            };
            openings.push((cursor, Arc::clone(&opening.record)));
            cursor = opening.record.parent();
        }
        (openings, true)
    }

    /// Takes the queued records through the one with commitment `history`, oldest first, or
    /// none when `history` is not queued.
    pub(crate) fn proven(&mut self, history: D) -> Arc<[Arc<TipRecord<D>>]> {
        let Some(position) = self
            .unproven
            .iter()
            .position(|(commitment, _)| *commitment == history)
        else {
            return Arc::new([]);
        };
        self.unproven
            .drain(..=position)
            .map(|(_, record)| record)
            .collect()
    }

    /// Places the order `fact` fixes: its leader's history openings, then its final sweep.
    ///
    /// Returns false, changing nothing, when an opening between the ordered one and the fact's
    /// is missing after the tracker has placed before, unless `skip` places the fact anyway
    /// without naming the blocks of the missing openings. A tracker that never placed (a
    /// restarted engine) skips at once: it never held the openings before its first fact.
    fn apply<S: Scheme>(
        &mut self,
        fact: &FinalityFact<D>,
        skip: bool,
        placed: &mut Vec<Activity<S, D>>,
    ) -> bool {
        let view = fact.round().view();
        let Some(commitment) = self.commitment(view, fact.leader()) else {
            return true;
        };
        let Some(record) = self
            .openings
            .get(&commitment)
            .map(|opening| Arc::clone(&opening.record))
        else {
            return true;
        };
        let Ok(swept) = FinalSweep::placed(
            record.tips(),
            fact.blocks(),
            fact.proposed(),
            fact.settled(),
            &self.lanes,
        ) else {
            return true;
        };

        let mut runs = Vec::new();
        let (openings, connected) = self.openings_since(commitment);
        if !connected && !skip && self.floor.is_some() {
            return false;
        }
        if connected {
            for (_, opening) in openings.iter().rev() {
                for (tip, current) in opening.tips().iter().zip(&mut self.placed) {
                    if tip.height() > *current {
                        runs.push(Placement::new(*tip, *current, tip.height()));
                        *current = tip.height();
                    }
                }
            }
        } else {
            // Without every opening since the ordered one, an anchor jump among them could
            // place blocks off the newest opening's path, so their runs stay unnamed.
            for (tip, current) in record.tips().iter().zip(&mut self.placed) {
                *current = (*current).max(tip.height());
            }
        }
        self.unproven.extend(openings.into_iter().rev());
        if let Some(excess) = self.unproven.len().checked_sub(RETAINED_UNPROVEN) {
            self.unproven.drain(..excess);
        }
        self.ordered = commitment;
        // Sweep slots above the emitted heights resolve on the final tips' own paths.
        for ((height, current), tip) in swept.into_iter().zip(&mut self.placed).zip(fact.blocks()) {
            if height > *current {
                runs.push(Placement::new(*tip, *current, height));
                *current = height;
            }
        }

        if self.floor.is_none_or(|floor| floor < view) {
            // Every lower view's order is a prefix of this one.
            self.floor = Some(view);
            self.leaders = self.leaders.split_off(&view);
            self.waiting = self.waiting.split_off(&view);
            self.stalled = self.stalled.split_off(&view);
            self.prune_openings();
        }
        if !runs.is_empty() {
            placed.push(Activity::Placed {
                view,
                evidence: fact.id(),
                history: commitment,
                placed: runs,
            });
        }
        true
    }

    /// Drops the oldest views beyond [`RETAINED_VIEWS`] and the openings only they committed.
    fn bound(&mut self) {
        if self.leaders.len() <= RETAINED_VIEWS {
            return;
        }
        while self.leaders.len() > RETAINED_VIEWS {
            self.leaders.pop_first();
        }
        self.prune_openings();
    }

    /// Drops the openings that no retained leader committed.
    fn prune_openings(&mut self) {
        let Some(oldest) = self.leaders.keys().next().copied() else {
            self.openings.clear();
            return;
        };
        // A retained leader's opening records a view at least as new as the leader's.
        self.openings.retain(|_, opening| opening.view >= oldest);
    }
}

/// Returns whether `a` places at least what `b` does above any shared history record: both
/// finalize one leader, `a`'s tips are at least as high on every chain, and `a` settles every
/// chain `b` settles.
///
/// Final tips of one leader lie on its proposal paths, so higher tips extend lower ones.
fn dominates<D: Digest>(a: &FinalityFact<D>, b: &FinalityFact<D>) -> bool {
    a.leader() == b.leader()
        && a.blocks().len() == b.blocks().len()
        && a.blocks()
            .iter()
            .zip(b.blocks())
            .all(|(a, b)| a.height() >= b.height())
        && a.settled().iter().zip(b.settled()).all(|(a, b)| *a || !*b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            mocks::Bls,
            types::{CertificateId, ChainId, FinalityId, Position},
        },
        types::{Epoch, Round},
    };
    use commonware_cryptography::{
        Hasher as _, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };

    type Placed = Vec<Activity<Bls<MinPk>, Sha256Digest>>;
    type Run = (BlockRef<Sha256Digest>, u64, u64);

    fn genesis() -> Sha256Digest {
        Sha256::hash(&[b"genesis history"])
    }

    fn reference(chain: usize, height: u64) -> BlockRef<Sha256Digest> {
        BlockRef::new(
            ChainId::new(chain as u32),
            Height::new(height),
            Sha256::hash(&[&chain.to_be_bytes(), &height.to_be_bytes()]),
        )
    }

    fn frontier(heights: &[u64]) -> Vec<BlockRef<Sha256Digest>> {
        heights
            .iter()
            .enumerate()
            .map(|(chain, height)| reference(chain, *height))
            .collect()
    }

    fn heights(heights: &[u64]) -> Vec<Height> {
        heights.iter().map(|height| Height::new(*height)).collect()
    }

    fn leader(view: u64) -> Sha256Digest {
        Sha256::hash(&[b"leader", &view.to_be_bytes()])
    }

    fn state(chains: usize) -> PlacementState<Sha256Digest> {
        PlacementState::new(genesis(), &frontier(&vec![0; chains]), Lanes::none())
    }

    fn record(
        parent: Sha256Digest,
        tips: Vec<BlockRef<Sha256Digest>>,
    ) -> Arc<TipRecord<Sha256Digest>> {
        Arc::new(TipRecord::at_tips(parent, tips).unwrap())
    }

    fn commitment(record: &TipRecord<Sha256Digest>) -> Sha256Digest {
        record.commitment::<Sha256>()
    }

    fn fact_with(
        view: u64,
        leader: Sha256Digest,
        blocks: Vec<BlockRef<Sha256Digest>>,
        proposed: &[u64],
        settled: &[bool],
    ) -> FinalityFact<Sha256Digest> {
        let chains = blocks.len();
        FinalityFact::new(
            FinalityId::Direct(Sha256::hash(&[b"pool", &view.to_be_bytes()])),
            Round::new(Epoch::zero(), View::new(view)),
            leader,
            CertificateId::new(Sha256::hash(&[b"vqc"])),
            5,
            blocks,
            heights(proposed),
            vec![Position::new(0); chains],
            settled.to_vec(),
        )
    }

    fn fact(
        view: u64,
        leader: Sha256Digest,
        blocks: &[u64],
        proposed: &[u64],
        settled: &[bool],
    ) -> FinalityFact<Sha256Digest> {
        fact_with(view, leader, frontier(blocks), proposed, settled)
    }

    /// Records `record` as the history of `leader` in `view` and returns what it placed.
    fn history(
        placement: &mut PlacementState<Sha256Digest>,
        view: u64,
        leader: Sha256Digest,
        record: &Arc<TipRecord<Sha256Digest>>,
    ) -> Placed {
        let mut placed = Vec::new();
        placement.history(
            View::new(view),
            leader,
            commitment(record),
            record,
            &mut placed,
        );
        placed
    }

    fn finality(
        placement: &mut PlacementState<Sha256Digest>,
        fact: &FinalityFact<Sha256Digest>,
    ) -> Placed {
        let mut placed = Vec::new();
        placement.finality(fact, &mut placed);
        placed
    }

    /// Returns the runs `activities` report, in order.
    fn runs(activities: &Placed) -> Vec<Run> {
        activities
            .iter()
            .flat_map(|activity| match activity {
                Activity::Placed { placed, .. } => placed
                    .iter()
                    .map(|run| (run.tip(), run.above().get(), run.height().get()))
                    .collect(),
                _ => Vec::new(),
            })
            .collect()
    }

    #[test]
    fn a_settled_fact_places_its_history_then_its_final_sweep() {
        let mut placement = state(2);
        let opening = record(genesis(), frontier(&[1, 1]));
        assert!(history(&mut placement, 3, leader(3), &opening).is_empty());
        let finalized = fact(3, leader(3), &[3, 2], &[3, 2], &[true, true]);
        let placed = finality(&mut placement, &finalized);
        assert_eq!(
            placed,
            vec![Activity::Placed {
                view: View::new(3),
                evidence: finalized.id(),
                history: commitment(&opening),
                placed: vec![
                    Placement::new(reference(0, 1), Height::zero(), Height::new(1)),
                    Placement::new(reference(1, 1), Height::zero(), Height::new(1)),
                    Placement::new(reference(0, 3), Height::new(1), Height::new(3)),
                    Placement::new(reference(1, 2), Height::new(1), Height::new(2)),
                ],
            }]
        );
        assert_eq!(placement.heights(), heights(&[3, 2]));
    }

    #[test]
    fn placement_starts_above_the_genesis_tips() {
        let mut placement = PlacementState::new(genesis(), &frontier(&[2, 0]), Lanes::none());
        let opening = record(genesis(), frontier(&[2, 0]));
        history(&mut placement, 1, leader(1), &opening);
        let placed = finality(
            &mut placement,
            &fact(1, leader(1), &[2, 1], &[2, 1], &[true, true]),
        );
        assert_eq!(runs(&placed), vec![(reference(1, 1), 0, 1)]);
    }

    #[test]
    fn every_opening_since_the_last_placed_one_is_placed_oldest_first() {
        let mut placement = state(2);
        // Leader 2 is certified but never finalized; leader 3 builds on it.
        let first = record(genesis(), frontier(&[1, 1]));
        let second = record(commitment(&first), frontier(&[2, 1]));
        history(&mut placement, 2, leader(2), &first);
        history(&mut placement, 3, leader(3), &second);
        let placed = finality(
            &mut placement,
            &fact(3, leader(3), &[3, 1], &[3, 1], &[true, true]),
        );
        assert_eq!(
            runs(&placed),
            vec![
                (reference(0, 1), 0, 1),
                (reference(1, 1), 0, 1),
                (reference(0, 2), 1, 2),
                (reference(0, 3), 2, 3),
            ]
        );
    }

    #[test]
    fn an_anchor_jump_places_only_the_blocks_read_off_each_tip() {
        // Chain 0 holds A1 <- A2 and a rival B2 <- B3 that also extends A1.
        let rival = |height: u64| {
            BlockRef::new(
                ChainId::new(0),
                Height::new(height),
                Sha256::hash(&[b"rival", &height.to_be_bytes()]),
            )
        };
        let opening = record(genesis(), vec![reference(0, 2)]);
        let jump = fact_with(2, leader(2), vec![rival(3)], &[3], &[true]);

        let mut placement = state(1);
        history(&mut placement, 2, leader(2), &opening);
        let placed = finality(&mut placement, &jump);
        // Marshal emits A1 and A2 from the opening, then only B3 from the sweep: B2 is never
        // placed.
        assert_eq!(
            runs(&placed),
            vec![(reference(0, 2), 0, 2), (rival(3), 2, 3)]
        );

        // A restarted tracker that never saw the opening chain from the ordered one names only
        // the later sweep runs.
        let mut restarted = state(1);
        let later = record(Sha256::hash(&[b"unseen opening"]), vec![rival(3)]);
        history(&mut restarted, 5, leader(5), &later);
        let placed = finality(
            &mut restarted,
            &fact_with(5, leader(5), vec![rival(4)], &[4], &[true]),
        );
        assert_eq!(runs(&placed), vec![(rival(4), 3, 4)]);
        assert_eq!(restarted.heights(), heights(&[4]));
    }

    #[test]
    fn a_missing_opening_advances_heights_without_naming_its_blocks() {
        let mut placement = state(2);
        let unseen = record(genesis(), frontier(&[1, 1]));
        let opening = record(commitment(&unseen), frontier(&[2, 2]));
        history(&mut placement, 4, leader(4), &opening);
        let placed = finality(
            &mut placement,
            &fact(4, leader(4), &[3, 2], &[3, 2], &[true, true]),
        );
        assert_eq!(runs(&placed), vec![(reference(0, 3), 2, 3)]);
        assert_eq!(placement.heights(), heights(&[3, 2]));

        // The next opening extends the one now ordered, so its runs are named again.
        let next = record(commitment(&opening), frontier(&[3, 3]));
        history(&mut placement, 5, leader(5), &next);
        let placed = finality(
            &mut placement,
            &fact(5, leader(5), &[3, 3], &[3, 3], &[true, true]),
        );
        assert_eq!(runs(&placed), vec![(reference(1, 3), 2, 3)]);
    }

    #[test]
    fn finalized_blocks_behind_a_shortfall_wait_for_a_later_view() {
        let mut placement = state(2);
        let first = record(genesis(), frontier(&[0, 0]));
        history(&mut placement, 3, leader(3), &first);
        // Chain 0 finalized only height 1 of a proposal reaching 2, so the sweep halts at chain
        // 0's offset 2: chain 1's block at height 2 is final but not yet placed.
        let placed = finality(
            &mut placement,
            &fact(3, leader(3), &[1, 3], &[2, 2], &[false, true]),
        );
        assert_eq!(placement.heights(), heights(&[1, 1]));
        assert_eq!(
            runs(&placed),
            vec![(reference(0, 1), 0, 1), (reference(1, 3), 0, 1)]
        );

        // The next view's opening carries both chains past the halt.
        let second = record(commitment(&first), frontier(&[2, 3]));
        history(&mut placement, 4, leader(4), &second);
        let placed = finality(
            &mut placement,
            &fact(4, leader(4), &[2, 3], &[2, 3], &[true, true]),
        );
        assert_eq!(placement.heights(), heights(&[2, 3]));
        assert_eq!(
            runs(&placed),
            vec![(reference(0, 2), 1, 2), (reference(1, 3), 1, 3)]
        );
    }

    #[test]
    fn payment_blocks_behind_a_shortfall_are_placed_at_once() {
        // Chain 1 is a payment chain: the payment pass places it up to its finalized tip before
        // chain 0's shortfall halts the ordinary pass.
        let mut placement =
            PlacementState::new(genesis(), &frontier(&[0, 0]), Lanes::new([false, true]));
        let first = record(genesis(), frontier(&[0, 0]));
        history(&mut placement, 3, leader(3), &first);
        let placed = finality(
            &mut placement,
            &fact(3, leader(3), &[1, 3], &[2, 2], &[false, true]),
        );
        assert_eq!(placement.heights(), heights(&[1, 3]));
        assert_eq!(
            runs(&placed),
            vec![(reference(0, 1), 0, 1), (reference(1, 3), 0, 3)]
        );

        // The next view's opening carries chain 0 past the halt; chain 1 is already placed.
        let second = record(commitment(&first), frontier(&[2, 3]));
        history(&mut placement, 4, leader(4), &second);
        let placed = finality(
            &mut placement,
            &fact(4, leader(4), &[2, 3], &[2, 3], &[true, true]),
        );
        assert_eq!(placement.heights(), heights(&[2, 3]));
        assert_eq!(runs(&placed), vec![(reference(0, 2), 1, 2)]);
    }

    #[test]
    fn an_unsettled_extension_is_placed_once_an_update_settles_it() {
        let mut placement = state(2);
        history(
            &mut placement,
            2,
            leader(2),
            &record(genesis(), frontier(&[0, 0])),
        );
        // Chain 0 proposed nothing and is unsettled; chain 1's extension above its proposed tip
        // waits behind chain 0's empty slot.
        finality(
            &mut placement,
            &fact(2, leader(2), &[0, 4], &[0, 3], &[false, true]),
        );
        assert_eq!(placement.heights(), heights(&[0, 3]));

        // More votes settle chain 0, and the same leader's updated fact places the extension
        // without reporting its history again.
        let placed = finality(
            &mut placement,
            &fact(2, leader(2), &[0, 4], &[0, 3], &[true, true]),
        );
        assert_eq!(runs(&placed), vec![(reference(1, 4), 3, 4)]);
    }

    #[test]
    fn a_fact_that_advances_nothing_reports_nothing() {
        let mut placement = state(2);
        history(
            &mut placement,
            2,
            leader(2),
            &record(genesis(), frontier(&[0, 0])),
        );
        let settled = fact(2, leader(2), &[1, 1], &[1, 1], &[true, true]);
        assert_eq!(finality(&mut placement, &settled).len(), 1);
        assert!(finality(&mut placement, &settled).is_empty());
    }

    #[test]
    fn a_fact_waits_for_its_leaders_history_record() {
        let mut placement = state(2);
        let waiting = fact(5, leader(5), &[2, 2], &[2, 2], &[true, true]);
        assert!(finality(&mut placement, &waiting).is_empty());
        // A record of an equivocating leader of the same view does not apply the fact.
        let equivocation = record(genesis(), frontier(&[1, 0]));
        assert!(history(&mut placement, 5, leader(50), &equivocation).is_empty());
        assert_eq!(placement.heights(), heights(&[0, 0]));

        let placed = history(
            &mut placement,
            5,
            leader(5),
            &record(genesis(), frontier(&[1, 1])),
        );
        assert_eq!(
            runs(&placed),
            vec![
                (reference(0, 1), 0, 1),
                (reference(1, 1), 0, 1),
                (reference(0, 2), 1, 2),
                (reference(1, 2), 1, 2),
            ]
        );
        assert_eq!(placement.heights(), heights(&[2, 2]));
    }

    #[test]
    fn a_record_alone_places_nothing() {
        let mut placement = state(2);
        let opening = record(genesis(), frontier(&[4, 4]));
        assert!(history(&mut placement, 1, leader(1), &opening).is_empty());
        assert_eq!(placement.heights(), heights(&[0, 0]));
    }

    #[test]
    fn placement_never_regresses_and_ignores_lower_views() {
        let mut placement = state(2);
        history(
            &mut placement,
            7,
            leader(7),
            &record(genesis(), frontier(&[3, 3])),
        );
        finality(
            &mut placement,
            &fact(7, leader(7), &[4, 4], &[4, 4], &[true, true]),
        );
        assert_eq!(placement.heights(), heights(&[4, 4]));

        // A lower view's late record and fact cannot move the frontier.
        let late = record(genesis(), frontier(&[1, 1]));
        assert!(history(&mut placement, 6, leader(6), &late).is_empty());
        assert!(
            finality(
                &mut placement,
                &fact(6, leader(6), &[5, 5], &[5, 5], &[true, true])
            )
            .is_empty()
        );
        assert_eq!(placement.heights(), heights(&[4, 4]));
        assert!(placement.leaders.keys().all(|view| *view >= View::new(7)));
        assert!(
            placement
                .openings
                .values()
                .all(|opening| opening.view >= View::new(7))
        );
    }

    #[test]
    fn malformed_inputs_place_nothing() {
        let mut placement = state(2);
        // A record or fact for the wrong number of chains is ignored.
        let wide = record(genesis(), frontier(&[1, 1, 1]));
        assert!(history(&mut placement, 1, leader(1), &wide).is_empty());
        assert!(placement.leaders.is_empty() && placement.openings.is_empty());
        history(
            &mut placement,
            2,
            leader(2),
            &record(genesis(), frontier(&[2, 2])),
        );
        // Final tips below the record's tips cannot form a sweep.
        assert!(
            finality(
                &mut placement,
                &fact(2, leader(2), &[1, 3], &[1, 3], &[true, true])
            )
            .is_empty()
        );
        assert_eq!(placement.heights(), heights(&[0, 0]));
    }

    #[test]
    fn retained_views_are_bounded() {
        let mut placement = state(1);
        // While finality stalls, records arrive for leaders that are never finalized and facts
        // for leaders whose records never arrive.
        for view in 1..=(RETAINED_VIEWS as u64 + 10) {
            let parent = Sha256::hash(&[b"parent", &view.to_be_bytes()]);
            history(
                &mut placement,
                view,
                leader(view),
                &record(parent, frontier(&[0])),
            );
            let unrecorded = Sha256::hash(&[b"unrecorded", &view.to_be_bytes()]);
            finality(&mut placement, &fact(view, unrecorded, &[1], &[1], &[true]));
        }
        assert_eq!(placement.leaders.len(), RETAINED_VIEWS);
        assert_eq!(placement.openings.len(), RETAINED_VIEWS);
        assert_eq!(placement.waiting.len(), RETAINED_VIEWS);
        assert_eq!(placement.heights(), heights(&[0]));
    }

    #[test]
    fn leaders_and_facts_of_one_view_are_bounded() {
        let mut placement = state(1);
        for marker in 0..100u64 {
            let equivocation = Sha256::hash(&[b"equivocation", &marker.to_be_bytes()]);
            let parent = Sha256::hash(&[b"parent", &marker.to_be_bytes()]);
            history(
                &mut placement,
                1,
                equivocation,
                &record(parent, frontier(&[0])),
            );
            finality(&mut placement, &fact(2, equivocation, &[1], &[1], &[true]));
        }
        // Mutually undominated facts of one leader: each settles a different chain.
        let mut two = state(2);
        for height in 1..=10 {
            finality(
                &mut two,
                &fact(
                    3,
                    leader(3),
                    &[height, 11 - height],
                    &[0, 0],
                    &[height % 2 == 0, height % 2 == 1],
                ),
            );
        }
        assert_eq!(placement.leaders[&View::new(1)].len(), RETAINED_RECORDS);
        assert_eq!(placement.openings.len(), RETAINED_RECORDS);
        assert_eq!(
            placement.waiting[&View::new(2)].len(),
            RETAINED_FACT_LEADERS
        );
        assert_eq!(two.waiting[&View::new(3)][&leader(3)].len(), RETAINED_FACTS);
        assert_eq!(placement.heights(), heights(&[0]));
    }

    #[test]
    fn undominated_waiting_facts_are_all_kept() {
        // Alone, the first fact places [0, 2] (chain 0 settled at its tip) and the second [1, 1]
        // (chain 0 unsettled one block above its tip): neither reaches the other.
        let opening = record(genesis(), frontier(&[0, 0]));
        let settled_low = fact(3, leader(3), &[0, 2], &[0, 0], &[true, false]);
        let unsettled_high = fact(3, leader(3), &[1, 2], &[0, 0], &[false, true]);
        for (fact, expected) in [(&settled_low, [0, 2]), (&unsettled_high, [1, 1])] {
            let mut alone = state(2);
            history(&mut alone, 3, leader(3), &opening);
            finality(&mut alone, fact);
            assert_eq!(alone.heights(), heights(&expected));
        }

        let mut placement = state(2);
        finality(&mut placement, &settled_low);
        finality(&mut placement, &unsettled_high);
        // A fact another one reaches adds nothing.
        finality(
            &mut placement,
            &fact(3, leader(3), &[0, 1], &[0, 0], &[true, false]),
        );
        assert_eq!(placement.waiting[&View::new(3)][&leader(3)].len(), 2);

        // Once the record arrives, the order both facts fix is placed.
        history(&mut placement, 3, leader(3), &opening);
        assert_eq!(placement.heights(), heights(&[1, 2]));
    }

    #[test]
    fn a_finalized_leader_is_placeable_after_equivocations_of_its_view() {
        let mut placement = state(1);
        for marker in 0..8u64 {
            let equivocation = Sha256::hash(&[b"equivocation", &marker.to_be_bytes()]);
            let parent = Sha256::hash(&[b"parent", &marker.to_be_bytes()]);
            history(
                &mut placement,
                1,
                equivocation,
                &record(parent, frontier(&[0])),
            );
        }
        history(
            &mut placement,
            1,
            leader(1),
            &record(genesis(), frontier(&[0])),
        );
        let placed = finality(&mut placement, &fact(1, leader(1), &[1], &[1], &[true]));
        assert_eq!(runs(&placed), vec![(reference(0, 1), 0, 1)]);
    }

    /// Returns the commitments of the records proven through `history`.
    fn proven(
        placement: &mut PlacementState<Sha256Digest>,
        history: Sha256Digest,
    ) -> Vec<Sha256Digest> {
        placement
            .proven(history)
            .iter()
            .map(|record| commitment(record))
            .collect()
    }

    #[test]
    fn placed_records_are_proven_once_oldest_first() {
        let mut placement = state(2);
        let first = record(genesis(), frontier(&[1, 1]));
        let second = record(commitment(&first), frontier(&[2, 1]));
        history(&mut placement, 2, leader(2), &first);
        history(&mut placement, 3, leader(3), &second);
        // Nothing is queued before its order is placed.
        assert!(proven(&mut placement, commitment(&first)).is_empty());
        finality(
            &mut placement,
            &fact(3, leader(3), &[2, 1], &[2, 1], &[true, true]),
        );

        // An unknown history takes nothing.
        assert!(proven(&mut placement, Sha256::hash(&[b"unknown"])).is_empty());
        assert_eq!(placement.unproven.len(), 2);
        // A proof of the older leader takes only its own record, then the newer proof the rest.
        assert_eq!(
            proven(&mut placement, commitment(&first)),
            vec![commitment(&first)]
        );
        assert!(proven(&mut placement, commitment(&first)).is_empty());
        assert_eq!(
            proven(&mut placement, commitment(&second)),
            vec![commitment(&second)]
        );
        assert!(placement.unproven.is_empty());
    }

    #[test]
    fn a_disconnected_opening_queues_the_suffix_it_holds() {
        let mut placement = state(2);
        let unseen = record(genesis(), frontier(&[1, 1]));
        let held = record(commitment(&unseen), frontier(&[2, 2]));
        let next = record(commitment(&held), frontier(&[3, 2]));
        history(&mut placement, 4, leader(4), &held);
        history(&mut placement, 5, leader(5), &next);
        finality(
            &mut placement,
            &fact(5, leader(5), &[3, 2], &[3, 2], &[true, true]),
        );
        assert_eq!(
            proven(&mut placement, commitment(&next)),
            vec![commitment(&held), commitment(&next)]
        );
    }

    #[test]
    fn a_late_intermediate_opening_is_placed_once_it_arrives() {
        let mut placement = state(1);
        let first = record(genesis(), frontier(&[1]));
        history(&mut placement, 10, leader(10), &first);
        finality(&mut placement, &fact(10, leader(10), &[2], &[2], &[true]));
        assert_eq!(placement.heights(), heights(&[2]));

        // Leader 11's record waits on a parent this node has not observed yet, so its finality
        // waits too; leader 12 builds on it and is finalized first.
        let second = record(commitment(&first), frontier(&[3]));
        let third = record(commitment(&second), frontier(&[5]));
        assert!(finality(&mut placement, &fact(11, leader(11), &[4], &[4], &[true])).is_empty());
        history(&mut placement, 12, leader(12), &third);
        let early = finality(&mut placement, &fact(12, leader(12), &[6], &[6], &[true]));
        // Nothing is placed past the gap until it is known.
        assert!(early.is_empty());
        assert_eq!(placement.heights(), heights(&[2]));

        let late = history(&mut placement, 11, leader(11), &second);
        assert_eq!(
            runs(&late),
            vec![
                (reference(0, 3), 2, 3),
                (reference(0, 4), 3, 4),
                (reference(0, 5), 4, 5),
                (reference(0, 6), 5, 6),
            ]
        );
        assert_eq!(
            proven(&mut placement, commitment(&third)),
            vec![commitment(&first), commitment(&second), commitment(&third)]
        );
    }

    #[test]
    fn a_late_intermediate_opening_without_finality_connects_the_stalled_fact() {
        let mut placement = state(1);
        let first = record(genesis(), frontier(&[1]));
        history(&mut placement, 10, leader(10), &first);
        finality(&mut placement, &fact(10, leader(10), &[1], &[1], &[true]));
        // Leader 11 is never finalized here; leader 12, which builds on it, is.
        let second = record(commitment(&first), frontier(&[3]));
        let third = record(commitment(&second), frontier(&[4]));
        history(&mut placement, 12, leader(12), &third);
        assert!(finality(&mut placement, &fact(12, leader(12), &[4], &[4], &[true])).is_empty());
        let late = history(&mut placement, 11, leader(11), &second);
        assert_eq!(
            runs(&late),
            vec![(reference(0, 3), 1, 3), (reference(0, 4), 3, 4)]
        );
    }

    #[test]
    fn an_opening_that_never_arrives_stalls_placement_only_for_a_bounded_span() {
        let mut placement = state(1);
        let first = record(genesis(), frontier(&[1]));
        history(&mut placement, 10, leader(10), &first);
        finality(&mut placement, &fact(10, leader(10), &[1], &[1], &[true]));
        // Leader 11's record never arrives.
        let mut parent = commitment(&record(commitment(&first), frontier(&[2])));
        let mut placed = Vec::new();
        let mut view = 12;
        while placed.is_empty() {
            assert!(
                view < 12 + STALLED_VIEWS as u64 + 2,
                "placement stalled without bound"
            );
            let opening = record(parent, frontier(&[view]));
            history(&mut placement, view, leader(view), &opening);
            placed = finality(
                &mut placement,
                &fact(view, leader(view), &[view], &[view], &[true]),
            );
            parent = commitment(&opening);
            view += 1;
        }
        // The gap is skipped; everything the held openings name after it is placed.
        assert_eq!(placement.heights(), heights(&[view - 1]));
        let resumed = record(parent, frontier(&[view]));
        history(&mut placement, view, leader(view), &resumed);
        let next = finality(
            &mut placement,
            &fact(view, leader(view), &[view], &[view], &[true]),
        );
        assert_eq!(runs(&next), vec![(reference(0, view), view - 1, view)]);
    }

    #[test]
    fn unproven_records_are_bounded() {
        let mut placement = state(1);
        let mut parent = genesis();
        let mut first = None;
        for view in 1..=(RETAINED_UNPROVEN as u64 + 5) {
            let opening = record(parent, frontier(&[view]));
            history(&mut placement, view, leader(view), &opening);
            finality(
                &mut placement,
                &fact(view, leader(view), &[view], &[view], &[true]),
            );
            parent = commitment(&opening);
            first.get_or_insert(parent);
        }
        assert_eq!(placement.unproven.len(), RETAINED_UNPROVEN);
        // The oldest records were dropped; the newest proof takes every retained one.
        assert!(proven(&mut placement, first.unwrap()).is_empty());
        assert_eq!(proven(&mut placement, parent).len(), RETAINED_UNPROVEN);
    }
}

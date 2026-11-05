//! Order: the proven positions from the delivered cut forward, and the exact block of each.
//!
//! The order is fed only from durable proofs: the history records that connect the delivered cut
//! to the horizon L-QC's leader history, oldest first, then that L-QC's final sweep (see
//! [`Expansion`]). A stronger or later horizon abandons the sweep in progress; the openings that
//! follow skip what it already yielded.
//!
//! A position names a height and the authenticated tip whose ancestor fills it. Its exact block
//! is found by walking parent links down from the tip through held headers, never by height
//! alone: a height can hold rival blocks. The path walked from each tip is cached until the
//! delivered height of its chain reaches the tip, so a run of positions under one tip costs one
//! walk.

use crate::{
    multimmit::{
        order::{Cut, Error as OrderError, Expansion, Position, SweepFact},
        types::{BlockRef, CertificateId, TipRecord},
    },
    types::Height,
};
use commonware_cryptography::Digest;
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::Arc,
};

/// The L-QC whose proof bounds the order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Target<D: Digest> {
    /// The certificate's identifier.
    pub(crate) id: CertificateId<D>,
    /// The leader's history commitment.
    pub(crate) history: D,
    /// The local ordinal of that history.
    pub(crate) ordinal: u64,
    /// The finality the certificate proves.
    pub(crate) fact: Arc<SweepFact<D>>,
    /// The output index the certificate's cut closes, when known.
    pub(crate) strength: u64,
}

/// One proven position, with the cut after it and its exact block once resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Slot<D: Digest> {
    /// The position.
    pub(crate) position: Position<D>,
    /// The history of the cut after this position.
    pub(crate) history: D,
    /// The tips of that history's record.
    pub(crate) ordered: Arc<[BlockRef<D>]>,
    /// The exact block filling the position, once resolved.
    pub(crate) block: Option<BlockRef<D>>,
}

impl<D: Digest> Slot<D> {
    /// Returns the chain index of the slot.
    pub(crate) const fn chain(&self) -> usize {
        self.position.chain().get() as usize
    }
}

/// The path walked down from one tip.
#[derive(Clone, Debug)]
struct Path<D: Digest> {
    /// The tip and the blocks walked below it, by height.
    blocks: BTreeMap<Height, BlockRef<D>>,
    /// Every block from this height up to the tip is durable.
    durable_from: Option<Height>,
}

impl<D: Digest> Path<D> {
    fn new(tip: BlockRef<D>) -> Self {
        Self {
            blocks: BTreeMap::from([(tip.height(), tip)]),
            durable_from: None,
        }
    }

    fn lowest(&self) -> Option<BlockRef<D>> {
        self.blocks.first_key_value().map(|(_, block)| *block)
    }
}

/// A block an unresolved position needs: the first missing block of a path, and the lowest
/// height the path must reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Need<D: Digest> {
    /// The missing block.
    pub(crate) block: BlockRef<D>,
    /// The lowest height wanted below it.
    pub(crate) low: Height,
}

/// Openings queued ahead of the step being expanded. Feeding stops there and resumes as steps
/// are consumed, so a far target costs bounded work and memory per turn.
const AHEAD: usize = 4;

/// What feeding the order needs next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Feed {
    /// Everything up to the target is queued.
    Done,
    /// Enough openings are queued ahead; feeding resumes once they are consumed.
    Ahead,
    /// The record at this ordinal is not durable and in memory yet.
    Record(u64),
    /// The ends of the L-QCs at this opened ordinal are not all projected yet; feeding past it
    /// could deliver past an end before it is known.
    Unprojected(u64),
}

/// The proven positions from the delivered cut forward.
pub(crate) struct Order<D: Digest> {
    expansion: Expansion<D>,
    /// Ordinal of the newest record whose opening is queued (the expansion's eventual history).
    queued: u64,
    /// The cut after each queued opening (and the starting cut), by the record's ordinal: an
    /// L-QC whose leader history is that record ends its order at this cut plus its sweep.
    opened: BTreeMap<u64, Cut<D>>,
    /// The L-QC whose sweep is queued.
    swept: Option<CertificateId<D>>,
    /// Ordinal of the record of the cut the order started at.
    start: u64,
    /// Positions taken from the expansion and not yet dispatched, in index order.
    window: VecDeque<Slot<D>>,
    capacity: usize,
    /// Paths walked from the tips of positions not yet delivered.
    paths: HashMap<BlockRef<D>, Path<D>>,
}

impl<D: Digest> Order<D> {
    /// Starts at `cut`, whose history has local ordinal `ordinal`, holding at most `capacity`
    /// undispatched positions.
    pub(crate) fn new(cut: Cut<D>, ordinal: u64, capacity: usize) -> Self {
        Self {
            opened: BTreeMap::from([(ordinal, cut.clone())]),
            expansion: Expansion::new(cut),
            queued: ordinal,
            swept: None,
            start: ordinal,
            window: VecDeque::with_capacity(capacity),
            capacity,
            paths: HashMap::new(),
        }
    }

    /// Returns the cut after the newest position taken into the window.
    pub(crate) const fn cut(&self) -> &Cut<D> {
        self.expansion.cut()
    }

    /// Returns the ordinal of the newest record whose opening is queued.
    pub(crate) const fn queued(&self) -> u64 {
        self.queued
    }

    /// Returns the ordinal of the record of the cut the order started at: [`Self::opened`] holds
    /// that cut there, which may lie past the cut the record's opening reaches.
    pub(crate) const fn start(&self) -> u64 {
        self.start
    }

    /// Returns the L-QC whose sweep is queued.
    pub(crate) const fn swept(&self) -> Option<CertificateId<D>> {
        self.swept
    }

    /// Returns whether every position up to the queued target has been taken.
    pub(crate) fn exhausted(&self) -> bool {
        self.expansion.is_idle()
    }

    /// Returns the cut after the opening of the record at `ordinal`, if it was queued here.
    pub(crate) fn opened(&self, ordinal: u64) -> Option<&Cut<D>> {
        self.opened.get(&ordinal)
    }

    /// Forgets the cuts of openings below `ordinal`.
    pub(crate) fn forget_below(&mut self, ordinal: u64) {
        self.opened = self.opened.split_off(&ordinal);
    }

    /// Returns the undispatched positions.
    pub(crate) const fn window(&self) -> &VecDeque<Slot<D>> {
        &self.window
    }

    /// Queues the order up to `target`: the openings of the records after the queued one through
    /// the target's history, then its sweep. `record` returns a durable, connected record by
    /// ordinal, and `projected` whether the ends of every L-QC at or below an opened ordinal are
    /// known: an L-QC's end lies at or after the cut its history opens, so nothing after that cut
    /// is queued before then ([`Feed::Unprojected`]).
    ///
    /// A target behind the queued history proves nothing new and is ignored. At most a few
    /// openings are queued ahead of the step being expanded ([`Feed::Ahead`]); calling again once
    /// they are consumed continues.
    pub(crate) fn feed(
        &mut self,
        target: &Target<D>,
        mut record: impl FnMut(u64) -> Option<(D, Arc<TipRecord<D>>)>,
        projected: impl Fn(u64) -> bool,
    ) -> Feed {
        if target.ordinal < self.queued || self.swept == Some(target.id) {
            return Feed::Done;
        }
        if self.swept.take().is_some() {
            // An earlier sweep is a prefix of what the target proves: drop what it has not
            // yielded yet, and let the openings that follow skip what it has.
            self.expansion.abandon_sweep();
        }
        while self.queued < target.ordinal {
            if self.expansion.pending_steps() >= AHEAD {
                return Feed::Ahead;
            }
            if !projected(self.queued) {
                return Feed::Unprojected(self.queued);
            }
            let Some((commitment, opened)) = record(self.queued + 1) else {
                return Feed::Record(self.queued + 1);
            };
            let cut = self
                .opened
                .get(&self.queued)
                .and_then(|cut| cut.open(commitment, &opened).ok());
            if let Some(cut) = cut {
                self.opened.insert(self.queued + 1, cut);
            }
            self.expansion.open(commitment, opened);
            self.queued += 1;
        }
        if !projected(self.queued) {
            return Feed::Unprojected(self.queued);
        }
        self.expansion.sweep(Arc::clone(&target.fact));
        self.swept = Some(target.id);
        Feed::Done
    }

    /// Takes positions into the window until it is full or the queued order is exhausted.
    pub(crate) fn fill(&mut self) -> Result<(), OrderError> {
        while self.window.len() < self.capacity {
            let Some(position) = self.expansion.next_position()? else {
                break;
            };
            let cut = self.expansion.cut();
            self.window.push_back(Slot {
                position,
                history: cut.history(),
                ordered: cut.shared_ordered(),
                block: None,
            });
        }
        Ok(())
    }

    /// Resolves the exact block of every unresolved position in the window that held headers
    /// allow, returning the first missing block of each chain's path. `parent` returns the parent
    /// of a held or queued block.
    pub(crate) fn resolve(
        &mut self,
        mut parent: impl FnMut(BlockRef<D>) -> Option<BlockRef<D>>,
    ) -> Vec<Need<D>> {
        let mut needs: Vec<Need<D>> = Vec::new();
        for slot in self.window.iter_mut() {
            if slot.block.is_some() {
                continue;
            }
            let tip = slot.position.tip;
            if needs.iter().any(|need| need.block.chain() == tip.chain()) {
                continue;
            }
            let path = self.paths.entry(tip).or_insert_with(|| Path::new(tip));
            let height = slot.position.height;
            loop {
                if let Some(block) = path.blocks.get(&height) {
                    slot.block = Some(*block);
                    // The tip is resolved by its authenticated reference alone; it still has to be
                    // held, like every block on the path.
                    if parent(*block).is_none() {
                        needs.push(Need {
                            block: *block,
                            low: height,
                        });
                    }
                    break;
                }
                let lowest = path.lowest().expect("a path holds its tip");
                let Some(next) = parent(lowest) else {
                    needs.push(Need {
                        block: lowest,
                        low: height,
                    });
                    break;
                };
                debug_assert_eq!(next.height().get() + 1, lowest.height().get());
                path.blocks.insert(next.height(), next);
            }
        }
        needs
    }

    /// Returns the front position when it is resolved and every block from it up to its tip is
    /// durable.
    pub(crate) fn ready(
        &mut self,
        mut durable: impl FnMut(BlockRef<D>) -> bool,
    ) -> Option<&Slot<D>> {
        let slot = self.window.front()?;
        let block = slot.block?;
        let tip = slot.position.tip;
        let path = self.paths.get_mut(&tip)?;
        let mut from = path
            .durable_from
            .unwrap_or_else(|| Height::new(tip.height().get() + 1));
        while from > block.height() {
            let below = Height::new(from.get() - 1);
            match path.blocks.get(&below) {
                Some(next) if durable(*next) => from = below,
                _ => break,
            }
        }
        path.durable_from = Some(from);
        (from <= block.height()).then_some(slot)
    }

    /// Takes the front position, which [`Self::ready`] returned.
    pub(crate) fn pop(&mut self) -> Option<Slot<D>> {
        let slot = self.window.pop_front()?;
        if let Some(block) = slot.block {
            // Every later position of the chain lies above the delivered block, so no path whose
            // tip is at or below it is needed again, and no path needs what lies below it.
            let chain = block.chain();
            self.paths.retain(|tip, path| {
                if tip.chain() != chain {
                    return true;
                }
                if tip.height() <= block.height() {
                    return false;
                }
                path.blocks = path.blocks.split_off(&block.height());
                true
            });
        }
        Some(slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::types::ChainId;
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest as Sha256Digest};
    use std::collections::HashMap;

    type D = Sha256Digest;

    /// Block `height` of `chain` on branch `branch`, whose parent is the same branch's block
    /// below unless `fork` says the branch starts above another.
    fn block(chain: u32, height: u64, branch: u8) -> BlockRef<D> {
        BlockRef::new(
            ChainId::new(chain),
            Height::new(height),
            Sha256::hash(&[&chain.to_be_bytes(), &height.to_be_bytes(), &[branch]]),
        )
    }

    fn genesis() -> D {
        Sha256::hash(&[b"genesis"])
    }

    fn start(chains: u32) -> Cut<D> {
        Cut::new(
            genesis(),
            (0..chains)
                .map(|chain| block(chain, 0, 0))
                .collect::<Vec<_>>()
                .into(),
            vec![Height::zero(); chains as usize],
        )
        .unwrap()
    }

    fn record(parent: D, tips: Vec<BlockRef<D>>) -> (D, Arc<TipRecord<D>>) {
        let record = TipRecord::at_tips(parent, tips).unwrap();
        (record.commitment::<Sha256>(), Arc::new(record))
    }

    fn target(id: u8, history: D, ordinal: u64, tips: Vec<BlockRef<D>>) -> Target<D> {
        let proposed = tips.iter().map(BlockRef::height).collect();
        let settled = vec![true; tips.len()];
        Target {
            id: CertificateId::new(Sha256::hash(&[&[id]])),
            history,
            ordinal,
            fact: Arc::new(SweepFact::new(tips, proposed, settled).unwrap()),
            strength: 0,
        }
    }

    /// Parent links of branch 0 on every chain.
    fn linear(block: BlockRef<D>) -> Option<BlockRef<D>> {
        (block.height().get() > 0)
            .then(|| self::block(block.chain().get(), block.height().get() - 1, 0))
    }

    fn drain(
        order: &mut Order<D>,
        durable: impl Fn(BlockRef<D>) -> bool + Copy,
    ) -> Vec<(u32, u64)> {
        let mut out = Vec::new();
        loop {
            order.fill().unwrap();
            assert!(order.resolve(linear).is_empty());
            if order.ready(durable).is_none() {
                return out;
            }
            let slot = order.pop().unwrap();
            let block = slot.block.unwrap();
            out.push((block.chain().get(), block.height().get()));
        }
    }

    #[test]
    fn records_then_sweep_resolve_through_held_parents() {
        let (first, opened) = record(genesis(), vec![block(0, 2, 0), block(1, 1, 0)]);
        let records = HashMap::from([(1u64, (first, opened))]);
        let mut order = Order::new(start(2), 0, 16);
        let proof = target(1, first, 1, vec![block(0, 3, 0), block(1, 2, 0)]);
        assert_eq!(
            order.feed(&proof, |ordinal| records.get(&ordinal).cloned(), |_| true),
            Feed::Done
        );
        assert_eq!(order.swept(), Some(proof.id));
        // Feeding the same target again queues nothing.
        assert_eq!(order.feed(&proof, |_| None, |_| true), Feed::Done);
        assert_eq!(
            drain(&mut order, |_| true),
            vec![(0, 1), (1, 1), (0, 2), (0, 3), (1, 2)]
        );
        assert!(order.exhausted());
        assert_eq!(order.cut().index(), 5);
        assert_eq!(order.cut().history(), first);
    }

    #[test]
    fn a_missing_record_stops_feeding_until_it_arrives() {
        let (first, opened) = record(genesis(), vec![block(0, 1, 0)]);
        let (second, next) = record(first, vec![block(0, 2, 0)]);
        let mut order = Order::new(start(1), 0, 16);
        let proof = target(1, second, 2, vec![block(0, 2, 0)]);
        let mut records = HashMap::from([(1u64, (first, opened))]);
        assert_eq!(
            order.feed(&proof, |ordinal| records.get(&ordinal).cloned(), |_| true),
            Feed::Record(2)
        );
        assert_eq!(order.queued(), 1);
        assert_eq!(drain(&mut order, |_| true), vec![(0, 1)]);
        records.insert(2, (second, next));
        assert_eq!(
            order.feed(&proof, |ordinal| records.get(&ordinal).cloned(), |_| true),
            Feed::Done
        );
        assert_eq!(drain(&mut order, |_| true), vec![(0, 2)]);
    }

    #[test]
    fn feeding_waits_at_an_ordinal_whose_ends_are_not_projected() {
        let (first, opened) = record(genesis(), vec![block(0, 1, 0)]);
        let (second, next) = record(first, vec![block(0, 2, 0)]);
        let records = HashMap::from([(1u64, (first, opened)), (2u64, (second, next))]);
        let mut order = Order::new(start(1), 0, 16);
        let proof = target(1, second, 2, vec![block(0, 3, 0)]);
        // Ordinal 1 opens, but its L-QCs' ends are unknown: the next record waits.
        let projected = std::cell::Cell::new(0u64);
        let feed = |order: &mut Order<D>| {
            order.feed(
                &proof,
                |ordinal| records.get(&ordinal).cloned(),
                |ordinal| ordinal < projected.get(),
            )
        };
        projected.set(1);
        assert_eq!(feed(&mut order), Feed::Unprojected(1));
        assert_eq!(order.queued(), 1);
        assert_eq!(drain(&mut order, |_| true), vec![(0, 1)]);
        // Ordinal 2 opens once ordinal 1 is projected; the sweep waits for ordinal 2.
        projected.set(2);
        assert_eq!(feed(&mut order), Feed::Unprojected(2));
        assert_eq!(order.swept(), None);
        projected.set(3);
        assert_eq!(feed(&mut order), Feed::Done);
        assert_eq!(drain(&mut order, |_| true), vec![(0, 2), (0, 3)]);
    }

    #[test]
    fn missing_headers_and_durability_hold_the_front() {
        let (first, opened) = record(genesis(), vec![block(0, 3, 0)]);
        let mut order = Order::new(start(1), 0, 16);
        let proof = target(1, first, 1, vec![block(0, 3, 0)]);
        order.feed(&proof, |_| Some((first, opened.clone())), |_| true);
        order.fill().unwrap();
        // Nothing is held: the walk needs the tip first.
        let needs = order.resolve(|_| None);
        assert_eq!(
            needs,
            vec![Need {
                block: block(0, 3, 0),
                low: Height::new(1)
            }]
        );
        assert!(order.ready(|_| true).is_none());
        // With every header held but the tip not durable, the first position waits: its
        // identity rests on the whole path from the tip.
        assert!(order.resolve(linear).is_empty());
        let tip = block(0, 3, 0);
        assert!(order.ready(|block| block != tip).is_none());
        assert_eq!(drain(&mut order, |_| true), vec![(0, 1), (0, 2), (0, 3)]);
    }

    #[test]
    fn a_later_target_abandons_the_sweep_and_skips_what_it_yielded() {
        let (first, opened) = record(genesis(), vec![block(0, 0, 0), block(1, 0, 0)]);
        let (second, next) = record(first, vec![block(0, 3, 0), block(1, 2, 0)]);
        let records = HashMap::from([(1u64, (first, opened)), (2u64, (second, next))]);
        let mut order = Order::new(start(2), 0, 2);
        let early = target(1, first, 1, vec![block(0, 2, 0), block(1, 2, 0)]);
        order.feed(&early, |ordinal| records.get(&ordinal).cloned(), |_| true);
        // The window holds two positions of the early sweep.
        order.fill().unwrap();
        assert_eq!(order.window().len(), 2);
        let late = target(2, second, 2, vec![block(0, 3, 0), block(1, 2, 0)]);
        order.feed(&late, |ordinal| records.get(&ordinal).cloned(), |_| true);
        assert_eq!(order.swept(), Some(late.id));
        let mut seen = Vec::new();
        loop {
            order.fill().unwrap();
            order.resolve(linear);
            if order.ready(|_| true).is_none() {
                break;
            }
            let slot = order.pop().unwrap();
            seen.push((slot.position.chain().get(), slot.position.height.get()));
        }
        assert_eq!(seen, vec![(0, 1), (1, 1), (0, 2), (1, 2), (0, 3)]);
    }
}

//! Finals: final blocks reported ahead of their ordered delivery.
//!
//! A leader finality fact names every chain's final block, so every block on that block's path is
//! final before the order reaches it: a sweep can stop at a shortfall or an unsettled chain and
//! order those blocks in a later view. Each chain establishes the exact blocks on its newest final
//! tip's path by walking parent links through held headers, never by height alone (a height can
//! hold rival blocks), and hands out the oldest unreported ones, contiguous above the highest
//! block it reported or delivered.
//!
//! A chain walks its final tip down once, keeping a reference every `window` heights, so a far tip
//! costs one pass and each later window at most two windows of steps. A newer tip is walked down
//! to the current tip before it replaces it. A chain holds at most `window` ready references and
//! one reference per `window` heights between them and its tip.

use crate::{multimmit::types::BlockRef, types::Height};
use commonware_cryptography::Digest;
use std::{
    collections::{BTreeMap, VecDeque},
    num::NonZeroUsize,
};

/// The part of a final tip's path established so far.
#[derive(Clone, Debug)]
struct Walk<D: Digest> {
    /// The final tip.
    tip: BlockRef<D>,
    /// The lowest block established on the tip's path; its header continues the walk.
    low: BlockRef<D>,
    /// Established blocks at heights that are multiples of the window.
    marks: BTreeMap<Height, BlockRef<D>>,
}

impl<D: Digest> Walk<D> {
    const fn new(tip: BlockRef<D>) -> Self {
        Self {
            tip,
            low: tip,
            marks: BTreeMap::new(),
        }
    }

    /// Walks down while above `stop`, returning whether it reached `stop`.
    fn descend(
        &mut self,
        stop: Height,
        window: u64,
        parent: &impl Fn(BlockRef<D>) -> Option<BlockRef<D>>,
    ) -> bool {
        while self.low.height() > stop {
            if self.low.height().get().is_multiple_of(window) {
                self.marks.insert(self.low.height(), self.low);
            }
            let Some(next) = parent(self.low) else {
                return false;
            };
            self.low = next;
        }
        true
    }
}

/// One chain's reports.
#[derive(Clone, Debug)]
struct Chain<D: Digest> {
    /// The highest height reported or delivered in this run, or resumed from.
    done: Height,
    /// The final tip whose path is established down to its low block.
    walk: Option<Walk<D>>,
    /// A newer final tip, walked down to [`Self::walk`]'s tip before it replaces it.
    upper: Option<Walk<D>>,
    /// The next blocks to report, ascending and contiguous from `done + 1`.
    ready: VecDeque<BlockRef<D>>,
}

impl<D: Digest> Chain<D> {
    const fn new(done: Height) -> Self {
        Self {
            done,
            walk: None,
            upper: None,
            ready: VecDeque::new(),
        }
    }

    /// Returns the newest final tip known.
    fn tip(&self) -> Option<BlockRef<D>> {
        self.upper
            .as_ref()
            .or(self.walk.as_ref())
            .map(|walk| walk.tip)
    }

    /// Takes everything up to `height` as reported or delivered.
    fn pass(&mut self, height: Height) {
        if height <= self.done {
            return;
        }
        self.done = height;
        while self
            .ready
            .front()
            .is_some_and(|block| block.height() <= height)
        {
            self.ready.pop_front();
        }
        if self
            .upper
            .as_ref()
            .is_some_and(|upper| upper.tip.height() <= height)
        {
            self.upper = None;
        }
        match &mut self.walk {
            Some(walk) if walk.tip.height() <= height => self.walk = None,
            Some(walk) => walk.marks = walk.marks.split_off(&height.next()),
            None => {}
        }
    }

    /// Walks as far as held headers allow and refills the ready blocks.
    fn advance(&mut self, window: u64, parent: &impl Fn(BlockRef<D>) -> Option<BlockRef<D>>) {
        let next = self.done.next();
        if let Some(upper) = &mut self.upper {
            let stop = self.walk.as_ref().map_or(next, |walk| walk.tip.height());
            if upper.descend(stop, window, parent) {
                let upper = self.upper.take().expect("upper walk is present");
                match &mut self.walk {
                    Some(walk) if walk.tip == upper.low => {
                        walk.tip = upper.tip;
                        walk.marks.extend(upper.marks);
                    }
                    // Final tips that disagree need more faults than the protocol tolerates;
                    // follow the newer one.
                    Some(_) => {
                        self.ready.clear();
                        self.walk = Some(upper);
                    }
                    None => self.walk = Some(upper),
                }
            }
        }
        let Some(walk) = &mut self.walk else {
            return;
        };
        if !walk.descend(next, window, parent) || !self.ready.is_empty() {
            return;
        }
        // The path is established down to `next`: read the next window off it, starting at the
        // nearest mark at or above the window's top.
        let top = Height::new(
            self.done
                .get()
                .saturating_add(window)
                .min(walk.tip.height().get()),
        );
        let mut at = walk
            .marks
            .range(top..)
            .next()
            .map_or(walk.tip, |(_, block)| *block);
        let mut blocks = Vec::new();
        loop {
            if at.height() <= top {
                blocks.push(at);
            }
            if at.height() <= next {
                break;
            }
            match parent(at) {
                Some(below) => at = below,
                None => {
                    // A block the walk passed is no longer held: walk again.
                    *walk = Walk::new(walk.tip);
                    return;
                }
            }
        }
        self.ready = blocks.into_iter().rev().collect();
    }
}

/// Every chain's reports of final blocks ahead of ordered delivery.
#[derive(Clone, Debug)]
pub(super) struct Finals<D: Digest> {
    window: u64,
    chains: Vec<Chain<D>>,
}

impl<D: Digest> Finals<D> {
    /// Creates reports that resume above `done`, one height per chain, handing out at most
    /// `window` blocks of a chain at a time.
    pub(super) fn new(window: NonZeroUsize, done: &[Height]) -> Self {
        Self {
            window: window.get() as u64,
            chains: done.iter().copied().map(Chain::new).collect(),
        }
    }

    /// Takes a final tip, returning whether it is newer than every tip of its chain.
    pub(super) fn final_tip(&mut self, tip: BlockRef<D>) -> bool {
        let Some(chain) = self.chains.get_mut(tip.chain().get() as usize) else {
            return false;
        };
        if tip.height() <= chain.done
            || chain
                .tip()
                .is_some_and(|known| tip.height() <= known.height())
        {
            return false;
        }
        if chain.walk.is_some() {
            chain.upper = Some(Walk::new(tip));
        } else {
            chain.walk = Some(Walk::new(tip));
        }
        true
    }

    /// Takes `block` as delivered in order, or reported: nothing at or below it is reported.
    pub(super) fn delivered(&mut self, block: BlockRef<D>) {
        if let Some(chain) = self.chains.get_mut(block.chain().get() as usize) {
            chain.pass(block.height());
        }
    }

    /// Resumes every chain above `done` (an installed floor), keeping each newest final tip.
    pub(super) fn reset(&mut self, done: &[Height]) {
        for (chain, done) in self.chains.iter_mut().zip(done) {
            let tip = chain.tip();
            let done = chain.done.max(*done);
            *chain = Chain::new(done);
            chain.walk = tip.filter(|tip| tip.height() > done).map(Walk::new);
        }
    }

    /// Walks every chain as far as `parent` (a held block's parent) allows.
    pub(super) fn advance(&mut self, parent: impl Fn(BlockRef<D>) -> Option<BlockRef<D>>) {
        for chain in &mut self.chains {
            chain.advance(self.window, &parent);
        }
    }

    /// Returns the next blocks of `chain` to report, oldest first.
    pub(super) fn ready(&self, chain: usize) -> impl Iterator<Item = BlockRef<D>> + '_ {
        self.chains
            .get(chain)
            .into_iter()
            .flat_map(|chain| chain.ready.iter().copied())
    }

    /// Returns the number of chains.
    pub(super) const fn chains(&self) -> usize {
        self.chains.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::types::ChainId;
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest as Sha256Digest};
    use std::collections::HashMap;

    type D = Sha256Digest;

    fn block(chain: u32, height: u64, branch: u8) -> BlockRef<D> {
        BlockRef::new(
            ChainId::new(chain),
            Height::new(height),
            Sha256::hash(&[&chain.to_be_bytes(), &height.to_be_bytes(), &[branch]]),
        )
    }

    /// Held blocks, each with its parent.
    #[derive(Default)]
    struct Held(HashMap<BlockRef<D>, BlockRef<D>>);

    impl Held {
        /// Holds `branch`'s blocks `heights` of chain zero, branching off branch zero below
        /// `from`.
        fn hold(&mut self, branch: u8, from: u64, heights: std::ops::RangeInclusive<u64>) {
            for height in heights {
                let parent_branch = if height - 1 < from { 0 } else { branch };
                self.0.insert(
                    block(0, height, branch),
                    block(0, height - 1, parent_branch),
                );
            }
        }

        fn parent(&self) -> impl Fn(BlockRef<D>) -> Option<BlockRef<D>> + '_ {
            |block| self.0.get(&block).copied()
        }
    }

    fn finals(window: usize) -> Finals<D> {
        Finals::new(NonZeroUsize::new(window).unwrap(), &[Height::zero()])
    }

    fn heights(finals: &Finals<D>) -> Vec<u64> {
        finals.ready(0).map(|block| block.height().get()).collect()
    }

    /// Reports every ready block of chain zero, returning their heights.
    fn report(finals: &mut Finals<D>) -> Vec<u64> {
        let ready = finals.ready(0).collect::<Vec<_>>();
        for block in &ready {
            finals.delivered(*block);
        }
        ready.iter().map(|block| block.height().get()).collect()
    }

    #[test]
    fn the_tips_path_is_reported_oldest_first_one_window_at_a_time() {
        let mut held = Held::default();
        held.hold(0, 0, 1..=5);
        let mut finals = finals(2);
        assert!(finals.final_tip(block(0, 5, 0)));
        let mut reported = Vec::new();
        for _ in 0..4 {
            finals.advance(held.parent());
            assert!(heights(&finals).len() <= 2);
            reported.extend(report(&mut finals));
        }
        assert_eq!(reported, vec![1, 2, 3, 4, 5]);
        finals.advance(held.parent());
        assert!(heights(&finals).is_empty());
    }

    #[test]
    fn a_missing_block_holds_the_walk_until_it_is_held() {
        let mut held = Held::default();
        held.hold(0, 0, 1..=2);
        held.hold(0, 0, 4..=5);
        let mut finals = finals(8);
        finals.final_tip(block(0, 5, 0));
        finals.advance(held.parent());
        assert!(
            heights(&finals).is_empty(),
            "the path below height 4 is unknown"
        );
        held.hold(0, 0, 3..=3);
        finals.advance(held.parent());
        assert_eq!(heights(&finals), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn rival_blocks_off_the_tips_path_are_never_reported() {
        let mut held = Held::default();
        held.hold(0, 0, 1..=4);
        // Branch one forks above height one and is fully held.
        held.hold(1, 2, 2..=6);
        let mut finals = finals(8);
        finals.final_tip(block(0, 4, 0));
        finals.advance(held.parent());
        assert_eq!(
            finals.ready(0).collect::<Vec<_>>(),
            (1..=4)
                .map(|height| block(0, height, 0))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn delivery_passes_reports_and_slides_the_window() {
        let mut held = Held::default();
        held.hold(0, 0, 1..=6);
        let mut finals = finals(2);
        finals.final_tip(block(0, 6, 0));
        finals.advance(held.parent());
        assert_eq!(heights(&finals), vec![1, 2]);
        // Ordered delivery reaches height three first: nothing at or below it is reported.
        finals.delivered(block(0, 3, 0));
        assert!(heights(&finals).is_empty());
        finals.advance(held.parent());
        assert_eq!(heights(&finals), vec![4, 5]);
        // Delivering the tip ends the chain's reports.
        finals.delivered(block(0, 6, 0));
        finals.advance(held.parent());
        assert!(heights(&finals).is_empty());
        // An older tip changes nothing.
        assert!(!finals.final_tip(block(0, 5, 0)));
    }

    #[test]
    fn a_newer_tip_replaces_the_old_one_once_its_walk_connects() {
        let mut held = Held::default();
        held.hold(0, 0, 1..=3);
        held.hold(0, 0, 6..=7);
        let mut finals = finals(2);
        finals.final_tip(block(0, 3, 0));
        finals.advance(held.parent());
        assert_eq!(report(&mut finals), vec![1, 2]);
        // The old tip's path is still reported while the new tip, which cannot connect until
        // heights 4 and 5 are held, is walked.
        assert!(finals.final_tip(block(0, 7, 0)));
        finals.advance(held.parent());
        assert_eq!(heights(&finals), vec![3]);
        held.hold(0, 0, 4..=5);
        finals.advance(held.parent());
        assert_eq!(report(&mut finals), vec![3]);
        finals.advance(held.parent());
        assert_eq!(report(&mut finals), vec![4, 5]);
        finals.advance(held.parent());
        assert_eq!(report(&mut finals), vec![6, 7]);
    }

    #[test]
    fn a_far_tip_keeps_few_references() {
        let mut held = Held::default();
        held.hold(0, 0, 1..=1_000);
        let mut finals = finals(8);
        finals.final_tip(block(0, 1_000, 0));
        finals.advance(held.parent());
        let chain = &finals.chains[0];
        assert_eq!(chain.ready.len(), 8);
        let marks = chain.walk.as_ref().unwrap().marks.len();
        assert!(marks <= 1_000 / 8 + 1, "{marks} marks");
        // Every later window is read off the nearest mark.
        let mut reported = report(&mut finals);
        for _ in 0..1_000 / 8 {
            finals.advance(held.parent());
            reported.extend(report(&mut finals));
        }
        assert_eq!(reported, (1..=1_000).collect::<Vec<_>>());
    }

    #[test]
    fn a_reset_resumes_above_the_floor_with_the_newest_tip() {
        let mut held = Held::default();
        held.hold(0, 0, 1..=6);
        let mut finals = finals(8);
        finals.final_tip(block(0, 6, 0));
        finals.advance(held.parent());
        assert_eq!(heights(&finals), vec![1, 2, 3, 4, 5, 6]);
        finals.reset(&[Height::new(4)]);
        finals.advance(held.parent());
        assert_eq!(heights(&finals), vec![5, 6]);
        finals.reset(&[Height::new(6)]);
        finals.advance(held.parent());
        assert!(heights(&finals).is_empty());
    }
}

//! Final blocks reported to the application before marshal orders them.
//!
//! A leader finality fact names every producer chain's final tip, and every block at or below it
//! is final, but the ordered sweep may defer those blocks to a later view. Delivery reports each
//! final block it has not yet reported or delivered as soon as its body is in local custody,
//! oldest first on its chain, so the application can start work for it early.
//!
//! The state here is volatile. After a restart or a floor installation, each chain resumes from
//! its height at delivery's acknowledgement cursor, so every final block not yet delivered in this
//! run is reported, including committed outputs that a previous run delivered without an
//! acknowledgement. A seeding scan reads the committed output rows after the acknowledgement
//! cursor to find those heights: a chain's first row there is one above its height at the cursor,
//! and a chain without a row there is at the emitted frontier. Committed outputs are final, so
//! each chain's emitted block and every later commit's outputs also count as final tips.
//!
//! # Windows
//!
//! Each chain reports its oldest unreported final blocks in windows of at most `lookahead`
//! blocks. Headers only link to their parents, so a window is found by descending the chain's
//! header ancestry from a known final block down to the chain's cursor and keeping the lowest
//! `lookahead` references. Once the window is reported (or delivered in order), the next descent
//! finds the next window, until the newest final tip is reached.
//!
//! A descent starts from the lowest anchor at least `lookahead` above the cursor, or the newest
//! final tip if none is. Anchors are known final blocks: the newest final tip, and every block a
//! descent reads at a height that is a multiple of `lookahead`. A chain keeps at most
//! `lookahead` anchors; past that it drops the anchor whose gap to its neighbors is smallest
//! relative to its distance from the cursor, so anchors stay dense near the cursor and thin out
//! toward the tip. Memory per chain is therefore at most about three `lookahead` references
//! (anchors, the descent's lowest references, the window), however far the final tip runs ahead,
//! while a window usually costs a descent of about two windows' headers.
//!
//! # Work
//!
//! Work runs as one job at a time: a seed reads a bounded batch of output rows, a walk reads one
//! bounded header segment for each of a bounded set of descending chains (taken in turn), and a
//! load reads the bodies of windowed blocks. Every job is small so the catalog interleaves its
//! own work between them. All read only local custody and never fetch from peers. A chain whose
//! next header or body is missing stalls until custody admits a block on that chain, a commit, or
//! a finality fact.
//!
//! Reports are exact within a run: delivery records each ordered delivery before it applies the
//! next read, and a block at or below its chain's cursor is never reported.

use crate::{
    multimmit::types::{BlockRef, Body, TransactionBlock},
    types::{Height, OutputIndex},
};
use commonware_cryptography::{Digest, Hasher};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

/// Most bodies one load reads.
const LOAD_BLOCKS: usize = 16;

/// Most chains one walk reads a segment for.
const WALK_CHAINS: usize = 8;

/// Most headers one walk reads per chain.
pub(super) const WALK_SEGMENT_HEADERS: usize = 16;

/// Most output rows one seed reads.
pub(super) const SEED_OUTPUTS: usize = 256;

/// The scan for each chain's height at the acknowledgement cursor.
struct Seed<D: Digest> {
    /// Next output row to read.
    next: OutputIndex,
    /// Last committed output row when the scan started.
    end: OutputIndex,
    /// Each chain's emitted block when the scan started.
    emitted: Vec<BlockRef<D>>,
    /// Each chain's first height found after the acknowledgement cursor.
    first: Vec<Option<Height>>,
    /// Each chain's newest ordered delivery since the reset.
    delivered: Vec<Height>,
}

/// A descent through a chain's header ancestry toward its cursor.
struct Descent<D: Digest> {
    /// The next header to read: the parent of the last one read.
    next: BlockRef<D>,
    /// The lowest references read so far, highest first, at most `lookahead`.
    lowest: VecDeque<BlockRef<D>>,
}

/// The reporting state of one producer chain.
struct Chain<D: Digest> {
    /// Height through which the chain's blocks were reported as final or delivered.
    cursor: Height,
    /// Height of the newest final tip known on the chain, never below `cursor`.
    top: Height,
    /// Known final blocks above `cursor` that descents start from, by height.
    anchors: BTreeMap<Height, BlockRef<D>>,
    /// The window: final blocks from `cursor + 1` up, oldest first.
    queue: VecDeque<BlockRef<D>>,
    /// The descent finding the next window.
    descent: Option<Descent<D>>,
    /// Local custody lacked the chain's next header or body.
    stalled: bool,
}

impl<D: Digest> Chain<D> {
    const fn new(cursor: Height) -> Self {
        Self {
            cursor,
            top: cursor,
            anchors: BTreeMap::new(),
            queue: VecDeque::new(),
            descent: None,
            stalled: false,
        }
    }

    /// Records the known final block `anchor`, keeping at most `max` anchors.
    ///
    /// Past `max`, it drops the anchor other than the newest final tip whose merged gap (from the
    /// anchor or cursor below to the anchor above) is smallest relative to its distance above the
    /// cursor.
    fn anchor(&mut self, anchor: BlockRef<D>, max: usize) {
        self.anchors.insert(anchor.height(), anchor);
        while self.anchors.len() > max {
            let cursor = u128::from(self.cursor.get());
            let heights = self
                .anchors
                .keys()
                .map(|height| u128::from(height.get()))
                .collect::<Vec<_>>();
            // The candidate's (merged gap, distance) with the smallest ratio.
            let mut best: Option<(usize, u128, u128)> = None;
            for (index, height) in heights.iter().enumerate() {
                let Some(above) = heights.get(index + 1) else {
                    // The highest anchor is the newest final tip.
                    continue;
                };
                let below = index.checked_sub(1).map_or(cursor, |below| heights[below]);
                let merged = above - below;
                let distance = height - cursor;
                if best.is_none_or(|(_, best_merged, best_distance)| {
                    merged * best_distance < best_merged * distance
                }) {
                    best = Some((index, merged, distance));
                }
            }
            let Some((index, _, _)) = best else {
                break;
            };
            let height = Height::new(heights[index] as u64);
            self.anchors.remove(&height);
        }
    }

    /// Forgets anchors at or below `height`.
    fn drop_anchors_through(&mut self, height: Height) {
        self.anchors = self.anchors.split_off(&height.next());
    }
}

/// One walk request: the chain, the next header to read, and how many headers to read.
pub(super) type WalkRequest<D> = (usize, BlockRef<D>, usize);

/// The headers a walk read down from a request's header, newest first, each as its reference
/// and its parent's.
pub(super) type Segment<D> = Vec<(BlockRef<D>, BlockRef<D>)>;

/// Work for the job that reads local custody.
pub(super) enum Work<D: Digest> {
    /// Read up to `max` output rows from `start`.
    Seed { start: OutputIndex, max: usize },
    /// Read one header segment down from each request's header.
    Walk(Vec<WalkRequest<D>>),
    /// Read the bodies of windowed blocks.
    Load(Vec<BlockRef<D>>),
}

/// Per-chain cursors of final blocks reported ahead of the ordered stream.
pub(super) struct Finals<D: Digest> {
    chains: Vec<Chain<D>>,
    lookahead: usize,
    /// Most chains one walk reads, within the catalog's header-request capacity.
    walk_chains: usize,
    /// The chain the next walk considers first, so every descending chain takes its turn.
    walk_from: usize,
    /// The scan for each chain's height at the acknowledgement cursor; no other work runs until
    /// it ends.
    seed: Option<Seed<D>>,
}

impl<D: Digest> Finals<D> {
    /// Creates state for no chains; [`Self::reset`] supplies them.
    ///
    /// `header_requests` is the most header segments the catalog serves in one read.
    pub(super) fn new(lookahead: usize, header_requests: usize) -> Self {
        Self {
            chains: Vec::new(),
            lookahead,
            walk_chains: header_requests.clamp(1, WALK_CHAINS),
            walk_from: 0,
            seed: None,
        }
    }

    /// Resumes every chain from its height at the acknowledgement cursor `acknowledged`,
    /// forgetting all other state.
    ///
    /// `emitted` is the emitted frontier at the committed output `committed`.
    pub(super) fn reset(
        &mut self,
        emitted: &[BlockRef<D>],
        acknowledged: OutputIndex,
        committed: OutputIndex,
    ) {
        self.chains = emitted
            .iter()
            .map(|reference| Chain::new(reference.height()))
            .collect();
        self.walk_from = 0;
        self.seed = None;
        if acknowledged < committed {
            self.seed = Some(Seed {
                next: acknowledged.next(),
                end: committed,
                emitted: emitted.to_vec(),
                first: vec![None; emitted.len()],
                delivered: vec![Height::zero(); emitted.len()],
            });
        } else {
            let chains = emitted.len();
            self.finish_seed(
                emitted.to_vec(),
                vec![None; chains],
                vec![Height::zero(); chains],
            );
        }
    }

    /// Applies seeded output rows, in output order from the requested start.
    pub(super) fn seeded(&mut self, rows: Vec<(OutputIndex, BlockRef<D>)>) {
        let Some(seed) = self.seed.as_mut() else {
            return;
        };
        if rows.first().is_none_or(|(index, _)| *index != seed.next) {
            // An empty or misplaced answer ends the scan with what it found.
            return self.abandon_seed();
        }
        for (index, reference) in rows {
            if index != seed.next {
                break;
            }
            if let Some(first) = usize::try_from(reference.chain().get())
                .ok()
                .and_then(|chain| seed.first.get_mut(chain))
            {
                first.get_or_insert(reference.height());
            }
            seed.next = index.next();
        }
        if seed.next > seed.end || seed.first.iter().all(Option::is_some) {
            let seed = self.seed.take().expect("the scan is running");
            self.finish_seed(seed.emitted, seed.first, seed.delivered);
        }
    }

    /// Ends the scan with what it found; a chain it has not found stays at its emitted block,
    /// so none of its committed outputs are reported.
    pub(super) fn abandon_seed(&mut self) {
        if let Some(seed) = self.seed.take() {
            let first = seed
                .first
                .iter()
                .zip(&seed.emitted)
                .map(|(first, emitted)| Some(first.unwrap_or(emitted.height().next())))
                .collect();
            self.finish_seed(seed.emitted, first, seed.delivered);
        }
    }

    /// Moves each chain's cursor to its height at the acknowledgement cursor (one below `first`,
    /// or its emitted block when `first` is unknown), or to its newest ordered delivery since
    /// the reset if that is higher, and counts its emitted block as a final tip.
    fn finish_seed(
        &mut self,
        emitted: Vec<BlockRef<D>>,
        first: Vec<Option<Height>>,
        delivered: Vec<Height>,
    ) {
        let lookahead = self.lookahead;
        let chains = self
            .chains
            .iter_mut()
            .zip(emitted)
            .zip(first)
            .zip(delivered);
        for (((chain, emitted), first), delivered) in chains {
            // Until now the cursor stayed at the emitted block unless delivery passed it.
            if chain.cursor <= emitted.height() {
                let acknowledged = first.map_or(emitted.height(), |first| {
                    first.previous().unwrap_or(Height::zero())
                });
                chain.cursor = acknowledged.max(delivered);
            }
            if emitted.height() > chain.cursor {
                chain.top = chain.top.max(emitted.height());
                chain.anchor(emitted, lookahead);
            }
        }
    }

    /// Records the final tips named by a finality fact, one per chain in chain order.
    ///
    /// The fact may bring the custody a stalled chain lacked, so every chain retries.
    pub(super) fn finalized(&mut self, tips: &[BlockRef<D>]) {
        if tips.len() != self.chains.len() {
            return;
        }
        for tip in tips {
            self.final_tip(*tip);
        }
        self.retry();
    }

    /// Records `tip`, a final block such as a committed output.
    pub(super) fn final_tip(&mut self, tip: BlockRef<D>) {
        let lookahead = self.lookahead;
        let Some(chain) = self.chain_mut(tip) else {
            return;
        };
        if tip.height() > chain.top {
            chain.top = tip.height();
            chain.anchor(tip, lookahead);
        }
    }

    /// Lets every stalled chain retry, after new custody may have arrived.
    pub(super) fn retry(&mut self) {
        for chain in &mut self.chains {
            chain.stalled = false;
        }
    }

    /// Lets `chain` retry, after custody admitted a block on it.
    pub(super) fn wake(&mut self, chain: usize) {
        if let Some(chain) = self.chains.get_mut(chain) {
            chain.stalled = false;
        }
    }

    /// Stalls every chain and ends any scan, after a read failed.
    pub(super) fn stall(&mut self) {
        self.abandon_seed();
        for chain in &mut self.chains {
            chain.stalled = true;
        }
    }

    /// Records the ordered delivery of `reference`.
    pub(super) fn delivered(&mut self, reference: BlockRef<D>) {
        let height = reference.height();
        if let Some(seed) = self.seed.as_mut()
            && let Some(delivered) = usize::try_from(reference.chain().get())
                .ok()
                .and_then(|chain| seed.delivered.get_mut(chain))
        {
            *delivered = (*delivered).max(height);
        }
        let Some(chain) = self.chain_mut(reference) else {
            return;
        };
        if height <= chain.cursor {
            return;
        }
        chain.cursor = height;
        chain.top = chain.top.max(height);
        while chain
            .queue
            .front()
            .is_some_and(|queued| queued.height() <= height)
        {
            chain.queue.pop_front();
        }
        chain.drop_anchors_through(height);
        // A descent already below the cursor would not end at it; the next one starts over.
        if chain
            .descent
            .as_ref()
            .is_some_and(|descent| descent.next.height() <= height)
        {
            chain.descent = None;
        }
    }

    /// Returns the next work: the seeding scan first, then loads of windowed blocks, then
    /// descents toward the cursors.
    pub(super) fn next(&mut self) -> Option<Work<D>> {
        if let Some(seed) = &self.seed {
            let remaining = seed
                .end
                .get()
                .saturating_sub(seed.next.get())
                .saturating_add(1);
            let max = usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(SEED_OUTPUTS);
            return Some(Work::Seed {
                start: seed.next,
                max,
            });
        }
        let mut loads = Vec::new();
        // Round-robin across chains, oldest first within each.
        let mut depth = 0;
        while loads.len() < LOAD_BLOCKS {
            let before = loads.len();
            for chain in self.chains.iter().filter(|chain| !chain.stalled) {
                if let Some(reference) = chain.queue.get(depth) {
                    loads.push(*reference);
                    if loads.len() == LOAD_BLOCKS {
                        break;
                    }
                }
            }
            if loads.len() == before {
                break;
            }
            depth += 1;
        }
        if !loads.is_empty() {
            return Some(Work::Load(loads));
        }
        let mut walks = Vec::new();
        let chains = self.chains.len();
        for offset in 0..chains {
            if walks.len() == self.walk_chains {
                break;
            }
            let index = (self.walk_from + offset) % chains;
            let chain = &mut self.chains[index];
            if chain.stalled || !chain.queue.is_empty() || chain.top <= chain.cursor {
                continue;
            }
            if chain.descent.is_none() {
                // The lowest anchor that fills a window, or the tip when none does.
                let fill = Height::new(chain.cursor.get().saturating_add(self.lookahead as u64));
                let Some(start) = chain
                    .anchors
                    .range(fill..)
                    .next()
                    .or_else(|| chain.anchors.last_key_value())
                    .map(|(_, start)| *start)
                else {
                    continue;
                };
                chain.descent = Some(Descent {
                    next: start,
                    lowest: VecDeque::new(),
                });
            }
            let next = chain.descent.as_ref().expect("descent was started").next;
            let remaining = next.height().get().saturating_sub(chain.cursor.get());
            let items = usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(self.lookahead)
                .min(WALK_SEGMENT_HEADERS);
            walks.push((index, next, items));
        }
        if let Some((last, _, _)) = walks.last() {
            self.walk_from = (last + 1) % chains;
        }
        (!walks.is_empty()).then_some(Work::Walk(walks))
    }

    /// Applies a walk: `segments` holds one segment per request.
    ///
    /// A segment may end early within the catalog's byte budget; only a segment that reads
    /// nothing means custody lacks the next header.
    pub(super) fn walked(&mut self, requests: Vec<WalkRequest<D>>, segments: Vec<Segment<D>>) {
        let lookahead = self.lookahead;
        for ((index, next, _), segment) in requests.into_iter().zip(segments) {
            let Some(chain) = self.chains.get_mut(index) else {
                continue;
            };
            // Delivery or a reset may have superseded the descent.
            let Some(mut descent) = chain.descent.take() else {
                continue;
            };
            if descent.next != next {
                chain.descent = Some(descent);
                continue;
            }
            let mut read = 0;
            for (reference, parent) in segment {
                if reference != descent.next || reference.height() <= chain.cursor {
                    break;
                }
                descent.lowest.push_back(reference);
                if descent.lowest.len() > lookahead {
                    descent.lowest.pop_front();
                }
                if reference.height().get() % lookahead as u64 == 0 {
                    chain.anchor(reference, lookahead);
                }
                descent.next = parent;
                read += 1;
            }
            if descent.next.height() <= chain.cursor {
                let cursor = chain.cursor;
                chain.queue = descent
                    .lowest
                    .into_iter()
                    .rev()
                    .filter(|reference| reference.height() > cursor)
                    .collect();
                if let Some(last) = chain.queue.back() {
                    let last = last.height();
                    chain.drop_anchors_through(last);
                }
                continue;
            }
            if read == 0 {
                chain.stalled = true;
            }
            chain.descent = Some(descent);
        }
    }

    /// Applies a load of `references`, returning the blocks to report in per-chain order.
    ///
    /// Only a chain's next queued block is reported, and ordered delivery drops queued blocks it
    /// passes, so a block delivered in order before the load finished is not. A chain stops at its first block without a body and
    /// stalls.
    pub(super) fn loaded<H, B>(
        &mut self,
        references: Vec<BlockRef<D>>,
        bodies: Vec<Option<Arc<TransactionBlock<H, B>>>>,
    ) -> Vec<Arc<TransactionBlock<H, B>>>
    where
        H: Hasher<Digest = D>,
        B: Body<H>,
    {
        let mut report = Vec::new();
        for (reference, body) in references.into_iter().zip(bodies) {
            let Some(chain) = self.chain_mut(reference) else {
                continue;
            };
            if chain.stalled || chain.queue.front() != Some(&reference) {
                continue;
            }
            match body.filter(|block| block.reference() == reference) {
                Some(block) => {
                    chain.queue.pop_front();
                    chain.cursor = reference.height();
                    report.push(block);
                }
                None => chain.stalled = true,
            }
        }
        report
    }

    fn chain_mut(&mut self, reference: BlockRef<D>) -> Option<&mut Chain<D>> {
        let index = usize::try_from(reference.chain().get()).ok()?;
        self.chains.get_mut(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            testing::TestBody,
            types::{ChainId, TransactionBlockHeader},
        },
        types::Epoch,
    };
    use commonware_cryptography::{Digestible as _, Sha256, sha256::Digest as Sha256Digest};

    type Ref = BlockRef<Sha256Digest>;

    fn reference(chain: u32, height: u64) -> Ref {
        BlockRef::new(
            ChainId::new(chain),
            Height::new(height),
            Sha256::hash(&[&chain.to_be_bytes()[..], &height.to_be_bytes()[..]]),
        )
    }

    /// Answers a walk from a chain of linked references, as the catalog would with every header.
    fn answer(requests: &[WalkRequest<Sha256Digest>]) -> Vec<Vec<(Ref, Ref)>> {
        requests
            .iter()
            .map(|(_, next, items)| {
                let chain = next.chain().get();
                let top = next.height().get();
                (0..*items as u64)
                    .take_while(|offset| *offset < top)
                    .map(|offset| {
                        let height = top - offset;
                        (reference(chain, height), reference(chain, height - 1))
                    })
                    .collect()
            })
            .collect()
    }

    /// Runs walks until a load is ready, returning the load and how many headers were read.
    fn walk_to_load(finals: &mut Finals<Sha256Digest>) -> (Vec<Ref>, usize) {
        let mut headers = 0;
        loop {
            match finals.next() {
                Some(Work::Walk(requests)) => {
                    let segments = answer(&requests);
                    headers += segments.iter().map(Vec::len).sum::<usize>();
                    finals.walked(requests, segments);
                }
                Some(Work::Load(references)) => return (references, headers),
                Some(Work::Seed { .. }) => panic!("unexpected seed"),
                None => panic!("no work"),
            }
        }
    }

    /// Reports a load with every body present, as the actor would, without real blocks.
    fn report(finals: &mut Finals<Sha256Digest>, references: &[Ref]) {
        for reference in references {
            let chain = finals.chain_mut(*reference).unwrap();
            assert_eq!(chain.queue.pop_front(), Some(*reference));
            chain.cursor = reference.height();
        }
    }

    fn heights(references: &[Ref]) -> Vec<u64> {
        references
            .iter()
            .map(|reference| reference.height().get())
            .collect()
    }

    #[test]
    fn a_large_jump_reports_the_oldest_window_first_and_slides_to_the_tip() {
        let mut finals = Finals::new(4, 64);
        finals.reset(&[reference(0, 2)], OutputIndex::zero(), OutputIndex::zero());
        finals.finalized(&[reference(0, 2)]);
        assert!(finals.next().is_none());

        finals.finalized(&[reference(0, 40)]);
        let mut reported = Vec::new();
        let mut headers = 0;
        while finals.chains[0].cursor < Height::new(40) {
            let (load, read) = walk_to_load(&mut finals);
            headers += read;
            assert!(load.len() <= 4);
            report(&mut finals, &load);
            reported.extend(heights(&load));
        }
        assert_eq!(reported, (3..=40).collect::<Vec<_>>());
        assert!(finals.next().is_none());
        // The first descent reads the whole gap; later ones start from nearby anchors.
        assert!(headers < 38 * 4, "{headers}");
        assert!(finals.chains[0].anchors.len() <= 4);
    }

    #[test]
    fn anchors_stay_bounded_and_descents_stay_short_across_a_long_catch_up() {
        let mut finals = Finals::new(8, 64);
        finals.reset(&[reference(0, 0)], OutputIndex::zero(), OutputIndex::zero());
        finals.finalized(&[reference(0, 10_000)]);
        let mut headers = 0;
        let mut reported = 0;
        while finals.chains[0].cursor < Height::new(10_000) {
            let (load, read) = walk_to_load(&mut finals);
            headers += read;
            assert!(finals.chains[0].anchors.len() <= 8);
            assert!(finals.chains[0].queue.len() <= 8);
            reported += load.len();
            report(&mut finals, &load);
        }
        assert_eq!(reported, 10_000);
        assert!(headers <= 8 * 10_000, "{headers}");
    }

    #[test]
    fn delivery_slides_the_window_and_a_reset_forgets_it() {
        let mut finals = Finals::new(3, 64);
        finals.reset(
            &[reference(0, 0), reference(1, 0)],
            OutputIndex::zero(),
            OutputIndex::zero(),
        );
        finals.finalized(&[reference(0, 10), reference(1, 2)]);
        // Chain 1's short gap fits one segment; chain 0 still descends.
        let (load, _) = walk_to_load(&mut finals);
        assert_eq!(load, vec![reference(1, 1), reference(1, 2)]);
        report(&mut finals, &load);
        let (load, _) = walk_to_load(&mut finals);
        assert_eq!(heights(&load), vec![1, 2, 3]);

        // Ordered delivery past chain 0's window starts the next window above it.
        finals.delivered(reference(0, 5));
        let (load, _) = walk_to_load(&mut finals);
        assert_eq!(heights(&load), vec![6, 7, 8]);

        // A floor at chain 0's tip leaves nothing to report.
        finals.reset(
            &[reference(0, 10), reference(1, 2)],
            OutputIndex::zero(),
            OutputIndex::zero(),
        );
        finals.finalized(&[reference(0, 10), reference(1, 2)]);
        assert!(finals.next().is_none());
    }

    #[test]
    fn a_missing_header_stalls_the_descent_until_its_chain_wakes() {
        let mut finals = Finals::new(8, 64);
        finals.reset(
            &[reference(0, 0), reference(1, 0)],
            OutputIndex::zero(),
            OutputIndex::zero(),
        );
        finals.finalized(&[reference(0, 4), reference(1, 0)]);
        let Some(Work::Walk(requests)) = finals.next() else {
            panic!("expected a walk");
        };
        // A segment that ends early resumes where it ended.
        let mut segments = answer(&requests);
        segments[0].truncate(2);
        finals.walked(requests, segments);
        let Some(Work::Walk(requests)) = finals.next() else {
            panic!("expected a walk");
        };
        assert_eq!(requests, vec![(0, reference(0, 2), 2)]);
        // Local custody lacks the header at height 2.
        finals.walked(requests, vec![Vec::new()]);
        assert!(finals.next().is_none());

        // Custody admitting a block on another chain leaves the chain stalled.
        finals.wake(1);
        assert!(finals.next().is_none());
        finals.wake(0);
        let Some(Work::Walk(requests)) = finals.next() else {
            panic!("expected a walk");
        };
        assert_eq!(requests, vec![(0, reference(0, 2), 2)]);
        finals.walked(requests.clone(), answer(&requests));
        let Some(Work::Load(load)) = finals.next() else {
            panic!("expected a load");
        };
        assert_eq!(heights(&load), vec![1, 2, 3, 4]);
    }

    #[test]
    fn walks_stay_within_the_header_request_capacity_and_take_turns() {
        let mut finals = Finals::new(64, 2);
        let chains = 5u32;
        let frontier = (0..chains)
            .map(|chain| reference(chain, 0))
            .collect::<Vec<_>>();
        finals.reset(&frontier, OutputIndex::zero(), OutputIndex::zero());
        let tips = (0..chains)
            .map(|chain| reference(chain, 100))
            .collect::<Vec<_>>();
        finals.finalized(&tips);
        let mut served = vec![0; chains as usize];
        for _ in 0..10 {
            let Some(Work::Walk(requests)) = finals.next() else {
                panic!("expected a walk");
            };
            assert!(requests.len() <= 2);
            for (index, _, items) in &requests {
                assert!(*items <= WALK_SEGMENT_HEADERS);
                served[*index] += 1;
            }
            finals.walked(requests.clone(), answer(&requests));
        }
        assert_eq!(served, vec![4; chains as usize]);
    }

    #[test]
    fn seeding_resumes_each_chain_at_the_acknowledgement_cursor() {
        // Rows 1 through 4 hold heights 1 and 2 of both chains; rows 5 through 8 hold chain 0's
        // heights 3 to 5 and chain 1's height 3. Delivery acknowledged row 4.
        let rows = vec![
            (OutputIndex::new(5), reference(0, 3)),
            (OutputIndex::new(6), reference(0, 4)),
            (OutputIndex::new(7), reference(0, 5)),
            (OutputIndex::new(8), reference(1, 3)),
        ];
        let emitted = [reference(0, 5), reference(1, 3)];
        let mut finals = Finals::new(8, 64);
        finals.reset(&emitted, OutputIndex::new(4), OutputIndex::new(8));
        let Some(Work::Seed { start, max }) = finals.next() else {
            panic!("expected a seed");
        };
        assert_eq!((start, max), (OutputIndex::new(5), 4));
        // Ordered delivery redelivers row 5 while the scan runs.
        finals.delivered(reference(0, 3));
        finals.seeded(rows);
        let (load, _) = walk_to_load(&mut finals);
        assert_eq!(
            load,
            vec![reference(0, 4), reference(1, 3), reference(0, 5)]
        );

        // A scan that reads nothing leaves the chains at the emitted frontier.
        finals.reset(&emitted, OutputIndex::new(4), OutputIndex::new(8));
        finals.seeded(Vec::new());
        assert!(finals.next().is_none());
    }

    #[test]
    fn a_load_never_reports_a_block_delivered_while_it_ran() {
        // Three linked blocks on chain 0.
        let mut parent = Sha256::hash(&[b"genesis"]);
        let blocks = (1..=3u64)
            .map(|height| {
                let body = TestBody::new(parent, Height::new(height), height);
                let header = TransactionBlockHeader::new(
                    Epoch::new(1),
                    ChainId::new(0),
                    Height::new(height),
                    parent,
                    body.digest(),
                )
                .unwrap();
                let block =
                    Arc::new(TransactionBlock::<Sha256, TestBody>::new(header, body).unwrap());
                parent = block.reference().digest();
                block
            })
            .collect::<Vec<_>>();
        let references = blocks
            .iter()
            .map(|block| block.reference())
            .collect::<Vec<_>>();
        let mut finals = Finals::new(8, 64);
        finals.reset(&[reference(0, 0)], OutputIndex::zero(), OutputIndex::zero());
        finals.finalized(&[references[2]]);
        let Some(Work::Walk(requests)) = finals.next() else {
            panic!("expected a walk");
        };
        let segment = references
            .iter()
            .rev()
            .zip(blocks.iter().rev())
            .map(|(reference, block)| (*reference, block.header().parent_ref()))
            .collect();
        finals.walked(requests, vec![segment]);
        let Some(Work::Load(load)) = finals.next() else {
            panic!("expected a load");
        };
        assert_eq!(load, references);

        // Ordered delivery of the second block lands before the load's bodies.
        finals.delivered(references[1]);
        let reported = finals.loaded(load, blocks.iter().cloned().map(Some).collect());
        assert_eq!(
            reported
                .iter()
                .map(|block| block.reference())
                .collect::<Vec<_>>(),
            vec![references[2]]
        );
    }

    #[test]
    fn a_descent_overtaken_by_delivery_restarts_above_the_cursor() {
        let mut finals = Finals::new(2, 64);
        finals.reset(&[reference(0, 0)], OutputIndex::zero(), OutputIndex::zero());
        finals.finalized(&[reference(0, 6)]);
        let Some(Work::Walk(requests)) = finals.next() else {
            panic!("expected a walk");
        };
        // Reads heights 6 and 5, then delivery passes the descent.
        finals.walked(requests.clone(), answer(&requests));
        finals.delivered(reference(0, 5));
        let (load, _) = walk_to_load(&mut finals);
        assert_eq!(heights(&load), vec![6]);
    }
}

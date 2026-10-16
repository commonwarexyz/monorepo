//! A naive model of extraction and ordering over explicitly materialized block trees.
//!
//! Every function enumerates the blocks of a window and counts endorsers by membership in explicit
//! ancestor sets, following the definitions of the specification's extraction section literally.
//! It is the oracle the optimized algebra is tested against; it is quadratic and makes no attempt
//! to bound its work.

use super::Ancestry;
use crate::{
    multimmit::types::{BlockRef, TransactionBlockHeader},
    types::{Epoch, Height, Participant},
};
use commonware_cryptography::{Digest, Hasher};
use std::collections::{BTreeMap, BTreeSet};

/// Producer blocks of one epoch, each linked to its parent; objects without a parent are roots.
#[derive(Clone, Debug)]
pub(crate) struct Tree<D: Digest> {
    epoch: Epoch,
    blocks: BTreeMap<BlockRef<D>, TransactionBlockHeader<D>>,
}

impl<D: Digest> Tree<D> {
    /// Creates an empty tree of `epoch`.
    pub(crate) const fn new(epoch: Epoch) -> Self {
        Self {
            epoch,
            blocks: BTreeMap::new(),
        }
    }

    /// Adds the child of `parent` committing to `payload` and returns it.
    pub(crate) fn extend<H: Hasher<Digest = D>>(
        &mut self,
        parent: &BlockRef<D>,
        payload: D,
    ) -> BlockRef<D> {
        let header = TransactionBlockHeader::new(
            self.epoch,
            parent.chain(),
            parent.height().next(),
            parent.digest(),
            payload,
        )
        .expect("children are above genesis");
        let block = header.block_ref::<H>();
        self.blocks.insert(block, header);
        block
    }

    /// Returns every non-root block.
    pub(crate) fn blocks(&self) -> impl Iterator<Item = BlockRef<D>> + '_ {
        self.blocks.keys().copied()
    }

    /// Returns `tip` and all its known ancestors, highest first.
    pub(crate) fn lineage(&self, tip: &BlockRef<D>) -> Vec<BlockRef<D>> {
        let mut lineage = vec![*tip];
        let mut current = *tip;
        while let Some(header) = self.blocks.get(&current) {
            current = header.parent_ref();
            lineage.push(current);
        }
        lineage
    }

    /// Returns whether `block` is `tip` or one of its ancestors.
    pub(crate) fn endorses(&self, tip: &BlockRef<D>, block: &BlockRef<D>) -> bool {
        self.lineage(tip).contains(block)
    }

    /// Returns the payload hashes of the blocks above `from` up to `tip`, lowest first, or `None`
    /// when `from` is not an ancestor of `tip`.
    pub(crate) fn payloads(&self, from: &BlockRef<D>, tip: &BlockRef<D>) -> Option<Vec<D>> {
        let mut payloads = Vec::new();
        for block in self.lineage(tip) {
            if block == *from {
                payloads.reverse();
                return Some(payloads);
            }
            payloads.push(self.blocks.get(&block)?.body_digest());
        }
        None
    }

    /// Returns the known blocks of the window of cap `cap` above `base` that extend it.
    pub(crate) fn window(&self, base: &BlockRef<D>, cap: u32) -> Vec<BlockRef<D>> {
        let end = base.height().get() + u64::from(cap);
        self.blocks()
            .filter(|block| {
                block.chain() == base.chain()
                    && block.height() > base.height()
                    && block.height().get() <= end
                    && self.endorses(block, base)
            })
            .collect()
    }
}

impl<D: Digest> Ancestry<D> for Tree<D> {
    fn ancestor(&self, tip: &BlockRef<D>, height: Height) -> Option<BlockRef<D>> {
        self.lineage(tip)
            .into_iter()
            .find(|block| block.height() == height)
    }
}

/// Returns the number of distinct signers with some tip in `votes` endorsing `block`.
fn endorsers<D: Digest>(
    tree: &Tree<D>,
    votes: &[(Participant, BlockRef<D>)],
    block: &BlockRef<D>,
) -> usize {
    votes
        .iter()
        .filter(|(_, tip)| tree.endorses(tip, block))
        .map(|(signer, _)| *signer)
        .collect::<BTreeSet<_>>()
        .len()
}

/// Returns the highest window block extending `base` that at least `quorum` distinct signers of
/// `votes` endorse, or `base`: `Tips(Q)_i` with quorum `n - 3f` and `b*_i` with `n - f`.
pub(crate) fn tip<D: Digest>(
    tree: &Tree<D>,
    base: &BlockRef<D>,
    cap: u32,
    quorum: usize,
    votes: &[(Participant, BlockRef<D>)],
) -> BlockRef<D> {
    let qualified: Vec<_> = tree
        .window(base, cap)
        .into_iter()
        .filter(|block| endorsers(tree, votes, block) >= quorum)
        .collect();
    let Some(height) = qualified.iter().map(BlockRef::height).max() else {
        return *base;
    };
    let highest: Vec<_> = qualified
        .into_iter()
        .filter(|block| block.height() == height)
        .collect();
    assert_eq!(highest.len(), 1, "two qualifying blocks share a height");
    highest[0]
}

/// Returns whether some window block above `base` strictly extending `floor` is endorsed by
/// `tip`.
fn beyond<D: Digest>(
    tree: &Tree<D>,
    base: &BlockRef<D>,
    cap: u32,
    floor: &BlockRef<D>,
    tip: &BlockRef<D>,
) -> bool {
    tree.window(base, cap).iter().any(|block| {
        block.height() > floor.height() && tree.endorses(block, floor) && tree.endorses(tip, block)
    })
}

/// Returns whether `base`'s chain is settled: `gamma + (n - phi) <= bound`, where `phi` counts
/// the signers of `first_binding` and `gamma` those whose first entry endorses a window block
/// strictly extending `final_tip`.
pub(crate) fn settled<D: Digest>(
    tree: &Tree<D>,
    base: &BlockRef<D>,
    final_tip: &BlockRef<D>,
    cap: u32,
    participants: usize,
    bound: usize,
    first_binding: &[(Participant, BlockRef<D>)],
) -> bool {
    let mut first = BTreeMap::new();
    for (signer, tip) in first_binding {
        first.entry(*signer).or_insert(*tip);
    }
    let gamma = first
        .values()
        .filter(|tip| beyond(tree, base, cap, final_tip, tip))
        .count();
    gamma + (participants - first.len()) <= bound
}

/// Returns `Det(G)_i`: the unique `t`, `base` or a window block extending it with at least
/// `quorum` endorsers among `votes`, such that no vote endorses a window block strictly extending
/// `t`.
pub(crate) fn determined<D: Digest>(
    tree: &Tree<D>,
    base: &BlockRef<D>,
    cap: u32,
    quorum: usize,
    votes: &[(Participant, BlockRef<D>)],
) -> Option<BlockRef<D>> {
    let candidates = std::iter::once(*base).chain(
        tree.window(base, cap)
            .into_iter()
            .filter(|block| endorsers(tree, votes, block) >= quorum),
    );
    let determined: Vec<_> = candidates
        .filter(|target| {
            !votes
                .iter()
                .any(|(_, tip)| beyond(tree, base, cap, target, tip))
        })
        .collect();
    assert!(determined.len() <= 1, "a chain is determined at two blocks");
    determined.first().copied()
}

/// Returns `Horiz(from, to)`: every block above `from_i` on `to_i`'s lineage, sorted by offset
/// above `from_i` and then by chain.
pub(crate) fn horiz<D: Digest>(
    tree: &Tree<D>,
    from: &[BlockRef<D>],
    to: &[BlockRef<D>],
) -> Vec<BlockRef<D>> {
    let mut placed: Vec<(u64, usize, BlockRef<D>)> = Vec::new();
    for (chain, (from, to)) in from.iter().zip(to).enumerate() {
        for block in tree.lineage(to) {
            if block.height() > from.height() {
                placed.push((block.height().get() - from.height().get(), chain, block));
            }
        }
    }
    placed.sort();
    placed.into_iter().map(|(_, _, block)| block).collect()
}

/// Returns the blocks the sweep over `base`, `finals`, and `settled` places, and whether it
/// halts.
pub(crate) fn sweep<D: Digest>(
    tree: &Tree<D>,
    base: &[BlockRef<D>],
    finals: &[BlockRef<D>],
    settled: &[bool],
) -> (Vec<BlockRef<D>>, bool) {
    let last = base
        .iter()
        .zip(finals)
        .map(|(base, last)| last.height().get() - base.height().get())
        .max()
        .unwrap_or(0);
    let mut positions = Vec::new();
    for offset in 1..=last {
        for chain in 0..base.len() {
            positions.push((offset, chain));
        }
    }
    let mut placed = Vec::new();
    for (offset, chain) in positions {
        let height = Height::new(base[chain].height().get() + offset);
        if height <= finals[chain].height() {
            placed.push(
                tree.ancestor(&finals[chain], height)
                    .expect("final tips are known"),
            );
        } else if !settled[chain] {
            return (placed, true);
        }
    }
    (placed, false)
}

/// Returns `Ord` of the V-QC chain whose tips, from the genesis V-QC on, are `tips`.
pub(crate) fn ord<D: Digest>(tree: &Tree<D>, tips: &[Vec<BlockRef<D>>]) -> Vec<BlockRef<D>> {
    tips.windows(2)
        .flat_map(|pair| horiz(tree, &pair[0], &pair[1]))
        .collect()
}

//! In-memory tree of candidate blocks above the last finalized block.
//!
//! The tree holds every fork marshal has observed above the finalized tip. It
//! is pruned each time marshal learns of a new finalization and rebuilt from
//! the prunable caches on startup. Together with the finalized block archive,
//! it makes the full locally known ancestry of any candidate tip addressable
//! by height (see [`crate::marshal::ancestry::DescendantStream`]).

use crate::{Block, types::Height};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// A contiguous chain of candidate blocks ending at a requested tip.
pub(crate) struct Branch<B: Block> {
    /// Blocks in ascending height order. The last block is the tip.
    pub blocks: Vec<Arc<B>>,
    /// The height of the finalized root, when the first block extends it,
    /// making the branch part of the locally known ancestry below the root.
    pub root: Option<Height>,
}

/// An in-memory tree of all candidate forks above the last finalized block.
///
/// The tree is anchored at a root, the highest block known to be finalized.
/// Every stored block sits strictly above the root. Blocks whose parents are
/// not locally known ("dangling") are retained: they may still connect once
/// the intermediate blocks arrive, and they are pruned once a finalization
/// proves them conflicting or passes their height.
///
/// Candidate blocks are adversarial input: a block can lie about its height
/// or its parent while keeping a valid digest. The tree therefore enforces
/// the chain invariant (a block's parent is exactly one height below it) on
/// every edge it exposes: [Self::insert] rejects blocks that provably violate
/// it against tracked state, [Self::finalize] removes blocks that claim the
/// finalized block as parent from the wrong height, and [Self::branch] stops
/// walking at any remaining unverifiable edge.
pub(crate) struct ForkTree<B: Block> {
    /// The height and digest of the highest known finalized block.
    root: Option<(Height, B::Digest)>,
    /// Candidate blocks by digest.
    nodes: BTreeMap<B::Digest, Arc<B>>,
    /// Candidate blocks at each height.
    by_height: BTreeMap<Height, Vec<Arc<B>>>,
}

impl<B: Block> ForkTree<B> {
    /// Creates an empty tree with no root.
    ///
    /// Until [`Self::finalize`] installs a root, all inserted blocks are
    /// accepted as candidates.
    pub(crate) const fn new() -> Self {
        Self {
            root: None,
            nodes: BTreeMap::new(),
            by_height: BTreeMap::new(),
        }
    }

    /// Returns the number of candidate blocks tracked.
    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Inserts a candidate block.
    ///
    /// Returns `false` if the block is already tracked, sits at or below the
    /// root, provably conflicts with the finalized chain (a child of the root
    /// height that does not extend the root), or provably violates the chain
    /// invariant (its claimed parent is tracked at a height other than one
    /// below its own).
    pub(crate) fn insert(&mut self, block: &Arc<B>) -> bool {
        // Deduplicate first: re-ingestion of an already tracked block is the
        // common case.
        let digest = block.digest();
        if self.nodes.contains_key(&digest) {
            return false;
        }

        let height = block.height();
        let parent = block.parent();
        if let Some((root_height, root_digest)) = &self.root {
            if height <= *root_height {
                return false;
            }
            // A candidate directly above the root must extend it, and a
            // candidate claiming the root as its parent must sit directly
            // above it. Either mismatch is a provable lie.
            if (height == root_height.next()) != (parent == *root_digest) {
                return false;
            }
        }

        // A candidate whose tracked parent is not exactly one height below
        // lies about its height or its parent.
        if let Some(tracked) = self.nodes.get(&parent)
            && tracked.height().next() != height
        {
            return false;
        }

        self.nodes.insert(digest, Arc::clone(block));
        self.by_height
            .entry(height)
            .or_default()
            .push(Arc::clone(block));
        true
    }

    /// Records a newly finalized block, pruning every candidate it supersedes.
    ///
    /// Candidates at or below `height` are dropped, as are candidates that
    /// provably conflict with the finalized block: children of `height` that
    /// do not extend `digest`, and their known descendants. Dangling
    /// candidates above `height` are kept until a later finalization decides
    /// them. Finalizations at or below the current root are ignored.
    pub(crate) fn finalize(&mut self, height: Height, digest: B::Digest) {
        if let Some((root_height, _)) = &self.root
            && height <= *root_height
        {
            return;
        }
        self.root = Some((height, digest));

        // Drop candidates at or below the new root.
        let above = self.by_height.split_off(&height.next());
        for blocks in self.by_height.values() {
            for stale in blocks {
                self.nodes.remove(&stale.digest());
            }
        }
        self.by_height = above;

        // Sweep ascending: a child of the root height conflicts unless it
        // extends the finalized digest, a candidate claiming the finalized
        // block as parent from any other height lies about its ancestry, and
        // above the boundary a candidate conflicts when its parent was
        // removed by this sweep. The chain invariant (parent height is
        // exactly one below) makes a single pass complete. Candidates whose
        // parents were never tracked cannot be classified and survive.
        let nodes = &mut self.nodes;
        let boundary = height.next();
        let mut conflicting = BTreeSet::new();
        for (&level, blocks) in self.by_height.iter_mut() {
            blocks.retain(|candidate| {
                let parent = candidate.parent();
                let conflicts = if parent == digest {
                    level != boundary
                } else if level == boundary {
                    true
                } else {
                    conflicting.contains(&parent)
                };
                if conflicts {
                    conflicting.insert(candidate.digest());
                    nodes.remove(&candidate.digest());
                }
                !conflicts
            });
        }
        self.by_height.retain(|_, blocks| !blocks.is_empty());
    }

    /// Returns the chain of candidate blocks ending at `tip`, walking parent
    /// links as far down as locally known.
    ///
    /// Returns `None` if `tip` is not tracked. The branch carries the root
    /// height when its first block extends the finalized root. The walk stops
    /// at any edge that is not contiguous in height (a block inserted before
    /// its claimed parent can lie about the relationship), reporting the
    /// branch as disconnected.
    pub(crate) fn branch(&self, tip: &B::Digest) -> Option<Branch<B>> {
        let mut blocks: Vec<Arc<B>> = Vec::new();
        let mut cursor = *tip;
        let root = loop {
            let Some(block) = self.nodes.get(&cursor) else {
                if blocks.is_empty() {
                    return None;
                }
                break None;
            };
            if let Some(lowest) = blocks.last()
                && block.height().next() != lowest.height()
            {
                break None;
            }
            cursor = block.parent();
            blocks.push(Arc::clone(block));
            if let Some((root_height, root_digest)) = &self.root
                && cursor == *root_digest
            {
                break Some(*root_height);
            }
        };
        blocks.reverse();
        Some(Branch { blocks, root })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Heightable as _, marshal::mocks::block::Block};
    use commonware_cryptography::{
        Digest as _, Digestible as _, Sha256, sha256::Digest as Sha256Digest,
    };

    type TestBlock = Block<Sha256Digest, ()>;

    fn block(parent: Sha256Digest, height: u64, seed: u64) -> Arc<TestBlock> {
        Arc::new(TestBlock::new::<Sha256>(
            (),
            parent,
            Height::new(height),
            seed,
        ))
    }

    /// Builds a chain of `len` blocks starting at `height` on `parent`,
    /// seeding digests with `seed` to keep forks distinct.
    fn chain(parent: Sha256Digest, height: u64, len: u64, seed: u64) -> Vec<Arc<TestBlock>> {
        let mut blocks = Vec::new();
        let mut parent = parent;
        for offset in 0..len {
            let next = block(parent, height + offset, seed + offset);
            parent = next.digest();
            blocks.push(next);
        }
        blocks
    }

    #[test]
    fn insert_rejects_duplicates_and_stale_heights() {
        let mut tree = ForkTree::<TestBlock>::new();
        let root = block(Sha256Digest::EMPTY, 5, 0);
        tree.finalize(root.height(), root.digest());

        // At or below the root.
        assert!(!tree.insert(&root));
        assert!(!tree.insert(&block(Sha256Digest::EMPTY, 4, 1)));

        // A valid child inserts once.
        let child = block(root.digest(), 6, 2);
        assert!(tree.insert(&child));
        assert!(!tree.insert(&child));
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn insert_rejects_conflicting_root_child() {
        let mut tree = ForkTree::<TestBlock>::new();
        let root = block(Sha256Digest::EMPTY, 5, 0);
        tree.finalize(root.height(), root.digest());

        // A child height block not extending the root conflicts.
        assert!(!tree.insert(&block(Sha256Digest::EMPTY, 6, 1)));

        // A dangling block above the child height is retained.
        assert!(tree.insert(&block(Sha256Digest::EMPTY, 7, 2)));
    }

    #[test]
    fn insert_accepts_everything_without_root() {
        let mut tree = ForkTree::<TestBlock>::new();
        assert!(tree.insert(&block(Sha256Digest::EMPTY, 0, 0)));
        assert!(tree.insert(&block(Sha256Digest::EMPTY, 100, 1)));
        assert_eq!(tree.len(), 2);
    }

    #[test]
    fn finalize_prunes_conflicting_forks_and_keeps_extension() {
        let mut tree = ForkTree::<TestBlock>::new();
        let root = block(Sha256Digest::EMPTY, 0, 0);
        tree.finalize(root.height(), root.digest());

        // Two forks off the root, both three blocks long.
        let canonical = chain(root.digest(), 1, 3, 10);
        let fork = chain(root.digest(), 1, 3, 20);
        for block in canonical.iter().chain(fork.iter()) {
            assert!(tree.insert(block));
        }
        assert_eq!(tree.len(), 6);

        // Finalizing the first canonical block removes the fork entirely.
        tree.finalize(canonical[0].height(), canonical[0].digest());
        assert_eq!(tree.len(), 2);
        for block in &canonical[1..] {
            assert!(tree.branch(&block.digest()).is_some());
        }
        for block in &fork {
            assert!(tree.branch(&block.digest()).is_none());
        }
    }

    #[test]
    fn finalize_keeps_dangling_candidates() {
        let mut tree = ForkTree::<TestBlock>::new();
        let root = block(Sha256Digest::EMPTY, 0, 0);
        tree.finalize(root.height(), root.digest());

        // A candidate whose parent is unknown locally.
        let dangling = block(Sha256Digest::EMPTY, 5, 1);
        assert!(tree.insert(&dangling));

        // Finalizing below its height cannot classify it.
        let next = block(root.digest(), 1, 2);
        assert!(tree.insert(&next));
        tree.finalize(next.height(), next.digest());
        assert!(tree.branch(&dangling.digest()).is_some());

        // Finalizing at its height removes it.
        tree.finalize(dangling.height(), Sha256::fill(0xAB));
        assert!(tree.branch(&dangling.digest()).is_none());
    }

    #[test]
    fn finalize_prunes_descendants_of_conflicts_but_not_dangling() {
        let mut tree = ForkTree::<TestBlock>::new();
        let root = block(Sha256Digest::EMPTY, 0, 0);
        tree.finalize(root.height(), root.digest());

        // A fork with descendants, plus a dangling chain above the boundary.
        let canonical = chain(root.digest(), 1, 1, 10);
        let fork = chain(root.digest(), 1, 4, 20);
        let dangling = chain(Sha256Digest::EMPTY, 3, 2, 30);
        for block in canonical.iter().chain(fork.iter()).chain(dangling.iter()) {
            assert!(tree.insert(block));
        }

        tree.finalize(canonical[0].height(), canonical[0].digest());

        // The conflicting fork is gone, including descendants above the boundary.
        for block in &fork {
            assert!(tree.branch(&block.digest()).is_none());
        }
        // The dangling chain survives: its ancestry is not locally decidable.
        for block in &dangling {
            assert!(tree.branch(&block.digest()).is_some());
        }
    }

    #[test]
    fn finalize_ignores_stale_and_skips_levels() {
        let mut tree = ForkTree::<TestBlock>::new();
        let root = block(Sha256Digest::EMPTY, 0, 0);
        tree.finalize(root.height(), root.digest());

        let canonical = chain(root.digest(), 1, 5, 10);
        for block in &canonical {
            assert!(tree.insert(block));
        }

        // A stale finalization is a no-op.
        tree.finalize(Height::zero(), Sha256Digest::EMPTY);
        assert_eq!(tree.len(), 5);

        // Jumping several levels prunes everything at or below the new root.
        tree.finalize(canonical[3].height(), canonical[3].digest());
        assert_eq!(tree.len(), 1);

        // The root advanced: candidates at or below it are rejected, and only
        // extensions of the new root are accepted directly above it.
        assert!(!tree.insert(&canonical[2]));
        assert!(!tree.insert(&block(root.digest(), 5, 20)));
        assert!(tree.insert(&block(canonical[3].digest(), 5, 21)));
    }

    #[test]
    fn insert_rejects_provable_chain_invariant_violations() {
        let mut tree = ForkTree::<TestBlock>::new();
        let root = block(Sha256Digest::EMPTY, 5, 0);
        tree.finalize(root.height(), root.digest());

        let child = block(root.digest(), 6, 1);
        assert!(tree.insert(&child));

        // A block claiming a tracked parent from the wrong height lies about
        // its height or its parent.
        assert!(!tree.insert(&block(child.digest(), 100, 2)));
        // A block claiming the root as parent from the wrong height lies too.
        assert!(!tree.insert(&block(root.digest(), 50, 3)));
        // The truthful equivalents are accepted.
        assert!(tree.insert(&block(child.digest(), 7, 4)));
        assert_eq!(tree.len(), 2);
    }

    #[test]
    fn branch_stops_at_incontiguous_edge() {
        let mut tree = ForkTree::<TestBlock>::new();
        let root = block(Sha256Digest::EMPTY, 0, 0);
        tree.finalize(root.height(), root.digest());

        // A lying block is inserted while its claimed parent is unknown, so
        // the violation is not provable yet.
        let parent = block(root.digest(), 1, 1);
        let liar = block(parent.digest(), 9, 2);
        assert!(tree.insert(&liar));
        assert!(tree.insert(&parent));

        // The walk must not fabricate ancestry across the lying edge.
        let branch = tree.branch(&liar.digest()).expect("branch");
        assert!(branch.root.is_none());
        assert_eq!(branch.blocks.len(), 1);
        assert_eq!(branch.blocks[0].digest(), liar.digest());
    }

    #[test]
    fn finalize_removes_wrong_height_root_children() {
        let mut tree = ForkTree::<TestBlock>::new();
        let root = block(Sha256Digest::EMPTY, 0, 0);
        tree.finalize(root.height(), root.digest());

        // A dangling block claims a future finalized block as its parent
        // from the wrong height. The parent is never tracked, so the lie is
        // not provable at insertion time.
        let next = block(root.digest(), 1, 1);
        let liar = block(next.digest(), 9, 2);
        assert!(tree.insert(&liar));

        // Once the parent finalizes, the lie is provable and the block is
        // swept out.
        tree.finalize(next.height(), next.digest());
        assert!(tree.branch(&liar.digest()).is_none());
        assert_eq!(tree.len(), 0);
    }

    #[test]
    fn branch_reports_connectivity() {
        let mut tree = ForkTree::<TestBlock>::new();
        let root = block(Sha256Digest::EMPTY, 0, 0);
        tree.finalize(root.height(), root.digest());

        // Unknown tip.
        assert!(tree.branch(&Sha256Digest::EMPTY).is_none());

        // Connected chain of three blocks.
        let canonical = chain(root.digest(), 1, 3, 10);
        for block in &canonical {
            assert!(tree.insert(block));
        }
        let branch = tree.branch(&canonical[2].digest()).expect("branch");
        assert!(branch.root.is_some());
        assert_eq!(branch.blocks.len(), 3);
        for (block, expected) in branch.blocks.iter().zip(canonical.iter()) {
            assert_eq!(block.digest(), expected.digest());
        }

        // A dangling chain walks down as far as known and reports disconnected.
        let dangling = chain(Sha256Digest::EMPTY, 7, 2, 20);
        for block in &dangling {
            assert!(tree.insert(block));
        }
        let branch = tree.branch(&dangling[1].digest()).expect("branch");
        assert!(branch.root.is_none());
        assert_eq!(branch.blocks.len(), 2);
    }
}

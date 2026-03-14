//! A lightweight, borrow-based batch layer over a merkleized MMB.
//!
//! # Overview
//!
//! A [`Batch`] borrows a parent MMB ([`Readable`]) immutably and records mutations -- appends
//! and leaf updates -- without mutating the parent. Multiple batches can coexist on the same
//! parent, and batches can be stacked (Base <- A <- B <- ...) to arbitrary depth.
//!
//! # Lifecycle
//!
//! ```text
//! Mmb ─────borrow────> UnmerkleizedBatch  (accumulate mutations)
//!                            │
//!                       merkleize()
//!                            │
//!                            v
//!                      MerkleizedBatch     (has root, supports proofs)
//!                            │
//!                       finalize()
//!                            │
//!                            v
//!                        Changeset         (owned delta, no borrow)
//!                            │
//!                      mmb.apply(cs).unwrap()
//!                            │
//!                            v
//!                           Mmb             (updated in place)
//! ```

use crate::merkle::{
    hasher::Hasher,
    mmb::{
        iterator::{
            birthed_node_pos, child_leaves, children, leaf_pos, peak_birth_leaf, PeakIterator,
        },
        mem::find_merge_pair,
        proof, Error, Family, Location, Position,
    },
    Proof, Readable,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use commonware_cryptography::Digest;
use core::ops::Range;

/// MMB-specific type alias for `merkle::proof::Proof`.
pub type MmbProof<D> = Proof<Family, D>;

/// Information needed to flatten a chain of batches into a single [`Changeset`].
pub trait BatchChainInfo: Send + Sync {
    /// The digest type used by this MMB.
    type Digest: Digest;

    /// Number of nodes in the original MMB that the batch chain was forked
    /// from. This is constant through the entire chain.
    fn base_size(&self) -> Position;

    /// Collect all overwrites that target nodes in the original MMB
    /// (i.e. positions < `base_size()`), walking from the deepest
    /// ancestor to the current batch. Later batches overwrite earlier ones.
    fn collect_overwrites(&self, into: &mut BTreeMap<Position, Self::Digest>);
}

/// A batch of mutations against a parent MMB, which may itself be a merkleized batch.
pub struct Batch<
    'a,
    D: Digest,
    P: Readable<Family = Family, Digest = D, Error = Error>,
    S: State<D> = Dirty,
> {
    /// The parent MMB.
    parent: &'a P,
    /// Nodes appended by this batch, at positions [parent.size(), parent.size() + appended.len()).
    appended: Vec<D>,
    /// Overwritten nodes at positions < parent.size(). Shadows parent data; later writes win.
    overwrites: BTreeMap<Position, D>,
    /// Type-state: Dirty (mutable, no root) or `Clean<D>` (immutable, has root).
    state: S,
}

/// Sealed trait for batch state types.
mod private {
    pub trait Sealed {}
}

/// Trait for valid batch state types.
pub trait State<D: Digest>: private::Sealed + Sized + Send + Sync {}

/// Marker type for a batch whose root digest has been computed.
#[derive(Clone, Copy, Debug)]
pub struct Clean<D: Digest> {
    /// The root digest of the MMB after this batch has been applied.
    pub root: D,
}

impl<D: Digest> private::Sealed for Clean<D> {}
impl<D: Digest> State<D> for Clean<D> {}

/// Marker type for an unmerkleized batch (root digest not yet computed).
#[derive(Clone, Debug, Default)]
pub struct Dirty {
    /// Internal nodes that need to have their digests recomputed.
    /// Each entry is (node_pos, height).
    dirty_nodes: BTreeSet<(Position, u32)>,
}

impl Dirty {
    /// Insert a dirty node. Returns true if newly inserted.
    fn insert(&mut self, pos: Position, height: u32) -> bool {
        self.dirty_nodes.insert((pos, height))
    }

    /// Take all dirty nodes sorted by ascending height (bottom-up for merkleize).
    fn take_sorted_by_height(&mut self) -> Vec<(Position, u32)> {
        let mut v: Vec<_> = core::mem::take(&mut self.dirty_nodes).into_iter().collect();
        v.sort_by_key(|a| a.1);
        v
    }
}

impl private::Sealed for Dirty {}
impl<D: Digest> State<D> for Dirty {}

/// A batch whose root digest has not been computed.
pub type UnmerkleizedBatch<'a, D, P> = Batch<'a, D, P, Dirty>;

/// A batch whose root digest has been computed.
pub type MerkleizedBatch<'a, D, P> = Batch<'a, D, P, Clean<D>>;

/// Owned set of changes against a base MMB.
/// Apply via [`super::mem::Mmb::apply`].
pub struct Changeset<D: Digest> {
    /// Nodes appended after the base MMB's existing nodes.
    pub(crate) appended: Vec<D>,
    /// Overwritten nodes within the base MMB's range.
    pub(crate) overwrites: BTreeMap<Position, D>,
    /// Root digest after applying the changeset.
    pub(crate) root: D,
    /// Size of the base MMB when this changeset was created.
    pub(crate) base_size: Position,
}

impl<'a, D: Digest, P: Readable<Family = Family, Digest = D, Error = Error>, S: State<D>>
    Batch<'a, D, P, S>
{
    /// The total number of nodes visible through this batch.
    fn size(&self) -> Position {
        Position::new(*self.parent.size() + self.appended.len() as u64)
    }

    /// Resolve a node: overwrites -> appended -> parent.
    fn get_node(&self, pos: Position) -> Option<D> {
        if pos >= self.size() {
            return None;
        }
        if let Some(d) = self.overwrites.get(&pos) {
            return Some(*d);
        }
        if pos >= self.parent.size() {
            let index = (*pos - *self.parent.size()) as usize;
            return self.appended.get(index).copied();
        }
        self.parent.get_node(pos)
    }

    /// Store a digest to the given storage location.
    fn store_node(&mut self, pos: Position, digest: D) {
        if pos >= self.parent.size() {
            let index = (*pos - *self.parent.size()) as usize;
            self.appended[index] = digest;
        } else {
            self.overwrites.insert(pos, digest);
        }
    }
}

impl<'a, D: Digest, P: Readable<Family = Family, Digest = D, Error = Error>>
    UnmerkleizedBatch<'a, D, P>
{
    /// The number of leaves visible through this batch.
    pub fn leaves(&self) -> Location {
        Location::try_from(self.size()).expect("invalid mmb size")
    }

    /// Create a new batch borrowing `parent` immutably.
    pub fn new(parent: &'a P) -> Self {
        Self {
            parent,
            appended: Vec::new(),
            overwrites: BTreeMap::new(),
            state: Dirty::default(),
        }
    }

    /// Hash `element` and add it as a leaf. Returns the leaf's location.
    pub fn add(
        &mut self,
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
        element: &[u8],
    ) -> Location {
        let loc = self.leaves();
        let pos = leaf_pos(loc);
        debug_assert_eq!(pos, self.size());

        // Capture peaks before appending (size is valid here).
        let mut peaks: Vec<(Position, u32)> = PeakIterator::new(self.size()).collect();
        peaks.reverse(); // oldest to newest

        let leaf_d = hasher.leaf_digest(pos, element);
        self.appended.push(leaf_d);
        peaks.push((pos, 0));

        if let Some(idx) = find_merge_pair(&peaks) {
            let height = peaks[idx].1 + 1;
            let parent_pos = Position::new(pos.as_u64() + 1);
            self.appended.push(D::EMPTY); // placeholder
            self.state.insert(parent_pos, height);
        }

        loc
    }

    /// Update the leaf at `loc` to `element`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LeafOutOfBounds`] if `loc` is not an existing leaf.
    /// Returns [`Error::ElementPruned`] if the leaf has been pruned.
    pub fn update_leaf(
        &mut self,
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
        loc: Location,
        element: &[u8],
    ) -> Result<(), Error> {
        let leaves = self.leaves();
        if loc >= leaves {
            return Err(Error::LeafOutOfBounds(loc));
        }
        let pos = Position::try_from(loc)?;
        if pos < self.parent.pruned_to_pos() {
            return Err(Error::ElementPruned(pos));
        }
        let digest = hasher.leaf_digest(pos, element);
        self.store_node(pos, digest);
        self.mark_dirty(loc);
        Ok(())
    }

    /// Mark ancestors of the leaf at `loc` as dirty up to its peak.
    fn mark_dirty(&mut self, loc: Location) {
        let size = self.size();
        let peaks = PeakIterator::new(size);
        let mut end_leaf_cursor = peaks.leaves().as_u64();

        for (peak_pos, height) in peaks {
            let leaves_in_peak = 1u64 << height;
            let leaf_start = end_leaf_cursor - leaves_in_peak;
            end_leaf_cursor = leaf_start;

            if loc.as_u64() < leaf_start || loc.as_u64() >= leaf_start + leaves_in_peak {
                continue;
            }

            // Found the peak containing this leaf. Walk from peak to leaf, marking ancestors.
            self.mark_ancestors(peak_pos, height, leaf_start, loc);
            return;
        }

        panic!("leaf {loc} not found in any peak (size: {size})");
    }

    /// Walk from a peak down to the target leaf, inserting each internal node on the path
    /// into the dirty set. Stops early if a node is already dirty (its ancestors must be too).
    fn mark_ancestors(
        &mut self,
        pos: Position,
        height: u32,
        leaf_start: u64,
        target_loc: Location,
    ) {
        if height == 0 {
            return; // at the leaf itself
        }

        if !self.state.insert(pos, height) {
            return; // already dirty, ancestors must be too
        }

        let mid_leaf = leaf_start + (1u64 << (height - 1));
        let (left_leaf, right_leaf) = child_leaves(
            peak_birth_leaf(Location::new(leaf_start + (1u64 << height) - 1), height),
            height,
        );
        let is_child_leaf = height == 1;

        if target_loc.as_u64() < mid_leaf {
            let left_pos = birthed_node_pos(left_leaf, is_child_leaf);
            self.mark_ancestors(left_pos, height - 1, leaf_start, target_loc);
        } else {
            let right_pos = birthed_node_pos(right_leaf, is_child_leaf);
            self.mark_ancestors(right_pos, height - 1, mid_leaf, target_loc);
        }
    }

    /// Consume this batch and produce an immutable [`MerkleizedBatch`] with computed root.
    pub fn merkleize(
        mut self,
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
    ) -> MerkleizedBatch<'a, D, P> {
        let dirty = self.state.take_sorted_by_height();

        for &(pos, height) in &dirty {
            let (left, right) = children(pos, height);
            let left_d = self.get_node(left).expect("left child missing");
            let right_d = self.get_node(right).expect("right child missing");
            let digest = hasher.node_digest(pos, &left_d, &right_d);
            self.store_node(pos, digest);
        }

        // Compute root from peaks.
        let leaves = Location::try_from(self.size()).expect("invalid mmb size");
        let mut peaks: Vec<D> = PeakIterator::new(self.size())
            .map(|(peak_pos, _)| self.get_node(peak_pos).expect("peak missing"))
            .collect();
        peaks.reverse(); // oldest to newest for root fold
        let root = hasher.root(leaves, peaks.iter());

        Batch {
            parent: self.parent,
            appended: self.appended,
            overwrites: self.overwrites,
            state: Clean { root },
        }
    }
}

impl<'a, D: Digest, P: Readable<Family = Family, Digest = D, Error = Error>> Readable
    for MerkleizedBatch<'a, D, P>
{
    type Family = Family;
    type Digest = D;
    type Error = Error;
    type PeakIterator = PeakIterator;

    fn size(&self) -> Position {
        self.size()
    }

    fn get_node(&self, pos: Position) -> Option<D> {
        self.get_node(pos)
    }

    fn root(&self) -> D {
        self.state.root
    }

    fn pruned_to_pos(&self) -> Position {
        self.parent.pruned_to_pos()
    }

    fn peak_iterator(&self) -> Self::PeakIterator {
        PeakIterator::new(self.size())
    }

    fn proof(
        &self,
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
        loc: Location,
    ) -> Result<MmbProof<D>, Error> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }
        self.range_proof(hasher, loc..loc + 1).map_err(|e| match e {
            Error::RangeOutOfBounds(loc) => Error::LeafOutOfBounds(loc),
            _ => e,
        })
    }

    fn range_proof(
        &self,
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
        range: Range<Location>,
    ) -> Result<MmbProof<D>, Error> {
        proof::build_range_proof(hasher, self.leaves(), range, |pos| self.get_node(pos))
    }
}

impl<
        'a,
        D: Digest,
        P: Readable<Family = Family, Digest = D, Error = Error> + BatchChainInfo<Digest = D>,
    > BatchChainInfo for MerkleizedBatch<'a, D, P>
{
    type Digest = D;

    fn base_size(&self) -> Position {
        self.parent.base_size()
    }

    fn collect_overwrites(&self, into: &mut BTreeMap<Position, D>) {
        self.parent.collect_overwrites(into);
        let base_size = self.parent.base_size();
        for (&pos, &digest) in &self.overwrites {
            if pos < base_size {
                into.insert(pos, digest);
            }
        }
    }
}

impl<'a, D: Digest, P: Readable<Family = Family, Digest = D, Error = Error>>
    MerkleizedBatch<'a, D, P>
{
    /// Create a child batch on top of this merkleized batch.
    pub fn new_batch(&self) -> UnmerkleizedBatch<'_, D, Self> {
        UnmerkleizedBatch::new(self)
    }

    /// Convert back to a dirty batch for further mutations.
    pub fn into_dirty(self) -> UnmerkleizedBatch<'a, D, P> {
        Batch {
            parent: self.parent,
            appended: self.appended,
            overwrites: self.overwrites,
            state: Dirty::default(),
        }
    }
}

impl<
        'a,
        D: Digest,
        P: Readable<Family = Family, Digest = D, Error = Error> + BatchChainInfo<Digest = D>,
    > MerkleizedBatch<'a, D, P>
{
    /// Flatten this batch chain into a single [`Changeset`] relative to the
    /// ultimate base MMB.
    pub fn finalize(self) -> Changeset<D> {
        let base_size = self.parent.base_size();
        let effective = self.size();

        // Resolve nodes at [base_size, effective).
        let mut appended = Vec::with_capacity((*effective - *base_size) as usize);
        for i in *base_size..*effective {
            appended.push(self.get_node(Position::new(i)).expect("node in range"));
        }

        // Collect overwrites from entire chain, filtered to positions < base_size.
        let mut overwrites = BTreeMap::new();
        self.collect_overwrites(&mut overwrites);
        overwrites.retain(|&pos, _| pos < base_size);

        Changeset {
            appended,
            overwrites,
            root: self.state.root,
            base_size,
        }
    }
}

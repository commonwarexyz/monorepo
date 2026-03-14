//! A lightweight, borrow-based batch layer over a merkleized MMB.
//!
//! # Overview
//!
//! A [`Batch`] borrows a parent MMB ([`Readable`]) immutably and records mutations (appends)
//! without mutating the parent. Multiple batches can coexist on the same parent.
//!
//! # Lifecycle
//!
//! ```text
//! Mmb ─────borrow────> UnmerkleizedBatch  (accumulate appends)
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
        iterator::{children, leaf_pos, PeakIterator},
        mem::find_merge_pair,
        proof, Error, Family, Location, Position,
    },
    proof::Proof,
};
use alloc::vec::Vec;
use commonware_cryptography::Digest;
use core::ops::Range;

/// MMB-specific type alias for `merkle::proof::Proof`.
pub type MmbProof<D> = Proof<Family, D>;

/// Read-only interface for a merkleized MMB.
pub trait Readable: Send + Sync {
    /// The digest type used by this MMB.
    type Digest: Digest;

    /// Total number of nodes (retained + pruned).
    fn size(&self) -> Position;

    /// Digest of the node at `pos`, or `None` if pruned / out of bounds.
    fn get_node(&self, pos: Position) -> Option<Self::Digest>;

    /// Root digest of the MMB.
    fn root(&self) -> Self::Digest;

    /// Items before this position have been pruned.
    fn pruned_to_pos(&self) -> Position;

    /// Total number of leaves.
    fn leaves(&self) -> Location {
        Location::try_from(self.size()).expect("invalid mmb size")
    }

    /// Iterator over (peak_position, height) in newest-to-oldest order.
    fn peak_iterator(&self) -> PeakIterator {
        PeakIterator::new(self.size())
    }

    /// [start, end) range of retained node positions.
    fn bounds(&self) -> Range<Position> {
        self.pruned_to_pos()..self.size()
    }

    /// Inclusion proof for the element at `loc`.
    fn proof(
        &self,
        hasher: &mut impl Hasher<Family = Family, Digest = Self::Digest>,
        loc: Location,
    ) -> Result<MmbProof<Self::Digest>, Error> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }
        self.range_proof(hasher, loc..loc + 1).map_err(|e| match e {
            Error::RangeOutOfBounds(loc) => Error::LeafOutOfBounds(loc),
            _ => e,
        })
    }

    /// Inclusion proof for all elements in `range`.
    fn range_proof(
        &self,
        hasher: &mut impl Hasher<Family = Family, Digest = Self::Digest>,
        range: Range<Location>,
    ) -> Result<MmbProof<Self::Digest>, Error> {
        let leaves = self.leaves();
        proof::build_range_proof(hasher, leaves, range, |pos| self.get_node(pos))
    }
}

/// Information needed to flatten a chain of batches into a single [`Changeset`].
pub trait BatchChainInfo: Send + Sync {
    /// The digest type used by this MMB.
    type Digest: Digest;

    /// Number of nodes in the original MMB that the batch chain was forked
    /// from. This is constant through the entire chain.
    fn base_size(&self) -> Position;
}

/// A batch of mutations against a parent MMB.
pub struct Batch<'a, D: Digest, P: Readable<Digest = D>, S: State<D> = Dirty> {
    /// The parent MMB.
    parent: &'a P,
    /// Nodes appended by this batch, at positions [parent.size(), parent.size() + appended.len()).
    appended: Vec<D>,
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
    /// Internal nodes that need to have their digests computed.
    /// Each entry is (parent_pos, height).
    dirty_nodes: Vec<(Position, u32)>,
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
    /// Root digest after applying the changeset.
    pub(crate) root: D,
    /// Size of the base MMB when this changeset was created.
    pub(crate) base_size: Position,
}

impl<'a, D: Digest, P: Readable<Digest = D>, S: State<D>> Batch<'a, D, P, S> {
    /// The total number of nodes visible through this batch.
    fn size(&self) -> Position {
        Position::new(*self.parent.size() + self.appended.len() as u64)
    }

    /// Resolve a node: appended -> parent.
    fn get_node(&self, pos: Position) -> Option<D> {
        if pos >= self.size() {
            return None;
        }
        if pos >= self.parent.size() {
            let index = (*pos - *self.parent.size()) as usize;
            return self.appended.get(index).copied();
        }
        self.parent.get_node(pos)
    }
}

impl<'a, D: Digest, P: Readable<Digest = D>> UnmerkleizedBatch<'a, D, P> {
    /// The number of leaves visible through this batch.
    pub fn leaves(&self) -> Location {
        Location::try_from(self.size()).expect("invalid mmb size")
    }

    /// Create a new batch borrowing `parent` immutably.
    pub fn new(parent: &'a P) -> Self {
        Self {
            parent,
            appended: Vec::new(),
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
            self.state.dirty_nodes.push((parent_pos, height));
        }

        loc
    }

    /// Consume this batch and produce an immutable [`MerkleizedBatch`] with computed root.
    pub fn merkleize(
        mut self,
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
    ) -> MerkleizedBatch<'a, D, P> {
        // Sort dirty nodes by height (ascending) so children are computed before parents.
        self.state.dirty_nodes.sort_by_key(|&(_, h)| h);

        for &(pos, height) in &self.state.dirty_nodes {
            let (left, right) = children(pos, height);
            let left_d = self.get_node(left).expect("left child missing");
            let right_d = self.get_node(right).expect("right child missing");
            let digest = hasher.node_digest(pos, &left_d, &right_d);
            let index = (*pos - *self.parent.size()) as usize;
            self.appended[index] = digest;
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
            state: Clean { root },
        }
    }
}

impl<'a, D: Digest, P: Readable<Digest = D>> Readable for MerkleizedBatch<'a, D, P> {
    type Digest = D;

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
}

impl<'a, D: Digest, P: Readable<Digest = D> + BatchChainInfo<Digest = D>> BatchChainInfo
    for MerkleizedBatch<'a, D, P>
{
    type Digest = D;

    fn base_size(&self) -> Position {
        self.parent.base_size()
    }
}

impl<'a, D: Digest, P: Readable<Digest = D>> MerkleizedBatch<'a, D, P> {
    /// Create a child batch on top of this merkleized batch.
    pub fn new_batch(&self) -> UnmerkleizedBatch<'_, D, Self> {
        UnmerkleizedBatch::new(self)
    }

    /// Convert back to a dirty batch for further mutations.
    pub fn into_dirty(self) -> UnmerkleizedBatch<'a, D, P> {
        Batch {
            parent: self.parent,
            appended: self.appended,
            state: Dirty::default(),
        }
    }
}

impl<'a, D: Digest, P: Readable<Digest = D> + BatchChainInfo<Digest = D>>
    MerkleizedBatch<'a, D, P>
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

        Changeset {
            appended,
            root: self.state.root,
            base_size,
        }
    }
}

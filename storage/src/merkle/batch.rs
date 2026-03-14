//! Shared batch infrastructure for Merkle-family data structures.
//!
//! Provides the type-state machinery ([`State`], [`Dirty`], [`Clean`]), the [`Batch`] struct
//! with its node resolution logic, and [`Changeset`]. Each Merkle family (MMR, MMB) builds on
//! these to supply family-specific `add`, `update_leaf`, and `merkleize`.

use crate::merkle::{Family, Position, Readable};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use commonware_cryptography::Digest;

// ---------------------------------------------------------------------------
// State type-state
// ---------------------------------------------------------------------------

mod private {
    pub trait Sealed {}
}

/// Trait for valid batch state types.
pub trait State<D: Digest>: private::Sealed + Sized + Send + Sync {}

/// Marker type for a batch whose root digest has been computed.
#[derive(Clone, Copy, Debug)]
pub struct Clean<D: Digest> {
    /// The root digest after this batch has been applied.
    pub root: D,
}

impl<D: Digest> private::Sealed for Clean<D> {}
impl<D: Digest> State<D> for Clean<D> {}

/// Marker type for an unmerkleized batch (root digest not yet computed).
#[derive(Clone, Debug)]
pub struct Dirty<F: Family> {
    /// Internal nodes that need to have their digests recomputed.
    /// Each entry is (node_pos, height).
    dirty_nodes: BTreeSet<(Position<F>, u32)>,
}

impl<F: Family> Default for Dirty<F> {
    fn default() -> Self {
        Self {
            dirty_nodes: BTreeSet::new(),
        }
    }
}

impl<F: Family> Dirty<F> {
    /// Insert a dirty node. Returns true if newly inserted.
    pub fn insert(&mut self, pos: Position<F>, height: u32) -> bool {
        self.dirty_nodes.insert((pos, height))
    }

    /// Take all dirty nodes sorted by ascending height (bottom-up for merkleize).
    pub fn take_sorted_by_height(&mut self) -> Vec<(Position<F>, u32)> {
        let mut v: Vec<_> = core::mem::take(&mut self.dirty_nodes).into_iter().collect();
        v.sort_by_key(|a| a.1);
        v
    }
}

impl<F: Family> private::Sealed for Dirty<F> {}
impl<F: Family, D: Digest> State<D> for Dirty<F> {}

// ---------------------------------------------------------------------------
// Batch
// ---------------------------------------------------------------------------

/// A batch of mutations against a parent Merkle structure.
///
/// The batch borrows the parent immutably and records appends and overwrites.
/// Multiple batches can coexist on the same parent, and batches can be stacked
/// (Base <- A <- B) to arbitrary depth.
pub struct Batch<'a, F: Family, D: Digest, P: Readable<Family = F, Digest = D>, S: State<D>> {
    /// The parent structure.
    pub(crate) parent: &'a P,
    /// Nodes appended by this batch.
    pub(crate) appended: Vec<D>,
    /// Overwritten nodes at positions < parent.size().
    pub(crate) overwrites: BTreeMap<Position<F>, D>,
    /// Type-state: Dirty (mutable, no root) or Clean (immutable, has root).
    pub(crate) state: S,
}

/// A batch whose root digest has not been computed.
pub type UnmerkleizedBatch<'a, F, D, P> = Batch<'a, F, D, P, Dirty<F>>;

/// A batch whose root digest has been computed.
pub type MerkleizedBatch<'a, F, D, P> = Batch<'a, F, D, P, Clean<D>>;

impl<'a, F: Family, D: Digest, P: Readable<Family = F, Digest = D>, S: State<D>>
    Batch<'a, F, D, P, S>
{
    /// The total number of nodes visible through this batch.
    pub fn size(&self) -> Position<F> {
        Position::new(*self.parent.size() + self.appended.len() as u64)
    }

    /// The number of leaves visible through this batch.
    pub fn leaves(&self) -> crate::merkle::Location<F> {
        crate::merkle::Location::try_from(self.size()).expect("invalid size")
    }

    /// Resolve a node: overwrites -> appended -> parent.
    pub fn get_node(&self, pos: Position<F>) -> Option<D> {
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

    /// Store a digest at the given position.
    pub fn store_node(&mut self, pos: Position<F>, digest: D) {
        if pos >= self.parent.size() {
            let index = (*pos - *self.parent.size()) as usize;
            self.appended[index] = digest;
        } else {
            self.overwrites.insert(pos, digest);
        }
    }
}

impl<'a, F: Family, D: Digest, P: Readable<Family = F, Digest = D>> UnmerkleizedBatch<'a, F, D, P> {
    /// Create a new batch borrowing `parent` immutably.
    pub fn new(parent: &'a P) -> Self {
        Self {
            parent,
            appended: Vec::new(),
            overwrites: BTreeMap::new(),
            state: Dirty::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Batch Chain and Finalize
// ---------------------------------------------------------------------------

/// Information needed to flatten a chain of batches into a single [`Changeset`].
pub trait BatchChainInfo<F: Family>: Send + Sync {
    /// The digest type used by this structure.
    type Digest: Digest;

    /// Number of nodes in the original structure that the batch chain was forked
    /// from. This is constant through the entire chain.
    fn base_size(&self) -> Position<F>;

    /// Collect all overwrites that target nodes in the original structure
    /// (i.e. positions < `base_size()`), walking from the deepest
    /// ancestor to the current batch. Later batches overwrite earlier ones.
    fn collect_overwrites(&self, into: &mut BTreeMap<Position<F>, Self::Digest>);
}

impl<
        'a,
        F: Family,
        D: Digest,
        P: Readable<Family = F, Digest = D> + BatchChainInfo<F, Digest = D>,
        S: State<D>,
    > BatchChainInfo<F> for Batch<'a, F, D, P, S>
{
    type Digest = D;

    fn base_size(&self) -> Position<F> {
        self.parent.base_size()
    }

    fn collect_overwrites(&self, into: &mut BTreeMap<Position<F>, D>) {
        self.parent.collect_overwrites(into);
        let base_size = self.base_size();
        for (pos, d) in &self.overwrites {
            if *pos < base_size {
                into.insert(*pos, *d);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Changeset
// ---------------------------------------------------------------------------

/// Owned set of changes against a base Merkle structure.
pub struct Changeset<F: Family, D: Digest> {
    /// Nodes appended after the base structure's existing nodes.
    pub appended: Vec<D>,
    /// Overwritten nodes within the base structure's range.
    pub overwrites: BTreeMap<Position<F>, D>,
    /// Root digest after applying the changeset.
    pub root: D,
    /// Size of the base structure when this changeset was created.
    pub base_size: Position<F>,
}

impl<
        'a,
        F: Family,
        D: Digest,
        P: Readable<Family = F, Digest = D> + BatchChainInfo<F, Digest = D>,
    > MerkleizedBatch<'a, F, D, P>
{
    /// Flatten this batch chain into a single [`Changeset`] relative to the
    /// ultimate base structure.
    pub fn finalize(self) -> Changeset<F, D> {
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

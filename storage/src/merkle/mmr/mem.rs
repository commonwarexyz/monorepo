//! A basic, no_std compatible MMR where all nodes are stored in-memory.
//!
//! `Mmr<D>` is a thin wrapper around [`crate::merkle::mem::Mem`] that provides MMR-specific error types
//! and additional operations (truncation, pinned node management).

use crate::merkle::{
    batch::BatchChainInfo,
    hasher::Hasher,
    mem,
    mmr::{iterator::PeakIterator, Error, Family, Location, Position, Proof, Readable},
};
use alloc::{collections::BTreeMap, vec::Vec};
use commonware_cryptography::Digest;
use core::ops::Range;

/// Minimum number of digest computations required during batch updates to trigger parallelization.
#[cfg(feature = "std")]
pub(crate) const MIN_TO_PARALLELIZE: usize = 20;

/// Configuration for initializing an [Mmr].
pub struct Config<D: Digest> {
    /// The retained nodes of the MMR.
    pub nodes: Vec<D>,

    /// The leaf location up to which this MMR has been pruned, or 0 if this MMR has never been
    /// pruned.
    pub pruned_to: Location,

    /// The pinned nodes of the MMR, in the order expected by `nodes_to_pin`.
    pub pinned_nodes: Vec<D>,
}

/// A basic MMR where all nodes are stored in-memory.
///
/// # Terminology
///
/// Nodes in this structure are either _retained_, _pruned_, or _pinned_. Retained nodes are nodes
/// that have not yet been pruned, and have digests stored explicitly within the tree structure.
/// Pruned nodes are those whose positions precede that of the _oldest retained_ node, for which no
/// digests are maintained. Pinned nodes are nodes that would otherwise be pruned based on their
/// position, but whose digests remain required for proof generation. The digests for pinned nodes
/// are stored in an auxiliary map, and are at most O(log2(n)) in number.
///
/// # Mutation
///
/// The MMR is always merkleized (its root is always computed). Mutations go through the
/// batch API: create an [`super::batch::UnmerkleizedBatch`] via [`Self::new_batch`],
/// accumulate changes, then apply the resulting [`super::batch::Changeset`] via [`Self::apply`].
#[derive(Clone, Debug)]
pub struct Mmr<D: Digest> {
    inner: mem::Mem<Family, D>,
}

impl<D: Digest> Mmr<D> {
    /// Create a new, empty MMR.
    pub fn new(hasher: &mut impl Hasher<Family, Digest = D>) -> Self {
        Self {
            inner: mem::Mem::new(hasher),
        }
    }

    /// Return an [Mmr] initialized with the given `config`.
    ///
    /// # Errors
    ///
    /// Returns [Error::InvalidPinnedNodes] if the number of pinned nodes doesn't match the expected
    /// count for `config.pruned_to`.
    ///
    /// Returns [Error::InvalidSize] if the MMR size is invalid.
    pub fn init(
        config: Config<D>,
        hasher: &mut impl Hasher<Family, Digest = D>,
    ) -> Result<Self, Error> {
        let inner = mem::Mem::init(
            mem::Config {
                nodes: config.nodes,
                pruned_to: config.pruned_to,
                pinned_nodes: config.pinned_nodes,
            },
            hasher,
        )?;
        Ok(Self { inner })
    }

    /// Re-initialize the MMR with the given nodes, pruned_to location, and pinned_nodes.
    pub fn from_components(
        hasher: &mut impl Hasher<Family, Digest = D>,
        nodes: Vec<D>,
        pruned_to: Location,
        pinned_nodes: Vec<D>,
    ) -> Result<Self, Error> {
        Self::init(
            Config {
                nodes,
                pruned_to,
                pinned_nodes,
            },
            hasher,
        )
    }

    /// Returns the root that would be produced by calling `root` on an empty MMR.
    pub fn empty_mmr_root(hasher: &mut impl commonware_cryptography::Hasher<Digest = D>) -> D {
        hasher.update(&0u64.to_be_bytes());
        hasher.finalize()
    }

    /// Return the total number of nodes in the MMR, irrespective of any pruning.
    pub fn size(&self) -> Position {
        self.inner.size()
    }

    /// Return the total number of leaves in the MMR.
    pub const fn leaves(&self) -> Location {
        self.inner.leaves()
    }

    /// Returns [start, end) where `start` is the oldest retained leaf and `end` is the total leaf
    /// count.
    pub fn bounds(&self) -> Range<Location> {
        self.inner.bounds()
    }

    /// Return a new iterator over the peaks of the MMR.
    pub fn peak_iterator(&self) -> PeakIterator {
        PeakIterator::new(self.size())
    }

    /// Get the root digest of the MMR.
    pub const fn root(&self) -> &D {
        self.inner.root()
    }

    /// Return the requested node or None if it is not stored in the MMR.
    pub fn get_node(&self, pos: Position) -> Option<D> {
        self.inner.get_node(pos)
    }

    /// Return the requested node, panicking if not available.
    pub(crate) fn get_node_unchecked(&self, pos: Position) -> &D {
        self.inner.get_node_unchecked(pos)
    }

    /// Get the nodes (position + digest) that need to be pinned at `prune_pos`.
    #[cfg(test)]
    pub(crate) fn nodes_to_pin(&self, prune_pos: Position) -> BTreeMap<Position, D> {
        self.inner.nodes_to_pin(prune_pos)
    }

    /// Utility used by stores that build on the mem MMR to pin extra nodes if needed.
    #[cfg(any(feature = "std", test))]
    pub(crate) fn add_pinned_nodes(&mut self, pinned_nodes: BTreeMap<Position, D>) {
        self.inner.add_pinned_nodes(pinned_nodes);
    }

    /// Create a new speculative batch with this MMR as its parent.
    pub fn new_batch(&self) -> super::batch::UnmerkleizedBatch<'_, D, Self> {
        super::batch::UnmerkleizedBatch::new(self)
    }

    /// Apply a changeset produced by [`super::batch::MerkleizedBatch::finalize`].
    pub fn apply(&mut self, changeset: super::batch::Changeset<D>) -> Result<(), Error> {
        self.inner.apply(changeset).map_err(Error::from)
    }

    /// Prune all nodes up to but not including the given leaf location.
    pub fn prune(&mut self, loc: Location) -> Result<(), Error> {
        self.inner.prune(loc).map_err(Error::from)
    }

    /// Prune all nodes and pin those required for proof generation.
    pub fn prune_all(&mut self) {
        self.inner.prune_all();
    }

    /// Truncate the MMR to a smaller valid size.
    #[cfg(feature = "std")]
    pub(crate) fn truncate(
        &mut self,
        new_size: Position,
        hasher: &mut impl Hasher<Family, Digest = D>,
    ) {
        self.inner.truncate(new_size, hasher);
    }

    /// Return an inclusion proof for the element at location `loc`.
    pub fn proof(
        &self,
        hasher: &mut impl Hasher<Family, Digest = D>,
        loc: Location,
    ) -> Result<Proof<D>, Error> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }
        self.range_proof(hasher, loc..loc + 1).map_err(|e| match e {
            Error::RangeOutOfBounds(_) => Error::LeafOutOfBounds(loc),
            _ => e,
        })
    }

    /// Return an inclusion proof for all elements in `range`.
    pub fn range_proof(
        &self,
        hasher: &mut impl Hasher<Family, Digest = D>,
        range: Range<Location>,
    ) -> Result<Proof<D>, Error> {
        let leaves = self.inner.leaves();
        crate::merkle::proof::build_range_proof(hasher, leaves, range, |pos| {
            self.inner.get_node(pos)
        })
        .map_err(Error::from)
    }

    /// Get the digests of nodes that need to be pinned when pruned to `start_pos`.
    #[cfg(test)]
    pub(crate) fn node_digests_to_pin(&self, start_pos: Position) -> Vec<D> {
        self.inner.node_digests_to_pin(start_pos)
    }

    /// Return the nodes currently pinned.
    #[cfg(test)]
    pub(super) fn pinned_nodes(&self) -> BTreeMap<Position, D> {
        self.inner.pinned_nodes()
    }

    /// The pruned-to position.
    pub(crate) const fn pruned_to_pos(&self) -> Position {
        self.inner.pruned_to_pos()
    }
}

impl<D: Digest> Readable for Mmr<D> {
    type Family = Family;
    type Digest = D;
    type Error = Error;
    type PeakIterator = PeakIterator;

    fn size(&self) -> Position {
        self.inner.size()
    }

    fn get_node(&self, pos: Position) -> Option<D> {
        self.inner.get_node(pos)
    }

    fn root(&self) -> D {
        *self.inner.root()
    }

    fn pruned_to_pos(&self) -> Position {
        self.inner.pruned_to_pos()
    }

    fn peak_iterator(&self) -> Self::PeakIterator {
        PeakIterator::new(self.inner.size())
    }

    fn proof(
        &self,
        hasher: &mut impl Hasher<Family, Digest = D>,
        loc: Location,
    ) -> Result<Proof<D>, Error> {
        self.proof(hasher, loc)
    }

    fn range_proof(
        &self,
        hasher: &mut impl Hasher<Family, Digest = D>,
        range: core::ops::Range<Location>,
    ) -> Result<Proof<D>, Error> {
        self.range_proof(hasher, range)
    }
}

impl<D: Digest> BatchChainInfo<Family> for Mmr<D> {
    type Digest = D;

    fn base_size(&self) -> Position {
        self.inner.size()
    }

    fn collect_overwrites(&self, _into: &mut BTreeMap<Position, D>) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{merkle::hasher::Standard, mmr::conformance::build_test_mmr};
    use commonware_cryptography::{sha256, Hasher as _, Sha256};

    type H = Standard<Sha256>;

    fn build_reference(hasher: &mut H, n: u64) -> Mmr<sha256::Digest> {
        let mmr = Mmr::new(hasher);
        build_test_mmr(hasher, mmr, n)
    }

    #[test]
    fn test_empty_mmr() {
        let mut hasher = H::new();
        let mmr = Mmr::<sha256::Digest>::new(&mut hasher);
        assert_eq!(mmr.size(), 0u64);
        assert_eq!(mmr.leaves(), 0u64);
    }

    #[test]
    fn test_add_and_root() {
        let mut hasher = H::new();
        let reference = build_reference(&mut hasher, 10);
        assert_ne!(*reference.root(), Mmr::empty_mmr_root(&mut Sha256::new()));
    }

    #[test]
    fn test_prune_and_reinit() {
        let mut hasher = H::new();
        let mut mmr = build_reference(&mut hasher, 100);
        let root_before = *mmr.root();

        mmr.prune(Location::new(50)).unwrap();
        assert_eq!(*mmr.root(), root_before);

        // Extract and reinit.
        let pruned_pos = mmr.pruned_to_pos();
        let retained: Vec<_> = (0..(*mmr.size() - *pruned_pos))
            .map(|i| mmr.get_node(Position::new(*pruned_pos + i)).unwrap())
            .collect();
        let pinned = mmr.node_digests_to_pin(pruned_pos);
        let pruned_to = Location::try_from(pruned_pos).unwrap();

        let reinit = Mmr::from_components(&mut hasher, retained, pruned_to, pinned).unwrap();
        assert_eq!(*reinit.root(), root_before);
    }

    #[test]
    fn test_stale_changeset() {
        let mut hasher = H::new();
        let mut mmr = build_reference(&mut hasher, 10);

        let cs1 = {
            let mut batch = mmr.new_batch();
            batch.add(&mut hasher, b"a");
            batch.merkleize(&mut hasher).finalize()
        };
        let cs2 = {
            let mut batch = mmr.new_batch();
            batch.add(&mut hasher, b"b");
            batch.merkleize(&mut hasher).finalize()
        };
        mmr.apply(cs2).unwrap();
        assert!(matches!(mmr.apply(cs1), Err(Error::StaleChangeset { .. })));
    }

    #[test]
    fn test_prune_all() {
        let mut hasher = H::new();
        let mut mmr = build_reference(&mut hasher, 50);
        let root = *mmr.root();
        mmr.prune_all();
        assert_eq!(*mmr.root(), root);
        assert!(mmr.bounds().is_empty());
    }

    #[test]
    fn test_proof_retained_and_pruned() {
        let mut hasher = H::new();
        let mut mmr = build_reference(&mut hasher, 100);
        mmr.prune(Location::new(30)).unwrap();

        // Retained element should produce a valid proof.
        let element = hasher.digest(&50u64.to_be_bytes());
        let proof = mmr.proof(&mut hasher, Location::new(50)).unwrap();
        assert!(proof.verify_element_inclusion(
            &mut hasher,
            &element,
            Location::new(50),
            mmr.root(),
        ));

        // Pruned element should fail.
        assert!(matches!(
            mmr.proof(&mut hasher, Location::new(0)),
            Err(Error::ElementPruned(_))
        ));
    }

    #[test]
    fn test_consistency_with_reference() {
        let mut hasher = H::new();

        for &n in &[1u64, 2, 10, 100, 199] {
            let reference = build_reference(&mut hasher, n);

            let base = Mmr::new(&mut hasher);
            let mut batch = super::super::batch::UnmerkleizedBatch::new(&base);
            for i in 0..n {
                let element = hasher.digest(&i.to_be_bytes());
                batch.add(&mut hasher, &element);
            }
            let merkleized = batch.merkleize(&mut hasher);
            let changeset = merkleized.finalize();
            let mut result = base.clone();
            result.apply(changeset).unwrap();

            assert_eq!(result.root(), reference.root(), "root mismatch for n={n}");
        }
    }
}

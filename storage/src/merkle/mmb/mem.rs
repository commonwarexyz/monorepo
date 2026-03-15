//! A basic, no_std compatible MMB where all nodes are stored in-memory.

use crate::merkle::{
    batch::BatchChainInfo,
    hasher::Hasher,
    mmb::{iterator::PeakIterator, proof, Error, Family, Location, Position},
    proof::Proof,
};
use alloc::{
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};
use commonware_cryptography::Digest;
use core::ops::Range;

/// Configuration for initializing an [Mmb].
pub struct Config<D: Digest> {
    /// The retained nodes of the MMB.
    pub nodes: Vec<D>,

    /// The leaf location up to which this MMB has been pruned, or 0 if this MMB has never been
    /// pruned.
    pub pruned_to: Location,

    /// The pinned nodes of the MMB, in the order expected by `iterator::nodes_to_pin`.
    pub pinned_nodes: Vec<D>,
}

/// A basic MMB where all nodes are stored in-memory.
///
/// Nodes in this structure are either retained, pruned, or pinned. Retained nodes are stored in
/// the main deque. Pruned nodes precede `pruned_to_pos` and are no longer stored unless they are
/// still required for root computation or proof generation, in which case they are kept in
/// `pinned_nodes`.
pub struct Mmb<D: Digest> {
    /// The retained nodes of the MMB, starting at `pruned_to_pos`.
    nodes: VecDeque<D>,

    /// The highest position for which this MMB has been pruned, or 0 if this MMB has never been
    /// pruned.
    ///
    /// # Invariant
    ///
    /// This is always leaf-aligned, meaning it is the position corresponding to some `Location`.
    pruned_to_pos: Position,

    /// The auxiliary map from node position to the digest of any pinned node.
    pinned_nodes: BTreeMap<Position, D>,

    /// The root digest of the MMB.
    root: D,

    /// The number of leaves in the MMB.
    leaves: Location,
}

impl<D: Digest> Mmb<D> {
    /// Create a new, empty MMB.
    pub fn new(hasher: &mut impl Hasher<Family = Family, Digest = D>) -> Self {
        let root = hasher.root(Location::new(0), core::iter::empty::<&D>());
        Self {
            nodes: VecDeque::new(),
            pruned_to_pos: Position::new(0),
            pinned_nodes: BTreeMap::new(),
            root,
            leaves: Location::new(0),
        }
    }

    /// Return an [Mmb] initialized with the given `config`.
    ///
    /// # Errors
    ///
    /// Returns [Error::InvalidPinnedNodes] if the number of pinned nodes doesn't match the expected
    /// count for `config.pruned_to`.
    ///
    /// Returns [Error::InvalidSize] if the MMB size is invalid.
    pub fn init(
        config: Config<D>,
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
    ) -> Result<Self, Error> {
        let pruned_to_pos = Position::try_from(config.pruned_to)?;

        let Some(size) = pruned_to_pos.checked_add(config.nodes.len() as u64) else {
            return Err(Error::InvalidSize(u64::MAX));
        };
        if !size.is_valid_size() {
            return Err(Error::InvalidSize(*size));
        }

        let expected_pinned_positions =
            <Family as crate::merkle::Family>::nodes_to_pin(size, pruned_to_pos);
        if config.pinned_nodes.len() != expected_pinned_positions.len() {
            return Err(Error::InvalidPinnedNodes);
        }

        let pinned_nodes = expected_pinned_positions
            .into_iter()
            .zip(config.pinned_nodes)
            .collect();
        let nodes = VecDeque::from(config.nodes);
        let leaves = Location::try_from(size).map_err(|_| Error::InvalidSize(*size))?;
        let root = Self::compute_root(hasher, leaves, &nodes, &pinned_nodes, pruned_to_pos);

        Ok(Self {
            nodes,
            pruned_to_pos,
            pinned_nodes,
            root,
            leaves,
        })
    }

    /// Re-initialize the MMB with the given nodes, pruning boundary, and pinned nodes.
    ///
    /// # Errors
    ///
    /// Returns [Error::InvalidPinnedNodes] if the provided pinned node count is invalid for the
    /// given state.
    ///
    /// Returns [Error::LocationOverflow] if `pruned_to` exceeds [crate::merkle::Family::MAX_LOCATION].
    pub fn from_components(
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
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

    /// Compute the root digest from the current peaks.
    fn compute_root(
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
        leaves: Location,
        nodes: &VecDeque<D>,
        pinned_nodes: &BTreeMap<Position, D>,
        pruned_to_pos: Position,
    ) -> D {
        let size = Position::try_from(leaves).expect("invalid MMB leaves");
        let get_node = |pos: Position| -> &D {
            if pos < pruned_to_pos {
                return pinned_nodes
                    .get(&pos)
                    .expect("requested node is pruned and not pinned");
            }

            let index = (*pos - *pruned_to_pos) as usize;
            &nodes[index]
        };

        let mut peaks: Vec<&D> = PeakIterator::new(size)
            .map(|(peak_pos, _)| get_node(peak_pos))
            .collect();
        peaks.reverse();
        hasher.root(leaves, peaks)
    }

    /// Return the total number of nodes in the MMB, irrespective of any pruning.
    pub fn size(&self) -> Position {
        Position::new(self.nodes.len() as u64 + *self.pruned_to_pos)
    }

    /// Return the total number of leaves in the MMB.
    pub const fn leaves(&self) -> Location {
        self.leaves
    }

    /// Returns [start, end) where `start` is the oldest retained leaf and `end` is the total leaf
    /// count.
    pub fn bounds(&self) -> Range<Location> {
        Location::try_from(self.pruned_to_pos).expect("valid pruned_to_pos")..self.leaves()
    }

    /// Return a new iterator over the peaks of the MMB.
    pub fn peak_iterator(&self) -> PeakIterator {
        PeakIterator::new(self.size())
    }

    /// Get the root digest.
    pub const fn root(&self) -> &D {
        &self.root
    }

    /// Return the requested node if it is either retained or present in the pinned_nodes map, and
    /// panic otherwise. Use `get_node` instead if you require a non-panicking getter.
    ///
    /// # Panics
    ///
    /// Panics if the requested node does not exist for any reason such as the node is pruned or
    /// `pos` is out of bounds.
    fn get_node_unchecked(&self, pos: Position) -> &D {
        if pos < self.pruned_to_pos {
            return self
                .pinned_nodes
                .get(&pos)
                .expect("requested node is pruned and not pinned");
        }

        &self.nodes[self.pos_to_index(pos)]
    }

    /// Return the index of the element in the current nodes vector given its position in the MMB.
    ///
    /// # Panics
    ///
    /// Panics if `pos` precedes the oldest retained position.
    fn pos_to_index(&self, pos: Position) -> usize {
        assert!(
            pos >= self.pruned_to_pos,
            "pos precedes oldest retained position"
        );

        *pos.checked_sub(*self.pruned_to_pos).unwrap() as usize
    }

    /// Return the positions and digests that must remain pinned for the provided pruning boundary.
    fn collect_pinned_nodes(&self, size: Position, prune_pos: Position) -> BTreeMap<Position, D> {
        <Family as crate::merkle::Family>::nodes_to_pin(size, prune_pos)
            .into_iter()
            .map(|pos| (pos, *self.get_node_unchecked(pos)))
            .collect()
    }

    /// Recompute the pinned node set for the current MMB size.
    fn refresh_pinned_nodes(&mut self) {
        if self.pruned_to_pos == 0 {
            self.pinned_nodes.clear();
            return;
        }

        self.pinned_nodes = self.collect_pinned_nodes(self.size(), self.pruned_to_pos);
    }

    /// Return the requested node or None if it is not stored in the MMB.
    pub fn get_node(&self, pos: Position) -> Option<D> {
        if pos < self.pruned_to_pos {
            return self.pinned_nodes.get(&pos).copied();
        }

        self.nodes.get(self.pos_to_index(pos)).copied()
    }

    /// Create a new speculative batch with this MMB as its parent.
    pub fn new_batch(&self) -> super::batch::UnmerkleizedBatch<'_, D, Self> {
        super::batch::UnmerkleizedBatch::new(self)
    }

    /// Apply a changeset produced by [`super::batch::MerkleizedBatch::finalize`].
    ///
    /// A changeset is only valid if the MMB has not been modified since the
    /// batch that produced it was created. Applying a stale changeset returns
    /// [`super::Error::StaleChangeset`].
    pub fn apply(&mut self, changeset: super::batch::Changeset<D>) -> Result<(), super::Error> {
        if changeset.base_size != self.size() {
            return Err(super::Error::StaleChangeset {
                expected: changeset.base_size,
                actual: self.size(),
            });
        }

        // 1. Overwrite: write modified digests into surviving base nodes.
        for (pos, digest) in changeset.overwrites {
            let index = self.pos_to_index(pos);
            self.nodes[index] = digest;
        }

        // 2. Append: push new nodes onto the end.
        for digest in changeset.appended {
            self.nodes.push_back(digest);
        }

        // 3. Update derived state.
        self.leaves = Location::try_from(self.size()).expect("invalid mmb size");
        self.refresh_pinned_nodes();
        self.root = changeset.root;
        Ok(())
    }

    /// Prune all nodes up to but not including the given leaf location, and pin the nodes still
    /// required for root computation and proof generation.
    ///
    /// # Errors
    ///
    /// Returns [Error::LocationOverflow] if `loc` exceeds [crate::merkle::Family::MAX_LOCATION].
    /// Returns [Error::LeafOutOfBounds] if `loc` exceeds the current leaf count.
    pub fn prune(&mut self, loc: Location) -> Result<(), Error> {
        if loc > self.leaves() {
            return Err(Error::LeafOutOfBounds(loc));
        }

        let pos = Position::try_from(loc)?;
        if pos <= self.pruned_to_pos {
            return Ok(());
        }

        self.prune_to_pos(pos);
        Ok(())
    }

    /// Prune all retained nodes.
    pub fn prune_all(&mut self) {
        if !self.nodes.is_empty() {
            self.prune_to_pos(self.size());
        }
    }

    /// Position-based pruning. Assumes `pos` is leaf-aligned.
    fn prune_to_pos(&mut self, pos: Position) {
        self.pinned_nodes = self.collect_pinned_nodes(self.size(), pos);
        let retained_nodes = self.pos_to_index(pos);
        self.nodes.drain(0..retained_nodes);
        self.pruned_to_pos = pos;
    }

    /// Return an inclusion proof for the element at location `loc`.
    ///
    /// # Errors
    ///
    /// Returns [Error::LocationOverflow] if `loc` exceeds the valid range.
    /// Returns [Error::LeafOutOfBounds] if `loc` >= [Self::leaves()].
    /// Returns [Error::ElementPruned] if a required node is missing.
    pub fn proof(
        &self,
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
        loc: Location,
    ) -> Result<Proof<Family, D>, Error> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }

        self.range_proof(hasher, loc..loc + 1).map_err(|e| match e {
            Error::RangeOutOfBounds(_) => Error::LeafOutOfBounds(loc),
            _ => e,
        })
    }

    /// Return an inclusion proof for all elements within the provided `range` of locations.
    ///
    /// # Errors
    ///
    /// Returns [Error::Empty] if the range is empty.
    /// Returns [Error::LocationOverflow] if any location exceeds the valid range.
    /// Returns [Error::RangeOutOfBounds] if `range.end` > [Self::leaves()].
    /// Returns [Error::ElementPruned] if a required node is missing.
    pub fn range_proof(
        &self,
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
        range: Range<Location>,
    ) -> Result<Proof<Family, D>, Error> {
        proof::build_range_proof(hasher, self.leaves, range, |pos| self.get_node(pos))
    }

    /// Get the digests of nodes that need to be pinned at the provided pruning boundary.
    #[cfg(test)]
    fn node_digests_to_pin(&self, prune_pos: Position) -> Vec<D> {
        <Family as crate::merkle::Family>::nodes_to_pin(self.size(), prune_pos)
            .into_iter()
            .map(|pos| *self.get_node_unchecked(pos))
            .collect()
    }
}

impl<D: Digest> crate::merkle::Readable for Mmb<D> {
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
        *self.root()
    }

    fn pruned_to_pos(&self) -> Position {
        self.pruned_to_pos
    }

    fn peak_iterator(&self) -> Self::PeakIterator {
        PeakIterator::new(self.size())
    }

    fn proof(
        &self,
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
        loc: Location,
    ) -> Result<Proof<Family, D>, Error> {
        self.proof(hasher, loc)
    }

    fn range_proof(
        &self,
        hasher: &mut impl Hasher<Family = Family, Digest = D>,
        range: Range<Location>,
    ) -> Result<Proof<Family, D>, Error> {
        self.range_proof(hasher, range)
    }
}

impl<D: Digest> BatchChainInfo<Family> for Mmb<D> {
    type Digest = D;

    fn base_size(&self) -> Position {
        self.size()
    }

    fn collect_overwrites(&self, _into: &mut BTreeMap<Position, D>) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{hasher::Standard, mmb::Family, Readable as _};
    use commonware_cryptography::Sha256;

    type D = <Sha256 as commonware_cryptography::Hasher>::Digest;
    type H = Standard<Family, Sha256>;

    fn build_mmb(n: u64) -> (H, Mmb<D>) {
        let mut hasher = H::new();
        let mut mmb = Mmb::new(&mut hasher);
        let changeset = {
            let mut batch = mmb.new_batch();
            for i in 0..n {
                batch.add(&mut hasher, &i.to_be_bytes());
            }
            batch.merkleize(&mut hasher).finalize()
        };
        mmb.apply(changeset).unwrap();
        (hasher, mmb)
    }

    #[test]
    fn test_empty() {
        let mut hasher = H::new();
        let mmb = Mmb::new(&mut hasher);
        assert_eq!(*mmb.leaves(), 0);
        assert_eq!(*mmb.size(), 0);
        assert!(mmb.bounds().is_empty());
    }

    #[test]
    fn test_append_and_size() {
        let mut hasher = H::new();
        let mut mmb = Mmb::new(&mut hasher);

        for i in 0u64..8 {
            let changeset = {
                let mut batch = mmb.new_batch();
                let loc = batch.add(&mut hasher, &i.to_be_bytes());
                assert_eq!(*loc, i);
                batch.merkleize(&mut hasher).finalize()
            };
            mmb.apply(changeset).unwrap();
        }
        assert_eq!(*mmb.leaves(), 8);
        assert_eq!(*mmb.size(), 13);
    }

    #[test]
    fn test_add_eight_values_structure() {
        let (mut hasher, mmb) = build_mmb(8);

        assert_eq!(mmb.bounds().start, Location::new(0));
        assert_eq!(mmb.size(), Position::new(13));
        assert_eq!(mmb.leaves(), Location::new(8));

        let peaks: Vec<(Position, u32)> = mmb.peak_iterator().collect();
        assert_eq!(
            peaks,
            vec![
                (Position::new(12), 1),
                (Position::new(9), 1),
                (Position::new(7), 2)
            ],
            "MMB peaks not as expected"
        );

        let leaf_positions = [0u64, 1, 3, 4, 6, 8, 10, 11];
        for (i, pos) in leaf_positions.into_iter().enumerate() {
            let expected = hasher.leaf_digest(Position::new(pos), &(i as u64).to_be_bytes());
            assert_eq!(
                mmb.get_node(Position::new(pos)).unwrap(),
                expected,
                "leaf digest mismatch at location {i}"
            );
        }

        let digest2 = hasher.node_digest(
            Position::new(2),
            &mmb.get_node(Position::new(0)).unwrap(),
            &mmb.get_node(Position::new(1)).unwrap(),
        );
        assert_eq!(mmb.get_node(Position::new(2)).unwrap(), digest2);

        let digest5 = hasher.node_digest(
            Position::new(5),
            &mmb.get_node(Position::new(3)).unwrap(),
            &mmb.get_node(Position::new(4)).unwrap(),
        );
        assert_eq!(mmb.get_node(Position::new(5)).unwrap(), digest5);

        let digest7 = hasher.node_digest(Position::new(7), &digest2, &digest5);
        assert_eq!(mmb.get_node(Position::new(7)).unwrap(), digest7);

        let digest9 = hasher.node_digest(
            Position::new(9),
            &mmb.get_node(Position::new(6)).unwrap(),
            &mmb.get_node(Position::new(8)).unwrap(),
        );
        assert_eq!(mmb.get_node(Position::new(9)).unwrap(), digest9);

        let digest12 = hasher.node_digest(
            Position::new(12),
            &mmb.get_node(Position::new(10)).unwrap(),
            &mmb.get_node(Position::new(11)).unwrap(),
        );
        assert_eq!(mmb.get_node(Position::new(12)).unwrap(), digest12);

        let expected_root = hasher.root(Location::new(8), [digest7, digest9, digest12].iter());
        assert_eq!(*mmb.root(), expected_root, "incorrect root");
    }

    #[test]
    fn test_root_changes_with_each_append() {
        let mut hasher = H::new();
        let mut mmb = Mmb::new(&mut hasher);
        let mut prev_root = *mmb.root();
        for i in 0u64..16 {
            let changeset = {
                let mut batch = mmb.new_batch();
                batch.add(&mut hasher, &i.to_be_bytes());
                batch.merkleize(&mut hasher).finalize()
            };
            mmb.apply(changeset).unwrap();
            assert_ne!(
                *mmb.root(),
                prev_root,
                "root should change after append {i}"
            );
            prev_root = *mmb.root();
        }
    }

    #[test]
    fn test_single_element_proof_roundtrip() {
        let (mut hasher, mmb) = build_mmb(16);
        let root = *mmb.root();
        for i in 0u64..16 {
            let proof = mmb
                .proof(&mut hasher, Location::new(i))
                .unwrap_or_else(|e| panic!("loc={i}: {e}"));
            assert!(
                proof.verify_element_inclusion(
                    &mut hasher,
                    &i.to_be_bytes(),
                    Location::new(i),
                    &root
                ),
                "loc={i}: proof should verify"
            );
        }
    }

    #[test]
    fn test_range_proof_roundtrip_exhaustive() {
        for n in 1u64..=24 {
            let (mut hasher, mmb) = build_mmb(n);
            let root = *mmb.root();

            for start in 0..n {
                for end in start + 1..=n {
                    let range = Location::new(start)..Location::new(end);
                    let proof = mmb
                        .range_proof(&mut hasher, range.clone())
                        .unwrap_or_else(|e| panic!("n={n}, range={start}..{end}: {e}"));
                    let elements: Vec<_> = (start..end).map(|i| i.to_be_bytes()).collect();

                    assert!(
                        proof.verify_range_inclusion(&mut hasher, &elements, range.start, &root),
                        "n={n}, range={start}..{end}: range proof should verify"
                    );
                }
            }
        }
    }

    #[test]
    fn test_root_with_repeated_pruning() {
        let (mut hasher, mut mmb) = build_mmb(32);
        let root = *mmb.root();

        for prune_leaf in 1..*mmb.leaves() {
            let prune_loc = Location::new(prune_leaf);
            mmb.prune(prune_loc).unwrap();
            assert_eq!(
                *mmb.root(),
                root,
                "root changed after pruning to {prune_loc}"
            );
            assert_eq!(mmb.bounds().start, prune_loc);
            assert!(
                mmb.proof(&mut hasher, prune_loc).is_ok(),
                "boundary leaf {prune_loc} should remain provable"
            );
            assert!(
                mmb.proof(&mut hasher, mmb.leaves() - 1).is_ok(),
                "latest leaf should remain provable after pruning to {prune_loc}"
            );
        }

        mmb.prune_all();
        assert_eq!(*mmb.root(), root, "root changed after prune_all");
        assert!(mmb.bounds().is_empty(), "prune_all should retain no leaves");
    }

    #[test]
    fn test_prune_and_reinit() {
        let (mut hasher, mut mmb) = build_mmb(24);

        let root = *mmb.root();
        let prune_loc = Location::new(9);
        let prune_pos = Position::try_from(prune_loc).unwrap();
        mmb.prune(prune_loc).unwrap();

        assert_eq!(mmb.bounds().start, prune_loc);
        assert_eq!(*mmb.root(), root);
        assert!(matches!(
            mmb.proof(&mut hasher, Location::new(0)),
            Err(Error::ElementPruned(_))
        ));

        for loc in *prune_loc..*mmb.leaves() {
            assert!(
                mmb.proof(&mut hasher, Location::new(loc)).is_ok(),
                "loc={loc} should remain provable after pruning"
            );
        }

        let mmb_copy = Mmb::init(
            Config {
                nodes: mmb.nodes.iter().copied().collect(),
                pruned_to: prune_loc,
                pinned_nodes: mmb.node_digests_to_pin(prune_pos),
            },
            &mut hasher,
        )
        .unwrap();

        assert_eq!(mmb_copy.size(), mmb.size());
        assert_eq!(mmb_copy.leaves(), mmb.leaves());
        assert_eq!(mmb_copy.bounds(), mmb.bounds());
        assert_eq!(*mmb_copy.root(), root);
        assert!(mmb_copy.proof(&mut hasher, Location::new(17)).is_ok());
    }

    #[test]
    fn test_append_after_partial_prune() {
        let (mut hasher, mut mmb) = build_mmb(20);
        mmb.prune(Location::new(7)).unwrap();

        let changeset = {
            let mut batch = mmb.new_batch();
            for i in 20u64..48 {
                batch.add(&mut hasher, &i.to_be_bytes());
            }
            batch.merkleize(&mut hasher).finalize()
        };
        mmb.apply(changeset).unwrap();

        let root = *mmb.root();
        for loc in *mmb.bounds().start..*mmb.leaves() {
            let proof = mmb
                .proof(&mut hasher, Location::new(loc))
                .unwrap_or_else(|e| panic!("loc={loc}: {e}"));
            assert!(
                proof.verify_element_inclusion(
                    &mut hasher,
                    &loc.to_be_bytes(),
                    Location::new(loc),
                    &root
                ),
                "loc={loc}: proof should verify after append on pruned MMB"
            );
        }
    }

    #[test]
    fn test_validity() {
        let mut hasher = H::new();
        let mut mmb = Mmb::new(&mut hasher);
        for i in 0u64..256 {
            assert!(
                mmb.size().is_valid_size(),
                "size should be valid at step {i}"
            );
            let old_size = mmb.size();
            let changeset = {
                let mut batch = mmb.new_batch();
                batch.add(&mut hasher, &i.to_be_bytes());
                batch.merkleize(&mut hasher).finalize()
            };
            mmb.apply(changeset).unwrap();
            for size in *old_size + 1..*mmb.size() {
                assert!(
                    !Position::new(size).is_valid_size(),
                    "size {size} should not be a valid MMB size"
                );
            }
        }
    }

    #[test]
    fn test_prune_all_does_not_break_append() {
        let mut hasher = H::new();
        let mut mmb = Mmb::new(&mut hasher);

        for i in 0u64..256 {
            mmb.prune_all();
            let changeset = {
                let mut batch = mmb.new_batch();
                let loc = batch.add(&mut hasher, &i.to_be_bytes());
                assert_eq!(loc, Location::new(i));
                batch.merkleize(&mut hasher).finalize()
            };
            mmb.apply(changeset).unwrap();
        }
    }

    #[test]
    fn test_init_pinned_nodes_validation() {
        let mut hasher = H::new();
        assert!(Mmb::<D>::init(
            Config {
                nodes: vec![],
                pruned_to: Location::new(0),
                pinned_nodes: vec![],
            },
            &mut hasher,
        )
        .is_ok());

        assert!(matches!(
            Mmb::<D>::init(
                Config {
                    nodes: vec![],
                    pruned_to: Location::new(8),
                    pinned_nodes: vec![],
                },
                &mut hasher,
            ),
            Err(Error::InvalidPinnedNodes)
        ));

        let err = Mmb::init(
            Config {
                nodes: vec![],
                pruned_to: Location::new(0),
                pinned_nodes: vec![hasher.digest(b"dummy")],
            },
            &mut hasher,
        )
        .err()
        .expect("missing expected init error");
        assert!(matches!(err, Error::InvalidPinnedNodes));

        let (_, mmb) = build_mmb(9);
        let prune_pos = Position::try_from(Location::new(9)).unwrap();
        let pinned_nodes = mmb.node_digests_to_pin(prune_pos);
        assert!(Mmb::init(
            Config {
                nodes: vec![],
                pruned_to: Location::new(9),
                pinned_nodes,
            },
            &mut hasher,
        )
        .is_ok());
    }

    #[test]
    fn test_init_size_validation() {
        let mut hasher = H::new();

        assert!(Mmb::<D>::init(
            Config {
                nodes: vec![],
                pruned_to: Location::new(0),
                pinned_nodes: vec![],
            },
            &mut hasher,
        )
        .is_ok());

        assert!(matches!(
            Mmb::init(
                Config {
                    nodes: vec![hasher.digest(b"node1"), hasher.digest(b"node2")],
                    pruned_to: Location::new(0),
                    pinned_nodes: vec![],
                },
                &mut hasher,
            ),
            Err(Error::InvalidSize(_))
        ));

        assert!(Mmb::init(
            Config {
                nodes: vec![
                    hasher.digest(b"leaf1"),
                    hasher.digest(b"leaf2"),
                    hasher.digest(b"parent"),
                ],
                pruned_to: Location::new(0),
                pinned_nodes: vec![],
            },
            &mut hasher,
        )
        .is_ok());

        let (_, mmb) = build_mmb(64);
        let nodes: Vec<_> = (0..*mmb.size())
            .map(|i| *mmb.get_node_unchecked(Position::new(i)))
            .collect();
        assert!(Mmb::init(
            Config {
                nodes,
                pruned_to: Location::new(0),
                pinned_nodes: vec![],
            },
            &mut hasher,
        )
        .is_ok());

        let (_, mut mmb) = build_mmb(11);
        mmb.prune(Location::new(4)).unwrap();
        let nodes: Vec<_> = (6..*mmb.size())
            .map(|i| *mmb.get_node_unchecked(Position::new(i)))
            .collect();
        let pinned_nodes = mmb.node_digests_to_pin(Position::new(6));

        assert!(Mmb::init(
            Config {
                nodes: nodes.clone(),
                pruned_to: Location::new(4),
                pinned_nodes: pinned_nodes.clone(),
            },
            &mut hasher,
        )
        .is_ok());

        assert!(matches!(
            Mmb::init(
                Config {
                    nodes,
                    pruned_to: Location::new(2),
                    pinned_nodes,
                },
                &mut hasher,
            ),
            Err(Error::InvalidSize(_))
        ));
    }

    #[test]
    fn test_range_proof_out_of_bounds() {
        let mut hasher = H::new();
        let mmb = Mmb::new(&mut hasher);
        assert_eq!(mmb.leaves(), Location::new(0));
        assert!(matches!(
            mmb.range_proof(&mut hasher, Location::new(0)..Location::new(1)),
            Err(Error::RangeOutOfBounds(_))
        ));

        let (_, mmb) = build_mmb(10);
        assert!(matches!(
            mmb.range_proof(&mut hasher, Location::new(5)..Location::new(11)),
            Err(Error::RangeOutOfBounds(_))
        ));
        assert!(mmb
            .range_proof(&mut hasher, Location::new(5)..Location::new(10))
            .is_ok());
    }

    #[test]
    fn test_proof_out_of_bounds() {
        let mut hasher = H::new();
        let mmb = Mmb::new(&mut hasher);
        assert!(matches!(
            mmb.proof(&mut hasher, Location::new(0)),
            Err(Error::LeafOutOfBounds(_))
        ));

        let (_, mmb) = build_mmb(10);
        assert!(matches!(
            mmb.proof(&mut hasher, Location::new(10)),
            Err(Error::LeafOutOfBounds(_))
        ));
        assert!(mmb.proof(&mut hasher, Location::new(9)).is_ok());
    }

    #[test]
    fn test_stale_changeset_sibling() {
        let mut hasher = H::new();
        let mut mmb = Mmb::new(&mut hasher);

        // Create two batches from the same base.
        let changeset_a = {
            let mut batch = mmb.new_batch();
            batch.add(&mut hasher, b"leaf-a");
            batch.merkleize(&mut hasher).finalize()
        };
        let changeset_b = {
            let mut batch = mmb.new_batch();
            batch.add(&mut hasher, b"leaf-b");
            batch.merkleize(&mut hasher).finalize()
        };

        // Apply A -- should succeed.
        mmb.apply(changeset_a).unwrap();

        // Apply B -- should fail (stale).
        let result = mmb.apply(changeset_b);
        assert!(
            matches!(result, Err(Error::StaleChangeset { .. })),
            "expected StaleChangeset, got {result:?}"
        );
    }

    #[test]
    fn test_stale_changeset_chained() {
        let (mut hasher, mut mmb) = build_mmb(1);

        // Parent batch, then fork two children.
        let parent = {
            let mut batch = mmb.new_batch();
            batch.add(&mut hasher, b"leaf-1");
            batch.merkleize(&mut hasher)
        };
        let child_a = {
            let mut batch = parent.new_batch();
            batch.add(&mut hasher, b"leaf-2a");
            batch.merkleize(&mut hasher).finalize()
        };
        let child_b = {
            let mut batch = parent.new_batch();
            batch.add(&mut hasher, b"leaf-2b");
            batch.merkleize(&mut hasher).finalize()
        };

        // Apply child_a, then child_b should be stale.
        mmb.apply(child_a).unwrap();
        let result = mmb.apply(child_b);
        assert!(
            matches!(result, Err(Error::StaleChangeset { .. })),
            "expected StaleChangeset for sibling, got {result:?}"
        );
    }

    #[test]
    fn test_stale_changeset_parent_before_child() {
        let mut hasher = H::new();
        let mut mmb = Mmb::new(&mut hasher);

        // Create parent, then child.
        let parent = {
            let mut batch = mmb.new_batch();
            batch.add(&mut hasher, b"leaf-0");
            batch.merkleize(&mut hasher)
        };
        let child = {
            let mut batch = parent.new_batch();
            batch.add(&mut hasher, b"leaf-1");
            batch.merkleize(&mut hasher).finalize()
        };
        let parent = parent.finalize();

        // Apply parent first -- child should now be stale.
        mmb.apply(parent).unwrap();
        let result = mmb.apply(child);
        assert!(
            matches!(result, Err(Error::StaleChangeset { .. })),
            "expected StaleChangeset for child after parent applied, got {result:?}"
        );
    }

    #[test]
    fn test_stale_changeset_child_before_parent() {
        let mut hasher = H::new();
        let mut mmb = Mmb::new(&mut hasher);

        // Create parent, then child.
        let parent = {
            let mut batch = mmb.new_batch();
            batch.add(&mut hasher, b"leaf-0");
            batch.merkleize(&mut hasher)
        };
        let child = {
            let mut batch = parent.new_batch();
            batch.add(&mut hasher, b"leaf-1");
            batch.merkleize(&mut hasher).finalize()
        };
        let parent = parent.finalize();

        // Apply child first -- parent should now be stale.
        mmb.apply(child).unwrap();
        let result = mmb.apply(parent);
        assert!(
            matches!(result, Err(Error::StaleChangeset { .. })),
            "expected StaleChangeset for parent after child applied, got {result:?}"
        );
    }

    #[test]
    fn test_update_leaf() {
        let (mut hasher, mut mmb) = build_mmb(11);
        let root_before = *mmb.root();

        // Update leaf 5 with new data.
        let changeset = {
            let mut batch = mmb.new_batch();
            batch
                .update_leaf(&mut hasher, Location::new(5), b"updated-5")
                .unwrap();
            batch.merkleize(&mut hasher).finalize()
        };
        mmb.apply(changeset).unwrap();

        // Root should change.
        assert_ne!(*mmb.root(), root_before, "root should change after update");

        // Size and leaves should not change.
        assert_eq!(*mmb.leaves(), 11);

        // The updated leaf should be provable with the new data.
        let proof = mmb.proof(&mut hasher, Location::new(5)).unwrap();
        assert!(
            proof.verify_element_inclusion(&mut hasher, b"updated-5", Location::new(5), mmb.root()),
            "updated leaf should verify with new data"
        );

        // The old data should no longer verify.
        assert!(
            !proof.verify_element_inclusion(
                &mut hasher,
                &5u64.to_be_bytes(),
                Location::new(5),
                mmb.root()
            ),
            "old data should not verify"
        );

        // Other leaves should still verify with their original data.
        for i in [0u64, 3, 7, 10] {
            let p = mmb.proof(&mut hasher, Location::new(i)).unwrap();
            assert!(
                p.verify_element_inclusion(
                    &mut hasher,
                    &i.to_be_bytes(),
                    Location::new(i),
                    mmb.root()
                ),
                "leaf {i} should still verify with original data"
            );
        }
    }

    #[test]
    fn test_update_leaf_every_position() {
        // Update each leaf one at a time and verify the entire tree after each update.
        let n = 20u64;
        let (mut hasher, mut mmb) = build_mmb(n);

        for update_loc in 0..n {
            let changeset = {
                let mut batch = mmb.new_batch();
                batch
                    .update_leaf(&mut hasher, Location::new(update_loc), b"new-value")
                    .unwrap();
                batch.merkleize(&mut hasher).finalize()
            };
            mmb.apply(changeset).unwrap();

            // The updated leaf should verify.
            let proof = mmb.proof(&mut hasher, Location::new(update_loc)).unwrap();
            assert!(
                proof.verify_element_inclusion(
                    &mut hasher,
                    b"new-value",
                    Location::new(update_loc),
                    mmb.root()
                ),
                "update at {update_loc} should verify"
            );
        }
    }

    #[test]
    fn test_update_leaf_errors() {
        let (mut hasher, mut mmb) = build_mmb(10);

        // Out of bounds.
        {
            let mut batch = mmb.new_batch();
            assert!(matches!(
                batch.update_leaf(&mut hasher, Location::new(10), b"x"),
                Err(Error::LeafOutOfBounds(_))
            ));
        }

        // Pruned leaf.
        mmb.prune(Location::new(5)).unwrap();
        {
            let mut batch = mmb.new_batch();
            assert!(matches!(
                batch.update_leaf(&mut hasher, Location::new(3), b"x"),
                Err(Error::ElementPruned(_))
            ));
            // Boundary leaf should succeed.
            assert!(batch
                .update_leaf(&mut hasher, Location::new(5), b"x")
                .is_ok());
        }
    }

    #[test]
    fn test_update_leaf_with_append() {
        let (mut hasher, mut mmb) = build_mmb(8);

        // Update an existing leaf and append new ones in the same batch.
        let changeset = {
            let mut batch = mmb.new_batch();
            batch
                .update_leaf(&mut hasher, Location::new(3), b"updated-3")
                .unwrap();
            batch.add(&mut hasher, &100u64.to_be_bytes());
            batch.add(&mut hasher, &101u64.to_be_bytes());
            batch.merkleize(&mut hasher).finalize()
        };
        mmb.apply(changeset).unwrap();

        assert_eq!(*mmb.leaves(), 10);

        // Updated leaf verifies.
        let proof = mmb.proof(&mut hasher, Location::new(3)).unwrap();
        assert!(proof.verify_element_inclusion(
            &mut hasher,
            b"updated-3",
            Location::new(3),
            mmb.root()
        ));

        // New leaves verify.
        let proof = mmb.proof(&mut hasher, Location::new(8)).unwrap();
        assert!(proof.verify_element_inclusion(
            &mut hasher,
            &100u64.to_be_bytes(),
            Location::new(8),
            mmb.root()
        ));
    }

    /// Batch root differs from base, proofs work on batch, base unchanged.
    #[test]
    fn test_batch_lifecycle() {
        let (mut hasher, mmb) = build_mmb(50);
        let base_root = *mmb.root();

        let mut batch = mmb.new_batch();
        for i in 50u64..60 {
            batch.add(&mut hasher, &i.to_be_bytes());
        }
        let merkleized = batch.merkleize(&mut hasher);

        assert_ne!(merkleized.root(), base_root);

        // Proof from merkleized batch should work.
        let proof = merkleized.proof(&mut hasher, Location::new(55)).unwrap();
        assert!(proof.verify_element_inclusion(
            &mut hasher,
            &55u64.to_be_bytes(),
            Location::new(55),
            &merkleized.root(),
        ));

        // Base should be unchanged.
        assert_eq!(*mmb.root(), base_root);
    }

    /// Two batches on same base with different mutations have independent roots.
    #[test]
    fn test_multiple_forks() {
        let (mut hasher, mmb) = build_mmb(50);
        let base_root = *mmb.root();

        let mut batch_a = mmb.new_batch();
        for i in 50u64..60 {
            batch_a.add(&mut hasher, &i.to_be_bytes());
        }
        let merkleized_a = batch_a.merkleize(&mut hasher);

        let mut batch_b = mmb.new_batch();
        for i in 100u64..105 {
            batch_b.add(&mut hasher, &i.to_be_bytes());
        }
        let merkleized_b = batch_b.merkleize(&mut hasher);

        assert_ne!(merkleized_a.root(), merkleized_b.root());
        assert_ne!(merkleized_a.root(), base_root);
        assert_ne!(merkleized_b.root(), base_root);
        assert_eq!(*mmb.root(), base_root);
    }

    /// Base <- A <- B. Proofs from B resolve through all layers.
    #[test]
    fn test_fork_of_fork_reads() {
        let (mut hasher, mmb) = build_mmb(50);

        let mut batch_a = mmb.new_batch();
        for i in 50u64..60 {
            batch_a.add(&mut hasher, &i.to_be_bytes());
        }
        let merkleized_a = batch_a.merkleize(&mut hasher);

        let mut batch_b = merkleized_a.new_batch();
        for i in 60u64..70 {
            batch_b.add(&mut hasher, &i.to_be_bytes());
        }
        let merkleized_b = batch_b.merkleize(&mut hasher);

        // B should match building 70 elements directly.
        let (_, ref_mmb) = build_mmb(70);
        assert_eq!(merkleized_b.root(), *ref_mmb.root());

        // Proofs from B should verify.
        for i in [0u64, 25, 55, 65, 69] {
            let proof = merkleized_b.proof(&mut hasher, Location::new(i)).unwrap();
            assert!(
                proof.verify_element_inclusion(
                    &mut hasher,
                    &i.to_be_bytes(),
                    Location::new(i),
                    &merkleized_b.root(),
                ),
                "proof failed for element {i}"
            );
        }
    }

    /// Base <- A <- B. B.finalize() captures both A and B changes.
    #[test]
    fn test_fork_of_fork_flattened_changeset() {
        let (mut hasher, mut mmb) = build_mmb(50);

        let mut batch_a = mmb.new_batch();
        for i in 50u64..60 {
            batch_a.add(&mut hasher, &i.to_be_bytes());
        }
        let merkleized_a = batch_a.merkleize(&mut hasher);

        let mut batch_b = merkleized_a.new_batch();
        for i in 60u64..70 {
            batch_b.add(&mut hasher, &i.to_be_bytes());
        }
        let merkleized_b = batch_b.merkleize(&mut hasher);
        let b_root = merkleized_b.root();

        let changeset = merkleized_b.finalize();
        drop(merkleized_a);
        mmb.apply(changeset).unwrap();

        assert_eq!(*mmb.root(), b_root);

        let (_, ref_mmb) = build_mmb(70);
        assert_eq!(mmb.root(), ref_mmb.root());
    }

    /// Merkleize a no-op batch. Same root as parent.
    #[test]
    fn test_empty_batch() {
        let (mut hasher, mmb) = build_mmb(50);
        let base_root = *mmb.root();

        let batch = mmb.new_batch();
        let merkleized = batch.merkleize(&mut hasher);

        assert_eq!(merkleized.root(), base_root);

        for loc in [0u64, 10, 49] {
            let base_proof = mmb.proof(&mut hasher, Location::new(loc)).unwrap();
            let batch_proof = merkleized.proof(&mut hasher, Location::new(loc)).unwrap();
            assert_eq!(base_proof, batch_proof, "proof mismatch at loc {loc}");
        }
    }

    /// MerkleizedBatch -> into_dirty -> more mutations -> merkleize -> verify.
    #[test]
    fn test_into_dirty_roundtrip() {
        let (mut hasher, mmb) = build_mmb(50);

        let mut batch = mmb.new_batch();
        for i in 50u64..55 {
            batch.add(&mut hasher, &i.to_be_bytes());
        }
        let merkleized = batch.merkleize(&mut hasher);

        let mut dirty_again = merkleized.into_dirty();
        for i in 55u64..60 {
            dirty_again.add(&mut hasher, &i.to_be_bytes());
        }
        let merkleized_again = dirty_again.merkleize(&mut hasher);

        let (_, ref_mmb) = build_mmb(60);
        assert_eq!(merkleized_again.root(), *ref_mmb.root());
    }

    /// Apply changeset 1. Create new batch on updated base, apply changeset 2.
    #[test]
    fn test_sequential_changesets() {
        let (mut hasher, mut mmb) = build_mmb(50);

        let cs1 = {
            let mut batch = mmb.new_batch();
            for i in 50u64..60 {
                batch.add(&mut hasher, &i.to_be_bytes());
            }
            batch.merkleize(&mut hasher).finalize()
        };
        mmb.apply(cs1).unwrap();

        let cs2 = {
            let mut batch = mmb.new_batch();
            for i in 60u64..70 {
                batch.add(&mut hasher, &i.to_be_bytes());
            }
            batch.merkleize(&mut hasher).finalize()
        };
        mmb.apply(cs2).unwrap();

        let (_, ref_mmb) = build_mmb(70);
        assert_eq!(mmb.root(), ref_mmb.root());
    }

    /// Batch on a pruned base. Proofs for retained elements work.
    #[test]
    fn test_batch_on_pruned_base() {
        let (mut hasher, mut mmb) = build_mmb(100);
        mmb.prune(Location::new(27)).unwrap();

        let changeset = {
            let mut batch = mmb.new_batch();
            for i in 100u64..110 {
                batch.add(&mut hasher, &i.to_be_bytes());
            }
            batch.merkleize(&mut hasher).finalize()
        };
        mmb.apply(changeset).unwrap();

        // Proof for retained element should work.
        let proof = mmb.proof(&mut hasher, Location::new(80)).unwrap();
        assert!(proof.verify_element_inclusion(
            &mut hasher,
            &80u64.to_be_bytes(),
            Location::new(80),
            mmb.root()
        ));

        // Proof for pruned element should fail.
        assert!(matches!(
            mmb.proof(&mut hasher, Location::new(0)),
            Err(Error::ElementPruned(_))
        ));
    }

    /// Single-element and range proofs from MerkleizedBatch verify.
    #[test]
    fn test_batch_proof_verification() {
        let (mut hasher, mmb) = build_mmb(50);

        let mut batch = mmb.new_batch();
        for i in 50u64..60 {
            batch.add(&mut hasher, &i.to_be_bytes());
        }
        let merkleized = batch.merkleize(&mut hasher);

        // Single element proof.
        let proof = merkleized.proof(&mut hasher, Location::new(55)).unwrap();
        assert!(proof.verify_element_inclusion(
            &mut hasher,
            &55u64.to_be_bytes(),
            Location::new(55),
            &merkleized.root(),
        ));

        // Range proof.
        let range = Location::new(50)..Location::new(55);
        let range_proof = merkleized.range_proof(&mut hasher, range.clone()).unwrap();
        let elements: Vec<_> = (50u64..55).map(|i| i.to_be_bytes()).collect();
        let element_refs: Vec<&[u8]> = elements.iter().map(|e| e.as_slice()).collect();
        assert!(range_proof.verify_range_inclusion(
            &mut hasher,
            &element_refs,
            range.start,
            &merkleized.root(),
        ));
    }

    /// Base <- A (overwrite leaf 5) <- B (adds). B's changeset includes A's overwrite.
    #[test]
    fn test_flattened_changeset_preserves_overwrites() {
        let (mut hasher, mut mmb) = build_mmb(100);

        // Layer A: overwrite leaf 5.
        let mut batch_a = mmb.new_batch();
        batch_a
            .update_leaf(&mut hasher, Location::new(5), b"overwritten")
            .unwrap();
        let merkleized_a = batch_a.merkleize(&mut hasher);

        // Layer B on A: add leaves.
        let mut batch_b = merkleized_a.new_batch();
        for i in 100u64..105 {
            batch_b.add(&mut hasher, &i.to_be_bytes());
        }
        let merkleized_b = batch_b.merkleize(&mut hasher);
        let b_root = merkleized_b.root();

        let changeset = merkleized_b.finalize();
        drop(merkleized_a);
        mmb.apply(changeset).unwrap();

        assert_eq!(*mmb.root(), b_root);

        // Verify leaf 5 has the updated data.
        let proof = mmb.proof(&mut hasher, Location::new(5)).unwrap();
        assert!(proof.verify_element_inclusion(
            &mut hasher,
            b"overwritten",
            Location::new(5),
            mmb.root()
        ));
    }

    /// Base <- A (overwrite 5) <- B (overwrite 10) <- C (add 10). Flatten and verify.
    #[test]
    fn test_three_deep_stacking() {
        let (mut hasher, mut mmb) = build_mmb(100);

        // Layer A: overwrite leaf 5.
        let mut batch_a = mmb.new_batch();
        batch_a
            .update_leaf(&mut hasher, Location::new(5), b"val-a")
            .unwrap();
        let merkleized_a = batch_a.merkleize(&mut hasher);

        // Layer B on A: overwrite leaf 10.
        let mut batch_b = merkleized_a.new_batch();
        batch_b
            .update_leaf(&mut hasher, Location::new(10), b"val-b")
            .unwrap();
        let merkleized_b = batch_b.merkleize(&mut hasher);

        // Layer C on B: add 10 leaves.
        let mut batch_c = merkleized_b.new_batch();
        for i in 300u64..310 {
            batch_c.add(&mut hasher, &i.to_be_bytes());
        }
        let merkleized_c = batch_c.merkleize(&mut hasher);
        let c_root = merkleized_c.root();

        let changeset = merkleized_c.finalize();
        drop(merkleized_b);
        drop(merkleized_a);
        mmb.apply(changeset).unwrap();

        assert_eq!(*mmb.root(), c_root);

        // Build the equivalent directly.
        let (mut ref_hasher, mut ref_mmb) = build_mmb(100);
        let changeset = {
            let mut batch = ref_mmb.new_batch();
            batch
                .update_leaf(&mut ref_hasher, Location::new(5), b"val-a")
                .unwrap();
            batch
                .update_leaf(&mut ref_hasher, Location::new(10), b"val-b")
                .unwrap();
            for i in 300u64..310 {
                batch.add(&mut ref_hasher, &i.to_be_bytes());
            }
            batch.merkleize(&mut ref_hasher).finalize()
        };
        ref_mmb.apply(changeset).unwrap();
        assert_eq!(mmb.root(), ref_mmb.root());
    }

    /// A overwrites leaf 5 with X, B overwrites leaf 5 with Y. Last writer wins.
    #[test]
    fn test_overwrite_collision_in_stack() {
        let (mut hasher, mut mmb) = build_mmb(100);

        let mut batch_a = mmb.new_batch();
        batch_a
            .update_leaf(&mut hasher, Location::new(5), b"val-x")
            .unwrap();
        let merkleized_a = batch_a.merkleize(&mut hasher);

        let mut batch_b = merkleized_a.new_batch();
        batch_b
            .update_leaf(&mut hasher, Location::new(5), b"val-y")
            .unwrap();
        let merkleized_b = batch_b.merkleize(&mut hasher);
        let b_root = merkleized_b.root();

        let changeset = merkleized_b.finalize();
        drop(merkleized_a);
        mmb.apply(changeset).unwrap();

        assert_eq!(*mmb.root(), b_root);

        // Verify leaf 5 has Y, not X.
        let proof = mmb.proof(&mut hasher, Location::new(5)).unwrap();
        assert!(proof.verify_element_inclusion(
            &mut hasher,
            b"val-y",
            Location::new(5),
            mmb.root()
        ));
    }

    /// Add leaves in a batch, then update one of those new leaves.
    #[test]
    fn test_update_appended_leaf() {
        let (mut hasher, mmb) = build_mmb(50);

        let mut batch = mmb.new_batch();
        for i in 50u64..60 {
            batch.add(&mut hasher, &i.to_be_bytes());
        }
        batch
            .update_leaf(&mut hasher, Location::new(52), b"updated-52")
            .unwrap();
        let merkleized = batch.merkleize(&mut hasher);

        // Verify the updated leaf.
        let proof = merkleized.proof(&mut hasher, Location::new(52)).unwrap();
        assert!(proof.verify_element_inclusion(
            &mut hasher,
            b"updated-52",
            Location::new(52),
            &merkleized.root(),
        ));

        // Build reference the same way.
        let (mut ref_hasher, mut ref_mmb) = build_mmb(60);
        let changeset = {
            let mut batch = ref_mmb.new_batch();
            batch
                .update_leaf(&mut ref_hasher, Location::new(52), b"updated-52")
                .unwrap();
            batch.merkleize(&mut ref_hasher).finalize()
        };
        ref_mmb.apply(changeset).unwrap();
        assert_eq!(merkleized.root(), *ref_mmb.root());
    }

    /// Regression: add then update_leaf in the same batch where the updated leaf falls within the
    /// merge parent's subtree.
    #[test]
    fn test_update_leaf_under_merge_parent() {
        // Start with 2 leaves so the next add triggers a merge of the two height-0 peaks.
        // After adding leaf 2, the merge creates a height-1 parent. Then we update leaf 0,
        // which is a child of that merge parent.
        let (mut hasher, mut mmb) = build_mmb(2);
        let changeset = {
            let mut batch = mmb.new_batch();
            batch.add(&mut hasher, &2u64.to_be_bytes());
            batch
                .update_leaf(&mut hasher, Location::new(0), b"updated-0")
                .unwrap();
            batch.merkleize(&mut hasher).finalize()
        };
        mmb.apply(changeset).unwrap();

        // Build a reference MMB with the same operations applied separately.
        let (mut ref_hasher, mut ref_mmb) = build_mmb(2);
        let cs = {
            let mut batch = ref_mmb.new_batch();
            batch.add(&mut ref_hasher, &2u64.to_be_bytes());
            batch.merkleize(&mut ref_hasher).finalize()
        };
        ref_mmb.apply(cs).unwrap();
        let cs = {
            let mut batch = ref_mmb.new_batch();
            batch
                .update_leaf(&mut ref_hasher, Location::new(0), b"updated-0")
                .unwrap();
            batch.merkleize(&mut ref_hasher).finalize()
        };
        ref_mmb.apply(cs).unwrap();

        assert_eq!(*mmb.root(), *ref_mmb.root(), "roots must match");

        // Updated leaf should verify.
        let proof = mmb.proof(&mut hasher, Location::new(0)).unwrap();
        assert!(
            proof.verify_element_inclusion(&mut hasher, b"updated-0", Location::new(0), mmb.root()),
            "updated leaf should verify"
        );
    }
}

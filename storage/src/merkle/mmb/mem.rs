//! A basic, no_std compatible MMB where all nodes are stored in-memory.

use crate::merkle::{
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

/// Find the rightmost pair of adjacent same-height peaks. Returns the index of the left element
/// in the pair, or `None` if no such pair exists.
pub(super) fn find_merge_pair(peaks: &[(Position, u32)]) -> Option<usize> {
    (0..peaks.len().saturating_sub(1))
        .rev()
        .find(|&i| peaks[i].1 == peaks[i + 1].1)
}

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

        for digest in changeset.appended {
            self.nodes.push_back(digest);
        }

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
            Error::RangeOutOfBounds(loc) => Error::LeafOutOfBounds(loc),
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

impl<D: Digest> super::batch::Readable for Mmb<D> {
    type Digest = D;

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
}

impl<D: Digest> super::batch::BatchChainInfo for Mmb<D> {
    type Digest = D;

    fn base_size(&self) -> Position {
        self.size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{hasher::Standard, mmb::Family};
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
}

//! A basic, no_std compatible MMR where all nodes are stored in-memory.

/// A basic MMR where all nodes are stored in-memory.
pub type Mmr<D> = crate::merkle::mem::Mem<super::Family, D>;

/// Configuration for initializing an [Mmr].
pub type Config<D> = crate::merkle::mem::Config<super::Family, D>;

#[cfg(any(feature = "std", test))]
use super::{Family, Position};
#[cfg(any(feature = "std", test))]
use alloc::collections::BTreeMap;

#[cfg(any(feature = "std", test))]
impl<D: commonware_cryptography::Digest> Mmr<D> {
    /// Pin extra nodes. It's up to the caller to ensure this set is valid.
    #[cfg(any(feature = "std", test))]
    pub(crate) fn add_pinned_nodes(&mut self, pinned_nodes: BTreeMap<Position, D>) {
        for (pos, node) in pinned_nodes.into_iter() {
            self.pinned_nodes.insert(pos, node);
        }
    }

    /// Truncate the MMR to a smaller valid size, discarding all nodes beyond that size.
    /// Recomputes the root after truncation.
    ///
    /// `new_size` must be a valid MMR size (i.e., `new_size.is_valid_size()`) and must be
    /// >= `pruned_to_pos`.
    #[cfg(feature = "std")]
    pub(crate) fn truncate(
        &mut self,
        new_size: Position,
        hasher: &mut impl crate::merkle::hasher::Hasher<Family, Digest = D>,
    ) {
        debug_assert!(new_size.is_valid_size());
        debug_assert!(new_size >= self.pruned_to_pos);
        let keep = (*new_size - *self.pruned_to_pos) as usize;
        self.nodes.truncate(keep);
        self.root = Self::compute_root(hasher, &self.nodes, &self.pinned_nodes, self.pruned_to_pos);
    }

    /// Return the nodes this MMR currently has pinned.
    #[cfg(test)]
    pub(super) fn pinned_nodes(&self) -> BTreeMap<Position, D> {
        self.pinned_nodes.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::hasher::Hasher as _,
        mmr::{conformance::build_test_mmr, Error, Location, StandardHasher as Standard},
    };
    use commonware_cryptography::{sha256, Hasher, Sha256};
    use commonware_runtime::{deterministic, tokio, Runner, ThreadPooler};
    use commonware_utils::NZUsize;

    /// Test MMR building by consecutively adding 11 equal elements to a new MMR, producing the
    /// structure in the example documented at the top of the mmr crate's mod.rs file with 19 nodes
    /// and 3 peaks.
    #[test]
    fn test_mem_mmr_add_eleven_values() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::new(&mut hasher);
            let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
            let mut leaves: Vec<Location> = Vec::new();
            for _ in 0..11 {
                let changeset = {
                    let mut batch = mmr.new_batch();
                    leaves.push(batch.leaves());
                    batch = batch.add(&mut hasher, &element);
                    batch.merkleize(&mut hasher).finalize()
                };
                mmr.apply(changeset).unwrap();
                let peaks: Vec<(Position, u32)> = mmr.peak_iterator().collect();
                assert_ne!(peaks.len(), 0);
                assert!(peaks.len() as u64 <= mmr.size());
            }
            assert_eq!(mmr.bounds().start, Location::new(0));
            assert_eq!(mmr.size(), 19, "mmr not of expected size");
            assert_eq!(
                leaves,
                (0..11).map(Location::new).collect::<Vec<_>>(),
                "mmr leaf locations not as expected"
            );
            let peaks: Vec<(Position, u32)> = mmr.peak_iterator().collect();
            assert_eq!(
                peaks,
                vec![
                    (Position::new(14), 3),
                    (Position::new(17), 1),
                    (Position::new(18), 0)
                ],
                "mmr peaks not as expected"
            );

            // Test append_parents on the final MMR. Since there's a height gap between the
            // highest peak (14) and the next, only the lower two peaks (17, 18) would merge,
            // producing 2 parents at heights 1 and 2.
            let parent_heights: Vec<u32> =
                crate::merkle::Family::append_parents(mmr.size()).collect();
            assert_eq!(parent_heights, vec![1, 2], "append_parents not as expected");

            // verify leaf digests
            for leaf in leaves.iter().by_ref() {
                let pos = Position::try_from(*leaf).unwrap();
                let digest = hasher.leaf_digest(pos, &element);
                assert_eq!(mmr.get_node(pos).unwrap(), digest);
            }

            // verify height=1 node digests
            let digest2 = hasher.node_digest(Position::new(2), &mmr.nodes[0], &mmr.nodes[1]);
            assert_eq!(mmr.nodes[2], digest2);
            let digest5 = hasher.node_digest(Position::new(5), &mmr.nodes[3], &mmr.nodes[4]);
            assert_eq!(mmr.nodes[5], digest5);
            let digest9 = hasher.node_digest(Position::new(9), &mmr.nodes[7], &mmr.nodes[8]);
            assert_eq!(mmr.nodes[9], digest9);
            let digest12 = hasher.node_digest(Position::new(12), &mmr.nodes[10], &mmr.nodes[11]);
            assert_eq!(mmr.nodes[12], digest12);
            let digest17 = hasher.node_digest(Position::new(17), &mmr.nodes[15], &mmr.nodes[16]);
            assert_eq!(mmr.nodes[17], digest17);

            // verify height=2 node digests
            let digest6 = hasher.node_digest(Position::new(6), &mmr.nodes[2], &mmr.nodes[5]);
            assert_eq!(mmr.nodes[6], digest6);
            let digest13 = hasher.node_digest(Position::new(13), &mmr.nodes[9], &mmr.nodes[12]);
            assert_eq!(mmr.nodes[13], digest13);
            let digest17 = hasher.node_digest(Position::new(17), &mmr.nodes[15], &mmr.nodes[16]);
            assert_eq!(mmr.nodes[17], digest17);

            // verify topmost digest
            let digest14 = hasher.node_digest(Position::new(14), &mmr.nodes[6], &mmr.nodes[13]);
            assert_eq!(mmr.nodes[14], digest14);

            // verify root
            let root = *mmr.root();
            let peak_digests = [digest14, digest17, mmr.nodes[18]];
            let expected_root = hasher.root(Location::new(11), peak_digests.iter());
            assert_eq!(root, expected_root, "incorrect root");

            // pruning tests
            mmr.prune(Location::new(8)).unwrap(); // prune up to the tallest peak
            assert_eq!(mmr.bounds().start, Location::new(8));

            // After pruning, we shouldn't be able to generate a proof for any elements before the
            // pruning boundary. (To be precise, due to the maintenance of pinned nodes, we may in
            // fact still be able to generate them for some, but it's not guaranteed. For example,
            // in this case, we actually can still generate a proof for the node with location 7
            // even though it's pruned.)
            assert!(matches!(
                mmr.proof(&mut hasher, Location::new(0)),
                Err(Error::ElementPruned(_))
            ));
            assert!(matches!(
                mmr.proof(&mut hasher, Location::new(6)),
                Err(Error::ElementPruned(_))
            ));

            // We should still be able to generate a proof for any leaf following the pruning
            // boundary, the first of which is at location 8 and the last location 10.
            assert!(mmr.proof(&mut hasher, Location::new(8)).is_ok());
            assert!(mmr.proof(&mut hasher, Location::new(10)).is_ok());

            let root_after_prune = *mmr.root();
            assert_eq!(root, root_after_prune, "root changed after pruning");

            assert!(
                mmr.range_proof(&mut hasher, Location::new(5)..Location::new(9))
                    .is_err(),
                "attempts to range_prove elements at or before the oldest retained should fail"
            );
            assert!(
                mmr.range_proof(&mut hasher, Location::new(8)..mmr.leaves())
                    .is_ok(),
                "attempts to range_prove over all elements following oldest retained should succeed"
            );

            // Test that we can initialize a new MMR from another's elements.
            let oldest_loc = mmr.bounds().start;
            let oldest_pos = Position::try_from(oldest_loc).unwrap();
            let digests = mmr.node_digests_to_pin(oldest_pos);
            let mmr_copy = Mmr::init(
                Config {
                    nodes: mmr.nodes.iter().copied().collect(),
                    pruned_to: oldest_loc,
                    pinned_nodes: digests,
                },
                &mut hasher,
            )
            .unwrap();
            assert_eq!(mmr_copy.size(), 19);
            assert_eq!(mmr_copy.leaves(), mmr.leaves());
            assert_eq!(mmr_copy.bounds().start, mmr.bounds().start);
            assert_eq!(*mmr_copy.root(), root);
        });
    }

    /// Test that batched MMR building produces the same root as the reference implementation.
    /// Root stability for the reference implementation is verified by the conformance test.
    #[test]
    fn test_mem_mmr_batched_root() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            const NUM_ELEMENTS: u64 = 199;
            let mut test_mmr = Mmr::new(&mut hasher);
            test_mmr = build_test_mmr(&mut hasher, test_mmr, NUM_ELEMENTS);
            let expected_root = test_mmr.root();

            let mut batched_mmr = Mmr::new(&mut hasher);

            // Add all elements in one batch
            let changeset = {
                let mut batch = batched_mmr.new_batch();
                for i in 0..NUM_ELEMENTS {
                    let element = hasher.digest(&i.to_be_bytes());
                    batch = batch.add(&mut hasher, &element);
                }
                batch.merkleize(&mut hasher).finalize()
            };
            batched_mmr.apply(changeset).unwrap();

            assert_eq!(
                batched_mmr.root(),
                expected_root,
                "Batched MMR root should match reference"
            );
        });
    }

    /// Test that parallel batched MMR building produces the same root as the reference.
    /// This requires the tokio runtime since the deterministic runtime is single-threaded.
    #[test]
    fn test_mem_mmr_batched_root_parallel() {
        let executor = tokio::Runner::default();
        executor.start(|context| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            const NUM_ELEMENTS: u64 = 199;
            let test_mmr = Mmr::new(&mut hasher);
            let test_mmr = build_test_mmr(&mut hasher, test_mmr, NUM_ELEMENTS);
            let expected_root = test_mmr.root();

            let pool = context.create_thread_pool(NZUsize!(4)).unwrap();
            let mut hasher: Standard<Sha256> = Standard::new();

            let mut mmr = Mmr::init(
                Config {
                    nodes: vec![],
                    pruned_to: Location::new(0),
                    pinned_nodes: vec![],
                },
                &mut hasher,
            )
            .unwrap();

            let changeset = {
                let mut batch = mmr.new_batch().with_pool(Some(pool));
                for i in 0u64..NUM_ELEMENTS {
                    let element = hasher.digest(&i.to_be_bytes());
                    batch = batch.add(&mut hasher, &element);
                }
                batch.merkleize(&mut hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            assert_eq!(
                mmr.root(),
                expected_root,
                "Batched MMR root should match reference"
            );
        });
    }

    #[test]
    fn test_init_size_validation() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            assert!(Mmr::init(
                Config::<sha256::Digest> {
                    nodes: vec![],
                    pruned_to: Location::new(0),
                    pinned_nodes: vec![],
                },
                &mut hasher,
            )
            .is_ok());

            assert!(matches!(
                Mmr::init(
                    Config {
                        nodes: vec![Sha256::hash(b"node1"), Sha256::hash(b"node2")],
                        pruned_to: Location::new(0),
                        pinned_nodes: vec![],
                    },
                    &mut hasher,
                ),
                Err(Error::InvalidSize(_))
            ));

            assert!(Mmr::init(
                Config {
                    nodes: vec![
                        Sha256::hash(b"leaf1"),
                        Sha256::hash(b"leaf2"),
                        Sha256::hash(b"parent"),
                    ],
                    pruned_to: Location::new(0),
                    pinned_nodes: vec![],
                },
                &mut hasher,
            )
            .is_ok());

            let mut mmr = Mmr::new(&mut hasher);
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0u64..64 {
                    batch = batch.add(&mut hasher, &i.to_be_bytes());
                }
                batch.merkleize(&mut hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            assert_eq!(mmr.size(), 127);
            let nodes: Vec<_> = (0..127)
                .map(|i| *mmr.get_node_unchecked(Position::new(i)))
                .collect();
            assert!(Mmr::init(
                Config {
                    nodes,
                    pruned_to: Location::new(0),
                    pinned_nodes: vec![],
                },
                &mut hasher,
            )
            .is_ok());

            let mut mmr = Mmr::new(&mut hasher);
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0u64..11 {
                    batch = batch.add(&mut hasher, &i.to_be_bytes());
                }
                batch.merkleize(&mut hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            mmr.prune(Location::new(4)).unwrap();
            let nodes: Vec<_> = (7..*mmr.size())
                .map(|i| *mmr.get_node_unchecked(Position::new(i)))
                .collect();
            let pinned_nodes = mmr.node_digests_to_pin(Position::new(7));
            assert!(Mmr::init(
                Config {
                    nodes: nodes.clone(),
                    pruned_to: Location::new(4),
                    pinned_nodes: pinned_nodes.clone(),
                },
                &mut hasher,
            )
            .is_ok());

            assert!(matches!(
                Mmr::init(
                    Config {
                        nodes,
                        pruned_to: Location::new(5),
                        pinned_nodes,
                    },
                    &mut hasher,
                ),
                Err(Error::InvalidSize(_))
            ));
        });
    }
}

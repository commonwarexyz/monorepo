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
        mmr::{
            conformance::build_test_mmr, iterator::nodes_needing_parents, Error, Location,
            StandardHasher as Standard,
        },
    };
    use commonware_cryptography::{sha256, Hasher, Sha256};
    use commonware_parallel::ThreadPool;
    use commonware_runtime::{deterministic, tokio, Runner, ThreadPooler};
    use commonware_utils::NZUsize;

    /// Test empty MMR behavior.
    #[test]
    fn test_mem_mmr_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mmr = Mmr::new(&mut hasher);
            assert_eq!(
                mmr.peak_iterator().next(),
                None,
                "empty iterator should have no peaks"
            );
            assert_eq!(mmr.size(), 0);
            assert_eq!(mmr.leaves(), Location::new(0));
            assert!(mmr.bounds().is_empty());
            assert_eq!(mmr.get_node(Position::new(0)), None);
            assert_eq!(*mmr.root(), hasher.root(Location::new(0), [].iter()));
            let mut mmr2 = Mmr::new(&mut hasher);
            mmr2.prune_all();
            assert_eq!(mmr2.size(), 0, "prune_all on empty MMR should do nothing");

            assert_eq!(*mmr.root(), hasher.root(Location::new(0), [].iter()));
        });
    }

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

            // Test nodes_needing_parents on the final MMR. Since there's a height gap between the
            // highest peak (14) and the next, only the lower two peaks (17, 18) should be returned.
            let peaks_needing_parents = nodes_needing_parents(mmr.peak_iterator());
            assert_eq!(
                peaks_needing_parents,
                vec![Position::new(17), Position::new(18)],
                "mmr nodes needing parents not as expected"
            );

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

    /// Test that pruning all nodes never breaks adding new nodes.
    #[test]
    fn test_mem_mmr_prune_all() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::new(&mut hasher);
            let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
            for _ in 0..1000 {
                mmr.prune_all();
                let changeset = {
                    let mut batch = mmr.new_batch();
                    batch = batch.add(&mut hasher, &element);
                    batch.merkleize(&mut hasher).finalize()
                };
                mmr.apply(changeset).unwrap();
            }
        });
    }

    /// Test that the MMR validity check works as expected.
    #[test]
    fn test_mem_mmr_validity() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::new(&mut hasher);
            let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
            for _ in 0..1001 {
                assert!(
                    mmr.size().is_valid_size(),
                    "mmr of size {} should be valid",
                    mmr.size()
                );
                let old_size = mmr.size();
                let changeset = {
                    let mut batch = mmr.new_batch();
                    batch = batch.add(&mut hasher, &element);
                    batch.merkleize(&mut hasher).finalize()
                };
                mmr.apply(changeset).unwrap();
                for size in *old_size + 1..*mmr.size() {
                    assert!(
                        !Position::new(size).is_valid_size(),
                        "mmr of size {size} should be invalid",
                    );
                }
            }
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

    /// Test that pruning after each add does not affect root computation.
    #[test]
    fn test_mem_mmr_root_with_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut reference_mmr = Mmr::new(&mut hasher);
            let mut mmr = Mmr::new(&mut hasher);
            for i in 0u64..200 {
                let element = hasher.digest(&i.to_be_bytes());

                // Add to reference MMR
                let cs = {
                    let mut batch = reference_mmr.new_batch();
                    batch = batch.add(&mut hasher, &element);
                    batch.merkleize(&mut hasher).finalize()
                };
                reference_mmr.apply(cs).unwrap();

                // Add to pruning MMR
                let cs = {
                    let mut batch = mmr.new_batch();
                    batch = batch.add(&mut hasher, &element);
                    batch.merkleize(&mut hasher).finalize()
                };
                mmr.apply(cs).unwrap();

                mmr.prune_all();
                assert_eq!(mmr.root(), reference_mmr.root());
            }
        });
    }

    #[test]
    fn test_mem_mmr_update_leaf() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            const NUM_ELEMENTS: u64 = 200;
            let mmr = Mmr::new(&mut hasher);
            let mut mmr = build_test_mmr(&mut hasher, mmr, NUM_ELEMENTS);
            let root = *mmr.root();

            // For a few leaves, update the leaf and ensure the root changes, and the root reverts
            // to its previous state then we update the leaf to its original value.
            for leaf in [0usize, 1, 10, 50, 100, 150, 197, 198] {
                // Change the leaf.
                let leaf_loc = Location::new(leaf as u64);
                let batch = mmr
                    .new_batch()
                    .update_leaf(&mut hasher, leaf_loc, &element)
                    .unwrap();
                mmr.apply(batch.merkleize(&mut hasher).finalize()).unwrap();
                let updated_root = *mmr.root();
                assert!(root != updated_root);

                // Restore the leaf to its original value, ensure the root is as before.
                let element = hasher.digest(&leaf.to_be_bytes());
                let batch = mmr
                    .new_batch()
                    .update_leaf(&mut hasher, leaf_loc, &element)
                    .unwrap();
                mmr.apply(batch.merkleize(&mut hasher).finalize()).unwrap();
                let restored_root = *mmr.root();
                assert_eq!(root, restored_root);
            }

            // Confirm the tree has all the hashes necessary to update any element after pruning.
            mmr.prune(Location::new(100)).unwrap();
            for leaf in 100u64..=190 {
                mmr.prune(Location::new(leaf)).unwrap();
                let leaf_loc = Location::new(leaf);
                let batch = mmr
                    .new_batch()
                    .update_leaf(&mut hasher, leaf_loc, &element)
                    .unwrap();
                mmr.apply(batch.merkleize(&mut hasher).finalize()).unwrap();
            }
        });
    }

    #[test]
    fn test_mem_mmr_update_leaf_error_out_of_bounds() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mmr = Mmr::new(&mut hasher);
            let mmr = build_test_mmr(&mut hasher, mmr, 200);
            let invalid_loc = mmr.leaves();
            let batch = mmr.new_batch();
            assert!(matches!(
                batch.update_leaf(&mut hasher, invalid_loc, &element),
                Err(Error::LeafOutOfBounds(_))
            ));
        });
    }

    #[test]
    fn test_mem_mmr_update_leaf_error_pruned() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mmr = Mmr::new(&mut hasher);
            let mut mmr = build_test_mmr(&mut hasher, mmr, 100);
            mmr.prune_all();
            let batch = mmr.new_batch();
            let result = batch.update_leaf(&mut hasher, Location::new(0), &element);
            assert!(matches!(result, Err(Error::ElementPruned(_))));
        });
    }

    #[test]
    fn test_mem_mmr_batch_update_leaf() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mmr = Mmr::new(&mut hasher);
            let mmr = build_test_mmr(&mut hasher, mmr, 200);
            do_batch_update(&mut hasher, mmr, None);
        });
    }

    /// Same test as above only using a thread pool to trigger parallelization. This requires we use
    /// tokio runtime instead of the deterministic one.
    #[test]
    fn test_mem_mmr_batch_parallel_update_leaf() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let executor = tokio::Runner::default();
        executor.start(|ctx| async move {
            let mmr = Mmr::init(
                Config {
                    nodes: Vec::new(),
                    pruned_to: Location::new(0),
                    pinned_nodes: Vec::new(),
                },
                &mut hasher,
            )
            .unwrap();
            let mmr = build_test_mmr(&mut hasher, mmr, 200);
            let pool = ctx.create_thread_pool(NZUsize!(4)).unwrap();
            do_batch_update(&mut hasher, mmr, Some(pool));
        });
    }

    #[test]
    fn test_update_leaf_digest() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            const NUM_ELEMENTS: u64 = 200;
            let mmr = Mmr::new(&mut hasher);
            let mut mmr = build_test_mmr(&mut hasher, mmr, NUM_ELEMENTS);
            let root = *mmr.root();

            let updated_digest = Sha256::fill(0xFF);

            // Save the original leaf digest so we can restore it.
            let loc = Location::new(5);
            let leaf_pos = Position::try_from(loc).unwrap();
            let original_digest = mmr.get_node(leaf_pos).unwrap();

            // Update a leaf via batch update_leaf_digest.
            let changeset = mmr
                .new_batch()
                .update_leaf_digest(loc, updated_digest)
                .unwrap()
                .merkleize(&mut hasher)
                .finalize();
            mmr.apply(changeset).unwrap();
            assert_ne!(*mmr.root(), root);

            // Restore the original digest and confirm the root reverts.
            let changeset = mmr
                .new_batch()
                .update_leaf_digest(loc, original_digest)
                .unwrap()
                .merkleize(&mut hasher)
                .finalize();
            mmr.apply(changeset).unwrap();
            assert_eq!(*mmr.root(), root);

            // Update multiple leaves before a single finalize.
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in [0u64, 1, 50, 100, 199] {
                    batch = batch
                        .update_leaf_digest(Location::new(i), updated_digest)
                        .unwrap();
                }
                batch.merkleize(&mut hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            assert_ne!(*mmr.root(), root);
        });
    }

    #[test]
    fn test_update_leaf_digest_errors() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            {
                // Out of bounds: location >= leaf count.
                let mmr = Mmr::new(&mut hasher);
                let mmr = build_test_mmr(&mut hasher, mmr, 100);
                let Err(err) = mmr
                    .new_batch()
                    .update_leaf_digest(Location::new(100), Sha256::fill(0))
                else {
                    panic!("expected error");
                };
                assert!(matches!(err, Error::LeafOutOfBounds(_)));
            }

            {
                // Pruned leaf.
                let mmr = Mmr::new(&mut hasher);
                let mut mmr = build_test_mmr(&mut hasher, mmr, 100);
                mmr.prune(Location::new(27)).unwrap();
                let Err(err) = mmr
                    .new_batch()
                    .update_leaf_digest(Location::new(0), Sha256::fill(0))
                else {
                    panic!("expected error");
                };
                assert!(matches!(err, Error::ElementPruned(_)));
            }
        });
    }

    fn do_batch_update(
        hasher: &mut Standard<Sha256>,
        mut mmr: Mmr<sha256::Digest>,
        pool: Option<ThreadPool>,
    ) {
        let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
        let root = *mmr.root();

        // Change a handful of leaves using a batch update.
        let changeset = {
            let mut batch = mmr.new_batch();
            if let Some(ref pool) = pool {
                batch = batch.with_pool(Some(pool.clone()));
            }
            for leaf in [0u64, 1, 10, 50, 100, 150, 197, 198] {
                let leaf_loc = Location::new(leaf);
                batch = batch.update_leaf(hasher, leaf_loc, &element).unwrap();
            }
            batch.merkleize(hasher).finalize()
        };
        mmr.apply(changeset).unwrap();
        let updated_root = *mmr.root();
        assert_ne!(updated_root, root);

        // Batch-restore the changed leaves to their original values.
        let changeset = {
            let mut batch = mmr.new_batch();
            for leaf in [0u64, 1, 10, 50, 100, 150, 197, 198] {
                let element = hasher.digest(&leaf.to_be_bytes());
                let leaf_loc = Location::new(leaf);
                batch = batch.update_leaf(hasher, leaf_loc, &element).unwrap();
            }
            batch.merkleize(hasher).finalize()
        };
        mmr.apply(changeset).unwrap();
        let restored_root = *mmr.root();
        assert_eq!(root, restored_root);
    }

    #[test]
    fn test_init_pinned_nodes_validation() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            // Test with empty config - should succeed
            let config = Config::<sha256::Digest> {
                nodes: vec![],
                pruned_to: Location::new(0),
                pinned_nodes: vec![],
            };
            assert!(Mmr::init(config, &mut hasher).is_ok());

            // Test with too few pinned nodes - should fail
            // 64 leaves = 127 nodes (complete tree)
            let config = Config::<sha256::Digest> {
                nodes: vec![],
                pruned_to: Location::new(64),
                pinned_nodes: vec![],
            };
            assert!(matches!(
                Mmr::init(config, &mut hasher),
                Err(Error::InvalidPinnedNodes)
            ));

            // Test with too many pinned nodes - should fail
            let config = Config {
                nodes: vec![],
                pruned_to: Location::new(0),
                pinned_nodes: vec![Sha256::hash(b"dummy")],
            };
            assert!(matches!(
                Mmr::init(config, &mut hasher),
                Err(Error::InvalidPinnedNodes)
            ));

            // Test with correct number of pinned nodes - should succeed
            // Build a small MMR to get valid pinned nodes
            let mut mmr = Mmr::new(&mut hasher);
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0u64..50 {
                    batch = batch.add(&mut hasher, &i.to_be_bytes());
                }
                batch.merkleize(&mut hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            let pinned_nodes = mmr.node_digests_to_pin(Position::new(50));
            let config = Config {
                nodes: vec![],
                pruned_to: Location::new(27),
                pinned_nodes,
            };
            assert!(Mmr::init(config, &mut hasher).is_ok());
        });
    }

    #[test]
    fn test_init_size_validation() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            // Test with valid size 0 - should succeed
            let config = Config::<sha256::Digest> {
                nodes: vec![],
                pruned_to: Location::new(0),
                pinned_nodes: vec![],
            };
            assert!(Mmr::init(config, &mut hasher).is_ok());

            // Test with invalid size 2 - should fail
            // Size 2 is invalid (can't have just one parent node + one leaf)
            let config = Config {
                nodes: vec![Sha256::hash(b"node1"), Sha256::hash(b"node2")],
                pruned_to: Location::new(0),
                pinned_nodes: vec![],
            };
            assert!(matches!(
                Mmr::init(config, &mut hasher),
                Err(Error::InvalidSize(_))
            ));

            // Test with valid size 3 (one full tree with 2 leaves) - should succeed
            let config = Config {
                nodes: vec![
                    Sha256::hash(b"leaf1"),
                    Sha256::hash(b"leaf2"),
                    Sha256::hash(b"parent"),
                ],
                pruned_to: Location::new(0),
                pinned_nodes: vec![],
            };
            assert!(Mmr::init(config, &mut hasher).is_ok());

            // Test with large valid size (127 = 2^7 - 1, a complete tree) - should succeed
            // Build a real MMR to get the correct structure
            let mut mmr = Mmr::new(&mut hasher);
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0u64..64 {
                    batch = batch.add(&mut hasher, &i.to_be_bytes());
                }
                batch.merkleize(&mut hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            assert_eq!(mmr.size(), 127); // Verify we have the expected size
            let nodes: Vec<_> = (0..127)
                .map(|i| *mmr.get_node_unchecked(Position::new(i)))
                .collect();

            let config = Config {
                nodes,
                pruned_to: Location::new(0),
                pinned_nodes: vec![],
            };
            assert!(Mmr::init(config, &mut hasher).is_ok());

            // Test with non-zero pruned_to - should succeed
            // Build a small MMR (11 leaves -> 19 nodes), prune it, then init from that state
            let mut mmr = Mmr::new(&mut hasher);
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0u64..11 {
                    batch = batch.add(&mut hasher, &i.to_be_bytes());
                }
                batch.merkleize(&mut hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            assert_eq!(mmr.size(), 19); // 11 leaves = 19 total nodes

            // Prune to leaf 4 (position 7)
            mmr.prune(Location::new(4)).unwrap();
            let nodes: Vec<_> = (7..*mmr.size())
                .map(|i| *mmr.get_node_unchecked(Position::new(i)))
                .collect();
            let pinned_nodes = mmr.node_digests_to_pin(Position::new(7));

            let config = Config {
                nodes: nodes.clone(),
                pruned_to: Location::new(4),
                pinned_nodes: pinned_nodes.clone(),
            };
            assert!(Mmr::init(config, &mut hasher).is_ok());

            // Same nodes but wrong pruned_to - should fail
            // Location(5) -> Position(8), 8 + 12 nodes = size 20 (invalid)
            let config = Config {
                nodes: nodes.clone(),
                pruned_to: Location::new(5),
                pinned_nodes: pinned_nodes.clone(),
            };
            assert!(matches!(
                Mmr::init(config, &mut hasher),
                Err(Error::InvalidSize(_))
            ));

            // Same nodes but different wrong pruned_to - should fail
            // Location(1) -> Position(1), 1 + 12 nodes = size 13 (invalid)
            let config = Config {
                nodes,
                pruned_to: Location::new(1),
                pinned_nodes,
            };
            assert!(matches!(
                Mmr::init(config, &mut hasher),
                Err(Error::InvalidSize(_))
            ));
        });
    }

    #[test]
    fn test_mem_mmr_range_proof_out_of_bounds() {
        let mut hasher: Standard<Sha256> = Standard::new();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Range end > leaves errors on empty MMR
            let mmr = Mmr::new(&mut hasher);
            assert_eq!(mmr.leaves(), Location::new(0));
            let result = mmr.range_proof(&mut hasher, Location::new(0)..Location::new(1));
            assert!(matches!(result, Err(Error::RangeOutOfBounds(_))));

            // Range end > leaves errors on non-empty MMR
            let mmr = build_test_mmr(&mut hasher, mmr, 10);
            assert_eq!(mmr.leaves(), Location::new(10));
            let result = mmr.range_proof(&mut hasher, Location::new(5)..Location::new(11));
            assert!(matches!(result, Err(Error::RangeOutOfBounds(_))));

            // Range end == leaves succeeds
            let result = mmr.range_proof(&mut hasher, Location::new(5)..Location::new(10));
            assert!(result.is_ok());
        });
    }

    #[test]
    fn test_mem_mmr_proof_out_of_bounds() {
        let mut hasher: Standard<Sha256> = Standard::new();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Test on empty MMR - should return error, not panic
            let mmr = Mmr::new(&mut hasher);
            let result = mmr.proof(&mut hasher, Location::new(0));
            assert!(
                matches!(result, Err(Error::LeafOutOfBounds(_))),
                "expected LeafOutOfBounds, got {:?}",
                result
            );

            // Test on non-empty MMR with location >= leaves
            let mmr = build_test_mmr(&mut hasher, mmr, 10);
            let result = mmr.proof(&mut hasher, Location::new(10));
            assert!(
                matches!(result, Err(Error::LeafOutOfBounds(_))),
                "expected LeafOutOfBounds, got {:?}",
                result
            );

            // location < leaves should succeed
            let result = mmr.proof(&mut hasher, Location::new(9));
            assert!(result.is_ok(), "expected Ok, got {:?}", result);
        });
    }

    #[test]
    fn test_stale_changeset_sibling() {
        let mut hasher: Standard<Sha256> = Standard::new();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut mmr = Mmr::new(&mut hasher);

            // Create two batches from the same base.
            let changeset_a = mmr
                .new_batch()
                .add(&mut hasher, b"leaf-a")
                .merkleize(&mut hasher)
                .finalize();
            let changeset_b = mmr
                .new_batch()
                .add(&mut hasher, b"leaf-b")
                .merkleize(&mut hasher)
                .finalize();

            // Apply A -- should succeed.
            mmr.apply(changeset_a).unwrap();

            // Apply B -- should fail (stale).
            let result = mmr.apply(changeset_b);
            assert!(
                matches!(result, Err(Error::StaleChangeset { .. })),
                "expected StaleChangeset, got {result:?}"
            );
        });
    }

    #[test]
    fn test_stale_changeset_chained() {
        let mut hasher: Standard<Sha256> = Standard::new();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut mmr = Mmr::new(&mut hasher);

            // Seed with one element.
            let changeset = mmr
                .new_batch()
                .add(&mut hasher, b"leaf-0")
                .merkleize(&mut hasher)
                .finalize();
            mmr.apply(changeset).unwrap();

            // Parent batch, then fork two children.
            let parent = mmr
                .new_batch()
                .add(&mut hasher, b"leaf-1")
                .merkleize(&mut hasher);
            let child_a = {
                let batch = parent.new_batch();
                batch
                    .add(&mut hasher, b"leaf-2a")
                    .merkleize(&mut hasher)
                    .finalize()
            };
            let child_b = {
                let batch = parent.new_batch();
                batch
                    .add(&mut hasher, b"leaf-2b")
                    .merkleize(&mut hasher)
                    .finalize()
            };

            // Apply child_a, then child_b should be stale.
            mmr.apply(child_a).unwrap();
            let result = mmr.apply(child_b);
            assert!(
                matches!(result, Err(Error::StaleChangeset { .. })),
                "expected StaleChangeset for sibling, got {result:?}"
            );
        });
    }

    #[test]
    fn test_stale_changeset_parent_before_child() {
        let mut hasher: Standard<Sha256> = Standard::new();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut mmr = Mmr::new(&mut hasher);

            // Create parent, then child.
            let parent = mmr
                .new_batch()
                .add(&mut hasher, b"leaf-0")
                .merkleize(&mut hasher);
            let child = parent
                .new_batch()
                .add(&mut hasher, b"leaf-1")
                .merkleize(&mut hasher)
                .finalize();
            let parent = parent.finalize();

            // Apply parent first -- child should now be stale.
            mmr.apply(parent).unwrap();
            let result = mmr.apply(child);
            assert!(
                matches!(result, Err(Error::StaleChangeset { .. })),
                "expected StaleChangeset for child after parent applied, got {result:?}"
            );
        });
    }

    #[test]
    fn test_stale_changeset_child_before_parent() {
        let mut hasher: Standard<Sha256> = Standard::new();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut mmr = Mmr::new(&mut hasher);

            // Create parent, then child.
            let parent = mmr
                .new_batch()
                .add(&mut hasher, b"leaf-0")
                .merkleize(&mut hasher);
            let child = parent
                .new_batch()
                .add(&mut hasher, b"leaf-1")
                .merkleize(&mut hasher)
                .finalize();
            let parent = parent.finalize();

            // Apply child first -- parent should now be stale.
            mmr.apply(child).unwrap();
            let result = mmr.apply(parent);
            assert!(
                matches!(result, Err(Error::StaleChangeset { .. })),
                "expected StaleChangeset for parent after child applied, got {result:?}"
            );
        });
    }
}

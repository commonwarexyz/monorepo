//! A basic, no_std compatible MMR where all nodes are stored in-memory.

/// A basic MMR where all nodes are stored in-memory.
pub type Mmr<D> = crate::merkle::mem::Mem<super::Family, D>;

/// Configuration for initializing an [Mmr].
pub type Config<D> = crate::merkle::mem::Config<super::Family, D>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{conformance::build_test_mmr, hasher::Hasher as _},
        mmr::{Error, Location, Position, StandardHasher as Standard},
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
            let hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::new(&hasher);
            let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
            let mut leaves: Vec<Location> = Vec::new();
            for _ in 0..11 {
                let changeset = {
                    let mut batch = mmr.new_batch();
                    leaves.push(batch.leaves());
                    batch = batch.add(&hasher, &element);
                    batch.merkleize(&hasher).finalize()
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

            // Test parent_heights on the final MMR. Since there's a height gap between the
            // highest peak (14) and the next, only the lower two peaks (17, 18) would merge,
            // producing 2 parents at heights 1 and 2.
            let heights: Vec<u32> = crate::merkle::Family::parent_heights(mmr.leaves()).collect();
            assert_eq!(heights, vec![1, 2], "parent_heights not as expected");

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
                mmr.proof(&hasher, Location::new(0)),
                Err(Error::ElementPruned(_))
            ));
            assert!(matches!(
                mmr.proof(&hasher, Location::new(6)),
                Err(Error::ElementPruned(_))
            ));

            // We should still be able to generate a proof for any leaf following the pruning
            // boundary, the first of which is at location 8 and the last location 10.
            assert!(mmr.proof(&hasher, Location::new(8)).is_ok());
            assert!(mmr.proof(&hasher, Location::new(10)).is_ok());

            let root_after_prune = *mmr.root();
            assert_eq!(root, root_after_prune, "root changed after pruning");

            assert!(
                mmr.range_proof(&hasher, Location::new(5)..Location::new(9))
                    .is_err(),
                "attempts to range_prove elements at or before the oldest retained should fail"
            );
            assert!(
                mmr.range_proof(&hasher, Location::new(8)..mmr.leaves())
                    .is_ok(),
                "attempts to range_prove over all elements following oldest retained should succeed"
            );

            // Test that we can initialize a new MMR from another's elements.
            let oldest_loc = mmr.bounds().start;
            let digests = mmr.node_digests_to_pin(oldest_loc);
            let mmr_copy = Mmr::init(
                Config {
                    nodes: mmr.nodes.iter().copied().collect(),
                    pruning_boundary: oldest_loc,
                    pinned_nodes: digests,
                },
                &hasher,
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
            let hasher: Standard<Sha256> = Standard::new();
            const NUM_ELEMENTS: u64 = 199;
            let mut test_mmr = Mmr::new(&hasher);
            test_mmr = build_test_mmr(&hasher, test_mmr, NUM_ELEMENTS);
            let expected_root = test_mmr.root();

            let mut batched_mmr = Mmr::new(&hasher);

            // Add all elements in one batch
            let changeset = {
                let mut batch = batched_mmr.new_batch();
                for i in 0..NUM_ELEMENTS {
                    let element = hasher.digest(&i.to_be_bytes());
                    batch = batch.add(&hasher, &element);
                }
                batch.merkleize(&hasher).finalize()
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
            let hasher: Standard<Sha256> = Standard::new();
            const NUM_ELEMENTS: u64 = 199;
            let test_mmr = Mmr::new(&hasher);
            let test_mmr = build_test_mmr(&hasher, test_mmr, NUM_ELEMENTS);
            let expected_root = test_mmr.root();

            let pool = context.create_thread_pool(NZUsize!(4)).unwrap();
            let hasher: Standard<Sha256> = Standard::new();

            let mut mmr = Mmr::init(
                Config {
                    nodes: vec![],
                    pruning_boundary: Location::new(0),
                    pinned_nodes: vec![],
                },
                &hasher,
            )
            .unwrap();

            let changeset = {
                let mut batch = mmr.new_batch().with_pool(Some(pool));
                for i in 0u64..NUM_ELEMENTS {
                    let element = hasher.digest(&i.to_be_bytes());
                    batch = batch.add(&hasher, &element);
                }
                batch.merkleize(&hasher).finalize()
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
            let hasher: Standard<Sha256> = Standard::new();
            assert!(Mmr::init(
                Config::<sha256::Digest> {
                    nodes: vec![],
                    pruning_boundary: Location::new(0),
                    pinned_nodes: vec![],
                },
                &hasher,
            )
            .is_ok());

            assert!(matches!(
                Mmr::init(
                    Config {
                        nodes: vec![Sha256::hash(b"node1"), Sha256::hash(b"node2")],
                        pruning_boundary: Location::new(0),
                        pinned_nodes: vec![],
                    },
                    &hasher,
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
                    pruning_boundary: Location::new(0),
                    pinned_nodes: vec![],
                },
                &hasher,
            )
            .is_ok());

            let mut mmr = Mmr::new(&hasher);
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0u64..64 {
                    batch = batch.add(&hasher, &i.to_be_bytes());
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            assert_eq!(mmr.size(), 127);
            let nodes: Vec<_> = (0..127)
                .map(|i| *mmr.get_node_unchecked(Position::new(i)))
                .collect();
            assert!(Mmr::init(
                Config {
                    nodes,
                    pruning_boundary: Location::new(0),
                    pinned_nodes: vec![],
                },
                &hasher,
            )
            .is_ok());

            let mut mmr = Mmr::new(&hasher);
            let changeset = {
                let mut batch = mmr.new_batch();
                for i in 0u64..11 {
                    batch = batch.add(&hasher, &i.to_be_bytes());
                }
                batch.merkleize(&hasher).finalize()
            };
            mmr.apply(changeset).unwrap();
            mmr.prune(Location::new(4)).unwrap();
            let nodes: Vec<_> = (7..*mmr.size())
                .map(|i| *mmr.get_node_unchecked(Position::new(i)))
                .collect();
            let pinned_nodes = mmr.node_digests_to_pin(Location::new(4));
            assert!(Mmr::init(
                Config {
                    nodes: nodes.clone(),
                    pruning_boundary: Location::new(4),
                    pinned_nodes: pinned_nodes.clone(),
                },
                &hasher,
            )
            .is_ok());

            assert!(matches!(
                Mmr::init(
                    Config {
                        nodes,
                        pruning_boundary: Location::new(5),
                        pinned_nodes,
                    },
                    &hasher,
                ),
                Err(Error::InvalidSize(_))
            ));
        });
    }
}

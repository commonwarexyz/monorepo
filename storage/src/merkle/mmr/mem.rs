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
            let mut mmr = Mmr::new();
            let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
            let mut leaves: Vec<Location> = Vec::new();
            for _ in 0..11 {
                let batch = {
                    let mut batch = mmr.new_batch();
                    leaves.push(batch.leaves());
                    batch = batch.add(&hasher, &element);
                    batch.merkleize(&mmr, &hasher)
                };
                mmr.apply_batch(&batch).unwrap();
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

            let heights: Vec<u32> =
                <crate::merkle::mmr::Family as crate::merkle::Family>::parent_heights(mmr.leaves())
                    .collect();
            assert_eq!(heights, vec![1, 2], "parent_heights not as expected");

            for leaf in leaves.iter().by_ref() {
                let pos = Position::try_from(*leaf).unwrap();
                let digest = hasher.leaf_digest(pos, &element);
                assert_eq!(mmr.get_node(pos).unwrap(), digest);
            }

            let root = mmr.root(&hasher, 0).unwrap();

            // pruning tests
            mmr.prune(Location::new(8)).unwrap();
            assert_eq!(mmr.bounds().start, Location::new(8));

            assert!(matches!(
                mmr.proof(&hasher, Location::new(0), 0),
                Err(Error::ElementPruned(_))
            ));
            assert!(matches!(
                mmr.proof(&hasher, Location::new(6), 0),
                Err(Error::ElementPruned(_))
            ));

            assert!(mmr.proof(&hasher, Location::new(8), 0).is_ok());
            assert!(mmr.proof(&hasher, Location::new(10), 0).is_ok());

            let root_after_prune = mmr.root(&hasher, 0).unwrap();
            assert_eq!(root, root_after_prune, "root changed after pruning");

            assert!(mmr
                .range_proof(&hasher, Location::new(5)..Location::new(9), 0)
                .is_err(),);
            assert!(mmr
                .range_proof(&hasher, Location::new(8)..mmr.leaves(), 0)
                .is_ok(),);

            // Test that we can initialize a new MMR from another's elements.
            let oldest_loc = mmr.bounds().start;
            let digests = mmr.node_digests_to_pin(oldest_loc);
            let mmr_copy = Mmr::init(Config {
                nodes: (*Position::try_from(oldest_loc).unwrap()..*mmr.size())
                    .map(|i| mmr.get_node(Position::new(i)).unwrap())
                    .collect(),
                pruning_boundary: oldest_loc,
                pinned_nodes: digests,
            })
            .unwrap();
            assert_eq!(mmr_copy.size(), 19);
            assert_eq!(mmr_copy.leaves(), mmr.leaves());
            assert_eq!(mmr_copy.bounds().start, mmr.bounds().start);
            assert_eq!(mmr_copy.root(&hasher, 0).unwrap(), root);
        });
    }

    /// Test that batched MMR building produces the same root as the reference implementation.
    #[test]
    fn test_mem_mmr_batched_root() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            const NUM_ELEMENTS: u64 = 199;
            let mut test_mmr = Mmr::new();
            test_mmr = build_test_mmr(&hasher, test_mmr, NUM_ELEMENTS);
            let expected_root = test_mmr.root(&hasher, 0).unwrap();

            let mut batched_mmr = Mmr::new();

            let batch = {
                let mut batch = batched_mmr.new_batch();
                for i in 0..NUM_ELEMENTS {
                    let element = hasher.digest(&i.to_be_bytes());
                    batch = batch.add(&hasher, &element);
                }
                batch.merkleize(&batched_mmr, &hasher)
            };
            batched_mmr.apply_batch(&batch).unwrap();

            assert_eq!(
                batched_mmr.root(&hasher, 0).unwrap(),
                expected_root,
                "Batched MMR root should match reference"
            );
        });
    }

    /// Test that parallel batched MMR building produces the same root as the reference.
    #[test]
    fn test_mem_mmr_batched_root_parallel() {
        let executor = tokio::Runner::default();
        executor.start(|context| async move {
            let hasher: Standard<Sha256> = Standard::new();
            const NUM_ELEMENTS: u64 = 199;
            let test_mmr = Mmr::new();
            let test_mmr = build_test_mmr(&hasher, test_mmr, NUM_ELEMENTS);
            let expected_root = test_mmr.root(&hasher, 0).unwrap();

            let pool = context.create_thread_pool(NZUsize!(4)).unwrap();
            let hasher: Standard<Sha256> = Standard::new();

            let mut mmr = Mmr::init(Config {
                nodes: vec![],
                pruning_boundary: Location::new(0),
                pinned_nodes: vec![],
            })
            .unwrap();

            let batch = {
                let mut batch = mmr.new_batch().with_pool(Some(pool));
                for i in 0u64..NUM_ELEMENTS {
                    let element = hasher.digest(&i.to_be_bytes());
                    batch = batch.add(&hasher, &element);
                }
                batch.merkleize(&mmr, &hasher)
            };
            mmr.apply_batch(&batch).unwrap();
            assert_eq!(
                mmr.root(&hasher, 0).unwrap(),
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
            assert!(Mmr::init(Config::<sha256::Digest> {
                nodes: vec![],
                pruning_boundary: Location::new(0),
                pinned_nodes: vec![],
            })
            .is_ok());

            assert!(matches!(
                Mmr::init(Config {
                    nodes: vec![Sha256::hash(b"node1"), Sha256::hash(b"node2")],
                    pruning_boundary: Location::new(0),
                    pinned_nodes: vec![],
                }),
                Err(Error::InvalidSize(_))
            ));

            assert!(Mmr::init(Config {
                nodes: vec![
                    Sha256::hash(b"leaf1"),
                    Sha256::hash(b"leaf2"),
                    Sha256::hash(b"parent"),
                ],
                pruning_boundary: Location::new(0),
                pinned_nodes: vec![],
            })
            .is_ok());

            let mut mmr = Mmr::new();
            let batch = {
                let mut batch = mmr.new_batch();
                for i in 0u64..64 {
                    batch = batch.add(&hasher, &i.to_be_bytes());
                }
                batch.merkleize(&mmr, &hasher)
            };
            mmr.apply_batch(&batch).unwrap();
            assert_eq!(mmr.size(), 127);
            let nodes: Vec<_> = (0..127)
                .map(|i| mmr.get_node(Position::new(i)).unwrap())
                .collect();
            assert!(Mmr::init(Config {
                nodes,
                pruning_boundary: Location::new(0),
                pinned_nodes: vec![],
            })
            .is_ok());

            let mut mmr = Mmr::new();
            let batch = {
                let mut batch = mmr.new_batch();
                for i in 0u64..11 {
                    batch = batch.add(&hasher, &i.to_be_bytes());
                }
                batch.merkleize(&mmr, &hasher)
            };
            mmr.apply_batch(&batch).unwrap();
            mmr.prune(Location::new(4)).unwrap();
            let nodes: Vec<_> = (7..*mmr.size())
                .map(|i| mmr.get_node(Position::new(i)).unwrap())
                .collect();
            let pinned_nodes = mmr.node_digests_to_pin(Location::new(4));
            assert!(Mmr::init(Config {
                nodes: nodes.clone(),
                pruning_boundary: Location::new(4),
                pinned_nodes: pinned_nodes.clone(),
            })
            .is_ok());

            assert!(matches!(
                Mmr::init(Config {
                    nodes,
                    pruning_boundary: Location::new(5),
                    pinned_nodes,
                }),
                Err(Error::InvalidSize(_))
            ));
        });
    }
}

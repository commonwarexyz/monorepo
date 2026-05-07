//! A basic, no_std compatible MMB where all nodes are stored in-memory.

/// A basic MMB where all nodes are stored in-memory.
pub type Mmb<D> = crate::merkle::mem::Mem<super::Family, D>;

/// Configuration for initializing an [Mmb].
pub type Config<D> = crate::merkle::mem::Config<super::Family, D>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{
        hasher::{Hasher as _, Standard},
        mmb::{Error, Location, Position},
        Bagging::ForwardFold,
    };
    use commonware_cryptography::Sha256;

    type D = <Sha256 as commonware_cryptography::Hasher>::Digest;
    type H = Standard<Sha256>;

    fn build_mmb(n: u64) -> (H, Mmb<D>) {
        let hasher = H::new(ForwardFold);
        let mut mmb = Mmb::new();
        let batch = {
            let mut batch = mmb.new_batch();
            for i in 0..n {
                batch = batch.add(&hasher, &i.to_be_bytes());
            }
            batch.merkleize(&mmb, &hasher)
        };
        mmb.apply_batch(&batch).unwrap();
        (hasher, mmb)
    }

    #[test]
    fn test_append_and_size() {
        let hasher = H::new(ForwardFold);
        let mut mmb = Mmb::new();

        for i in 0u64..8 {
            let batch = {
                let mut batch = mmb.new_batch();
                let loc = batch.leaves();
                batch = batch.add(&hasher, &i.to_be_bytes());
                assert_eq!(*loc, i);
                batch.merkleize(&mmb, &hasher)
            };
            mmb.apply_batch(&batch).unwrap();
        }
        assert_eq!(*mmb.leaves(), 8);
        assert_eq!(*mmb.size(), 13);
    }

    #[test]
    fn test_add_eight_values_structure() {
        let (hasher, mmb) = build_mmb(8);

        assert_eq!(mmb.bounds().start, Location::new(0));
        assert_eq!(mmb.size(), Position::new(13));
        assert_eq!(mmb.leaves(), Location::new(8));

        let peaks: Vec<(Position, u32)> = mmb.peak_iterator().collect();
        assert_eq!(
            peaks,
            vec![
                (Position::new(7), 2),
                (Position::new(9), 1),
                (Position::new(12), 1)
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

        let expected_root = hasher
            .root(Location::new(8), 0, [digest7, digest9, digest12].iter())
            .expect("zero inactive peaks is always valid");
        assert_eq!(
            mmb.root(&hasher, 0).unwrap(),
            expected_root,
            "incorrect root"
        );
    }

    #[test]
    fn test_prune_and_reinit() {
        let (hasher, mut mmb) = build_mmb(24);

        let root = mmb.root(&hasher, 0).unwrap();
        let prune_loc = Location::new(9);
        mmb.prune(prune_loc).unwrap();

        assert_eq!(mmb.bounds().start, prune_loc);
        assert_eq!(mmb.root(&hasher, 0).unwrap(), root);
        assert!(matches!(
            mmb.proof(&hasher, Location::new(0), 0),
            Err(Error::ElementPruned(_))
        ));

        for loc in *prune_loc..*mmb.leaves() {
            assert!(
                mmb.proof(&hasher, Location::new(loc), 0).is_ok(),
                "loc={loc} should remain provable after pruning"
            );
        }

        let mmb_copy = Mmb::init(Config {
            nodes: (*Position::try_from(prune_loc).unwrap()..*mmb.size())
                .map(|i| mmb.get_node(Position::new(i)).unwrap())
                .collect(),
            pruning_boundary: prune_loc,
            pinned_nodes: mmb.node_digests_to_pin(prune_loc),
        })
        .unwrap();

        assert_eq!(mmb_copy.size(), mmb.size());
        assert_eq!(mmb_copy.leaves(), mmb.leaves());
        assert_eq!(mmb_copy.bounds(), mmb.bounds());
        assert_eq!(mmb_copy.root(&hasher, 0).unwrap(), root);
        assert!(mmb_copy.proof(&hasher, Location::new(17), 0).is_ok());
    }

    #[test]
    fn test_init_size_validation() {
        let hasher = H::new(ForwardFold);

        assert!(Mmb::<D>::init(Config {
            nodes: vec![],
            pruning_boundary: Location::new(0),
            pinned_nodes: vec![],
        })
        .is_ok());

        assert!(matches!(
            Mmb::init(Config {
                nodes: vec![hasher.digest(b"node1"), hasher.digest(b"node2")],
                pruning_boundary: Location::new(0),
                pinned_nodes: vec![],
            }),
            Err(Error::InvalidSize(_))
        ));

        assert!(Mmb::init(Config {
            nodes: vec![
                hasher.digest(b"leaf1"),
                hasher.digest(b"leaf2"),
                hasher.digest(b"parent"),
            ],
            pruning_boundary: Location::new(0),
            pinned_nodes: vec![],
        })
        .is_ok());

        let (_, mmb) = build_mmb(64);
        let nodes: Vec<_> = (0..*mmb.size())
            .map(|i| *mmb.get_node_unchecked(Position::new(i)))
            .collect();
        assert!(Mmb::init(Config {
            nodes,
            pruning_boundary: Location::new(0),
            pinned_nodes: vec![],
        })
        .is_ok());

        let (_, mut mmb) = build_mmb(11);
        mmb.prune(Location::new(4)).unwrap();
        let nodes: Vec<_> = (6..*mmb.size())
            .map(|i| *mmb.get_node_unchecked(Position::new(i)))
            .collect();
        let pinned_nodes = mmb.node_digests_to_pin(Location::new(4));

        assert!(Mmb::init(Config {
            nodes: nodes.clone(),
            pruning_boundary: Location::new(4),
            pinned_nodes: pinned_nodes.clone(),
        })
        .is_ok());

        assert!(matches!(
            Mmb::init(Config {
                nodes,
                pruning_boundary: Location::new(2),
                pinned_nodes,
            }),
            Err(Error::InvalidSize(_))
        ));
    }
}

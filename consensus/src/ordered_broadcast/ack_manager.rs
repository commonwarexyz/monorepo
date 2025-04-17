use commonware_cryptography::{
    bls12381::primitives::{group, ops, poly::PartialSignature},
    Digest,
};
use commonware_utils::Array;
use std::collections::{BTreeMap, HashMap, HashSet};

use super::types::{Ack, Epoch};

/// A struct representing a set of partial signatures for a payload digest.
#[derive(Default)]
struct Partials<D: Digest> {
    // The set of share indices that have signed the payload.
    pub shares: HashSet<u32>,

    // A map from payload digest to partial signatures.
    // Each share should only sign once for each sequencer/height/epoch.
    pub sigs: HashMap<D, Vec<PartialSignature>>,
}

/// Evidence for a chunk.
/// This is either a set of partial signatures or a threshold signature.
enum Evidence<D: Digest> {
    Partials(Partials<D>),
    Threshold(group::Signature),
}

impl<D: Digest> Default for Evidence<D> {
    fn default() -> Self {
        Self::Partials(Partials {
            shares: HashSet::new(),
            sigs: HashMap::new(),
        })
    }
}

/// Manages acknowledgements for chunks.
#[derive(Default)]
pub struct AckManager<P: Array, D: Digest> {
    // Acknowledgements for digests.
    //
    // Map from Sequencer => Height => Epoch => Evidence
    //
    // Evidence may be partial signatures or threshold signatures.
    //
    // The BTreeMaps are sorted by key, so we can prune old entries. In particular, we can prune
    // entries where the height is less than the height of the highest chunk for the sequencer.
    // We can often prune entries for old epochs as well.
    acks: HashMap<P, BTreeMap<u64, BTreeMap<Epoch, Evidence<D>>>>,
}

impl<P: Array, D: Digest> AckManager<P, D> {
    /// Creates a new `AckManager`.
    pub fn new() -> Self {
        Self {
            acks: HashMap::new(),
        }
    }

    /// Adds a partial signature to the evidence.
    ///
    /// If-and-only-if the quorum is newly-reached, the threshold signature is returned.
    pub fn add_ack(&mut self, ack: &Ack<P, D>, quorum: u32) -> Option<group::Signature> {
        let evidence = self
            .acks
            .entry(ack.chunk.sequencer.clone())
            .or_default()
            .entry(ack.chunk.height)
            .or_default()
            .entry(ack.epoch)
            .or_default();

        match evidence {
            Evidence::Threshold(_) => None,
            Evidence::Partials(p) => {
                if !p.shares.insert(ack.signature.index) {
                    // Validator already signed
                    return None;
                }

                // Add the partial
                let partials = p.sigs.entry(ack.chunk.payload).or_default();
                partials.push(ack.signature.clone());

                // Return early if no quorum
                if partials.len() < quorum as usize {
                    return None;
                }

                // Take ownership of the partials, which must exist
                let partials = p.sigs.remove(&ack.chunk.payload).unwrap();

                // Construct the threshold signature
                let threshold = ops::threshold_signature_recover(quorum, &partials).unwrap();
                Some(threshold)
            }
        }
    }

    /// Returns a tuple of (Epoch, Threshold), if it exists, for the given sequencer and height.
    ///
    /// If multiple epochs have thresholds, the highest epoch is returned.
    pub fn get_threshold(&self, sequencer: &P, height: u64) -> Option<(Epoch, group::Signature)> {
        self.acks
            .get(sequencer)
            .and_then(|m| m.get(&height))
            .and_then(|m| {
                // Reverse iterator to get the highest epoch first
                m.iter().rev().find_map(|(epoch, evidence)| match evidence {
                    Evidence::Threshold(t) => Some((*epoch, *t)),
                    _ => None,
                })
            })
    }

    /// Sets the threshold for the given sequencer, height, and epoch.
    /// Returns `true` if the threshold was newly set, `false` if it already existed.
    pub fn add_threshold(
        &mut self,
        sequencer: &P,
        height: u64,
        epoch: Epoch,
        threshold: group::Signature,
    ) -> bool {
        // Set the threshold.
        // If the threshold already existed, return false
        if let Some(Evidence::Threshold(_)) = self
            .acks
            .entry(sequencer.clone())
            .or_default()
            .entry(height)
            .or_default()
            .insert(epoch, Evidence::Threshold(threshold))
        {
            return false;
        }

        // Prune all entries with height less than the parent
        //
        // This approach ensures we don't accidentally notify the application of a threshold signature multiple
        // times (which could otherwise occur if we recover the threshold signature for some chunk at tip and then
        // receive a duplicate broadcast of said chunk before a sequencer sends one at a new height).
        if let Some(m) = self.acks.get_mut(sequencer) {
            let min_height = height.saturating_sub(1);
            m.retain(|&h, _| h >= min_height);
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ordered_broadcast::types::Chunk;
    use commonware_cryptography::{bls12381::dkg::ops::generate_shares, ed25519, sha256};
    use commonware_runtime::deterministic::Executor;

    /// Aggregated helper functions to reduce duplication in tests.
    mod helpers {
        use super::*;
        use crate::ordered_broadcast::types::Chunk;
        use commonware_codec::FixedSize;
        use commonware_cryptography::bls12381::primitives::group::Share;

        const NAMESPACE: &[u8] = b"1234";

        /// Generate shares using the default executor.
        pub fn setup_shares(num_validators: u32, quorum: u32) -> Vec<Share> {
            let (_, mut context, _) = Executor::default();
            let (_identity, shares) = generate_shares(&mut context, None, num_validators, quorum);
            shares
        }

        /// Generate a fixed public key for testing.
        pub fn gen_public_key(val: u8) -> ed25519::PublicKey {
            ed25519::PublicKey::try_from(&[val; ed25519::PublicKey::SIZE][..]).unwrap()
        }

        /// Create an Ack by signing a partial with the provided share.
        pub fn create_ack(
            share: &Share,
            chunk: Chunk<ed25519::PublicKey, sha256::Digest>,
            epoch: Epoch,
        ) -> Ack<ed25519::PublicKey, sha256::Digest> {
            Ack::sign(NAMESPACE, share, chunk, epoch)
        }

        /// Recover a threshold signature from a set of partials.
        pub fn recover_threshold(
            quorum: u32,
            partials: Vec<commonware_cryptography::bls12381::primitives::poly::PartialSignature>,
        ) -> commonware_cryptography::bls12381::primitives::group::Signature {
            ops::threshold_signature_recover(quorum, &partials).unwrap()
        }

        /// Generate a threshold signature directly from the shares specified by `indices`.
        pub fn generate_threshold_from_indices(
            shares: &[Share],
            chunk: &Chunk<ed25519::PublicKey, sha256::Digest>,
            epoch: &Epoch,
            quorum: u32,
            indices: &[usize],
        ) -> commonware_cryptography::bls12381::primitives::group::Signature {
            let partials: Vec<_> = indices
                .iter()
                .map(|&i| create_ack(&shares[i], chunk.clone(), *epoch).signature)
                .collect();
            recover_threshold(quorum, partials)
        }

        /// Create a vector of acks for the given share indices.
        pub fn create_acks_for_indices(
            shares: &[Share],
            chunk: Chunk<ed25519::PublicKey, sha256::Digest>,
            epoch: Epoch,
            indices: &[usize],
        ) -> Vec<Ack<ed25519::PublicKey, sha256::Digest>> {
            indices
                .iter()
                .map(|&i| create_ack(&shares[i], chunk.clone(), epoch))
                .collect()
        }

        /// Add acks (generated from the provided share indices) to the manager.
        /// Returns the threshold signature if produced.
        pub fn add_acks_for_indices(
            manager: &mut AckManager<ed25519::PublicKey, sha256::Digest>,
            shares: &[Share],
            chunk: Chunk<ed25519::PublicKey, sha256::Digest>,
            epoch: Epoch,
            quorum: u32,
            indices: &[usize],
        ) -> Option<commonware_cryptography::bls12381::primitives::group::Signature> {
            let acks = create_acks_for_indices(shares, chunk, epoch, indices);
            let mut threshold = None;
            for ack in acks {
                if let Some(sig) = manager.add_ack(&ack, quorum) {
                    threshold = Some(sig);
                }
            }
            threshold
        }
    } // end helpers

    /// Different payloads for the same chunk produce distinct thresholds.
    #[test]
    fn test_chunk_different_payloads() {
        let num_validators = 6;
        let quorum = 3;
        let shares = helpers::setup_shares(num_validators, quorum);
        let mut acks = AckManager::<ed25519::PublicKey, sha256::Digest>::new();
        let sequencer = helpers::gen_public_key(1);
        let height = 10;
        let epoch = 5;

        let chunk1 = Chunk::new(sequencer.clone(), height, sha256::hash(b"payload1"));
        let chunk2 = Chunk::new(sequencer, height, sha256::hash(b"payload2"));

        let threshold1 =
            helpers::add_acks_for_indices(&mut acks, &shares, chunk1, epoch, quorum, &[0, 1, 2]);
        let threshold2 =
            helpers::add_acks_for_indices(&mut acks, &shares, chunk2, epoch, quorum, &[3, 4, 5]);

        let t1 = threshold1.expect("Expected threshold signature for payload1");
        let t2 = threshold2.expect("Expected threshold signature for payload2");
        assert_ne!(t1, t2);
    }

    /// Adding thresholds for different heights prunes older entries.
    #[test]
    fn test_sequencer_different_heights() {
        let num_validators = 4;
        let quorum = 3;
        let shares = helpers::setup_shares(num_validators, quorum);
        let mut acks = AckManager::<ed25519::PublicKey, sha256::Digest>::new();
        let sequencer = helpers::gen_public_key(1);
        let epoch = 10;
        let height1 = 10;
        let height2 = 20;

        let chunk1 = Chunk::new(sequencer.clone(), height1, sha256::hash(b"chunk1"));
        let threshold1 =
            helpers::generate_threshold_from_indices(&shares, &chunk1, &epoch, quorum, &[0, 1, 2]);
        assert!(acks.add_threshold(&sequencer, height1, epoch, threshold1));
        assert_eq!(
            acks.get_threshold(&sequencer, height1),
            Some((epoch, threshold1))
        );

        let chunk2 = Chunk::new(sequencer.clone(), height2, sha256::hash(b"chunk2"));
        let threshold2 =
            helpers::generate_threshold_from_indices(&shares, &chunk2, &epoch, quorum, &[0, 1, 2]);
        assert!(acks.add_threshold(&sequencer, height2, epoch, threshold2));

        assert_eq!(acks.get_threshold(&sequencer, height1), None);
        assert_eq!(
            acks.get_threshold(&sequencer, height2),
            Some((epoch, threshold2))
        );
    }

    /// Adding thresholds for contiguous heights prunes entries older than the immediate parent.
    #[test]
    fn test_sequencer_contiguous_heights() {
        let num_validators = 4;
        let quorum = 3;
        let shares = helpers::setup_shares(num_validators, quorum);
        let mut acks = AckManager::<ed25519::PublicKey, sha256::Digest>::new();
        let sequencer = helpers::gen_public_key(1);
        let epoch = 10;

        let chunk1 = Chunk::new(sequencer.clone(), 10, sha256::hash(b"chunk1"));
        let threshold1 =
            helpers::generate_threshold_from_indices(&shares, &chunk1, &epoch, quorum, &[0, 1, 2]);
        assert!(acks.add_threshold(&sequencer, 10, epoch, threshold1));
        assert_eq!(
            acks.get_threshold(&sequencer, 10),
            Some((epoch, threshold1))
        );

        let chunk2 = Chunk::new(sequencer.clone(), 11, sha256::hash(b"chunk2"));
        let threshold2 =
            helpers::generate_threshold_from_indices(&shares, &chunk2, &epoch, quorum, &[0, 1, 2]);
        assert!(acks.add_threshold(&sequencer, 11, epoch, threshold2));

        assert_eq!(
            acks.get_threshold(&sequencer, 10),
            Some((epoch, threshold1))
        );
        assert_eq!(
            acks.get_threshold(&sequencer, 11),
            Some((epoch, threshold2))
        );

        let chunk3 = Chunk::new(sequencer.clone(), 12, sha256::hash(b"chunk3"));
        let threshold3 =
            helpers::generate_threshold_from_indices(&shares, &chunk3, &epoch, quorum, &[0, 1, 2]);
        assert!(acks.add_threshold(&sequencer, 12, epoch, threshold3));

        assert_eq!(acks.get_threshold(&sequencer, 10), None);
        assert_eq!(
            acks.get_threshold(&sequencer, 11),
            Some((epoch, threshold2))
        );
        assert_eq!(
            acks.get_threshold(&sequencer, 12),
            Some((epoch, threshold3))
        );
    }

    /// For the same sequencer and height, the highest epoch's threshold is returned.
    #[test]
    fn test_chunk_different_epochs() {
        let num_validators = 4;
        let quorum = 3;
        let shares = helpers::setup_shares(num_validators, quorum);
        let mut acks = AckManager::<ed25519::PublicKey, sha256::Digest>::new();
        let sequencer = helpers::gen_public_key(1);
        let height = 30;
        let epoch1 = 1;
        let epoch2 = 2;

        let chunk = Chunk::new(sequencer.clone(), height, sha256::hash(b"chunk"));

        let threshold1 =
            helpers::generate_threshold_from_indices(&shares, &chunk, &epoch1, quorum, &[0, 1, 2]);
        assert!(acks.add_threshold(&sequencer, height, epoch1, threshold1));

        let threshold2 =
            helpers::generate_threshold_from_indices(&shares, &chunk, &epoch2, quorum, &[0, 1, 2]);
        assert!(acks.add_threshold(&sequencer, height, epoch2, threshold2));

        assert_eq!(
            acks.get_threshold(&sequencer, height),
            Some((epoch2, threshold2))
        );
    }

    /// Adding the same threshold twice returns false.
    #[test]
    fn test_add_threshold() {
        let num_validators = 4;
        let quorum = 3;
        let shares = helpers::setup_shares(num_validators, quorum);
        let mut acks = AckManager::<ed25519::PublicKey, sha256::Digest>::new();
        let epoch = 99;
        let sequencer = helpers::gen_public_key(1);
        let height = 42;
        let chunk = Chunk::new(sequencer.clone(), height, sha256::hash(&sequencer));

        let threshold =
            helpers::generate_threshold_from_indices(&shares, &chunk, &epoch, quorum, &[0, 1, 2]);

        assert_eq!(acks.get_threshold(&sequencer, height), None);
        assert!(acks.add_threshold(&sequencer, height, epoch, threshold));
        assert_eq!(
            acks.get_threshold(&sequencer, height),
            Some((epoch, threshold))
        );
        assert!(!acks.add_threshold(&sequencer, height, epoch, threshold));
        assert_eq!(
            acks.get_threshold(&sequencer, height),
            Some((epoch, threshold))
        );
    }

    /// Duplicate partial submissions are ignored.
    #[test]
    fn test_duplicate_partial_submission() {
        let num_validators = 4;
        let quorum = 3;
        let shares = helpers::setup_shares(num_validators, quorum);
        let mut acks = AckManager::<ed25519::PublicKey, sha256::Digest>::new();
        let sequencer = helpers::gen_public_key(1);
        let epoch = 1;
        let height = 10;
        let chunk = Chunk::new(sequencer, height, sha256::hash(b"payload"));

        let ack = helpers::create_ack(&shares[0], chunk, epoch);
        assert!(acks.add_ack(&ack, quorum).is_none());
        assert!(acks.add_ack(&ack, quorum).is_none());
    }

    /// Once a threshold is reached, further acks are ignored.
    #[test]
    fn test_subsequent_acks_after_threshold_reached() {
        let num_validators = 4;
        let quorum = 3;
        let shares = helpers::setup_shares(num_validators, quorum);
        let mut acks = AckManager::<ed25519::PublicKey, sha256::Digest>::new();
        let sequencer = helpers::gen_public_key(1);
        let epoch = 1;
        let height = 10;
        let chunk = Chunk::new(sequencer, height, sha256::hash(b"payload"));

        let acks_vec = helpers::create_acks_for_indices(&shares, chunk.clone(), epoch, &[0, 1, 2]);
        let mut produced = None;
        for ack in acks_vec {
            if let Some(thresh) = acks.add_ack(&ack, quorum) {
                produced = Some(thresh);
            }
        }
        assert!(produced.is_some());

        let ack = helpers::create_ack(&shares[3], chunk, epoch);
        assert!(acks.add_ack(&ack, quorum).is_none());
    }

    /// Acks for different sequencers are managed separately.
    #[test]
    fn test_multiple_sequencers() {
        let num_validators = 4;
        let quorum = 3;
        let shares = helpers::setup_shares(num_validators, quorum);
        let mut acks = AckManager::<ed25519::PublicKey, sha256::Digest>::new();

        let sequencer1 = helpers::gen_public_key(1);
        let sequencer2 = helpers::gen_public_key(3);
        let epoch = 1;
        let height = 10;

        let chunk1 = Chunk::new(sequencer1.clone(), height, sha256::hash(b"payload1"));
        let chunk2 = Chunk::new(sequencer2.clone(), height, sha256::hash(b"payload2"));

        let threshold1 =
            helpers::add_acks_for_indices(&mut acks, &shares, chunk1, epoch, quorum, &[0, 1, 2])
                .unwrap();
        let threshold2 =
            helpers::add_acks_for_indices(&mut acks, &shares, chunk2, epoch, quorum, &[0, 1, 2])
                .unwrap();

        assert_ne!(threshold1, threshold2);
        assert!(acks.add_threshold(&sequencer1, height, epoch, threshold1));
        assert!(acks.add_threshold(&sequencer2, height, epoch, threshold2));
    }

    /// If quorum is never reached, no threshold is produced.
    #[test]
    fn test_partial_quorum_never_reached() {
        let num_validators = 4;
        let quorum = 3;
        let shares = helpers::setup_shares(num_validators, quorum);
        let mut acks = AckManager::<ed25519::PublicKey, sha256::Digest>::new();
        let sequencer = helpers::gen_public_key(1);
        let epoch = 1;
        let height = 10;
        let chunk = Chunk::new(sequencer.clone(), height, sha256::hash(b"payload"));

        let acks_vec = helpers::create_acks_for_indices(&shares, chunk, epoch, &[0, 1]);
        for ack in acks_vec {
            assert!(acks.add_ack(&ack, quorum).is_none());
        }
        assert_eq!(acks.get_threshold(&sequencer, height), None);
    }

    /// Interleaved acks for different payloads are aggregated separately.
    #[test]
    fn test_interleaved_payloads() {
        let num_validators = 6;
        let quorum = 3;
        let shares = helpers::setup_shares(num_validators, quorum);
        let mut acks = AckManager::<ed25519::PublicKey, sha256::Digest>::new();
        let sequencer = helpers::gen_public_key(1);
        let epoch = 1;
        let height = 10;

        let payload1 = sha256::hash(b"payload1");
        let payload2 = sha256::hash(b"payload2");

        let chunk1 = Chunk::new(sequencer.clone(), height, payload1);
        let chunk2 = Chunk::new(sequencer, height, payload2);

        let submissions = [
            (0, &chunk1),
            (1, &chunk2),
            (2, &chunk1),
            (3, &chunk2),
            (4, &chunk1),
            (5, &chunk2),
        ];
        let mut thresholds = Vec::new();
        for (i, chunk) in submissions.into_iter() {
            let ack = helpers::create_ack(&shares[i], chunk.clone(), epoch);
            if let Some(threshold) = acks.add_ack(&ack, quorum) {
                thresholds.push((chunk.payload, threshold));
            }
        }
        assert!(!thresholds.is_empty());
        for (p, _) in thresholds {
            assert!(p == payload1 || p == payload2);
        }
    }
}

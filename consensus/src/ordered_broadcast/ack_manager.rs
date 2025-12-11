use super::types::Ack;
use crate::types::Epoch;
use commonware_cryptography::{
    bls12381::primitives::{
        ops,
        sharing::Sharing,
        variant::{PartialSignature, Variant},
    },
    Digest, PublicKey,
};
use std::collections::{BTreeMap, HashMap, HashSet};

/// A struct representing a set of partial signatures for a payload digest.
#[derive(Default)]
struct Partials<V: Variant, D: Digest> {
    // The set of share indices that have signed the payload.
    pub shares: HashSet<u32>,

    // A map from payload digest to partial signatures.
    // Each share should only sign once for each sequencer/height/epoch.
    pub sigs: HashMap<D, Vec<PartialSignature<V>>>,
}

/// Evidence for a chunk.
/// This is either a set of partial signatures or a threshold signature.
enum Evidence<V: Variant, D: Digest> {
    Partials(Partials<V, D>),
    Threshold(V::Signature),
}

impl<V: Variant, D: Digest> Default for Evidence<V, D> {
    fn default() -> Self {
        Self::Partials(Partials {
            shares: HashSet::new(),
            sigs: HashMap::new(),
        })
    }
}

/// Manages acknowledgements for chunks.
#[derive(Default)]
pub struct AckManager<P: PublicKey, V: Variant, D: Digest> {
    // Acknowledgements for digests.
    //
    // Map from Sequencer => Height => Epoch => Evidence
    //
    // Evidence may be partial signatures or threshold signatures.
    //
    // The BTreeMaps are sorted by key, so we can prune old entries. In particular, we can prune
    // entries where the height is less than the height of the highest chunk for the sequencer.
    // We can often prune entries for old epochs as well.
    #[allow(clippy::type_complexity)]
    acks: HashMap<P, BTreeMap<u64, BTreeMap<Epoch, Evidence<V, D>>>>,
}

impl<P: PublicKey, V: Variant, D: Digest> AckManager<P, V, D> {
    /// Creates a new `AckManager`.
    pub fn new() -> Self {
        Self {
            acks: HashMap::new(),
        }
    }

    /// Adds a partial signature to the evidence.
    ///
    /// If-and-only-if the quorum is newly-reached, the threshold signature is returned.
    pub fn add_ack(&mut self, ack: &Ack<P, V, D>, public: &Sharing<V>) -> Option<V::Signature> {
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
                if partials.len() < public.required() as usize {
                    return None;
                }

                // Take ownership of the partials, which must exist
                let partials = p.sigs.remove(&ack.chunk.payload).unwrap();

                // Construct the threshold signature
                let threshold =
                    ops::threshold_signature_recover::<V, _>(public, &partials).unwrap();
                Some(threshold)
            }
        }
    }

    /// Returns a tuple of (Epoch, Threshold), if it exists, for the given sequencer and height.
    ///
    /// If multiple epochs have thresholds, the highest epoch is returned.
    pub fn get_threshold(&self, sequencer: &P, height: u64) -> Option<(Epoch, V::Signature)> {
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
        threshold: V::Signature,
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
    use commonware_cryptography::{
        bls12381::{
            dkg,
            primitives::variant::{MinPk, MinSig},
        },
        ed25519::PublicKey,
        Hasher, Sha256,
    };

    /// Aggregated helper functions to reduce duplication in tests.
    mod helpers {
        use super::*;
        use crate::ordered_broadcast::types::Chunk;
        use commonware_codec::{DecodeExt, FixedSize};
        use commonware_cryptography::{bls12381::primitives::group::Share, Hasher};
        use commonware_utils::NZU32;
        use rand::{rngs::StdRng, SeedableRng as _};

        const NAMESPACE: &[u8] = b"1234";

        /// Generate shares using a seeded RNG.
        pub fn setup_shares<V: Variant>(num_validators: u32) -> (Sharing<V>, Vec<Share>) {
            let mut rng = StdRng::seed_from_u64(0);
            let (public, shares) =
                dkg::deal_anonymous::<V>(&mut rng, Default::default(), NZU32!(num_validators));
            (public, shares)
        }

        /// Generate a fixed public key for testing.
        pub fn gen_public_key(val: u8) -> PublicKey {
            PublicKey::decode([val; PublicKey::SIZE].as_ref()).unwrap()
        }

        /// Create an Ack by signing a partial with the provided share.
        pub fn create_ack<V: Variant>(
            share: &Share,
            chunk: Chunk<PublicKey, <Sha256 as Hasher>::Digest>,
            epoch: Epoch,
        ) -> Ack<PublicKey, V, <Sha256 as Hasher>::Digest> {
            Ack::sign(NAMESPACE, share, chunk, epoch)
        }

        /// Recover a threshold signature from a set of partials.
        pub fn recover_threshold<V: Variant>(
            quorum: &Sharing<V>,
            partials: Vec<PartialSignature<V>>,
        ) -> V::Signature {
            ops::threshold_signature_recover::<V, _>(quorum, &partials).unwrap()
        }

        /// Generate a threshold signature directly from the shares specified by `indices`.
        pub fn generate_threshold_from_indices<V: Variant>(
            shares: &[Share],
            chunk: &Chunk<PublicKey, <Sha256 as Hasher>::Digest>,
            epoch: Epoch,
            quorum: &Sharing<V>,
            indices: &[usize],
        ) -> V::Signature {
            let partials: Vec<_> = indices
                .iter()
                .map(|&i| create_ack::<V>(&shares[i], chunk.clone(), epoch).signature)
                .collect();
            recover_threshold::<V>(quorum, partials)
        }

        /// Create a vector of acks for the given share indices.
        pub fn create_acks_for_indices<V: Variant>(
            shares: &[Share],
            chunk: Chunk<PublicKey, <Sha256 as Hasher>::Digest>,
            epoch: Epoch,
            indices: &[usize],
        ) -> Vec<Ack<PublicKey, V, <Sha256 as Hasher>::Digest>> {
            indices
                .iter()
                .map(|&i| create_ack(&shares[i], chunk.clone(), epoch))
                .collect()
        }

        /// Add acks (generated from the provided share indices) to the manager.
        /// Returns the threshold signature if produced.
        pub fn add_acks_for_indices<V: Variant>(
            manager: &mut AckManager<PublicKey, V, <Sha256 as Hasher>::Digest>,
            shares: &[Share],
            chunk: Chunk<PublicKey, <Sha256 as Hasher>::Digest>,
            epoch: Epoch,
            quorum: &Sharing<V>,
            indices: &[usize],
        ) -> Option<V::Signature> {
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
    fn chunk_different_payloads<V: Variant>() {
        let num_validators = 6;
        let (quorum, shares) = helpers::setup_shares::<V>(num_validators);
        let sequencer = helpers::gen_public_key(1);
        let height = 10;
        let epoch = Epoch::new(5);

        let chunk1 = Chunk::new(sequencer.clone(), height, Sha256::hash(b"payload1"));
        let chunk2 = Chunk::new(sequencer, height, Sha256::hash(b"payload2"));

        let threshold1 = helpers::add_acks_for_indices(
            &mut AckManager::<PublicKey, V, <Sha256 as Hasher>::Digest>::new(),
            &shares,
            chunk1,
            epoch,
            &quorum,
            &[0, 1, 2, 3, 4],
        );
        let threshold2 = helpers::add_acks_for_indices(
            &mut AckManager::<PublicKey, V, <Sha256 as Hasher>::Digest>::new(),
            &shares,
            chunk2,
            epoch,
            &quorum,
            &[1, 2, 3, 4, 5],
        );

        let t1 = threshold1.expect("Expected threshold signature for payload1");
        let t2 = threshold2.expect("Expected threshold signature for payload2");
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_chunk_different_payloads() {
        chunk_different_payloads::<MinPk>();
        chunk_different_payloads::<MinSig>();
    }

    /// Adding thresholds for different heights prunes older entries.
    fn sequencer_different_heights<V: Variant>() {
        let num_validators = 4;
        let (quorum, shares) = helpers::setup_shares::<V>(num_validators);
        let mut acks = AckManager::<PublicKey, V, <Sha256 as Hasher>::Digest>::new();
        let sequencer = helpers::gen_public_key(1);
        let epoch = Epoch::new(10);
        let height1 = 10;
        let height2 = 20;

        let chunk1 = Chunk::new(sequencer.clone(), height1, Sha256::hash(b"chunk1"));
        let threshold1 = helpers::generate_threshold_from_indices::<V>(
            &shares,
            &chunk1,
            epoch,
            &quorum,
            &[0, 1, 2],
        );
        assert!(acks.add_threshold(&sequencer, height1, epoch, threshold1));
        assert_eq!(
            acks.get_threshold(&sequencer, height1),
            Some((epoch, threshold1))
        );

        let chunk2 = Chunk::new(sequencer.clone(), height2, Sha256::hash(b"chunk2"));
        let threshold2 = helpers::generate_threshold_from_indices::<V>(
            &shares,
            &chunk2,
            epoch,
            &quorum,
            &[0, 1, 2],
        );
        assert!(acks.add_threshold(&sequencer, height2, epoch, threshold2));

        assert_eq!(acks.get_threshold(&sequencer, height1), None);
        assert_eq!(
            acks.get_threshold(&sequencer, height2),
            Some((epoch, threshold2))
        );
    }

    #[test]
    fn test_sequencer_different_heights() {
        sequencer_different_heights::<MinPk>();
        sequencer_different_heights::<MinSig>();
    }

    /// Adding thresholds for contiguous heights prunes entries older than the immediate parent.
    fn sequencer_contiguous_heights<V: Variant>() {
        let num_validators = 4;
        let (quorum, shares) = helpers::setup_shares::<V>(num_validators);
        let mut acks = AckManager::<PublicKey, V, <Sha256 as Hasher>::Digest>::new();
        let sequencer = helpers::gen_public_key(1);
        let epoch = Epoch::new(10);

        let chunk1 = Chunk::new(sequencer.clone(), 10, Sha256::hash(b"chunk1"));
        let threshold1 = helpers::generate_threshold_from_indices::<V>(
            &shares,
            &chunk1,
            epoch,
            &quorum,
            &[0, 1, 2],
        );
        assert!(acks.add_threshold(&sequencer, 10, epoch, threshold1));
        assert_eq!(
            acks.get_threshold(&sequencer, 10),
            Some((epoch, threshold1))
        );

        let chunk2 = Chunk::new(sequencer.clone(), 11, Sha256::hash(b"chunk2"));
        let threshold2 = helpers::generate_threshold_from_indices::<V>(
            &shares,
            &chunk2,
            epoch,
            &quorum,
            &[0, 1, 2],
        );
        assert!(acks.add_threshold(&sequencer, 11, epoch, threshold2));

        assert_eq!(
            acks.get_threshold(&sequencer, 10),
            Some((epoch, threshold1))
        );
        assert_eq!(
            acks.get_threshold(&sequencer, 11),
            Some((epoch, threshold2))
        );

        let chunk3 = Chunk::new(sequencer.clone(), 12, Sha256::hash(b"chunk3"));
        let threshold3 = helpers::generate_threshold_from_indices::<V>(
            &shares,
            &chunk3,
            epoch,
            &quorum,
            &[0, 1, 2],
        );
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

    #[test]
    fn test_sequencer_contiguous_heights() {
        sequencer_contiguous_heights::<MinPk>();
        sequencer_contiguous_heights::<MinSig>();
    }

    /// For the same sequencer and height, the highest epoch's threshold is returned.
    fn chunk_different_epochs<V: Variant>() {
        let num_validators = 4;
        let (quorum, shares) = helpers::setup_shares::<V>(num_validators);
        let mut acks = AckManager::<PublicKey, V, <Sha256 as Hasher>::Digest>::new();
        let sequencer = helpers::gen_public_key(1);
        let height = 30;
        let epoch1 = Epoch::new(1);
        let epoch2 = Epoch::new(2);

        let chunk = Chunk::new(sequencer.clone(), height, Sha256::hash(b"chunk"));

        let threshold1 = helpers::generate_threshold_from_indices::<V>(
            &shares,
            &chunk,
            epoch1,
            &quorum,
            &[0, 1, 2],
        );
        assert!(acks.add_threshold(&sequencer, height, epoch1, threshold1));

        let threshold2 = helpers::generate_threshold_from_indices::<V>(
            &shares,
            &chunk,
            epoch2,
            &quorum,
            &[0, 1, 2],
        );
        assert!(acks.add_threshold(&sequencer, height, epoch2, threshold2));

        assert_eq!(
            acks.get_threshold(&sequencer, height),
            Some((epoch2, threshold2))
        );
    }

    #[test]
    fn test_chunk_different_epochs() {
        chunk_different_epochs::<MinPk>();
        chunk_different_epochs::<MinSig>();
    }

    /// Adding the same threshold twice returns false.
    fn add_threshold<V: Variant>() {
        let num_validators = 4;
        let (quorum, shares) = helpers::setup_shares::<V>(num_validators);
        let mut acks = AckManager::<PublicKey, V, <Sha256 as Hasher>::Digest>::new();
        let epoch = Epoch::new(99);
        let sequencer = helpers::gen_public_key(1);
        let height = 42;
        let chunk = Chunk::new(sequencer.clone(), height, Sha256::hash(&sequencer));

        let threshold = helpers::generate_threshold_from_indices::<V>(
            &shares,
            &chunk,
            epoch,
            &quorum,
            &[0, 1, 2],
        );

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

    #[test]
    fn test_add_threshold() {
        add_threshold::<MinPk>();
        add_threshold::<MinSig>();
    }

    /// Duplicate partial submissions are ignored.
    fn duplicate_partial_submission<V: Variant>() {
        let num_validators = 4;
        let (quorum, shares) = helpers::setup_shares::<V>(num_validators);
        let mut acks = AckManager::<PublicKey, V, <Sha256 as Hasher>::Digest>::new();
        let sequencer = helpers::gen_public_key(1);
        let epoch = Epoch::new(1);
        let height = 10;
        let chunk = Chunk::new(sequencer, height, Sha256::hash(b"payload"));

        let ack = helpers::create_ack(&shares[0], chunk, epoch);
        assert!(acks.add_ack(&ack, &quorum).is_none());
        assert!(acks.add_ack(&ack, &quorum).is_none());
    }

    #[test]
    fn test_duplicate_partial_submission() {
        duplicate_partial_submission::<MinPk>();
        duplicate_partial_submission::<MinSig>();
    }

    /// Once a threshold is reached, further acks are ignored.
    fn subsequent_acks_after_threshold_reached<V: Variant>() {
        let num_validators = 4;
        let (quorum, shares) = helpers::setup_shares::<V>(num_validators);
        let mut acks = AckManager::<PublicKey, V, <Sha256 as Hasher>::Digest>::new();
        let sequencer = helpers::gen_public_key(1);
        let epoch = Epoch::new(1);
        let height = 10;
        let chunk = Chunk::new(sequencer, height, Sha256::hash(b"payload"));

        let acks_vec = helpers::create_acks_for_indices(&shares, chunk.clone(), epoch, &[0, 1, 2]);
        let mut produced = None;
        for ack in acks_vec {
            if let Some(thresh) = acks.add_ack(&ack, &quorum) {
                produced = Some(thresh);
            }
        }
        assert!(produced.is_some());

        let ack = helpers::create_ack(&shares[3], chunk, epoch);
        assert!(acks.add_ack(&ack, &quorum).is_none());
    }

    #[test]
    fn test_subsequent_acks_after_threshold_reached() {
        subsequent_acks_after_threshold_reached::<MinPk>();
        subsequent_acks_after_threshold_reached::<MinSig>();
    }

    /// Acks for different sequencers are managed separately.
    fn multiple_sequencers<V: Variant>() {
        let num_validators = 4;
        let (quorum, shares) = helpers::setup_shares::<V>(num_validators);
        let mut acks = AckManager::<PublicKey, V, <Sha256 as Hasher>::Digest>::new();

        let sequencer1 = helpers::gen_public_key(1);
        let sequencer2 = helpers::gen_public_key(3);
        let epoch = Epoch::new(1);
        let height = 10;

        let chunk1 = Chunk::new(sequencer1.clone(), height, Sha256::hash(b"payload1"));
        let chunk2 = Chunk::new(sequencer2.clone(), height, Sha256::hash(b"payload2"));

        let threshold1 =
            helpers::add_acks_for_indices(&mut acks, &shares, chunk1, epoch, &quorum, &[0, 1, 2])
                .unwrap();
        let threshold2 =
            helpers::add_acks_for_indices(&mut acks, &shares, chunk2, epoch, &quorum, &[0, 1, 2])
                .unwrap();

        assert_ne!(threshold1, threshold2);
        assert!(acks.add_threshold(&sequencer1, height, epoch, threshold1));
        assert!(acks.add_threshold(&sequencer2, height, epoch, threshold2));
    }

    #[test]
    fn test_multiple_sequencers() {
        multiple_sequencers::<MinPk>();
        multiple_sequencers::<MinSig>();
    }

    /// If quorum is never reached, no threshold is produced.
    fn partial_quorum_never_reached<V: Variant>() {
        let num_validators = 4;
        let (quorum, shares) = helpers::setup_shares::<V>(num_validators);
        let mut acks = AckManager::<PublicKey, V, <Sha256 as Hasher>::Digest>::new();
        let sequencer = helpers::gen_public_key(1);
        let epoch = Epoch::new(1);
        let height = 10;
        let chunk = Chunk::new(sequencer.clone(), height, Sha256::hash(b"payload"));

        let acks_vec = helpers::create_acks_for_indices(&shares, chunk, epoch, &[0, 1]);
        for ack in acks_vec {
            assert!(acks.add_ack(&ack, &quorum).is_none());
        }
        assert_eq!(acks.get_threshold(&sequencer, height), None);
    }

    #[test]
    fn test_partial_quorum_never_reached() {
        partial_quorum_never_reached::<MinPk>();
        partial_quorum_never_reached::<MinSig>();
    }

    /// Interleaved acks for different payloads are aggregated separately.
    fn interleaved_payloads<V: Variant>() {
        let num_validators = 6;
        let (quorum, shares) = helpers::setup_shares::<V>(num_validators);
        let mut acks = AckManager::<PublicKey, V, <Sha256 as Hasher>::Digest>::new();
        let sequencer = helpers::gen_public_key(1);
        let epoch = Epoch::new(1);
        let height = 10;

        let payload1 = Sha256::hash(b"payload1");
        let payload2 = Sha256::hash(b"payload2");

        let chunk1 = Chunk::new(sequencer.clone(), height, payload1);
        let chunk2 = Chunk::new(sequencer, height, payload2);

        let submissions = (0..2 * quorum.required())
            .map(|i| ((i >> 1) + (i & 1)) % num_validators)
            .zip([&chunk1, &chunk2].into_iter().cycle());
        let mut thresholds = Vec::new();
        for (i, chunk) in submissions {
            let ack = helpers::create_ack(&shares[i as usize], chunk.clone(), epoch);
            if let Some(threshold) = acks.add_ack(&ack, &quorum) {
                thresholds.push((chunk.payload, threshold));
            }
        }
        assert!(!thresholds.is_empty());
        for (p, _) in thresholds {
            assert!(p == payload1 || p == payload2);
        }
    }

    #[test]
    fn test_interleaved_payloads() {
        interleaved_payloads::<MinPk>();
        interleaved_payloads::<MinSig>();
    }
}

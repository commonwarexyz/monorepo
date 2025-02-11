use crate::linked::{safe, Epoch};
use commonware_cryptography::{
    bls12381::primitives::{group, ops, poly::PartialSignature},
    Array,
};
use std::collections::{BTreeMap, HashMap, HashSet};

/// A struct representing a set of partial signatures for a payload digest.
#[derive(Default)]
struct Partials<D: Array> {
    // The set of share indices that have signed the payload.
    pub shares: HashSet<u32>,

    // A map from payload digest to partial signatures.
    // Each share should only sign once for each sequencer/height/epoch.
    pub sigs: HashMap<D, Vec<PartialSignature>>,
}

/// Evidence for a chunk.
/// This is either a set of partial signatures or a threshold signature.
enum Evidence<D: Array> {
    Partials(Partials<D>),
    Threshold(group::Signature),
}

impl<D: Array> Default for Evidence<D> {
    fn default() -> Self {
        Self::Partials(Partials {
            shares: HashSet::new(),
            sigs: HashMap::new(),
        })
    }
}

/// Manages acknowledgements for chunks.
#[derive(Default)]
pub struct AckManager<D: Array, P: Array> {
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

impl<D: Array, P: Array> AckManager<D, P> {
    /// Creates a new `AckManager`.
    pub fn new() -> Self {
        Self {
            acks: HashMap::new(),
        }
    }

    /// Adds a partial signature to the evidence.
    ///
    /// If-and-only-if the quorum is newly-reached, the threshold signature is returned.
    pub fn add_ack(&mut self, ack: &safe::Ack<D, P>, quorum: u32) -> Option<group::Signature> {
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
                if !p.shares.insert(ack.partial.index) {
                    // Signer already existed
                    return None;
                }

                // Add the partial
                let partials = p.sigs.entry(ack.chunk.payload.clone()).or_default();
                partials.push(ack.partial.clone());

                // Return early if no quorum
                if partials.len() < quorum as usize {
                    return None;
                }

                // Take ownership of the partials, which must exist
                let partials = p.sigs.remove(&ack.chunk.payload).unwrap();

                // Construct the threshold signature
                let threshold = ops::threshold_signature_recover(quorum, partials).unwrap();
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

        // Prune old entries for this sequencer
        if let Some(m) = self.acks.get_mut(sequencer) {
            m.retain(|&h, _| h >= height);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linked::{namespace, safe, serializer};
    use commonware_cryptography::{bls12381::dkg::ops::generate_shares, ed25519, sha256};
    use commonware_runtime::deterministic::Executor;
    use commonware_utils::SizedSerialize;

    #[test]
    fn test_chunk_different_payloads() {
        // Use 6 validators so that two disjoint groups of 3 can sign different payloads.
        let num_validators = 6;
        let quorum = 3;
        let (_, mut runtime, _) = Executor::default();
        let (_identity, shares) = generate_shares(&mut runtime, None, num_validators, quorum);
        let mut acks = AckManager::<sha256::Digest, ed25519::PublicKey>::new();

        let sequencer =
            ed25519::PublicKey::try_from(&[1u8; ed25519::PublicKey::SERIALIZED_LEN][..]).unwrap();
        let height = 10;
        let epoch = 5;

        // Create two chunks with same sequencer, height but different payloads.
        let payload1 = sha256::hash(b"payload1");
        let chunk1 = safe::Chunk {
            sequencer: sequencer.clone(),
            height,
            payload: payload1.clone(),
        };
        let payload2 = sha256::hash(b"payload2");
        let chunk2 = safe::Chunk {
            sequencer: sequencer.clone(),
            height,
            payload: payload2.clone(),
        };

        // For payload1, use signers 0,1,2.
        let mut threshold1 = None;
        for i in 0..quorum {
            let partial = ops::partial_sign_message(
                &shares[i as usize],
                Some(namespace::ack(b"1234").as_slice()),
                &serializer::ack(&chunk1, epoch),
            );
            let ack = safe::Ack {
                chunk: chunk1.clone(),
                epoch,
                partial: partial.clone(),
            };
            let res = acks.add_ack(&ack, quorum);
            if i == (quorum - 1) {
                assert!(res.is_some());
                threshold1 = res;
            } else {
                assert!(res.is_none());
            }
        }

        // For payload2, use disjoint signers 3,4,5.
        let mut threshold2 = None;
        for i in quorum..(quorum * 2) {
            let partial = ops::partial_sign_message(
                &shares[i as usize],
                Some(namespace::ack(b"1234").as_slice()),
                &serializer::ack(&chunk2, epoch),
            );
            let ack = safe::Ack {
                chunk: chunk2.clone(),
                epoch,
                partial: partial.clone(),
            };
            let res = acks.add_ack(&ack, quorum);
            if i == (quorum * 2 - 1) {
                assert!(res.is_some());
                threshold2 = res;
            } else {
                assert!(res.is_none());
            }
        }

        // Ensure that threshold signatures for different payloads are produced and are distinct.
        let t1 = threshold1.expect("Expected threshold signature for payload1");
        let t2 = threshold2.expect("Expected threshold signature for payload2");
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_sequencer_different_heights() {
        // Test that adding a threshold for a higher chunk height prunes older heights.
        let num_validators = 4;
        let quorum = 3;
        let (_, mut runtime, _) = Executor::default();
        let (_identity, shares) = generate_shares(&mut runtime, None, num_validators, quorum);
        let mut acks = AckManager::<sha256::Digest, ed25519::PublicKey>::new();

        let sequencer =
            ed25519::PublicKey::try_from(&[1u8; ed25519::PublicKey::SERIALIZED_LEN][..]).unwrap();
        let epoch = 10;
        let height1 = 10;
        let height2 = 20;

        // For height1, create a chunk and threshold.
        let chunk1 = safe::Chunk {
            sequencer: sequencer.clone(),
            height: height1,
            payload: sha256::hash(b"chunk1"),
        };
        let mut partials1 = Vec::new();
        for i in 0..quorum {
            let partial = ops::partial_sign_message(
                &shares[i as usize],
                Some(namespace::ack(b"1234").as_slice()),
                &serializer::ack(&chunk1, epoch),
            );
            partials1.push(partial);
        }
        let threshold1 = ops::threshold_signature_recover(quorum, partials1).unwrap();
        let res = acks.add_threshold(&sequencer, height1, epoch, threshold1);
        assert!(res);
        assert_eq!(
            acks.get_threshold(&sequencer, height1),
            Some((epoch, threshold1))
        );

        // For height2, create a new chunk and threshold.
        let chunk2 = safe::Chunk {
            sequencer: sequencer.clone(),
            height: height2,
            payload: sha256::hash(b"chunk2"),
        };
        let mut partials2 = Vec::new();
        for i in 0..quorum {
            let partial = ops::partial_sign_message(
                &shares[i as usize],
                Some(namespace::ack(b"1234").as_slice()),
                &serializer::ack(&chunk2, epoch),
            );
            partials2.push(partial);
        }
        let threshold2 = ops::threshold_signature_recover(quorum, partials2).unwrap();
        let res = acks.add_threshold(&sequencer, height2, epoch, threshold2);
        assert!(res);

        // After adding height2, the old height1 entry should be pruned.
        assert_eq!(acks.get_threshold(&sequencer, height1), None);
        assert_eq!(
            acks.get_threshold(&sequencer, height2),
            Some((epoch, threshold2))
        );
    }

    #[test]
    fn test_chunk_different_epochs() {
        // Test that for the same sequencer and height, multiple epochs can be recorded,
        // and get_threshold returns the one with the highest epoch.
        let num_validators = 4;
        let quorum = 3;
        let (_, mut runtime, _) = Executor::default();
        let (_identity, shares) = generate_shares(&mut runtime, None, num_validators, quorum);
        let mut acks = AckManager::<sha256::Digest, ed25519::PublicKey>::new();

        let sequencer =
            ed25519::PublicKey::try_from(&[1u8; ed25519::PublicKey::SERIALIZED_LEN][..]).unwrap();
        let height = 30;
        let epoch1 = 1;
        let epoch2 = 2;

        // Use the same chunk (and thus payload) for both epochs.
        let chunk = safe::Chunk {
            sequencer: sequencer.clone(),
            height,
            payload: sha256::hash(b"chunk"),
        };

        // Generate threshold signature for epoch1.
        let mut partials1 = Vec::new();
        for i in 0..quorum {
            let partial = ops::partial_sign_message(
                &shares[i as usize],
                Some(namespace::ack(b"1234").as_slice()),
                &serializer::ack(&chunk, epoch1),
            );
            partials1.push(partial);
        }
        let threshold1 = ops::threshold_signature_recover(quorum, partials1).unwrap();
        let res1 = acks.add_threshold(&sequencer, height, epoch1, threshold1);
        assert!(res1);

        // Generate threshold signature for epoch2.
        let mut partials2 = Vec::new();
        for i in 0..quorum {
            let partial = ops::partial_sign_message(
                &shares[i as usize],
                Some(namespace::ack(b"1234").as_slice()),
                &serializer::ack(&chunk, epoch2),
            );
            partials2.push(partial);
        }
        let threshold2 = ops::threshold_signature_recover(quorum, partials2).unwrap();
        let res2 = acks.add_threshold(&sequencer, height, epoch2, threshold2);
        assert!(res2);

        // get_threshold should return the threshold for the highest epoch (epoch2).
        assert_eq!(
            acks.get_threshold(&sequencer, height),
            Some((epoch2, threshold2))
        );
    }

    #[test]
    fn test_add_threshold() {
        let num_validators = 4;
        let quorum = 3;
        let (_, mut runtime, _) = Executor::default();
        let (_identity, shares) = generate_shares(&mut runtime, None, num_validators, quorum);
        let mut acks = AckManager::<sha256::Digest, ed25519::PublicKey>::new();

        // Create ack
        let epoch = 99;
        let sequencer =
            ed25519::PublicKey::try_from(&[1u8; ed25519::PublicKey::SERIALIZED_LEN][..]).unwrap();
        let height = 42;
        let chunk = safe::Chunk {
            sequencer: sequencer.clone(),
            height,
            payload: sha256::hash(&sequencer),
        };

        // Create partials
        let mut partials = vec![];
        for i in 0..quorum {
            let p = ops::partial_sign_message(
                &shares[i as usize],
                Some(namespace::ack(b"1234").as_slice()),
                &serializer::ack(&chunk, epoch),
            );
            partials.push(p);
        }

        // Generate a threshold signature.
        let threshold = ops::threshold_signature_recover(quorum, partials).unwrap();

        // Get the threshold signature; it should not exist.
        let result = acks.get_threshold(&sequencer, height);
        assert_eq!(result, None);

        // Add the threshold signature.
        let result = acks.add_threshold(&sequencer, height, epoch, threshold);
        assert!(result);
        let result = acks.get_threshold(&sequencer, height);
        assert_eq!(result, Some((epoch, threshold)));

        // Add the threshold signature again.
        let result = acks.add_threshold(&sequencer, height, epoch, threshold);
        assert!(!result);
        let result = acks.get_threshold(&sequencer, height);
        assert_eq!(result, Some((epoch, threshold)));
    }
}

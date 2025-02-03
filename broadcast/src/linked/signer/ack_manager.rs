use crate::linked::Epoch;
use commonware_cryptography::{
    bls12381::primitives::{group, ops, poly::PartialSignature},
    Digest, PublicKey,
};
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Default)]
pub struct Partials<D: Digest> {
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
        Self::Partials(Partials::<D>::default())
    }
}

/// Manages acknowledgements for chunks.
#[derive(Default)]
pub struct AckManager<D: Digest> {
    // Acknowledgements for digests.
    //
    // Map from Sequencer => Height => Epoch => Evidence
    //
    // Evidence may be partial signatures or threshold signatures.
    //
    // The BTreeMaps are sorted by key, so we can prune old entries. In particular, we can prune
    // entries where the height is less than the height of the highest chunk for the sequencer.
    // We can often prune entries for old epochs as well.
    acks: HashMap<PublicKey, BTreeMap<u64, BTreeMap<Epoch, Evidence<D>>>>,
}

impl<D: Digest> AckManager<D> {
    /// Adds a partial signature to the evidence.
    ///
    /// If-and-only-if the quorum is newly-reached, the threshold signature is returned.
    pub fn add_partial(
        &mut self,
        sequencer: &PublicKey,
        height: u64,
        epoch: Epoch,
        payload_digest: &D,
        partial: &PartialSignature,
        quorum: u32,
    ) -> Option<group::Signature> {
        let evidence = self
            .acks
            .entry(sequencer.clone())
            .or_default()
            .entry(height)
            .or_default()
            .entry(epoch)
            .or_default();

        match evidence {
            Evidence::Threshold(_) => None,
            Evidence::Partials(p) => {
                if !p.shares.insert(partial.index) {
                    // Signer already existed
                    return None;
                }

                // Add the partial
                let partials = p.sigs.entry(payload_digest.clone()).or_default();
                partials.push(partial.clone());

                // Return early if no quorum
                if partials.len() < quorum as usize {
                    return None;
                }

                // Take ownership of the partials, which must exist
                let partials = p.sigs.remove(payload_digest).unwrap();

                // Construct the threshold signature
                let threshold = ops::threshold_signature_recover(quorum, partials).unwrap();
                Some(threshold)
            }
        }
    }

    /// Returns a tuple of (Epoch, Threshold), if it exists, for the given sequencer and height.
    ///
    /// If multiple epochs have thresholds, the highest epoch is returned.
    pub fn get_threshold(
        &self,
        sequencer: &PublicKey,
        height: u64,
    ) -> Option<(Epoch, group::Signature)> {
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
        sequencer: &PublicKey,
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

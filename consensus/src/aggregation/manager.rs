use super::types::{Ack, Epoch, Index};
use commonware_cryptography::{
    bls12381::primitives::{ops, variant::Variant},
    Digest,
};
use std::collections::{BTreeMap, HashMap};

enum Sig<V: Variant> {
    /// A partial signature
    Partials(HashMap<u32, V::Signature>),

    /// A threshold signature
    Threshold(V::Signature),
}

impl<V: Variant> Default for Sig<V> {
    fn default() -> Self {
        Self::Partials(HashMap::default())
    }
}

impl<V: Variant> Sig<V> {
    fn add_partial(&mut self, index: u32, signature: &V::Signature) -> Option<V::Signature> {
        // Check if the signature is already a threshold signature
        let Sig::Partials(partials) = self else {
            return None;
        };
    }
}

/// A map from a digest to a tree of signatures.
type SigsByEpoch<V: Variant> = BTreeMap<Epoch, Sig<V>>;

/// Evidence for a chunk.
/// This is either a set of partial signatures or a threshold signature.
enum Evidence<V: Variant, D: Digest> {
    Pending(BTreeMap<D, SigsByEpoch<V>>),
    Verified(D, SigsByEpoch<V>),
}

impl<V: Variant, D: Digest> Evidence<V, D> {
    fn pending() -> Self {
        Self::Pending(BTreeMap::default())
    }

    fn verified(digest: D) -> Self {
        Self::Verified(digest, BTreeMap::default())
    }

    fn verify(&mut self, digest: D) {
        let evidence = std::mem::take(self);
        match evidence {
            Evidence::Pending(mut pending) => {
                *self = Evidence::Verified(digest, pending.remove(&digest).unwrap_or_default())
            }
            Evidence::Verified(d, _) => assert_eq!(d, digest),
        }
    }
}

/// Manages acknowledgements for chunks.
#[derive(Default)]
pub struct Manager<V: Variant, D: Digest> {
    // ---------- Configuration ----------
    /// The quorum required to produce a threshold signature.
    quorum: u32,

    // ---------- State ----------
    /// The lowest index for which we do not have a threshold signature.
    next_unconfirmed: Index,

    /// The lowest index for which we have zero information. That is, we are not even waiting for a
    /// proposal for this index.
    next_empty: Index,

    /// TODO
    acks: BTreeMap<Index, Evidence<V, D>>,
}

impl<V: Variant, D: Digest> Manager<V, D> {
    /// Creates a new `Manager`.
    pub fn with_quorum(quorum: u32) -> Self {
        Self {
            quorum,
            next_unconfirmed: 0,
            next_empty: 0,
            acks: BTreeMap::default(),
        }
    }

    /// Adds a new pending entry for the given index.
    pub fn pending(&mut self, index: Index) {
        assert!(self.acks.insert(index, Evidence::pending()).is_none());
    }

    /// Verifies the digest for the given index.
    pub fn verify(&mut self, index: Index, digest: D) {
        self.acks
            .entry(index)
            .or_insert_with(|| Evidence::verified(digest))
            .verify(digest);
    }

    /// Adds a partial signature to the evidence.
    ///
    /// If-and-only-if the quorum is newly-reached, the threshold signature is returned.
    pub fn add_ack(&mut self, ack: &Ack<V, D>) -> Option<V::Signature> {
        match self.acks.get_mut(&ack.item.index) {
            None => return None,
            Some(Evidence::Pending(digests)) => {
                // Add the partial signature to the pending evidence
                let sigs = digests
                    .entry(ack.item.digest)
                    .or_insert_with(|| SigsByEpoch::default())
                    .entry(ack.epoch)
                    .or_insert_with(|| Sig::default());

                // Get partials
                let Sig::Partials(partials) = sigs else {
                    // Evidence is already a threshold signature, no need to process further
                    return None;
                };

                // Check if the partial signature is already present
                if partials.contains_key(&ack.signature.index) {
                    return None;
                }

                // Add the partial signature
                partials.insert(ack.signature.index, ack.signature.clone());

                // Don't attempt to construct the partial signature until the digest is verified
            }
            Some(Evidence::Verified(digest, epochs)) => {
                // Verify the digest
                if ack.item.digest != *digest {
                    return None;
                }

                epochs.entry(ack.epoch).or_insert_with(|| Sig::default());

                let Sig::Partials(partials) = sigs else {
                    // Evidence is already a threshold signature, no need to process further
                    return None;
                };
            }
        }
        let evidence = self
            .acks
            .entry(ack.item.index)
            .or_default()
            .entry(ack.epoch)
            .or_insert_with(|| Evidence::with_capacity(self.quorum as usize));

        let Evidence::Partials(partials) = evidence else {
            // Evidence is already a threshold signature, no need to process further
            return None;
        };

        // Check if the partial signature is already present
        if partials.contains_key(&ack.signature.index) {
            return None;
        }

        // Add the partial
        partials.insert(ack.signature.index, ack.signature.clone());

        // Return early if no quorum
        if partials.len() < self.quorum as usize {
            return None;
        }

        // Construct the threshold signature
        let threshold = ops::threshold_signature_recover(self.quorum, partials.values())
            .expect("Failed to recover threshold signature");
        Some(threshold)
    }

    /// Sets the threshold for the given height and epoch.
    /// Returns `true` if the threshold was newly set, `false` if it already existed.
    pub fn add_threshold(&mut self, index: Index, epoch: Epoch, threshold: V::Signature) -> bool {
        // Set the threshold.
        // If the threshold already existed, return false
        if let Some(Evidence::Threshold(_)) = self
            .acks
            .entry(index)
            .or_default()
            .insert(epoch, Evidence::Threshold(threshold))
        {
            return false;
        }

        // Prune all entries with index less than the parent
        //
        // This approach ensures we don't accidentally notify the application of a threshold signature multiple
        // times (which could otherwise occur if we recover the threshold signature for some chunk at tip and then
        // receive a duplicate broadcast of said chunk).
        let min_height = index.saturating_sub(1);
        self.acks.retain(|&h, _| h >= min_height);

        true
    }

    // Update the next unconfirmed index to the next available value.
    // Start searching from, but not including, the given index.
    pub fn update_next_unconfirmed(&mut self, index: Index) {
        let mut index = index;
        loop {
            index += 1;
            let confirmed = self
                .acks
                .get(&index)
                .is_some_and(|emap| emap.values().any(|e| matches!(e, Evidence::Threshold(_))));
            if !confirmed {
                self.next_unconfirmed = index;
                return;
            }
        }
    }

    /// Sets the `next_empty` value to the next available value. Start searching from, but not
    /// including, the given index.
    pub fn update_next_empty_from(&mut self, index: Index) {
        let mut index = index;
        loop {
            index += 1;
            if !self.acks.contains_key(&index) {
                self.next_empty = index;
                return;
            }
        }
    }

    /// Prune up-to-and-including the given index.
    pub fn prune(&mut self, index: Index) {
        // Prune old entries.
        self.acks.retain(|&h, _| h > index);

        // Update next values if we need to "fast-forward" them
        if self.next_empty <= index {
            self.update_next_empty_from(index);
        }
        if self.next_unconfirmed <= index {
            self.update_next_unconfirmed(index);
        }
    }

    // ---------- Getters ----------

    /// Returns a tuple of (Epoch, Threshold), if it exists, for the given height.
    ///
    /// If multiple epochs have thresholds, the highest epoch is returned.
    pub fn get_threshold(&self, index: Index) -> Option<(Epoch, V::Signature)> {
        self.acks.get(&index).and_then(|m| {
            // Reverse iterator to get the highest epoch first
            m.iter().rev().find_map(|(epoch, evidence)| match evidence {
                Evidence::Threshold(t) => Some((*epoch, *t)),
                _ => None,
            })
        })
    }

    /// Returns the index of the next unconfirmed index.
    pub fn next_unconfirmed(&self) -> Index {
        self.next_unconfirmed
    }

    /// Returns the index of the next empty index.
    ///
    /// This is the next index for which we do not have any information, which means that we have
    /// not even started requesting a proposal for this index.
    pub fn next_empty(&self) -> Index {
        self.next_empty
    }
}

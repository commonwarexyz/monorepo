use crate::linked::{wire, Epoch};
use bytes::Bytes;
use commonware_cryptography::{bls12381::primitives::group, Digest, PublicKey};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Evidence for a chunk.
/// This is either a set of partial signatures or a threshold signature.
pub enum Evidence {
    Partials(HashSet<Bytes>),
    Threshold(Box<group::Signature>),
}

impl Default for Evidence {
    fn default() -> Self {
        Self::Partials(HashSet::new())
    }
}

/// A chain represents a single sequencer's chain of chunks.
type Chain = BTreeMap<u64, HashMap<Digest, Evidence>>;

/// Manages acknowledgements for chunks.
#[derive(Default)]
pub struct AckManager {
    // Acknowledgements for digests.
    //
    // Map from Epoch => Sequencer => Height => PayloadDigest => Evidence
    //
    // Evidence may be partial signatures or threshold signatures.
    //
    // The BTreeMaps are sorted by key, so we can prune old entries. In particular, we can prune
    // entries where the height is less than the height of the highest chunk for the sequencer.
    // We can often prune entries for old epochs as well.
    acks: BTreeMap<Epoch, HashMap<PublicKey, Chain>>,
}

impl AckManager {
    /// Returns the evidence for the given epoch, sequencer, height, and chunk.
    /// If the evidence did not exist, it is initialized as an empty set of partials.
    pub fn get_or_init(&mut self, epoch: Epoch, chunk: &wire::Chunk) -> &mut Evidence {
        self.acks
            .entry(epoch)
            .or_default()
            .entry(chunk.sequencer.clone())
            .or_default()
            .entry(chunk.height)
            .or_default()
            .entry(chunk.payload_digest.clone())
            .or_default()
    }

    /// Prunes all entries (at the given epoch and sequencer) below the height (exclusive).
    pub fn prune_height(&mut self, epoch: Epoch, sequencer: &PublicKey, height: u64) {
        if let Some(m) = self.acks.get_mut(&epoch).and_then(|m| m.get_mut(sequencer)) {
            m.retain(|h, _| *h >= height);
        }
    }

    /// Prunes all entries below the given epoch (exclusive).
    pub fn prune_epoch(&mut self, epoch: Epoch) {
        self.acks.retain(|e, _| *e >= epoch);
    }
}

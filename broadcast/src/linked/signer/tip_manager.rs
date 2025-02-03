use crate::linked::wire;
use commonware_cryptography::PublicKey;
use std::collections::HashMap;

/// Manages the highest-height chunk for each sequencer.
#[derive(Default)]
pub struct TipManager {
    // The highest-height chunk for each sequencer.
    // The chunk must have the threshold signature of its parent.
    // Existence of the chunk implies:
    // - The existence of the sequencer's entire chunk chain (from height zero)
    // - That the chunk has been acked by this signer.
    tips: HashMap<PublicKey, wire::Link>,
}

impl TipManager {
    /// Inserts a new tip. Returns true if the tip is new.
    /// Panics if the new tip is lower-height than the existing tip.
    pub fn put(&mut self, link: &wire::Link) -> bool {
        let new_chunk = link.chunk.as_ref().unwrap();
        let old = self
            .tips
            .insert(link.chunk.as_ref().unwrap().sequencer.clone(), link.clone());

        // Validate that the replacement is valid
        if let Some(old) = old {
            let old_chunk = old.chunk.as_ref().unwrap();
            // New chunk cannot be lower
            if old_chunk.height > new_chunk.height {
                panic!("Attempted to insert a lower-height tip");
            }
            // New chunk cannot be the same height with a different payload
            if old_chunk.height == new_chunk.height {
                assert!(old_chunk.payload_digest == new_chunk.payload_digest);
                return false;
            }
            return true;
        }

        true
    }

    /// Returns the tip for the given sequencer.
    pub fn get(&self, sequencer: &PublicKey) -> Option<wire::Link> {
        self.tips.get(sequencer).cloned()
    }

    /// Returns just the chunk for the given sequencer.
    pub fn get_chunk(&self, sequencer: &PublicKey) -> Option<wire::Chunk> {
        self.tips.get(sequencer).and_then(|link| link.chunk.clone())
    }

    /// Returns the height of the tip for the given sequencer.
    pub fn get_height(&self, sequencer: &PublicKey) -> Option<u64> {
        self.tips
            .get(sequencer)
            .map(|link| link.chunk.as_ref().unwrap().height)
    }
}

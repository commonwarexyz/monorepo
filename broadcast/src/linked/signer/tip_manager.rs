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
    /// Inserts a new tip.
    pub fn put(&mut self, link: wire::Link) {
        let new_height = link.chunk.as_ref().unwrap().height;
        let old = self
            .tips
            .insert(link.chunk.as_ref().unwrap().sequencer.clone(), link);
        if let Some(old) = old {
            if old.chunk.as_ref().unwrap().height > new_height {
                panic!("Attempted to insert a lower-height tip");
            }
        }
    }

    /// Returns the tip for the given sequencer.
    pub fn get(&self, sequencer: &PublicKey) -> Option<wire::Link> {
        self.tips.get(sequencer).cloned()
    }

    /// Returns just the chunk for the given sequencer.
    pub fn get_chunk(&self, sequencer: &PublicKey) -> Option<wire::Chunk> {
        self.tips.get(sequencer).and_then(|link| link.chunk.clone())
    }
}

use crate::linked::wire;
use commonware_cryptography::Array;
use std::collections::HashMap;

/// Manages the highest-height chunk for each sequencer.
#[derive(Default)]
pub struct TipManager<P: Array> {
    // The highest-height chunk for each sequencer.
    // The chunk must have the threshold signature of its parent.
    // Existence of the chunk implies:
    // - The existence of the sequencer's entire chunk chain (from height zero)
    // - That the chunk has been acked by this signer.
    tips: HashMap<P, wire::Link>,
}

impl<P: Array> TipManager<P> {
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
                assert!(old_chunk.payload == new_chunk.payload);
                return false;
            }
            return true;
        }

        true
    }

    /// Returns the tip for the given sequencer.
    pub fn get(&self, sequencer: &P) -> Option<wire::Link> {
        self.tips.get(sequencer).cloned()
    }

    /// Returns just the chunk for the given sequencer.
    pub fn get_chunk(&self, sequencer: &P) -> Option<wire::Chunk> {
        self.tips.get(sequencer).and_then(|link| link.chunk.clone())
    }

    /// Returns the height of the tip for the given sequencer.
    pub fn get_height(&self, sequencer: &P) -> Option<u64> {
        self.tips
            .get(sequencer)
            .map(|link| link.chunk.as_ref().unwrap().height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linked::wire;
    use commonware_cryptography::Array;

    // Helper to create a dummy link.
    fn create_link<P: Array>(sequencer: P, height: u64, payload: &[u8]) -> wire::Link {
        wire::Link {
            chunk: Some(wire::Chunk {
                sequencer,
                height,
                payload: payload.to_vec(),
            }),
            signature: bytes::Bytes::new(),
            parent: None,
        }
    }

    // Helper to create a dummy PublicKey.
    // (Assuming PublicKey implements From<Vec<u8>>.)
    fn test_public_key<P: Array>(id: u8) -> P {
        P::from(vec![id])
    }

    #[test]
    fn test_put_new_tip() {
        let mut manager = TipManager::default();
        let key = test_public_key(1);
        let link = create_link(key.clone(), 1, b"payload");
        // Inserting a new tip returns true.
        assert!(manager.put(&link));
        // Getting the tip returns the same link.
        assert_eq!(manager.get(&key), Some(link.clone()));
        // The chunk and height can be retrieved as expected.
        let chunk = link.chunk.clone().unwrap();
        assert_eq!(manager.get_chunk(&key), Some(chunk.clone()));
        assert_eq!(manager.get_height(&key), Some(chunk.height));
    }

    #[test]
    fn test_put_same_height_same_payload() {
        let mut manager = TipManager::default();
        let key = test_public_key(2);
        let link1 = create_link(key.clone(), 1, b"payload");
        assert!(manager.put(&link1));
        // Inserting a tip with the same height and same payload returns false.
        let link2 = create_link(key.clone(), 1, b"payload");
        assert!(!manager.put(&link2));
        assert_eq!(manager.get_height(&key), Some(1));
    }

    #[test]
    fn test_put_higher_tip() {
        let mut manager = TipManager::default();
        let key = test_public_key(3);
        let link1 = create_link(key.clone(), 1, b"payload1");
        assert!(manager.put(&link1));
        // Inserting a tip with a higher height should return true.
        let link2 = create_link(key.clone(), 2, b"payload2");
        assert!(manager.put(&link2));
        assert_eq!(manager.get_height(&key), Some(2));
        assert_eq!(manager.get(&key), Some(link2));
    }

    #[test]
    #[should_panic(expected = "Attempted to insert a lower-height tip")]
    fn test_put_lower_tip_panics() {
        let mut manager = TipManager::default();
        let key = test_public_key(4);
        let link1 = create_link(key.clone(), 2, b"payload");
        assert!(manager.put(&link1));
        // Inserting a tip with a lower height should panic.
        let link2 = create_link(key.clone(), 1, b"payload");
        manager.put(&link2);
    }

    #[test]
    #[should_panic]
    fn test_put_same_height_different_payload_panics() {
        let mut manager = TipManager::default();
        let key = test_public_key(5);
        let link1 = create_link(key.clone(), 1, b"payload1");
        assert!(manager.put(&link1));
        // Inserting a tip with the same height but a different payload should panic.
        let link2 = create_link(key.clone(), 1, b"payload2");
        manager.put(&link2);
    }

    #[test]
    fn test_get_nonexistent() {
        let manager = TipManager::default();
        let key = test_public_key(6);
        // For a sequencer with no tip, all getters return None.
        assert_eq!(manager.get(&key), None);
        assert_eq!(manager.get_chunk(&key), None);
        assert_eq!(manager.get_height(&key), None);
    }
}

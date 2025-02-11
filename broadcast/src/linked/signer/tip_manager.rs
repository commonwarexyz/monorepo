use crate::linked::safe;
use commonware_cryptography::{Array, Scheme};
use std::collections::HashMap;

/// Manages the highest-height chunk for each sequencer.
#[derive(Default, Debug)]
pub struct TipManager<C: Scheme, D: Array> {
    // The highest-height chunk for each sequencer.
    // The chunk must have the threshold signature of its parent.
    // Existence of the chunk implies:
    // - The existence of the sequencer's entire chunk chain (from height zero)
    // - That the chunk has been acked by this signer.
    tips: HashMap<C::PublicKey, safe::Link<C, D>>,
}

impl<C: Scheme, D: Array> TipManager<C, D> {
    /// Creates a new `TipManager`.
    pub fn new() -> Self {
        Self {
            tips: HashMap::new(),
        }
    }

    /// Inserts a new tip. Returns true if the tip is new.
    /// Panics if the new tip is lower-height than the existing tip.
    pub fn put(&mut self, link: &safe::Link<C, D>) -> bool {
        let old = self.tips.insert(link.chunk.sequencer.clone(), link.clone());

        // Validate that the replacement is valid
        if let Some(old) = old {
            // New chunk cannot be lower
            if old.chunk.height > link.chunk.height {
                panic!("Attempted to insert a lower-height tip");
            }
            // New chunk cannot be the same height with a different payload
            if old.chunk.height == link.chunk.height {
                assert!(old.chunk.payload == link.chunk.payload);
                return false;
            }
            return true;
        }

        true
    }

    /// Returns the tip for the given sequencer.
    pub fn get(&self, sequencer: &C::PublicKey) -> Option<safe::Link<C, D>> {
        self.tips.get(sequencer).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linked::safe;
    use bytes::Bytes;
    use commonware_cryptography::{
        ed25519::{self, Ed25519},
        sha256::{self, Digest},
        Array,
    };
    use commonware_utils::SizedSerialize;
    use rand::SeedableRng;

    /// Helper to create a dummy link.
    fn create_link<C: Scheme, D: Array>(
        sequencer: C::PublicKey,
        height: u64,
        payload: D,
    ) -> safe::Link<C, D> {
        let signature = {
            let mut data = Bytes::from(vec![3u8; C::Signature::SERIALIZED_LEN]);
            C::Signature::read_from(&mut data).unwrap()
        };
        safe::Link {
            chunk: safe::Chunk {
                sequencer,
                height,
                payload,
            },
            signature,
            parent: None,
        }
    }

    /// Generates a deterministic public key for testing.
    fn test_public_key(seed: u64) -> ed25519::PublicKey {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        ed25519::Ed25519::new(&mut rng).public_key()
    }

    #[test]
    fn test_put_new_tip() {
        let mut manager = TipManager::<Ed25519, Digest>::new();
        let key = test_public_key(1);
        let link = create_link(key.clone(), 1, sha256::hash(b"payload"));
        // Inserting a new tip returns true.
        assert!(manager.put(&link));
        // Getting the tip returns the same link.
        let got = manager.get(&key).unwrap();
        assert_eq!(got.chunk, link.chunk);
        assert_eq!(got.signature, link.signature);
        assert_eq!(got.parent, link.parent);
    }

    #[test]
    fn test_put_same_height_same_payload() {
        let mut manager = TipManager::<Ed25519, Digest>::new();
        let key = test_public_key(2);
        let link = create_link(key.clone(), 1, sha256::hash(b"payload"));
        assert!(manager.put(&link));
        // Inserting a tip with the same height and same payload returns false.
        assert!(!manager.put(&link));
        let got = manager.get(&key).unwrap();
        assert_eq!(got.chunk, link.chunk);
        assert_eq!(got.signature, link.signature);
        assert_eq!(got.parent, link.parent);
    }

    #[test]
    fn test_put_higher_tip() {
        let mut manager = TipManager::<Ed25519, Digest>::new();
        let key = test_public_key(3);
        let link1 = create_link(key.clone(), 1, sha256::hash(b"payload1"));
        assert!(manager.put(&link1));
        // Inserting a tip with a higher height should return true.
        let link2 = create_link(key.clone(), 2, sha256::hash(b"payload2"));
        assert!(manager.put(&link2));
        let got = manager.get(&key).unwrap();
        assert_eq!(got.chunk, link2.chunk);
        assert_eq!(got.signature, link2.signature);
        assert_eq!(got.parent, link2.parent);
    }

    #[test]
    #[should_panic(expected = "Attempted to insert a lower-height tip")]
    fn test_put_lower_tip_panics() {
        let mut manager = TipManager::<Ed25519, Digest>::new();
        let key = test_public_key(4);
        let link1 = create_link(key.clone(), 2, sha256::hash(b"payload"));
        assert!(manager.put(&link1));
        // Inserting a tip with a lower height should panic.
        let link2 = create_link(key.clone(), 1, sha256::hash(b"payload"));
        manager.put(&link2);
    }

    #[test]
    #[should_panic]
    fn test_put_same_height_different_payload_panics() {
        let mut manager = TipManager::<Ed25519, Digest>::new();
        let key = test_public_key(5);
        let link1 = create_link(key.clone(), 1, sha256::hash(b"payload1"));
        assert!(manager.put(&link1));
        // Inserting a tip with the same height but a different payload should panic.
        let link2 = create_link(key.clone(), 1, sha256::hash(b"payload2"));
        manager.put(&link2);
    }

    #[test]
    fn test_get_nonexistent() {
        let manager = TipManager::<Ed25519, Digest>::new();
        let key = test_public_key(6);
        assert!(manager.get(&key).is_none());
    }
}

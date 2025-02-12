use crate::linked::canon;
use commonware_cryptography::{Array, Scheme};
use std::collections::{hash_map::Entry, HashMap};

/// Manages the highest-height chunk for each sequencer.
#[derive(Default, Debug)]
pub struct TipManager<C: Scheme, D: Array> {
    // The highest-height chunk for each sequencer.
    // The chunk must have the threshold signature of its parent.
    // Existence of the chunk implies:
    // - The existence of the sequencer's entire chunk chain (from height zero)
    // - That the chunk has been acked by this signer.
    tips: HashMap<C::PublicKey, canon::Link<C, D>>,
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
    pub fn put(&mut self, link: &canon::Link<C, D>) -> bool {
        match self.tips.entry(link.chunk.sequencer.clone()) {
            Entry::Vacant(e) => {
                e.insert(link.clone());
                true
            }
            Entry::Occupied(mut e) => {
                let old = e.get();
                if old.chunk.height > link.chunk.height {
                    panic!("Attempted to insert a lower-height tip");
                }
                if old.chunk.height == link.chunk.height {
                    assert!(
                        old.chunk.payload == link.chunk.payload,
                        "New tip has the same height but a different payload"
                    );
                    return false;
                }
                e.insert(link.clone());
                true
            }
        }
    }

    /// Returns the tip for the given sequencer.
    pub fn get(&self, sequencer: &C::PublicKey) -> Option<canon::Link<C, D>> {
        self.tips.get(sequencer).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linked::canon;
    use bytes::Bytes;
    use commonware_cryptography::{
        ed25519::{self, Ed25519, PublicKey, Signature},
        sha256::{self, Digest},
        Array,
    };
    use commonware_utils::SizedSerialize;
    use rand::SeedableRng;

    /// Helper functions for TipManager tests.
    mod helpers {
        use super::*;

        /// Creates a dummy link for testing.
        pub fn create_dummy_link(
            sequencer: PublicKey,
            height: u64,
            payload: &str,
        ) -> canon::Link<Ed25519, Digest> {
            let signature = {
                let mut data = Bytes::from(vec![3u8; Signature::SERIALIZED_LEN]);
                Signature::read_from(&mut data).unwrap()
            };
            canon::Link::<Ed25519, Digest> {
                chunk: canon::Chunk {
                    sequencer,
                    height,
                    payload: sha256::hash(payload.as_bytes()),
                },
                signature,
                parent: None,
            }
        }

        /// Generates a deterministic public key for testing using the provided seed.
        pub fn deterministic_public_key(seed: u64) -> ed25519::PublicKey {
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            ed25519::Ed25519::new(&mut rng).public_key()
        }

        /// Inserts a tip into the given TipManager and returns the inserted link.
        pub fn insert_tip(
            manager: &mut TipManager<Ed25519, Digest>,
            key: ed25519::PublicKey,
            height: u64,
            payload: &str,
        ) -> canon::Link<Ed25519, Digest> {
            let link = create_dummy_link(key.clone(), height, payload);
            manager.put(&link);
            link
        }
    }

    /// Different payloads for the same sequencer and height produce distinct thresholds.
    #[test]
    fn test_put_new_tip() {
        let mut manager = TipManager::<Ed25519, Digest>::new();
        let key = helpers::deterministic_public_key(1);
        let link = helpers::create_dummy_link(key.clone(), 1, "payload");
        assert!(manager.put(&link));
        let got = manager.get(&key).unwrap();
        assert_eq!(got.chunk, link.chunk);
        assert_eq!(got.signature, link.signature);
        assert_eq!(got.parent, link.parent);
    }

    /// Inserting a tip with the same height and payload returns false.
    #[test]
    fn test_put_same_height_same_payload() {
        let mut manager = TipManager::<Ed25519, Digest>::new();
        let key = helpers::deterministic_public_key(2);
        let link = helpers::create_dummy_link(key.clone(), 1, "payload");
        assert!(manager.put(&link));
        assert!(!manager.put(&link));
        let got = manager.get(&key).unwrap();
        assert_eq!(got.chunk, link.chunk);
        assert_eq!(got.signature, link.signature);
        assert_eq!(got.parent, link.parent);
    }

    /// Inserting a tip with a higher height updates the stored tip.
    #[test]
    fn test_put_higher_tip() {
        let mut manager = TipManager::<Ed25519, Digest>::new();
        let key = helpers::deterministic_public_key(3);
        let link1 = helpers::create_dummy_link(key.clone(), 1, "payload1");
        assert!(manager.put(&link1));
        let link2 = helpers::create_dummy_link(key.clone(), 2, "payload2");
        assert!(manager.put(&link2));
        let got = manager.get(&key).unwrap();
        assert_eq!(got.chunk, link2.chunk);
        assert_eq!(got.signature, link2.signature);
        assert_eq!(got.parent, link2.parent);
    }

    /// Inserting a tip with a lower height panics.
    #[test]
    #[should_panic(expected = "Attempted to insert a lower-height tip")]
    fn test_put_lower_tip_panics() {
        let mut manager = TipManager::<Ed25519, Digest>::new();
        let key = helpers::deterministic_public_key(4);
        let link1 = helpers::create_dummy_link(key.clone(), 2, "payload");
        assert!(manager.put(&link1));
        let link2 = helpers::create_dummy_link(key.clone(), 1, "payload");
        manager.put(&link2);
    }

    /// Inserting a tip with the same height but different payload panics.
    #[test]
    #[should_panic]
    fn test_put_same_height_different_payload_panics() {
        let mut manager = TipManager::<Ed25519, Digest>::new();
        let key = helpers::deterministic_public_key(5);
        let link1 = helpers::create_dummy_link(key.clone(), 1, "payload1");
        assert!(manager.put(&link1));
        let link2 = helpers::create_dummy_link(key.clone(), 1, "payload2");
        manager.put(&link2);
    }

    /// Getting a tip for a nonexistent sequencer returns None.
    #[test]
    fn test_get_nonexistent() {
        let manager = TipManager::<Ed25519, Digest>::new();
        let key = helpers::deterministic_public_key(6);
        assert!(manager.get(&key).is_none());
    }

    /// Multiple sequencers are handled independently.
    #[test]
    fn test_multiple_sequencers() {
        let mut manager = TipManager::<Ed25519, Digest>::new();
        let key1 = helpers::deterministic_public_key(10);
        let key2 = helpers::deterministic_public_key(20);
        let link1 = helpers::insert_tip(&mut manager, key1.clone(), 1, "payload1");
        let link2 = helpers::insert_tip(&mut manager, key2.clone(), 2, "payload2");

        let got1 = manager.get(&key1).unwrap();
        let got2 = manager.get(&key2).unwrap();
        assert_eq!(got1.chunk, link1.chunk);
        assert_eq!(got2.chunk, link2.chunk);
    }

    /// Multiple updates for the same sequencer yield the tip with the highest height.
    #[test]
    fn test_put_multiple_updates() {
        let mut manager = TipManager::<Ed25519, Digest>::new();
        let key = helpers::deterministic_public_key(7);

        // Insert tip with height 1.
        let link1 = helpers::insert_tip(&mut manager, key.clone(), 1, "payload1");
        let got1 = manager.get(&key).unwrap();
        assert_eq!(got1.chunk.height, 1);
        assert_eq!(got1.chunk.payload, link1.chunk.payload);

        // Insert tip with height 2.
        let link2 = helpers::insert_tip(&mut manager, key.clone(), 2, "payload2");
        let got2 = manager.get(&key).unwrap();
        assert_eq!(got2.chunk.height, 2);
        assert_eq!(got2.chunk.payload, link2.chunk.payload);

        // Insert tip with height 3.
        let link3 = helpers::insert_tip(&mut manager, key.clone(), 3, "payload3");
        let got3 = manager.get(&key).unwrap();
        assert_eq!(got3.chunk.height, 3);
        assert_eq!(got3.chunk.payload, link3.chunk.payload);

        // Re-inserting the same tip should return false.
        assert!(!manager.put(&link3));

        // Insert tip with height 4.
        let link4 = helpers::insert_tip(&mut manager, key.clone(), 4, "payload4");
        let got4 = manager.get(&key).unwrap();
        assert_eq!(got4.chunk.height, 4);
        assert_eq!(got4.chunk.payload, link4.chunk.payload);
    }
}

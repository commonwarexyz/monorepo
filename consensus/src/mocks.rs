use crate::{Hash, Height, Payload, HASH_LENGTH};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_utils::{hash, hex};
use futures::{channel::mpsc, SinkExt};
use std::collections::HashMap;

const GENESIS_BYTES: &[u8] = b"genesis";

pub enum Progress {
    Notarized(Height),
    Finalized(Height),
}

pub struct Application {
    participant: PublicKey,

    verified: HashMap<Hash, Height>,
    finalized: HashMap<Hash, Height>,

    progress: mpsc::UnboundedSender<(PublicKey, Progress)>,
}

impl Application {
    pub fn new(
        participant: PublicKey,
        sender: mpsc::UnboundedSender<(PublicKey, Progress)>,
    ) -> Self {
        Self {
            participant,
            verified: HashMap::new(),
            finalized: HashMap::new(),
            progress: sender,
        }
    }

    fn verify_payload(height: Height, payload: &Payload) {
        if payload.len() != HASH_LENGTH + 8 {
            panic!("invalid payload length");
        }
        let parsed_height = Height::from_be_bytes(payload[HASH_LENGTH..].try_into().unwrap());
        if parsed_height != height {
            panic!("invalid height");
        }
    }
}

impl crate::Application for Application {
    fn genesis(&mut self) -> (Hash, Payload) {
        let payload = Bytes::from(GENESIS_BYTES);
        let hash = hash(&payload);
        self.verified.insert(hash.clone(), 0);
        self.finalized.insert(hash.clone(), 0);
        (hash, payload)
    }

    async fn propose(&mut self, parent: Hash, height: Height) -> Option<Payload> {
        if parent.len() != HASH_LENGTH {
            panic!("invalid parent hash length");
        }
        let parent = self.verified.get(&parent).expect("parent not verified");
        if parent + 1 != height {
            panic!("invalid height");
        }
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.participant);
        payload.extend_from_slice(&height.to_be_bytes());
        Some(Bytes::from(payload))
    }

    fn parse(&self, parent: Hash, height: Height, payload: Payload) -> Option<Hash> {
        if parent.len() != HASH_LENGTH {
            panic!("invalid parent hash length");
        }
        Self::verify_payload(height, &payload);
        Some(hash(&payload))
    }

    async fn verify(&mut self, parent: Hash, height: Height, payload: Payload, hash: Hash) -> bool {
        if parent.len() != HASH_LENGTH {
            panic!("invalid parent hash length");
        }
        if hash.len() != HASH_LENGTH {
            panic!("invalid hash length");
        }
        if let Some(height) = self.verified.get(&hash) {
            panic!("hash already verified: {}:{:?}", height, hex(&hash));
        }
        Self::verify_payload(height, &payload);
        let parent = match self.verified.get(&parent) {
            Some(parent) => parent,
            None => {
                panic!("parent not verified: {}:{:?}", height, hex(&parent));
            }
        };
        if parent + 1 != height {
            panic!("invalid height");
        }
        self.verified.insert(hash.clone(), height);
        true
    }

    async fn notarized(&mut self, hash: Hash) {
        if hash.len() != HASH_LENGTH {
            panic!("invalid hash length");
        }
        let height = self.verified.get(&hash).expect("hash not verified");
        if self.finalized.contains_key(&hash) {
            panic!("hash already finalized");
        }
        let _ = self
            .progress
            .send((self.participant.clone(), Progress::Notarized(*height)))
            .await;
    }

    async fn finalized(&mut self, hash: Hash) {
        if hash.len() != HASH_LENGTH {
            panic!("invalid hash length");
        }
        if let Some(height) = self.finalized.get(&hash) {
            panic!("hash already finalized: {}:{:?}", height, hex(&hash));
        }
        let height = self.verified.get(&hash).expect("hash not verified");
        self.finalized.insert(hash, *height);
        let _ = self
            .progress
            .send((self.participant.clone(), Progress::Finalized(*height)))
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Application as _;
    use commonware_cryptography::{Ed25519, Scheme};
    use futures::{executor::block_on, StreamExt};

    #[test]
    fn test_normal_flow() {
        block_on(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let (sender, mut receiver) = mpsc::unbounded();
            let mut app = Application::new(participant.clone(), sender);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Propose a block at height 1
            let parent = genesis_hash.clone();
            let height = 1;
            let payload = app
                .propose(parent.clone(), height)
                .await
                .expect("propose failed");

            // Parse the payload to get the hash
            let hash = app
                .parse(parent.clone(), height, payload.clone())
                .expect("parse failed");

            // Verify the block
            let verified = app
                .verify(parent.clone(), height, payload.clone(), hash.clone())
                .await;
            assert!(verified);

            // Notarize the block
            app.notarized(hash.clone()).await;

            // Expect a progress message for notarization
            let (progress_participant, progress) =
                receiver.next().await.expect("no progress message");
            assert_eq!(progress_participant, participant);
            match progress {
                Progress::Notarized(h) => {
                    assert_eq!(h, height);
                }
                _ => panic!("expected Notarized progress"),
            }

            // Finalize the block
            app.finalized(hash.clone()).await;

            // Expect a progress message for finalization
            let (progress_participant, progress) =
                receiver.next().await.expect("no progress message");
            assert_eq!(progress_participant, participant);
            match progress {
                Progress::Finalized(h) => {
                    assert_eq!(h, height);
                }
                _ => panic!("expected Finalized progress"),
            }
        });
    }

    #[test]
    #[should_panic(expected = "parent not verified")]
    fn test_propose_invalid_parent() {
        block_on(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let (sender, _) = mpsc::unbounded();
            let mut app = Application::new(participant, sender);

            // Create an invalid parent hash
            let invalid_parent = hash(&Bytes::from_static(b"invalid"));

            // Attempt to propose a block with invalid parent, should panic
            let height = 1;
            app.propose(invalid_parent.clone(), height).await;
        });
    }

    #[test]
    #[should_panic(expected = "invalid height")]
    fn test_propose_invalid_height() {
        block_on(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let (sender, _) = mpsc::unbounded();
            let mut app = Application::new(participant, sender);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Propose a block at height 1
            let parent = genesis_hash.clone();
            let height = 100;
            app.propose(parent.clone(), height)
                .await
                .expect("propose failed");
        });
    }

    #[test]
    #[should_panic(expected = "invalid height")]
    fn test_verify_invalid_height() {
        block_on(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let (sender, _) = mpsc::unbounded();
            let mut app = Application::new(participant, sender);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Propose a block at height 1
            let parent = genesis_hash.clone();
            let height = 1;
            let payload = app
                .propose(parent.clone(), height)
                .await
                .expect("propose failed");

            // Parse the payload to get the hash
            let hash = app
                .parse(parent.clone(), height, payload.clone())
                .expect("parse failed");

            // Attempt to verify the block with incorrect height (e.g., height 2)
            let invalid_height = 2;
            app.verify(
                parent.clone(),
                invalid_height,
                payload.clone(),
                hash.clone(),
            )
            .await;
        });
    }

    #[test]
    #[should_panic(expected = "parent not verified")]
    fn test_verify_unverified_parent() {
        block_on(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let (sender, _) = mpsc::unbounded();
            let mut app = Application::new(participant, sender);

            // Create an unverified parent hash
            let unverified_parent = hash(&Bytes::from_static(b"unverified_parent"));

            // Manually create a payload for height 1
            let height: Height = 1;
            let mut payload = Vec::new();
            payload.extend_from_slice(&app.participant);
            payload.extend_from_slice(&height.to_be_bytes());
            let payload = Bytes::from(payload);

            // Parse the payload to get the hash
            let hash = app
                .parse(unverified_parent.clone(), height, payload.clone())
                .expect("parse failed");

            // Attempt to verify the block, should panic
            app.verify(
                unverified_parent.clone(),
                height,
                payload.clone(),
                hash.clone(),
            )
            .await;
        });
    }

    #[test]
    #[should_panic(expected = "invalid payload length")]
    fn test_verify_payload_invalid_length() {
        block_on(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let (sender, _) = mpsc::unbounded();
            let mut app = Application::new(participant, sender);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Create a payload with invalid length
            let height = 1;
            let invalid_payload = Bytes::from_static(b"short");

            // Attempt to parse the payload, should panic
            app.parse(genesis_hash.clone(), height, invalid_payload.clone());
        });
    }

    #[test]
    #[should_panic(expected = "hash already verified")]
    fn test_verify_same_hash_twice() {
        block_on(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let (sender, _) = mpsc::unbounded();
            let mut app = Application::new(participant, sender);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Propose a block at height 1
            let parent = genesis_hash.clone();
            let height = 1;
            let payload = app
                .propose(parent.clone(), height)
                .await
                .expect("propose failed");

            // Parse the payload to get the hash
            let hash = app
                .parse(parent.clone(), height, payload.clone())
                .expect("parse failed");

            // Verify the block
            app.verify(parent.clone(), height, payload.clone(), hash.clone())
                .await;

            // Attempt to verify the same block again, should panic
            app.verify(parent.clone(), height, payload.clone(), hash.clone())
                .await;
        });
    }

    #[test]
    #[should_panic(expected = "hash already finalized")]
    fn test_notarize_after_finalize() {
        block_on(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let (sender, _) = mpsc::unbounded();
            let mut app = Application::new(participant, sender);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Propose a block at height 1
            let parent = genesis_hash.clone();
            let height = 1;
            let payload = app
                .propose(parent.clone(), height)
                .await
                .expect("propose failed");

            // Parse the payload to get the hash
            let hash = app
                .parse(parent.clone(), height, payload.clone())
                .expect("parse failed");

            // Verify the block
            let verified = app
                .verify(parent.clone(), height, payload.clone(), hash.clone())
                .await;
            assert!(verified);

            // Notarize and finalize the block
            app.notarized(hash.clone()).await;
            app.finalized(hash.clone()).await;

            // Attempt to notarize the block again, should panic
            app.notarized(hash.clone()).await;
        });
    }

    #[test]
    #[should_panic(expected = "hash not verified")]
    fn test_notarization_not_verified() {
        block_on(async move {
            let (sender, _) = mpsc::unbounded();
            let mut app = Application::new(PublicKey::default(), sender);
            app.notarized(hash(&Bytes::from_static(b"hello"))).await;
        });
    }

    #[test]
    #[should_panic(expected = "invalid hash length")]
    fn test_notarization_invalid_hash() {
        block_on(async move {
            let (sender, _) = mpsc::unbounded();
            let mut app = Application::new(PublicKey::default(), sender);
            app.notarized(Bytes::from_static(b"hello")).await;
        });
    }

    #[test]
    #[should_panic(expected = "hash already finalized")]
    fn test_notarization_genesis_block() {
        block_on(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let (sender, _) = mpsc::unbounded();
            let mut app = Application::new(participant, sender);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Attempt to finalize the genesis block, should panic
            app.notarized(genesis_hash.clone()).await;
        });
    }

    #[test]
    #[should_panic(expected = "hash not verified")]
    fn test_finalization_not_verified() {
        block_on(async move {
            let (sender, _) = mpsc::unbounded();
            let mut app = Application::new(PublicKey::default(), sender);
            app.finalized(hash(&Bytes::from_static(b"hello"))).await;
        });
    }

    #[test]
    #[should_panic(expected = "invalid hash length")]
    fn test_finalization_invalid_hash() {
        block_on(async move {
            let (sender, _) = mpsc::unbounded();
            let mut app = Application::new(PublicKey::default(), sender);
            app.finalized(Bytes::from_static(b"hello")).await;
        });
    }

    #[test]
    #[should_panic(expected = "hash already finalized")]
    fn test_finalization_genesis_block() {
        block_on(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let (sender, _) = mpsc::unbounded();
            let mut app = Application::new(participant, sender);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Attempt to finalize the genesis block, should panic
            app.finalized(genesis_hash.clone()).await;
        });
    }
}

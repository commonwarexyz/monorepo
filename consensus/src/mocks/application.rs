use crate::{Hash, Height, Payload, HASH_LENGTH};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_runtime::Clock;
use commonware_utils::{hash, hex};
use futures::{channel::mpsc, SinkExt};
use rand::RngCore;
use rand_distr::{Distribution, Normal};
use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

const GENESIS_BYTES: &[u8] = b"genesis";

type Latency = (f64, f64);

pub struct Config {
    /// The public key of the participant.
    ///
    /// It is common to use multiple instances of an application in a single simulation, this
    /// helps to identify the source of both progress and errors.
    pub participant: PublicKey,
    pub sender: mpsc::UnboundedSender<(PublicKey, Progress)>,

    pub propose_latency: Latency,
    pub parse_latency: Latency,
    pub verify_latency: Latency,
}

pub enum Progress {
    Notarized(Height, Hash),
    Finalized(Height, Hash),
}

pub struct Application<E: Clock + RngCore> {
    runtime: E,

    participant: PublicKey,
    progress: mpsc::UnboundedSender<(PublicKey, Progress)>,

    propose_latency: Normal<f64>,
    parse_latency: Normal<f64>,
    verify_latency: Normal<f64>,

    parsed: HashSet<Hash>,
    verified: HashMap<Hash, Height>,
    last_finalized: u64,
    finalized: HashMap<Hash, Height>,
}

impl<E: Clock + RngCore> Application<E> {
    pub fn new(runtime: E, cfg: Config) -> Self {
        // Generate samplers
        let propose_latency = Normal::new(cfg.propose_latency.0, cfg.propose_latency.1).unwrap();
        let parse_latency = Normal::new(cfg.parse_latency.0, cfg.parse_latency.1).unwrap();
        let verify_latency = Normal::new(cfg.verify_latency.0, cfg.verify_latency.1).unwrap();
        Self {
            runtime,

            participant: cfg.participant,
            progress: cfg.sender,

            propose_latency,
            parse_latency,
            verify_latency,

            parsed: HashSet::new(),
            verified: HashMap::new(),
            last_finalized: 0,
            finalized: HashMap::new(),
        }
    }

    fn verify_payload(height: Height, payload: &Payload) {
        let parsed_height = Height::from_be_bytes(payload[HASH_LENGTH..].try_into().unwrap());
        if parsed_height != height {
            panic!("invalid height");
        }
    }

    fn panic(&self, msg: &str) {
        panic!("[{}] {}", hex(&self.participant), msg);
    }
}

impl<E: Clock + RngCore> crate::Application for Application<E> {
    fn genesis(&mut self) -> (Hash, Payload) {
        let payload = Bytes::from(GENESIS_BYTES);
        let hash = hash(&payload);
        self.parsed.insert(hash.clone());
        self.verified.insert(hash.clone(), 0);
        self.finalized.insert(hash.clone(), 0);
        (hash, payload)
    }

    async fn propose(&mut self, parent: Hash, height: Height) -> Option<(Payload, Hash)> {
        // Verify parent exists and we are at the correct height
        if parent.len() != HASH_LENGTH {
            self.panic("invalid parent hash length");
        }
        if let Some(parent) = self.verified.get(&parent) {
            if parent + 1 != height {
                self.panic("invalid height");
            }
        } else {
            self.panic("parent not verified");
        }

        // Simulate the propose latency
        let duration = self.propose_latency.sample(&mut self.runtime);
        self.runtime
            .sleep(Duration::from_millis(duration as u64))
            .await;

        // Generate the payload
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.participant);
        payload.extend_from_slice(&height.to_be_bytes());
        let payload = Bytes::from(payload);
        let payload_hash = self.parse(parent, height, payload.clone()).await.unwrap();
        Some((payload, payload_hash))
    }

    async fn parse(&mut self, parent: Hash, _: Height, payload: Payload) -> Option<Hash> {
        // Verify parent is well-formed
        if parent.len() != HASH_LENGTH {
            self.panic("invalid parent hash length");
        }

        // Simulate the parse latency
        let duration = self.parse_latency.sample(&mut self.runtime);
        self.runtime
            .sleep(Duration::from_millis(duration as u64))
            .await;

        // Parse and record the payload
        //
        // A payload may be parsed multiple times, so we don't enforce
        // uniqueness here.
        let payload_hash = hash(&payload);
        self.parsed.insert(payload_hash.clone());
        Some(payload_hash)
    }

    async fn verify(
        &mut self,
        parent: Hash,
        height: Height,
        payload: Payload,
        block: Hash,
    ) -> bool {
        // Verify parent exists and we are at the correct height
        if parent.len() != HASH_LENGTH {
            self.panic("invalid parent hash length");
        }
        if block.len() != HASH_LENGTH {
            self.panic("invalid hash length");
        }
        let payload_hash = hash(&payload);
        if !self.parsed.contains(&payload_hash) {
            self.panic("payload not parsed");
        }
        if self.verified.contains_key(&block) {
            self.panic("block already verified");
        }
        if let Some(parent) = self.verified.get(&parent) {
            if parent + 1 != height {
                self.panic("invalid height");
            }
        } else {
            self.panic("parent not verified");
        };

        // Simulate the verify latency
        let duration = self.verify_latency.sample(&mut self.runtime);
        self.runtime
            .sleep(Duration::from_millis(duration as u64))
            .await;

        // Verify the payload
        Self::verify_payload(height, &payload);
        self.verified.insert(block.clone(), height);
        true
    }

    async fn notarized(&mut self, hash: Hash) {
        if hash.len() != HASH_LENGTH {
            self.panic("invalid hash length");
        }
        if self.finalized.contains_key(&hash) {
            self.panic("hash already finalized");
        }
        if let Some(height) = self.verified.get(&hash) {
            let _ = self
                .progress
                .send((self.participant.clone(), Progress::Notarized(*height, hash)))
                .await;
        } else {
            self.panic("hash not verified");
        }
    }

    async fn finalized(&mut self, hash: Hash) {
        if hash.len() != HASH_LENGTH {
            self.panic("invalid hash length");
        }
        if self.finalized.contains_key(&hash) {
            self.panic("hash already finalized");
        }
        if let Some(height) = self.verified.get(&hash) {
            if self.last_finalized + 1 != *height {
                self.panic("invalid finalization height");
            }
            self.last_finalized = *height;
            self.finalized.insert(hash.clone(), *height);
            let _ = self
                .progress
                .send((self.participant.clone(), Progress::Finalized(*height, hash)))
                .await;
        } else {
            self.panic("hash not verified");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Application as _;
    use commonware_cryptography::{Ed25519, Scheme};
    use commonware_runtime::{deterministic::Executor, Runner};
    use futures::StreamExt;

    #[test]
    fn test_normal_flow_propose() {
        // Create the runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let (sender, mut receiver) = mpsc::unbounded();
            let cfg = Config {
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
            };
            let mut app = Application::new(runtime, cfg);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Propose a block at height 1
            let parent = genesis_hash.clone();
            let height = 1;
            let (payload, payload_hash) = app
                .propose(parent.clone(), height)
                .await
                .expect("propose failed");
            let block_hash = hash(&payload_hash);

            // Verify the block
            let verified = app
                .verify(parent.clone(), height, payload.clone(), block_hash.clone())
                .await;
            assert!(verified);

            // Notarize the block
            app.notarized(block_hash.clone()).await;

            // Expect a progress message for notarization
            let (progress_participant, progress) =
                receiver.next().await.expect("no progress message");
            assert_eq!(progress_participant, participant);
            match progress {
                Progress::Notarized(notarized_height, notarized_hash) => {
                    assert_eq!(notarized_height, height);
                    assert_eq!(notarized_hash, block_hash);
                }
                _ => panic!("expected Notarized progress"),
            }

            // Finalize the block
            app.finalized(block_hash.clone()).await;

            // Expect a progress message for finalization
            let (progress_participant, progress) =
                receiver.next().await.expect("no progress message");
            assert_eq!(progress_participant, participant);
            match progress {
                Progress::Finalized(finalized_height, finalized_hash) => {
                    assert_eq!(finalized_height, height);
                    assert_eq!(finalized_hash, block_hash);
                }
                _ => panic!("expected Finalized progress"),
            }
        });
    }

    #[test]
    fn test_normal_flow_verify() {
        // Create the runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let (sender, mut receiver) = mpsc::unbounded();
            let cfg = Config {
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
            };
            let mut app = Application::new(runtime, cfg);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Get block at height 1
            let parent = genesis_hash.clone();
            let height: Height = 1;
            let mut payload = Vec::new();
            payload.extend_from_slice(&participant);
            payload.extend_from_slice(&height.to_be_bytes());
            let payload = Bytes::from(payload);

            // Parse the payload
            let payload_hash = app
                .parse(parent.clone(), height, payload.clone())
                .await
                .expect("parse failed");
            let block_hash = hash(&payload_hash);

            // Verify the block
            let verified = app
                .verify(parent.clone(), height, payload.clone(), block_hash.clone())
                .await;
            assert!(verified);

            // Notarize the block
            app.notarized(block_hash.clone()).await;

            // Expect a progress message for notarization
            let (progress_participant, progress) =
                receiver.next().await.expect("no progress message");
            assert_eq!(progress_participant, participant);
            match progress {
                Progress::Notarized(notarized_height, notarized_hash) => {
                    assert_eq!(notarized_height, height);
                    assert_eq!(notarized_hash, block_hash);
                }
                _ => panic!("expected Notarized progress"),
            }

            // Finalize the block
            app.finalized(block_hash.clone()).await;

            // Expect a progress message for finalization
            let (progress_participant, progress) =
                receiver.next().await.expect("no progress message");
            assert_eq!(progress_participant, participant);
            match progress {
                Progress::Finalized(finalized_height, finalized_hash) => {
                    assert_eq!(finalized_height, height);
                    assert_eq!(finalized_hash, block_hash);
                }
                _ => panic!("expected Finalized progress"),
            }
        });
    }

    #[test]
    #[should_panic(expected = "parent not verified")]
    fn test_propose_invalid_parent() {
        // Create the runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let (sender, _) = mpsc::unbounded();
            let cfg = Config {
                participant,
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
            };
            let mut app = Application::new(runtime, cfg);

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
        // Create the runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let (sender, _) = mpsc::unbounded();
            let cfg = Config {
                participant,
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
            };
            let mut app = Application::new(runtime, cfg);

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
    #[should_panic(expected = "payload not parsed")]
    fn test_verify_not_parsed() {
        // Create the runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let (sender, _) = mpsc::unbounded();
            let cfg = Config {
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
            };
            let mut app = Application::new(runtime, cfg);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Get block at height 1
            let parent = genesis_hash.clone();
            let height: Height = 1;
            let mut payload = Vec::new();
            payload.extend_from_slice(&participant);
            payload.extend_from_slice(&height.to_be_bytes());
            let payload = Bytes::from(payload);
            let payload_hash = hash(&payload);
            let block_hash = hash(&payload_hash);

            // Verify the block
            app.verify(parent.clone(), height, payload.clone(), block_hash.clone())
                .await;
        });
    }

    // #[test]
    // #[should_panic(expected = "invalid height")]
    // fn test_verify_invalid_height() {
    //     // Create the runtime
    //     let (executor, runtime, _) = Executor::default();
    //     executor.start(async move {
    //         // Create the application
    //         let participant = Ed25519::from_seed(0).public_key();
    //         let (sender, _) = mpsc::unbounded();
    //         let cfg = Config {
    //             participant,
    //             sender,
    //             propose_latency: (10.0, 5.0),
    //             parse_latency: (10.0, 5.0),
    //             verify_latency: (10.0, 5.0),
    //         };
    //         let mut app = Application::new(runtime, cfg);

    //         // Genesis
    //         let (genesis_hash, _) = app.genesis();

    //         // Propose a block at height 1
    //         let parent = genesis_hash.clone();
    //         let height = 1;
    //         let (payload, payload_hash) = app
    //             .propose(parent.clone(), height)
    //             .await
    //             .expect("propose failed");

    //         // Attempt to verify the block with incorrect height (e.g., height 2)
    //         let invalid_height = 2;
    //         app.verify(
    //             parent.clone(),
    //             invalid_height,
    //             payload.clone(),
    //             hash.clone(),
    //         )
    //         .await;
    //     });
    // }

    // #[test_async]
    // #[should_panic(expected = "parent not verified")]
    // async fn test_verify_unverified_parent() {
    //     // Create the application
    //     let participant = Ed25519::from_seed(0).public_key();
    //     let (sender, _) = mpsc::unbounded();
    //     let mut app = Application::new(participant, sender);

    //     // Create an unverified parent hash
    //     let unverified_parent = hash(&Bytes::from_static(b"unverified_parent"));

    //     // Manually create a payload for height 1
    //     let height: Height = 1;
    //     let mut payload = Vec::new();
    //     payload.extend_from_slice(&app.participant);
    //     payload.extend_from_slice(&height.to_be_bytes());
    //     let payload = Bytes::from(payload);

    //     // Parse the payload to get the hash
    //     let hash = app
    //         .parse(unverified_parent.clone(), height, payload.clone())
    //         .expect("parse failed");

    //     // Attempt to verify the block, should panic
    //     app.verify(
    //         unverified_parent.clone(),
    //         height,
    //         payload.clone(),
    //         hash.clone(),
    //     )
    //     .await;
    // }

    // #[test_async]
    // #[should_panic(expected = "invalid payload length")]
    // async fn test_verify_payload_invalid_length() {
    //     // Create the application
    //     let participant = Ed25519::from_seed(0).public_key();
    //     let (sender, _) = mpsc::unbounded();
    //     let mut app = Application::new(participant, sender);

    //     // Genesis
    //     let (genesis_hash, _) = app.genesis();

    //     // Create a payload with invalid length
    //     let height = 1;
    //     let invalid_payload = Bytes::from_static(b"short");

    //     // Attempt to parse the payload, should panic
    //     app.parse(genesis_hash.clone(), height, invalid_payload.clone());
    // }

    // #[test_async]
    // #[should_panic(expected = "hash already verified")]
    // async fn test_verify_same_hash_twice() {
    //     // Create the application
    //     let participant = Ed25519::from_seed(0).public_key();
    //     let (sender, _) = mpsc::unbounded();
    //     let mut app = Application::new(participant, sender);

    //     // Genesis
    //     let (genesis_hash, _) = app.genesis();

    //     // Propose a block at height 1
    //     let parent = genesis_hash.clone();
    //     let height = 1;
    //     let payload = app
    //         .propose(parent.clone(), height)
    //         .await
    //         .expect("propose failed");

    //     // Parse the payload to get the hash
    //     let hash = app
    //         .parse(parent.clone(), height, payload.clone())
    //         .expect("parse failed");

    //     // Verify the block
    //     app.verify(parent.clone(), height, payload.clone(), hash.clone())
    //         .await;

    //     // Attempt to verify the same block again, should panic
    //     app.verify(parent.clone(), height, payload.clone(), hash.clone())
    //         .await;
    // }

    // #[test_async]
    // #[should_panic(expected = "hash already finalized")]
    // async fn test_notarize_after_finalize() {
    //     // Create the application
    //     let participant = Ed25519::from_seed(0).public_key();
    //     let (sender, _) = mpsc::unbounded();
    //     let mut app = Application::new(participant, sender);

    //     // Genesis
    //     let (genesis_hash, _) = app.genesis();

    //     // Propose a block at height 1
    //     let parent = genesis_hash.clone();
    //     let height = 1;
    //     let payload = app
    //         .propose(parent.clone(), height)
    //         .await
    //         .expect("propose failed");

    //     // Parse the payload to get the hash
    //     let hash = app
    //         .parse(parent.clone(), height, payload.clone())
    //         .expect("parse failed");

    //     // Verify the block
    //     let verified = app
    //         .verify(parent.clone(), height, payload.clone(), hash.clone())
    //         .await;
    //     assert!(verified);

    //     // Notarize and finalize the block
    //     app.notarized(hash.clone()).await;
    //     app.finalized(hash.clone()).await;

    //     // Attempt to notarize the block again, should panic
    //     app.notarized(hash.clone()).await;
    // }

    // #[test_async]
    // #[should_panic(expected = "hash not verified")]
    // async fn test_notarization_not_verified() {
    //     let (sender, _) = mpsc::unbounded();
    //     let mut app = Application::new(PublicKey::default(), sender);
    //     app.notarized(hash(&Bytes::from_static(b"hello"))).await;
    // }

    // #[test_async]
    // #[should_panic(expected = "invalid hash length")]
    // async fn test_notarization_invalid_hash() {
    //     let (sender, _) = mpsc::unbounded();
    //     let mut app = Application::new(PublicKey::default(), sender);
    //     app.notarized(Bytes::from_static(b"hello")).await;
    // }

    // #[test_async]
    // #[should_panic(expected = "hash already finalized")]
    // async fn test_notarization_genesis_block() {
    //     // Create the application
    //     let participant = Ed25519::from_seed(0).public_key();
    //     let (sender, _) = mpsc::unbounded();
    //     let mut app = Application::new(participant, sender);

    //     // Genesis
    //     let (genesis_hash, _) = app.genesis();

    //     // Attempt to finalize the genesis block, should panic
    //     app.notarized(genesis_hash.clone()).await;
    // }

    // #[test_async]
    // #[should_panic(expected = "hash not verified")]
    // async fn test_finalization_not_verified() {
    //     let (sender, _) = mpsc::unbounded();
    //     let mut app = Application::new(PublicKey::default(), sender);
    //     app.finalized(hash(&Bytes::from_static(b"hello"))).await;
    // }

    // #[test_async]
    // #[should_panic(expected = "invalid hash length")]
    // async fn test_finalization_invalid_hash() {
    //     let (sender, _) = mpsc::unbounded();
    //     let mut app = Application::new(PublicKey::default(), sender);
    //     app.finalized(Bytes::from_static(b"hello")).await;
    // }

    // #[test_async]
    // #[should_panic(expected = "hash already finalized")]
    // async fn test_finalization_genesis_block() {
    //     // Create the application
    //     let participant = Ed25519::from_seed(0).public_key();
    //     let (sender, _) = mpsc::unbounded();
    //     let mut app = Application::new(participant, sender);

    //     // Genesis
    //     let (genesis_hash, _) = app.genesis();

    //     // Attempt to finalize the genesis block, should panic
    //     app.finalized(genesis_hash.clone()).await;
    // }
}

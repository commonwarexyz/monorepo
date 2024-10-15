use crate::{Activity, Context, Hash, Hasher, Height, Payload, View};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_runtime::Clock;
use commonware_utils::hex;
use futures::{channel::mpsc, SinkExt};
use rand::RngCore;
use rand_distr::{Distribution, Normal};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
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
    pub participants: HashMap<View, Vec<PublicKey>>,

    pub sender: mpsc::UnboundedSender<(PublicKey, Progress)>,

    pub propose_latency: Latency,
    pub parse_latency: Latency,
    pub verify_latency: Latency,
}

pub enum Progress {
    Notarized(Height, Hash),
    Finalized(Height, Hash),
}

type ViewInfo = (HashSet<PublicKey>, Vec<PublicKey>);

#[derive(Default)]
struct State {
    parsed: HashSet<Hash>,
    verified: HashMap<Hash, Height>,
    last_finalized: u64,
    finalized: HashMap<Hash, Height>,
}

// TODO: add arc/mutex to support copying of state
#[derive(Clone)]
pub struct Application<E: Clock + RngCore, H: Hasher> {
    runtime: E,
    hasher: H,

    participant: PublicKey,
    parsed_participants: BTreeMap<View, ViewInfo>,

    propose_latency: Normal<f64>,
    parse_latency: Normal<f64>,
    verify_latency: Normal<f64>,

    progress: mpsc::UnboundedSender<(PublicKey, Progress)>,

    state: Arc<Mutex<State>>,
}

impl<E: Clock + RngCore, H: Hasher> Application<E, H> {
    pub fn new(runtime: E, hasher: H, cfg: Config) -> Self {
        // Generate samplers
        let propose_latency = Normal::new(cfg.propose_latency.0, cfg.propose_latency.1).unwrap();
        let parse_latency = Normal::new(cfg.parse_latency.0, cfg.parse_latency.1).unwrap();
        let verify_latency = Normal::new(cfg.verify_latency.0, cfg.verify_latency.1).unwrap();

        // Generate participants map
        let mut participants = BTreeMap::new();
        for (view, keys) in cfg.participants.into_iter() {
            let set: HashSet<PublicKey> = keys.iter().cloned().collect();
            let info = (set, keys);
            participants.insert(view, info);
        }

        // Return constructed application
        Self {
            runtime,
            hasher,

            participant: cfg.participant,
            parsed_participants: participants,

            parse_latency,
            propose_latency,
            verify_latency,

            progress: cfg.sender,

            state: Arc::new(Mutex::new(State::default())),
        }
    }

    fn panic(&self, msg: &str) -> ! {
        panic!("[{}] {}", hex(&self.participant), msg);
    }
}

impl<E: Clock + RngCore, H: Hasher> crate::Application for Application<E, H> {
    fn genesis(&mut self) -> (Hash, Payload) {
        let payload = Bytes::from(GENESIS_BYTES);
        let hash = self.hasher.hash(&payload);
        let mut state = self.state.lock().unwrap();
        state.parsed.insert(hash.clone());
        state.verified.insert(hash.clone(), 0);
        state.finalized.insert(hash.clone(), 0);
        (hash, payload)
    }

    fn participants(&self, view: View) -> Option<&Vec<PublicKey>> {
        let closest = match self.parsed_participants.range(..=view).next_back() {
            Some((_, p)) => p,
            None => {
                self.panic("no participants in required range");
            }
        };
        Some(&closest.1)
    }

    fn is_participant(&self, view: View, candidate: &PublicKey) -> Option<bool> {
        self.parsed_participants
            .get(&view)
            .map(|(set, _)| set.contains(candidate))
    }

    async fn propose(&mut self, context: Context, _activity: Activity) -> Option<Payload> {
        // Verify parent exists and we are at the correct height
        if !H::validate(&context.parent) {
            self.panic("invalid parent hash length");
        }
        {
            let state = self.state.lock().unwrap();
            if state.verified.contains_key(&context.parent) {
                if state.verified.get(&context.parent).unwrap() + 1 != context.height {
                    self.panic("invalid height");
                }
            } else {
                self.panic("parent not verified");
            }
        }

        // Simulate the propose latency
        let duration = self.propose_latency.sample(&mut self.runtime);
        self.runtime
            .sleep(Duration::from_millis(duration as u64))
            .await;

        // Generate the payload
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.participant);
        payload.extend_from_slice(&context.height.to_be_bytes());
        Some(Bytes::from(payload))
    }

    async fn parse(&mut self, payload: Payload) -> Option<Hash> {
        // Verify the payload is well-formed
        if payload.len() != 40 {
            self.panic("invalid payload length");
        }

        // Simulate the parse latency
        let duration = self.parse_latency.sample(&mut self.runtime);
        self.runtime
            .sleep(Duration::from_millis(duration as u64))
            .await;

        // Parse the payload
        let hash = self.hasher.hash(&payload);
        {
            let mut state = self.state.lock().unwrap();
            state.parsed.insert(hash.clone());
        }
        Some(hash)
    }

    async fn verify(
        &mut self,
        context: Context,
        _activity: Activity,
        payload: Payload,
        block: Hash,
    ) -> bool {
        // Simulate the verify latency
        let duration = self.verify_latency.sample(&mut self.runtime);
        self.runtime
            .sleep(Duration::from_millis(duration as u64))
            .await;

        // Verify parent exists and we are at the correct height
        if !H::validate(&context.parent) {
            self.panic("invalid parent hash length");
        }
        if !H::validate(&block) {
            self.panic("invalid hash length");
        }

        // Verify the payload
        let parsed_height = Height::from_be_bytes(payload[32..].try_into().unwrap());
        if parsed_height != context.height {
            self.panic("invalid height");
        }

        // Ensure not duplicate check
        let mut state = self.state.lock().unwrap();
        if state.verified.contains_key(&block) {
            self.panic("block already verified");
        }
        if let Some(parent) = state.verified.get(&context.parent) {
            if parent + 1 != context.height {
                self.panic("invalid height");
            }
        } else {
            self.panic("parent not verified");
        };
        if !state.parsed.contains(&self.hasher.hash(&payload)) {
            self.panic("payload not parsed");
        }
        state.verified.insert(block.clone(), context.height);
        true
    }

    async fn notarized(&mut self, block: Hash) {
        if !H::validate(&block) {
            self.panic("invalid hash length");
        }
        let height = {
            let state = self.state.lock().unwrap();
            if state.finalized.contains_key(&block) {
                self.panic("block already finalized");
            }
            if let Some(height) = state.verified.get(&block) {
                *height
            } else {
                self.panic("block not verified");
            }
        };
        let _ = self
            .progress
            .send((self.participant.clone(), Progress::Notarized(height, block)))
            .await;
    }

    async fn finalized(&mut self, block: Hash) {
        if !H::validate(&block) {
            self.panic("invalid hash length");
        }
        let height = {
            let mut state = self.state.lock().unwrap();
            if state.finalized.contains_key(&block) {
                self.panic("block already finalized");
            }
            let height = match state.verified.get(&block) {
                Some(height) => *height,
                None => self.panic("block not verified"),
            };
            if state.last_finalized + 1 != height {
                self.panic(&format!(
                    "invalid finalization height: {} != {}",
                    state.last_finalized + 1,
                    height
                ));
            }
            state.last_finalized = height;
            state.finalized.insert(block.clone(), height);
            height
        };
        let _ = self
            .progress
            .send((self.participant.clone(), Progress::Finalized(height, block)))
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sha256::Sha256, Application as _};
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
                participants: HashMap::from([(1, vec![participant.clone()])]),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
            };
            let mut hasher = Sha256::default();
            let mut app = Application::new(runtime, hasher.clone(), cfg);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Propose a block at height 1
            let parent = genesis_hash.clone();
            let height = 1;
            let context = Context {
                parent,
                view: 1,
                height,
            };
            let activity = Activity {
                proposer: participant.clone(),
                contributions: HashMap::new(),
                faults: HashMap::new(),
            };
            let payload = app
                .propose(context.clone(), activity.clone())
                .await
                .expect("propose failed");
            let dummy_block_hash = hasher.hash(&payload);

            // Parse the payload
            app.parse(payload.clone()).await.expect("parse failed");

            // Verify the block
            let verified = app
                .verify(context, activity, payload.clone(), dummy_block_hash.clone())
                .await;
            assert!(verified);

            // Notarize the block
            app.notarized(dummy_block_hash.clone()).await;

            // Expect a progress message for notarization
            let (progress_participant, progress) =
                receiver.next().await.expect("no progress message");
            assert_eq!(progress_participant, participant);
            match progress {
                Progress::Notarized(notarized_height, notarized_hash) => {
                    assert_eq!(notarized_height, height);
                    assert_eq!(notarized_hash, dummy_block_hash);
                }
                _ => panic!("expected Notarized progress"),
            }

            // Finalize the block
            app.finalized(dummy_block_hash.clone()).await;

            // Expect a progress message for finalization
            let (progress_participant, progress) =
                receiver.next().await.expect("no progress message");
            assert_eq!(progress_participant, participant);
            match progress {
                Progress::Finalized(finalized_height, finalized_hash) => {
                    assert_eq!(finalized_height, height);
                    assert_eq!(finalized_hash, dummy_block_hash);
                }
                _ => panic!("expected Finalized progress"),
            }
        });
    }

    // #[test]
    // fn test_normal_flow_verify() {
    //     // Create the runtime
    //     let (executor, runtime, _) = Executor::default();
    //     executor.start(async move {
    //         // Create the application
    //         let participant = Ed25519::from_seed(0).public_key();
    //         let (sender, mut receiver) = mpsc::unbounded();
    //         let cfg = Config {
    //             participant: participant.clone(),
    //             sender,
    //             propose_latency: (10.0, 5.0),
    //             parse_latency: (10.0, 5.0),
    //             verify_latency: (10.0, 5.0),
    //         };
    //         let mut app = Application::new(runtime, cfg);

    //         // Genesis
    //         let (genesis_hash, _) = app.genesis();

    //         // Get block at height 1
    //         let parent = genesis_hash.clone();
    //         let height: Height = 1;
    //         let mut payload = Vec::new();
    //         payload.extend_from_slice(&participant);
    //         payload.extend_from_slice(&height.to_be_bytes());
    //         let payload = Bytes::from(payload);

    //         // Parse the payload
    //         let payload_hash = app
    //             .parse(parent.clone(), height, payload.clone())
    //             .await
    //             .expect("parse failed");
    //         let block_hash = hash(&payload_hash);

    //         // Verify the block
    //         let verified = app
    //             .verify(parent.clone(), height, payload.clone(), block_hash.clone())
    //             .await;
    //         assert!(verified);

    //         // Notarize the block
    //         app.notarized(block_hash.clone()).await;

    //         // Expect a progress message for notarization
    //         let (progress_participant, progress) =
    //             receiver.next().await.expect("no progress message");
    //         assert_eq!(progress_participant, participant);
    //         match progress {
    //             Progress::Notarized(notarized_height, notarized_hash) => {
    //                 assert_eq!(notarized_height, height);
    //                 assert_eq!(notarized_hash, block_hash);
    //             }
    //             _ => panic!("expected Notarized progress"),
    //         }

    //         // Finalize the block
    //         app.finalized(block_hash.clone()).await;

    //         // Expect a progress message for finalization
    //         let (progress_participant, progress) =
    //             receiver.next().await.expect("no progress message");
    //         assert_eq!(progress_participant, participant);
    //         match progress {
    //             Progress::Finalized(finalized_height, finalized_hash) => {
    //                 assert_eq!(finalized_height, height);
    //                 assert_eq!(finalized_hash, block_hash);
    //             }
    //             _ => panic!("expected Finalized progress"),
    //         }
    //     });
    // }

    // #[test]
    // #[should_panic(expected = "parent not verified")]
    // fn test_propose_invalid_parent() {
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

    //         // Create an invalid parent hash
    //         let invalid_parent = hash(&Bytes::from_static(b"invalid"));

    //         // Attempt to propose a block with invalid parent, should panic
    //         let height = 1;
    //         app.propose(invalid_parent.clone(), height).await;
    //     });
    // }

    // #[test]
    // #[should_panic(expected = "invalid height")]
    // fn test_propose_invalid_height() {
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
    //         let height = 100;
    //         app.propose(parent.clone(), height)
    //             .await
    //             .expect("propose failed");
    //     });
    // }

    // #[test]
    // #[should_panic(expected = "payload not parsed")]
    // fn test_verify_not_parsed() {
    //     // Create the runtime
    //     let (executor, runtime, _) = Executor::default();
    //     executor.start(async move {
    //         // Create the application
    //         let participant = Ed25519::from_seed(0).public_key();
    //         let (sender, _) = mpsc::unbounded();
    //         let cfg = Config {
    //             participant: participant.clone(),
    //             sender,
    //             propose_latency: (10.0, 5.0),
    //             parse_latency: (10.0, 5.0),
    //             verify_latency: (10.0, 5.0),
    //         };
    //         let mut app = Application::new(runtime, cfg);

    //         // Genesis
    //         let (genesis_hash, _) = app.genesis();

    //         // Get block at height 1
    //         let parent = genesis_hash.clone();
    //         let height: Height = 1;
    //         let mut payload = Vec::new();
    //         payload.extend_from_slice(&participant);
    //         payload.extend_from_slice(&height.to_be_bytes());
    //         let payload = Bytes::from(payload);
    //         let payload_hash = hash(&payload);
    //         let block_hash = hash(&payload_hash);

    //         // Verify the block
    //         app.verify(parent.clone(), height, payload.clone(), block_hash.clone())
    //             .await;
    //     });
    // }

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
    //         let block_hash = hash(&payload_hash);

    //         // Attempt to verify the block with incorrect height (e.g., height 2)
    //         let invalid_height = 2;
    //         app.verify(parent, invalid_height, payload, block_hash)
    //             .await;
    //     });
    // }

    // #[test]
    // #[should_panic(expected = "parent not verified")]
    // fn test_verify_unverified_parent() {
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

    //         // Create an unverified parent hash
    //         let unverified_parent = hash(&Bytes::from_static(b"unverified_parent"));

    //         // Manually create a payload for height 1
    //         let height: Height = 1;
    //         let mut payload = Vec::new();
    //         payload.extend_from_slice(&app.participant);
    //         payload.extend_from_slice(&height.to_be_bytes());
    //         let payload = Bytes::from(payload);

    //         // Parse the payload to get the hash
    //         let payload_hash = app
    //             .parse(unverified_parent.clone(), height, payload.clone())
    //             .await
    //             .expect("parse failed");
    //         let block_hash = hash(&payload_hash);

    //         // Attempt to verify the block, should panic
    //         app.verify(unverified_parent, height, payload, block_hash)
    //             .await;
    //     });
    // }

    // #[test]
    // #[should_panic(expected = "invalid payload length")]
    // fn test_parse_payload_invalid_length() {
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

    //         // Create a payload with invalid length
    //         let height = 1;
    //         let invalid_payload = Bytes::from_static(b"short");

    //         // Attempt to parse the payload, should panic
    //         app.parse(genesis_hash.clone(), height, invalid_payload.clone())
    //             .await;
    //     });
    // }

    // #[test]
    // #[should_panic(expected = "block already verified")]
    // fn test_verify_same_hash_twice() {
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
    //         let block_hash = hash(&payload_hash);

    //         // Verify the block
    //         app.verify(parent.clone(), height, payload.clone(), block_hash.clone())
    //             .await;

    //         // Attempt to verify the same block again, should panic
    //         app.verify(parent, height, payload, block_hash).await;
    //     });
    // }

    // #[test]
    // #[should_panic(expected = "block already finalized")]
    // fn test_notarize_after_finalize() {
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
    //         let block_hash = hash(&payload_hash);

    //         // Verify the block
    //         let verified = app
    //             .verify(parent.clone(), height, payload.clone(), block_hash.clone())
    //             .await;
    //         assert!(verified);

    //         // Notarize and finalize the block
    //         app.notarized(block_hash.clone()).await;
    //         app.finalized(block_hash.clone()).await;

    //         // Attempt to notarize the block again, should panic
    //         app.notarized(block_hash).await;
    //     });
    // }

    // #[test]
    // #[should_panic(expected = "block not verified")]
    // fn test_notarization_not_verified() {
    //     // Create the runtime
    //     let (executor, runtime, _) = Executor::default();
    //     executor.start(async move {
    //         // Create the application
    //         let (sender, _) = mpsc::unbounded();
    //         let cfg = Config {
    //             participant: PublicKey::default(),
    //             sender,
    //             propose_latency: (10.0, 5.0),
    //             parse_latency: (10.0, 5.0),
    //             verify_latency: (10.0, 5.0),
    //         };
    //         let mut app = Application::new(runtime, cfg);
    //         app.notarized(hash(&Bytes::from_static(b"hello"))).await;
    //     });
    // }

    // #[test]
    // #[should_panic(expected = "invalid hash length")]
    // fn test_notarization_invalid_hash() {
    //     // Create the runtime
    //     let (executor, runtime, _) = Executor::default();
    //     executor.start(async move {
    //         // Create the application
    //         let (sender, _) = mpsc::unbounded();
    //         let mut app = Application::new(
    //             runtime,
    //             Config {
    //                 participant: PublicKey::default(),
    //                 sender,
    //                 propose_latency: (10.0, 5.0),
    //                 parse_latency: (10.0, 5.0),
    //                 verify_latency: (10.0, 5.0),
    //             },
    //         );
    //         app.notarized(Bytes::from_static(b"hello")).await;
    //     });
    // }

    // #[test]
    // #[should_panic(expected = "block already finalized")]
    // fn test_notarization_genesis_block() {
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

    //         // Attempt to finalize the genesis block, should panic
    //         app.notarized(genesis_hash.clone()).await;
    //     });
    // }

    // #[test]
    // #[should_panic(expected = "block not verified")]
    // fn test_finalization_not_verified() {
    //     // Create the runtime
    //     let (executor, runtime, _) = Executor::default();
    //     executor.start(async move {
    //         // Create the application
    //         let (sender, _) = mpsc::unbounded();
    //         let cfg = Config {
    //             participant: PublicKey::default(),
    //             sender,
    //             propose_latency: (10.0, 5.0),
    //             parse_latency: (10.0, 5.0),
    //             verify_latency: (10.0, 5.0),
    //         };
    //         let mut app = Application::new(runtime, cfg);
    //         app.finalized(hash(&Bytes::from_static(b"hello"))).await;
    //     });
    // }

    // #[test]
    // #[should_panic(expected = "invalid hash length")]
    // fn test_finalization_invalid_hash() {
    //     // Create the runtime
    //     let (executor, runtime, _) = Executor::default();
    //     executor.start(async move {
    //         // Create the application
    //         let (sender, _) = mpsc::unbounded();
    //         let mut app = Application::new(
    //             runtime,
    //             Config {
    //                 participant: PublicKey::default(),
    //                 sender,
    //                 propose_latency: (10.0, 5.0),
    //                 parse_latency: (10.0, 5.0),
    //                 verify_latency: (10.0, 5.0),
    //             },
    //         );
    //         app.finalized(Bytes::from_static(b"hello")).await;
    //     });
    // }

    // #[test]
    // #[should_panic(expected = "block already finalized")]
    // fn test_finalization_genesis_block() {
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

    //         // Attempt to finalize the genesis block, should panic
    //         app.finalized(genesis_hash.clone()).await;
    //     });
    // }
}

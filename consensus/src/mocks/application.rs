use crate::{Activity, Context, Hash, Hasher, Height, Payload, Proof, Supervisor, View};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_runtime::Clock;
use commonware_utils::hex;
use futures::{channel::mpsc, SinkExt};
use rand::RngCore;
use rand_distr::{Distribution, Normal};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

const GENESIS_BYTES: &[u8] = b"genesis";

type Latency = (f64, f64);

pub struct Config<H: Hasher, S: Supervisor> {
    pub hasher: H,
    pub supervisor: S,

    /// The public key of the participant.
    ///
    /// It is common to use multiple instances of an application in a single simulation, this
    /// helps to identify the source of both progress and errors.
    pub participant: PublicKey,

    pub propose_latency: Latency,
    pub parse_latency: Latency,
    pub verify_latency: Latency,
    pub allow_invalid_payload: bool,

    pub sender: mpsc::UnboundedSender<(PublicKey, Progress)>,
}

pub enum Progress {
    Notarized(Height, Hash),
    Finalized(Height, Hash),
}

#[derive(Default)]
struct State {
    parsed: HashSet<Hash>,
    verified: HashMap<Hash, Height>,
    last_finalized: u64,
    finalized: HashMap<Hash, Height>,

    notarized_views: HashSet<View>,
    finalized_views: HashSet<View>,
}

#[derive(Clone)]
pub struct Application<E: Clock + RngCore, H: Hasher, S: Supervisor> {
    runtime: E,
    hasher: H,
    supervisor: S,

    participant: PublicKey,

    propose_latency: Normal<f64>,
    parse_latency: Normal<f64>,
    verify_latency: Normal<f64>,
    allow_invalid_payload: bool,

    progress: mpsc::UnboundedSender<(PublicKey, Progress)>,

    state: Arc<Mutex<State>>,
}

impl<E: Clock + RngCore, H: Hasher, S: Supervisor> Application<E, H, S> {
    pub fn new(runtime: E, cfg: Config<H, S>) -> Self {
        // Generate samplers
        let propose_latency = Normal::new(cfg.propose_latency.0, cfg.propose_latency.1).unwrap();
        let parse_latency = Normal::new(cfg.parse_latency.0, cfg.parse_latency.1).unwrap();
        let verify_latency = Normal::new(cfg.verify_latency.0, cfg.verify_latency.1).unwrap();

        // Return constructed application
        Self {
            runtime,
            hasher: cfg.hasher,
            supervisor: cfg.supervisor,

            participant: cfg.participant,

            propose_latency,
            parse_latency,
            verify_latency,
            allow_invalid_payload: cfg.allow_invalid_payload,

            progress: cfg.sender,

            state: Arc::new(Mutex::new(State::default())),
        }
    }

    fn panic(&self, msg: &str) -> ! {
        panic!("[{}] {}", hex(&self.participant), msg);
    }
}

impl<E: Clock + RngCore, H: Hasher, S: Supervisor> crate::Application for Application<E, H, S> {
    fn genesis(&mut self) -> (Hash, Payload) {
        let payload = Bytes::from(GENESIS_BYTES);
        self.hasher.update(&payload);
        let hash = self.hasher.finalize();
        let mut state = self.state.lock().unwrap();
        state.parsed.insert(hash.clone());
        state.verified.insert(hash.clone(), 0);
        state.finalized.insert(hash.clone(), 0);
        (hash, payload)
    }

    async fn propose(&mut self, context: Context) -> Option<Payload> {
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
        if !self.allow_invalid_payload && payload.len() != 40 {
            self.panic("invalid payload length");
        }

        // Simulate the parse latency
        let duration = self.parse_latency.sample(&mut self.runtime);
        self.runtime
            .sleep(Duration::from_millis(duration as u64))
            .await;

        // Parse the payload
        self.hasher.update(&payload);
        let hash = self.hasher.finalize();
        {
            let mut state = self.state.lock().unwrap();
            state.parsed.insert(hash.clone());
        }
        Some(hash)
    }

    async fn verify(&mut self, context: Context, payload: Payload, block: Hash) -> bool {
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
        if !self.allow_invalid_payload {
            if payload.len() != 40 {
                self.panic("invalid payload length");
            }
            let parsed_height = Height::from_be_bytes(payload[32..].try_into().unwrap());
            if parsed_height != context.height {
                self.panic(&format!(
                    "invalid height (in payload): {} != {}",
                    parsed_height, context.height
                ));
            }
        }

        // Ensure not duplicate check
        let mut state = self.state.lock().unwrap();
        if state.verified.contains_key(&block) {
            self.panic("block already verified");
        }
        if let Some(parent) = state.verified.get(&context.parent) {
            if parent + 1 != context.height {
                self.panic(&format!(
                    "invalid height (from last verified): {} != {}",
                    parent + 1,
                    context.height
                ));
            }
        } else {
            self.panic("parent not verified");
        };
        self.hasher.update(&payload);
        let hash = self.hasher.finalize();
        if !state.parsed.contains(&hash) {
            self.panic("payload not parsed");
        }
        state.verified.insert(block.clone(), context.height);
        true
    }
}

impl<E: Clock + RngCore, H: Hasher, S: Supervisor> crate::Finalizer for Application<E, H, S> {
    async fn notarized(&mut self, view: View, block: Hash) {
        if view == 0 {
            self.panic("cannot notarize genesis block");
        }
        if !H::validate(&block) {
            self.panic("invalid hash length");
        }
        let height = {
            let mut state = self.state.lock().unwrap();
            if state.finalized.contains_key(&block) {
                self.panic("block already finalized");
            }
            if !state.notarized_views.insert(view) {
                self.panic("view already notarized");
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

    async fn finalized(&mut self, view: View, block: Hash) {
        if view == 0 {
            self.panic("cannot finalize genesis block");
        }
        if !H::validate(&block) {
            self.panic("invalid hash length");
        }
        let height = {
            let mut state = self.state.lock().unwrap();
            if state.finalized.contains_key(&block) {
                self.panic("block already finalized");
            }
            if !state.finalized_views.insert(view) {
                self.panic("view already finalized");
            }
            let height = match state.verified.get(&block) {
                Some(height) => *height,
                None => self.panic("block not verified"),
            };
            let expected = state.last_finalized + 1;
            if expected != height {
                self.panic(&format!(
                    "invalid finalization height: {} != {}",
                    expected, height
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

impl<E: Clock + RngCore, H: Hasher, S: Supervisor> crate::Supervisor for Application<E, H, S> {
    fn participants(&self, view: View) -> Option<&Vec<PublicKey>> {
        self.supervisor.participants(view)
    }

    fn is_participant(&self, view: View, candidate: &PublicKey) -> Option<bool> {
        self.supervisor.is_participant(view, candidate)
    }

    async fn report(&mut self, activity: Activity, proof: Proof) {
        self.supervisor.report(activity, proof).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sha256::Sha256, Application as _, Finalizer as _};
    use commonware_cryptography::{Ed25519, Scheme};
    use commonware_runtime::{deterministic::Executor, Runner};
    use futures::StreamExt;

    #[derive(Clone)]
    struct NoReportSupervisor {
        participants: Vec<PublicKey>,
    }

    impl NoReportSupervisor {
        fn new(participants: Vec<PublicKey>) -> Self {
            Self { participants }
        }
    }

    impl Supervisor for NoReportSupervisor {
        fn participants(&self, _view: View) -> Option<&Vec<PublicKey>> {
            Some(&self.participants)
        }

        fn is_participant(&self, _view: View, candidate: &PublicKey) -> Option<bool> {
            Some(self.participants.contains(candidate))
        }

        async fn report(&mut self, _activity: Activity, _proof: Proof) {}
    }

    #[test]
    fn test_normal_flow_propose() {
        // Create the runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let mut hasher = Sha256::default();
            let supervisor = NoReportSupervisor::new(vec![participant.clone()]);
            let (sender, mut receiver) = mpsc::unbounded();
            let cfg = Config {
                hasher: hasher.clone(),
                supervisor,
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                allow_invalid_payload: false,
            };
            let mut app = Application::new(runtime, cfg);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Propose a block at height 1
            let height = 1;
            let view = 1;
            let context = Context {
                parent: genesis_hash.clone(),
                height,
                view,
                proposer: participant.clone(),
            };
            let payload = app.propose(context.clone()).await.expect("propose failed");

            // Parse block
            let payload_hash = app.parse(payload.clone()).await.expect("parse failed");
            hasher.update(&payload_hash);
            let block_hash = hasher.finalize();

            // Verify the block
            let verified = app
                .verify(context, payload.clone(), block_hash.clone())
                .await;
            assert!(verified);

            // Notarize the block
            app.notarized(view, block_hash.clone()).await;

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
            app.finalized(view, block_hash.clone()).await;

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
            let mut hasher = Sha256::default();
            let supervisor = NoReportSupervisor::new(vec![participant.clone()]);
            let (sender, mut receiver) = mpsc::unbounded();
            let cfg = Config {
                hasher: hasher.clone(),
                supervisor,
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                allow_invalid_payload: false,
            };
            let mut app = Application::new(runtime, cfg);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Get block at height 1
            let view = 1;
            let height = 1;
            let context = Context {
                parent: genesis_hash.clone(),
                height,
                view: 1,
                proposer: participant.clone(),
            };
            let mut payload = Vec::new();
            payload.extend_from_slice(&context.proposer);
            payload.extend_from_slice(&context.height.to_be_bytes());
            let payload = Bytes::from(payload);

            // Parse the payload
            let payload_hash = app.parse(payload.clone()).await.expect("parse failed");
            hasher.update(&payload_hash);
            let block_hash = hasher.finalize();

            // Verify the block
            let verified = app
                .verify(context, payload.clone(), block_hash.clone())
                .await;
            assert!(verified);

            // Notarize the block
            app.notarized(view, block_hash.clone()).await;

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
            app.finalized(view, block_hash.clone()).await;

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
            let mut hasher = Sha256::default();
            let supervisor = NoReportSupervisor::new(vec![participant.clone()]);
            let (sender, _) = mpsc::unbounded();
            let cfg = Config {
                hasher: hasher.clone(),
                supervisor,
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                allow_invalid_payload: false,
            };
            let mut app = Application::new(runtime, cfg);

            // Create an invalid parent hash
            hasher.update(&Bytes::from_static(b"invalid"));
            let invalid_parent = hasher.finalize();

            // Attempt to propose a block with invalid parent, should panic
            let context = Context {
                parent: invalid_parent.clone(),
                height: 1,
                view: 1,
                proposer: participant.clone(),
            };
            app.propose(context).await;
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
            let hasher = Sha256::default();
            let supervisor = NoReportSupervisor::new(vec![participant.clone()]);
            let (sender, _) = mpsc::unbounded();
            let cfg = Config {
                hasher: hasher.clone(),
                supervisor,
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                allow_invalid_payload: false,
            };
            let mut app = Application::new(runtime, cfg);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Propose a block at invalid height
            let context = Context {
                parent: genesis_hash.clone(),
                height: 100,
                view: 1,
                proposer: participant.clone(),
            };
            app.propose(context).await;
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
            let mut hasher = Sha256::default();
            let supervisor = NoReportSupervisor::new(vec![participant.clone()]);
            let (sender, _) = mpsc::unbounded();
            let cfg = Config {
                hasher: hasher.clone(),
                supervisor,
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                allow_invalid_payload: false,
            };
            let mut app = Application::new(runtime, cfg);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Create a payload
            let height: Height = 1;
            let mut payload = Vec::new();
            payload.extend_from_slice(&participant);
            payload.extend_from_slice(&height.to_be_bytes());
            let payload = Bytes::from(payload);
            hasher.update(&payload);
            let payload_hash = hasher.finalize();
            hasher.update(&payload_hash);
            let block_hash = hasher.finalize();

            // Attempt to verify the block without parsing, should panic
            let context = Context {
                parent: genesis_hash.clone(),
                height,
                view: 1,
                proposer: participant.clone(),
            };
            app.verify(context, payload, block_hash).await;
        });
    }

    #[test]
    #[should_panic(expected = "invalid height")]
    fn test_verify_invalid_height() {
        // Create the runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let mut hasher = Sha256::default();
            let supervisor = NoReportSupervisor::new(vec![participant.clone()]);
            let (sender, _) = mpsc::unbounded();
            let cfg = Config {
                hasher: hasher.clone(),
                supervisor,
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                allow_invalid_payload: false,
            };
            let mut app = Application::new(runtime, cfg);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Propose a block at height 1
            let height = 1;
            let context = Context {
                parent: genesis_hash.clone(),
                height,
                view: 1,
                proposer: participant.clone(),
            };
            let payload = app.propose(context.clone()).await.expect("propose failed");

            // Parse block
            let payload_hash = app.parse(payload.clone()).await.expect("parse failed");
            hasher.update(&payload_hash);
            let block_hash = hasher.finalize();

            // Attempt to verify the block with incorrect height (e.g., height 2)
            let invalid_context = Context {
                parent: genesis_hash.clone(),
                height: 2,
                view: 1,
                proposer: participant.clone(),
            };
            app.verify(invalid_context, payload, block_hash).await;
        });
    }

    #[test]
    #[should_panic(expected = "parent not verified")]
    fn test_verify_unverified_parent() {
        // Create the runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let mut hasher = Sha256::default();
            let supervisor = NoReportSupervisor::new(vec![participant.clone()]);
            let (sender, _) = mpsc::unbounded();
            let cfg = Config {
                hasher: hasher.clone(),
                supervisor,
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                allow_invalid_payload: false,
            };
            let mut app = Application::new(runtime, cfg);

            // Create an unverified parent hash
            hasher.update(&Bytes::from_static(b"unverified_parent"));
            let unverified_parent = hasher.finalize();

            // Create a payload
            let height: Height = 1;
            let mut payload = Vec::new();
            payload.extend_from_slice(&participant);
            payload.extend_from_slice(&height.to_be_bytes());
            let payload = Bytes::from(payload);
            hasher.update(&payload);
            let payload_hash = hasher.finalize();
            hasher.update(&payload_hash);
            let block_hash = hasher.finalize();

            // Attempt to verify the block with unverified parent, should panic
            let context = Context {
                parent: unverified_parent.clone(),
                height,
                view: 1,
                proposer: participant.clone(),
            };
            app.verify(context, payload, block_hash).await;
        });
    }

    #[test]
    #[should_panic(expected = "invalid payload length")]
    fn test_parse_payload_invalid_length() {
        // Create the runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let hasher = Sha256::default();
            let supervisor = NoReportSupervisor::new(vec![participant.clone()]);
            let (sender, _) = mpsc::unbounded();
            let cfg = Config {
                hasher,
                supervisor,
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                allow_invalid_payload: false,
            };
            let mut app = Application::new(runtime, cfg);

            // Genesis
            let _ = app.genesis();

            // Attempt to parse the payload, should panic
            app.parse(Bytes::from_static(b"short")).await;
        });
    }

    #[test]
    fn test_parse_payload_invalid_length_allowed() {
        // Create the runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let hasher = Sha256::default();
            let supervisor = NoReportSupervisor::new(vec![participant.clone()]);
            let (sender, _) = mpsc::unbounded();
            let cfg = Config {
                hasher,
                supervisor,
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                allow_invalid_payload: true,
            };
            let mut app = Application::new(runtime, cfg);

            // Genesis
            let _ = app.genesis();

            // Attempt to parse the payload, should panic
            app.parse(Bytes::from_static(b"short")).await;
        });
    }

    #[test]
    #[should_panic(expected = "block already verified")]
    fn test_verify_same_hash_twice() {
        // Create the runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let mut hasher = Sha256::default();
            let supervisor = NoReportSupervisor::new(vec![participant.clone()]);
            let (sender, _) = mpsc::unbounded();
            let cfg = Config {
                hasher: hasher.clone(),
                supervisor,
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                allow_invalid_payload: false,
            };
            let mut app = Application::new(runtime, cfg);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Propose a block at height 1
            let height = 1;
            let context = Context {
                parent: genesis_hash.clone(),
                height,
                view: 1,
                proposer: participant.clone(),
            };
            let payload = app.propose(context.clone()).await.expect("propose failed");

            // Parse block
            let payload_hash = app.parse(payload.clone()).await.expect("parse failed");
            hasher.update(&payload_hash);
            let block_hash = hasher.finalize();

            // Verify the block
            app.verify(context.clone(), payload.clone(), block_hash.clone())
                .await;

            // Attempt to verify the same block again, should panic
            app.verify(context, payload, block_hash).await;
        });
    }

    #[test]
    #[should_panic(expected = "block already finalized")]
    fn test_notarize_after_finalize() {
        // Create the runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let mut hasher = Sha256::default();
            let supervisor = NoReportSupervisor::new(vec![participant.clone()]);
            let (sender, _) = mpsc::unbounded();
            let cfg = Config {
                hasher: hasher.clone(),
                supervisor,
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                allow_invalid_payload: false,
            };
            let mut app = Application::new(runtime, cfg);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Propose a block at height 1
            let view = 1;
            let height = 1;
            let context = Context {
                parent: genesis_hash.clone(),
                height,
                view,
                proposer: participant.clone(),
            };
            let payload = app.propose(context.clone()).await.expect("propose failed");

            // Parse block
            let payload_hash = app.parse(payload.clone()).await.expect("parse failed");
            hasher.update(&payload_hash);
            let block_hash = hasher.finalize();

            // Verify the block
            let verified = app
                .verify(context, payload.clone(), block_hash.clone())
                .await;
            assert!(verified);

            // Notarize and finalize the block
            app.notarized(view, block_hash.clone()).await;
            app.finalized(view, block_hash.clone()).await;

            // Attempt to notarize the block again, should panic
            app.notarized(view, block_hash).await;
        });
    }

    #[test]
    #[should_panic(expected = "block not verified")]
    fn test_notarization_not_verified() {
        // Create the runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let mut hasher = Sha256::default();
            let supervisor = NoReportSupervisor::new(vec![participant.clone()]);
            let (sender, _) = mpsc::unbounded();
            let cfg = Config {
                hasher: hasher.clone(),
                supervisor,
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                allow_invalid_payload: false,
            };
            let mut app = Application::new(runtime, cfg);

            // Attempt to notarize an unverified block, should panic
            hasher.update(&Bytes::from_static(b"hello"));
            app.notarized(1, hasher.finalize()).await;
        });
    }

    #[test]
    #[should_panic(expected = "invalid hash length")]
    fn test_notarization_invalid_hash() {
        // Create the runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let hasher = Sha256::default();
            let supervisor = NoReportSupervisor::new(vec![participant.clone()]);
            let (sender, _) = mpsc::unbounded();
            let cfg = Config {
                hasher: hasher.clone(),
                supervisor,
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                allow_invalid_payload: false,
            };
            let mut app = Application::new(runtime, cfg);

            // Attempt to notarize a block with invalid hash length, should panic
            app.notarized(1, Bytes::from_static(b"hello")).await;
        });
    }

    #[test]
    #[should_panic(expected = "block already finalized")]
    fn test_notarization_genesis_block() {
        // Create the runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let hasher = Sha256::default();
            let supervisor = NoReportSupervisor::new(vec![participant.clone()]);
            let (sender, _) = mpsc::unbounded();
            let cfg = Config {
                hasher,
                supervisor,
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                allow_invalid_payload: false,
            };
            let mut app = Application::new(runtime, cfg);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Attempt to notarize the genesis block, should panic
            app.notarized(1, genesis_hash.clone()).await;
        });
    }

    #[test]
    #[should_panic(expected = "block not verified")]
    fn test_finalization_not_verified() {
        // Create the runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let mut hasher = Sha256::default();
            let supervisor = NoReportSupervisor::new(vec![participant.clone()]);
            let (sender, _) = mpsc::unbounded();
            let cfg = Config {
                hasher: hasher.clone(),
                supervisor,
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                allow_invalid_payload: false,
            };
            let mut app = Application::new(runtime, cfg);

            // Attempt to finalize an unverified block, should panic
            hasher.update(&Bytes::from_static(b"hello"));
            app.finalized(1, hasher.finalize()).await;
        });
    }

    #[test]
    #[should_panic(expected = "invalid hash length")]
    fn test_finalization_invalid_hash() {
        // Create the runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let hasher = Sha256::default();
            let supervisor = NoReportSupervisor::new(vec![participant.clone()]);
            let (sender, _) = mpsc::unbounded();
            let cfg = Config {
                hasher,
                supervisor,
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                allow_invalid_payload: false,
            };
            let mut app = Application::new(runtime, cfg);

            // Attempt to finalize a block with invalid hash length, should panic
            app.finalized(1, Bytes::from_static(b"hello")).await;
        });
    }

    #[test]
    #[should_panic(expected = "block already finalized")]
    fn test_finalization_genesis_block() {
        // Create the runtime
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create the application
            let participant = Ed25519::from_seed(0).public_key();
            let hasher = Sha256::default();
            let supervisor = NoReportSupervisor::new(vec![participant.clone()]);
            let (sender, _) = mpsc::unbounded();
            let cfg = Config {
                hasher,
                supervisor,
                participant: participant.clone(),
                sender,
                propose_latency: (10.0, 5.0),
                parse_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                allow_invalid_payload: false,
            };
            let mut app = Application::new(runtime, cfg);

            // Genesis
            let (genesis_hash, _) = app.genesis();

            // Attempt to finalize the genesis block, should panic
            app.finalized(1, genesis_hash.clone()).await;
        });
    }
}

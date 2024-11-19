use super::{Context, Height, View};
use crate::{Activity, Automaton, Finalizer, Payload, Proof, Supervisor};
use bytes::Bytes;
use commonware_cryptography::{Digest, Hasher, PublicKey};
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
    Notarized(Height, Digest),
    Finalized(Height, Digest),
}

#[derive(Default)]
struct State {
    parsed: HashSet<Digest>,
    verified: HashMap<Digest, Height>,
    last_finalized: u64,
    finalized: HashMap<Digest, Height>,

    notarized_views: HashSet<Digest>,
    finalized_views: HashSet<Digest>,
}

#[derive(Clone)]
pub struct Application<E: Clock + RngCore, H: Hasher, S: Supervisor<Index = View>> {
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

impl<E: Clock + RngCore, H: Hasher, S: Supervisor<Index = View>> Application<E, H, S> {
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

impl<E: Clock + RngCore, H: Hasher, S: Supervisor<Index = View>> Automaton
    for Application<E, H, S>
{
    type Context = Context;

    fn genesis(&mut self) -> (Payload, Digest) {
        let payload = Bytes::from(GENESIS_BYTES);
        self.hasher.update(&payload);
        let digest = self.hasher.finalize();
        let mut state = self.state.lock().unwrap();
        state.parsed.insert(digest.clone());
        state.verified.insert(digest.clone(), 0);
        state.finalized.insert(digest.clone(), 0);
        (payload, digest)
    }

    async fn propose(&mut self, context: Self::Context) -> Option<Payload> {
        // Verify parent exists and we are at the correct height
        if !H::validate(&context.parent) {
            self.panic("invalid parent digest length");
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

    async fn parse(&mut self, payload: Payload) -> Option<Digest> {
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
        let digest = self.hasher.finalize();
        {
            let mut state = self.state.lock().unwrap();
            state.parsed.insert(digest.clone());
        }
        Some(digest)
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Payload,
        container: Digest,
    ) -> bool {
        // Simulate the verify latency
        let duration = self.verify_latency.sample(&mut self.runtime);
        self.runtime
            .sleep(Duration::from_millis(duration as u64))
            .await;

        // Verify parent exists and we are at the correct height
        if !H::validate(&context.parent) {
            self.panic("invalid parent digest length");
        }
        if !H::validate(&container) {
            self.panic("invalid digest length");
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
        if state.verified.contains_key(&container) {
            self.panic("container already verified");
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
        let digest = self.hasher.finalize();
        if !state.parsed.contains(&digest) {
            self.panic("payload not parsed");
        }
        state.verified.insert(container, context.height);
        true
    }
}

impl<E: Clock + RngCore, H: Hasher, S: Supervisor<Index = View>> Finalizer
    for Application<E, H, S>
{
    async fn prepared(&mut self, container: Digest) {
        if !H::validate(&container) {
            self.panic("invalid digest length");
        }
        let height = {
            let mut state = self.state.lock().unwrap();
            if state.finalized.contains_key(&container) {
                self.panic("container already finalized");
            }
            if !state.notarized_views.insert(container.clone()) {
                self.panic("view already notarized");
            }
            if let Some(height) = state.verified.get(&container) {
                *height
            } else {
                self.panic("container not verified");
            }
        };
        let _ = self
            .progress
            .send((
                self.participant.clone(),
                Progress::Notarized(height, container),
            ))
            .await;
    }

    async fn finalized(&mut self, container: Digest) {
        if !H::validate(&container) {
            self.panic("invalid digest length");
        }
        let height = {
            let mut state = self.state.lock().unwrap();
            if state.finalized.contains_key(&container) {
                self.panic("container already finalized");
            }
            if !state.finalized_views.insert(container.clone()) {
                self.panic("view already finalized");
            }
            let height = match state.verified.get(&container) {
                Some(height) => *height,
                None => self.panic("container not verified"),
            };
            let expected = state.last_finalized + 1;
            if expected != height {
                self.panic(&format!(
                    "invalid finalization height: {} != {}",
                    expected, height
                ));
            }
            state.last_finalized = height;
            state.finalized.insert(container.clone(), height);
            height
        };
        let _ = self
            .progress
            .send((
                self.participant.clone(),
                Progress::Finalized(height, container),
            ))
            .await;
    }
}

// TODO: do we actually need to provide supervisor here?
impl<E: Clock + RngCore, H: Hasher, S: Supervisor<Seed = (), Index = View>> Supervisor
    for Application<E, H, S>
{
    type Index = S::Index;
    type Seed = S::Seed;

    fn leader(&self, index: View, _seed: ()) -> Option<PublicKey> {
        let participants = self.supervisor.participants(index)?;
        let index = index % participants.len() as u64;
        Some(participants[index as usize].clone())
    }

    fn participants(&self, index: View) -> Option<&Vec<PublicKey>> {
        self.supervisor.participants(index)
    }

    fn is_participant(&self, index: View, candidate: &PublicKey) -> Option<bool> {
        self.supervisor.is_participant(index, candidate)
    }

    async fn report(&mut self, activity: Activity, proof: Proof) {
        self.supervisor.report(activity, proof).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Ed25519, Scheme, Sha256};
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
        type Index = View;
        type Seed = ();

        fn leader(&self, index: View, _seed: ()) -> Option<PublicKey> {
            let index = index % self.participants.len() as u64;
            Some(self.participants[index as usize].clone())
        }

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
            let (_, genesis_digest) = app.genesis();

            // Propose a container at height 1
            let height = 1;
            let view = 1;
            let context = Context {
                parent: genesis_digest.clone(),
                height,
                view,
                proposer: participant.clone(),
            };
            let payload = app.propose(context.clone()).await.expect("propose failed");

            // Parse container
            let payload_digest = app.parse(payload.clone()).await.expect("parse failed");
            hasher.update(&payload_digest);
            let container_digest = hasher.finalize();

            // Verify the container
            let verified = app
                .verify(context, payload.clone(), container_digest.clone())
                .await;
            assert!(verified);

            // Notarize the container
            app.prepared(container_digest.clone()).await;

            // Expect a progress message for notarization
            let (progress_participant, progress) =
                receiver.next().await.expect("no progress message");
            assert_eq!(progress_participant, participant);
            match progress {
                Progress::Notarized(notarized_height, notarized_digest) => {
                    assert_eq!(notarized_height, height);
                    assert_eq!(notarized_digest, container_digest);
                }
                _ => panic!("expected Notarized progress"),
            }

            // Finalize the container
            app.finalized(container_digest.clone()).await;

            // Expect a progress message for finalization
            let (progress_participant, progress) =
                receiver.next().await.expect("no progress message");
            assert_eq!(progress_participant, participant);
            match progress {
                Progress::Finalized(finalized_height, finalized_digest) => {
                    assert_eq!(finalized_height, height);
                    assert_eq!(finalized_digest, container_digest);
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
            let (_, genesis_digest) = app.genesis();

            // Get container at height 1
            let height = 1;
            let context = Context {
                parent: genesis_digest.clone(),
                height,
                view: 1,
                proposer: participant.clone(),
            };
            let mut payload = Vec::new();
            payload.extend_from_slice(&context.proposer);
            payload.extend_from_slice(&context.height.to_be_bytes());
            let payload = Bytes::from(payload);

            // Parse the payload
            let payload_digest = app.parse(payload.clone()).await.expect("parse failed");
            hasher.update(&payload_digest);
            let container_digest = hasher.finalize();

            // Verify the container
            let verified = app
                .verify(context, payload.clone(), container_digest.clone())
                .await;
            assert!(verified);

            // Notarize the container
            app.prepared(container_digest.clone()).await;

            // Expect a progress message for notarization
            let (progress_participant, progress) =
                receiver.next().await.expect("no progress message");
            assert_eq!(progress_participant, participant);
            match progress {
                Progress::Notarized(notarized_height, notarized_digest) => {
                    assert_eq!(notarized_height, height);
                    assert_eq!(notarized_digest, container_digest);
                }
                _ => panic!("expected Notarized progress"),
            }

            // Finalize the container
            app.finalized(container_digest.clone()).await;

            // Expect a progress message for finalization
            let (progress_participant, progress) =
                receiver.next().await.expect("no progress message");
            assert_eq!(progress_participant, participant);
            match progress {
                Progress::Finalized(finalized_height, finalized_digest) => {
                    assert_eq!(finalized_height, height);
                    assert_eq!(finalized_digest, container_digest);
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

            // Create an invalid parent digest
            hasher.update(&Bytes::from_static(b"invalid"));
            let invalid_parent = hasher.finalize();

            // Attempt to propose a container with invalid parent, should panic
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
            let (_, genesis_digest) = app.genesis();

            // Propose a container at invalid height
            let context = Context {
                parent: genesis_digest.clone(),
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
            let (_, genesis_digest) = app.genesis();

            // Create a payload
            let height: Height = 1;
            let mut payload = Vec::new();
            payload.extend_from_slice(&participant);
            payload.extend_from_slice(&height.to_be_bytes());
            let payload = Bytes::from(payload);
            hasher.update(&payload);
            let payload_digest = hasher.finalize();
            hasher.update(&payload_digest);
            let container_digest = hasher.finalize();

            // Attempt to verify the container without parsing, should panic
            let context = Context {
                parent: genesis_digest.clone(),
                height,
                view: 1,
                proposer: participant.clone(),
            };
            app.verify(context, payload, container_digest).await;
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
            let (_, genesis_digest) = app.genesis();

            // Propose a container at height 1
            let height = 1;
            let context = Context {
                parent: genesis_digest.clone(),
                height,
                view: 1,
                proposer: participant.clone(),
            };
            let payload = app.propose(context.clone()).await.expect("propose failed");

            // Parse container
            let payload_digest = app.parse(payload.clone()).await.expect("parse failed");
            hasher.update(&payload_digest);
            let container_digest = hasher.finalize();

            // Attempt to verify the container with incorrect height (e.g., height 2)
            let invalid_context = Context {
                parent: genesis_digest.clone(),
                height: 2,
                view: 1,
                proposer: participant.clone(),
            };
            app.verify(invalid_context, payload, container_digest).await;
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

            // Create an unverified parent digest
            hasher.update(&Bytes::from_static(b"unverified_parent"));
            let unverified_parent = hasher.finalize();

            // Create a payload
            let height: Height = 1;
            let mut payload = Vec::new();
            payload.extend_from_slice(&participant);
            payload.extend_from_slice(&height.to_be_bytes());
            let payload = Bytes::from(payload);
            hasher.update(&payload);
            let payload_digest = hasher.finalize();
            hasher.update(&payload_digest);
            let container_digest = hasher.finalize();

            // Attempt to verify the container with unverified parent, should panic
            let context = Context {
                parent: unverified_parent.clone(),
                height,
                view: 1,
                proposer: participant.clone(),
            };
            app.verify(context, payload, container_digest).await;
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
    #[should_panic(expected = "container already verified")]
    fn test_verify_same_digest_twice() {
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
            let (_, genesis_digest) = app.genesis();

            // Propose a container at height 1
            let height = 1;
            let context = Context {
                parent: genesis_digest.clone(),
                height,
                view: 1,
                proposer: participant.clone(),
            };
            let payload = app.propose(context.clone()).await.expect("propose failed");

            // Parse container
            let payload_digest = app.parse(payload.clone()).await.expect("parse failed");
            hasher.update(&payload_digest);
            let container_digest = hasher.finalize();

            // Verify the container
            app.verify(context.clone(), payload.clone(), container_digest.clone())
                .await;

            // Attempt to verify the same container again, should panic
            app.verify(context, payload, container_digest).await;
        });
    }

    #[test]
    #[should_panic(expected = "container already finalized")]
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
            let (_, genesis_digest) = app.genesis();

            // Propose a container at height 1
            let view = 1;
            let height = 1;
            let context = Context {
                parent: genesis_digest.clone(),
                height,
                view,
                proposer: participant.clone(),
            };
            let payload = app.propose(context.clone()).await.expect("propose failed");

            // Parse container
            let payload_digest = app.parse(payload.clone()).await.expect("parse failed");
            hasher.update(&payload_digest);
            let container_digest = hasher.finalize();

            // Verify the container
            let verified = app
                .verify(context, payload.clone(), container_digest.clone())
                .await;
            assert!(verified);

            // Notarize and finalize the container
            app.prepared(container_digest.clone()).await;
            app.finalized(container_digest.clone()).await;

            // Attempt to notarize the container again, should panic
            app.prepared(container_digest).await;
        });
    }

    #[test]
    #[should_panic(expected = "container not verified")]
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

            // Attempt to notarize an unverified container, should panic
            hasher.update(&Bytes::from_static(b"hello"));
            app.prepared(hasher.finalize()).await;
        });
    }

    #[test]
    #[should_panic(expected = "invalid digest length")]
    fn test_notarization_invalid_digest() {
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

            // Attempt to notarize a container with invalid digest length, should panic
            app.prepared(Bytes::from_static(b"hello")).await;
        });
    }

    #[test]
    #[should_panic(expected = "container already finalized")]
    fn test_notarization_genesis_container() {
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
            let (_, genesis_digest) = app.genesis();

            // Attempt to notarize the genesis container, should panic
            app.prepared(genesis_digest.clone()).await;
        });
    }

    #[test]
    #[should_panic(expected = "container not verified")]
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

            // Attempt to finalize an unverified container, should panic
            hasher.update(&Bytes::from_static(b"hello"));
            app.finalized(hasher.finalize()).await;
        });
    }

    #[test]
    #[should_panic(expected = "invalid digest length")]
    fn test_finalization_invalid_digest() {
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

            // Attempt to finalize a container with invalid digest length, should panic
            app.finalized(Bytes::from_static(b"hello")).await;
        });
    }

    #[test]
    #[should_panic(expected = "container already finalized")]
    fn test_finalization_genesis_container() {
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
            let (_, genesis_digest) = app.genesis();

            // Attempt to finalize the genesis container, should panic
            app.finalized(genesis_digest.clone()).await;
        });
    }
}

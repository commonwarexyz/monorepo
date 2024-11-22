use super::{Context, Height, View};
use crate::{Activity, Automaton, Header, Proof, Supervisor};
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
    // TODO: need to input broadcast artifacts into application
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

impl<E: Clock + RngCore, H: Hasher, S: Supervisor<Seed = (), Index = View>> Automaton
    for Application<E, H, S>
{
    type Context = Context;

    fn genesis(&self) -> Digest {
        let payload = Bytes::from(GENESIS_BYTES);
        // TODO: clean this up
        let mut hasher = self.hasher.clone();
        hasher.update(&payload);
        let digest = hasher.finalize();
        let mut state = self.state.lock().unwrap();
        state.parsed.insert(digest.clone());
        state.verified.insert(digest.clone(), 0);
        state.finalized.insert(digest.clone(), 0);
        digest
    }

    async fn propose(&mut self, context: Self::Context) -> Option<Digest> {
        // Verify parent exists and we are at the correct height
        if !H::validate(&context.parent.1) {
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

    async fn broadcast(&mut self, context: Self::Context, header: Header, payload: Digest) {
        unimplemented!();
    }

    async fn verify(&mut self, context: Self::Context, payload: Digest) -> Option<bool> {
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
        None
    }

    async fn notarized(&mut self, context: Self::Context, container: Digest) {
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

    async fn finalized(&mut self, context: Self::Context, container: Digest) {
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

impl<E: Clock + RngCore, H: Hasher, S: Supervisor<Seed = (), Index = View>> Supervisor
    for Application<E, H, S>
{
    type Index = S::Index;
    type Seed = S::Seed;

    fn leader(&self, index: Self::Index, seed: Self::Seed) -> Option<PublicKey> {
        self.supervisor.leader(index, seed)
    }

    fn participants(&self, index: Self::Index) -> Option<&Vec<PublicKey>> {
        self.supervisor.participants(index)
    }

    fn is_participant(&self, index: Self::Index, candidate: &PublicKey) -> Option<bool> {
        self.supervisor.is_participant(index, candidate)
    }

    async fn report(&mut self, activity: Activity, proof: Proof) {
        self.supervisor.report(activity, proof).await
    }
}

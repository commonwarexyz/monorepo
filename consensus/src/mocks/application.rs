use crate::{Context, Hash, Hasher, Height, Payload, Proof, Supervisor, View};
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
        if payload.len() != 40 {
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

impl<E: Clock + RngCore, H: Hasher, S: Supervisor> crate::Supervisor for Application<E, H, S> {
    fn participants(&self, view: View) -> Option<&Vec<PublicKey>> {
        self.supervisor.participants(view)
    }

    fn is_participant(&self, view: View, candidate: &PublicKey) -> Option<bool> {
        self.supervisor.is_participant(view, candidate)
    }

    async fn report(&mut self, activity: crate::Activity, proof: Proof) {
        self.supervisor.report(activity, proof).await
    }
}

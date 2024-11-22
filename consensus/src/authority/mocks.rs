use super::{
    prover::Prover, Context, Height, View, CONFLICTING_FINALIZE, CONFLICTING_NOTARIZE, FINALIZE,
    NOTARIZE, NULLIFY_AND_FINALIZE,
};
use crate::{Activity, Automaton as Au, Header, Proof, Supervisor as Su};
use bytes::Bytes;
use commonware_cryptography::{Digest, Hasher, PublicKey, Scheme};
use commonware_runtime::Clock;
use commonware_utils::hex;
use core::hash;
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

#[derive(Clone)]
pub struct Broadcast {
    containers: Arc<Mutex<HashMap<Digest, Bytes>>>,
}

impl Broadcast {
    pub fn new() -> Self {
        Self {
            containers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn put(&self, container: Digest, payload: Bytes) {
        self.containers.lock().unwrap().insert(container, payload);
    }

    pub async fn get(&self, container: Digest) -> Option<Bytes> {
        self.containers.lock().unwrap().remove(&container)
    }
}

pub struct AutomatonConfig<H: Hasher> {
    pub hasher: H,

    pub broadcast: Broadcast,

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
pub struct Automaton<E: Clock + RngCore, H: Hasher> {
    runtime: E,

    hasher: Arc<Mutex<H>>,
    broadcast: Broadcast,

    participant: PublicKey,

    propose_latency: Normal<f64>,
    parse_latency: Normal<f64>,
    verify_latency: Normal<f64>,
    allow_invalid_payload: bool,

    progress: mpsc::UnboundedSender<(PublicKey, Progress)>,

    state: Arc<Mutex<State>>,
}

impl<E: Clock + RngCore, H: Hasher> Automaton<E, H> {
    // TODO: need to input broadcast artifacts into automaton concurrently?
    pub fn new(runtime: E, cfg: AutomatonConfig<H>) -> Self {
        // Generate samplers
        let propose_latency = Normal::new(cfg.propose_latency.0, cfg.propose_latency.1).unwrap();
        let parse_latency = Normal::new(cfg.parse_latency.0, cfg.parse_latency.1).unwrap();
        let verify_latency = Normal::new(cfg.verify_latency.0, cfg.verify_latency.1).unwrap();

        // Return constructed application
        Self {
            runtime,

            hasher: Arc::new(Mutex::new(cfg.hasher)),
            broadcast: cfg.broadcast,

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

impl<E: Clock + RngCore, H: Hasher> Au for Automaton<E, H> {
    type Context = Context;

    fn genesis(&self) -> Digest {
        let payload = Bytes::from(GENESIS_BYTES);
        let digest = {
            let mut hasher = self.hasher.lock().unwrap();
            hasher.update(&payload);
            hasher.finalize()
        };
        let mut state = self.state.lock().unwrap();
        state.parsed.insert(digest.clone());
        state.verified.insert(digest.clone(), 0);
        state.finalized.insert(digest.clone(), 0);
        digest
    }

    async fn propose(&self, context: Self::Context) -> Option<Digest> {
        // Verify parent exists and we are at the correct height
        if !H::validate(&context.parent.1) {
            self.panic("invalid parent digest length");
        }
        if self.broadcast.get(context.parent.1).await.is_none() {
            return None;
        }
        {
            let state = self.state.lock().unwrap();
            if !state.verified.contains_key(&context.parent.1) {
                return None;
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
        payload.extend_from_slice(&context.index.0.to_be_bytes());
        payload.extend_from_slice(&context.index.1.to_be_bytes());
        let mut hasher = self.hasher.lock().unwrap();
        hasher.update(&payload);
        Some(hasher.finalize())
    }

    async fn broadcast(&self, context: Self::Context, header: Header, payload: Digest) {
        // TODO: need to send to other application instances using a simple overlay
        // TODO: if get block after all votes, no one will do anything?
        unimplemented!();
        self.broadcast.put(payload, pending);
    }

    async fn verify(&self, context: Self::Context, payload: Digest) -> Option<bool> {
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

    async fn notarized(&self, context: Self::Context, container: Digest) {
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

    async fn finalized(&self, context: Self::Context, container: Digest) {
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

pub struct SupervisorConfig<C: Scheme, H: Hasher> {
    pub prover: Prover<C, H>,
    pub participants: BTreeMap<View, Vec<PublicKey>>,
}

type HeightActivity = HashMap<Height, HashMap<Digest, HashSet<PublicKey>>>;
type Faults = HashMap<PublicKey, HashMap<View, HashSet<Activity>>>;

#[derive(Clone)]
pub struct Supervisor<C: Scheme, H: Hasher> {
    participants: BTreeMap<View, (HashSet<PublicKey>, Vec<PublicKey>)>,

    prover: Prover<C, H>,

    proposals: Arc<Mutex<HeightActivity>>,
    votes: Arc<Mutex<HeightActivity>>,
    finalizes: Arc<Mutex<HeightActivity>>,
    faults: Arc<Mutex<Faults>>,
}

impl<C: Scheme, H: Hasher> Supervisor<C, H> {
    fn new(cfg: SupervisorConfig<C, H>) -> Self {
        let mut parsed_participants = BTreeMap::new();
        for (view, mut validators) in cfg.participants.into_iter() {
            let mut set = HashSet::new();
            for validator in validators.iter() {
                set.insert(validator.clone());
            }
            validators.sort();
            parsed_participants.insert(view, (set.clone(), validators));
        }
        Self {
            participants: parsed_participants,
            prover: cfg.prover,
            proposals: Arc::new(Mutex::new(HashMap::new())),
            votes: Arc::new(Mutex::new(HashMap::new())),
            finalizes: Arc::new(Mutex::new(HashMap::new())),
            faults: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<C: Scheme, H: Hasher> Su for Supervisor<C, H> {
    type Index = View;
    type Seed = ();

    fn leader(&self, index: Self::Index, _seed: Self::Seed) -> Option<PublicKey> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, p)) => p,
            None => {
                panic!("no participants in required range");
            }
        };
        Some(closest.1[index as usize % closest.1.len()].clone())
    }

    fn participants(&self, index: Self::Index) -> Option<&Vec<PublicKey>> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, p)) => p,
            None => {
                panic!("no participants in required range");
            }
        };
        Some(&closest.1)
    }

    fn is_participant(&self, index: Self::Index, candidate: &PublicKey) -> Option<bool> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, p)) => p,
            None => {
                panic!("no participants in required range");
            }
        };
        Some(closest.0.contains(candidate))
    }

    async fn report(&mut self, activity: Activity, proof: Proof) {
        // We check signatures for all messages to ensure that the prover is working correctly
        // but in production this isn't necessary (as signatures are already verified in
        // consensus).
        match activity {
            NOTARIZE => {
                // TODO: use payload digest?
                let (index, _, payload, public_key) =
                    self.prover.deserialize_notarize(proof, true).unwrap();
                self.votes
                    .lock()
                    .unwrap()
                    .entry(index.height)
                    .or_default()
                    .entry(payload)
                    .or_default()
                    .insert(public_key);
            }
            FINALIZE => {
                let (index, _, payload, public_key) =
                    self.prover.deserialize_finalize(proof, true).unwrap();
                self.finalizes
                    .lock()
                    .unwrap()
                    .entry(index.height)
                    .or_default()
                    .entry(payload)
                    .or_default()
                    .insert(public_key);
            }
            CONFLICTING_NOTARIZE => {
                let (public_key, view) = self
                    .prover
                    .deserialize_conflicting_notarize(proof, true)
                    .unwrap();
                self.faults
                    .lock()
                    .unwrap()
                    .entry(public_key)
                    .or_default()
                    .entry(view)
                    .or_default()
                    .insert(CONFLICTING_NOTARIZE);
            }
            CONFLICTING_FINALIZE => {
                let (public_key, view) = self
                    .prover
                    .deserialize_conflicting_finalize(proof, true)
                    .unwrap();
                self.faults
                    .lock()
                    .unwrap()
                    .entry(public_key)
                    .or_default()
                    .entry(view)
                    .or_default()
                    .insert(CONFLICTING_FINALIZE);
            }
            NULLIFY_AND_FINALIZE => {
                let (public_key, view) = self
                    .prover
                    .deserialize_nullify_finalize(proof, true)
                    .unwrap();
                self.faults
                    .lock()
                    .unwrap()
                    .entry(public_key)
                    .or_default()
                    .entry(view)
                    .or_default()
                    .insert(NULLIFY_AND_FINALIZE);
            }
            unexpected => {
                panic!("unexpected activity: {}", unexpected);
            }
        }
    }
}

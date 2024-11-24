use super::{
    prover::Prover, Context, View, CONFLICTING_FINALIZE, CONFLICTING_NOTARIZE, FINALIZE, NOTARIZE,
    NULLIFY_AND_FINALIZE,
};
use crate::{Activity, Automaton as Au, Finalizer, Proof, Relay as Re, Supervisor as Su};
use bytes::Bytes;
use commonware_cryptography::{Digest, Hasher, PublicKey, Scheme};
use commonware_runtime::Clock;
use commonware_utils::hex;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use rand::RngCore;
use rand_distr::{Distribution, Normal};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use tracing::debug;

const GENESIS_BYTES: &[u8] = b"genesis";

type Latency = (f64, f64);

#[derive(Clone)]
pub struct Relay {
    pending: HashMap<Digest, Bytes>,
    broadcast: HashMap<Digest, Bytes>,
}

impl Relay {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            broadcast: HashMap::new(),
        }
    }

    pub fn pending(&mut self, container: Digest, payload: Bytes) {
        self.pending.insert(container, payload);
    }

    pub fn broadcast(&mut self, container: Digest) {
        let payload = self
            .pending
            .remove(&container)
            .expect("container not pending");
        self.broadcast.insert(container, payload);
    }

    pub fn get(&self, container: &Digest) -> Option<Bytes> {
        self.broadcast.get(container).cloned()
    }
}

pub struct AutomatonConfig<H: Hasher> {
    pub hasher: H,

    pub relay: Arc<Mutex<Relay>>,

    /// The public key of the participant.
    ///
    /// It is common to use multiple instances of an application in a single simulation, this
    /// helps to identify the source of both progress and errors.
    pub participant: PublicKey,

    pub propose_latency: Latency,
    pub verify_latency: Latency,

    pub sender: mpsc::UnboundedSender<(PublicKey, Progress)>,
}

pub enum Progress {
    Notarized(Proof, Digest),
    Finalized(Proof, Digest),
}

enum Work {
    Propose(Context, oneshot::Sender<Digest>),
    Verify(Context, Digest, oneshot::Sender<bool>),
}

pub struct Automaton<E: Clock + RngCore, H: Hasher> {
    runtime: E,
    hasher: H,
    participant: PublicKey,

    /// Relay is a mock for distributing artifacts between applications.
    relay: Arc<Mutex<Relay>>,

    propose_latency: Normal<f64>,
    verify_latency: Normal<f64>,

    progress: mpsc::UnboundedSender<(PublicKey, Progress)>,

    work_sender: mpsc::UnboundedSender<Work>,
    work_receiver: mpsc::UnboundedReceiver<Work>,

    verified: HashSet<Digest>,

    notarized_views: HashSet<Digest>,
    finalized_views: HashSet<Digest>,
    last_finalized: u64,
}

impl<E: Clock + RngCore, H: Hasher> Automaton<E, H> {
    // TODO: need to input broadcast artifacts into automaton concurrently?
    pub fn new(runtime: E, cfg: AutomatonConfig<H>) -> Self {
        // Generate samplers
        let propose_latency = Normal::new(cfg.propose_latency.0, cfg.propose_latency.1).unwrap();
        let verify_latency = Normal::new(cfg.verify_latency.0, cfg.verify_latency.1).unwrap();

        // Return constructed application
        let (work_sender, work_receiver) = mpsc::unbounded();
        Self {
            runtime,

            hasher: cfg.hasher,
            relay: cfg.relay,

            participant: cfg.participant,

            propose_latency,
            verify_latency,

            progress: cfg.sender,

            work_sender,
            work_receiver,

            verified: HashSet::new(),

            last_finalized: 0,
            notarized_views: HashSet::new(),
            finalized_views: HashSet::new(),
        }
    }

    fn panic(&self, msg: &str) -> ! {
        panic!("[{}] {}", hex(&self.participant), msg);
    }

    pub async fn run(mut self) {
        while let Some(work) = self.work_receiver.next().await {
            match work {
                Work::Propose(context, sender) => {

        // Simulate the propose latency
        let duration = self.propose_latency.sample(&mut self.runtime);
        self.runtime
            .sleep(Duration::from_millis(duration as u64))
            .await;

        // Verify parent exists and we are at the correct height
        if !H::validate(&context.parent.1) {
            self.panic("invalid parent digest length");
        }
        let parent_height = match self.state.verified.get(&context.parent.1) {
            Some(height) => *height,
            None => {
                debug!(parent = hex(&context.parent.1), "parent not verified");
                return None;
            }
        };
        if context.index.1 != parent_height + 1 {
            self.panic(&format!(
                "invalid height: {} != {} + 1",
                context.index.1, parent_height
            ));
        }

        // Generate the payload
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.participant);
        payload.extend_from_slice(&context.index.0.to_be_bytes());
        payload.extend_from_slice(&context.index.1.to_be_bytes());
        self.hasher.update(&payload);
        let digest = self.hasher.finalize();

        // Mark verified
        self.state.verified.insert(digest.clone(), context.index.1);

        // Store pending payload
        self.relay
            .lock()
            .unwrap()
            .pending(digest.clone(), Bytes::from(payload));
        Some(digest)
                    let _ = self.propose(context).await;
                }
                Work::Verify(context, payload, sender) => {
                    let _ = self.verify(context, payload).await;

        // Simulate the verify latency
        let duration = self.verify_latency.sample(&mut self.runtime);
        self.runtime
            .sleep(Duration::from_millis(duration as u64))
            .await;

        // Verify parent exists and we are at the correct height
        if !H::validate(&context.parent.1) {
            self.panic("invalid parent digest length");
        }
        if !H::validate(&payload) {
            self.panic("invalid digest length");
        }

        // Ensure not duplicate check
        if self.state.verified.contains_key(&payload) {
            self.panic("container already verified");
        }

        // TODO: verified should include concatenation fo parent/payload?
        if let Some(parent) = self.state.verified.get(&context.parent.1) {
            if parent + 1 != context.index.1 {
                self.panic(&format!(
                    "invalid height (from last verified): {} != {}",
                    parent + 1,
                    context.index.1
                ));
            }
        } else {
            debug!(parent = hex(&context.parent.1), "parent not verified");
            return None;
        };

        // Verify the payload
        let contents = match self.relay.lock().unwrap().get(&payload) {
            Some(contents) => contents,
            None => return None,
        };
        if !self.allow_invalid_payload {
            if contents.len() != 48 {
                self.panic("invalid payload length");
            }
            let parsed_view = Height::from_be_bytes(contents[32..40].try_into().unwrap());
            if parsed_view != context.index.0 {
                self.panic(&format!(
                    "invalid view (in payload): {} != {}",
                    parsed_view, context.index.0
                ));
            }
            let parsed_height = Height::from_be_bytes(contents[40..].try_into().unwrap());
            if parsed_height != context.index.1 {
                self.panic(&format!(
                    "invalid height (in payload): {} != {}",
                    parsed_height, context.index.1
                ));
            }
        }
        debug!(payload = hex(&payload), "verified");
        self.state.verified.insert(payload, context.index.1);
        Some(true)
                }
            }
        }
    }
}

impl<E: Clock + RngCore, H: Hasher> Au for Automaton<E, H> {
    type Context = Context;

    fn genesis(&mut self) -> Digest {
        let payload = Bytes::from(GENESIS_BYTES);
        self.hasher.update(&payload);
        let digest = self.hasher.finalize();
        self.verified.insert(digest.clone());
        self.finalized_views.insert(digest.clone());
        digest
    }

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Digest> {
        let (sender, receiver) = oneshot::channel();
        let _ = self
            .work_sender
            .send(Work::Propose(context, sender))
            .await;
        receiver
    }

    async fn verify(&mut self, context: Self::Context, payload: Digest) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        let _ = self
            .work_sender
            .send(Work::Verify(context, payload, sender))
            .await;
        receiver
    }
}

impl <E: Clock + RngCore, H: Hasher> Re for Automaton<E, H> {
    async fn broadcast(&mut self, payload: Digest) {
        self.relay.lock().unwrap().broadcast(payload);
    }
}

impl <E:Clock + RngCore, H: Hasher> Finalizer for Automaton<E, H> {
    async fn notarized(&mut self, proof: Proof, payload: Digest) {
        if !H::validate(&payload) {
            self.panic("invalid digest length");
        }
        if !self.notarized_views.insert(payload.clone()) {
            self.panic("view already notarized");
        }
        let _ = self
            .progress
            .send((
                self.participant.clone(),
                Progress::Notarized(proof, payload),
            ))
            .await;
    }

    async fn finalized(&mut self, proof:Proof, payload: Digest) {
        if !H::validate(&payload) {
            self.panic("invalid digest length");
        }
        if !self.finalized_views.insert(payload.clone()) {
            self.panic("view already finalized");
        }
        let _ = self
            .progress
            .send((
                self.participant.clone(),
                Progress::Finalized(proof, payload),
            ))
            .await;
    }
}

pub struct SupervisorConfig<C: Scheme, H: Hasher> {
    pub prover: Prover<C, H>,
    pub participants: BTreeMap<View, Vec<PublicKey>>,
}

type Faults = HashMap<PublicKey, HashMap<View, HashSet<Activity>>>;

#[derive(Clone)]
pub struct Supervisor<C: Scheme, H: Hasher> {
    participants: BTreeMap<View, (HashSet<PublicKey>, Vec<PublicKey>)>,

    prover: Prover<C, H>,

    pub votes: Arc<Mutex<HeightActivity>>,
    pub finalizes: Arc<Mutex<HeightActivity>>,
    pub faults: Arc<Mutex<Faults>>,
}

impl<C: Scheme, H: Hasher> Supervisor<C, H> {
    pub fn new(cfg: SupervisorConfig<C, H>) -> Self {
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

    async fn report(&self, activity: Activity, proof: Proof) {
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

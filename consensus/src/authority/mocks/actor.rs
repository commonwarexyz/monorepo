use super::{
    ingress::{Mailbox, Message},
    relay::Relay,
};
use crate::{
    authority::{
        prover::Prover, Context, View, CONFLICTING_FINALIZE, CONFLICTING_NOTARIZE, FINALIZE,
        NOTARIZE, NULLIFY_AND_FINALIZE,
    },
    Activity, Proof, Supervisor as Su,
};
use bytes::{Buf, Bytes};
use commonware_cryptography::{Digest, Hasher, PublicKey, Scheme};
use commonware_macros::select;
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

pub enum Progress {
    Notarized(Proof, Digest),
    Finalized(Proof, Digest),
}

pub struct ApplicationConfig<H: Hasher> {
    pub hasher: H,

    pub relay: Arc<Relay>,

    /// The public key of the participant.
    ///
    /// It is common to use multiple instances of an application in a single simulation, this
    /// helps to identify the source of both progress and errors.
    pub participant: PublicKey,

    pub propose_latency: Latency,
    pub verify_latency: Latency,

    pub tracker: mpsc::UnboundedSender<(PublicKey, Progress)>,
}

pub struct Application<E: Clock + RngCore, H: Hasher> {
    runtime: E,
    hasher: H,
    participant: PublicKey,

    relay: Arc<Relay>,
    broadcast: mpsc::UnboundedReceiver<(Digest, Bytes)>,
    tracker: mpsc::UnboundedSender<(PublicKey, Progress)>,

    mailbox: mpsc::Receiver<Message>,

    propose_latency: Normal<f64>,
    verify_latency: Normal<f64>,

    pending: HashMap<Digest, Bytes>,

    verified: HashSet<Digest>,
    notarized_views: HashSet<Digest>,
    finalized_views: HashSet<Digest>,
    last_finalized: u64,
}

impl<E: Clock + RngCore, H: Hasher> Application<E, H> {
    // TODO: need to input broadcast artifacts into automaton concurrently?
    pub fn new(runtime: E, cfg: ApplicationConfig<H>) -> (Self, Mailbox) {
        // Register self on relay
        let broadcast = cfg.relay.register(cfg.participant.clone());

        // Generate samplers
        let propose_latency = Normal::new(cfg.propose_latency.0, cfg.propose_latency.1).unwrap();
        let verify_latency = Normal::new(cfg.verify_latency.0, cfg.verify_latency.1).unwrap();

        // Return constructed application
        let (sender, receiver) = mpsc::channel(1024);
        (
            Self {
                runtime,
                hasher: cfg.hasher,
                participant: cfg.participant,

                relay: cfg.relay,
                broadcast,
                tracker: cfg.tracker,

                mailbox: receiver,

                propose_latency,
                verify_latency,

                pending: HashMap::new(),

                verified: HashSet::new(),
                last_finalized: 0,
                notarized_views: HashSet::new(),
                finalized_views: HashSet::new(),
            },
            Mailbox::new(sender),
        )
    }

    fn panic(&self, msg: &str) -> ! {
        panic!("[{}] {}", hex(&self.participant), msg);
    }

    fn genesis(&mut self) -> Digest {
        let payload = Bytes::from(GENESIS_BYTES);
        self.hasher.update(&payload);
        let digest = self.hasher.finalize();
        self.verified.insert(digest.clone());
        self.finalized_views.insert(digest.clone());
        digest
    }

    /// When proposing a block, we do not care if the parent is verified (or even in our possession).
    /// Backfilling verification dependencies is considered out-of-scope for consensus.
    async fn propose(&mut self, context: Context) -> Digest {
        // Simulate the propose latency
        let duration = self.propose_latency.sample(&mut self.runtime);
        self.runtime
            .sleep(Duration::from_millis(duration as u64))
            .await;

        // Verify parent exists and we are at the correct height
        if !H::validate(&context.parent.1) {
            self.panic("invalid parent digest length");
        }

        // Generate the payload
        let mut payload = Vec::new();
        payload.extend_from_slice(&context.view.to_be_bytes());
        payload.extend_from_slice(&context.parent.1);
        self.hasher.update(&payload);
        let digest = self.hasher.finalize();

        // Mark verified
        self.verified.insert(digest.clone());

        // Store pending payload
        self.pending.insert(digest.clone(), payload.into());
        digest
    }

    async fn verify(&mut self, context: Context, payload: Digest, mut contents: Bytes) -> bool {
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

        // Verify contents
        if contents.len() != 40 {
            self.panic("invalid payload length");
        }
        let parsed_view = contents.get_u64();
        if parsed_view != context.view {
            self.panic(&format!(
                "invalid view (in payload): {} != {}",
                parsed_view, context.view
            ));
        }
        let parsed_parent: Digest = contents.copy_to_bytes(H::len());
        if parsed_parent != context.parent.1 {
            self.panic(&format!(
                "invalid parent (in payload): {} != {}",
                hex(&parsed_parent),
                hex(&context.parent.1)
            ));
        }
        debug!(payload = hex(&payload), "verified");
        self.verified.insert(payload);
        true
    }

    async fn broadcast(&mut self, payload: Digest) {
        let contents = self.pending.remove(&payload).expect("missing payload");
        self.relay
            .broadcast(&self.participant, (payload, contents))
            .await;
    }

    async fn notarized(&mut self, proof: Proof, payload: Digest) {
        if !H::validate(&payload) {
            self.panic("invalid digest length");
        }
        if !self.notarized_views.insert(payload.clone()) {
            self.panic("view already notarized");
        }
        let _ = self
            .tracker
            .send((
                self.participant.clone(),
                Progress::Notarized(proof, payload),
            ))
            .await;
    }

    async fn finalized(&mut self, proof: Proof, payload: Digest) {
        if !H::validate(&payload) {
            self.panic("invalid digest length");
        }
        if !self.finalized_views.insert(payload.clone()) {
            self.panic("view already finalized");
        }
        let _ = self
            .tracker
            .send((
                self.participant.clone(),
                Progress::Finalized(proof, payload),
            ))
            .await;
    }

    pub async fn run(mut self) {
        // Setup digest tracking
        let mut waiters: HashMap<Digest, Vec<(Context, oneshot::Sender<bool>)>> = HashMap::new();
        let mut seen: HashMap<Digest, Bytes> = HashMap::new();

        // Handle actions
        loop {
            select! {
                message = self.mailbox.next() => {
                    let message = message.expect("mailbox closed");
                    match message {
                        Message::Genesis { response } => {
                            let digest = self.genesis();
                            let _ = response.send(digest);
                        }
                        Message::Propose { context, response } => {
                            let digest = self.propose(context).await;
                            let _ = response.send(digest);
                        }
                        Message::Verify { context, payload, response } => {
                            if let Some(contents) = seen.get(&payload) {
                                debug!(payload = hex(&payload), "have broadcast");
                                let verified = self.verify(context, payload, contents.clone()).await;
                                let _ = response.send(verified);
                            } else {
                                debug!(payload = hex(&payload), "waiting for broadcast");
                                waiters
                                    .entry(payload.clone())
                                    .or_default()
                                    .push((context, response));
                                continue;
                            }
                        }
                        Message::Broadcast { payload } => {
                            self.broadcast(payload).await;
                        }
                        Message::Notarized { proof, payload } => {
                            self.notarized(proof, payload).await;
                        }
                        Message::Finalized { proof, payload } => {
                            self.finalized(proof, payload).await;
                        }
                    }
                },
                broadcast = self.broadcast.next() => {
                    // Record digest for future use
                    let (digest, contents) = broadcast.expect("broadcast closed");
                    debug!(payload = hex(&digest), "received broadcast");
                    seen.insert(digest.clone(), contents.clone());

                    // Check if we have a waiter
                    if let Some(waiters) = waiters.remove(&digest) {
                        for (context, sender) in waiters {
                            let verified = self.verify(context, digest.clone(), contents.clone()).await;
                            let _ = sender.send(verified);
                        }
                    }
                }
            }
        }
    }
}

pub struct SupervisorConfig<C: Scheme, H: Hasher> {
    pub prover: Prover<C, H>,
    pub participants: BTreeMap<View, Vec<PublicKey>>,
}

type Participation = HashMap<View, HashMap<Digest, HashSet<PublicKey>>>;
type Faults = HashMap<PublicKey, HashMap<View, HashSet<Activity>>>;

#[derive(Clone)]
pub struct Supervisor<C: Scheme, H: Hasher> {
    participants: BTreeMap<View, (HashSet<PublicKey>, Vec<PublicKey>)>,

    prover: Prover<C, H>,

    pub votes: Arc<Mutex<Participation>>,
    pub finalizes: Arc<Mutex<Participation>>,
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
                let (view, _, payload, public_key) =
                    self.prover.deserialize_notarize(proof, true).unwrap();
                self.votes
                    .lock()
                    .unwrap()
                    .entry(view)
                    .or_default()
                    .entry(payload)
                    .or_default()
                    .insert(public_key);
            }
            FINALIZE => {
                let (view, _, payload, public_key) =
                    self.prover.deserialize_finalize(proof, true).unwrap();
                self.finalizes
                    .lock()
                    .unwrap()
                    .entry(view)
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

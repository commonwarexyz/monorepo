use super::relay::Relay;
use crate::{simplex::Context, Automaton as Au, Committer as Co, DigestBytes, Proof, Relay as Re};
use bytes::{Buf, BufMut, Bytes};
use commonware_cryptography::{Hasher, PublicKey};
use commonware_macros::select;
use commonware_runtime::Clock;
use commonware_utils::hex;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use rand::{Rng, RngCore};
use rand_distr::{Distribution, Normal};
use std::{
    collections::{HashMap, HashSet},
    mem::size_of,
    sync::Arc,
    time::Duration,
};

pub enum Message {
    Genesis {
        response: oneshot::Sender<DigestBytes>,
    },
    Propose {
        context: Context,
        response: oneshot::Sender<DigestBytes>,
    },
    Verify {
        context: Context,
        payload: DigestBytes,
        response: oneshot::Sender<bool>,
    },
    Broadcast {
        payload: DigestBytes,
    },
    Notarized {
        proof: Proof,
        payload: DigestBytes,
    },
    Finalized {
        proof: Proof,
        payload: DigestBytes,
    },
}

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub(super) fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }
}

impl Au for Mailbox {
    type Context = Context;

    async fn genesis(&mut self) -> DigestBytes {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Genesis { response })
            .await
            .expect("Failed to send genesis");
        receiver.await.expect("Failed to receive genesis")
    }

    async fn propose(&mut self, context: Context) -> oneshot::Receiver<DigestBytes> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Propose { context, response })
            .await
            .expect("Failed to send propose");
        receiver
    }

    async fn verify(&mut self, context: Context, payload: DigestBytes) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Verify {
                context,
                payload,
                response,
            })
            .await
            .expect("Failed to send verify");
        receiver
    }
}

impl Re for Mailbox {
    async fn broadcast(&mut self, payload: DigestBytes) {
        self.sender
            .send(Message::Broadcast { payload })
            .await
            .expect("Failed to send broadcast");
    }
}

impl Co for Mailbox {
    async fn prepared(&mut self, proof: Proof, payload: DigestBytes) {
        self.sender
            .send(Message::Notarized { proof, payload })
            .await
            .expect("Failed to send notarized");
    }

    async fn finalized(&mut self, proof: Proof, payload: DigestBytes) {
        self.sender
            .send(Message::Finalized { proof, payload })
            .await
            .expect("Failed to send finalized");
    }
}

const GENESIS_BYTES: &[u8] = b"genesis";

type Latency = (f64, f64);

pub enum Progress {
    Notarized(Proof, DigestBytes),
    Finalized(Proof, DigestBytes),
}

pub struct Config<H: Hasher> {
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
    broadcast: mpsc::UnboundedReceiver<(DigestBytes, Bytes)>,
    tracker: mpsc::UnboundedSender<(PublicKey, Progress)>,

    mailbox: mpsc::Receiver<Message>,

    propose_latency: Normal<f64>,
    verify_latency: Normal<f64>,

    pending: HashMap<DigestBytes, Bytes>,

    verified: HashSet<DigestBytes>,
    notarized_views: HashSet<DigestBytes>,
    finalized_views: HashSet<DigestBytes>,
}

impl<E: Clock + RngCore, H: Hasher> Application<E, H> {
    pub fn new(runtime: E, cfg: Config<H>) -> (Self, Mailbox) {
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
                notarized_views: HashSet::new(),
                finalized_views: HashSet::new(),
            },
            Mailbox::new(sender),
        )
    }

    fn panic(&self, msg: &str) -> ! {
        panic!("[{}] {}", hex(&self.participant), msg);
    }

    fn genesis(&mut self) -> DigestBytes {
        let payload = Bytes::from(GENESIS_BYTES);
        self.hasher.update(&payload);
        let digest = DigestBytes::copy_from_slice(self.hasher.finalize().as_ref());
        self.verified.insert(digest.clone());
        self.finalized_views.insert(digest.clone());
        digest
    }

    /// When proposing a block, we do not care if the parent is verified (or even in our possession).
    /// Backfilling verification dependencies is considered out-of-scope for consensus.
    async fn propose(&mut self, context: Context) -> DigestBytes {
        // Simulate the propose latency
        let duration = self.propose_latency.sample(&mut self.runtime);
        self.runtime
            .sleep(Duration::from_millis(duration as u64))
            .await;

        // Verify parent exists and we are at the correct height
        if !H::validate(&H::from(&context.parent.1)) {
            self.panic("invalid parent digest length");
        }

        // Generate the payload
        let payload_len = size_of::<u64>() + context.parent.1.len() + size_of::<u64>();
        let mut payload = Vec::with_capacity(payload_len);
        payload.put_u64(context.view);
        payload.extend_from_slice(&context.parent.1);
        payload.put_u64(self.runtime.gen::<u64>()); // Ensures we always have a unique payload
        self.hasher.update(&payload);
        let digest = DigestBytes::copy_from_slice(self.hasher.finalize().as_ref());

        // Mark verified
        self.verified.insert(digest.clone());

        // Store pending payload
        self.pending.insert(digest.clone(), payload.into());
        digest
    }

    async fn verify(
        &mut self,
        context: Context,
        payload: DigestBytes,
        mut contents: Bytes,
    ) -> bool {
        // Simulate the verify latency
        let duration = self.verify_latency.sample(&mut self.runtime);
        self.runtime
            .sleep(Duration::from_millis(duration as u64))
            .await;

        // Verify parent exists and we are at the correct height
        if !H::validate(&H::from(&context.parent.1)) {
            self.panic("invalid parent digest length");
        }
        if !H::validate(&H::from(&payload)) {
            self.panic("invalid digest length");
        }

        // Verify contents
        if contents.len() != 48 {
            self.panic("invalid payload length");
        }
        let parsed_view = contents.get_u64();
        if parsed_view != context.view {
            self.panic(&format!(
                "invalid view (in payload): {} != {}",
                parsed_view, context.view
            ));
        }
        let parsed_parent: DigestBytes = contents.copy_to_bytes(H::DIGEST_LENGTH);
        if parsed_parent != context.parent.1 {
            self.panic(&format!(
                "invalid parent (in payload): {} != {}",
                hex(&parsed_parent),
                hex(&context.parent.1)
            ));
        }
        // We don't care about the random number
        self.verified.insert(payload);
        true
    }

    async fn broadcast(&mut self, payload: DigestBytes) {
        let contents = self.pending.remove(&payload).expect("missing payload");
        self.relay
            .broadcast(&self.participant, (payload, contents))
            .await;
    }

    async fn notarized(&mut self, proof: Proof, payload: DigestBytes) {
        if !H::validate(&H::from(&payload)) {
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

    async fn finalized(&mut self, proof: Proof, payload: DigestBytes) {
        if !H::validate(&H::from(&payload)) {
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
        let mut waiters: HashMap<DigestBytes, Vec<(Context, oneshot::Sender<bool>)>> =
            HashMap::new();
        let mut seen: HashMap<DigestBytes, Bytes> = HashMap::new();

        // Handle actions
        loop {
            select! {
                message = self.mailbox.next() => {
                    let message =match message {
                        Some(message) => message,
                        None => break,
                    };
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
                                let verified = self.verify(context, payload, contents.clone()).await;
                                let _ = response.send(verified);
                            } else {
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
                    seen.insert(digest.clone(), contents.clone());

                    // Check if we have a waiter
                    if let Some(waiters) = waiters.remove(&digest) {
                        for (context, sender) in waiters {
                            let verified = self.verify(context, digest.clone(), contents.clone()).await;
                            sender.send(verified).expect("Failed to send verification");
                        }
                    }
                }
            }
        }
    }
}

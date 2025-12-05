//! Mock application used by `simplex` tests to produce and verify payloads,
//! simulating proposal/verification latency and broadcasting via a mock relay.

use super::relay::Relay;
use crate::{
    simplex::types::Context,
    types::{Epoch, Round},
    Automaton as Au, Relay as Re,
};
use bytes::Bytes;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_macros::select_loop;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Spawner};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use rand::{Rng, RngCore};
use rand_distr::{Distribution, Normal};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tracing::debug;

pub enum Message<D: Digest, P: PublicKey> {
    Genesis {
        epoch: Epoch,
        response: oneshot::Sender<D>,
    },
    Propose {
        context: Context<D, P>,
        response: oneshot::Sender<D>,
    },
    Verify {
        context: Context<D, P>,
        payload: D,
        response: oneshot::Sender<bool>,
    },
    Broadcast {
        payload: D,
    },
}

#[derive(Clone)]
pub struct Mailbox<D: Digest, P: PublicKey> {
    sender: mpsc::Sender<Message<D, P>>,
}

impl<D: Digest, P: PublicKey> Mailbox<D, P> {
    pub(super) const fn new(sender: mpsc::Sender<Message<D, P>>) -> Self {
        Self { sender }
    }
}

impl<D: Digest, P: PublicKey> Au for Mailbox<D, P> {
    type Digest = D;
    type Context = Context<D, P>;

    async fn genesis(&mut self, epoch: Epoch) -> Self::Digest {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Genesis { epoch, response })
            .await
            .expect("Failed to send genesis");
        receiver.await.expect("Failed to receive genesis")
    }

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Propose { context, response })
            .await
            .expect("Failed to send propose");
        receiver
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
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

impl<D: Digest, P: PublicKey> Re for Mailbox<D, P> {
    type Digest = D;

    async fn broadcast(&mut self, payload: Self::Digest) {
        self.sender
            .send(Message::Broadcast { payload })
            .await
            .expect("Failed to send broadcast");
    }
}

const GENESIS_BYTES: &[u8] = b"genesis";

type Latency = (f64, f64);

pub struct Config<H: Hasher, P: PublicKey> {
    pub hasher: H,

    pub relay: Arc<Relay<H::Digest, P>>,

    /// The public key of the participant.
    ///
    /// It is common to use multiple instances of an application in a single simulation, this
    /// helps to identify the source of both progress and errors.
    pub me: P,

    pub propose_latency: Latency,
    pub verify_latency: Latency,
}

pub struct Application<E: Clock + RngCore + Spawner, H: Hasher, P: PublicKey> {
    context: ContextCell<E>,
    hasher: H,
    me: P,

    relay: Arc<Relay<H::Digest, P>>,
    broadcast: mpsc::UnboundedReceiver<(H::Digest, Bytes)>,

    mailbox: mpsc::Receiver<Message<H::Digest, P>>,

    propose_latency: Normal<f64>,
    verify_latency: Normal<f64>,

    pending: HashMap<H::Digest, Bytes>,

    verified: HashSet<H::Digest>,
}

impl<E: Clock + RngCore + Spawner, H: Hasher, P: PublicKey> Application<E, H, P> {
    pub fn new(context: E, cfg: Config<H, P>) -> (Self, Mailbox<H::Digest, P>) {
        // Register self on relay
        let broadcast = cfg.relay.register(cfg.me.clone());

        // Generate samplers
        let propose_latency = Normal::new(cfg.propose_latency.0, cfg.propose_latency.1).unwrap();
        let verify_latency = Normal::new(cfg.verify_latency.0, cfg.verify_latency.1).unwrap();

        // Return constructed application
        let (sender, receiver) = mpsc::channel(1024);
        (
            Self {
                context: ContextCell::new(context),
                hasher: cfg.hasher,
                me: cfg.me,

                relay: cfg.relay,
                broadcast,

                mailbox: receiver,

                propose_latency,
                verify_latency,

                pending: HashMap::new(),

                verified: HashSet::new(),
            },
            Mailbox::new(sender),
        )
    }

    fn panic(&self, msg: &str) -> ! {
        panic!("[{:?}] {}", self.me, msg);
    }

    fn genesis(&mut self, epoch: Epoch) -> H::Digest {
        self.hasher
            .update(&(Bytes::from(GENESIS_BYTES), epoch).encode());
        let digest = self.hasher.finalize();
        self.verified.insert(digest);
        digest
    }

    /// When proposing a block, we do not care if the parent is verified (or even in our possession).
    /// Backfilling verification dependencies is considered out-of-scope for consensus.
    async fn propose(&mut self, context: Context<H::Digest, P>) -> H::Digest {
        // Simulate the propose latency
        let duration = self.propose_latency.sample(&mut self.context);
        self.context
            .sleep(Duration::from_millis(duration as u64))
            .await;

        // Generate the payload
        let rand = self.context.gen::<u64>();
        let payload = (context.round, context.parent.1, rand).encode();
        self.hasher.update(&payload);
        let digest = self.hasher.finalize();

        // Mark verified
        self.verified.insert(digest);

        // Store pending payload
        self.pending.insert(digest, payload.into());
        digest
    }

    async fn verify(
        &mut self,
        context: Context<H::Digest, P>,
        payload: H::Digest,
        mut contents: Bytes,
    ) -> bool {
        // Simulate the verify latency
        let duration = self.verify_latency.sample(&mut self.context);
        self.context
            .sleep(Duration::from_millis(duration as u64))
            .await;

        // Verify contents
        let (parsed_round, parent, _) =
            <(Round, H::Digest, u64)>::decode(&mut contents).expect("invalid payload");
        if parsed_round != context.round {
            self.panic(&format!(
                "invalid round (in payload): {} != {}",
                parsed_round, context.round
            ));
        }
        if parent != context.parent.1 {
            self.panic(&format!(
                "invalid parent (in payload): {:?} != {:?}",
                parent, context.parent.1
            ));
        }
        // We don't care about the random number
        self.verified.insert(payload);
        true
    }

    async fn broadcast(&mut self, payload: H::Digest) {
        let contents = self.pending.remove(&payload).expect("missing payload");
        self.relay.broadcast(&self.me, (payload, contents)).await;
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    async fn run(mut self) {
        // Setup digest tracking
        #[allow(clippy::type_complexity)]
        let mut waiters: HashMap<
            H::Digest,
            Vec<(Context<H::Digest, P>, oneshot::Sender<bool>)>,
        > = HashMap::new();
        let mut seen: HashMap<H::Digest, Bytes> = HashMap::new();

        // Handle actions
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping application");
            },
            message = self.mailbox.next() => {
                let message =match message {
                    Some(message) => message,
                    None => break,
                };
                match message {
                    Message::Genesis { epoch, response } => {
                        let digest = self.genesis(epoch);
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
                                .entry(payload)
                                .or_default()
                                .push((context, response));
                            continue;
                        }
                    }
                    Message::Broadcast { payload } => {
                        self.broadcast(payload).await;
                    }
                }
            },
            broadcast = self.broadcast.next() => {
                // Record digest for future use
                let (digest, contents) = broadcast.expect("broadcast closed");
                seen.insert(digest, contents.clone());

                // Check if we have a waiter
                if let Some(waiters) = waiters.remove(&digest) {
                    for (context, sender) in waiters {
                        let verified = self.verify(context, digest, contents.clone()).await;
                        sender.send(verified).expect("Failed to send verification");
                    }
                }
            }
        }
    }
}

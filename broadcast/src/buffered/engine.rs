use super::{metrics, Config, Mailbox, Message};
use crate::buffered::metrics::SequencerLabel;
use commonware_codec::Codec;
use commonware_cryptography::{Digestible, PublicKey};
use commonware_macros::select_loop;
use commonware_p2p::{
    utils::codec::{wrap, WrappedSender},
    Receiver, Recipients, Sender,
};
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::status::{CounterExt, GaugeExt, Status},
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_utils::channel::{fallible::OneshotExt, mpsc, oneshot};
use std::collections::{BTreeMap, VecDeque};
use tracing::{debug, error, trace, warn};

/// A responder waiting for a message.
struct Waiter<M> {
    /// The responder to send the message to.
    responder: oneshot::Sender<M>,
}

/// Instance of the main engine for the module.
///
/// It is responsible for:
/// - Broadcasting messages to the network
/// - Receiving messages from the network
/// - Storing messages in the cache
/// - Responding to requests from the application
pub struct Engine<E, P, M>
where
    E: BufferPooler + Clock + Spawner + Metrics,
    P: PublicKey,
    M: Digestible + Codec,
{
    ////////////////////////////////////////
    // Interfaces
    ////////////////////////////////////////
    context: ContextCell<E>,

    ////////////////////////////////////////
    // Configuration
    ////////////////////////////////////////
    /// My public key
    public_key: P,

    /// Whether messages are sent as priority
    priority: bool,

    /// Number of messages to cache per peer
    deque_size: usize,

    /// Configuration for decoding messages
    codec_config: M::Cfg,

    ////////////////////////////////////////
    // Messaging
    ////////////////////////////////////////
    /// The mailbox for receiving messages.
    mailbox_receiver: mpsc::Receiver<Message<P, M>>,

    /// Pending requests from the application.
    waiters: BTreeMap<M::Digest, Vec<Waiter<M>>>,

    ////////////////////////////////////////
    // Cache
    ////////////////////////////////////////
    /// All cached messages by digest.
    items: BTreeMap<M::Digest, M>,

    /// A LRU cache of the latest received digests from each peer.
    ///
    /// This is used to limit the number of digests stored per peer.
    /// At most `deque_size` digests are stored per peer. This value is expected to be small, so
    /// membership checks are done in linear time.
    deques: BTreeMap<P, VecDeque<M::Digest>>,

    /// The number of times each digest (globally unique) exists in one of the deques.
    ///
    /// Multiple peers can send the same message and we only want to store
    /// the message once.
    counts: BTreeMap<M::Digest, usize>,

    ////////////////////////////////////////
    // Metrics
    ////////////////////////////////////////
    /// Metrics
    metrics: metrics::Metrics,
}

impl<E, P, M> Engine<E, P, M>
where
    E: BufferPooler + Clock + Spawner + Metrics,
    P: PublicKey,
    M: Digestible + Codec,
{
    /// Creates a new engine with the given context and configuration.
    /// Returns the engine and a mailbox for sending messages to the engine.
    pub fn new(context: E, cfg: Config<P, M::Cfg>) -> (Self, Mailbox<P, M>) {
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::<P, M>::new(mailbox_sender);

        // TODO(#1833): Metrics should use the post-start context
        let metrics = metrics::Metrics::init(context.clone());

        let result = Self {
            context: ContextCell::new(context),
            public_key: cfg.public_key,
            priority: cfg.priority,
            deque_size: cfg.deque_size,
            codec_config: cfg.codec_config,
            mailbox_receiver,
            waiters: BTreeMap::new(),
            deques: BTreeMap::new(),
            items: BTreeMap::new(),
            counts: BTreeMap::new(),
            metrics,
        };

        (result, mailbox)
    }

    /// Starts the engine with the given network.
    pub fn start(
        mut self,
        network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(network).await)
    }

    /// Inner run loop called by `start`.
    async fn run(mut self, network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>)) {
        let (mut sender, mut receiver) = wrap(
            self.codec_config.clone(),
            self.context.network_buffer_pool().clone(),
            network.0,
            network.1,
        );

        select_loop! {
            self.context,
            on_start => {
                // Cleanup waiters
                self.cleanup_waiters();
                let _ = self.metrics.waiters.try_set(self.waiters.len());
            },
            on_stopped => {
                debug!("shutdown");
            },
            // Handle mailbox messages
            Some(msg) = self.mailbox_receiver.recv() else {
                error!("mailbox receiver failed");
                break;
            } => match msg {
                Message::Broadcast {
                    recipients,
                    message,
                    responder,
                } => {
                    trace!("mailbox: broadcast");
                    self.handle_broadcast(&mut sender, recipients, message, responder)
                        .await;
                }
                Message::Subscribe { digest, responder } => {
                    trace!("mailbox: subscribe");
                    self.handle_subscribe(digest, responder);
                }
                Message::Get { digest, responder } => {
                    trace!("mailbox: get");
                    self.handle_get(digest, responder);
                }
            },
            // Handle incoming messages
            msg = receiver.recv() => {
                // Error handling
                let (peer, msg) = match msg {
                    Ok(r) => r,
                    Err(err) => {
                        error!(?err, "receiver failed");
                        break;
                    }
                };

                // Decode the message
                let msg = match msg {
                    Ok(msg) => msg,
                    Err(err) => {
                        warn!(?err, ?peer, "failed to decode message");
                        self.metrics.receive.inc(Status::Invalid);
                        continue;
                    }
                };

                trace!(?peer, "network");
                self.metrics
                    .peer
                    .get_or_create(&SequencerLabel::from(&peer))
                    .inc();
                self.handle_network(peer, msg);
            },
        }
    }

    ////////////////////////////////////////
    // Handling
    ////////////////////////////////////////

    /// Handles a `broadcast` request from the application.
    async fn handle_broadcast<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, M>,
        recipients: Recipients<P>,
        msg: M,
        responder: oneshot::Sender<Vec<P>>,
    ) {
        // Store the message, continue even if it was already stored
        let _ = self.insert_message(self.public_key.clone(), msg.clone());

        // Broadcast the message to the network
        let sent_to = sender
            .send(recipients, msg, self.priority)
            .await
            .unwrap_or_else(|err| {
                error!(?err, "failed to send message");
                vec![]
            });
        responder.send_lossy(sent_to);
    }

    /// Handles a `subscribe` request from the application.
    ///
    /// If the message is already in the cache, the responder is immediately sent the message.
    /// Otherwise, the responder is stored in the waiters list.
    fn handle_subscribe(&mut self, digest: M::Digest, responder: oneshot::Sender<M>) {
        // Check if the message is already in the cache
        if let Some(item) = self.items.get(&digest).cloned() {
            self.respond_subscribe(responder, item);
            return;
        }

        // Store the responder
        self.waiters
            .entry(digest)
            .or_default()
            .push(Waiter { responder });
    }

    /// Handles a `get` request from the application.
    fn handle_get(&mut self, digest: M::Digest, responder: oneshot::Sender<Option<M>>) {
        let item = self.items.get(&digest).cloned();
        self.respond_get(responder, item);
    }

    /// Handles a message that was received from a peer.
    fn handle_network(&mut self, peer: P, msg: M) {
        if !self.insert_message(peer.clone(), msg) {
            debug!(?peer, "message already stored");
            self.metrics.receive.inc(Status::Dropped);
            return;
        }

        self.metrics.receive.inc(Status::Success);
    }

    ////////////////////////////////////////
    // Cache Management
    ////////////////////////////////////////

    /// Inserts a message into the cache.
    ///
    /// Returns `true` if the message was inserted, `false` if it was already present.
    /// Updates the deque, item count, and message cache, potentially evicting an old message.
    fn insert_message(&mut self, peer: P, msg: M) -> bool {
        let digest = msg.digest();

        // Send the message to the waiters, if any
        if let Some(waiters) = self.waiters.remove(&digest) {
            for waiter in waiters {
                self.respond_subscribe(waiter.responder, msg.clone());
            }
        }

        // Get the relevant deque for the peer
        let deque = self
            .deques
            .entry(peer)
            .or_insert_with(|| VecDeque::with_capacity(self.deque_size + 1));

        // If the message is already in the deque, move it to the front and return early
        if let Some(i) = deque.iter().position(|d| *d == digest) {
            if i != 0 {
                let v = deque.remove(i).unwrap(); // Must exist
                deque.push_front(v);
            }
            return false;
        };

        // - Insert the digest into the peer cache
        // - Increment the item count
        // - Insert the message if-and-only-if the new item count is 1
        deque.push_front(digest);
        let count = self
            .counts
            .entry(digest)
            .and_modify(|c| *c = c.checked_add(1).unwrap())
            .or_insert(1);
        if *count == 1 {
            let existing = self.items.insert(digest, msg);
            assert!(existing.is_none());
        }

        // If the cache is full...
        if deque.len() > self.deque_size {
            // Remove the oldest item from the peer cache
            // Decrement the item count
            // Remove the message if-and-only-if the new item count is 0
            let stale = deque.pop_back().unwrap();
            let count = self
                .counts
                .entry(stale)
                .and_modify(|c| *c = c.checked_sub(1).unwrap())
                .or_insert_with(|| unreachable!());
            if *count == 0 {
                let existing = self.counts.remove(&stale);
                assert!(existing == Some(0));
                self.items.remove(&stale);
            }
        }

        true
    }

    ////////////////////////////////////////
    // Utilities
    ////////////////////////////////////////

    /// Remove all waiters that have dropped receivers.
    fn cleanup_waiters(&mut self) {
        self.waiters.retain(|_, waiters| {
            let initial_len = waiters.len();
            waiters.retain(|waiter| !waiter.responder.is_closed());
            let dropped_count = initial_len - waiters.len();

            // Increment metrics for each dropped waiter
            for _ in 0..dropped_count {
                self.metrics.get.inc(Status::Dropped);
            }

            !waiters.is_empty()
        });
    }

    /// Respond to a waiter with a message.
    /// Increments the appropriate metric based on the result.
    fn respond_subscribe(&mut self, responder: oneshot::Sender<M>, msg: M) {
        self.metrics.subscribe.inc(if responder.send_lossy(msg) {
            Status::Success
        } else {
            Status::Dropped
        });
    }

    /// Respond to a get request.
    /// Increments the appropriate metric based on the result.
    fn respond_get(&mut self, responder: oneshot::Sender<Option<M>>, msg: Option<M>) {
        let found = msg.is_some();
        self.metrics.get.inc(if responder.send_lossy(msg) {
            if found {
                Status::Success
            } else {
                Status::Failure
            }
        } else {
            Status::Dropped
        });
    }
}

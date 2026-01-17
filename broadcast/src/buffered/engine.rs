use super::{metrics, Config, Mailbox, Message};
use crate::buffered::metrics::SequencerLabel;
use commonware_codec::Codec;
use commonware_cryptography::{Committable, Digestible, PublicKey};
use commonware_macros::select;
use commonware_p2p::{
    utils::codec::{wrap, WrappedSender},
    Receiver, Recipients, Sender,
};
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::status::{CounterExt, GaugeExt, Status},
    Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_utils::channels::fallible::OneshotExt;
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use std::collections::{BTreeMap, VecDeque};
use tracing::{debug, error, trace, warn};

/// A responder waiting for a message.
struct Waiter<M> {
    /// The responder to send the message to.
    responder: oneshot::Sender<M>,
}

/// A pair of commitment and digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Pair<Dc, Dd> {
    /// The commitment of the message.
    commitment: Dc,

    /// The digest of the message.
    digest: Dd,
}

/// Instance of the main engine for the module.
///
/// It is responsible for:
/// - Broadcasting messages to the network
/// - Receiving messages from the network
/// - Storing messages in the cache
/// - Responding to requests from the application
pub struct Engine<E: Clock + Spawner + Metrics, P: PublicKey, M: Committable + Digestible + Codec> {
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
    waiters: BTreeMap<M::Commitment, Vec<Waiter<M>>>,

    ////////////////////////////////////////
    // Cache
    ////////////////////////////////////////
    /// All cached messages by commitment and digest.
    ///
    /// We store messages outside of the deques to minimize memory usage
    /// when receiving duplicate messages.
    items: BTreeMap<M::Commitment, BTreeMap<M::Digest, M>>,

    /// A LRU cache of the latest received identities and digests from each peer.
    ///
    /// This is used to limit the number of digests stored per peer.
    /// At most `deque_size` digests are stored per peer. This value is expected to be small, so
    /// membership checks are done in linear time.
    #[allow(clippy::type_complexity)]
    deques: BTreeMap<P, VecDeque<Pair<M::Commitment, M::Digest>>>,

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

impl<E: Clock + Spawner + Metrics, P: PublicKey, M: Committable + Digestible + Codec>
    Engine<E, P, M>
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
        let (mut sender, mut receiver) = wrap(self.codec_config.clone(), network.0, network.1);
        let mut shutdown = self.context.stopped();

        loop {
            // Cleanup waiters
            self.cleanup_waiters();
            let _ = self.metrics.waiters.try_set(self.waiters.len());

            select! {
                // Handle shutdown signal
                _ = &mut shutdown => {
                    debug!("shutdown");
                    break;
                },

                // Handle mailbox messages
                mail = self.mailbox_receiver.next() => {
                    let Some(msg) = mail else {
                        error!("mailbox receiver failed");
                        break;
                    };
                    match msg {
                        Message::Broadcast{ recipients, message, responder } => {
                            trace!("mailbox: broadcast");
                            self.handle_broadcast(&mut sender, recipients, message, responder).await;
                        }
                        Message::Subscribe{ commitment, responder } => {
                            trace!("mailbox: subscribe");
                            self.handle_subscribe(commitment, responder).await;
                        }
                        Message::Get{ commitment, responder } => {
                            trace!("mailbox: get");
                            self.handle_get(commitment, responder).await;
                        }
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
                    self.metrics.peer.get_or_create(&SequencerLabel::from(&peer)).inc();
                    self.handle_network(peer, msg).await;
                },
            }
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

    /// Finds a message by commitment.
    fn find_message(&self, commitment: M::Commitment) -> Option<M> {
        self.items
            .get(&commitment)
            .and_then(|msgs| msgs.values().next())
            .cloned()
    }

    /// Handles a `subscribe` request from the application.
    ///
    /// If the message is already in the cache, the responder is immediately sent the message.
    /// Otherwise, the responder is stored in the waiters list.
    async fn handle_subscribe(&mut self, commitment: M::Commitment, responder: oneshot::Sender<M>) {
        // Check if the message is already in the cache
        if let Some(item) = self.find_message(commitment) {
            self.respond_subscribe(responder, item);
            return;
        }

        // Store the responder
        self.waiters
            .entry(commitment)
            .or_default()
            .push(Waiter { responder });
    }

    /// Handles a `get` request from the application.
    async fn handle_get(
        &mut self,
        commitment: M::Commitment,
        responder: oneshot::Sender<Option<M>>,
    ) {
        let item = self.find_message(commitment);
        self.respond_get(responder, item);
    }

    /// Handles a message that was received from a peer.
    async fn handle_network(&mut self, peer: P, msg: M) {
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
        // Get the commitment and digest of the message
        let pair = Pair {
            commitment: msg.commitment(),
            digest: msg.digest(),
        };

        // Send the message to all waiters for this commitment
        if let Some(waiters) = self.waiters.remove(&pair.commitment) {
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
        if let Some(i) = deque.iter().position(|d| *d == pair) {
            if i != 0 {
                let v = deque.remove(i).unwrap(); // Must exist
                deque.push_front(v);
            }
            return false;
        };

        // - Insert the message into the peer cache
        // - Increment the item count
        // - Insert the message if-and-only-if the new item count is 1
        deque.push_front(pair);
        let count = self
            .counts
            .entry(pair.digest)
            .and_modify(|c| *c = c.checked_add(1).unwrap())
            .or_insert(1);
        if *count == 1 {
            let existing = self
                .items
                .entry(pair.commitment)
                .or_default()
                .insert(pair.digest, msg);
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
                .entry(stale.digest)
                .and_modify(|c| *c = c.checked_sub(1).unwrap())
                .or_insert_with(|| unreachable!());
            if *count == 0 {
                let existing = self.counts.remove(&stale.digest);
                assert!(existing == Some(0));
                let identities = self.items.get_mut(&stale.commitment).unwrap();
                identities.remove(&stale.digest); // Must have existed
                if identities.is_empty() {
                    self.items.remove(&stale.commitment);
                }
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
            waiters.retain(|waiter| !waiter.responder.is_canceled());
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

    /// Respond to a waiter with an optional message.
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

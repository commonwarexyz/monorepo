use super::{metrics, Config, Mailbox, Message};
use crate::buffered::metrics::SequencerLabel;
use bytes::Bytes;
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Digestible};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{
    telemetry::status::{CounterExt, Status},
    Clock, Handle, Metrics, Spawner,
};
use commonware_utils::Array;
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use std::{
    collections::{HashMap, VecDeque},
    marker::PhantomData,
};
use tracing::{debug, error, trace, warn};

/// Instance of the main engine for the module.
///
/// It is responsible for:
/// - Broadcasting messages to the network
/// - Receiving messages from the network
/// - Storing messages in the cache
/// - Responding to requests from the application
pub struct Engine<
    E: Clock + Spawner + Metrics,
    P: Array,
    D: Digest,
    M: Digestible<D> + Codec,
    NetS: Sender<PublicKey = P>,
    NetR: Receiver<PublicKey = P>,
> {
    ////////////////////////////////////////
    // Interfaces
    ////////////////////////////////////////
    context: E,
    _phantom: PhantomData<(NetS, NetR)>,

    ////////////////////////////////////////
    // Configuration
    ////////////////////////////////////////
    /// My public key
    public_key: P,

    /// Whether messages are sent as priority
    priority: bool,

    /// Number of messages to cache per sender
    deque_size: usize,

    ////////////////////////////////////////
    // Messaging
    ////////////////////////////////////////
    /// The mailbox for receiving messages.
    mailbox_receiver: mpsc::Receiver<Message<D, M>>,

    /// Pending requests from the application.
    waiters: HashMap<D, Vec<oneshot::Sender<M>>>,

    ////////////////////////////////////////
    // Cache
    ////////////////////////////////////////
    /// All cached messages by digest.
    items: HashMap<D, M>,

    /// A LRU cache of the latest received digests from each peer.
    ///
    /// This is used to limit the number of digests stored per peer.
    /// At most `deque_size` digests are stored per peer. This value is expected to be small, so
    /// membership checks are done in linear time.
    deques: HashMap<P, VecDeque<D>>,

    /// The number of times each digest exists in one of the deques.
    ///
    /// This is because multiple peers can send the same message.
    counts: HashMap<D, usize>,

    ////////////////////////////////////////
    // Metrics
    ////////////////////////////////////////
    /// Metrics
    metrics: metrics::Metrics,
}

impl<
        E: Clock + Spawner + Metrics,
        P: Array,
        D: Digest,
        M: Digestible<D> + Codec,
        NetS: Sender<PublicKey = P>,
        NetR: Receiver<PublicKey = P>,
    > Engine<E, P, D, M, NetS, NetR>
{
    /// Creates a new engine with the given context and configuration.
    /// Returns the engine and a mailbox for sending messages to the engine.
    pub fn new(context: E, cfg: Config<P>) -> (Self, Mailbox<D, M>) {
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::<D, M>::new(mailbox_sender);
        let metrics = metrics::Metrics::init(context.clone());

        let result = Self {
            context,
            _phantom: PhantomData,
            public_key: cfg.public_key,
            priority: cfg.priority,
            deque_size: cfg.deque_size,
            mailbox_receiver,
            waiters: HashMap::new(),
            deques: HashMap::new(),
            items: HashMap::new(),
            counts: HashMap::new(),
            metrics,
        };

        (result, mailbox)
    }

    /// Starts the engine with the given network.
    pub fn start(mut self, network: (NetS, NetR)) -> Handle<()> {
        self.context.spawn_ref()(self.run(network))
    }

    /// Inner run loop called by `start`.
    async fn run(mut self, network: (NetS, NetR)) {
        let (mut net_sender, mut net_receiver) = network;
        let mut shutdown = self.context.stopped();

        loop {
            // Cleanup waiters
            self.cleanup_waiters();

            select! {
                // Handle shutdown signal
                _ = &mut shutdown => {
                    debug!("shutdown");
                },

                // Handle mailbox messages
                mail = self.mailbox_receiver.next() => {
                    let Some(msg) = mail else {
                        error!("mailbox receiver failed");
                        break;
                    };
                    match msg {
                        Message::Broadcast{ message } => {
                            trace!("mailbox: broadcast");
                            self.handle_broadcast(&mut net_sender, message).await;
                        }
                        Message::Get{ digest, responder } => {
                            trace!("mailbox: get");
                            self.handle_get(digest, responder).await;
                        }
                    }
                },

                // Handle incoming messages
                msg = net_receiver.recv() => {
                    trace!("receiver");
                    // Error handling
                    let (peer, msg) = match msg {
                        Ok(r) => r,
                        Err(err) => {
                            error!(?err, "receiver failed");
                            break;
                        }
                    };

                    // Decode the message
                    let message = match M::decode(msg) {
                        Ok(message) => message,
                        Err(err) => {
                            warn!(?err, ?peer, "failed to decode message");
                            self.metrics.receive.inc(Status::Invalid);
                            continue;
                        }
                    };

                    self.metrics.peer.get_or_create(&SequencerLabel::from(&peer)).inc();
                    self.handle_network(peer, message).await;
                },
            }
        }
    }

    ////////////////////////////////////////
    // Handling
    ////////////////////////////////////////

    /// Handles a `broadcast` request from the application.
    async fn handle_broadcast(&mut self, net_sender: &mut NetS, msg: M) {
        // Store the message, continue even if it was already stored
        let _ = self.insert_message(self.public_key.clone(), msg.clone());

        // Broadcast the message to the network
        let recipients = Recipients::All;
        let msg = Bytes::from(msg.encode());
        if let Err(err) = net_sender.send(recipients, msg, self.priority).await {
            warn!(?err, "failed to send message");
        }
    }

    /// Handles a `get` request from the application.
    ///
    /// If the message is already in the cache, the responder is immediately sent the message.
    /// Otherwise, the responder is stored in the waiters list.
    async fn handle_get(&mut self, digest: D, responder: oneshot::Sender<M>) {
        // Check if the message is already in the cache
        if let Some(msg) = self.items.get(&digest) {
            self.respond(responder, msg.clone());
            return;
        }

        // Store the responder
        self.waiters.entry(digest).or_default().push(responder);
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
        let digest = msg.digest();

        // Send the message to the waiters, if any, ignoring errors (as the receiver may have dropped)
        if let Some(responders) = self.waiters.remove(&digest) {
            for responder in responders {
                self.respond(responder, msg.clone());
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
                deque.remove(i).unwrap(); // Must exist
                deque.push_front(digest);
            }
            return false;
        };

        // - Insert the message into the peer cache
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
            // Remove the oldest digest from the peer cache
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
                self.items.remove(&stale).unwrap(); // Must have existed
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
            waiters.retain(|waiter| !waiter.is_canceled());
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
    fn respond(&mut self, responder: oneshot::Sender<M>, msg: M) {
        let result = responder.send(msg);
        self.metrics.get.inc(match result {
            Ok(_) => Status::Success,
            Err(_) => Status::Dropped,
        });
    }
}

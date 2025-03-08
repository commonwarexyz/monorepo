//! Engine for the broadcast module.
//!
//! It is responsible for:
//! - Broadcasting nodes (if a sequencer)
//! - Signing chunks (if a validator)
//! - Tracking the latest chunk in each sequencer’s chain
//! - Recovering threshold signatures from partial signatures for each chunk
//! - Notifying other actors of new chunks and threshold signatures

use super::{metrics, Config, Digestible, Mailbox, Message, Serializable};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Metrics, Spawner};
use commonware_utils::Array;
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use std::{
    collections::{HashMap, VecDeque},
    marker::PhantomData,
};
use tracing::{debug, error, warn};

/// Instance of the `linked` broadcast engine.
pub struct Engine<
    E: Clock + Spawner + Metrics,
    P: Array,
    D: Array,
    B: Digestible<D> + Serializable,
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
    cache_per_sender_size: usize,

    ////////////////////////////////////////
    // Messaging
    ////////////////////////////////////////

    // The mailbox for receiving messages (primarily from the application).
    mailbox_receiver: mpsc::Receiver<Message<D, B>>,

    /// Requests from the application to retrieve blobs by digest.
    waiters: HashMap<D, Vec<oneshot::Sender<B>>>,

    ////////////////////////////////////////
    // State
    ////////////////////////////////////////
    /// A LRUCache of the latest received messages from each sequencer.
    cache: HashMap<P, VecDeque<D>>,

    /// A cache of the blobs by digest.
    items: HashMap<D, B>,

    ////////////////////////////////////////
    // Metrics
    ////////////////////////////////////////

    // Metrics
    metrics: metrics::Metrics,
}

impl<
        E: Clock + Spawner + Metrics,
        P: Array,
        D: Array,
        B: Digestible<D> + Serializable,
        NetS: Sender<PublicKey = P>,
        NetR: Receiver<PublicKey = P>,
    > Engine<E, P, D, B, NetS, NetR>
{
    /// Creates a new engine with the given context and configuration.
    /// Returns the engine and a mailbox for sending messages to the engine.
    pub fn new(context: E, cfg: Config<P>) -> (Self, Mailbox<D, B>) {
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::<D, B>::new(mailbox_sender);
        let metrics = metrics::Metrics::init(context.clone());

        let result = Self {
            context,
            _phantom: PhantomData,
            public_key: cfg.public_key,
            priority: cfg.priority,
            cache_per_sender_size: cfg.cache_per_sender_size,
            mailbox_receiver,
            waiters: HashMap::new(),
            cache: HashMap::new(),
            items: HashMap::new(),
            metrics,
        };

        (result, mailbox)
    }

    pub fn start(mut self, network: (NetS, NetR)) -> Handle<()> {
        self.context.spawn_ref()(self.run(network))
    }

    /// Inner run loop called by `start`.
    async fn run(mut self, network: (NetS, NetR)) {
        let (mut net_sender, mut net_receiver) = network;
        let mut shutdown = self.context.stopped();

        loop {
            select! {
                // Handle shutdown signal
                _ = &mut shutdown => {
                    debug!("shutdown");
                },

                // Handle mailbox messages
                mail = self.mailbox_receiver.next() => {
                    debug!("mailbox");

                    // Error handling
                    let Some(msg) = mail else {
                        error!("mailbox receiver failed");
                        break;
                    };

                    match msg {
                        Message::Broadcast{ blob } => {
                            debug!("broadcast");
                            self.handle_broadcast(&mut net_sender, blob).await;
                        }
                        Message::Retrieve{ digest, responder } => {
                            debug!("retrieve");
                            self.handle_retrieve(digest, responder).await;
                        }
                    }
                },

                // Handle incoming messages
                msg = net_receiver.recv() => {
                    debug!("receiver");
                    // Error handling
                    let (peer, msg) = match msg {
                        Ok(r) => r,
                        Err(err) => {
                            warn!(?err, "receiver failed");
                            break;
                        }
                    };

                    // Metrics
                    self.metrics.broadcast
                    .get_or_create(&metrics::SequencerLabel::from(&peer))
                    .inc();

                    // Decode the message
                    let blob = match B::deserialize(&msg) {
                        Ok(blob) => blob,
                        Err(err) => {
                            warn!(?err, ?peer, "failed to decode message");
                            continue;
                        }
                    };

                    self.handle_network(peer, blob).await;
                },
            }
        }
    }

    ////////////////////////////////////////
    // Handling
    ////////////////////////////////////////

    /// Handles a broadcast request from the application.
    async fn handle_broadcast(&mut self, net_sender: &mut NetS, blob: B) {
        // Store the blob, continue even if it was already stored
        let _ = self.insert_blob(self.public_key.clone(), blob.clone());

        // Broadcast the blob to the network
        let bytes = blob.serialize();
        let recipients = Recipients::All;
        if let Err(err) = net_sender
            .send(recipients, bytes.into(), self.priority)
            .await
        {
            warn!(?err, "failed to send message");
        }
    }

    /// Handles a retrieve request from the application.
    ///
    /// If the blob is already in the cache, the responder is immediately sent the blob.
    /// Otherwise, the responder is stored in the waiters list.
    async fn handle_retrieve(&mut self, digest: D, responder: oneshot::Sender<B>) {
        // Check if the blob is already in the cache
        if let Some(blob) = self.items.get(&digest) {
            let _ = responder.send(blob.clone());
            return;
        }

        // Store the responder
        let waiters = self.waiters.entry(digest.clone()).or_default();
        waiters.push(responder);
    }

    /// Handles a blob that was received from a peer.
    async fn handle_network(&mut self, peer: P, blob: B) {
        if !self.insert_blob(peer.clone(), blob) {
            warn!(?peer, "blob already stored");
        }
    }

    ////////////////////////////////////////
    // Utilities
    ////////////////////////////////////////

    /// Inserts a blob into the cache.
    ///
    /// Returns `true` if the blob was inserted, `false` if it was already present.
    fn insert_blob(&mut self, peer: P, blob: B) -> bool {
        let digest = blob.digest();

        // Check if the blob is already in the cache
        if self.items.contains_key(&digest) {
            return false;
        }

        // Send the blob to the waiters, if any, ignoring errors (as the receiver may have dropped)
        if let Some(waiters) = self.waiters.remove(&digest) {
            for responder in waiters {
                let _ = responder.send(blob.clone());
            }
        }

        // Store the blob in the cache
        self.items.insert(digest.clone(), blob);
        let cache = self
            .cache
            .entry(peer)
            .or_insert_with(|| VecDeque::with_capacity(self.cache_per_sender_size + 1));
        cache.push_back(digest);

        // Evict the oldest blob if the cache is full
        if cache.len() > self.cache_per_sender_size {
            let deleted = cache.pop_front().expect("missing cache");
            self.items.remove(&deleted).expect("missing item");
        }

        true
    }
}

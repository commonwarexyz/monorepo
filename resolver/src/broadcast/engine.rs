use super::{config::Config, ingress::{Mailbox, Message}, wire, Coordinator, Producer};
use crate::Consumer;
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_macros::select;
use commonware_p2p::{utils::codec::{wrap, WrappedSender}, Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Metrics, Spawner};
use commonware_utils::Span;
use futures::{channel::{mpsc, oneshot}, StreamExt};
use governor::clock::Clock as GClock;
use rand::Rng;
use std::{collections::{BTreeSet, HashMap}, marker::PhantomData};
use tracing::{debug, error, trace, warn};

/// Manages incoming and outgoing broadcast requests.
pub struct Engine<
    E: Clock + GClock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Coordinator<PublicKey = P>,
    Key: Span,
    Con: Consumer<Key = Key, Value = Bytes, Failure = ()>,
    Pro: Producer<Key = Key>,
    NetS: Sender<PublicKey = P>,
    NetR: Receiver<PublicKey = P>,
> {
    /// Context used to spawn tasks, manage time, etc.
    context: E,

    /// Consumes validated data
    consumer: Con,

    /// Produces data for incoming requests
    producer: Pro,

    /// Manages the list of peers used for broadcast
    coordinator: D,

    /// Used to detect changes in the peer set
    last_peer_set_id: Option<u64>,

    /// Mailbox for resolver API
    mailbox: mpsc::Receiver<Message<Key>>,

    /// Cache: for each key, set of seen digests to deduplicate notifications
    seen_hashes: HashMap<Key, BTreeSet<[u8; 32]>>,

    /// Tracks keys that should be ignored (canceled)
    canceled: BTreeSet<Key>,

    /// Whether to mark request/response as priority
    priority_requests: bool,
    priority_responses: bool,

    /// Holds futures that resolve once the `Producer` has produced the data.
    serves: commonware_utils::futures::Pool<Serve<P, Key>>,

    /// Phantom for networking types
    _s: PhantomData<NetS>,
    _r: PhantomData<NetR>,
}

/// Represents a pending serve operation (produce then respond).
struct Serve<P: PublicKey, K: Span> {
    peer: P,
    key: K,
    result: Result<Bytes, oneshot::Canceled>,
}

impl<
        E: Clock + GClock + Spawner + Rng + Metrics,
        P: PublicKey,
        D: Coordinator<PublicKey = P>,
        Key: Span,
        Con: Consumer<Key = Key, Value = Bytes, Failure = ()>,
        Pro: Producer<Key = Key>,
        NetS: Sender<PublicKey = P>,
        NetR: Receiver<PublicKey = P>,
    > Engine<E, P, D, Key, Con, Pro, NetS, NetR>
{
    /// Creates a new `Engine` with the given configuration and mailbox.
    pub fn new(context: E, cfg: Config<P, D, Key, Con, Pro>) -> (Self, Mailbox<Key>) {
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context,
                consumer: cfg.consumer,
                producer: cfg.producer,
                coordinator: cfg.coordinator,
                last_peer_set_id: None,
                mailbox: receiver,
                seen_hashes: HashMap::new(),
                canceled: BTreeSet::new(),
                priority_requests: cfg.priority_requests,
                priority_responses: cfg.priority_responses,
                serves: commonware_utils::futures::Pool::default(),
                _s: PhantomData,
                _r: PhantomData,
            },
            Mailbox::new(sender),
        )
    }

    /// Runs the actor until the context is stopped.
    pub fn start(mut self, network: (NetS, NetR)) -> Handle<()> {
        self.context.spawn_ref()(self.run(network))
    }

    async fn run(mut self, network: (NetS, NetR)) {
        let mut shutdown = self.context.stopped();

        // Wrap channel
        let (mut sender, mut receiver) = wrap((), network.0, network.1);

        // Set initial peer set id
        self.last_peer_set_id = Some(self.coordinator.peer_set_id());

        loop {
            select! {
                _ = &mut shutdown => {
                    debug!("shutdown");
                    return;
                },

                // Handle mailbox messages
                msg = self.mailbox.next() => {
                    let Some(msg) = msg else {
                        error!("mailbox closed");
                        return;
                    };
                    match msg {
                        Message::Fetch { key } => {
                            trace!(?key, "mailbox: fetch (broadcast)");
                            self.canceled.remove(&key);
                            self.broadcast_request(&mut sender, key).await;
                        }
                        Message::Cancel { key } => {
                            trace!(?key, "mailbox: cancel");
                            self.canceled.insert(key.clone());
                            self.seen_hashes.remove(&key);
                            // Notify consumer of failure semantics
                            self.consumer.failed(key, ()).await;
                        }
                        Message::Retain { predicate } => {
                            trace!("mailbox: retain");
                            self.seen_hashes.retain(|k, _| predicate(k));
                            self.canceled.retain(|k| predicate(k));
                        }
                        Message::Clear => {
                            trace!("mailbox: clear");
                            self.seen_hashes.clear();
                            self.canceled.clear();
                        }
                    }
                },

                // Handle network messages
                msg = receiver.recv() => {
                    let (peer, msg) = match msg {
                        Ok(msg) => msg,
                        Err(err) => {
                            error!(?err, "receiver closed");
                            return;
                        }
                    };

                    // Skip if there is a decoding error
                    let msg = match msg {
                        Ok(msg) => msg,
                        Err(err) => {
                            trace!(?err, ?peer, "decode failed");
                            continue;
                        }
                    };

                    match msg.payload {
                        wire::Payload::Request(key) => self.handle_network_request(&mut sender, peer, key).await,
                        wire::Payload::Response { key, data } => self.handle_network_response(peer, key, data).await,
                    }
                },
                // Handle completed serve operations (send responses)
                serve = self.serves.next_completed() => {
                    let Serve { peer, key, result } = serve;
                    if let Ok(data) = result {
                        let msg = wire::Message { payload: wire::Payload::Response { key, data } };
                        let result = sender.send(Recipients::One(peer.clone()), msg, self.priority_responses).await;
                        match result {
                            Err(err) => error!(?err, ?peer, "serve send failed"),
                            Ok(to) if to.is_empty() => warn!(?peer, "serve send failed (empty)"),
                            Ok(_) => trace!(?peer, "serve sent"),
                        }
                    }
                },
            }
        }
    }

    async fn broadcast_request(&mut self, sender: &mut WrappedSender<NetS, wire::Message<Key>>, key: Key) {
        let msg = wire::Message { payload: wire::Payload::Request(key.clone()) };
        // Broadcast to all peers
        let result = sender.send(Recipients::All, msg, self.priority_requests).await;
        match result {
            Err(err) => error!(?err, "broadcast send failed"),
            Ok(to) if to.is_empty() => warn!("broadcast sent to empty set"),
            Ok(_) => trace!(?key, "broadcast sent"),
        }
    }

    async fn handle_network_request(&mut self, _sender: &mut WrappedSender<NetS, wire::Message<Key>>, peer: P, key: Key) {
        trace!(?peer, ?key, "peer request (broadcast)");
        let mut producer = self.producer.clone();
        self.serves.push(async move {
            let receiver = producer.produce(key.clone()).await;
            let result = receiver.await;
            Serve { peer, key, result }
        });
    }

    async fn handle_network_response(&mut self, peer: P, key: Key, response: Bytes) {
        trace!(?peer, ?key, "peer response: data (broadcast)");

        // Drop if canceled
        if self.canceled.contains(&key) {
            return;
        }

        // Compute 32-byte hash for dedupe (use blake3 via cryptography crate)
        let digest = commonware_cryptography::blake3::hash(response.as_ref());
        let entry = self.seen_hashes.entry(key.clone()).or_default();
        if !entry.insert(digest.0) {
            // Already seen this content for this key; ignore
            return;
        }

        // Deliver to consumer; if invalid, do nothing (still deduped by content)
        let _ = self.consumer.deliver(key, response).await;
    }
}



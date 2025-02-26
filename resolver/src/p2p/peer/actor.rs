use super::{
    config::Config,
    fetcher::Fetcher,
    ingress::{Mailbox, Message},
};
use crate::{
    p2p::{
        wire::{self, peer_msg::Payload},
        Coordinator, Producer,
    },
    Consumer,
};
use bytes::Bytes;
use commonware_cryptography::Scheme;
use commonware_macros::select;
use commonware_p2p::utils::requester::Requester;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Metrics, Spawner};
use commonware_utils::{futures::Pool as FuturesPool, Array};
use futures::{
    channel::{mpsc, oneshot},
    future::{self, Either},
    StreamExt,
};
use governor::clock::Clock as GClock;
use prost::Message as _;
use rand::Rng;
use std::marker::PhantomData;
use tracing::{debug, error, warn};

/// Manages incoming and outgoing P2P requests, coordinating fetch and serve operations.
pub struct Actor<
    E: Clock + GClock + Spawner + Rng + Metrics,
    C: Scheme,
    D: Coordinator<PublicKey = C::PublicKey>,
    Key: Array,
    Con: Consumer<Key = Key, Value = Bytes, Failure = ()>,
    Pro: Producer<Key = Key>,
    NetS: Sender<PublicKey = C::PublicKey>,
    NetR: Receiver<PublicKey = C::PublicKey>,
> {
    /// Context used to spawn tasks, manage time, etc.
    context: E,

    /// Consumes data that is fetched from the network
    consumer: Con,

    /// Produces data for incoming requests
    producer: Pro,

    /// Manages the list of peers that can be used to fetch data
    coordinator: D,

    /// Used to detect changes in the peer set
    last_peer_set_id: Option<u64>,

    /// Mailbox that makes and cancels fetch requests
    mailbox: mpsc::Receiver<Message<Key>>,

    /// Manages outgoing fetch requests
    fetcher: Fetcher<E, C, Key, NetS>,

    /// Holds futures that resolve once the `Producer` has produced the data.
    /// Once the future is resolved, the data (or an error) is sent to the peer.
    /// Has unbounded size; the number of concurrent requests should be limited
    /// by the `Producer` which may drop requests.
    serves: FuturesPool<(C::PublicKey, u64, Result<Bytes, oneshot::Canceled>)>,

    /// Whether responses are sent with priority over other network messages
    priority_responses: bool,

    /// Phantom data for networking types
    _s: PhantomData<NetS>,
    _r: PhantomData<NetR>,
}

impl<
        E: Clock + GClock + Spawner + Rng + Metrics,
        C: Scheme,
        D: Coordinator<PublicKey = C::PublicKey>,
        Key: Array,
        Con: Consumer<Key = Key, Value = Bytes, Failure = ()>,
        Pro: Producer<Key = Key>,
        NetS: Sender<PublicKey = C::PublicKey>,
        NetR: Receiver<PublicKey = C::PublicKey>,
    > Actor<E, C, D, Key, Con, Pro, NetS, NetR>
{
    /// Creates a new `Actor` with the given configuration.
    ///
    /// Returns the actor and a mailbox to send messages to it.
    pub async fn new(context: E, cfg: Config<C, D, Key, Con, Pro>) -> (Self, Mailbox<Key>) {
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        let requester = Requester::new(context.clone(), cfg.requester_config);
        let fetcher = Fetcher::new(
            context.clone(),
            requester,
            cfg.fetch_retry_timeout,
            cfg.priority_requests,
        );
        (
            Self {
                context,
                consumer: cfg.consumer,
                producer: cfg.producer,
                coordinator: cfg.coordinator,
                last_peer_set_id: None,
                mailbox: receiver,
                fetcher,
                serves: FuturesPool::default(),
                priority_responses: cfg.priority_responses,
                _s: PhantomData,
                _r: PhantomData,
            },
            Mailbox::new(sender),
        )
    }

    /// Runs the actor until the context is stopped.
    ///
    /// The actor will handle:
    /// - Fetching data from other peers and notifying the `Consumer`
    /// - Serving data to other peers by requesting it from the `Producer`
    pub fn start(mut self, network: (NetS, NetR)) -> Handle<()> {
        self.context.spawn_ref()(self.run(network))
    }

    /// Inner run loop called by `start`.
    async fn run(mut self, network: (NetS, NetR)) {
        let (mut sender, mut receiver) = network;
        let mut shutdown = self.context.stopped();

        // Set initial peer set.
        self.last_peer_set_id = Some(self.coordinator.peer_set_id());
        self.fetcher.reconcile(self.coordinator.peers());

        loop {
            // Update peer list if-and-only-if it might have changed.
            let peer_set_id = self.coordinator.peer_set_id();
            if self.last_peer_set_id != Some(peer_set_id) {
                self.last_peer_set_id = Some(peer_set_id);
                self.fetcher.reconcile(self.coordinator.peers());
            }

            // Get retry timeout (if any)
            let deadline_pending = match self.fetcher.get_pending_deadline() {
                Some(deadline) => Either::Left(self.context.sleep_until(deadline)),
                None => Either::Right(future::pending()),
            };

            // Get requester timeout (if any)
            let deadline_active = match self.fetcher.get_active_deadline() {
                Some(deadline) => Either::Left(self.context.sleep_until(deadline)),
                None => Either::Right(future::pending()),
            };

            // Handle shutdown signal
            select! {
                _ = &mut shutdown => {
                    debug!("shutdown");
                    self.serves.cancel_all();
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
                            debug!(?key, "mailbox: fetch");
                            self.fetcher.fetch(&mut sender, key.clone(), true).await;
                        }
                        Message::Cancel { key } => {
                            debug!(?key, "mailbox: cancel");
                            if self.fetcher.cancel(&key) {
                                self.consumer.failed(key, ()).await;
                            }
                        }
                    }
                },

                // Handle completed server requests
                msg = self.serves.next_completed() => {
                    let (peer, id, result) = msg;
                    Self::handle_serve(&mut sender, peer, id, result, self.priority_responses).await;
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
                    let msg = match wire::PeerMsg::decode(msg) {
                        Ok(msg) => msg,
                        Err(err) => {
                            warn!(?err, ?peer, "decode failed");
                            continue;
                        }
                    };
                    match msg.payload {
                        Some(Payload::Request(request)) => self.handle_network_request(peer, msg.id, request).await,
                        Some(Payload::Response(response)) => self.handle_network_response(&mut sender, peer, msg.id, response).await,
                        None => self.handle_network_response_empty(&mut sender, peer, msg.id).await,
                    };
                },

                // Handle pending deadline
                _ = deadline_pending => {
                    let key = self.fetcher.pop_pending();
                    debug!(?key, "retrying");
                    self.fetcher.fetch(&mut sender, key, false).await;
                },

                // Handle active deadline
                _ = deadline_active => {
                    if let Some(key) = self.fetcher.pop_active() {
                        debug!(?key, "requester timeout");
                        self.fetcher.fetch(&mut sender, key, false).await;
                    }
                },
            }
        }
    }

    /// Handles the case where the application responds to a request from an external peer.
    async fn handle_serve(
        sender: &mut NetS,
        peer: C::PublicKey,
        id: u64,
        response: Result<Bytes, oneshot::Canceled>,
        priority: bool,
    ) {
        // Encode message. If the response is an error, send an empty response.
        let msg = wire::PeerMsg {
            id,
            payload: response.ok().map(Payload::Response),
        }
        .encode_to_vec()
        .into();

        // Send message to peer
        let result = sender
            .send(Recipients::One(peer.clone()), msg, priority)
            .await;

        // Log result, but do not handle errors
        match result {
            Err(err) => error!(?err, ?peer, ?id, "serve send failed"),
            Ok(to) if to.is_empty() => warn!(?peer, ?id, "serve send failed"),
            Ok(_) => debug!(?peer, ?id, "serve sent"),
        };
    }

    /// Handle a network request from a peer.
    async fn handle_network_request(&mut self, peer: C::PublicKey, id: u64, request: Bytes) {
        // Parse request
        let Ok(key) = Key::try_from(request.to_vec()) else {
            warn!(?peer, ?id, "peer invalid request");
            return;
        };

        // Serve the request
        debug!(?peer, ?id, "peer request");
        let mut producer = self.producer.clone();
        self.serves.push(async move {
            let receiver = producer.produce(key).await;
            let result = receiver.await;
            (peer, id, result)
        });
    }

    /// Handle a network response from a peer.
    async fn handle_network_response(
        &mut self,
        sender: &mut NetS,
        peer: C::PublicKey,
        id: u64,
        response: Bytes,
    ) {
        debug!(?peer, ?id, "peer response: data");

        // Get the key associated with the response, if any
        let Some(key) = self.fetcher.pop_by_id(id, &peer, true) else {
            // It's possible that the key does not exist if the request was canceled
            return;
        };

        // The peer had the data, so we can deliver it to the consumer
        if self.consumer.deliver(key.clone(), response).await {
            // If the data is valid, the fetch is complete
            return;
        }

        // If the data is invalid, we need to block the peer and try again
        self.fetcher.block(peer);
        self.fetcher.fetch(sender, key, false).await;
    }

    /// Handle a network response from a peer that did not have the data.
    async fn handle_network_response_empty(
        &mut self,
        sender: &mut NetS,
        peer: C::PublicKey,
        id: u64,
    ) {
        warn!(?peer, ?id, "peer response: error");

        // Get the key associated with the response, if any
        let Some(key) = self.fetcher.pop_by_id(id, &peer, false) else {
            // It's possible that the key does not exist if the request was canceled
            return;
        };

        // The peer did not have the data, so we need to try again
        self.fetcher.fetch(sender, key, false).await;
    }
}

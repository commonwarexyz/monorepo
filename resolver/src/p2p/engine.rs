use super::{
    config::Config,
    fetcher::Fetcher,
    ingress::{Mailbox, Message},
    metrics,
};
use super::{
    wire::{Payload, PeerMsg},
    Coordinator, Producer,
};
use crate::Consumer;
use bytes::Bytes;
use commonware_codec::{DecodeExt, Encode};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{
    telemetry::metrics::{
        histogram,
        status::{CounterExt, Status},
    },
    Clock, Handle, Metrics, Spawner,
};
use commonware_utils::{futures::Pool as FuturesPool, Array};
use futures::{
    channel::{mpsc, oneshot},
    future::{self, Either},
    StreamExt,
};
use governor::clock::Clock as GClock;
use rand::Rng;
use std::{collections::HashMap, marker::PhantomData};
use tracing::{debug, error, trace, warn};

/// Represents a pending serve operation.
struct Serve<E: Clock, P: Array> {
    timer: histogram::Timer<E>,
    peer: P,
    id: u64,
    result: Result<Bytes, oneshot::Canceled>,
}

/// Manages incoming and outgoing P2P requests, coordinating fetch and serve operations.
pub struct Engine<
    E: Clock + GClock + Spawner + Rng + Metrics,
    P: Array,
    D: Coordinator<PublicKey = P>,
    Key: Array,
    Con: Consumer<Key = Key, Value = Bytes, Failure = ()>,
    Pro: Producer<Key = Key>,
    NetS: Sender<PublicKey = P>,
    NetR: Receiver<PublicKey = P>,
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
    fetcher: Fetcher<E, P, Key, NetS>,

    /// Track the start time of fetch operations
    fetch_timers: HashMap<Key, histogram::Timer<E>>,

    /// Holds futures that resolve once the `Producer` has produced the data.
    /// Once the future is resolved, the data (or an error) is sent to the peer.
    /// Has unbounded size; the number of concurrent requests should be limited
    /// by the `Producer` which may drop requests.
    serves: FuturesPool<Serve<E, P>>,

    /// Whether responses are sent with priority over other network messages
    priority_responses: bool,

    /// Metrics for the peer actor
    metrics: metrics::Metrics<E>,

    /// Phantom data for networking types
    _s: PhantomData<NetS>,
    _r: PhantomData<NetR>,
}

impl<
        E: Clock + GClock + Spawner + Rng + Metrics,
        P: Array,
        D: Coordinator<PublicKey = P>,
        Key: Array,
        Con: Consumer<Key = Key, Value = Bytes, Failure = ()>,
        Pro: Producer<Key = Key>,
        NetS: Sender<PublicKey = P>,
        NetR: Receiver<PublicKey = P>,
    > Engine<E, P, D, Key, Con, Pro, NetS, NetR>
{
    /// Creates a new `Actor` with the given configuration.
    ///
    /// Returns the actor and a mailbox to send messages to it.
    pub fn new(context: E, cfg: Config<P, D, Key, Con, Pro>) -> (Self, Mailbox<Key>) {
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        let metrics = metrics::Metrics::init(context.clone());
        let fetcher = Fetcher::new(
            context.clone(),
            cfg.requester_config,
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
                metrics,
                fetch_timers: HashMap::new(),
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
            // Update metrics
            self.metrics
                .fetch_pending
                .set(self.fetcher.len_pending() as i64);
            self.metrics
                .fetch_active
                .set(self.fetcher.len_active() as i64);
            self.metrics
                .peers_blocked
                .set(self.fetcher.len_blocked() as i64);
            self.metrics.serve_processing.set(self.serves.len() as i64);

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
                            trace!(?key, "mailbox: fetch");

                            // Check if the fetch is already in progress
                            if self.fetch_timers.contains_key(&key) {
                                trace!(?key, "duplicate fetch");
                                self.metrics.fetch.inc(Status::Dropped);
                                continue;
                            }

                            // Record fetch start time
                            self.fetch_timers.insert(key.clone(), self.metrics.fetch_duration.timer());
                            self.fetcher.fetch(&mut sender, key, true).await;
                        }
                        Message::Cancel { key } => {
                            trace!(?key, "mailbox: cancel");
                            let mut guard = self.metrics.cancel.guard(Status::Dropped);
                            if self.fetcher.cancel(&key) {
                                guard.set(Status::Success);
                                self.fetch_timers.remove(&key).unwrap().cancel(); // must exist, don't record metric
                                self.consumer.failed(key.clone(), ()).await;
                            }
                        }
                    }
                },

                // Handle completed server requests
                serve = self.serves.next_completed() => {
                    let Serve { timer, peer, id, result } = serve;

                    // Metrics and logs
                    match result {
                        Ok(_) => {
                            self.metrics.serve.inc(Status::Success);
                        }
                        Err(err) => {
                            debug!(?err, ?peer, ?id, "serve failed");
                            timer.cancel();
                            self.metrics.serve.inc(Status::Failure);
                        }
                    }

                    // Send response to peer
                    self.handle_serve(&mut sender, peer, id, result, self.priority_responses).await;
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
                    let msg = match PeerMsg::decode(msg) {
                        Ok(msg) => msg,
                        Err(err) => {
                            trace!(?err, ?peer, "decode failed");
                            continue;
                        }
                    };
                    match msg.payload {
                        Payload::Request(request) => self.handle_network_request(peer, msg.id, request).await,
                        Payload::Response(response) => self.handle_network_response(&mut sender, peer, msg.id, response).await,
                        Payload::ErrorResponse => self.handle_network_error_response(&mut sender, peer, msg.id).await,
                    };
                },

                // Handle pending deadline
                _ = deadline_pending => {
                    let key = self.fetcher.pop_pending();
                    debug!(?key, "retrying");
                    self.metrics.fetch.inc(Status::Failure);
                    self.fetcher.fetch(&mut sender, key, false).await;
                },

                // Handle active deadline
                _ = deadline_active => {
                    if let Some(key) = self.fetcher.pop_active() {
                        debug!(?key, "requester timeout");
                        self.metrics.fetch.inc(Status::Failure);
                        self.fetcher.fetch(&mut sender, key, false).await;
                    }
                },
            }
        }
    }

    /// Handles the case where the application responds to a request from an external peer.
    async fn handle_serve(
        &mut self,
        sender: &mut NetS,
        peer: P,
        id: u64,
        response: Result<Bytes, oneshot::Canceled>,
        priority: bool,
    ) {
        // Encode message
        let payload = match response {
            Ok(data) => Payload::Response(data),
            Err(_) => Payload::ErrorResponse,
        };
        let msg: Bytes = PeerMsg { id, payload }.encode().into();

        // Send message to peer
        let result = sender
            .send(Recipients::One(peer.clone()), msg, priority)
            .await;

        // Log result, but do not handle errors
        match result {
            Err(err) => error!(?err, ?peer, ?id, "serve send failed"),
            Ok(to) if to.is_empty() => warn!(?peer, ?id, "serve send failed"),
            Ok(_) => trace!(?peer, ?id, "serve sent"),
        };
    }

    /// Handle a network request from a peer.
    async fn handle_network_request(&mut self, peer: P, id: u64, request: Bytes) {
        // Parse request
        let Ok(key) = Key::try_from(request.to_vec()) else {
            trace!(?peer, ?id, "peer invalid request");
            self.metrics.serve.inc(Status::Invalid);
            return;
        };

        // Serve the request
        trace!(?peer, ?id, "peer request");
        let mut producer = self.producer.clone();
        let timer = self.metrics.serve_duration.timer();
        self.serves.push(async move {
            let receiver = producer.produce(key).await;
            let result = receiver.await;
            Serve {
                timer,
                peer,
                id,
                result,
            }
        });
    }

    /// Handle a network response from a peer.
    async fn handle_network_response(
        &mut self,
        sender: &mut NetS,
        peer: P,
        id: u64,
        response: Bytes,
    ) {
        trace!(?peer, ?id, "peer response: data");

        // Get the key associated with the response, if any
        let Some(key) = self.fetcher.pop_by_id(id, &peer, true) else {
            // It's possible that the key does not exist if the request was canceled
            return;
        };

        // The peer had the data, so we can deliver it to the consumer
        if self.consumer.deliver(key.clone(), response).await {
            // Record metrics
            self.metrics.fetch.inc(Status::Success);
            self.fetch_timers.remove(&key).unwrap(); // must exist in the map, records metric on drop
            return;
        }

        // If the data is invalid, we need to block the peer and try again
        self.fetcher.block(peer);
        self.metrics.fetch.inc(Status::Failure);
        self.fetcher.fetch(sender, key, false).await;
    }

    /// Handle a network response from a peer that did not have the data.
    async fn handle_network_error_response(&mut self, sender: &mut NetS, peer: P, id: u64) {
        trace!(?peer, ?id, "peer response: error");

        // Get the key associated with the response, if any
        let Some(key) = self.fetcher.pop_by_id(id, &peer, false) else {
            // It's possible that the key does not exist if the request was canceled
            return;
        };

        // The peer did not have the data, so we need to try again
        self.metrics.fetch.inc(Status::Failure);
        // Don't reset start time for retries, keep the original
        self.fetcher.fetch(sender, key, false).await;
    }
}

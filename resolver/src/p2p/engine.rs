use super::{
    config::Config,
    fetcher::Fetcher,
    ingress::{FetchRequest, Mailbox, Message},
    metrics, wire, Producer,
};
use crate::Consumer;
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_macros::select;
use commonware_p2p::{
    utils::codec::{wrap, WrappedSender},
    Blocker, Manager, Receiver, Recipients, Sender,
};
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::{
        histogram,
        status::{CounterExt, GaugeExt, Status},
    },
    Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_utils::{futures::Pool as FuturesPool, Span};
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
struct Serve<E: Clock, P: PublicKey> {
    timer: histogram::Timer<E>,
    peer: P,
    id: u64,
    result: Result<Bytes, oneshot::Canceled>,
}

/// Manages incoming and outgoing P2P requests, coordinating fetch and serve operations.
pub struct Engine<
    E: Clock + GClock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Manager<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    Key: Span,
    Con: Consumer<Key = Key, Value = Bytes, Failure = ()>,
    Pro: Producer<Key = Key>,
    NetS: Sender<PublicKey = P>,
    NetR: Receiver<PublicKey = P>,
> {
    /// Context used to spawn tasks, manage time, etc.
    context: ContextCell<E>,

    /// Consumes data that is fetched from the network
    consumer: Con,

    /// Produces data for incoming requests
    producer: Pro,

    /// Manages the list of peers that can be used to fetch data
    manager: D,

    /// The blocker that will be used to block peers that send invalid responses
    blocker: B,

    /// Used to detect changes in the peer set
    last_peer_set_id: Option<u64>,

    /// Mailbox that makes and cancels fetch requests
    mailbox: mpsc::Receiver<Message<Key, P>>,

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
        P: PublicKey,
        D: Manager<PublicKey = P>,
        B: Blocker<PublicKey = P>,
        Key: Span,
        Con: Consumer<Key = Key, Value = Bytes, Failure = ()>,
        Pro: Producer<Key = Key>,
        NetS: Sender<PublicKey = P>,
        NetR: Receiver<PublicKey = P>,
    > Engine<E, P, D, B, Key, Con, Pro, NetS, NetR>
{
    /// Creates a new `Actor` with the given configuration.
    ///
    /// Returns the actor and a mailbox to send messages to it.
    pub fn new(context: E, cfg: Config<P, D, B, Key, Con, Pro>) -> (Self, Mailbox<Key, P>) {
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);

        // TODO(#1833): Metrics should use the post-start context
        let metrics = metrics::Metrics::init(context.clone());
        let fetcher = Fetcher::new(
            context.with_label("fetcher"),
            cfg.requester_config,
            cfg.fetch_retry_timeout,
            cfg.priority_requests,
        );
        (
            Self {
                context: ContextCell::new(context),
                consumer: cfg.consumer,
                producer: cfg.producer,
                manager: cfg.manager,
                blocker: cfg.blocker,
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
        spawn_cell!(self.context, self.run(network).await)
    }

    /// Inner run loop called by `start`.
    async fn run(mut self, network: (NetS, NetR)) {
        let mut shutdown = self.context.stopped();
        let peer_set_subscription = &mut self.manager.subscribe().await;

        // Wrap channel
        let (mut sender, mut receiver) = wrap((), network.0, network.1);

        loop {
            // Update metrics
            let _ = self
                .metrics
                .fetch_pending
                .try_set(self.fetcher.len_pending());
            let _ = self.metrics.fetch_active.try_set(self.fetcher.len_active());
            let _ = self
                .metrics
                .peers_blocked
                .try_set(self.fetcher.len_blocked());
            let _ = self.metrics.serve_processing.try_set(self.serves.len());

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

                // Handle peer set updates
                peer_set_update = peer_set_subscription.next() => {
                    let Some((id, _, all)) = peer_set_update else {
                        debug!("peer set subscription closed");
                        return;
                    };

                    // Instead of directing our requests to exclusively the latest set (which may still be syncing, we
                    // reconcile with all tracked peers).
                    if self.last_peer_set_id < Some(id) {
                        self.last_peer_set_id = Some(id);
                        self.fetcher.reconcile(all.as_ref());
                    }
                },

                // Handle active deadline
                _ = deadline_active => {
                    if let Some(key) = self.fetcher.pop_active() {
                        debug!(?key, "requester timeout");
                        self.metrics.fetch.inc(Status::Failure);
                        self.fetcher.add_retry(key);
                    }
                },

                // Handle pending deadline
                _ = deadline_pending => {
                    self.fetcher.fetch(&mut sender).await;
                },

                // Handle mailbox messages
                msg = self.mailbox.next() => {
                    let Some(msg) = msg else {
                        error!("mailbox closed");
                        return;
                    };
                    match msg {
                        Message::Fetch(requests) => {
                            for FetchRequest { key, targets } in requests {
                                trace!(?key, "mailbox: fetch");

                                // Check if the fetch is already in progress
                                let is_new = !self.fetch_timers.contains_key(&key);

                                // Update targets (even for existing fetches)
                                match targets {
                                    Some(targets) => self.fetcher.add_targets(key.clone(), targets),
                                    None => self.fetcher.clear_targets(&key),
                                }

                                // Only start new fetch if not already in progress
                                if is_new {
                                    self.fetch_timers.insert(key.clone(), self.metrics.fetch_duration.timer());
                                    self.fetcher.add_ready(key);
                                } else {
                                    trace!(?key, "updated targets for existing fetch");
                                }
                            }
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
                        Message::Retain { predicate } => {
                            trace!("mailbox: retain");

                            // Remove from fetcher
                            self.fetcher.retain(&predicate);

                            // Clean up timers and notify consumer
                            let before = self.fetch_timers.len();
                            let removed = self.fetch_timers.extract_if(|k, _| !predicate(k)).collect::<Vec<_>>();
                            for (key, timer) in removed {
                                timer.cancel();
                                self.consumer.failed(key, ()).await;
                            }

                            // Metrics
                            let removed = (before - self.fetch_timers.len()) as u64;
                            if removed == 0 {
                                self.metrics.cancel.inc(Status::Dropped);
                            } else {
                                self.metrics.cancel.inc_by(Status::Success, removed);
                            }
                        }
                        Message::Clear => {
                            trace!("mailbox: clear");

                            // Clear fetcher
                            self.fetcher.clear();

                            // Drain timers and notify consumer
                            let removed = self.fetch_timers.len() as u64;
                            for (key, timer) in self.fetch_timers.drain() {
                                timer.cancel();
                                self.consumer.failed(key, ()).await;
                            }

                            // Metrics
                            if removed == 0 {
                                self.metrics.cancel.inc(Status::Dropped);
                            } else {
                                self.metrics.cancel.inc_by(Status::Success, removed);
                            }
                        }
                    }
                    assert_eq!(self.fetcher.len(), self.fetch_timers.len());
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
                    // Break if the receiver is closed
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
                        wire::Payload::Request(key) => self.handle_network_request(peer, msg.id, key).await,
                        wire::Payload::Response(response) => self.handle_network_response(peer, msg.id, response).await,
                        wire::Payload::Error => self.handle_network_error_response(peer, msg.id).await,
                    };
                },
            }
        }
    }

    /// Handles the case where the application responds to a request from an external peer.
    async fn handle_serve(
        &mut self,
        sender: &mut WrappedSender<NetS, wire::Message<Key>>,
        peer: P,
        id: u64,
        response: Result<Bytes, oneshot::Canceled>,
        priority: bool,
    ) {
        // Encode message
        let payload: wire::Payload<Key> = response.map_or_else(
            |_| wire::Payload::Error,
            |data| wire::Payload::Response(data),
        );
        let msg = wire::Message { id, payload };

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
    async fn handle_network_request(&mut self, peer: P, id: u64, key: Key) {
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
    async fn handle_network_response(&mut self, peer: P, id: u64, response: Bytes) {
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

            // Clear all targets for this key
            self.fetcher.clear_targets(&key);
            return;
        }

        // If the data is invalid, we need to block the peer and try again
        // (blocking the peer also removes any targets associated with it)
        self.blocker.block(peer.clone()).await;
        self.fetcher.block(peer);
        self.metrics.fetch.inc(Status::Failure);
        self.fetcher.add_retry(key);
    }

    /// Handle a network response from a peer that did not have the data.
    async fn handle_network_error_response(&mut self, peer: P, id: u64) {
        trace!(?peer, ?id, "peer response: error");

        // Get the key associated with the response, if any
        let Some(key) = self.fetcher.pop_by_id(id, &peer, false) else {
            // It's possible that the key does not exist if the request was canceled
            return;
        };

        // The peer did not have the data, so we need to try again
        self.metrics.fetch.inc(Status::Failure);
        self.fetcher.add_retry(key);
    }
}

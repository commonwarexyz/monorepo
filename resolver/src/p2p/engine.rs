use super::{
    config::Config,
    fetcher::{Config as FetcherConfig, Fetcher},
    inflight::Inflight,
    ingress::{FetchRequest, Mailbox, Message},
    metrics, wire, Producer,
};
use crate::{Consumer, Delivery};
use bytes::Bytes;
use commonware_actor::mailbox;
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_p2p::{
    utils::codec::{wrap, WrappedSender},
    Blocker, Provider, Receiver, Recipients, Sender,
};
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::{histogram, status::Status, GaugeExt},
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_utils::{channel::oneshot, futures::Pool as FuturesPool, Span};
use futures::future::{self, Either};
use rand::Rng;
use std::{
    collections::{BTreeSet, HashMap},
    marker::PhantomData,
};
use tracing::{debug, error, trace, warn};

/// Represents a pending serve operation.
struct Serve<P: PublicKey> {
    timer: histogram::Timer,
    peer: P,
    id: u64,
    result: Result<Bytes, oneshot::error::RecvError>,
}

/// Manages incoming and outgoing P2P requests, coordinating fetch and serve operations.
pub struct Engine<
    E: BufferPooler + Clock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    Key: Span,
    Con: Consumer<Request = Key, Value = Bytes>,
    Pro: Producer<Request = Key>,
    NetS: Sender<PublicKey = P>,
    NetR: Receiver<PublicKey = P>,
> where
    Con::Subscriber: Eq,
{
    /// Context used to spawn tasks, manage time, etc.
    context: ContextCell<E>,

    /// Produces data for incoming requests
    producer: Pro,

    /// Manages the list of peers that can be used to fetch data
    peer_provider: D,

    /// The blocker that will be used to block peers that send invalid responses
    blocker: B,

    /// Used to detect changes in the peer set
    last_peer_set_id: Option<u64>,

    /// Mailbox that makes and cancels fetch requests
    mailbox: mailbox::Receiver<Message<Key, P, Con::Subscriber>>,

    /// Manages outgoing fetch requests
    fetcher: Fetcher<E, P, Key, NetS>,

    /// Tracks all in-flight fetch state
    inflight: Inflight<E, Con, P, Key>,

    /// Local subscribers that keep each fetch request alive.
    interests: HashMap<Key, Interests<Con::Subscriber>>,

    /// Holds futures that resolve once the `Producer` has produced the data.
    /// Once the future is resolved, the data (or an error) is sent to the peer.
    /// Has unbounded size; the number of concurrent requests should be limited
    /// by the `Producer` which may drop requests.
    serves: FuturesPool<Serve<P>>,

    /// Whether responses are sent with priority over other network messages
    priority_responses: bool,

    /// Metrics for the peer actor
    metrics: metrics::Metrics,

    /// Phantom data for networking types
    _r: PhantomData<NetR>,
}

struct Interests<S> {
    subscribers: BTreeSet<S>,
}

impl<S> Default for Interests<S> {
    fn default() -> Self {
        Self {
            subscribers: BTreeSet::new(),
        }
    }
}

impl<S> Interests<S> {
    fn is_empty(&self) -> bool {
        self.subscribers.is_empty()
    }
}

impl<
        E: BufferPooler + Clock + Spawner + Rng + Metrics,
        P: PublicKey,
        D: Provider<PublicKey = P>,
        B: Blocker<PublicKey = P>,
        Key: Span,
        Con: Consumer<Request = Key, Value = Bytes>,
        Pro: Producer<Request = Key>,
        NetS: Sender<PublicKey = P>,
        NetR: Receiver<PublicKey = P>,
    > Engine<E, P, D, B, Key, Con, Pro, NetS, NetR>
where
    Con::Subscriber: Clone + Ord + Send + 'static,
{
    /// Creates a new `Actor` with the given configuration.
    ///
    /// Returns the actor and a mailbox to send messages to it.
    pub fn new(
        context: E,
        cfg: Config<P, D, B, Key, Con, Pro>,
    ) -> (Self, Mailbox<Key, P, Con::Subscriber>) {
        let (sender, receiver) = mailbox::new(context.child("mailbox"), cfg.mailbox_size);

        let metrics = metrics::Metrics::init(&context);
        let fetcher = Fetcher::new(
            context.child("fetcher"),
            FetcherConfig {
                me: cfg.me,
                initial: cfg.initial,
                timeout: cfg.timeout,
                retry_timeout: cfg.fetch_retry_timeout,
                priority_requests: cfg.priority_requests,
            },
        );
        (
            Self {
                context: ContextCell::new(context),
                producer: cfg.producer,
                peer_provider: cfg.peer_provider,
                blocker: cfg.blocker,
                last_peer_set_id: None,
                mailbox: receiver,
                fetcher,
                inflight: Inflight::new(cfg.consumer),
                interests: HashMap::new(),
                serves: FuturesPool::default(),
                priority_responses: cfg.priority_responses,
                metrics,
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
        spawn_cell!(self.context, self.run(network))
    }

    /// Inner run loop called by `start`.
    async fn run(mut self, network: (NetS, NetR)) {
        // Wrap channel
        let (mut sender, mut receiver) = wrap(
            (),
            self.context.network_buffer_pool().clone(),
            network.0,
            network.1,
        );
        let peer_set_subscription = &mut self.peer_provider.subscribe().await;

        select_loop! {
            self.context,
            on_start => {
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
            },
            on_stopped => {
                debug!("shutdown");
                self.inflight.drain();
                self.interests.clear();
                self.serves.cancel_all();
            },
            // Handle peer set updates
            Some(update) = peer_set_subscription.recv() else {
                debug!("peer set subscription closed");
                return;
            } => {
                if self.last_peer_set_id < Some(update.index) {
                    self.last_peer_set_id = Some(update.index);
                    self.fetcher.reconcile(update.latest.primary.as_ref());
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
                self.fetcher.fetch(&mut sender);
            },
            // Handle mailbox messages
            Some(msg) = self.mailbox.recv() else {
                error!("mailbox closed");
                return;
            } => {
                match msg {
                    Message::Fetch(requests) => {
                        for FetchRequest {
                            request,
                            subscribers,
                            targets,
                        } in requests
                        {
                            trace!(?request, "mailbox: fetch");
                            if subscribers.is_empty() {
                                trace!(?request, "fetch has no retained subscribers");
                                continue;
                            }

                            // Check if the fetch is already in progress
                            let is_new = !self.inflight.contains(&request);
                            let interests = self
                                .interests
                                .entry(request.clone())
                                .or_default();
                            interests.subscribers.extend(subscribers);

                            // Update targets
                            match targets {
                                Some(targets) => {
                                    // Only add targets if this is a new fetch OR the existing
                                    // fetch already has targets. Don't restrict an "all" fetch
                                    // (no targets) to specific targets.
                                    if is_new || self.fetcher.has_targets(&request) {
                                        self.fetcher.add_targets(request.clone(), targets);
                                    }
                                }
                                None => self.fetcher.clear_targets(&request),
                            }

                            // Only start new fetch if not already in progress
                            if is_new {
                                self.inflight.insert(
                                    request.clone(),
                                    self.metrics.fetch_duration.timer(self.context.as_ref()),
                                );
                                self.fetcher.add_ready(request);
                            } else {
                                trace!(?request, "updated targets for existing fetch");
                            }
                        }
                    }
                    Message::Cancel { subscriber } => {
                        trace!("mailbox: cancel");
                        let count = self.cancel_subscriber(&subscriber);
                        self.record_cancellations(count);
                    }
                    Message::Retain { predicate } => {
                        trace!("mailbox: retain");

                        self.interests.retain(|_, interests| {
                            interests
                                .subscribers
                                .retain(|subscriber| predicate(subscriber));
                            !interests.is_empty()
                        });
                        let interests = &self.interests;
                        self.fetcher.retain(|key| interests.contains_key(key));
                        let count =
                            self.inflight.retain(|key| interests.contains_key(key)) as u64;
                        self.record_cancellations(count);
                    }
                    Message::Clear => {
                        trace!("mailbox: clear");

                        self.interests.clear();
                        self.fetcher.clear();
                        let count = self.inflight.drain() as u64;
                        self.record_cancellations(count);
                    }
                }
            },
            // Handle completed consumer deliveries
            delivery = self.inflight.next_delivery() => {
                // If the delivery was aborted, its inflight entry was dropped (via
                // Cancel, Retain, Clear, or shutdown) before the consumer finished validating.
                let (peer, key, result) = match delivery {
                    Ok(delivery) => delivery,
                    Err(_) => continue,
                };
                self.handle_delivery(peer, key, result);
            },
            // Handle completed server requests
            serve = self.serves.next_completed() => {
                let Serve {
                    timer,
                    peer,
                    id,
                    result,
                } = serve;

                // Metrics and logs
                match result {
                    Ok(_) => {
                        timer.observe(self.context.as_ref());
                        self.metrics.serve.inc(Status::Success);
                    }
                    Err(ref err) => {
                        debug!(?err, ?peer, ?id, "serve failed");
                        self.metrics.serve.inc(Status::Failure);
                    }
                }

                // Send response to peer
                self.handle_serve(&mut sender, peer, id, result, self.priority_responses);
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
                    wire::Payload::Request(key) => self.handle_network_request(peer, msg.id, key),
                    wire::Payload::Response(response) => {
                        self.handle_network_response(peer, msg.id, response)
                    }
                    wire::Payload::Error => self.handle_network_error_response(peer, msg.id),
                };
            },
        }
    }

    /// Record cancellation metrics for a retain-style operation.
    fn record_cancellations(&mut self, count: u64) {
        if count == 0 {
            self.metrics.cancel.inc(Status::Dropped);
        } else {
            self.metrics.cancel.inc_by(Status::Success, count);
        }
    }

    /// Remove a subscriber from all fetches and cancel any requests that no longer
    /// have subscribers.
    fn cancel_subscriber(&mut self, subscriber: &Con::Subscriber) -> u64 {
        let mut requests = Vec::new();
        self.interests.retain(|request, interests| {
            interests.subscribers.remove(subscriber);
            if interests.is_empty() {
                requests.push(request.clone());
                false
            } else {
                true
            }
        });

        let mut count = 0;
        for request in requests {
            self.fetcher.cancel(&request);
            self.fetcher.clear_targets(&request);
            if self.inflight.cancel(&request) {
                count += 1;
            }
        }
        count
    }

    /// Handles the case where the application responds to a request from an external peer.
    fn handle_serve(
        &mut self,
        sender: &mut WrappedSender<NetS, wire::Message<Key>>,
        peer: P,
        id: u64,
        response: Result<Bytes, oneshot::error::RecvError>,
        priority: bool,
    ) {
        // Encode message
        let payload: wire::Payload<Key> = response.map_or_else(
            |_| wire::Payload::Error,
            |data| wire::Payload::Response(data),
        );
        let msg = wire::Message { id, payload };

        // Send message to peer
        let result = sender.send(Recipients::One(peer.clone()), msg, priority);

        // Log result, but do not handle errors.
        if result.is_empty() {
            warn!(?peer, ?id, "serve send failed");
        } else {
            trace!(?peer, ?id, "serve sent");
        };
    }

    /// Handle a network request from a peer.
    fn handle_network_request(&mut self, peer: P, id: u64, key: Key) {
        // Serve the request
        trace!(?peer, ?id, "peer request");
        let mut producer = self.producer.clone();
        let timer = self.metrics.serve_duration.timer(self.context.as_ref());
        let receiver = producer.produce(key);
        self.serves.push(async move {
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
    fn handle_network_response(&mut self, peer: P, id: u64, response: Bytes) {
        trace!(?peer, ?id, "peer response: data");

        // Get the key associated with the response, if any
        let Some(key) = self.fetcher.pop_by_id(id, &peer, true) else {
            // It's possible that the key does not exist if the request was canceled
            return;
        };

        let Some(interests) = self.interests.get(&key) else {
            warn!(?key, "response for fetch with no interests");
            self.inflight.cancel(&key);
            return;
        };
        if interests.is_empty() {
            warn!(?key, "response for fetch with no interests");
            self.inflight.cancel(&key);
            return;
        }
        let delivery = Delivery {
            request: key.clone(),
            subscribers: interests.subscribers.iter().cloned().collect(),
        };

        // The peer had the data, so deliver it to the consumer without blocking the engine.
        self.inflight.deliver(key, delivery, peer, response);
    }

    /// Handle completed delivery to the consumer.
    fn handle_delivery(&mut self, peer: P, key: Key, valid: bool) {
        if valid {
            self.metrics.fetch.inc(Status::Success);
            self.inflight.complete(&key, self.context.as_ref());
            self.interests.remove(&key);
            self.fetcher.clear_targets(&key);
            return;
        }

        // If the data is invalid, block the peer and try again. Blocking the
        // peer also removes any targets associated with it.
        commonware_p2p::block!(self.blocker, peer.clone(), "invalid data received");
        self.fetcher.block(peer);
        self.metrics.fetch.inc(Status::Failure);
        self.fetcher.add_retry(key);
    }

    /// Handle a network response from a peer that did not have the data.
    fn handle_network_error_response(&mut self, peer: P, id: u64) {
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

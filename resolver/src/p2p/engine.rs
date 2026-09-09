use super::{
    Producer,
    config::Config,
    fetcher::{Config as FetcherConfig, Fetcher},
    inflight::Inflight,
    ingress::{FetchKey, Mailbox, Message},
    metrics, wire,
};
use crate::{Consumer, Delivery, Outcome, subscribers};
use bytes::Bytes;
use commonware_actor::mailbox;
use commonware_cryptography::PublicKey;
use commonware_macros::select_loop;
use commonware_p2p::{
    Blocker, PeerSetUpdate, Provider, Receiver, Recipients, Sender,
    utils::codec::{WrappedSender, wrap},
};
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::metrics::{GaugeExt, histogram, status::Status},
};
use commonware_utils::{Span, channel::oneshot, futures::Pool as FuturesPool, ordered::Set};
use futures::{
    StreamExt,
    future::{self, Either},
};
use rand_core::Rng;
use std::marker::PhantomData;
use tracing::{debug, error, trace, warn};

#[derive(Clone, Copy)]
enum PeerSelection {
    LatestPrimary,
    AllTracked,
}

impl PeerSelection {
    fn select<P: PublicKey>(self, update: PeerSetUpdate<P>) -> Set<P> {
        match self {
            Self::LatestPrimary => update.latest.primary,
            Self::AllTracked => update.all.union(),
        }
    }
}

/// Represents a pending serve operation.
struct Serve<P: PublicKey> {
    timer: histogram::Timer,
    peer: P,
    id: u64,
    result: Result<Bytes, oneshot::error::RecvError>,
}

/// Manages incoming and outgoing P2P requests, coordinating fetch and serve operations.
pub struct Engine<E, P, D, B, Key, Con, Pro, NetS, NetR>
where
    E: BufferPooler + Clock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    Key: Span,
    Con: Consumer<Key = Key, Value = Bytes>,
    Pro: Producer<Key = Key>,
    NetS: Sender<PublicKey = P>,
    NetR: Receiver<PublicKey = P>,
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

    /// Mailbox that makes and prunes fetches
    mailbox: mailbox::Receiver<Message<Key, P, Con::Subscriber>>,

    /// Manages outgoing fetch requests
    fetcher: Fetcher<E, P, Key, NetS>,

    /// Tracks all in-flight fetch state
    inflight: Inflight<Con, P>,

    /// Subscribers that keep each fetch alive.
    subscribers: subscribers::Tracker<Key, Con::Subscriber>,

    /// Holds futures that resolve once the `Producer` has produced the data.
    /// Once the future is resolved, the data (or an error) is sent to the peer.
    /// Has unbounded size; the number of concurrent requests should be limited
    /// by the `Producer` which may drop requests.
    serves: FuturesPool<'static, Serve<P>>,

    /// Whether responses are sent with priority over other network messages
    priority_responses: bool,

    /// Peer-set view used for outgoing requests.
    peer_selection: PeerSelection,

    /// Metrics for the peer actor
    metrics: metrics::Metrics,

    /// Phantom data for networking types
    _r: PhantomData<NetR>,
}

impl<E, P, D, B, Key, Con, Pro, NetS, NetR> Engine<E, P, D, B, Key, Con, Pro, NetS, NetR>
where
    E: BufferPooler + Clock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    Key: Span,
    Con: Consumer<Key = Key, Value = Bytes>,
    Pro: Producer<Key = Key>,
    NetS: Sender<PublicKey = P>,
    NetR: Receiver<PublicKey = P>,
    Con::Subscriber: Clone + Ord + Send + 'static,
{
    /// Creates a new `Actor` with the given configuration.
    ///
    /// Returns the actor and a mailbox to send messages to it.
    pub fn new(
        context: E,
        cfg: Config<P, D, B, Key, Con, Pro>,
    ) -> (Self, Mailbox<Key, P, Con::Subscriber>) {
        Self::init(context, cfg, PeerSelection::LatestPrimary)
    }

    /// Creates an actor that may request from every peer in the retained peer-set history.
    ///
    /// This mode is intended for resolving historical data whose authoritative source may no
    /// longer belong to the latest primary peer set.
    pub fn new_with_all_peers(
        context: E,
        cfg: Config<P, D, B, Key, Con, Pro>,
    ) -> (Self, Mailbox<Key, P, Con::Subscriber>) {
        Self::init(context, cfg, PeerSelection::AllTracked)
    }

    fn init(
        context: E,
        cfg: Config<P, D, B, Key, Con, Pro>,
        peer_selection: PeerSelection,
    ) -> (Self, Mailbox<Key, P, Con::Subscriber>) {
        let (sender, receiver) = mailbox::new(context.child("mailbox"), cfg.mailbox_size);

        let metrics = metrics::Metrics::init(&context);
        let fetcher = Fetcher::new(
            context.child("fetcher"),
            FetcherConfig {
                me: cfg.me,
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
                subscribers: subscribers::Tracker::new(),
                serves: FuturesPool::default(),
                priority_responses: cfg.priority_responses,
                peer_selection,
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
        let mut peer_set_subscription = self.peer_provider.subscribe().await;
        let mut blocked_subscription = Some(self.blocker.blocked());

        select_loop! {
            self.context,
            on_start => {
                // Wait for the next blocked-set update, or forever once the
                // network stops publishing them.
                let blocked_update = blocked_subscription.as_mut().map_or_else(
                    || Either::Right(future::pending()),
                    |subscription| Either::Left(subscription.next()),
                );

                // Update metrics
                let _ = self
                    .metrics
                    .fetch_pending
                    .try_set(self.fetcher.len_pending());
                let _ = self.metrics.fetch_active.try_set(self.fetcher.len_active());
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
                self.subscribers.clear();
                self.serves.cancel_all();
            },
            // Handle peer set updates
            Some(update) = peer_set_subscription.recv() else {
                debug!("peer set subscription closed");
                return;
            } => {
                if self.last_peer_set_id < Some(update.index) {
                    self.last_peer_set_id = Some(update.index);
                    let peers = self.peer_selection.select(update);
                    self.fetcher.reconcile(peers.as_ref());
                }
            },
            // Handle blocked-set updates
            blocked = blocked_update => {
                match blocked {
                    Some(blocked) => self.fetcher.set_blocked(blocked),
                    None => {
                        debug!("blocked subscription closed");
                        blocked_subscription = None;
                    }
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
            // Handle completed consumer deliveries before accepting new work:
            // a fetch issued in reaction to a delivery's outcome must find the
            // completed key no longer in flight, not be deduplicated against
            // it and dropped when it completes.
            delivery = self.inflight.next_delivery() => {
                // If the delivery was aborted, its inflight entry was dropped (via
                // Retain or shutdown) before the consumer finished validating.
                if let Ok((peer, elapsed, bytes, delivery, result)) = delivery {
                    self.handle_delivery(peer, elapsed, bytes, delivery, result);
                }
            },
            // Handle mailbox messages
            Some(msg) = self.mailbox.recv() else {
                error!("mailbox closed");
                return;
            } => {
                match msg {
                    Message::Fetch(keys) => {
                        for FetchKey {
                            key,
                            subscribers,
                            metadata: targets,
                        } in keys
                        {
                            trace!(?key, "mailbox: fetch");

                            // Check if the fetch is already in progress
                            let is_new = !self.inflight.contains(&key);
                            self.subscribers.insert(key.clone(), subscribers);

                            // Update targets
                            match targets {
                                Some(targets) => {
                                    // Only add targets if this is a new fetch OR the existing
                                    // fetch already has targets. Don't restrict an "all" fetch
                                    // (no targets) to specific targets.
                                    if is_new || self.fetcher.has_targets(&key) {
                                        self.fetcher.add_targets(key.clone(), targets);
                                    }
                                }
                                None => self.fetcher.clear_targets(&key),
                            }

                            // Only start new fetch if not already in progress
                            if is_new {
                                self.inflight.insert(
                                    key.clone(),
                                    self.metrics.fetch_duration.timer(self.context.as_ref()),
                                );
                                self.fetcher.add_ready(key);
                            } else {
                                trace!(?key, "updated targets for existing fetch");
                            }
                        }
                    }
                    Message::Retain { predicate } => {
                        trace!("mailbox: retain");

                        self.subscribers
                            .retain(|key, subscriber| predicate(key, subscriber));
                        let subscribers = &self.subscribers;
                        self.fetcher.retain(|key| subscribers.contains(key));
                        let count = self.inflight.retain(|key| subscribers.contains(key)) as u64;
                        self.record_cancellations(count);
                    }
                }
            },
            // Wake the loop when pending work becomes ready. The send is
            // performed in `on_end` after the selected event is handled.
            _ = deadline_pending => {},
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

                match msg {
                    Ok(msg) => match msg.payload {
                        wire::Payload::Request(key) => {
                            self.handle_network_request(peer, msg.id, key)
                        }
                        wire::Payload::Response(response) => {
                            self.handle_network_response(peer, msg.id, response)
                        }
                        wire::Payload::Error => self.handle_network_error_response(peer, msg.id),
                    },
                    Err(err) => {
                        trace!(?err, ?peer, "decode failed");
                    }
                };
            },
            on_end => {
                // Attempt at most one due outbound request after each selected
                // event so sustained event traffic cannot starve pending work.
                if self
                    .fetcher
                    .get_pending_deadline()
                    .is_some_and(|deadline| deadline <= self.context.current())
                {
                    self.fetcher.fetch(&mut sender);
                }
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
        let Some((key, elapsed)) = self.fetcher.pop_response(id, &peer) else {
            // It's possible that the key does not exist if the request was pruned.
            return;
        };

        let Some(subscribers) = self.subscribers.pending(&key) else {
            warn!(?key, "response for fetch with no subscribers");
            self.inflight.cancel(&key);
            return;
        };
        let delivery = Delivery { key, subscribers };

        // The peer had the data, so deliver it to the consumer without blocking the engine.
        self.inflight.deliver(delivery, peer, elapsed, response);
    }

    /// Handle completed delivery to the consumer.
    fn handle_delivery(
        &mut self,
        peer: P,
        elapsed: std::time::Duration,
        bytes: usize,
        delivery: Delivery<Key, Con::Subscriber>,
        outcome: Option<Outcome>,
    ) {
        let Delivery {
            key,
            subscribers: delivered,
            ..
        } = delivery;
        let already_accepted = self.inflight.response_accepted(&key);

        // A dropped verdict says nothing about the response, only that the consumer
        // did not judge it for these subscribers. Hand the response to the
        // remaining subscribers, or retire the key when none remain.
        let Some(outcome) = outcome else {
            let remaining = self
                .subscribers
                .remove_delivered(&key, delivered.map_into(|(subscriber, _)| subscriber));
            if let Some(subscribers) = remaining {
                self.inflight.redeliver(Delivery { key, subscribers });
                return;
            }
            if !already_accepted {
                self.metrics.fetch.inc(Status::Dropped);
            }
            self.inflight.cancel(&key);
            self.fetcher.clear_targets(&key);
            return;
        };

        if !already_accepted && outcome != Outcome::Ignored {
            self.fetcher.record_response(&peer, elapsed, bytes);
        }

        match outcome {
            Outcome::Complete => {
                // Remove only the subscribers that accepted this response. If other
                // subscribers still need the key, deliver the same accepted response
                // locally with the remaining annotations.
                let remaining = self
                    .subscribers
                    .remove_delivered(&key, delivered.map_into(|(subscriber, _)| subscriber));

                if let Some(subscribers) = remaining {
                    if !already_accepted {
                        self.metrics.fetch.inc(Status::Success);
                        self.inflight.accept_response(&key, self.context.as_ref());
                    }
                    self.inflight.redeliver(Delivery { key, subscribers });
                } else {
                    // All subscribers observed a valid response; clear any targeting
                    // state retained for this key.
                    if !already_accepted {
                        self.metrics.fetch.inc(Status::Success);
                    }
                    self.inflight.complete(self.context.as_ref(), &key);
                    self.fetcher.clear_targets(&key);
                }
            }
            Outcome::Ambiguous => {
                // The peer served valid data for the wire key, but local
                // subscribers still need different evidence. Do not cache the
                // response or penalize the peer; retry the same key.
                self.metrics.fetch.inc(Status::Ambiguous);
                self.inflight.discard_response(&key);
                self.fetcher.add_retry(key);
            }
            Outcome::Invalid => {
                // A previously accepted response is only redelivered locally to subscribers that
                // joined while validation was pending. A later invalid outcome therefore reflects
                // conflicting consumer verdicts, not invalid peer data. Retire the fetch without
                // blocking the peer or retrying the accepted response.
                if already_accepted {
                    warn!(
                        ?key,
                        "previously accepted response was rejected during local redelivery"
                    );
                    self.metrics.fetch.inc(Status::Failure);
                    self.inflight.complete(self.context.as_ref(), &key);
                    self.subscribers.remove(&key);
                    self.fetcher.clear_targets(&key);
                    return;
                }

                // If the data is invalid, block the peer and try again. The network
                // reports the block through the blocked subscription, which is what
                // makes the peer ineligible until it is unblocked.
                commonware_p2p::block!(self.blocker, peer, "invalid data received");
                self.metrics.fetch.inc(Status::Failure);
                self.inflight.discard_response(&key);
                self.fetcher.add_retry(key);
            }
            Outcome::Ignored => {
                // The consumer no longer needs the key. Retire the entire fetch without
                // scoring or blocking the response's source.
                self.metrics.fetch.inc(Status::Dropped);
                self.inflight.cancel(&key);
                self.subscribers.remove(&key);
                self.fetcher.clear_targets(&key);
            }
        }
    }

    /// Handle a network response from a peer that did not have the data.
    fn handle_network_error_response(&mut self, peer: P, id: u64) {
        trace!(?peer, ?id, "peer response: error");

        // Get the key associated with the response, if any
        let Some(key) = self.fetcher.pop_missing(id, &peer) else {
            // It's possible that the key does not exist if the request was pruned.
            return;
        };

        // The peer did not have the data, so we need to try again
        self.metrics.fetch.inc(Status::Failure);
        self.fetcher.add_retry(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use commonware_p2p::TrackedPeers;

    #[test]
    fn peer_selection_can_include_retained_sets() {
        let current = PrivateKey::from_seed(0).public_key();
        let retained_primary = PrivateKey::from_seed(1).public_key();
        let retained_secondary = PrivateKey::from_seed(2).public_key();
        let update = PeerSetUpdate {
            index: 2,
            latest: TrackedPeers::primary(Set::from_iter_dedup([current.clone()])),
            all: TrackedPeers::new(
                Set::from_iter_dedup([current.clone(), retained_primary.clone()]),
                Set::from_iter_dedup([retained_secondary.clone()]),
            ),
        };

        assert_eq!(
            PeerSelection::LatestPrimary.select(update.clone()),
            Set::from_iter_dedup([current.clone()])
        );
        assert_eq!(
            PeerSelection::AllTracked.select(update),
            Set::from_iter_dedup([current, retained_primary, retained_secondary])
        );
    }
}

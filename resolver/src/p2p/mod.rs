//! Resolve data identified by a fixed-length key by using the P2P network.
//!
//! # Overview
//!
//! The `p2p` module enables resolving data by fixed-length keys in a P2P network. Central to the
//! module is the `peer` actor which manages the fetch lifecycle. Its mailbox allows
//! initiation and pruning of fetches via the `Resolver` interface.
//!
//! The peer handles an arbitrarily large number of concurrent fetches by sending requests to other
//! peers and processing their responses. It selects peers based on performance, retrying if a
//! request fails or provides invalid data. Blocked peers are learned from the network through
//! [`Blocker::blocked`](commonware_p2p::Blocker::blocked), so a peer becomes eligible again when
//! its block expires. Fetches persist until pruned, fulfilled, or reported as no longer needed by
//! the `Consumer`.
//!
//! The `Consumer` returns a [`crate::Outcome`], checking data integrity and authenticity unless it
//! no longer needs the key. A [`Resolved`](crate::Outcome::Resolved) outcome retires its delivered
//! subscribers when all are satisfied, and otherwise retries without penalizing the peer. An
//! invalid response retries after blocking the peer, and an ignored response retires the key
//! without scoring its peer. A verdict the consumer drops without answering hands the response
//! to the remaining subscribers, or retires the key when none remain. Pruning a fetch with
//! in-progress response validation aborts that validation. An invalid outcome produced after
//! cancellation does not block the peer.
//!
//! The peer also serves data to other peers, forwarding network requests to the `Producer`. The
//! `Producer` provides data asynchronously (e.g., from storage). If it fails, the peer sends an
//! error response, prompting the requester to retry. Each message between peers contains an ID.
//! Each request is sent with a unique ID, and each response includes the ID of the request it
//! responds to.
//!
//! # Targeting
//!
//! Callers can restrict fetches to specific target peers using
//! [`TargetedResolver::fetch_targeted`](crate::TargetedResolver::fetch_targeted).
//! Only target peers are tried, there is no automatic fallback to other peers. Targets persist through
//! transient failures (timeout, "no data" response, send failure) since the peer might be slow or
//! receive the data later.
//!
//! While a fetch is in progress, callers can modify targeting:
//! - [`TargetedResolver::fetch_targeted`](crate::TargetedResolver::fetch_targeted) adds peers to the existing target set
//!   (only if the fetch already has targets, an "all" fetch remains unrestricted)
//! - [`Resolver::fetch`](crate::Resolver::fetch) clears targeting so any peer of the latest peer
//!   set can serve it
//!
//! These modifications only apply to in-progress fetches. Once a fetch succeeds, is pruned, or is
//! ignored by the consumer, the targets for that key are cleared automatically. A blocked peer is
//! skipped until the network unblocks it, so a fetch whose every target is blocked stays
//! outstanding and resumes when one of them is unblocked, new targets are added, or targeting is
//! cleared.
//!
//! # Subscribers
//!
//! [`Resolver::fetch`](crate::Resolver::fetch) accepts a peer-visible key and a
//! subscriber. This is useful when several subscribers can share the same peer-visible
//! fetch. A fetch remains active while at least one attached subscriber satisfies the latest
//! [`Resolver::retain`](crate::Resolver::retain) predicate. When the fetch resolves, the
//! key and currently retained subscribers are supplied to
//! [`Consumer::deliver`](crate::Consumer::deliver). Subscribers added while response validation
//! is in progress are delivered the same response locally, once it is accepted or when the
//! consumer drops its verdict without judging it.
//!
//! While a response is being validated, its key remains in flight, so no further request is sent.
//! New fetches for the key only attach subscribers or targets. Consumers return
//! [`Resolved`](crate::Outcome::Resolved) with [`All`](crate::Resolution::All) when the response
//! satisfies every delivered subscriber. When a peer-visible key admits multiple valid responses,
//! report [`Some`](crate::Resolution::Some) if this response satisfied at least one previously
//! unresolved delivered subscriber but leaves others unresolved, or
//! [`None`](crate::Resolution::None) if none became satisfied. Both keep the key active so the
//! resolver can try another response.
//!
//! Retire satisfied subscribers with [`Resolver::retain`](crate::Resolver::retain).
//! The resolver cannot infer resolution from subscriber removals because cancellation and
//! unrelated progress can also remove subscribers. Credit follows the delivered subscriber
//! snapshot, so progress for a subscriber that joins during validation may go uncredited.
//!
//! # Mechanism
//!
//! All pending fresh keys are attempted before any pending retries. Fresh keys and retries are
//! each ordered by their next attempt time.
//!
//! ## Peer Selection
//!
//! Inbound requests are served for every connected peer, but fetches go only to peers in the latest
//! peer set from the [`Provider`](commonware_p2p::Provider). A fetch without targets may use any
//! peer of that set, primary or secondary. A fetch with targets uses only its targets in that set
//! and skips any target outside it until a later set includes it. The local peer and blocked
//! peers are excluded from selection.
//!
//! Each draw chooses between sampling proportionally to peer weights and sampling uniformly.
//! The initial request has retry count `r = 0`. Each dispatched attempt that leaves the fetch
//! unresolved increments `r`, shifting selection toward uniform sampling:
//!
//! ```text
//!                             +---------------+
//!         1 / (r + 1) +------>| weighted draw |---+
//!                     |       +---------------+   |
//! eligible peers -----+                           +--> try to send
//!                     |       +---------------+   |
//!         r / (r + 1) +------>| uniform draw  |---+
//!                             +---------------+
//! ```
//!
//! The initial request is entirely weighted. The first, second, and third retries use uniform
//! sampling with probability `1/2`, `2/3`, and `3/4`, respectively. As retries accumulate, the
//! uniform share gives peers with low weights more opportunities to serve data. Across attempts,
//! sampling is with replacement: any eligible peer can be chosen again, including after a
//! transient failure.
//!
//! To dispatch a request for one key, the resolver tries each eligible peer at most once.
//! Rate-limit skips and locally rejected or closed sends continue with the remaining peers,
//! without changing scores or `r`. These temporary exclusions end when a send succeeds or every
//! eligible peer has been tried.
//!
//! Tracking a peer does not guarantee a connection. Sends to disconnected peers may be accepted
//! locally and time out before a retry is scheduled.
//!
//! ## Peer Scores
//!
//! A peer's weight estimates how many useful payload bytes it serves per charged second.
//! A response earns credit when a consumer first reports [`Resolved`](crate::Outcome::Resolved)
//! with [`All`](crate::Resolution::All) or [`Some`](crate::Resolution::Some). It contributes its
//! payload size and the time from sending the request to receiving the response, once per network
//! response, even when that response is delivered to several subscribers.
//! [`None`](crate::Resolution::None) leaves the peer's averages unchanged, as do ignored responses
//! and dropped verdicts.
//!
//! A timeout or missing-data reply contributes zero bytes and charges the full [`Config::timeout`].
//! This charge also applies to immediate missing-data replies, so fast failures cannot improve a
//! peer's weight.
//!
//! These observations update separate averages: `B` for payload bytes and `T` for charged seconds.
//!
//! ```text
//! Useful response ----> (payload bytes, response time) ----+
//!                                                          |
//!                                                          +--> (B, T) --> floor(B / T) + 1
//!                                                          |
//! Timeout / no data --> (0, configured request timeout) ---+
//! ```
//!
//! The first observation initializes both averages. Each later observation receives half the
//! weight in each average, with byte averages rounded down to `2^-32` bytes and time averages to
//! nanoseconds. Every charged duration is at least one nanosecond, and the resulting peer weight
//! saturates at `u64::MAX`. New and rejoining peers start at weight one.
//!
//! An [`Invalid`](crate::Outcome::Invalid) verdict on a response that has not already earned
//! credit requests a network block without recording a score observation. Blocking retains a
//! tracked peer's averages. When it is unblocked, selection uses its current score.
//!
//! ## Failures and Recovery
//!
//! Timeouts and missing-data replies halve the byte average while moving the time average
//! halfway toward the full timeout charge. The configured request timeout stays fixed. Let `B`
//! and `T` be the averages before a sequence of failures, and `D` the timeout charge in seconds.
//! Ignoring rounding, `k` consecutive failures give the following byte-rate estimate:
//!
//! ```text
//! rate = B / (T + (2^k - 1) * D)
//! ```
//!
//! Old byte credit decays exponentially with consecutive failures. A long history of successful
//! requests does not accumulate an unbounded reserve. For example, a peer averaging 1,000,000
//! bytes in 100 milliseconds, with a two-second timeout, has these estimated rates:
//!
//! | Consecutive failures | Approximate byte rate |
//! |----------------------|-----------------------|
//! | 0                    | 10 MB/s               |
//! | 1                    | 476 kB/s              |
//! | 2                    | 164 kB/s              |
//! | 3                    | 71 kB/s               |
//!
//! Averages only change when an observation arrives, so waiting alone cannot improve a score.
//! Weights reflect the sizes of previously served values as well as peer performance. Uniform
//! retries give peers with low weights opportunities to serve useful responses and recover.
//!
//! Peer scores are shared across keys, while each key has its own retry count. When a previously
//! useful peer stops serving data, failures reduce its shared byte average while each unresolved
//! key increasingly samples peers uniformly. The peer can still have the highest weight when
//! alternatives have no history, or sustain a high weight by selectively serving other keys.
//! Fresh keys start with a weighted draw, so one failure does not guarantee immediate demotion.
//! Requests already sent keep their original deadlines.
//!
//! # Message Sizes
//!
//! ```text
//! Request (tag 0):
//! +--------+---------+-------------------+
//! | id (8) | tag (1) | key (encoded Key) |
//! +--------+---------+-------------------+
//!
//! Response (tag 1):
//! +--------+---------+----------------------+----------------------+
//! | id (8) | tag (1) | length (varint, 1-5) | value (length bytes) |
//! +--------+---------+----------------------+----------------------+
//!
//! Error (tag 2):
//! +--------+---------+
//! | id (8) | tag (1) |
//! +--------+---------+
//! ```
//!
//! A response carries the `Producer`'s value in one message and echoes the request's `id`. A
//! request adds [`REQUEST_OVERHEAD`] bytes to its key, an error is exactly that size, and a
//! response adds at most [`MAX_RESPONSE_OVERHEAD`] bytes to its value. [`max_message_size`] returns
//! a bound on all three for a key type and largest value. Every message must fit the network's
//! payload limit, less the subchannel prefix on a [Muxer](commonware_p2p::utils::mux::Muxer)
//! subchannel.
//!
//! # Performance Considerations
//!
//! The peer supports arbitrarily many concurrent fetches, but resource usage generally
//! depends on the rate-limiting configuration of the underlying P2P network.

use bytes::Bytes;
use commonware_utils::{Span, channel::oneshot};

mod config;
pub use config::Config;
mod engine;
pub use engine::Engine;
mod fetcher;
mod inflight;
mod ingress;
pub use ingress::Mailbox;
mod metrics;
mod score;
mod wire;
pub use wire::{MAX_RESPONSE_OVERHEAD, REQUEST_OVERHEAD, max_message_size};

#[cfg(feature = "mocks")]
pub mod mocks;

/// Serves data requested by the network.
pub trait Producer: Clone + Send + 'static {
    /// Type used to key data requested from peers.
    type Key: Span;

    /// Serve a request received from the network.
    fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes>;
}

#[cfg(test)]
mod tests {
    use super::{
        Config, Engine, Mailbox,
        mocks::{Consumer, Key, Producer},
    };
    use crate::{Delivery, Fetch, Outcome, Resolution, Resolver, TargetedResolver};
    use bytes::Bytes;
    use commonware_cryptography::{
        Signer,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::{
        Blocker, Manager as _, Provider, TrackedPeers,
        simulated::{Link, Network, Oracle, Receiver, Sender},
    };
    use commonware_runtime::{
        Clock, Metrics as _, Quota, Runner, Spawner as _, Supervisor as _, deterministic,
        telemetry::metrics::count_running_tasks,
    };
    use commonware_utils::{
        NZU32, NZUsize,
        channel::{
            fallible::{FallibleExt, OneshotExt},
            mpsc, oneshot,
        },
        non_empty_vec,
        ordered::Set,
        probability,
        sync::Mutex,
    };
    use std::{
        collections::{HashMap, VecDeque},
        num::{NonZeroU32, NonZeroUsize},
        sync::Arc,
        time::Duration,
    };

    const MAILBOX_SIZE: NonZeroUsize = NZUsize!(1024);
    const RATE_LIMIT: NonZeroU32 = NZU32!(10);
    const TIMEOUT: Duration = Duration::from_millis(400);
    const FETCH_RETRY_TIMEOUT: Duration = Duration::from_millis(100);
    const LINK: Link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: probability!(1.0),
    };
    const LINK_UNRELIABLE: Link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: probability!(0.5),
    };

    fn status_metric_total(metrics: &str, name: &str, status: &str) -> u64 {
        let prefix = format!("{name}{{");
        let status_label = format!("status=\"{status}\"");
        metrics
            .lines()
            .filter(|line| line.starts_with(&prefix) && line.contains(&status_label))
            .map(|line| {
                line.split_whitespace()
                    .next_back()
                    .expect("metric line must have a value")
                    .parse::<u64>()
                    .expect("status metric value must be an integer")
            })
            .sum()
    }

    fn peer_resolve_count(metrics: &str) -> u64 {
        metrics
            .lines()
            .filter(|line| line.starts_with("actor_fetcher_resolves_count"))
            .map(|line| {
                line.split_whitespace()
                    .next_back()
                    .expect("metric line must have a value")
                    .parse::<u64>()
                    .expect("metric count must be an integer")
            })
            .sum()
    }

    fn peer_weight(metrics: &str) -> u64 {
        metrics
            .lines()
            .find(|line| line.starts_with("actor_fetcher_peer_performance{"))
            .expect("peer performance metric must be exported")
            .split_whitespace()
            .next_back()
            .unwrap()
            .parse()
            .unwrap()
    }

    async fn setup_network_and_peers(
        context: &deterministic::Context,
        peer_seeds: &[u64],
    ) -> (
        Oracle<PublicKey, deterministic::Context>,
        Vec<PrivateKey>,
        Vec<PublicKey>,
        Vec<(
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        )>,
    ) {
        setup_network_and_peers_with_rate_limit(context, peer_seeds, Quota::per_second(RATE_LIMIT))
            .await
    }

    async fn setup_network_and_peers_with_rate_limit(
        context: &deterministic::Context,
        peer_seeds: &[u64],
        rate_limit: Quota,
    ) -> (
        Oracle<PublicKey, deterministic::Context>,
        Vec<PrivateKey>,
        Vec<PublicKey>,
        Vec<(
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        )>,
    ) {
        let (network, oracle) = Network::new(
            context.child("network"),
            commonware_p2p::simulated::Config {
                max_size: 1024 * 1024,
                max_peers_per_set: NZUsize!(peer_seeds.len()),
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(3),
            },
        );
        network.start();

        let schemes: Vec<PrivateKey> = peer_seeds
            .iter()
            .map(|seed| PrivateKey::from_seed(*seed))
            .collect();
        let peers: Vec<PublicKey> = schemes.iter().map(|s| s.public_key()).collect();
        let mut manager = oracle.manager();
        manager.track(0, Set::try_from(peers.clone()).unwrap());

        let mut connections = Vec::new();
        for peer in &peers {
            let (sender, receiver) = oracle
                .control(peer.clone())
                .register(0, rate_limit)
                .await
                .unwrap();
            connections.push((sender, receiver));
        }

        (oracle, schemes, peers, connections)
    }

    async fn add_link(
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        link: Link,
        peers: &[PublicKey],
        from: usize,
        to: usize,
    ) {
        oracle
            .add_link(peers[from].clone(), peers[to].clone(), link.clone())
            .await
            .unwrap();
        oracle
            .add_link(peers[to].clone(), peers[from].clone(), link)
            .await
            .unwrap();
    }

    #[derive(Clone, Default)]
    struct SequencedProducer {
        data: Arc<Mutex<HashMap<Key, VecDeque<Bytes>>>>,
    }

    impl SequencedProducer {
        fn insert(&mut self, key: Key, values: impl IntoIterator<Item = Bytes>) {
            self.data.lock().insert(key, values.into_iter().collect());
        }

        fn remaining(&self, key: &Key) -> Vec<Bytes> {
            self.data
                .lock()
                .get(key)
                .map(|values| values.iter().cloned().collect())
                .unwrap_or_default()
        }
    }

    impl crate::p2p::Producer for SequencedProducer {
        type Key = Key;

        fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
            let (sender, receiver) = oneshot::channel();
            if let Some(value) = self.data.lock().get_mut(&key).and_then(VecDeque::pop_front) {
                let _ = sender.send(value);
            }
            receiver
        }
    }

    fn setup_and_spawn_actor<C, R>(
        context: &deterministic::Context,
        provider: impl Provider<PublicKey = PublicKey>,
        blocker: impl Blocker<PublicKey = PublicKey>,
        signer: impl Signer<PublicKey = PublicKey>,
        connection: (
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        ),
        consumer: C,
        producer: Producer<Key, Bytes>,
    ) -> Mailbox<Key, PublicKey, R>
    where
        C: crate::Consumer<Key = Key, Subscriber = R, Value = Bytes>,
        R: Clone + Ord + Send + 'static,
    {
        setup_and_spawn_actor_with_producer(
            context, provider, blocker, signer, connection, consumer, producer,
        )
    }

    fn setup_and_spawn_actor_with_producer<C, R, Pro>(
        context: &deterministic::Context,
        provider: impl Provider<PublicKey = PublicKey>,
        blocker: impl Blocker<PublicKey = PublicKey>,
        signer: impl Signer<PublicKey = PublicKey>,
        connection: (
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        ),
        consumer: C,
        producer: Pro,
    ) -> Mailbox<Key, PublicKey, R>
    where
        C: crate::Consumer<Key = Key, Subscriber = R, Value = Bytes>,
        Pro: crate::p2p::Producer<Key = Key>,
        R: Clone + Ord + Send + 'static,
    {
        let public_key = signer.public_key();
        let (engine, mailbox) = Engine::new(
            context.child("actor").with_attribute("peer", &public_key),
            Config {
                peer_provider: provider,
                blocker,
                consumer,
                producer,
                mailbox_size: MAILBOX_SIZE,
                me: Some(public_key),
                timeout: TIMEOUT,
                fetch_retry_timeout: FETCH_RETRY_TIMEOUT,
                priority_requests: false,
                priority_responses: false,
            },
        );
        engine.start(connection);

        mailbox
    }

    type DeliveryGate = (oneshot::Receiver<()>, Outcome);
    type DeliveryGates = Arc<Mutex<VecDeque<DeliveryGate>>>;

    #[derive(Clone)]
    struct BlockingConsumer {
        context: Arc<deterministic::Context>,
        sender: mpsc::UnboundedSender<(Key, Bytes)>,
        started: mpsc::UnboundedSender<Key>,
        gates: DeliveryGates,
    }

    impl BlockingConsumer {
        fn new(
            context: deterministic::Context,
            gates: Vec<DeliveryGate>,
        ) -> (
            Self,
            mpsc::UnboundedReceiver<(Key, Bytes)>,
            mpsc::UnboundedReceiver<Key>,
        ) {
            let (sender, receiver) = mpsc::unbounded_channel();
            let (started, started_receiver) = mpsc::unbounded_channel();
            (
                Self {
                    context: Arc::new(context),
                    sender,
                    started,
                    gates: Arc::new(Mutex::new(gates.into())),
                },
                receiver,
                started_receiver,
            )
        }
    }

    impl crate::Consumer for BlockingConsumer {
        type Key = Key;
        type Value = Bytes;
        type Subscriber = ();
        type Outcome = Outcome;

        fn deliver(
            &mut self,
            delivery: Delivery<Self::Key, Self::Subscriber>,
            value: Self::Value,
        ) -> oneshot::Receiver<Self::Outcome> {
            let key = delivery.key;
            self.started.send_lossy(key.clone());
            let (gate, outcome) = self.gates.lock().pop_front().map_or(
                (None, Outcome::Resolved(Resolution::All)),
                |(gate, outcome)| (Some(gate), outcome),
            );
            let (mut response, receiver) = oneshot::channel();
            let sender = self.sender.clone();
            self.context.child("delivery").spawn(move |_| async move {
                if let Some(gate) = gate {
                    select! {
                        _ = response.closed() => return,
                        result = gate => {
                            if result.is_err() {
                                let _ = response.send(Outcome::Invalid);
                                return;
                            }
                        },
                    }
                }
                if outcome == Outcome::Resolved(Resolution::All) {
                    sender.send_lossy((key, value));
                }
                let _ = response.send(outcome);
            });
            receiver
        }
    }

    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    struct SubscriberTag(u16);

    type RecordedDelivery = (Delivery<Key, SubscriberTag>, Bytes);

    #[derive(Clone)]
    struct BlockingSubscriberRecordingConsumer {
        context: Arc<deterministic::Context>,
        sender: mpsc::UnboundedSender<RecordedDelivery>,
        started: mpsc::UnboundedSender<Delivery<Key, SubscriberTag>>,
        gates: DeliveryGates,
    }

    impl BlockingSubscriberRecordingConsumer {
        fn new(
            context: deterministic::Context,
            gates: Vec<DeliveryGate>,
        ) -> (
            Self,
            mpsc::UnboundedReceiver<RecordedDelivery>,
            mpsc::UnboundedReceiver<Delivery<Key, SubscriberTag>>,
        ) {
            let (sender, receiver) = mpsc::unbounded_channel();
            let (started, started_receiver) = mpsc::unbounded_channel();
            (
                Self {
                    context: Arc::new(context),
                    sender,
                    started,
                    gates: Arc::new(Mutex::new(gates.into())),
                },
                receiver,
                started_receiver,
            )
        }
    }

    impl crate::Consumer for BlockingSubscriberRecordingConsumer {
        type Key = Key;
        type Value = Bytes;
        type Subscriber = SubscriberTag;
        type Outcome = Outcome;

        fn deliver(
            &mut self,
            delivery: Delivery<Self::Key, Self::Subscriber>,
            value: Self::Value,
        ) -> oneshot::Receiver<Self::Outcome> {
            self.started.send_lossy(delivery.clone());
            let (gate, outcome) = self.gates.lock().pop_front().map_or(
                (None, Outcome::Resolved(Resolution::All)),
                |(gate, outcome)| (Some(gate), outcome),
            );
            let (mut response, receiver) = oneshot::channel();
            let sender = self.sender.clone();
            self.context.child("delivery").spawn(move |_| async move {
                if let Some(gate) = gate {
                    select! {
                        _ = response.closed() => return,
                        result = gate => {
                            if result.is_err() {
                                let _ = response.send(Outcome::Invalid);
                                return;
                            }
                        },
                    }
                }
                if outcome == Outcome::Resolved(Resolution::All) {
                    sender.send_lossy((delivery, value));
                }
                let _ = response.send(outcome);
            });
            receiver
        }
    }

    #[derive(Clone)]
    struct SubscriberRecordingConsumer {
        sender: mpsc::UnboundedSender<RecordedDelivery>,
    }

    impl SubscriberRecordingConsumer {
        fn new() -> (Self, mpsc::UnboundedReceiver<RecordedDelivery>) {
            let (sender, receiver) = mpsc::unbounded_channel();
            (Self { sender }, receiver)
        }
    }

    impl crate::Consumer for SubscriberRecordingConsumer {
        type Key = Key;
        type Value = Bytes;
        type Subscriber = SubscriberTag;
        type Outcome = bool;

        fn deliver(
            &mut self,
            delivery: Delivery<Self::Key, Self::Subscriber>,
            value: Self::Value,
        ) -> oneshot::Receiver<bool> {
            let (sender, receiver) = oneshot::channel();
            self.sender.send_lossy((delivery, value));
            let _ = sender.send(true);
            receiver
        }
    }

    fn dummy_consumer() -> Consumer<Key, Bytes> {
        Consumer::dummy()
    }

    fn consumer() -> (Consumer<Key, Bytes>, mpsc::UnboundedReceiver<(Key, Bytes)>) {
        Consumer::new()
    }

    async fn wait_for_blocked(
        context: &deterministic::Context,
        oracle: &Oracle<PublicKey, deterministic::Context>,
        blocker: &PublicKey,
        blocked: &PublicKey,
    ) {
        loop {
            let blocked_peers = oracle.blocked().await.unwrap();
            if blocked_peers
                .iter()
                .any(|(a, b)| a == blocker && b == blocked)
            {
                return;
            }
            context.sleep(Duration::from_millis(10)).await;
        }
    }

    /// Tests that fetching a key from another peer succeeds when data is available.
    /// This test sets up two peers, where Peer 1 requests data that Peer 2 has,
    /// and verifies that the data is correctly delivered to Peer 1's consumer.
    #[test_traced]
    fn test_fetch_success() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(2);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 2"));

            let (cons1, mut cons_out1) = consumer();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            mailbox1.fetch(key.clone());

            let (key_actual, value) = cons_out1.recv().await.unwrap();
            assert_eq!(key_actual, key);
            assert_eq!(value, Bytes::from("data for key 2"));
        });
    }

    /// A consumer that hands each delivery's response sender to the test,
    /// letting it resolve verdicts synchronously (without a task yield).
    #[derive(Clone)]
    struct HoldingConsumer {
        deliveries: mpsc::UnboundedSender<(Key, oneshot::Sender<Outcome>)>,
    }

    impl HoldingConsumer {
        fn new() -> (
            Self,
            mpsc::UnboundedReceiver<(Key, oneshot::Sender<Outcome>)>,
        ) {
            let (deliveries, receiver) = mpsc::unbounded_channel();
            (Self { deliveries }, receiver)
        }
    }

    impl crate::Consumer for HoldingConsumer {
        type Key = Key;
        type Value = Bytes;
        type Subscriber = ();
        type Outcome = Outcome;

        fn deliver(
            &mut self,
            delivery: Delivery<Self::Key, Self::Subscriber>,
            _: Self::Value,
        ) -> oneshot::Receiver<Outcome> {
            let (sender, receiver) = oneshot::channel();
            self.deliveries.send_lossy((delivery.key, sender));
            receiver
        }
    }

    type HeldDelivery = (
        Delivery<Key, SubscriberTag>,
        Bytes,
        oneshot::Sender<Outcome>,
    );

    /// A consumer that hands each delivery, its value, and its response sender
    /// to the test, keeping the delivered subscribers visible.
    #[derive(Clone)]
    struct HoldingSubscriberConsumer {
        deliveries: mpsc::UnboundedSender<HeldDelivery>,
    }

    impl HoldingSubscriberConsumer {
        fn new() -> (Self, mpsc::UnboundedReceiver<HeldDelivery>) {
            let (deliveries, receiver) = mpsc::unbounded_channel();
            (Self { deliveries }, receiver)
        }
    }

    impl crate::Consumer for HoldingSubscriberConsumer {
        type Key = Key;
        type Value = Bytes;
        type Subscriber = SubscriberTag;
        type Outcome = Outcome;

        fn deliver(
            &mut self,
            delivery: Delivery<Self::Key, Self::Subscriber>,
            value: Self::Value,
        ) -> oneshot::Receiver<Outcome> {
            let (sender, receiver) = oneshot::channel();
            self.deliveries.send_lossy((delivery, value, sender));
            receiver
        }
    }

    #[test_traced]
    fn test_fetch_after_accepted_verdict_restarts() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(2);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 2"));

            let (cons1, mut deliveries) = HoldingConsumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            mailbox1.fetch(key.clone());
            let (first, verdict) = deliveries.recv().await.unwrap();
            assert_eq!(first, key);

            // Accept the response and re-fetch the key before yielding: both
            // the completion and the fetch are pending when the engine next
            // runs, and it must settle the completion first so the re-fetch
            // starts fresh instead of being deduplicated against the
            // completing key and dropped with it.
            verdict.send_lossy(Outcome::Resolved(Resolution::All));
            mailbox1.fetch(key.clone());

            select! {
                delivered = deliveries.recv() => {
                    let (second, verdict) = delivered.unwrap();
                    assert_eq!(second, key);
                    verdict.send_lossy(Outcome::Resolved(Resolution::All));
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("re-fetch was dropped with the completed fetch");
                },
            }
        });
    }

    #[test_traced]
    fn test_pending_delivery_does_not_block_engine() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;

            let key1 = Key(1);
            let key2 = Key(2);
            let data1 = Bytes::from("data for key 1");
            let data2 = Bytes::from("data for key 2");

            let mut prod2 = Producer::default();
            prod2.insert(key1.clone(), data1.clone());

            let mut prod3 = Producer::default();
            prod3.insert(key2.clone(), data2.clone());

            let (gate_sender1, gate_receiver1) = oneshot::channel();
            let (gate_sender2, gate_receiver2) = oneshot::channel();
            let (cons1, mut cons_out1, mut started) = BlockingConsumer::new(
                context.child("consumer"),
                vec![
                    (gate_receiver1, Outcome::Resolved(Resolution::All)),
                    (gate_receiver2, Outcome::Resolved(Resolution::All)),
                ],
            );

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod3,
            );

            mailbox1.fetch(key1.clone());
            let started_key = started.recv().await.expect("delivery did not start");
            assert_eq!(started_key, key1);

            mailbox1.fetch(key2.clone());
            select! {
                started_key = started.recv() => {
                    assert_eq!(started_key.expect("delivery did not start"), key2);
                },
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("resolver engine blocked on pending delivery");
                },
            };

            gate_sender2.send(()).unwrap();
            let (key_actual, value) = cons_out1.recv().await.expect("consumer channel closed");
            assert_eq!(key_actual, key2);
            assert_eq!(value, data2);

            gate_sender1.send(()).unwrap();
            let (key_actual, value) = cons_out1.recv().await.expect("consumer channel closed");
            assert_eq!(key_actual, key1);
            assert_eq!(value, data1);
        });
    }

    #[test_traced]
    fn test_retain_drops_pending_delivery() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(1);
            let data = Bytes::from("data for key 1");
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), data.clone());

            let (mut first_gate_sender, first_gate_receiver) = oneshot::channel();
            let (second_gate_sender, second_gate_receiver) = oneshot::channel();
            let (cons1, mut cons_out1, mut started) = BlockingConsumer::new(
                context.child("consumer"),
                vec![
                    (first_gate_receiver, Outcome::Resolved(Resolution::All)),
                    (second_gate_receiver, Outcome::Resolved(Resolution::All)),
                ],
            );

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            mailbox1.fetch(key.clone());
            let started_key = started.recv().await.expect("delivery did not start");
            assert_eq!(started_key, key);

            let canceled = key.clone();
            mailbox1.retain(move |key, _| key != &canceled);
            mailbox1.fetch(key.clone());

            first_gate_sender.closed().await;
            let started_key = started.recv().await.expect("second delivery did not start");
            assert_eq!(started_key, key);

            second_gate_sender.send(()).unwrap();
            let (key_actual, value) = cons_out1.recv().await.expect("consumer channel closed");
            assert_eq!(key_actual, key);
            assert_eq!(value, data);

            select! {
                _ = cons_out1.recv() => panic!("unexpected extra event"),
                _ = context.sleep(Duration::from_millis(100)) => {},
            };
        });
    }

    #[test_traced]
    fn test_larger_responses_earn_more_throughput_credit() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;
            let link = Link {
                jitter: Duration::ZERO,
                ..LINK.clone()
            };
            add_link(&mut oracle, link, &peers, 0, 1).await;

            // Both requests cross the same link. Only the amount of accepted data changes.
            let responses = [
                (Key(1), Bytes::from(vec![1; 1])),
                (Key(2), Bytes::from(vec![2; 1024])),
            ];
            let mut producer = Producer::default();
            let (mut consumer, mut deliveries) = Consumer::<Key, Bytes>::new();
            for (key, value) in &responses {
                producer.insert(key.clone(), value.clone());
                consumer.add_expected(key.clone(), value.clone());
            }

            let scheme = schemes.remove(0);
            let mut mailbox = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                consumer,
                Producer::default(),
            );
            let scheme = schemes.remove(0);
            let _server = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                producer,
            );

            let mut weights = Vec::new();
            for (index, (key, value)) in responses.into_iter().enumerate() {
                mailbox.fetch(key.clone());
                assert_eq!(deliveries.recv().await.unwrap(), (key, value));

                // Delivery starts before its verdict is processed. Read the weight only
                // after the engine has credited the accepted network response.
                loop {
                    let metrics = context.encode();
                    if peer_resolve_count(&metrics) == index as u64 + 1 {
                        weights.push(peer_weight(&metrics));
                        break;
                    }
                    context.sleep(Duration::from_millis(1)).await;
                }
            }

            assert!(weights[1] > weights[0] * 100, "{weights:?}");
        });
    }

    #[test_traced]
    fn test_invalid_delivery_retries_and_rearms_slot() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(1);
            let data = Bytes::from("data for key 1");

            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), data.clone());

            let mut prod3 = Producer::default();
            prod3.insert(key.clone(), data.clone());

            let (first_gate_sender, first_gate_receiver) = oneshot::channel();
            let (second_gate_sender, second_gate_receiver) = oneshot::channel();
            let (cons1, mut cons_out1, mut started) = BlockingConsumer::new(
                context.child("consumer"),
                vec![
                    (first_gate_receiver, Outcome::Invalid),
                    (second_gate_receiver, Outcome::Resolved(Resolution::All)),
                ],
            );

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod3,
            );

            mailbox1.fetch_targeted(
                key.clone(),
                non_empty_vec![peers[1].clone(), peers[2].clone()],
            );
            let started_key = started.recv().await.expect("delivery did not start");
            assert_eq!(started_key, key);

            first_gate_sender.send(()).unwrap();
            wait_for_blocked(&context, &oracle, &peers[0], &peers[1]).await;
            assert_eq!(peer_resolve_count(&context.encode()), 0);

            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;
            oracle.manager().track(
                1,
                Set::try_from([peers[0].clone(), peers[2].clone()]).unwrap(),
            );

            let started_key = started.recv().await.expect("retry delivery did not start");
            assert_eq!(started_key, key);

            second_gate_sender.send(()).unwrap();
            let (key_actual, value) = cons_out1.recv().await.expect("consumer channel closed");
            assert_eq!(key_actual, key);
            assert_eq!(value, data);
        });
    }

    #[test_traced]
    fn test_delivery_credits_only_useful_responses() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;
            let link = Link {
                jitter: Duration::ZERO,
                ..LINK.clone()
            };
            add_link(&mut oracle, link, &peers, 0, 1).await;

            let warmup = Key(0);
            let key = Key(1);
            let data = Bytes::from(vec![1; 1024]);
            let mut producer = Producer::default();
            producer.insert(warmup.clone(), Bytes::from_static(&[0]));
            producer.insert(key.clone(), data.clone());
            let (consumer, mut deliveries) = HoldingSubscriberConsumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                consumer,
                Producer::default(),
            );
            let scheme = schemes.remove(0);
            let _server = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                producer,
            );

            // Establish a weight above the minimum so both rewards and penalties are visible.
            mailbox.fetch(Fetch {
                key: warmup.clone(),
                subscriber: SubscriberTag(0),
                span: tracing::Span::none(),
            });
            let (delivery, _, verdict) = deliveries.recv().await.unwrap();
            assert_eq!(delivery.key, warmup);
            verdict.send(Outcome::Resolved(Resolution::All)).unwrap();
            while peer_resolve_count(&context.encode()) != 1 {
                context.sleep(Duration::from_millis(1)).await;
            }
            let original_weight = peer_weight(&context.encode());
            assert!(original_weight > 1);

            let first = SubscriberTag(1);
            let second = SubscriberTag(2);
            mailbox.fetch_all(
                [first.clone(), second.clone()]
                    .into_iter()
                    .map(|subscriber| Fetch {
                        key: key.clone(),
                        subscriber,
                        span: tracing::Span::none(),
                    })
                    .collect(),
            );
            let expected = Delivery {
                key: key.clone(),
                subscribers: non_empty_vec![
                    (first.clone(), tracing::Span::none()),
                    (second.clone(), tracing::Span::none()),
                ],
            };
            let (delivery, value, verdict) = deliveries.recv().await.unwrap();
            assert_eq!(delivery, expected);
            assert_eq!(value, data);
            verdict.send(Outcome::Resolved(Resolution::None)).unwrap();

            // A new network delivery proves the neutral verdict was processed and retried.
            let (delivery, value, verdict) = deliveries.recv().await.unwrap();
            assert_eq!(delivery, expected);
            assert_eq!(value, data);
            let metrics = context.encode();
            assert_eq!(peer_resolve_count(&metrics), 1);
            assert_eq!(peer_weight(&metrics), original_weight);

            // Only one subscriber is satisfied. The other still needs another response.
            mailbox.retain(move |_, subscriber| subscriber != &first);
            verdict.send(Outcome::Resolved(Resolution::Some)).unwrap();
            let (delivery, value, verdict) = deliveries.recv().await.unwrap();
            assert_eq!(
                delivery,
                Delivery {
                    key,
                    subscribers: non_empty_vec![(second, tracing::Span::none())],
                }
            );
            assert_eq!(value, data);
            let metrics = context.encode();
            assert_eq!(peer_resolve_count(&metrics), 2);
            assert!(peer_weight(&metrics) > original_weight);

            verdict.send(Outcome::Resolved(Resolution::All)).unwrap();
            while peer_resolve_count(&context.encode()) != 3 {
                context.sleep(Duration::from_millis(1)).await;
            }
            assert!(oracle.blocked().await.unwrap().is_empty());
            let metrics = context.encode();
            assert_eq!(
                status_metric_total(&metrics, "actor_fetch_total", "Ambiguous"),
                2
            );
        });
    }

    #[test_traced]
    fn test_dropped_verdict_retires_fetch_without_blocking_peer() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(1);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 1"));

            let (cons1, mut deliveries) = HoldingConsumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            mailbox1.fetch(key.clone());
            let (delivered, verdict) = deliveries.recv().await.unwrap();
            assert_eq!(delivered, key);

            // Drop the verdict, as a consumer does when it stops with the
            // delivery still queued. No one is waiting on the key, so the fetch
            // is retired rather than retried, and the peer stays unblocked
            // because nothing is known about what it served.
            drop(verdict);
            select! {
                _ = deliveries.recv() => panic!("retired fetch must not be retried"),
                _ = context.sleep(Duration::from_secs(1)) => {},
            };
            assert!(oracle.blocked().await.unwrap().is_empty());
            assert_eq!(peer_resolve_count(&context.encode()), 0);

            // The retired key is not deduplicated against, so a fresh fetch runs.
            mailbox1.fetch(key.clone());
            let (delivered, verdict) = deliveries.recv().await.unwrap();
            assert_eq!(delivered, key);
            verdict.send_lossy(Outcome::Resolved(Resolution::All));

            let metrics = context.encode();
            assert_eq!(
                status_metric_total(&metrics, "actor_fetch_total", "Dropped"),
                1
            );
        });
    }

    #[test_traced]
    fn test_dropped_verdict_hands_response_to_late_subscriber() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(1);
            let data = Bytes::from("data for key 1");
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), data.clone());

            let (cons1, mut deliveries) = HoldingSubscriberConsumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            let first = SubscriberTag(1);
            let late = SubscriberTag(2);
            mailbox1.fetch(Fetch {
                key: key.clone(),
                subscriber: first.clone(),
                span: tracing::Span::none(),
            });
            let (delivery, value, verdict) = deliveries.recv().await.unwrap();
            assert_eq!(
                delivery,
                Delivery {
                    key: key.clone(),
                    subscribers: non_empty_vec![(first, tracing::Span::none())],
                }
            );
            assert_eq!(value, data);

            // A late subscriber joins while the first delivery is unjudged, then
            // that delivery's verdict is dropped. The late subscriber is handed
            // the same response to judge instead of the key being retired.
            mailbox1.fetch(Fetch {
                key: key.clone(),
                subscriber: late.clone(),
                span: tracing::Span::none(),
            });
            context.sleep(Duration::from_millis(100)).await;
            drop(verdict);
            let (delivery, value, verdict) = deliveries.recv().await.unwrap();
            assert_eq!(
                delivery,
                Delivery {
                    key,
                    subscribers: non_empty_vec![(late, tracing::Span::none())],
                }
            );
            assert_eq!(value, data);
            assert_eq!(peer_resolve_count(&context.encode()), 0);
            verdict.send_lossy(Outcome::Resolved(Resolution::All));

            context.sleep(Duration::from_millis(100)).await;
            assert!(oracle.blocked().await.unwrap().is_empty());
            let metrics = context.encode();
            assert_eq!(peer_resolve_count(&metrics), 1);
            assert_eq!(
                status_metric_total(&metrics, "actor_fetch_total", "Success"),
                1
            );
            assert_eq!(
                status_metric_total(&metrics, "actor_fetch_total", "Dropped"),
                0
            );
        });
    }

    #[test_traced]
    fn test_ignored_delivery_retires_late_subscribers_without_rating_or_retry() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(1);
            let first = Bytes::from("obsolete response");
            let second = Bytes::from("fresh response");
            let mut producer = SequencedProducer::default();
            producer.insert(key.clone(), [first, second.clone()]);
            let producer_observer = producer.clone();

            let (gate_sender, gate_receiver) = oneshot::channel();
            let (consumer, mut deliveries, mut started) = BlockingSubscriberRecordingConsumer::new(
                context.child("consumer"),
                vec![(gate_receiver, Outcome::Ignored)],
            );

            let scheme = schemes.remove(0);
            let mut mailbox = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                consumer,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _responder = setup_and_spawn_actor_with_producer(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                producer,
            );

            let first_subscriber = SubscriberTag(1);
            let late_subscriber = SubscriberTag(2);
            let fresh_subscriber = SubscriberTag(3);
            mailbox.fetch(Fetch {
                key: key.clone(),
                subscriber: first_subscriber.clone(),
                span: tracing::Span::none(),
            });
            assert_eq!(
                started.recv().await.expect("delivery did not start"),
                Delivery {
                    key: key.clone(),
                    subscribers: non_empty_vec![(first_subscriber, tracing::Span::none())],
                }
            );

            // A subscriber attached after the delivery snapshot is still retired by
            // the key-global ignored outcome.
            mailbox.fetch(Fetch {
                key: key.clone(),
                subscriber: late_subscriber,
                span: tracing::Span::none(),
            });
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(producer_observer.remaining(&key), vec![second.clone()]);
            gate_sender.send(()).expect("consumer gate dropped");

            context
                .sleep(FETCH_RETRY_TIMEOUT + Duration::from_millis(100))
                .await;
            assert_eq!(producer_observer.remaining(&key), vec![second.clone()]);
            assert!(oracle.blocked().await.unwrap().is_empty());

            let metrics = context.encode();
            assert_eq!(
                status_metric_total(&metrics, "actor_fetch_total", "Dropped"),
                1
            );
            assert_eq!(peer_resolve_count(&metrics), 0);

            // A new request for the same key starts cleanly after the ignored fetch is retired.
            mailbox.fetch(Fetch {
                key: key.clone(),
                subscriber: fresh_subscriber.clone(),
                span: tracing::Span::none(),
            });
            assert_eq!(
                started.recv().await.expect("fresh delivery did not start"),
                Delivery {
                    key: key.clone(),
                    subscribers: non_empty_vec![(fresh_subscriber.clone(), tracing::Span::none())],
                }
            );
            assert_eq!(
                deliveries.recv().await.expect("consumer channel closed"),
                (
                    Delivery {
                        key: key.clone(),
                        subscribers: non_empty_vec![(fresh_subscriber, tracing::Span::none())],
                    },
                    second
                )
            );
            assert!(producer_observer.remaining(&key).is_empty());
        });
    }

    async fn run_pending_invalid_delivery_race(
        context: &deterministic::Context,
        validation_first: bool,
    ) {
        let (mut oracle, mut schemes, peers, mut connections) =
            setup_network_and_peers(context, &[1, 2]).await;

        add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

        let key = Key(1);
        let mut prod2 = Producer::default();
        prod2.insert(key.clone(), Bytes::from("data for key 1"));

        let (mut gate_sender, gate_receiver) = oneshot::channel();
        let (cons1, mut cons_out1, mut started) = BlockingConsumer::new(
            context.child("consumer"),
            vec![(gate_receiver, Outcome::Invalid)],
        );

        let scheme = schemes.remove(0);
        let mut mailbox1 = setup_and_spawn_actor(
            context,
            oracle.manager(),
            oracle.control(scheme.public_key()),
            scheme,
            connections.remove(0),
            cons1,
            Producer::default(),
        );

        let scheme = schemes.remove(0);
        let _mailbox2 = setup_and_spawn_actor(
            context,
            oracle.manager(),
            oracle.control(scheme.public_key()),
            scheme,
            connections.remove(0),
            dummy_consumer(),
            prod2,
        );

        mailbox1.fetch(key.clone());
        let started_key = started.recv().await.expect("delivery did not start");
        assert_eq!(started_key, key);

        if validation_first {
            gate_sender.send(()).unwrap();
            wait_for_blocked(context, &oracle, &peers[0], &peers[1]).await;
            mailbox1.retain(|_, _| false);
            let blocked = oracle.blocked().await.unwrap();
            assert_eq!(blocked.len(), 1);
            assert_eq!(blocked[0].0, peers[0]);
            assert_eq!(blocked[0].1, peers[1]);
        } else {
            mailbox1.retain(|_, _| false);
            gate_sender.closed().await;
            assert!(oracle.blocked().await.unwrap().is_empty());
        }

        select! {
            _ = cons_out1.recv() => panic!("unexpected event"),
            _ = context.sleep(Duration::from_millis(100)) => {},
        };
        assert_eq!(peer_resolve_count(&context.encode()), 0);
    }

    #[test_traced]
    fn test_retain_pending_invalid_delivery_race() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            run_pending_invalid_delivery_race(&context, false).await;
            run_pending_invalid_delivery_race(&context, true).await;
        });
    }

    /// Tests that pruning a fetch leaves the consumer untouched.
    /// This test initiates a fetch and immediately prunes it, verifying
    /// that the consumer does not receive any event.
    #[test_traced]
    fn test_retain_drops_fetch() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (oracle, mut schemes, _peers, mut connections) =
                setup_network_and_peers(&context, &[1]).await;

            let (cons1, mut cons_out1) = consumer();
            let prod1 = Producer::default();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                prod1,
            );

            let key = Key(3);
            mailbox1.fetch(key.clone());
            let canceled = key.clone();
            mailbox1.retain(move |key, _| key != &canceled);

            select! {
                _ = cons_out1.recv() => panic!("unexpected event"),
                _ = context.sleep(Duration::from_millis(100)) => {},
            };
        });
    }

    /// Tests fetching data from a peer when some peers lack the data.
    /// This test sets up three peers, where Peer 1 requests data that only Peer 3 has.
    /// It verifies that the resolver retries with another peer and successfully
    /// delivers the data to Peer 1's consumer.
    #[test_traced]
    fn test_peer_no_data() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;

            let prod1 = Producer::default();
            let prod2 = Producer::default();
            let mut prod3 = Producer::default();
            let key = Key(3);
            prod3.insert(key.clone(), Bytes::from("data for key 3"));

            let (cons1, mut cons_out1) = consumer();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                prod1,
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod3,
            );

            mailbox1.fetch(key.clone());

            let (key_actual, value) = cons_out1.recv().await.unwrap();
            assert_eq!(key_actual, key);
            assert_eq!(value, Bytes::from("data for key 3"));
        });
    }

    /// Tests fetching when no peers are available.
    /// This test sets up a single peer with an empty peer provider (no peers).
    /// It initiates a fetch, waits beyond the retry timeout, prunes the fetch,
    /// and verifies that the consumer receives a failure notification.
    #[test_traced]
    fn test_no_peers_available() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (oracle, mut schemes, _peers, mut connections) =
                setup_network_and_peers(&context, &[1]).await;

            let (cons1, mut cons_out1) = consumer();
            let prod1 = Producer::default();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                prod1,
            );

            mailbox1.fetch(Key(4));
            context.sleep(Duration::from_secs(5)).await;

            // With no peers, no event should arrive
            select! {
                _ = cons_out1.recv() => panic!("Fetch should have failed due to no peers"),
                _ = context.sleep(Duration::from_millis(100)) => {},
            };
        });
    }

    /// Tests that fetches issued before the first peer set arrives stay pending and complete once
    /// the initial update is tracked.
    #[test_traced]
    fn test_fetch_before_initial_peer_set_waits_for_update() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.child("network"),
                commonware_p2p::simulated::Config {
                    max_size: 1024 * 1024,
                    max_peers_per_set: NZUsize!(2),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let mut schemes = [1_u64, 2]
                .into_iter()
                .map(PrivateKey::from_seed)
                .collect::<Vec<_>>();
            schemes.sort_by_key(|s| s.public_key());
            let peers: Vec<PublicKey> = schemes.iter().map(|s| s.public_key()).collect();

            let mut connections = Vec::new();
            for peer in &peers {
                let (sender, receiver) = oracle
                    .control(peer.clone())
                    .register(0, Quota::per_second(RATE_LIMIT))
                    .await
                    .unwrap();
                connections.push((sender, receiver));
            }

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(2);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 2"));

            let (cons1, mut cons_out1) = consumer();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            mailbox1.fetch(key.clone());

            select! {
                event = cons_out1.recv() => {
                    panic!("fetch should wait for the initial peer set, got {event:?}");
                },
                _ = context.sleep(Duration::from_millis(200)) => {},
            };

            oracle
                .manager()
                .track(0, Set::try_from(peers.clone()).unwrap());

            let (key_actual, value) = cons_out1.recv().await.unwrap();
            assert_eq!(key_actual, key);
            assert_eq!(value, Bytes::from("data for key 2"));
        });
    }

    /// Tests that concurrent fetches are handled correctly.
    /// Also tests that the peer can recover from having no peers available.
    /// Also tests that the peer can get data from multiple peers that have different sets of data.
    #[test_traced]
    fn test_concurrent_fetch_requests() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3]).await;

            let key2 = Key(2);
            let key3 = Key(3);
            let mut prod2 = Producer::default();
            prod2.insert(key2.clone(), Bytes::from("data for key 2"));
            let mut prod3 = Producer::default();
            prod3.insert(key3.clone(), Bytes::from("data for key 3"));

            let (cons1, mut cons_out1) = consumer();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod3,
            );

            // Add choppy links between the requester and the two producers
            add_link(&mut oracle, LINK_UNRELIABLE.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK_UNRELIABLE.clone(), &peers, 0, 2).await;

            // Run the fetches multiple times to ensure that the peer tries both of its peers
            for _ in 0..10 {
                // Initiate concurrent fetches.
                mailbox1.fetch(key2.clone());
                mailbox1.fetch(key3.clone());

                // Collect both events without assuming order
                let mut events = Vec::new();
                events.push(cons_out1.recv().await.expect("Consumer channel closed"));
                events.push(cons_out1.recv().await.expect("Consumer channel closed"));

                // Check that both keys were successfully fetched
                let mut found_key2 = false;
                let mut found_key3 = false;
                for (key_actual, value) in events {
                    if key_actual == key2 {
                        assert_eq!(value, Bytes::from("data for key 2"));
                        found_key2 = true;
                    } else if key_actual == key3 {
                        assert_eq!(value, Bytes::from("data for key 3"));
                        found_key3 = true;
                    } else {
                        panic!("Unexpected key received");
                    }
                }
                assert!(found_key2 && found_key3,);
            }
        });
    }

    /// Tests that pruning an inactive fetch has no effect.
    /// Prunes a key before, after, and during the fetch process.
    #[test_traced]
    fn test_retain_drops_key() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(6);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 6"));

            let (cons1, mut cons_out1) = consumer();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            // Prune before sending the fetch, expecting no effect.
            let canceled = key.clone();
            mailbox1.retain(move |key, _| key != &canceled);
            select! {
                _ = cons_out1.recv() => {
                    panic!("unexpected event");
                },
                _ = context.sleep(Duration::from_millis(100)) => {},
            };

            // Initiate fetch and wait for data to be delivered
            mailbox1.fetch(key.clone());
            let (key_actual, value) = cons_out1.recv().await.unwrap();
            assert_eq!(key_actual, key);
            assert_eq!(value, Bytes::from("data for key 6"));

            // Attempt to prune after data has been delivered, expecting no effect
            let canceled = key.clone();
            mailbox1.retain(move |key, _| key != &canceled);
            select! {
                _ = cons_out1.recv() => {
                    panic!("unexpected event");
                },
                _ = context.sleep(Duration::from_millis(100)) => {},
            };

            // Initiate and prune another fetch.
            let key = Key(7);
            mailbox1.fetch(key.clone());
            let canceled = key.clone();
            mailbox1.retain(move |key, _| key != &canceled);

            // No event should arrive after pruning.
            select! {
                _ = cons_out1.recv() => panic!("unexpected event"),
                _ = context.sleep(Duration::from_millis(100)) => {},
            };
        });
    }

    /// Tests that a peer is blocked after delivering invalid data,
    /// preventing further fetches from that peer.
    #[test_traced]
    fn test_blocking_peer() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;
            add_link(&mut oracle, LINK.clone(), &peers, 1, 2).await;

            let key_a = Key(1);
            let key_b = Key(2);
            let invalid_data_a = Bytes::from("invalid for A");
            let valid_data_a = Bytes::from("valid for A");
            let valid_data_b = Bytes::from("valid for B");

            // Set up producers
            let mut prod2 = Producer::default();
            prod2.insert(key_a.clone(), invalid_data_a.clone());
            prod2.insert(key_b.clone(), valid_data_b.clone());

            let mut prod3 = Producer::default();
            prod3.insert(key_a.clone(), valid_data_a.clone());

            // Set up consumer for Peer1 with expected values
            let (mut cons1, mut cons_out1) = consumer();
            cons1.add_expected(key_a.clone(), valid_data_a.clone());
            cons1.add_expected(key_b.clone(), valid_data_b.clone());

            // Spawn actors
            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod3,
            );

            // Fetch keyA multiple times to ensure that Peer2 is blocked.
            for _ in 0..20 {
                // Fetch keyA
                mailbox1.fetch(key_a.clone());

                // Wait for success event for keyA
                let (key_actual, value) = cons_out1.recv().await.unwrap();
                assert_eq!(key_actual, key_a);
                assert_eq!(value, valid_data_a);
            }

            // Fetch keyB
            mailbox1.fetch(key_b.clone());

            // Wait for some time (longer than retry timeout)
            context.sleep(Duration::from_secs(5)).await;

            // No success event should be received for keyB since the only peer with valid data is blocked
            select! {
                _ = cons_out1.recv() => panic!("unexpected event"),
                _ = context.sleep(Duration::from_millis(100)) => {},
            };

            // Prune the fetch for keyB.
            let canceled = key_b.clone();
            mailbox1.retain(move |key, _| key != &canceled);

            // Check oracle
            let blocked = oracle.blocked().await.unwrap();
            assert_eq!(blocked.len(), 1);
            assert_eq!(blocked[0].0, peers[0]);
            assert_eq!(blocked[0].1, peers[1]);
        });
    }

    /// Tests that duplicate fetches for the same key are handled properly.
    /// The test verifies that when the same key is fetched multiple times,
    /// the data is correctly delivered once without errors.
    #[test_traced]
    fn test_duplicate_fetch_key() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(5);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 5"));

            let (cons1, mut cons_out1) = consumer();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            // Send duplicate fetches for the same key.
            mailbox1.fetch(key.clone());
            mailbox1.fetch(key.clone());

            // Should receive the data only once
            let (key_actual, value) = cons_out1.recv().await.unwrap();
            assert_eq!(key_actual, key);
            assert_eq!(value, Bytes::from("data for key 5"));

            // Make sure we don't receive a second event for the duplicate fetch
            select! {
                _ = cons_out1.recv() => {
                    panic!("Unexpected second event received for duplicate fetch");
                },
                _ = context.sleep(Duration::from_millis(500)) => {
                    // No additional events should be produced
                },
            };
        });
    }

    /// Tests that changing peer sets is handled correctly using the update channel.
    /// This test verifies that when the peer set changes from peer A to peer B,
    /// the resolver correctly adapts and fetches from the new peer.
    #[test_traced]
    fn test_changing_peer_sets() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;

            let key1 = Key(1);
            let key2 = Key(2);

            let mut prod2 = Producer::default();
            prod2.insert(key1.clone(), Bytes::from("data from peer 2"));

            let mut prod3 = Producer::default();
            prod3.insert(key2.clone(), Bytes::from("data from peer 3"));

            let (cons1, mut cons_out1) = consumer();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            // Fetch key1 from peer 2
            mailbox1.fetch(key1.clone());

            // Wait for successful fetch
            let (key_actual, value) = cons_out1.recv().await.unwrap();
            assert_eq!(key_actual, key1);
            assert_eq!(value, Bytes::from("data from peer 2"));

            // Change peer set to include peer 3
            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod3,
            );

            // Need to wait for the peer set change to propagate
            context.sleep(Duration::from_millis(200)).await;

            // Fetch key2 from peer 3
            mailbox1.fetch(key2.clone());

            // Wait for successful fetch
            let (key_actual, value) = cons_out1.recv().await.unwrap();
            assert_eq!(key_actual, key2);
            assert_eq!(value, Bytes::from("data from peer 3"));
        });
    }

    #[test_traced]
    fn test_fetch_targeted() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Keep both servers reachable so the healthy non-target could answer any fallback.
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;

            // The target serves invalid data, while the non-target holds a valid copy.
            let key = Key(1);
            let invalid_data = Bytes::from("invalid data");
            let valid_data = Bytes::from("valid data");

            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), invalid_data.clone());

            let mut prod3 = Producer::default();
            prod3.insert(key.clone(), valid_data.clone());

            // Reject the target's response before delivering a result to the caller.
            let (mut cons1, mut cons_out1) = consumer();
            cons1.add_expected(key.clone(), valid_data.clone());

            // Start the requester and both servers before issuing the restricted fetch.
            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod3,
            );

            // Wait for peer-set subscriptions to initialize.
            context.sleep(Duration::from_millis(100)).await;

            // Target only peer 2 and wait for its invalid response to get it blocked.
            mailbox1.fetch_targeted(key.clone(), non_empty_vec![peers[1].clone()]);
            loop {
                let blocked = oracle.blocked().await.unwrap();
                if !blocked.is_empty() {
                    assert_eq!(blocked.len(), 1);
                    assert_eq!(blocked[0].0, peers[0]);
                    assert_eq!(blocked[0].1, peers[1]);
                    break;
                }
                context.sleep(Duration::from_millis(10)).await;
            }

            // Keep the targets fixed through several retry periods. The healthy non-target
            // must remain unused while the only target is blocked.
            select! {
                event = cons_out1.recv() => {
                    panic!("fetch must remain restricted to its blocked target: {event:?}");
                },
                _ = context.sleep(Duration::from_secs(1)) => {},
            };
            assert_eq!(
                status_metric_total(&context.encode(), "actor_fetch_total", "Success"),
                0
            );

            // Adding peer 3 as a target lets the fetch succeed.
            mailbox1.fetch_targeted(key.clone(), non_empty_vec![peers[2].clone()]);
            let (key_actual, value) = cons_out1.recv().await.unwrap();
            assert_eq!(key_actual, key);
            assert_eq!(value, valid_data);

            // The caller's target update must produce exactly one successful fetch.
            let metrics = context.encode();
            assert_eq!(
                status_metric_total(&metrics, "actor_fetch_total", "Success"),
                1
            );
        });
    }

    /// A blocker whose blocked-set subscription closes immediately, as test
    /// mocks elsewhere in the workspace do.
    #[derive(Clone)]
    struct ClosedBlocker;

    impl Blocker for ClosedBlocker {
        type PublicKey = PublicKey;

        fn block(&mut self, _peer: Self::PublicKey) -> commonware_actor::Feedback {
            commonware_actor::Feedback::Ok
        }

        fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
            let (_, receiver) = commonware_utils::channel::ring::channel(NZUsize!(1));
            receiver
        }
    }

    #[test_traced]
    fn test_closed_blocked_subscription_keeps_fetching() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(1);
            let data = Bytes::from("data for key 1");
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), data.clone());

            let (cons1, mut cons_out1) = consumer();

            // The engine keeps serving fetches when the blocked-set stream ends.
            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                ClosedBlocker,
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            mailbox1.fetch(key.clone());
            assert_eq!(cons_out1.recv().await.unwrap(), (key, data));
        });
    }

    #[test_traced]
    fn test_unblocked_peer_becomes_eligible_again() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(1);
            let data = Bytes::from("data for key 1");
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), data.clone());

            // The first response is judged invalid, the second one is accepted.
            let (first_gate_sender, first_gate_receiver) = oneshot::channel();
            let (second_gate_sender, second_gate_receiver) = oneshot::channel();
            let (cons1, mut cons_out1, mut started) = BlockingConsumer::new(
                context.child("consumer"),
                vec![
                    (first_gate_receiver, Outcome::Invalid),
                    (second_gate_receiver, Outcome::Resolved(Resolution::All)),
                ],
            );

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            mailbox1.fetch_targeted(key.clone(), non_empty_vec![peers[1].clone()]);
            assert_eq!(started.recv().await.unwrap(), key);
            first_gate_sender.send(()).unwrap();
            wait_for_blocked(&context, &oracle, &peers[0], &peers[1]).await;

            // The only target is blocked, so the fetch waits.
            select! {
                _ = started.recv() => panic!("blocked target was retried"),
                _ = context.sleep(Duration::from_secs(1)) => {},
            };

            // Once the network lifts the block, the same target is tried again.
            oracle
                .unblock(peers[0].clone(), peers[1].clone())
                .await
                .unwrap();
            assert_eq!(started.recv().await.unwrap(), key);
            second_gate_sender.send(()).unwrap();
            assert_eq!(cons_out1.recv().await.unwrap(), (key, data));
        });
    }

    #[test_traced]
    fn test_fetch_targeted_no_fallback() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3, 4]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 3).await;

            let key = Key(1);

            // Only peer 4 has the data, peers 2 and 3 don't
            let mut prod4 = Producer::default();
            prod4.insert(key.clone(), Bytes::from("data from peer 4"));

            let (cons1, mut cons_out1) = consumer();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                Producer::default(), // no data
            );

            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                Producer::default(), // no data
            );

            let scheme = schemes.remove(0);
            let _mailbox4 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod4,
            );

            // Wait for peer set to be established
            context.sleep(Duration::from_millis(100)).await;

            // Start a fetch targeting peers 2 and 3, neither of which has the data.
            // Peer 4 has the data but is not a target, so it should never be tried.
            mailbox1.fetch_targeted(
                key.clone(),
                non_empty_vec![peers[1].clone(), peers[2].clone()],
            );

            // Wait enough time for targets to fail and retry multiple times
            // The fetch should not succeed because peer 4 (which has data) is not targeted
            select! {
                event = cons_out1.recv() => {
                    panic!("Fetch should not succeed, but got: {event:?}");
                },
                _ = context.sleep(Duration::from_secs(3)) => {
                    // Expected: no success event because peer 4 is not targeted
                },
            };
        });
    }

    #[test_traced]
    fn test_fetch_all_targeted() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3, 4]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 3).await;

            let key1 = Key(1);
            let key2 = Key(2);
            let key3 = Key(3);

            // Peer 2 has key1
            let mut prod2 = Producer::default();
            prod2.insert(key1.clone(), Bytes::from("data for key 1"));

            // Peer 3 has key3
            let mut prod3 = Producer::default();
            prod3.insert(key3.clone(), Bytes::from("data for key 3"));

            // Peer 4 has key2
            let mut prod4 = Producer::default();
            prod4.insert(key2.clone(), Bytes::from("data for key 2"));

            // Consumer expects all three keys
            let (mut cons1, mut cons_out1) = consumer();
            cons1.add_expected(key1.clone(), Bytes::from("data for key 1"));
            cons1.add_expected(key2.clone(), Bytes::from("data for key 2"));
            cons1.add_expected(key3.clone(), Bytes::from("data for key 3"));

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod3,
            );

            let scheme = schemes.remove(0);
            let _mailbox4 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod4,
            );

            // Wait for peer set to be established
            context.sleep(Duration::from_millis(100)).await;

            // Fetch keys with mixed targeting:
            // - key1 targeted to peer 2 (has data) -> should succeed from target
            // - key2 targeted to peer 4 (has data) -> should succeed from target
            // - key3 no targeting -> fetched from any peer (peer 3 has it)
            mailbox1.fetch_all_targeted(vec![
                (key1.clone(), non_empty_vec![peers[1].clone()]), // peer 2 has key1
                (key2.clone(), non_empty_vec![peers[3].clone()]), // peer 4 has key2
            ]);
            mailbox1.fetch(key3.clone()); // no targeting for key3

            // Collect all three events
            let mut results = HashMap::new();
            for _ in 0..3 {
                let (key, value) = cons_out1.recv().await.unwrap();
                results.insert(key, value);
            }

            // Verify all keys received correct data
            assert_eq!(results.len(), 3);
            assert_eq!(results.get(&key1).unwrap(), &Bytes::from("data for key 1"));
            assert_eq!(results.get(&key2).unwrap(), &Bytes::from("data for key 2"));
            assert_eq!(results.get(&key3).unwrap(), &Bytes::from("data for key 3"));

            // Verify metrics: 3 successful fetches
            let metrics = context.encode();
            assert_eq!(
                status_metric_total(&metrics, "actor_fetch_total", "Success"),
                3
            );
        });
    }

    /// Tests that calling fetch() on an in-progress targeted fetch clears the targets,
    /// allowing the fetch to succeed from any available peer.
    #[test_traced]
    fn test_fetch_clears_targets() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;

            let key = Key(1);
            let valid_data = Bytes::from("valid data");

            // Peer 2 has no data, peer 3 has the data
            let mut prod3 = Producer::default();
            prod3.insert(key.clone(), valid_data.clone());

            let (cons1, mut cons_out1) = consumer();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                Producer::default(), // no data
            );

            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod3,
            );

            // Wait for peer set to be established
            context.sleep(Duration::from_millis(100)).await;

            // Start fetch with target for peer 2 only (who doesn't have data)
            mailbox1.fetch_targeted(key.clone(), non_empty_vec![peers[1].clone()]);

            // Wait for the targeted fetch to fail a few times
            context.sleep(Duration::from_millis(500)).await;

            // Call fetch() which should clear the targets and allow fallback to any peer
            mailbox1.fetch(key.clone());

            // Should now succeed from peer 3 (who has data but wasn't originally targeted)
            let (key_actual, value) = cons_out1.recv().await.unwrap();
            assert_eq!(key_actual, key);
            assert_eq!(value, valid_data);
        });
    }

    #[test_traced]
    fn test_fetch_targeted_does_not_restrict_all() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;

            let key = Key(1);
            let valid_data = Bytes::from("valid data");

            // Peer 2 has no data, peer 3 has the data
            let mut prod3 = Producer::default();
            prod3.insert(key.clone(), valid_data.clone());

            let (cons1, mut cons_out1) = consumer();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                Producer::default(), // no data
            );

            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod3,
            );

            // Wait for peer set to be established
            context.sleep(Duration::from_millis(100)).await;

            // Start fetch without targets (can try any peer)
            mailbox1.fetch(key.clone());

            // Wait a bit for the fetch to start
            context.sleep(Duration::from_millis(50)).await;

            // Call fetch_targeted with peer 2 only (who doesn't have data)
            // This should NOT restrict the existing "all" fetch
            mailbox1.fetch_targeted(key.clone(), non_empty_vec![peers[1].clone()]);

            // Should still succeed from peer 3 (who has data but wasn't in the targeted call)
            // because the original fetch was "all" and shouldn't be restricted
            let (key_actual, value) = cons_out1.recv().await.unwrap();
            assert_eq!(key_actual, key);
            assert_eq!(value, valid_data);
        });
    }

    #[test_traced]
    fn test_retain() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            let key = Key(5);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 5"));

            let (cons1, mut cons_out1) = consumer();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            // Retain before fetching should have no effect
            mailbox1.retain(|_, _| true);
            select! {
                _ = cons_out1.recv() => {
                    panic!("unexpected event");
                },
                _ = context.sleep(Duration::from_millis(100)) => {},
            };

            // Start a fetch (no link, so fetch stays in-flight)
            mailbox1.fetch(key.clone());

            // Retain with predicate that excludes the key. This must clean up
            // the in-flight entry for the key.
            let key_clone = key.clone();
            mailbox1.retain(move |key, _| key != &key_clone);

            // Now add link so fetches can complete
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            // Fetch same key again, if the in-flight entry wasn't cleaned up, this would
            // be treated as a duplicate and silently ignored
            mailbox1.fetch(key.clone());

            // Should succeed
            let (key_actual, value) = cons_out1.recv().await.unwrap();
            assert_eq!(key_actual, key);
            assert_eq!(value, Bytes::from("data for key 5"));
        });
    }

    #[test_traced]
    fn test_retain_uses_subscribers() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            let key = Key(5);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 5"));

            let (cons1, mut cons_out1): (Consumer<Key, Bytes, SubscriberTag>, _) = Consumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            let dropped_subscriber = SubscriberTag(50);
            let kept_subscriber = SubscriberTag(51);
            mailbox1.fetch(Fetch {
                key: key.clone(),
                subscriber: dropped_subscriber,
                span: tracing::Span::none(),
            });
            mailbox1.fetch(Fetch {
                key: key.clone(),
                subscriber: kept_subscriber.clone(),
                span: tracing::Span::none(),
            });

            context.sleep(Duration::from_millis(100)).await;
            mailbox1.retain(move |_, subscriber| subscriber == &kept_subscriber);
            context.sleep(Duration::from_millis(100)).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let (key_actual, value) = cons_out1.recv().await.unwrap();
            assert_eq!(key_actual, key);
            assert_eq!(value, Bytes::from("data for key 5"));
        });
    }

    #[test_traced]
    fn test_deliver_receives_subscribers() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            let key = Key(5);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 5"));

            let (cons1, mut cons_out1) = SubscriberRecordingConsumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            let first_subscriber = SubscriberTag(50);
            let second_subscriber = SubscriberTag(51);
            mailbox1.fetch(Fetch {
                key: key.clone(),
                subscriber: second_subscriber.clone(),
                span: tracing::Span::none(),
            });
            mailbox1.fetch(Fetch {
                key: key.clone(),
                subscriber: first_subscriber.clone(),
                span: tracing::Span::none(),
            });

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let (delivery, value) = cons_out1.recv().await.unwrap();
            assert_eq!(
                delivery,
                Delivery {
                    key,
                    subscribers: non_empty_vec![
                        (first_subscriber, tracing::Span::none()),
                        (second_subscriber, tracing::Span::none())
                    ],
                }
            );
            assert_eq!(value, Bytes::from("data for key 5"));
        });
    }

    #[test_traced]
    fn test_deliver_receives_multiple_subscribers() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            let key = Key(5);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 5"));

            let (cons1, mut cons_out1) = SubscriberRecordingConsumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            let first_subscriber = SubscriberTag(49);
            let second_subscriber = SubscriberTag(50);
            mailbox1.fetch(Fetch {
                key: key.clone(),
                subscriber: first_subscriber.clone(),
                span: tracing::Span::none(),
            });
            mailbox1.fetch(Fetch {
                key: key.clone(),
                subscriber: second_subscriber.clone(),
                span: tracing::Span::none(),
            });

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let (delivery, value) = cons_out1.recv().await.unwrap();
            assert_eq!(
                delivery,
                Delivery {
                    key: key.clone(),
                    subscribers: non_empty_vec![
                        (first_subscriber, tracing::Span::none()),
                        (second_subscriber, tracing::Span::none())
                    ],
                }
            );
            assert_eq!(value, Bytes::from("data for key 5"));
        });
    }

    #[test_traced]
    fn test_fetch_during_validation_reuses_response_after_success() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(5);
            let first_response = Bytes::from("data for key 5");
            let second_response = Bytes::from("refetched data for key 5");
            let mut prod2 = SequencedProducer::default();
            prod2.insert(
                key.clone(),
                [first_response.clone(), second_response.clone()],
            );
            let prod2_observer = prod2.clone();

            let (first_gate_sender, first_gate_receiver) = oneshot::channel();
            let (second_gate_sender, second_gate_receiver) = oneshot::channel();
            let (cons1, mut deliveries, mut started) = BlockingSubscriberRecordingConsumer::new(
                context.child("consumer"),
                vec![
                    (first_gate_receiver, Outcome::Resolved(Resolution::All)),
                    (second_gate_receiver, Outcome::Resolved(Resolution::All)),
                ],
            );

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor_with_producer(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            let first_subscriber = SubscriberTag(49);
            let second_subscriber = SubscriberTag(50);
            mailbox1.fetch(Fetch {
                key: key.clone(),
                subscriber: first_subscriber.clone(),
                span: tracing::Span::none(),
            });

            let delivery = started.recv().await.expect("delivery did not start");
            assert_eq!(
                delivery,
                Delivery {
                    key: key.clone(),
                    subscribers: non_empty_vec![(first_subscriber.clone(), tracing::Span::none())],
                }
            );

            mailbox1.fetch(Fetch {
                key: key.clone(),
                subscriber: second_subscriber.clone(),
                span: tracing::Span::none(),
            });
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(
                prod2_observer.remaining(&key),
                vec![second_response.clone()]
            );

            first_gate_sender.send(()).unwrap();
            let (delivery, value) = deliveries.recv().await.expect("consumer channel closed");
            assert_eq!(
                delivery,
                Delivery {
                    key: key.clone(),
                    subscribers: non_empty_vec![(first_subscriber, tracing::Span::none())],
                }
            );
            assert_eq!(value, first_response);

            let delivery = select! {
                delivery = started.recv() => delivery.expect("second delivery did not start"),
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("late subscriber was not delivered");
                },
            };
            assert_eq!(
                delivery,
                Delivery {
                    key: key.clone(),
                    subscribers: non_empty_vec![(second_subscriber.clone(), tracing::Span::none())],
                }
            );
            assert_eq!(peer_resolve_count(&context.encode()), 1);

            second_gate_sender.send(()).unwrap();
            let (delivery, value) = deliveries.recv().await.expect("consumer channel closed");
            assert_eq!(
                delivery,
                Delivery {
                    key: key.clone(),
                    subscribers: non_empty_vec![(second_subscriber, tracing::Span::none())],
                }
            );
            assert_eq!(value, first_response);
            assert_eq!(prod2_observer.remaining(&key), vec![second_response]);
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(peer_resolve_count(&context.encode()), 1);
        });
    }

    #[test_traced]
    fn test_late_targeted_subscriber_joins_retry_after_unresolved_delivery() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(5);
            let ambiguous_response = Bytes::from("ambiguous data for key 5");
            let unexpected_refetch = Bytes::from("unexpected refetch for key 5");
            let mut prod2 = SequencedProducer::default();
            prod2.insert(
                key.clone(),
                [ambiguous_response, unexpected_refetch.clone()],
            );
            let prod2_observer = prod2.clone();

            let valid_response = Bytes::from("valid data for key 5");
            let mut prod3 = SequencedProducer::default();
            prod3.insert(key.clone(), [valid_response.clone()]);
            let prod3_observer = prod3.clone();

            let (first_gate_sender, first_gate_receiver) = oneshot::channel();
            let (second_gate_sender, second_gate_receiver) = oneshot::channel();
            let (cons1, mut deliveries, mut started) = BlockingSubscriberRecordingConsumer::new(
                context.child("consumer"),
                vec![
                    (first_gate_receiver, Outcome::Resolved(Resolution::None)),
                    (second_gate_receiver, Outcome::Resolved(Resolution::All)),
                ],
            );

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor_with_producer(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor_with_producer(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod3,
            );

            let first_subscriber = SubscriberTag(49);
            let second_subscriber = SubscriberTag(50);

            // Start unrestricted repair and park its first response in validation.
            mailbox1.fetch(Fetch {
                key: key.clone(),
                subscriber: first_subscriber.clone(),
                span: tracing::Span::none(),
            });

            let delivery = started.recv().await.expect("delivery did not start");
            assert_eq!(
                delivery,
                Delivery {
                    key: key.clone(),
                    subscribers: non_empty_vec![(first_subscriber.clone(), tracing::Span::none())],
                }
            );

            // A targeted objection for the same key attaches to the parked fetch
            // without issuing another network request.
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;
            mailbox1.fetch_targeted(
                Fetch {
                    key: key.clone(),
                    subscriber: second_subscriber.clone(),
                    span: tracing::Span::none(),
                },
                non_empty_vec![peers[2].clone()],
            );

            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(
                prod2_observer.remaining(&key),
                vec![unexpected_refetch.clone()]
            );
            assert_eq!(prod3_observer.remaining(&key), vec![valid_response.clone()]);

            oracle
                .remove_link(peers[0].clone(), peers[1].clone())
                .await
                .unwrap();
            oracle
                .remove_link(peers[1].clone(), peers[0].clone())
                .await
                .unwrap();

            // An ambiguous response retries unrestricted repair with both
            // subscribers and does not penalize the serving peer.
            first_gate_sender.send(()).unwrap();
            oracle.manager().track(
                1,
                Set::try_from([peers[0].clone(), peers[2].clone()]).unwrap(),
            );

            let delivery = select! {
                delivery = started.recv() => delivery.expect("retry delivery did not start"),
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("ambiguous response was not retried with the late subscriber");
                },
            };
            assert_eq!(
                delivery,
                Delivery {
                    key: key.clone(),
                    subscribers: non_empty_vec![
                        (first_subscriber.clone(), tracing::Span::none()),
                        (second_subscriber.clone(), tracing::Span::none())
                    ],
                }
            );

            second_gate_sender.send(()).unwrap();
            let (delivery, value) = deliveries.recv().await.expect("consumer channel closed");
            assert_eq!(
                delivery,
                Delivery {
                    key: key.clone(),
                    subscribers: non_empty_vec![
                        (first_subscriber, tracing::Span::none()),
                        (second_subscriber, tracing::Span::none())
                    ],
                }
            );
            assert_eq!(value, valid_response);
            assert_eq!(prod2_observer.remaining(&key), vec![unexpected_refetch]);
            assert!(prod3_observer.remaining(&key).is_empty());
            assert!(oracle.blocked().await.unwrap().is_empty());
        });
    }

    #[test_traced]
    fn test_due_retry_precedes_queued_fresh_request() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers_with_rate_limit(
                    &context,
                    &[1, 2],
                    Quota::per_second(NZU32!(2)),
                )
                .await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let retry_key = Key(60);
            let fresh_key = Key(61);

            let (requester_consumer, mut deliveries) = HoldingConsumer::new();
            let requester = schemes.remove(0);
            let requester_key = requester.public_key();
            let (requester_engine, mut requester_mailbox) = Engine::new(
                context.child("requester"),
                Config {
                    peer_provider: oracle.manager(),
                    blocker: oracle.control(requester_key.clone()),
                    consumer: requester_consumer,
                    producer: Producer::<Key, Bytes>::default(),
                    mailbox_size: MAILBOX_SIZE,
                    me: Some(requester_key),
                    timeout: TIMEOUT,
                    fetch_retry_timeout: Duration::ZERO,
                    priority_requests: false,
                    priority_responses: false,
                },
            );

            let mut producer = Producer::default();
            producer.insert(retry_key.clone(), Bytes::from("retry"));
            producer.insert(fresh_key.clone(), Bytes::from("fresh"));
            let responder = schemes.remove(0);
            let _responder_mailbox = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(responder.public_key()),
                responder,
                connections.remove(1),
                dummy_consumer(),
                producer,
            );

            requester_engine.start(connections.remove(0));
            requester_mailbox.fetch(retry_key.clone());

            let (delivered_key, verdict) =
                deliveries.recv().await.expect("requester consumer closed");
            assert_eq!(delivered_key, retry_key);

            // Resolving the delivery makes its retry due before the queued
            // mailbox request is admitted. The two-token quota admits the
            // retry and holds the fresh request.
            requester_mailbox.fetch(fresh_key.clone());
            verdict.send_lossy(Outcome::Resolved(Resolution::None));

            let (delivered_key, verdict) =
                deliveries.recv().await.expect("requester consumer closed");
            assert_eq!(delivered_key, retry_key);
            verdict.send_lossy(Outcome::Resolved(Resolution::All));

            let (delivered_key, verdict) =
                deliveries.recv().await.expect("requester consumer closed");
            assert_eq!(delivered_key, fresh_key);
            verdict.send_lossy(Outcome::Resolved(Resolution::All));
        });
    }

    #[test_traced]
    fn test_late_subscriber_delivery_ignores_unrelated_waiter() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;

            let blocked_key = Key(4);
            let waiting_key = Key(5);
            let main_key = Key(6);
            let data = Bytes::from("data for key 6");

            let mut prod2 = Producer::default();
            prod2.insert(blocked_key.clone(), Bytes::from("bad data"));

            let mut prod3 = Producer::default();
            prod3.insert(main_key.clone(), data.clone());

            let (first_gate_sender, first_gate_receiver) = oneshot::channel();
            let (second_gate_sender, second_gate_receiver) = oneshot::channel();
            let (cons1, mut deliveries, mut started) = BlockingSubscriberRecordingConsumer::new(
                context.child("consumer"),
                vec![
                    (first_gate_receiver, Outcome::Invalid),
                    (second_gate_receiver, Outcome::Resolved(Resolution::All)),
                ],
            );

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod3,
            );

            mailbox1.fetch(Fetch {
                key: blocked_key.clone(),
                subscriber: SubscriberTag(1),
                span: tracing::Span::none(),
            });
            started
                .recv()
                .await
                .expect("blocking delivery did not start");
            first_gate_sender.send(()).unwrap();
            wait_for_blocked(&context, &oracle, &peers[0], &peers[1]).await;

            mailbox1.fetch_targeted(
                Fetch {
                    key: waiting_key,
                    subscriber: SubscriberTag(2),
                    span: tracing::Span::none(),
                },
                non_empty_vec![peers[1].clone()],
            );
            context.sleep(Duration::from_millis(100)).await;

            let first_subscriber = SubscriberTag(3);
            let second_subscriber = SubscriberTag(4);
            mailbox1.fetch(Fetch {
                key: main_key.clone(),
                subscriber: first_subscriber.clone(),
                span: tracing::Span::none(),
            });

            let delivery = started.recv().await.expect("delivery did not start");
            assert_eq!(
                delivery,
                Delivery {
                    key: main_key.clone(),
                    subscribers: non_empty_vec![(first_subscriber.clone(), tracing::Span::none())],
                }
            );

            mailbox1.fetch(Fetch {
                key: main_key.clone(),
                subscriber: second_subscriber.clone(),
                span: tracing::Span::none(),
            });
            context.sleep(Duration::from_millis(100)).await;

            second_gate_sender.send(()).unwrap();
            let (delivery, value) = deliveries.recv().await.expect("consumer channel closed");
            assert_eq!(
                delivery,
                Delivery {
                    key: main_key.clone(),
                    subscribers: non_empty_vec![(first_subscriber, tracing::Span::none())],
                }
            );
            assert_eq!(value, data);

            let delivery = select! {
                delivery = started.recv() => delivery.expect("second delivery did not start"),
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("late subscriber was not delivered while an unrelated waiter was armed");
                },
            };
            assert_eq!(
                delivery,
                Delivery {
                    key: main_key,
                    subscribers: non_empty_vec![(second_subscriber, tracing::Span::none())],
                }
            );
        });
    }

    #[test_traced]
    fn test_deliver_receives_distinct_subscriber_type() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            let key = Key(5);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 5"));

            let (cons1, mut cons_out1) = SubscriberRecordingConsumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            let subscriber = SubscriberTag(50);
            let retained = subscriber.clone();
            mailbox1.fetch(Fetch {
                key: key.clone(),
                subscriber: subscriber.clone(),
                span: tracing::Span::none(),
            });

            context.sleep(Duration::from_millis(100)).await;
            mailbox1.retain(move |_, subscriber| subscriber == &retained);
            context.sleep(Duration::from_millis(100)).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let (delivery, value) = cons_out1.recv().await.unwrap();
            assert_eq!(
                delivery,
                Delivery {
                    key,
                    subscribers: non_empty_vec![(subscriber, tracing::Span::none())],
                }
            );
            assert_eq!(value, Bytes::from("data for key 5"));
        });
    }

    #[test_traced]
    fn test_deliver_receives_single_subscriber() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            let key = Key(5);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 5"));

            let (cons1, mut cons_out1) = SubscriberRecordingConsumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            let subscriber = SubscriberTag(50);
            mailbox1.fetch(Fetch {
                key: key.clone(),
                subscriber: subscriber.clone(),
                span: tracing::Span::none(),
            });
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let (delivery, value) = cons_out1.recv().await.unwrap();
            assert_eq!(
                delivery,
                Delivery {
                    key,
                    subscribers: non_empty_vec![(subscriber, tracing::Span::none())],
                }
            );
            assert_eq!(value, Bytes::from("data for key 5"));
        });
    }

    #[test_traced]
    fn test_retain_drops_all() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            // No link yet, so the fetch will stay in flight
            let key = Key(6);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 6"));

            let (cons1, mut cons_out1) = consumer();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            // Pruning before fetching should have no effect.
            mailbox1.retain(|_, _| false);
            select! {
                _ = cons_out1.recv() => {
                    panic!("unexpected event");
                },
                _ = context.sleep(Duration::from_millis(100)) => {},
            };

            // Start a fetch (no link, so fetch stays in-flight)
            mailbox1.fetch(key.clone());

            // Prune all fetches.
            mailbox1.retain(|_, _| false);

            // Now add link so fetches can complete
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            // Fetch same key again, if the in-flight entry wasn't cleaned up, this would
            // be treated as a duplicate and silently ignored
            mailbox1.fetch(key.clone());

            // Should succeed
            let (key_actual, value) = cons_out1.recv().await.unwrap();
            assert_eq!(key_actual, key);
            assert_eq!(value, Bytes::from("data for key 6"));
        });
    }

    /// Tests that when a peer is rate-limited, the fetcher spills over to another peer.
    /// With 2 peers and rate limit of 1/sec each, 2 requests issued simultaneously should
    /// both complete immediately (one to each peer) without waiting for rate limit reset.
    #[test_traced]
    fn test_rate_limit_spillover() {
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|context| async move {
            // Use a very restrictive rate limit: 1 request per second per peer
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers_with_rate_limit(
                    &context,
                    &[1, 2, 3],
                    Quota::per_second(NZU32!(1)),
                )
                .await;

            // Add links between peer 1 and both peer 2 and peer 3
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;

            // Both peer 2 and peer 3 have the same data
            let mut prod2 = Producer::default();
            let mut prod3 = Producer::default();
            prod2.insert(Key(0), Bytes::from("data for key 0"));
            prod2.insert(Key(1), Bytes::from("data for key 1"));
            prod3.insert(Key(0), Bytes::from("data for key 0"));
            prod3.insert(Key(1), Bytes::from("data for key 1"));

            let (cons1, mut cons_out1) = consumer();

            // Set up peer 1 (the requester)
            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            // Set up peer 2 (has data)
            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            // Set up peer 3 (also has data)
            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod3,
            );

            // Wait for peer set to be established
            context.sleep(Duration::from_millis(100)).await;
            let start = context.current();

            // Issue 2 fetches rapidly.
            // With rate limit of 1/sec per peer and 2 peers, both should complete
            // immediately via spill-over (one request to each peer)
            mailbox1.fetch(Key(0));
            mailbox1.fetch(Key(1));

            // Collect results
            let mut results = HashMap::new();
            for _ in 0..2 {
                let (key, value) = cons_out1.recv().await.unwrap();
                results.insert(key.clone(), value);
            }

            // Verify both keys were fetched successfully
            assert_eq!(results.len(), 2);
            assert_eq!(
                results.get(&Key(0)).unwrap(),
                &Bytes::from("data for key 0")
            );
            assert_eq!(
                results.get(&Key(1)).unwrap(),
                &Bytes::from("data for key 1")
            );

            // A quick completion (well under 1 second) proves spill-over worked. Without
            // spill-over, the second request would wait about 1 second for the rate limit to reset.
            let elapsed = context.current().duration_since(start).unwrap();
            assert!(
                elapsed < Duration::from_millis(500),
                "Expected quick completion via spill-over, but took {elapsed:?}"
            );
        });
    }

    /// Tests that rate limiting causes retries to eventually succeed after the rate limit resets.
    /// This test uses a single peer with a restrictive rate limit and verifies that
    /// fetches eventually complete after waiting for the rate limit to reset.
    #[test_traced]
    fn test_rate_limit_retry_after_reset() {
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|context| async move {
            // Use a restrictive rate limit: 1 request per second
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers_with_rate_limit(
                    &context,
                    &[1, 2],
                    Quota::per_second(NZU32!(1)),
                )
                .await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            // Peer 2 has data for multiple keys
            let mut prod2 = Producer::default();
            prod2.insert(Key(1), Bytes::from("data for key 1"));
            prod2.insert(Key(2), Bytes::from("data for key 2"));
            prod2.insert(Key(3), Bytes::from("data for key 3"));

            let (cons1, mut cons_out1) = consumer();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            // Wait for peer set to be established
            context.sleep(Duration::from_millis(100)).await;
            let start = context.current();

            // Issue 3 fetches to a single peer with rate limit of 1/sec.
            // Only 1 can be sent immediately, the others must wait for rate limit reset
            mailbox1.fetch(Key(1));
            mailbox1.fetch(Key(2));
            mailbox1.fetch(Key(3));

            // All 3 should eventually succeed (after rate limit resets)
            let mut results = HashMap::new();
            for _ in 0..3 {
                let (key, value) = cons_out1.recv().await.unwrap();
                results.insert(key.clone(), value);
            }

            assert_eq!(results.len(), 3);
            for i in 1..=3 {
                assert_eq!(
                    results.get(&Key(i)).unwrap(),
                    &Bytes::from(format!("data for key {}", i))
                );
            }

            // Verify it took significant time due to rate limiting
            // With 3 requests at 1/sec to a single peer, requests 2 and 3 must wait
            // for rate limit resets (~1 second each), so total should be > 2 seconds
            let elapsed = context.current().duration_since(start).unwrap();
            assert!(
                elapsed > Duration::from_secs(2),
                "Expected rate limiting to cause delay > 2s, but took {elapsed:?}"
            );
        });
    }

    /// Tests that the resolver never sends fetches to itself (me exclusion).
    /// Even when the local peer has the data in its producer, it should fetch from
    /// another peer instead.
    #[test_traced]
    fn test_self_exclusion() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(1);
            let data = Bytes::from("shared data");

            // Both peers have the data: peer 1 (requester) and peer 2
            let mut prod1 = Producer::default();
            prod1.insert(key.clone(), data.clone());
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), data.clone());

            let (cons1, mut cons_out1) = consumer();

            // Set up peer 1 with `me` set, so it never fetches from itself despite having the data
            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                prod1, // peer 1 has the data
            );

            // Set up peer 2 with the data as well
            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            // Wait for peer set to be established
            context.sleep(Duration::from_millis(100)).await;

            // Fetch the key. It should come from peer 2, not from self.
            mailbox1.fetch(key.clone());

            // Should succeed (from peer 2)
            let (key_actual, value) = cons_out1.recv().await.unwrap();
            assert_eq!(key_actual, key);
            assert_eq!(value, data);
        });
    }

    /// A fetch without targets reaches secondary peers of the latest set as well as primary ones.
    #[test_traced]
    fn test_fetch_uses_secondary_peers() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (network, oracle) = Network::new(
                context.child("network"),
                commonware_p2p::simulated::Config {
                    max_size: 1024 * 1024,
                    max_peers_per_set: NZUsize!(3),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let schemes: Vec<PrivateKey> = [1u64, 2, 3]
                .into_iter()
                .map(PrivateKey::from_seed)
                .collect();
            let peers: Vec<PublicKey> = schemes.iter().map(|s| s.public_key()).collect();
            let mut schemes = schemes;

            let mut connections = Vec::new();
            for peer in &peers {
                let (sender, receiver) = oracle
                    .control(peer.clone())
                    .register(0, Quota::per_second(RATE_LIMIT))
                    .await
                    .unwrap();
                connections.push((sender, receiver));
            }

            // Topology: peer 1 (requester) linked to peers 2 and 3. Peers 1 and 2 are primary
            // and peer 2 has no data. Peer 3 is secondary and has the data.
            let mut oracle = oracle;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;

            oracle.manager().track(
                1,
                TrackedPeers::new(
                    Set::try_from([peers[0].clone(), peers[1].clone()]).unwrap(),
                    Set::try_from([peers[2].clone()]).unwrap(),
                ),
            );
            context.sleep(Duration::from_millis(100)).await;

            let key = Key(1);
            let data = Bytes::from("secondary only data");

            let (cons1, mut cons_out1) = consumer();

            // Peer 1: the requester, has no data.
            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            // Peer 2: primary, has no data.
            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                Producer::default(),
            );

            // Peer 3: secondary, has the data.
            let mut prod3 = Producer::default();
            prod3.insert(key.clone(), data.clone());
            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod3,
            );

            // The only peer with the data is secondary, and the fetch reaches it.
            mailbox1.fetch(key.clone());
            let (key_actual, value) = cons_out1.recv().await.unwrap();
            assert_eq!(key_actual, key);
            assert_eq!(value, data);
        });
    }

    /// A targeted fetch reaches a target that is a secondary peer, whether or not a
    /// primary peer is targeted as well.
    #[test_traced]
    fn test_fetch_targeted_reaches_secondary_peer() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (network, oracle) = Network::new(
                context.child("network"),
                commonware_p2p::simulated::Config {
                    max_size: 1024 * 1024,
                    max_peers_per_set: NZUsize!(3),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let schemes: Vec<PrivateKey> = [1u64, 2, 3]
                .into_iter()
                .map(PrivateKey::from_seed)
                .collect();
            let peers: Vec<PublicKey> = schemes.iter().map(|s| s.public_key()).collect();
            let mut schemes = schemes;

            let mut connections = Vec::new();
            for peer in &peers {
                let (sender, receiver) = oracle
                    .control(peer.clone())
                    .register(0, Quota::per_second(RATE_LIMIT))
                    .await
                    .unwrap();
                connections.push((sender, receiver));
            }

            // Peer 1 (the requester) links to peers 2 and 3. Peers 1 and 2 are primary and
            // peer 3 is secondary.
            let mut oracle = oracle;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;

            oracle.manager().track(
                1,
                TrackedPeers::new(
                    Set::try_from([peers[0].clone(), peers[1].clone()]).unwrap(),
                    Set::try_from([peers[2].clone()]).unwrap(),
                ),
            );
            context.sleep(Duration::from_millis(100)).await;

            let data = Bytes::from("secondary only data");

            let (cons1, mut cons_out1) = consumer();

            // Peer 1: the requester, has no data.
            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            // Peer 2: primary, has no data.
            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                Producer::default(),
            );

            // Peer 3: secondary, has the data for both keys.
            let mut prod3 = Producer::default();
            prod3.insert(Key(1), data.clone());
            prod3.insert(Key(2), data.clone());
            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod3,
            );

            // With both peers targeted, only the secondary peer can serve the key.
            mailbox1.fetch_targeted(Key(1), non_empty_vec![peers[1].clone(), peers[2].clone()]);
            let (key, received) = cons_out1.recv().await.unwrap();
            assert_eq!(key, Key(1));
            assert_eq!(received, data);

            // Targeting only the secondary peer also succeeds.
            mailbox1.fetch_targeted(Key(2), non_empty_vec![peers[2].clone()]);
            let (key, received) = cons_out1.recv().await.unwrap();
            assert_eq!(key, Key(2));
            assert_eq!(received, data);
        });
    }

    /// Fetches use peers of the latest set in either role, never peers retained only from an
    /// older set, and a target outside the latest set is skipped.
    #[test_traced]
    fn test_fetch_uses_latest_set_only() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (network, oracle) = Network::new(
                context.child("network"),
                commonware_p2p::simulated::Config {
                    max_size: 1024 * 1024,
                    max_peers_per_set: NZUsize!(2),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(2),
                },
            );
            network.start();

            let schemes: Vec<PrivateKey> = [1u64, 2, 3]
                .into_iter()
                .map(PrivateKey::from_seed)
                .collect();
            let peers: Vec<PublicKey> = schemes.iter().map(|s| s.public_key()).collect();
            let mut schemes = schemes;

            let mut connections = Vec::new();
            for peer in &peers {
                let (sender, receiver) = oracle
                    .control(peer.clone())
                    .register(0, Quota::per_second(RATE_LIMIT))
                    .await
                    .unwrap();
                connections.push((sender, receiver));
            }

            let mut oracle = oracle;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;

            // Keep the requester tracked across the cutover so the fetch path itself remains
            // active, while peer 2 is retained only through the overlap window after peer 3
            // joins the newest set as a secondary peer.
            oracle
                .manager()
                .track(
                    0,
                    Set::try_from([peers[0].clone(), peers[1].clone()]).unwrap(),
                );
            context.sleep(Duration::from_millis(100)).await;

            let key = Key(7);
            let targeted_key = Key(8);
            let latest_key = Key(9);
            let data = Bytes::from("old primary data");

            let (cons1, mut cons_out1) = consumer();

            // Peer 1: requester.
            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            // Peer 2: old primary, still retained in `all.primary`, has the data.
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), data.clone());
            prod2.insert(targeted_key.clone(), data.clone());
            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            // Peer 3: latest secondary, has only the data for `latest_key`.
            let mut prod3 = Producer::default();
            prod3.insert(latest_key.clone(), data.clone());
            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod3,
            );

            context.sleep(Duration::from_millis(100)).await;

            // Track peer 3 as a secondary peer of the latest set while keeping the requester in
            // it. Peer 2 remains in the provider's overlap window (`all.primary`), but new
            // resolver traffic uses only the latest set.
            oracle.manager().track(
                1,
                TrackedPeers::new(
                    Set::try_from([peers[0].clone()]).unwrap(),
                    Set::try_from([peers[2].clone()]).unwrap(),
                ),
            );
            context.sleep(Duration::from_millis(100)).await;

            mailbox1.fetch(key);

            select! {
                event = cons_out1.recv() => {
                    panic!(
                        "fetch should not succeed from an old primary retained only in the overlap window, got: {event:?}"
                    );
                },
                _ = context.sleep(Duration::from_secs(1)) => {},
            }

            // A target retained only in the overlap window is ignored as well.
            mailbox1
                .fetch_targeted(targeted_key, non_empty_vec![peers[1].clone()]);

            select! {
                event = cons_out1.recv() => {
                    panic!(
                        "targeted fetch must not reach a peer outside the latest peer set, got: {event:?}"
                    );
                },
                _ = context.sleep(Duration::from_secs(1)) => {},
            }

            // The latest set's secondary peer serves a fetch without targets.
            mailbox1.fetch(latest_key.clone());
            let (key_actual, value) = cons_out1.recv().await.unwrap();
            assert_eq!(key_actual, latest_key);
            assert_eq!(value, data);
        });
    }

    #[test_traced]
    fn test_fetch_after_cutover_relies_on_latest_primary_history() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (network, oracle) = Network::new(
                context.child("network"),
                commonware_p2p::simulated::Config {
                    max_size: 1024 * 1024,
                    max_peers_per_set: NZUsize!(2),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(2),
                },
            );
            network.start();

            let schemes: Vec<PrivateKey> = [1u64, 2, 3]
                .into_iter()
                .map(PrivateKey::from_seed)
                .collect();
            let peers: Vec<PublicKey> = schemes.iter().map(|s| s.public_key()).collect();
            let mut schemes = schemes;

            let mut connections = Vec::new();
            for peer in &peers {
                let (sender, receiver) = oracle
                    .control(peer.clone())
                    .register(0, Quota::per_second(RATE_LIMIT))
                    .await
                    .unwrap();
                connections.push((sender, receiver));
            }

            let mut oracle = oracle;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;

            // Keep the requester in the peer set across the cutover while peer 2 remains connected
            // only through the overlap window after the latest primary advances to peer 3.
            oracle.manager().track(
                0,
                Set::try_from([peers[0].clone(), peers[1].clone()]).unwrap(),
            );
            context.sleep(Duration::from_millis(100)).await;

            let key = Key(9);
            let invalid_history = Bytes::from("stale overlap history");
            let valid_history = Bytes::from("latest primary history");

            let (mut cons1, mut cons_out1) = consumer();
            cons1.add_expected(key.clone(), valid_history.clone());

            // Peer 1: requester.
            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            );

            // Peer 2: old primary retained only via overlap. If queried, it would be blocked for
            // serving invalid history.
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), invalid_history);
            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod2,
            );

            // Peer 3: latest primary and the only peer that should satisfy the fetch.
            let mut prod3 = Producer::default();
            prod3.insert(key.clone(), valid_history.clone());
            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod3,
            );

            context.sleep(Duration::from_millis(100)).await;

            oracle.manager().track(
                1,
                Set::try_from([peers[0].clone(), peers[2].clone()]).unwrap(),
            );
            context.sleep(Duration::from_millis(100)).await;

            mailbox1.fetch(key.clone());

            let (key_actual, value) = cons_out1.recv().await.unwrap();
            assert_eq!(key_actual, key);
            assert_eq!(value, valid_history);

            assert!(
                oracle.blocked().await.unwrap().is_empty(),
                "overlap-only peers should not be queried for post-cutover history"
            );
        });
    }

    #[test_traced]
    fn test_secondary_peer_requests_are_served() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            // Topology: peer 1 is primary (has data), peer 2 is secondary (requester).
            // Verifies that a primary peer serves requests from secondary peers
            // (i.e. secondary peers can't fetch via broadcast, but their direct
            // requests are still answered).
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            oracle.manager().track(
                1,
                TrackedPeers::new(
                    Set::try_from([peers[0].clone()]).unwrap(),
                    Set::try_from([peers[1].clone()]).unwrap(),
                ),
            );
            context.sleep(Duration::from_millis(100)).await;

            let key = Key(9);
            let data = Bytes::from("served to secondary");

            // Peer 1: primary, has the data.
            let mut prod1 = Producer::default();
            prod1.insert(key.clone(), data.clone());

            let scheme = schemes.remove(0);
            let _mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                dummy_consumer(),
                prod1,
            );

            // Peer 2: secondary, uses fetch_targeted to explicitly request from peer 1.
            let (mut cons2, mut cons_out2) = consumer();
            cons2.add_expected(key.clone(), data.clone());
            let scheme = schemes.remove(0);
            let mut mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons2,
                Producer::default(),
            );

            mailbox2.fetch_targeted(key.clone(), non_empty_vec![peers[0].clone()]);

            let (key_actual, value) = cons_out2.recv().await.unwrap();
            assert_eq!(key_actual, key);
            assert_eq!(value, data);
        });
    }

    #[test_traced]
    fn test_shutdown_aborts_pending_delivery_without_leaked_tasks() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(1);
            let data = Bytes::from("data for key 1");
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), data);

            let (mut gate_sender, gate_receiver) = oneshot::channel();
            let (cons1, mut cons_out1, mut started) = BlockingConsumer::new(
                context.child("consumer"),
                vec![(gate_receiver, Outcome::Resolved(Resolution::All))],
            );

            let actor_context = context.child("actor");

            let scheme = schemes.remove(0);
            let public_key = scheme.public_key();
            let (engine, mut mailbox1): (_, Mailbox<Key, PublicKey>) = Engine::new(
                actor_context.child("peer").with_attribute("index", 0),
                Config {
                    peer_provider: oracle.manager(),
                    blocker: oracle.control(public_key.clone()),
                    consumer: cons1,
                    producer: Producer::<Key, Bytes>::default(),
                    mailbox_size: MAILBOX_SIZE,
                    me: Some(public_key),
                    timeout: TIMEOUT,
                    fetch_retry_timeout: FETCH_RETRY_TIMEOUT,
                    priority_requests: false,
                    priority_responses: false,
                },
            );
            let handle1 = engine.start(connections.remove(0));

            let scheme = schemes.remove(0);
            let public_key = scheme.public_key();
            let (engine, _mailbox2): (_, Mailbox<Key, PublicKey>) = Engine::new(
                actor_context.child("peer").with_attribute("index", 1),
                Config {
                    peer_provider: oracle.manager(),
                    blocker: oracle.control(public_key.clone()),
                    consumer: dummy_consumer(),
                    producer: prod2,
                    mailbox_size: MAILBOX_SIZE,
                    me: Some(public_key),
                    timeout: TIMEOUT,
                    fetch_retry_timeout: FETCH_RETRY_TIMEOUT,
                    priority_requests: false,
                    priority_responses: false,
                },
            );
            let handle2 = engine.start(connections.remove(0));

            mailbox1.fetch(key.clone());
            let started_key = started.recv().await.expect("delivery did not start");
            assert_eq!(started_key, key);

            assert!(count_running_tasks(&context, "actor") > 0);

            handle1.abort();
            handle2.abort();

            context.sleep(Duration::from_millis(100)).await;

            select! {
                _ = gate_sender.closed() => {},
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("pending delivery was not aborted");
                },
            };

            select! {
                event = cons_out1.recv() => assert!(event.is_none(), "unexpected event"),
                _ = context.sleep(Duration::from_millis(100)) => {},
            };

            let running_after = count_running_tasks(&context, "actor");
            assert_eq!(
                running_after, 0,
                "all actor tasks should be stopped, but {running_after} still running"
            );
        });
    }

    fn spawn_actors_with_handles(
        context: &deterministic::Context,
        oracle: &Oracle<PublicKey, deterministic::Context>,
        schemes: Vec<PrivateKey>,
        connections: Vec<(
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        )>,
        consumers: Vec<Consumer<Key, Bytes>>,
        producers: Vec<Producer<Key, Bytes>>,
    ) -> (
        Vec<Mailbox<Key, PublicKey>>,
        Vec<commonware_runtime::Handle<()>>,
    ) {
        let actor_context = context.child("actor");
        let mut mailboxes = Vec::new();
        let mut handles = Vec::new();

        for (idx, ((scheme, conn), (consumer, producer))) in schemes
            .into_iter()
            .zip(connections)
            .zip(consumers.into_iter().zip(producers))
            .enumerate()
        {
            let ctx = actor_context.child("peer").with_attribute("index", idx);
            let public_key = scheme.public_key();
            let (engine, mailbox) = Engine::new(
                ctx,
                Config {
                    peer_provider: oracle.manager(),
                    blocker: oracle.control(public_key.clone()),
                    consumer,
                    producer,
                    mailbox_size: MAILBOX_SIZE,
                    me: Some(public_key),
                    timeout: TIMEOUT,
                    fetch_retry_timeout: FETCH_RETRY_TIMEOUT,
                    priority_requests: false,
                    priority_responses: false,
                },
            );
            handles.push(engine.start(conn));
            mailboxes.push(mailbox);
        }

        (mailboxes, handles)
    }

    #[test_traced]
    fn test_operations_after_shutdown_do_not_panic() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(1);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 1"));

            let (cons1, mut cons_out1) = consumer();

            let (mut mailboxes, handles) = spawn_actors_with_handles(
                &context,
                &oracle,
                schemes,
                connections,
                vec![cons1, dummy_consumer()],
                vec![Producer::default(), prod2],
            );

            // Fetch to verify network is functional
            mailboxes[0].fetch(key.clone());
            let (_, value) = cons_out1.recv().await.unwrap();
            assert_eq!(value, Bytes::from("data for key 1"));

            // Abort all actors
            for handle in handles {
                handle.abort();
            }
            context.sleep(Duration::from_millis(100)).await;

            // All operations should not panic after shutdown

            // Fetch should not panic
            let key2 = Key(2);
            mailboxes[0].fetch(key2.clone());

            // Retain can prune a single key after shutdown without panicking.
            let canceled = key2;
            mailboxes[0].retain(move |key, _| key != &canceled);

            // Retain should not panic
            mailboxes[0].retain(|_, _| true);

            // Fetch targeted should not panic
            mailboxes[0].fetch_targeted(Key(3), non_empty_vec![peers[1].clone()]);
        });
    }

    fn clean_shutdown(seed: u64) {
        let cfg = deterministic::Config::default()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|context| async move {
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(1);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 1"));

            let (cons1, mut cons_out1) = consumer();

            let (mut mailboxes, handles) = spawn_actors_with_handles(
                &context,
                &oracle,
                schemes,
                connections,
                vec![cons1, dummy_consumer()],
                vec![Producer::default(), prod2],
            );

            // Allow tasks to start
            context.sleep(Duration::from_millis(100)).await;

            // Count running tasks under the actor prefix
            let running_before = count_running_tasks(&context, "actor");
            assert!(
                running_before > 0,
                "at least one actor task should be running"
            );

            // Verify network is functional
            mailboxes[0].fetch(key.clone());
            let (_, value) = cons_out1.recv().await.unwrap();
            assert_eq!(value, Bytes::from("data for key 1"));

            // Abort all actors
            for handle in handles {
                handle.abort();
            }
            context.sleep(Duration::from_millis(100)).await;

            // Verify all actor tasks are stopped
            let running_after = count_running_tasks(&context, "actor");
            assert_eq!(
                running_after, 0,
                "all actor tasks should be stopped, but {running_after} still running"
            );
        });
    }

    #[test]
    fn test_clean_shutdown() {
        for seed in 0..25 {
            clean_shutdown(seed);
        }
    }
}

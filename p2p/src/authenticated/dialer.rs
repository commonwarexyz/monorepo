//! Actor responsible for dialing peers and establishing connections.

use crate::{
    Ingress,
    authenticated::{dialing::Dialable, metrics, stream::Config as StreamConfig},
};
use commonware_cryptography::PublicKey;
use commonware_macros::{select, select_loop};
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Network, Resolver, SinkOf, Spawner,
    StreamOf, spawn_cell,
    telemetry::metrics::{CounterFamily, MetricsExt as _},
};
use commonware_stream::Upgrader;
use rand::seq::{IndexedRandom, SliceRandom};
use rand_core::CryptoRng;
use std::{future::Future, sync::Arc, time::Duration};
use tracing::debug;

/// The tracker's side of dialing: which peers to dial, and a reservation for each dial.
pub trait Tracker<P: PublicKey>: Send + 'static {
    /// Held for the lifetime of a connection attempt and released on drop.
    type Reservation: Send + 'static;

    /// Peers that can be dialed now and when to query again.
    fn dialable(&self) -> impl Future<Output = Dialable<P>> + Send;

    /// Reserve a peer for dialing, returning where to reach it.
    fn dial(&self, peer: P) -> impl Future<Output = Option<(Self::Reservation, Ingress)>> + Send;
}

// Connection handed to the spawner on a successful dial.
type Connection<E, H> = (
    <H as Upgrader>::Sender<StreamOf<E>, SinkOf<E>>,
    <H as Upgrader>::Receiver<StreamOf<E>, SinkOf<E>>,
);

/// Configuration for the dialer actor.
pub struct Config<H: Upgrader> {
    /// Settings for authenticating and wrapping connections.
    pub stream: Arc<StreamConfig<H>>,

    /// Maximum duration of an outbound dial attempt.
    pub dial_timeout: Duration,

    /// The frequency at which to dial a single peer from the queue. This also limits the rate at
    /// which we attempt to dial peers in general.
    pub dial_frequency: Duration,

    /// The maximum interval between tracker queries when the queue is empty. This tracks the
    /// configured peer connection cooldown, since that is the soonest any peer could become
    /// reservable again.
    pub peer_connection_cooldown: Duration,

    /// Whether to allow dialing private IP addresses after DNS resolution.
    pub allow_private_ips: bool,
}

/// Actor responsible for dialing peers and establishing outgoing connections.
pub struct Actor<E: Spawner + Clock + Network + Resolver + Metrics, H: Upgrader>
where
    H::PublicKey: PublicKey,
{
    context: ContextCell<E>,

    // ---------- State ----------
    /// The list of peers to dial.
    queue: Vec<H::PublicKey>,

    // ---------- Configuration ----------
    stream: Arc<StreamConfig<H>>,
    dial_timeout: Duration,
    dial_frequency: Duration,
    peer_connection_cooldown: Duration,
    allow_private_ips: bool,

    // ---------- Metrics ----------
    /// The number of dial attempts made to each peer.
    attempts: CounterFamily<metrics::Peer<H::PublicKey>>,
}

impl<E: Spawner + BufferPooler + Clock + Network + Resolver + CryptoRng + Metrics, H: Upgrader>
    Actor<E, H>
where
    H::PublicKey: PublicKey,
{
    pub fn new(context: E, cfg: Config<H>) -> Self {
        let attempts = context.family("attempts", "The number of dial attempts made to each peer");
        Self {
            context: ContextCell::new(context),
            queue: Vec::new(),
            stream: cfg.stream,
            dial_timeout: cfg.dial_timeout,
            dial_frequency: cfg.dial_frequency,
            peer_connection_cooldown: cfg.peer_connection_cooldown,
            allow_private_ips: cfg.allow_private_ips,
            attempts,
        }
    }

    /// Dial a peer for which we have a reservation.
    fn dial_peer<R: Send + 'static>(
        &mut self,
        peer: H::PublicKey,
        ingress: Ingress,
        reservation: R,
        spawn: impl FnOnce(Connection<E, H>, R) + Send + 'static,
    ) {
        // Increment metrics.
        self.attempts.get_or_create_by(&peer).inc();

        // Spawn dialer to connect to peer
        self.context.child("dialer").spawn({
            let stream = self.stream.clone();
            let allow_private_ips = self.allow_private_ips;
            let dial_timeout = self.dial_timeout;
            move |mut context| async move {
                let timeout = context.sleep(dial_timeout);
                let dial = async {
                    // Resolve ingress to socket addresses (filtered by private IP policy)
                    let addresses: Vec<_> = ingress
                        .resolve_filtered(&context, allow_private_ips)
                        .await
                        .map(Iterator::collect)
                        .unwrap_or_default();
                    let Some(&address) = addresses.choose(&mut context) else {
                        debug!(?ingress, "failed to resolve or no valid addresses");
                        return;
                    };

                    // Attempt to dial peer
                    let (sink, raw_stream) = match context.dial(address).await {
                        Ok(connection) => connection,
                        Err(err) => {
                            debug!(?err, "failed to dial peer");
                            return;
                        }
                    };
                    debug!(?peer, ?ingress, "dialed peer");

                    // Upgrade connection
                    let connection = stream.dial(context, peer.clone(), raw_stream, sink).await;
                    let connection = match connection {
                        Ok(connection) => connection,
                        Err(err) => {
                            debug!(?err, "failed to upgrade connection");
                            return;
                        }
                    };
                    debug!(?peer, ?ingress, "upgraded connection");

                    // Start peer to handle messages
                    spawn(connection, reservation);
                };

                select! {
                    _ = dial => {},
                    _ = timeout => {
                        debug!(?peer, ?ingress, "dial attempt timed out");
                    },
                }
            }
        });
    }

    /// Start the dialer actor.
    ///
    /// `spawn` is called with each established connection and its reservation.
    pub fn start<T, S>(mut self, tracker: T, spawn: S) -> Handle<()>
    where
        T: Tracker<H::PublicKey>,
        S: Fn(Connection<E, H>, T::Reservation) + Clone + Send + 'static,
    {
        spawn_cell!(self.context, self.run(tracker, spawn))
    }

    async fn run<T, S>(mut self, tracker: T, spawn: S)
    where
        T: Tracker<H::PublicKey>,
        S: Fn(Connection<E, H>, T::Reservation) + Clone + Send + 'static,
    {
        let mut dial_deadline = self.context.current();
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping dialer");
            },
            _ = self.context.sleep_until(dial_deadline) => {
                // Refill the queue if empty.
                let now = self.context.current();
                let mut next_query_at = None;
                if self.queue.is_empty() {
                    let dialable = tracker.dialable().await;
                    self.queue = dialable.peers;
                    self.queue.shuffle(self.context.as_mut());
                    next_query_at = dialable.next_query_at;
                }

                // Set next deadline.
                dial_deadline = if self.queue.is_empty() {
                    let min = now + self.dial_frequency;
                    let max = (now + self.peer_connection_cooldown).max(min);
                    next_query_at.unwrap_or(max).clamp(min, max)
                } else {
                    now + self.dial_frequency
                };

                // Pop through peers until we can reserve and dial one.
                while let Some(peer) = self.queue.pop() {
                    if let Some((reservation, ingress)) = tracker.dial(peer.clone()).await {
                        self.dial_peer(peer, ingress, reservation, spawn.clone());
                        break;
                    }
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        ChaCha20Poly1305, Signer as _,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_runtime::{Runner, Supervisor as _, deterministic};
    use commonware_stream::{
        cups::{self, Cups},
        sake::{self, Sake},
        utils::Timeout,
    };
    use futures::channel::oneshot;
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::atomic::{AtomicUsize, Ordering},
        time::{Duration, SystemTime},
    };

    /// Tracker that offers fixed peers and counts calls.
    #[derive(Clone)]
    struct Mock {
        peers: Vec<PublicKey>,
        next_query_in: Option<Duration>,
        dialables: Arc<AtomicUsize>,
        dials: Arc<AtomicUsize>,
    }

    impl Mock {
        fn new(peers: usize, next_query_in: Option<Duration>) -> Self {
            Self {
                peers: (0..peers as u64)
                    .map(|i| PrivateKey::from_seed(i).public_key())
                    .collect(),
                next_query_in,
                dialables: Arc::new(AtomicUsize::new(0)),
                dials: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl Tracker<PublicKey> for Mock {
        type Reservation = ();

        async fn dialable(&self) -> Dialable<PublicKey> {
            self.dialables.fetch_add(1, Ordering::Relaxed);
            Dialable {
                peers: self.peers.clone(),
                next_query_at: self.next_query_in.map(|d| SystemTime::UNIX_EPOCH + d),
            }
        }

        async fn dial(&self, _: PublicKey) -> Option<((), Ingress)> {
            self.dials.fetch_add(1, Ordering::Relaxed);
            Some(((), SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8000).into()))
        }
    }

    fn actor(
        context: deterministic::Context,
        dial_frequency: Duration,
        peer_connection_cooldown: Duration,
    ) -> Actor<deterministic::Context, Timeout<Cups<Sake<PrivateKey>, ChaCha20Poly1305>>> {
        let stream = StreamConfig::new(
            Timeout::new(
                Cups::<_, ChaCha20Poly1305>::new(
                    Sake {
                        signer: PrivateKey::from_seed(0),
                        synchrony_bound: Duration::from_secs(5),
                        max_handshake_age: Duration::from_secs(10),
                        version: sake::Version::V1,
                    },
                    cups::Version::V1,
                ),
                Duration::from_secs(5),
            ),
            b"test",
            1024,
        );
        Actor::new(
            context,
            Config {
                stream: Arc::new(stream),
                dial_timeout: Duration::from_secs(15),
                dial_frequency,
                peer_connection_cooldown,
                allow_private_ips: true,
            },
        )
    }

    /// Run the dialer against `tracker` for `duration`.
    fn run_for(
        context: &deterministic::Context,
        tracker: Mock,
        dial_frequency: Duration,
        peer_connection_cooldown: Duration,
        duration: Duration,
    ) -> impl Future<Output = ()> {
        let dialer = actor(
            context.child("dialer"),
            dial_frequency,
            peer_connection_cooldown,
        );
        let _handle = dialer.start(tracker, |_, _| {});
        context.sleep(duration)
    }

    #[test]
    fn test_dial_timeout_releases_reservation() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let peer = PrivateKey::from_seed(1).public_key();
            let address = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8000);
            let dial_timeout = Duration::from_millis(100);

            // The deterministic network completes the transport dial immediately, but retaining
            // the listener without accepting leaves the encrypted handshake pending.
            let _listener = context
                .bind(address)
                .await
                .expect("Failed to bind listener");
            let mut dialer = actor(
                context.child("dialer"),
                Duration::from_secs(1),
                Duration::from_secs(60),
            );
            dialer.dial_timeout = dial_timeout;

            // Dropping the reservation closes the receiver.
            let (reservation, released) = oneshot::channel::<()>();
            let start = context.current();
            dialer.dial_peer(peer, address.into(), reservation, |_, _| {});

            // The outer dial timeout must cancel the pending handshake and drop its reservation
            // before the much longer handshake timeout can fire.
            let deadline = start + dial_timeout * 2;
            select! {
                result = released => assert!(result.is_err()),
                _ = context.sleep_until(deadline) => panic!("Dial reservation was not released"),
            }
            assert!(
                context.current().duration_since(start).unwrap() >= dial_timeout,
                "Reservation released before the dial timeout"
            );
        });
    }

    #[test]
    fn test_dialer_dials_one_peer_per_tick() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let dial_frequency = Duration::from_millis(100);
            let tracker = Mock::new(10, Some(Duration::ZERO));
            let dials = tracker.dials.clone();
            run_for(
                &context,
                tracker,
                dial_frequency,
                Duration::from_secs(60),
                dial_frequency * 3,
            )
            .await;

            // Should have dialed ~3 peers (one per tick), not all 10 at once
            let dials = dials.load(Ordering::Relaxed);
            assert!((2..=4).contains(&dials), "expected 2-4 dials, got {dials}");
        });
    }

    #[test]
    fn test_dialer_uses_tracker_next_query_deadline() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            // Tracker reports next_query_at in the past, shorter than dial_frequency. The dialer
            // should clamp to dial_frequency, so we only get 1 refresh in 350ms instead of 3-4.
            let dial_frequency = Duration::from_millis(500);
            let mut tracker = Mock::new(0, Some(Duration::ZERO));
            tracker.next_query_in = Some(Duration::ZERO);
            let dialables = tracker.dialables.clone();
            run_for(
                &context,
                tracker,
                dial_frequency,
                dial_frequency,
                Duration::from_millis(350),
            )
            .await;
            assert_eq!(dialables.load(Ordering::Relaxed), 1);
        });
    }

    #[test]
    fn test_dialer_drains_queue_at_dial_frequency() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let tracker = Mock::new(3, None);
            let dials = tracker.dials.clone();
            run_for(
                &context,
                tracker,
                Duration::from_millis(100),
                Duration::from_secs(60),
                Duration::from_millis(250),
            )
            .await;
            assert_eq!(dials.load(Ordering::Relaxed), 3);
        });
    }

    #[test]
    fn test_dialer_does_not_panic_when_dial_frequency_exceeds_peer_connection_cooldown() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let tracker = Mock::new(0, None);
            let dialables = tracker.dialables.clone();
            run_for(
                &context,
                tracker,
                Duration::from_millis(200),
                Duration::from_millis(50),
                Duration::from_millis(350),
            )
            .await;
            assert_eq!(dialables.load(Ordering::Relaxed), 2);
        });
    }
}

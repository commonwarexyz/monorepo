//! Listener

use crate::authenticated::{
    lookup::actors::{spawner, tracker},
    Mailbox as SpawnerMailbox,
};
use commonware_actor::Feedback;
use commonware_cryptography::Signer;
use commonware_macros::select_loop;
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::{Counter, MetricsExt as _},
    BufferPooler, Clock, ContextCell, Handle, KeyedRateLimiter, Listener, Metrics, Network, Quota,
    SinkOf, Spawner, StreamOf,
};
use commonware_stream::encrypted::{listen, Config as StreamConfig};
use commonware_utils::{channel::ring, concurrency::Limiter, net::SubnetMask, IpAddrExt, NZUsize};
use futures::{Sink, StreamExt};
use rand_core::CryptoRngCore;
use std::{
    collections::HashSet,
    fmt,
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    pin::Pin,
};
use tracing::debug;

/// Subnet mask of `/24` for IPv4 and `/48` for IPv6 networks.
const SUBNET_MASK: SubnetMask = SubnetMask::new(24, 48);

/// Interval at which to prune tracked IPs and Subnets.
const CLEANUP_INTERVAL: u32 = 16_384;

pub(crate) type Updates = ring::Receiver<HashSet<IpAddr>>;

#[derive(Clone)]
pub(crate) struct Mailbox(ring::Sender<HashSet<IpAddr>>);

impl fmt::Debug for Mailbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Mailbox").finish()
    }
}

impl Mailbox {
    pub(crate) fn new() -> (Self, Updates) {
        let (sender, receiver) = ring::channel(NZUsize!(1));
        (Self(sender), receiver)
    }

    pub(crate) fn set(&mut self, registered_ips: HashSet<IpAddr>) -> Feedback {
        if Pin::new(&mut self.0).start_send(registered_ips).is_ok() {
            Feedback::Ok
        } else {
            Feedback::Closed
        }
    }
}

/// Configuration for the listener actor.
pub struct Config<C: Signer> {
    pub address: SocketAddr,
    pub stream_cfg: StreamConfig<C>,
    pub allow_private_ips: bool,
    pub bypass_ip_check: bool,
    pub max_concurrent_handshakes: NonZeroU32,
    pub allowed_handshake_rate_per_ip: Quota,
    pub allowed_handshake_rate_per_subnet: Quota,
}

pub struct Actor<E: Spawner + BufferPooler + Clock + Network + CryptoRngCore + Metrics, C: Signer> {
    context: ContextCell<E>,

    address: SocketAddr,
    stream_cfg: StreamConfig<C>,
    allow_private_ips: bool,
    bypass_ip_check: bool,
    handshake_limiter: Limiter,
    allowed_handshake_rate_per_ip: Quota,
    allowed_handshake_rate_per_subnet: Quota,
    registered_ips: HashSet<IpAddr>,
    updates: Updates,
    handshakes_blocked: Counter,
    handshakes_concurrent_rate_limited: Counter,
    handshakes_ip_rate_limited: Counter,
    handshakes_subnet_rate_limited: Counter,
}

impl<E: Spawner + BufferPooler + Clock + Network + CryptoRngCore + Metrics, C: Signer> Actor<E, C> {
    pub fn new(context: E, cfg: Config<C>, updates: Updates) -> Self {
        // Create metrics
        let handshakes_blocked = context.counter(
            "handshakes_blocked",
            "number of handshake attempts blocked because the IP was not registered",
        );
        let handshakes_concurrent_rate_limited = context.counter(
            "handshake_concurrent_rate_limited",
            "number of handshake attempts dropped because maximum concurrent handshakes was reached",
        );
        let handshakes_ip_rate_limited = context.counter(
            "handshake_ip_rate_limited",
            "number of handshake attempts dropped because an IP exceeded its rate limit",
        );
        let handshakes_subnet_rate_limited = context.counter(
            "handshake_subnet_rate_limited",
            "number of handshake attempts dropped because a subnet exceeded its rate limit",
        );

        Self {
            context: ContextCell::new(context),

            address: cfg.address,
            stream_cfg: cfg.stream_cfg,
            allow_private_ips: cfg.allow_private_ips,
            bypass_ip_check: cfg.bypass_ip_check,
            handshake_limiter: Limiter::new(cfg.max_concurrent_handshakes),
            allowed_handshake_rate_per_ip: cfg.allowed_handshake_rate_per_ip,
            allowed_handshake_rate_per_subnet: cfg.allowed_handshake_rate_per_subnet,
            registered_ips: HashSet::new(),
            updates,
            handshakes_blocked,
            handshakes_concurrent_rate_limited,
            handshakes_ip_rate_limited,
            handshakes_subnet_rate_limited,
        }
    }

    #[allow(clippy::type_complexity)]
    async fn handshake(
        context: E,
        address: SocketAddr,
        stream_cfg: StreamConfig<C>,
        sink: SinkOf<E>,
        stream: StreamOf<E>,
        tracker: tracker::Mailbox<C::PublicKey>,
        mut supervisor: SpawnerMailbox<spawner::Message<SinkOf<E>, StreamOf<E>, C::PublicKey>>,
    ) {
        // Perform handshake
        let source_ip = address.ip();
        let (peer, send, recv) = match listen(
            context,
            |peer| tracker.acceptable(peer, source_ip),
            stream_cfg,
            stream,
            sink,
        )
        .await
        {
            Ok(connection) => connection,
            Err(err) => {
                debug!(?err, ?address, "failed to upgrade connection");
                return;
            }
        };
        debug!(?peer, ?address, "completed handshake");

        // Attempt to claim the connection
        let Some(reservation) = tracker.listen(peer.clone()).await else {
            debug!(?peer, ?address, "unable to reserve connection to peer");
            return;
        };
        debug!(?peer, ?address, "reserved connection");

        // Start peer to handle messages
        let _ = supervisor.spawn((send, recv), reservation);
    }

    #[allow(clippy::type_complexity)]
    pub fn start(
        mut self,
        tracker: tracker::Mailbox<C::PublicKey>,
        supervisor: SpawnerMailbox<spawner::Message<SinkOf<E>, StreamOf<E>, C::PublicKey>>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(tracker, supervisor))
    }

    #[allow(clippy::type_complexity)]
    async fn run(
        mut self,
        tracker: tracker::Mailbox<C::PublicKey>,
        supervisor: SpawnerMailbox<spawner::Message<SinkOf<E>, StreamOf<E>, C::PublicKey>>,
    ) {
        // Setup the rate limiters
        let ip_rate_limiter = KeyedRateLimiter::hashmap_with_clock(
            self.allowed_handshake_rate_per_ip,
            self.context.child("ip_rate_limiter"),
        );
        let subnet_rate_limiter = KeyedRateLimiter::hashmap_with_clock(
            self.allowed_handshake_rate_per_subnet,
            self.context.child("subnet_rate_limiter"),
        );

        // Start listening for incoming connections
        let mut listener = self
            .context
            .bind(self.address)
            .await
            .expect("failed to bind listener");

        // Loop over incoming connections
        let mut accepted = 0;
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping listener");
            },
            Some(registered_ips) = self.updates.next() else {
                debug!("listener updates closed");
                break;
            } => {
                self.registered_ips = registered_ips;
            },
            listener = listener.accept() => {
                // Accept a new connection
                let (address, sink, stream) = match listener {
                    Ok((address, sink, stream)) => (address, sink, stream),
                    Err(e) => {
                        debug!(error = ?e, "failed to accept connection");
                        continue;
                    }
                };
                debug!(?address, "accepted incoming connection");

                // Check whether the IP is private
                let ip = address.ip();
                if !self.allow_private_ips && !IpAddrExt::is_global(&ip) {
                    self.handshakes_blocked.inc();
                    debug!(?address, "rejecting private address");
                    continue;
                }

                // Check whether the IP is registered
                if !self.bypass_ip_check && !self.registered_ips.contains(&ip) {
                    self.handshakes_blocked.inc();
                    debug!(?address, "rejecting unregistered address");
                    continue;
                }

                // Cleanup the rate limiters periodically
                if accepted > CLEANUP_INTERVAL {
                    ip_rate_limiter.retain_recent();
                    subnet_rate_limiter.retain_recent();
                    accepted = 0;
                }
                accepted += 1;

                // Check whether the IP (and subnet) exceeds its rate limit
                let ip_limited = if ip_rate_limiter.check_key(&ip).is_err() {
                    self.handshakes_ip_rate_limited.inc();
                    debug!(?address, "ip exceeded handshake rate limit");
                    true
                } else {
                    false
                };
                let subnet = ip.subnet(&SUBNET_MASK);
                let subnet_limited = if subnet_rate_limiter.check_key(&subnet).is_err() {
                    self.handshakes_subnet_rate_limited.inc();
                    debug!(?address, "subnet exceeded handshake rate limit");
                    true
                } else {
                    false
                };

                // We wait to check whether the handshake is permitted until after updating both the ip
                // and subnet rate limiters
                if ip_limited || subnet_limited {
                    continue;
                }

                // Check whether there are too many ongoing handshakes
                let Some(reservation) = self.handshake_limiter.try_acquire() else {
                    self.handshakes_concurrent_rate_limited.inc();
                    debug!(?address, "maximum concurrent handshakes reached");
                    continue;
                };

                // Spawn a new handshaker to upgrade connection
                self.context.child("handshaker").spawn({
                    let stream_cfg = self.stream_cfg.clone();
                    let tracker = tracker.clone();
                    let supervisor = supervisor.clone();
                    move |context| async move {
                        Self::handshake(
                            context, address, stream_cfg, sink, stream, tracker, supervisor,
                        )
                        .await;

                        // Once the handshake attempt is complete, release the reservation
                        drop(reservation);
                    }
                });
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_actor::mailbox;
    use commonware_cryptography::ed25519::{PrivateKey, PublicKey};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic, Error as RuntimeError, Runner as _, Stream, Supervisor as _,
    };
    use commonware_utils::{NZUsize, NZU32};
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    #[test]
    fn mailbox_keeps_latest_registered_ips() {
        let runner = deterministic::Runner::default();
        runner.start(|_| async move {
            let (mut mailbox, mut receiver) = Mailbox::new();
            let first = HashSet::from([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
            let second = HashSet::from([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))]);
            let third = HashSet::from([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))]);

            assert_eq!(mailbox.set(first), Feedback::Ok);
            assert_eq!(mailbox.set(second), Feedback::Ok);
            assert_eq!(mailbox.set(third.clone()), Feedback::Ok);

            assert_eq!(receiver.next().await, Some(third));
        });
    }

    fn check_rate_limits<CheckMetrics>(
        allowed_handshake_rate_per_ip: Quota,
        allowed_handshake_rate_per_subnet: Quota,
        check_metrics: CheckMetrics,
    ) where
        CheckMetrics: FnOnce(&str),
    {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30_101);
            let stream_cfg = StreamConfig {
                signing_key: PrivateKey::from_seed(1),
                namespace: b"test-rate-limit".to_vec(),
                max_message_size: 1024,
                synchrony_bound: Duration::from_secs(1),
                max_handshake_age: Duration::from_secs(1),
                handshake_timeout: Duration::from_millis(5),
            };

            let (mut updates_tx, updates_rx) = Mailbox::new();
            let actor = Actor::new(
                context.child("listener"),
                Config {
                    address,
                    stream_cfg,
                    allow_private_ips: true,
                    max_concurrent_handshakes: NZU32!(8),
                    bypass_ip_check: false,
                    allowed_handshake_rate_per_ip,
                    allowed_handshake_rate_per_subnet,
                },
                updates_rx,
            );

            let mut allowed = HashSet::new();
            allowed.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
            assert_eq!(updates_tx.set(allowed), Feedback::Ok);

            let (tracker_mailbox, mut tracker_rx) = mailbox::new::<tracker::Message<PublicKey>>(
                context.child("tracker_mailbox"),
                NZUsize!(1024),
            );
            let tracker_task = context.child("tracker").spawn(|_| async move {
                while let Some(message) = tracker_rx.recv().await {
                    match message {
                        tracker::Message::Acceptable { responder, .. } => {
                            let _ = responder.send(true);
                        }
                        tracker::Message::Listen { reservation, .. } => {
                            let _ = reservation.send(None);
                        }
                        tracker::Message::Release { .. } => {}
                        _ => panic!("unexpected tracker message"),
                    }
                }
            });

            let (supervisor_mailbox, mut supervisor_rx) =
                SpawnerMailbox::new(context.child("supervisor_mailbox"), NZUsize!(1));
            let supervisor_task = context
                .child("supervisor")
                .spawn(|_| async move { while supervisor_rx.recv().await.is_some() {} });
            let listener_handle =
                actor.start(tracker::Mailbox::new(tracker_mailbox), supervisor_mailbox);

            // Connect to the listener
            let (sink, mut stream) = loop {
                match context.dial(address).await {
                    Ok(pair) => break pair,
                    Err(RuntimeError::ConnectionFailed) => {
                        context.sleep(Duration::from_millis(1)).await;
                    }
                    Err(err) => panic!("unexpected dial error: {err:?}"),
                }
            };

            // Wait for some message or drop
            let _ = stream.recv(1).await;
            drop((sink, stream));

            // Additional attempts should be rate limited immediately
            for _ in 0..3 {
                let (sink, mut stream) = context.dial(address).await.expect("dial");

                // Wait for some message or drop
                let _ = stream.recv(1).await;
                drop((sink, stream));
            }

            let metrics = context.encode();
            check_metrics(&metrics);

            listener_handle.abort();
            tracker_task.abort();
            supervisor_task.abort();
        });
    }

    #[test_traced("DEBUG")]
    fn rate_limits_ip() {
        check_rate_limits(
            Quota::per_hour(NZU32!(1)),
            Quota::per_hour(NZU32!(100)),
            |metrics| {
                assert!(
                    metrics.contains("handshake_ip_rate_limited_total 3"),
                    "{}",
                    metrics
                );
                assert!(
                    metrics.contains("handshake_subnet_rate_limited_total 0"),
                    "{}",
                    metrics
                );
                assert!(
                    metrics.contains("handshakes_blocked_total 0"),
                    "{}",
                    metrics
                );
            },
        );
    }

    #[test_traced("DEBUG")]
    fn rate_limits_subnet() {
        check_rate_limits(
            Quota::per_hour(NZU32!(100)),
            Quota::per_hour(NZU32!(1)),
            |metrics| {
                assert!(
                    metrics.contains("handshake_subnet_rate_limited_total 3"),
                    "{}",
                    metrics
                );
                assert!(
                    metrics.contains("handshake_ip_rate_limited_total 0"),
                    "{}",
                    metrics
                );
                assert!(
                    metrics.contains("handshakes_blocked_total 0"),
                    "{}",
                    metrics
                );
            },
        );
    }

    #[test_traced("DEBUG")]
    fn rate_limits_both() {
        check_rate_limits(
            Quota::per_hour(NZU32!(1)),
            Quota::per_hour(NZU32!(1)),
            |metrics| {
                assert!(
                    metrics.contains("handshake_ip_rate_limited_total 3"),
                    "{}",
                    metrics
                );
                assert!(
                    metrics.contains("handshake_subnet_rate_limited_total 3"),
                    "{}",
                    metrics
                );
                assert!(
                    metrics.contains("handshakes_blocked_total 0"),
                    "{}",
                    metrics
                );
            },
        );
    }

    #[test_traced("DEBUG")]
    fn blocks_unregistered_ips() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30_101);
            let stream_cfg = StreamConfig {
                signing_key: PrivateKey::from_seed(1),
                namespace: b"test-rate-limit".to_vec(),
                max_message_size: 1024,
                synchrony_bound: Duration::from_secs(1),
                max_handshake_age: Duration::from_secs(1),
                handshake_timeout: Duration::from_millis(5),
            };

            let (_updates_tx, updates_rx) = Mailbox::new();
            let actor = Actor::new(
                context.child("listener"),
                Config {
                    address,
                    stream_cfg,
                    allow_private_ips: true,
                    bypass_ip_check: false,
                    max_concurrent_handshakes: NZU32!(8),
                    allowed_handshake_rate_per_ip: Quota::per_hour(NZU32!(100)),
                    allowed_handshake_rate_per_subnet: Quota::per_hour(NZU32!(100)),
                },
                updates_rx,
            );

            let (tracker_mailbox, mut tracker_rx) = mailbox::new::<tracker::Message<PublicKey>>(
                context.child("tracker_mailbox"),
                NZUsize!(1024),
            );
            let tracker_task = context.child("tracker").spawn(|_| async move {
                while let Some(message) = tracker_rx.recv().await {
                    match message {
                        tracker::Message::Acceptable { responder, .. } => {
                            let _ = responder.send(true);
                        }
                        tracker::Message::Listen { reservation, .. } => {
                            let _ = reservation.send(None);
                        }
                        tracker::Message::Release { .. } => {}
                        _ => panic!("unexpected tracker message"),
                    }
                }
            });

            let (supervisor_mailbox, mut supervisor_rx) =
                SpawnerMailbox::new(context.child("supervisor_mailbox"), NZUsize!(1));
            let supervisor_task = context
                .child("supervisor")
                .spawn(|_| async move { while supervisor_rx.recv().await.is_some() {} });
            let listener_handle =
                actor.start(tracker::Mailbox::new(tracker_mailbox), supervisor_mailbox);

            // Connect to the listener
            let (sink, mut stream) = loop {
                match context.dial(address).await {
                    Ok(pair) => break pair,
                    Err(RuntimeError::ConnectionFailed) => {
                        context.sleep(Duration::from_millis(1)).await;
                    }
                    Err(err) => panic!("unexpected dial error: {err:?}"),
                }
            };

            // Wait for some message or drop
            let _ = stream.recv(1).await;
            drop((sink, stream));

            // Check metrics
            let metrics = context.encode();
            assert!(
                metrics.contains("handshakes_blocked_total 1"),
                "{}",
                metrics
            );

            listener_handle.abort();
            tracker_task.abort();
            supervisor_task.abort();
        });
    }

    #[test_traced("DEBUG")]
    fn allows_unregistered_ips() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30_101);
            let stream_cfg = StreamConfig {
                signing_key: PrivateKey::from_seed(1),
                namespace: b"test-rate-limit".to_vec(),
                max_message_size: 1024,
                synchrony_bound: Duration::from_secs(1),
                max_handshake_age: Duration::from_secs(1),
                handshake_timeout: Duration::from_millis(5),
            };

            let (_updates_tx, updates_rx) = Mailbox::new();
            let actor = Actor::new(
                context.child("listener"),
                Config {
                    address,
                    stream_cfg,
                    allow_private_ips: true,
                    bypass_ip_check: true,
                    max_concurrent_handshakes: NZU32!(8),
                    allowed_handshake_rate_per_ip: Quota::per_hour(NZU32!(100)),
                    allowed_handshake_rate_per_subnet: Quota::per_hour(NZU32!(100)),
                },
                updates_rx,
            );

            let (tracker_mailbox, mut tracker_rx) = mailbox::new::<tracker::Message<PublicKey>>(
                context.child("tracker_mailbox"),
                NZUsize!(1024),
            );
            let tracker_task = context.child("tracker").spawn(|_| async move {
                while let Some(message) = tracker_rx.recv().await {
                    match message {
                        tracker::Message::Acceptable { responder, .. } => {
                            let _ = responder.send(true);
                        }
                        tracker::Message::Listen { reservation, .. } => {
                            let _ = reservation.send(None);
                        }
                        tracker::Message::Release { .. } => {}
                        _ => panic!("unexpected tracker message"),
                    }
                }
            });

            let (supervisor_mailbox, mut supervisor_rx) =
                SpawnerMailbox::new(context.child("supervisor_mailbox"), NZUsize!(1));
            let supervisor_task = context
                .child("supervisor")
                .spawn(|_| async move { while supervisor_rx.recv().await.is_some() {} });
            let listener_handle =
                actor.start(tracker::Mailbox::new(tracker_mailbox), supervisor_mailbox);

            // Connect to the listener
            let (sink, mut stream) = loop {
                match context.dial(address).await {
                    Ok(pair) => break pair,
                    Err(RuntimeError::ConnectionFailed) => {
                        context.sleep(Duration::from_millis(1)).await;
                    }
                    Err(err) => panic!("unexpected dial error: {err:?}"),
                }
            };

            // Wait for some message or drop
            let _ = stream.recv(1).await;
            drop((sink, stream));

            // Check metrics
            let metrics = context.encode();
            assert!(
                metrics.contains("handshakes_blocked_total 0"),
                "{}",
                metrics
            );

            listener_handle.abort();
            tracker_task.abort();
            supervisor_task.abort();
        });
    }

    #[test_traced("DEBUG")]
    fn blocks_private_ips() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30_101);
            let stream_cfg = StreamConfig {
                signing_key: PrivateKey::from_seed(1),
                namespace: b"test-private-ips".to_vec(),
                max_message_size: 1024,
                synchrony_bound: Duration::from_secs(1),
                max_handshake_age: Duration::from_secs(1),
                handshake_timeout: Duration::from_millis(5),
            };

            let (mut updates_tx, updates_rx) = Mailbox::new();
            let actor = Actor::new(
                context.child("listener"),
                Config {
                    address,
                    stream_cfg,
                    allow_private_ips: false,
                    bypass_ip_check: true,
                    max_concurrent_handshakes: NZU32!(8),
                    allowed_handshake_rate_per_ip: Quota::per_hour(NZU32!(100)),
                    allowed_handshake_rate_per_subnet: Quota::per_hour(NZU32!(100)),
                },
                updates_rx,
            );

            // Register the IP so it would be allowed if not for the private IP check
            let mut allowed = HashSet::new();
            allowed.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
            assert_eq!(updates_tx.set(allowed), Feedback::Ok);

            let (tracker_mailbox, mut tracker_rx) = mailbox::new::<tracker::Message<PublicKey>>(
                context.child("tracker_mailbox"),
                NZUsize!(1024),
            );
            let tracker_task = context.child("tracker").spawn(|_| async move {
                while let Some(message) = tracker_rx.recv().await {
                    match message {
                        tracker::Message::Acceptable { responder, .. } => {
                            let _ = responder.send(true);
                        }
                        tracker::Message::Listen { reservation, .. } => {
                            let _ = reservation.send(None);
                        }
                        tracker::Message::Release { .. } => {}
                        _ => panic!("unexpected tracker message"),
                    }
                }
            });

            let (supervisor_mailbox, mut supervisor_rx) =
                SpawnerMailbox::new(context.child("supervisor_mailbox"), NZUsize!(1));
            let supervisor_task = context
                .child("supervisor")
                .spawn(|_| async move { while supervisor_rx.recv().await.is_some() {} });
            let listener_handle =
                actor.start(tracker::Mailbox::new(tracker_mailbox), supervisor_mailbox);

            // Connect to the listener from a private IP
            let (sink, mut stream) = loop {
                match context.dial(address).await {
                    Ok(pair) => break pair,
                    Err(RuntimeError::ConnectionFailed) => {
                        context.sleep(Duration::from_millis(1)).await;
                    }
                    Err(err) => panic!("unexpected dial error: {err:?}"),
                }
            };

            // Wait for some message or drop
            let _ = stream.recv(1).await;
            drop((sink, stream));

            // Check metrics - should be blocked because it's a private IP
            let metrics = context.encode();
            assert!(
                metrics.contains("handshakes_blocked_total 1"),
                "{}",
                metrics
            );

            listener_handle.abort();
            tracker_task.abort();
            supervisor_task.abort();
        });
    }
}

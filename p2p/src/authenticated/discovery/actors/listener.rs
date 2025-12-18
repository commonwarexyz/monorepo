//! Listener

use crate::authenticated::{
    discovery::actors::{spawner, tracker},
    mailbox::UnboundedMailbox,
    Mailbox,
};
use commonware_cryptography::Signer;
use commonware_macros::select_loop;
use commonware_runtime::{
    spawn_cell, Clock, ContextCell, Handle, KeyedRateLimiter, Listener, Metrics, Network, Quota,
    SinkOf, Spawner, StreamOf,
};
use commonware_stream::{listen, Config as StreamConfig};
use commonware_utils::{concurrency::Limiter, net::SubnetMask, IpAddrExt};
use prometheus_client::metrics::counter::Counter;
use rand::{CryptoRng, Rng};
use std::{net::SocketAddr, num::NonZeroU32};
use tracing::debug;

/// Subnet mask of `/24` for IPv4 and `/48` for IPv6 networks.
const SUBNET_MASK: SubnetMask = SubnetMask::new(24, 48);

/// Interval at which to prune tracked IPs and Subnets.
const CLEANUP_INTERVAL: u32 = 16_384;

/// Configuration for the listener actor.
pub struct Config<C: Signer> {
    pub address: SocketAddr,
    pub stream_cfg: StreamConfig<C>,
    pub allow_private_ips: bool,
    pub max_concurrent_handshakes: NonZeroU32,
    pub allowed_handshake_rate_per_ip: Quota,
    pub allowed_handshake_rate_per_subnet: Quota,
}

pub struct Actor<E: Spawner + Clock + Network + Rng + CryptoRng + Metrics, C: Signer> {
    context: ContextCell<E>,

    address: SocketAddr,
    stream_cfg: StreamConfig<C>,
    allow_private_ips: bool,
    handshake_limiter: Limiter,
    allowed_handshake_rate_per_ip: Quota,
    allowed_handshake_rate_per_subnet: Quota,
    handshakes_blocked: Counter,
    handshakes_concurrent_rate_limited: Counter,
    handshakes_ip_rate_limited: Counter,
    handshakes_subnet_rate_limited: Counter,
}

impl<E: Spawner + Clock + Network + Rng + CryptoRng + Metrics, C: Signer> Actor<E, C> {
    pub fn new(context: E, cfg: Config<C>) -> Self {
        // Create metrics
        let handshakes_blocked = Counter::default();
        context.register(
            "handshakes_blocked",
            "number of handshake attempts blocked because the IP was private",
            handshakes_blocked.clone(),
        );
        let handshakes_concurrent_rate_limited = Counter::default();
        context.register(
            "handshake_concurrent_rate_limited",
            "number of handshake attempts dropped because maximum concurrent handshakes was reached",
            handshakes_concurrent_rate_limited.clone(),
        );
        let handshakes_ip_rate_limited = Counter::default();
        context.register(
            "handshake_ip_rate_limited",
            "number of handshake attempts dropped because an IP exceeded its rate limit",
            handshakes_ip_rate_limited.clone(),
        );
        let handshakes_subnet_rate_limited = Counter::default();
        context.register(
            "handshake_subnet_rate_limited",
            "number of handshake attempts dropped because a subnet exceeded its rate limit",
            handshakes_subnet_rate_limited.clone(),
        );

        Self {
            context: ContextCell::new(context),

            address: cfg.address,
            stream_cfg: cfg.stream_cfg,
            allow_private_ips: cfg.allow_private_ips,
            handshake_limiter: Limiter::new(cfg.max_concurrent_handshakes),
            allowed_handshake_rate_per_ip: cfg.allowed_handshake_rate_per_ip,
            allowed_handshake_rate_per_subnet: cfg.allowed_handshake_rate_per_subnet,
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
        mut tracker: UnboundedMailbox<tracker::Message<C::PublicKey>>,
        mut supervisor: Mailbox<spawner::Message<SinkOf<E>, StreamOf<E>, C::PublicKey>>,
    ) {
        let (peer, send, recv) = match listen(
            context,
            |peer| tracker.acceptable(peer),
            stream_cfg,
            stream,
            sink,
        )
        .await
        {
            Ok(x) => x,
            Err(err) => {
                debug!(?err, "failed to complete handshake");
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
        supervisor.spawn((send, recv), reservation).await;
    }

    #[allow(clippy::type_complexity)]
    pub fn start(
        mut self,
        tracker: UnboundedMailbox<tracker::Message<C::PublicKey>>,
        supervisor: Mailbox<spawner::Message<SinkOf<E>, StreamOf<E>, C::PublicKey>>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(tracker, supervisor).await)
    }

    #[allow(clippy::type_complexity)]
    async fn run(
        self,
        tracker: UnboundedMailbox<tracker::Message<C::PublicKey>>,
        supervisor: Mailbox<spawner::Message<SinkOf<E>, StreamOf<E>, C::PublicKey>>,
    ) {
        // Create the rate limiters
        let ip_rate_limiter = KeyedRateLimiter::hashmap_with_clock(
            self.allowed_handshake_rate_per_ip,
            self.context.clone(),
        );
        let subnet_rate_limiter = KeyedRateLimiter::hashmap_with_clock(
            self.allowed_handshake_rate_per_subnet,
            self.context.clone(),
        );

        // Start listening for incoming connections
        let mut listener = self
            .context
            .bind(self.address)
            .await
            .expect("failed to bind listener");

        // Loop over incoming connections as fast as our rate limiter allows
        let mut accepted = 0;
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping listener");
            },
            conn = listener.accept() => {
                // Accept a new connection
                let (address, sink, stream) = match conn {
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

                // Cleanup the rate limiters periodically
                if accepted > CLEANUP_INTERVAL {
                    ip_rate_limiter.shrink_to_fit();
                    subnet_rate_limiter.shrink_to_fit();
                    accepted = 0;
                }
                accepted += 1;
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
                self.context.with_label("handshaker").spawn({
                    let stream_cfg = self.stream_cfg.clone();
                    let tracker = tracker.clone();
                    let supervisor = supervisor.clone();
                    move |context| async move {
                        Self::handshake(
                            context.into(),
                            address,
                            stream_cfg,
                            sink,
                            stream,
                            tracker,
                            supervisor,
                        )
                        .await;

                        // Once the handshake attempt is complete, release the reservation
                        drop(reservation);
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::ed25519::PrivateKey;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Error as RuntimeError, Runner as _, Stream};
    use commonware_utils::NZU32;
    use futures::StreamExt as _;
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    fn check_rate_limits<CheckMetrics>(
        allowed_handshake_rate_per_ip: Quota,
        allowed_handshake_rate_per_subnet: Quota,
        check_metrics: CheckMetrics,
    ) where
        CheckMetrics: FnOnce(&str),
    {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30_001);
            let stream_cfg = StreamConfig {
                signing_key: PrivateKey::from_seed(1),
                namespace: b"test-rate-limit".to_vec(),
                max_message_size: 1024,
                synchrony_bound: Duration::from_secs(1),
                max_handshake_age: Duration::from_secs(1),
                handshake_timeout: Duration::from_millis(5),
            };

            let actor = Actor::new(
                context.clone(),
                Config {
                    address,
                    stream_cfg,
                    allow_private_ips: true,
                    max_concurrent_handshakes: NZU32!(8),
                    allowed_handshake_rate_per_ip,
                    allowed_handshake_rate_per_subnet,
                },
            );

            let (tracker_mailbox, mut tracker_rx) = UnboundedMailbox::new();
            let tracker_task = context.clone().spawn(|_| async move {
                while let Some(message) = tracker_rx.next().await {
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

            let (supervisor_mailbox, mut supervisor_rx) = Mailbox::new(1);
            let supervisor_task = context
                .clone()
                .spawn(|_| async move { while supervisor_rx.next().await.is_some() {} });
            let listener_handle = actor.start(tracker_mailbox, supervisor_mailbox);

            // Allow a single handshake attempt from this IP.
            let (sink, mut stream) = loop {
                match context.dial(address).await {
                    Ok(pair) => break pair,
                    Err(RuntimeError::ConnectionFailed) => {
                        context.sleep(Duration::from_millis(1)).await;
                    }
                    Err(err) => panic!("unexpected dial error: {err:?}"),
                }
            };

            // Wait for some message or drop.
            let buf = vec![0u8; 1];
            let _ = stream.recv(buf).await;
            drop((sink, stream));

            // Additional attempts should be rate limited immediately.
            for _ in 0..3 {
                let (sink, mut stream) = context.dial(address).await.expect("dial");

                // Wait for some message or drop.
                let buf = vec![0u8; 1];
                let _ = stream.recv(buf).await;
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
            },
        );
    }

    #[test_traced("DEBUG")]
    fn blocks_private_ips() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30_001);
            let stream_cfg = StreamConfig {
                signing_key: PrivateKey::from_seed(1),
                namespace: b"test-private-ips".to_vec(),
                max_message_size: 1024,
                synchrony_bound: Duration::from_secs(1),
                max_handshake_age: Duration::from_secs(1),
                handshake_timeout: Duration::from_millis(5),
            };

            let actor = Actor::new(
                context.clone(),
                Config {
                    address,
                    stream_cfg,
                    allow_private_ips: false,
                    max_concurrent_handshakes: NZU32!(8),
                    allowed_handshake_rate_per_ip: Quota::per_hour(NZU32!(100)),
                    allowed_handshake_rate_per_subnet: Quota::per_hour(NZU32!(100)),
                },
            );

            let (tracker_mailbox, mut tracker_rx) = UnboundedMailbox::new();
            let tracker_task = context.clone().spawn(|_| async move {
                while let Some(message) = tracker_rx.next().await {
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

            let (supervisor_mailbox, mut supervisor_rx) = Mailbox::new(1);
            let supervisor_task = context
                .clone()
                .spawn(|_| async move { while supervisor_rx.next().await.is_some() {} });
            let listener_handle = actor.start(tracker_mailbox, supervisor_mailbox);

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
            let buf = vec![0u8; 1];
            let _ = stream.recv(buf).await;
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

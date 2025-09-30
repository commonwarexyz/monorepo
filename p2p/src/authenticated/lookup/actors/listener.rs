//! Listener

use crate::authenticated::{
    lookup::actors::{spawner, tracker},
    Mailbox,
};
use commonware_cryptography::Signer;
use commonware_runtime::{Clock, Handle, Listener, Metrics, Network, SinkOf, Spawner, StreamOf};
use commonware_stream::{listen, Config as StreamConfig};
use commonware_utils::{IpAddrExt, Limiter, Subnet};
use governor::{
    clock::ReasonablyRealtime, middleware::NoOpMiddleware, state::keyed::HashMapStateStore, Quota,
    RateLimiter,
};
use prometheus_client::metrics::counter::Counter;
use rand::{CryptoRng, Rng};
use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
};
use tracing::debug;

/// Interval at which to cleanup the rate limiters.
const CLEANUP_INTERVAL: u32 = 16_384;

/// Configuration for the listener actor.
pub struct Config<C: Signer> {
    pub address: SocketAddr,
    pub stream_cfg: StreamConfig<C>,
    pub max_concurrent_handshakes: NonZeroU32,
    pub allowed_handshake_rate_per_ip: Quota,
    pub allowed_handshake_rate_per_subnet: Quota,
}

pub struct Actor<
    E: Spawner + Clock + ReasonablyRealtime + Network + Rng + CryptoRng + Metrics,
    C: Signer,
> {
    context: E,

    address: SocketAddr,
    stream_cfg: StreamConfig<C>,
    handshakes: Limiter,
    ip_rate_limiter: RateLimiter<IpAddr, HashMapStateStore<IpAddr>, E, NoOpMiddleware<E::Instant>>,
    subnet_rate_limiter:
        RateLimiter<Subnet, HashMapStateStore<Subnet>, E, NoOpMiddleware<E::Instant>>,
    handshakes_dropped: Counter,
    handshakes_ip_rate_limited: Counter,
    handshakes_subnet_rate_limited: Counter,
}

impl<E: Spawner + Clock + ReasonablyRealtime + Network + Rng + CryptoRng + Metrics, C: Signer>
    Actor<E, C>
{
    pub fn new(context: E, cfg: Config<C>) -> Self {
        // Create metrics
        let handshakes_dropped = Counter::default();
        context.register(
            "handshake_dropped",
            "number of handshakes dropped because maximum concurrent handshakes was reached",
            handshakes_dropped.clone(),
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
            context: context.clone(),

            address: cfg.address,
            stream_cfg: cfg.stream_cfg,
            handshakes: Limiter::new(cfg.max_concurrent_handshakes.get()),
            ip_rate_limiter: RateLimiter::hashmap_with_clock(
                cfg.allowed_handshake_rate_per_ip,
                &context,
            ),
            subnet_rate_limiter: RateLimiter::hashmap_with_clock(
                cfg.allowed_handshake_rate_per_subnet,
                &context,
            ),
            handshakes_dropped,
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
        mut tracker: Mailbox<tracker::Message<E, C::PublicKey>>,
        mut supervisor: Mailbox<spawner::Message<E, SinkOf<E>, StreamOf<E>, C::PublicKey>>,
    ) {
        // Perform handshake
        let (peer, send, recv) = match listen(
            context,
            |peer| tracker.listenable(peer),
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
        supervisor.spawn((send, recv), reservation).await;
    }

    #[allow(clippy::type_complexity)]
    pub fn start(
        self,
        tracker: Mailbox<tracker::Message<E, C::PublicKey>>,
        supervisor: Mailbox<spawner::Message<E, SinkOf<E>, StreamOf<E>, C::PublicKey>>,
    ) -> Handle<()> {
        self.context
            .clone()
            .spawn(|_| self.run(tracker, supervisor))
    }

    #[allow(clippy::type_complexity)]
    async fn run(
        self,
        tracker: Mailbox<tracker::Message<E, C::PublicKey>>,
        supervisor: Mailbox<spawner::Message<E, SinkOf<E>, StreamOf<E>, C::PublicKey>>,
    ) {
        // Start listening for incoming connections
        let mut listener = self
            .context
            .bind(self.address)
            .await
            .expect("failed to bind listener");

        // Loop over incoming connections
        let mut limited = 0;
        loop {
            // Accept a new connection
            let (address, sink, stream) = match listener.accept().await {
                Ok((address, sink, stream)) => (address, sink, stream),
                Err(e) => {
                    debug!(error = ?e, "failed to accept connection");
                    continue;
                }
            };
            debug!(?address, "accepted incoming connection");

            // Cleanup the rate limiters periodically
            if limited > CLEANUP_INTERVAL {
                self.ip_rate_limiter.shrink_to_fit();
                self.subnet_rate_limiter.shrink_to_fit();
                limited = 0;
            }

            // Drop the connection if the IP exceeds its rate limit
            let ip = address.ip();
            if self.ip_rate_limiter.check_key(&ip).is_err() {
                self.handshakes_ip_rate_limited.inc();
                debug!(ip = ?address.ip(), "ip exceeded handshake rate limit");
                continue;
            }
            let subnet = ip.subnet();
            if self.subnet_rate_limiter.check_key(&subnet).is_err() {
                self.handshakes_subnet_rate_limited.inc();
                debug!(ip = ?address.ip(), subnet = ?subnet, "subnet exceeded handshake rate limit");
                continue;
            }

            // Attempt to reserve a slot for the handshake
            let Some(reservation) = self.handshakes.try_acquire() else {
                self.handshakes_dropped.inc();
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
                        context, address, stream_cfg, sink, stream, tracker, supervisor,
                    )
                    .await;

                    // Once the handshake attempt is complete, release the reservation
                    drop(reservation);
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{ed25519::PrivateKey, PrivateKeyExt as _};
    use commonware_runtime::{deterministic, Error as RuntimeError, Runner as _};
    use futures::StreamExt as _;
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    #[test]
    fn increments_ip_rate_limit_metric() {
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

            let actor = Actor::new(
                context.clone(),
                Config {
                    address,
                    stream_cfg,
                    max_concurrent_handshakes: NonZeroU32::new(8).expect("non-zero"),
                    allowed_handshake_rate_per_ip: Quota::per_hour(NonZeroU32::new(1).unwrap()),
                    allowed_handshake_rate_per_subnet: Quota::per_hour(
                        NonZeroU32::new(64).unwrap(),
                    ),
                },
            );

            let (tracker_mailbox, mut tracker_rx) = Mailbox::test();
            let tracker_task = context.clone().spawn(|_| async move {
                while let Some(message) = tracker_rx.next().await {
                    match message {
                        tracker::Message::Listenable { responder, .. } => {
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

            let (supervisor_mailbox, mut supervisor_rx) = Mailbox::test();
            let supervisor_task = context
                .clone()
                .spawn(|_| async move { while supervisor_rx.next().await.is_some() {} });

            let listener_handle = actor.start(tracker_mailbox, supervisor_mailbox);

            let (sink, stream) = loop {
                match context.dial(address).await {
                    Ok(pair) => break pair,
                    Err(RuntimeError::ConnectionFailed) => {
                        context.sleep(Duration::from_millis(1)).await;
                    }
                    Err(err) => panic!("unexpected dial error: {err:?}"),
                }
            };
            drop((sink, stream));
            context.sleep(Duration::from_millis(10)).await;

            for _ in 0..3 {
                let (sink, stream) = context.dial(address).await.expect("dial");
                drop((sink, stream));
                context.sleep(Duration::from_millis(1)).await;
            }

            context.sleep(Duration::from_millis(10)).await;
            let metrics = context.encode();
            assert!(
                metrics.contains("handshake_ip_rate_limited_total 3"),
                "{}",
                metrics
            );

            listener_handle.abort();
            tracker_task.abort();
            supervisor_task.abort();
        });
    }
}

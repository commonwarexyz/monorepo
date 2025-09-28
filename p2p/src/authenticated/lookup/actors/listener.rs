//! Listener

use crate::authenticated::{
    lookup::actors::{spawner, tracker},
    Mailbox,
};
use commonware_cryptography::Signer;
use commonware_runtime::{Clock, Handle, Listener, Metrics, Network, RwLock, SinkOf, Spawner, StreamOf};
use commonware_stream::{listen, Config as StreamConfig};
use governor::{
    clock::ReasonablyRealtime, middleware::NoOpMiddleware, state::keyed::HashMapStateStore, Quota,
    RateLimiter,
};
use prometheus_client::metrics::counter::Counter;
use rand::{CryptoRng, Rng};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};
use tracing::debug;

/// Configuration for the listener actor.
pub struct Config<C: Signer> {
    pub address: SocketAddr,
    pub stream_cfg: StreamConfig<C>,
    pub max_concurrent_handshakes: NonZeroU32,
    pub allowed_handshake_rate_per_ip: Quota,
    pub allowed_handshake_rate_per_peer: Quota,
}

pub struct Actor<
    E: Spawner + Clock + ReasonablyRealtime + Network + Rng + CryptoRng + Metrics,
    C: Signer,
> {
    context: E,

    address: SocketAddr,
    stream_cfg: StreamConfig<C>,
    max_concurrent_handshakes: u32,
    in_flight_handshakes: Arc<AtomicU32>,
    ip_rate_limiter:
        Arc<RateLimiter<IpAddr, HashMapStateStore<IpAddr>, E, NoOpMiddleware<E::Instant>>>,
    peer_rate_limiter: Arc<
        RateLimiter<C::PublicKey, HashMapStateStore<C::PublicKey>, E, NoOpMiddleware<E::Instant>>,
    >,
    prioritized_ips: Arc<RwLock<HashMap<IpAddr, HashSet<C::PublicKey>>>>,

    handshakes_rate_limited: Counter,
    handshakes_ip_rate_limited: Counter,
    handshakes_peer_rate_limited: Counter,
}

impl<E: Spawner + Clock + ReasonablyRealtime + Network + Rng + CryptoRng + Metrics, C: Signer>
    Actor<E, C>
{
    pub fn new(context: E, cfg: Config<C>) -> Self {
        // Create metrics
        let handshakes_rate_limited = Counter::default();
        context.register(
            "handshake_rate_limited",
            "number of handshakes dropped because maximum concurrent handshakes was reached",
            handshakes_rate_limited.clone(),
        );
        let handshakes_ip_rate_limited = Counter::default();
        context.register(
            "handshake_ip_rate_limited",
            "number of handshake attempts dropped because an IP exceeded its rate limit",
            handshakes_ip_rate_limited.clone(),
        );
        let handshakes_peer_rate_limited = Counter::default();
        context.register(
            "handshake_peer_rate_limited",
            "number of handshake attempts dropped because a peer exceeded its rate limit",
            handshakes_peer_rate_limited.clone(),
        );

        Self {
            context: context.clone(),

            address: cfg.address,
            stream_cfg: cfg.stream_cfg,
            max_concurrent_handshakes: cfg.max_concurrent_handshakes.get(),
            in_flight_handshakes: Arc::new(AtomicU32::new(0)),
            ip_rate_limiter: Arc::new(RateLimiter::hashmap_with_clock(
                cfg.allowed_handshake_rate_per_ip,
                &context,
            )),
            peer_rate_limiter: Arc::new(RateLimiter::hashmap_with_clock(
                cfg.allowed_handshake_rate_per_peer,
                &context,
            )),
            prioritized_ips: Arc::new(RwLock::new(HashMap::new())),

            handshakes_rate_limited,
            handshakes_ip_rate_limited,
            handshakes_peer_rate_limited,
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
        peer_rate_limiter: Arc<
            RateLimiter<
                C::PublicKey,
                HashMapStateStore<C::PublicKey>,
                E,
                NoOpMiddleware<E::Instant>,
            >,
        >,
        prioritized_ips: Arc<RwLock<HashMap<IpAddr, HashSet<C::PublicKey>>>>,
        handshakes_peer_rate_limited: Counter,
        _in_flight: InFlightGuard,
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

        if peer_rate_limiter.check_key(&peer).is_err() {
            handshakes_peer_rate_limited.inc();
            debug!(?peer, ?address, "peer exceeded handshake rate limit");
            return;
        }

        // Attempt to claim the connection
        let Some(reservation) = tracker.listen(peer.clone()).await else {
            debug!(?peer, ?address, "unable to reserve connection to peer");
            return;
        };
        debug!(?peer, ?address, "reserved connection");

        {
            let mut guard = prioritized_ips.write().await;
            guard.entry(address.ip()).or_default().insert(peer.clone());
        }

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
        'accept: loop {
            // Accept a new connection
            let (address, sink, stream) = match listener.accept().await {
                Ok((address, sink, stream)) => (address, sink, stream),
                Err(e) => {
                    debug!(error = ?e, "failed to accept connection");
                    continue;
                }
            };
            debug!(ip = ?address.ip(), port = ?address.port(), "accepted incoming connection");

            let prioritized_ip = {
                let guard = self.prioritized_ips.read().await;
                guard.get(&address.ip()).is_some_and(|set| !set.is_empty())
            };

            if self.ip_rate_limiter.check_key(&address.ip()).is_err() {
                self.handshakes_ip_rate_limited.inc();
                debug!(ip = ?address.ip(), "ip exceeded handshake rate limit");
                continue;
            }

            let in_flight = loop {
                let result = self.in_flight_handshakes.fetch_update(
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                    |current| (current < self.max_concurrent_handshakes).then_some(current + 1),
                );
                match result {
                    Ok(_) => break InFlightGuard::new(self.in_flight_handshakes.clone()),
                    Err(_) if prioritized_ip => {
                        self.context.sleep(Duration::from_millis(1)).await;
                    }
                    Err(_) => {
                        self.handshakes_rate_limited.inc();
                        debug!(?address, "maximum concurrent handshakes reached");
                        continue 'accept;
                    }
                }
            };

            // Spawn a new handshaker to upgrade connection
            self.context.with_label("handshaker").spawn({
                let stream_cfg = self.stream_cfg.clone();
                let tracker = tracker.clone();
                let supervisor = supervisor.clone();
                let peer_rate_limiter = self.peer_rate_limiter.clone();
                let prioritized_ips = self.prioritized_ips.clone();
                let handshakes_peer_rate_limited = self.handshakes_peer_rate_limited.clone();
                let in_flight = in_flight;
                move |context| {
                    Self::handshake(
                        context,
                        address,
                        stream_cfg,
                        sink,
                        stream,
                        tracker,
                        supervisor,
                        peer_rate_limiter,
                        prioritized_ips,
                        handshakes_peer_rate_limited,
                        in_flight,
                    )
                }
            });
        }
    }
}

struct InFlightGuard {
    counter: Arc<AtomicU32>,
}

impl InFlightGuard {
    fn new(counter: Arc<AtomicU32>) -> Self {
        Self { counter }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
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
                    allowed_handshake_rate_per_peer: Quota::per_hour(NonZeroU32::new(16).unwrap()),
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

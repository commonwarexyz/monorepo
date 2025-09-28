//! Listener

use crate::authenticated::{
    discovery::actors::{spawner, tracker},
    Mailbox,
};
use commonware_cryptography::Signer;
use commonware_runtime::{Clock, Handle, Listener, Metrics, Network, SinkOf, Spawner, StreamOf};
use commonware_stream::{listen, Config as StreamConfig};
use governor::{
    clock::ReasonablyRealtime, middleware::NoOpMiddleware, state::keyed::HashMapStateStore, Quota,
    RateLimiter,
};
use prometheus_client::metrics::counter::Counter;
use rand::{CryptoRng, Rng};
use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
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
    peer_rate_limiter:
        Arc<RateLimiter<C::PublicKey, HashMapStateStore<C::PublicKey>, E, NoOpMiddleware<E::Instant>>>,

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
        handshakes_peer_rate_limited: Counter,
        _in_flight: InFlightGuard,
    ) {
        let (peer, send, recv) = match listen(
            context,
            |peer| tracker.listenable(peer),
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

        // Loop over incoming connections as fast as our rate limiter allows
        loop {
            // Accept a new connection
            let (address, sink, stream) = match listener.accept().await {
                Ok((address, sink, stream)) => (address, sink, stream),
                Err(e) => {
                    debug!(error = ?e, "failed to accept connection");
                    continue;
                }
            };
            debug!(ip = ?address.ip(), port = ?address.port(), "accepted incoming connection");

            // Drop the connection if the IP exceeds its rate limit
            if self.ip_rate_limiter.check_key(&address.ip()).is_err() {
                self.handshakes_ip_rate_limited.inc();
                debug!(ip = ?address.ip(), "ip exceeded handshake rate limit");
                continue;
            }

            // Attempt to reserve a slot for the handshake
            let Ok(_) = self.in_flight_handshakes.fetch_update(
                Ordering::AcqRel,
                Ordering::Relaxed,
                |current| (current < self.max_concurrent_handshakes).then_some(current + 1),
            ) else {
                self.handshakes_rate_limited.inc();
                debug!(?address, "maximum concurrent handshakes reached");
                continue;
            };

            let in_flight = InFlightGuard::new(self.in_flight_handshakes.clone());

            // Spawn a new handshaker to upgrade connection
            self.context.with_label("handshaker").spawn({
                let stream_cfg = self.stream_cfg.clone();
                let tracker = tracker.clone();
                let supervisor = supervisor.clone();
                let peer_rate_limiter = self.peer_rate_limiter.clone();
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

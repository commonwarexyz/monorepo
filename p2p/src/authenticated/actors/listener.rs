//! Listener

use crate::authenticated::actors::{spawner, tracker};
use commonware_cryptography::Scheme;
use commonware_runtime::{
    telemetry::traces::status, Clock, Handle, Listener, Metrics, Network, SinkOf, Spawner, StreamOf,
};
use commonware_stream::public_key::{Config as StreamConfig, Connection, IncomingConnection};
use governor::{
    clock::ReasonablyRealtime,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use prometheus_client::metrics::counter::Counter;
use rand::{CryptoRng, Rng};
use std::net::SocketAddr;
use tracing::{debug, debug_span, Instrument};

/// Configuration for the listener actor.
pub struct Config<C: Scheme> {
    pub address: SocketAddr,
    pub stream_cfg: StreamConfig<C>,
    pub allowed_incoming_connection_rate: Quota,
}

pub struct Actor<
    E: Spawner + Clock + ReasonablyRealtime + Network + Rng + CryptoRng + Metrics,
    C: Scheme,
> {
    context: E,

    address: SocketAddr,
    stream_cfg: StreamConfig<C>,
    rate_limiter: RateLimiter<NotKeyed, InMemoryState, E, NoOpMiddleware<E::Instant>>,

    handshakes_rate_limited: Counter,
}

impl<E: Spawner + Clock + ReasonablyRealtime + Network + Rng + CryptoRng + Metrics, C: Scheme>
    Actor<E, C>
{
    pub fn new(context: E, cfg: Config<C>) -> Self {
        // Create metrics
        let handshakes_rate_limited = Counter::default();
        context.register(
            "handshake_rate_limited",
            "number of handshakes rate limited",
            handshakes_rate_limited.clone(),
        );

        Self {
            context: context.clone(),

            address: cfg.address,
            stream_cfg: cfg.stream_cfg,
            rate_limiter: RateLimiter::direct_with_clock(
                cfg.allowed_incoming_connection_rate,
                &context,
            ),

            handshakes_rate_limited,
        }
    }

    async fn handshake(
        context: E,
        address: SocketAddr,
        stream_cfg: StreamConfig<C>,
        sink: SinkOf<E>,
        stream: StreamOf<E>,
        mut tracker: tracker::Mailbox<E, C>,
        mut supervisor: spawner::Mailbox<E, SinkOf<E>, StreamOf<E>, C::PublicKey>,
    ) {
        // Create span
        let span = debug_span!("listener", ?address);
        let guard = span.enter();

        // Wait for the peer to send us their public key
        //
        // IncomingConnection limits how long we will wait for the peer to send us their public key
        // to ensure an adversary can't force us to hold many pending connections open.
        let incoming = match IncomingConnection::verify(&context, stream_cfg, sink, stream)
            .instrument(debug_span!("verify"))
            .await
        {
            Ok(partial) => partial,
            Err(e) => {
                status::error(&span, "failed to verify incoming handshake", Some(&e));
                return;
            }
        };
        span.record("peer", incoming.peer().to_string());

        // Attempt to claim the connection
        //
        // Reserve also checks if the peer is authorized.
        let peer = incoming.peer();
        let Some(reservation) = tracker
            .listen(peer.clone())
            .instrument(debug_span!("reserve"))
            .await
        else {
            status::error(&span, "unable to reserve connection to peer", None);
            return;
        };

        // Perform handshake
        let stream = match Connection::upgrade_listener(context, incoming)
            .instrument(debug_span!("upgrade"))
            .await
        {
            Ok(connection) => connection,
            Err(e) => {
                status::error(&span, "failed to upgrade connection", Some(&e));
                return;
            }
        };
        debug!(?peer, "upgraded connection");

        // Drop guard
        status::ok(&span);
        drop(guard);

        // Start peer to handle messages
        supervisor.spawn(stream, reservation).await;
    }

    pub fn start(
        self,
        tracker: tracker::Mailbox<E, C>,
        supervisor: spawner::Mailbox<E, SinkOf<E>, StreamOf<E>, C::PublicKey>,
    ) -> Handle<()> {
        self.context
            .clone()
            .spawn(|_| self.run(tracker, supervisor))
    }

    async fn run(
        self,
        tracker: tracker::Mailbox<E, C>,
        supervisor: spawner::Mailbox<E, SinkOf<E>, StreamOf<E>, C::PublicKey>,
    ) {
        // Start listening for incoming connections
        let mut listener = self
            .context
            .bind(self.address)
            .await
            .expect("failed to bind listener");

        // Loop over incoming connections as fast as our rate limiter allows
        loop {
            // Ensure we don't attempt to perform too many handshakes at once
            match self.rate_limiter.check() {
                Ok(_) => {}
                Err(negative) => {
                    self.handshakes_rate_limited.inc();
                    let wait = negative.wait_time_from(self.context.now());
                    self.context.sleep(wait).await;
                }
            }

            // Accept a new connection
            let (address, sink, stream) = match listener.accept().await {
                Ok((address, sink, stream)) => (address, sink, stream),
                Err(e) => {
                    debug!(error = ?e, "failed to accept connection");
                    continue;
                }
            };
            debug!(ip = ?address.ip(), port = ?address.port(), "accepted incoming connection");

            // Spawn a new handshaker to upgrade connection
            self.context.with_label("handshaker").spawn({
                let stream_cfg = self.stream_cfg.clone();
                let tracker = tracker.clone();
                let supervisor = supervisor.clone();
                move |context| {
                    Self::handshake(
                        context, address, stream_cfg, sink, stream, tracker, supervisor,
                    )
                }
            });
        }
    }
}

//! Listener

use crate::authenticated::{
    discovery::actors::{spawner, tracker},
    Mailbox,
};
use commonware_cryptography::Signer;
use commonware_runtime::{Clock, Handle, Listener, Metrics, Network, SinkOf, Spawner, StreamOf};
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
use tracing::debug;

/// Configuration for the listener actor.
pub struct Config<C: Signer> {
    pub address: SocketAddr,
    pub stream_cfg: StreamConfig<C>,
    pub allowed_incoming_connection_rate: Quota,
}

pub struct Actor<
    E: Spawner + Clock + ReasonablyRealtime + Network + Rng + CryptoRng + Metrics,
    C: Signer,
> {
    context: E,

    address: SocketAddr,
    stream_cfg: StreamConfig<C>,
    rate_limiter: RateLimiter<NotKeyed, InMemoryState, E, NoOpMiddleware<E::Instant>>,

    handshakes_rate_limited: Counter,
}

impl<E: Spawner + Clock + ReasonablyRealtime + Network + Rng + CryptoRng + Metrics, C: Signer>
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
        // Wait for the peer to send us their public key
        //
        // IncomingConnection limits how long we will wait for the peer to send us their public key
        // to ensure an adversary can't force us to hold many pending connections open.
        let incoming = match IncomingConnection::verify(&context, stream_cfg, sink, stream).await {
            Ok(partial) => partial,
            Err(err) => {
                debug!(?err, "failed to verify incoming handshake");
                return;
            }
        };
        let peer = incoming.peer();
        debug!(?peer, ?address, "verified handshake");

        // Check if the peer is listenable
        if !tracker.listenable(peer.clone()).await {
            debug!(?peer, ?address, "peer not listenable");
            return;
        }

        // Perform handshake
        let stream = match Connection::upgrade_listener(context, incoming).await {
            Ok(connection) => connection,
            Err(err) => {
                debug!(?err, ?peer, ?address, "failed to upgrade connection");
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
        supervisor.spawn(stream, reservation).await;
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
            // Ensure we don't attempt to perform too many handshakes at once
            if let Err(wait_until) = self.rate_limiter.check() {
                self.handshakes_rate_limited.inc();
                let wait = wait_until.wait_time_from(self.context.now());
                self.context.sleep(wait).await;
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

//! Listener

use crate::authenticated::actors::{spawner, tracker};
use commonware_cryptography::Scheme;
use commonware_runtime::{Clock, Listener, Network, Sink, Spawner, Stream};
use commonware_stream::public_key::{Config as StreamConfig, Connection, IncomingConnection};
use commonware_utils::hex;
use governor::{
    clock::ReasonablyRealtime,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use prometheus_client::{metrics::counter::Counter, registry::Registry};
use rand::{CryptoRng, Rng};
use std::{
    marker::PhantomData,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tracing::debug;

/// Configuration for the listener actor.
pub struct Config<C: Scheme> {
    pub registry: Arc<Mutex<Registry>>,
    pub address: SocketAddr,
    pub stream_cfg: StreamConfig<C>,
    pub allowed_incoming_connectioned_rate: Quota,
}

pub struct Actor<
    Si: Sink,
    St: Stream,
    L: Listener<Si, St>,
    E: Spawner + Clock + ReasonablyRealtime + Network<L, Si, St> + Rng + CryptoRng,
    C: Scheme,
> {
    runtime: E,

    address: SocketAddr,
    stream_cfg: StreamConfig<C>,
    rate_limiter: RateLimiter<NotKeyed, InMemoryState, E, NoOpMiddleware<E::Instant>>,

    handshakes_rate_limited: Counter,

    _phantom_si: PhantomData<Si>,
    _phantom_st: PhantomData<St>,
    _phantom_l: PhantomData<L>,
}

impl<
        Si: Sink,
        St: Stream,
        L: Listener<Si, St>,
        E: Spawner + Clock + ReasonablyRealtime + Network<L, Si, St> + Rng + CryptoRng,
        C: Scheme,
    > Actor<Si, St, L, E, C>
{
    pub fn new(runtime: E, cfg: Config<C>) -> Self {
        // Create metrics
        let handshakes_rate_limited = Counter::default();
        {
            let mut registry = cfg.registry.lock().unwrap();
            registry.register(
                "handshake_rate_limited",
                "number of handshakes rate limited",
                handshakes_rate_limited.clone(),
            );
        }

        Self {
            runtime: runtime.clone(),

            address: cfg.address,
            stream_cfg: cfg.stream_cfg,
            rate_limiter: RateLimiter::direct_with_clock(
                cfg.allowed_incoming_connectioned_rate,
                &runtime,
            ),

            handshakes_rate_limited,

            _phantom_si: PhantomData,
            _phantom_st: PhantomData,
            _phantom_l: PhantomData,
        }
    }

    async fn handshake(
        runtime: E,
        stream_cfg: StreamConfig<C>,
        sink: Si,
        stream: St,
        mut tracker: tracker::Mailbox<E, C::PublicKey>,
        mut supervisor: spawner::Mailbox<E, Si, St, C::PublicKey>,
    ) {
        // Wait for the peer to send us their public key
        //
        // IncomingConnection limits how long we will wait for the peer to send us their public key
        // to ensure an adversary can't force us to hold many pending connections open.
        let incoming = match IncomingConnection::verify(&runtime, stream_cfg, sink, stream).await {
            Ok(partial) => partial,
            Err(e) => {
                debug!(error = ?e, "failed to verify incoming handshake");
                return;
            }
        };

        // Attempt to claim the connection
        //
        // Reserve also checks if the peer is authorized.
        let peer = incoming.peer();
        let reservation = match tracker.reserve(peer.clone()).await {
            Some(reservation) => reservation,
            None => {
                debug!(?peer, "unable to reserve connection to peer");
                return;
            }
        };

        // Perform handshake
        let stream = match Connection::upgrade_listener(runtime, incoming).await {
            Ok(connection) => connection,
            Err(e) => {
                debug!(error = ?e, ?peer, "failed to upgrade connection");
                return;
            }
        };
        debug!(?peer, "upgraded connection");

        // Start peer to handle messages
        supervisor.spawn(peer, stream, reservation).await;
    }

    pub async fn run(
        self,
        tracker: tracker::Mailbox<E, C::PublicKey>,
        supervisor: spawner::Mailbox<E, Si, St, C::PublicKey>,
    ) {
        // Start listening for incoming connections
        let mut listener = self
            .runtime
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
                    let wait = negative.wait_time_from(self.runtime.now());
                    self.runtime.sleep(wait).await;
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
            self.runtime.spawn(
                "handshaker",
                Self::handshake(
                    self.runtime.clone(),
                    self.stream_cfg.clone(),
                    sink,
                    stream,
                    tracker.clone(),
                    supervisor.clone(),
                ),
            );
        }
    }
}

//! Listener

use crate::authenticated::actors::{spawner, tracker};
use commonware_cryptography::Scheme;
use commonware_runtime::{Clock, Listener, Network, Sink, Spawner, Stream};
use commonware_utils::hex;
use commonware_stream::public_key::{
    Config as ConnectionConfig,
    IncomingHandshake,
    Instance,
};
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
    pub connection: ConnectionConfig<C>,
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
    connection: ConnectionConfig<C>,
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
            connection: cfg.connection,
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
        connection: ConnectionConfig<C>,
        sink: Si,
        stream: St,
        mut tracker: tracker::Mailbox<E>,
        mut supervisor: spawner::Mailbox<E, C, Si, St>,
    ) {
        // Wait for the peer to send us their public key
        //
        // PartialHandshake limits how long we will wait for the peer to send us their public key
        // to ensure an adversary can't force us to hold many pending connections open.
        let handshake = match IncomingHandshake::verify(
            runtime.clone(),
            &connection.crypto,
            &connection.namespace,
            connection.max_message_size,
            connection.synchrony_bound,
            connection.max_handshake_age,
            connection.handshake_timeout,
            sink,
            stream,
        )
        .await
        {
            Ok(incoming) => incoming,
            Err(e) => {
                debug!(error = ?e, "failed to complete handshake");
                return;
            }
        };

        // Attempt to claim the connection
        //
        // Reserve also checks if the peer is authorized.
        let peer = handshake.peer_public_key.clone();
        let reservation = match tracker.reserve(peer.clone()).await {
            Some(reservation) => reservation,
            None => {
                debug!(peer = hex(&peer), "unable to reserve connection to peer");
                return;
            }
        };

        // Perform handshake
        let stream = match Instance::upgrade_listener(runtime, connection, handshake).await {
            Ok(connection) => connection,
            Err(e) => {
                debug!(error = ?e, peer=hex(&peer), "failed to upgrade connection");
                return;
            }
        };
        debug!(peer = hex(&peer), "upgraded connection");

        // Start peer to handle messages
        supervisor.spawn(peer, stream, reservation).await;
    }

    pub async fn run(
        self,
        tracker: tracker::Mailbox<E>,
        supervisor: spawner::Mailbox<E, C, Si, St>,
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
                    self.connection.clone(),
                    sink,
                    stream,
                    tracker.clone(),
                    supervisor.clone(),
                ),
            );
        }
    }
}

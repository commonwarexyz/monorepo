//! Listener

use std::{marker::PhantomData, net::SocketAddr};

use crate::authenticated::{
    actors::{spawner, tracker},
    connection::{self, IncomingHandshake, Instance},
};
use commonware_cryptography::{utils::hex, Scheme};
use commonware_runtime::{Clock, Listener, Network, Sink, Spawner, Stream};
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use rand::{CryptoRng, Rng};
use tracing::debug;

/// Configuration for the listener actor.
pub struct Config<C: Scheme> {
    pub address: SocketAddr,
    pub connection: connection::Config<C>,
    pub allowed_incoming_connectioned_rate: Quota,
}

pub struct Actor<
    Si: Sink,
    St: Stream,
    L: Listener<Si, St>,
    E: Spawner + Clock + Network<L, Si, St> + Rng + CryptoRng,
    C: Scheme,
> {
    context: E,

    address: SocketAddr,
    connection: connection::Config<C>,
    rate_limiter: DefaultDirectRateLimiter,

    _phantom_si: PhantomData<Si>,
    _phantom_st: PhantomData<St>,
    _phantom_l: PhantomData<L>,
}

impl<
        Si: Sink,
        St: Stream,
        L: Listener<Si, St>,
        E: Spawner + Clock + Network<L, Si, St> + Rng + CryptoRng,
        C: Scheme,
    > Actor<Si, St, L, E, C>
{
    pub fn new(context: E, cfg: Config<C>) -> Self {
        Self {
            context,

            address: cfg.address,
            connection: cfg.connection,
            rate_limiter: RateLimiter::direct(cfg.allowed_incoming_connectioned_rate),

            _phantom_si: PhantomData,
            _phantom_st: PhantomData,
            _phantom_l: PhantomData,
        }
    }

    async fn handshake(
        context: E,
        connection: connection::Config<C>,
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
            context.clone(),
            &connection.crypto,
            connection.synchrony_bound,
            connection.max_handshake_age,
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
        let stream = match Instance::upgrade_listener(context, connection, handshake).await {
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
            .context
            .bind(self.address)
            .await
            .expect("failed to bind listener");

        // Loop over incoming connections as fast as our rate limiter allows
        loop {
            // Ensure we don't attempt to perform too many handshakes at once
            self.rate_limiter.until_ready().await;

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
            self.context.spawn(Self::handshake(
                self.context.clone(),
                self.connection.clone(),
                sink,
                stream,
                tracker.clone(),
                supervisor.clone(),
            ));
        }
    }
}

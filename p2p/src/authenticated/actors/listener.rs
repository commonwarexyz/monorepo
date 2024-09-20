//! Listener

use std::marker::PhantomData;

use crate::authenticated::{
    actors::{spawner, tracker},
    connection::{self, IncomingHandshake, Stream},
};
use commonware_cryptography::{utils::hex, Scheme};
use commonware_runtime::{Clock, Listener, Spawner, Stream as RStream};
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use tracing::debug;

/// Configuration for the listener actor.
pub struct Config<C: Scheme> {
    pub connection: connection::Config<C>,
    pub allowed_incoming_connectioned_rate: Quota,
}

pub struct Actor<E: Spawner + Clock, S: RStream, L: Listener<S>, C: Scheme> {
    context: E,
    listener: L,

    connection: connection::Config<C>,
    rate_limiter: DefaultDirectRateLimiter,

    _phantom: PhantomData<S>,
}

impl<E: Spawner + Clock, S: RStream, L: Listener<S>, C: Scheme> Actor<E, S, L, C> {
    pub fn new(context: E, listener: L, cfg: Config<C>) -> Self {
        Self {
            context,
            listener,

            connection: cfg.connection,
            rate_limiter: RateLimiter::direct(cfg.allowed_incoming_connectioned_rate),

            _phantom: PhantomData,
        }
    }

    async fn handshake(
        context: E,
        connection: connection::Config<C>,
        stream: S,
        tracker: tracker::Mailbox<E>,
        supervisor: spawner::Mailbox<E, C>,
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
            connection.handshake_timeout,
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
        let stream = match Stream::upgrade_listener(context, connection, handshake).await {
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

    pub async fn run(self, tracker: tracker::Mailbox<E>, supervisor: spawner::Mailbox<E, C>) {
        // Loop over incoming connections as fast as our rate limiter allows
        loop {
            // Ensure we don't attempt to perform too many handshakes at once
            self.rate_limiter.until_ready().await;

            // Accept a new connection
            let (address, stream) = match self.listener.accept().await {
                Ok((address, stream)) => (address, stream),
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
                stream,
                tracker.clone(),
                supervisor.clone(),
            ));
        }
    }
}

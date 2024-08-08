//! Listener

use std::net::{Ipv4Addr, SocketAddr};

use crate::{
    actors::{spawner, tracker},
    connection::{self, IncomingHandshake, Stream},
    crypto::Crypto,
};
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use tokio::net::{TcpListener, TcpStream};
use tracing::debug;

/// Configuration for the listener actor.
pub struct Config<C: Crypto> {
    pub port: u16,
    pub connection: connection::Config<C>,
    pub allowed_incoming_connectioned_rate: Quota,
}

pub struct Actor<C: Crypto> {
    port: u16,
    connection: connection::Config<C>,

    rate_limiter: DefaultDirectRateLimiter,
}

impl<C: Crypto> Actor<C> {
    pub fn new(cfg: Config<C>) -> Self {
        Self {
            port: cfg.port,
            connection: cfg.connection,
            rate_limiter: RateLimiter::direct(cfg.allowed_incoming_connectioned_rate),
        }
    }

    async fn handshake(
        connection: connection::Config<C>,
        stream: TcpStream,
        tracker: tracker::Mailbox,
        supervisor: spawner::Mailbox<C>,
    ) {
        // Wait for the peer to send us their public key
        //
        // PartialHandshake limits how long we will wait for the peer to send us their public key
        // to ensure an adversary can't force us to hold many pending connections open.
        let handshake = match IncomingHandshake::verify(
            &connection.crypto,
            connection.max_frame_length,
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
                debug!(
                    peer = hex::encode(&peer),
                    "unable to reserve connection to peer"
                );
                return;
            }
        };

        // Perform handshake
        let stream = match Stream::upgrade_listener(connection, handshake).await {
            Ok(connection) => connection,
            Err(e) => {
                debug!(error = ?e, peer=hex::encode(&peer), "failed to upgrade connection");
                return;
            }
        };
        debug!(peer = hex::encode(&peer), "upgraded connection");

        // Start peer to handle messages
        supervisor.spawn(peer, stream, reservation).await;
    }

    pub async fn run(self, tracker: tracker::Mailbox, supervisor: spawner::Mailbox<C>) {
        // Configure the listener on the specified port
        let address = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.port);
        let listener = TcpListener::bind(address).await.unwrap();
        debug!(port = self.port, "listening for incoming connections");

        // Loop over incoming connections as fast as our rate limiter allows
        loop {
            // Ensure we don't attempt to perform too many handshakes at once
            self.rate_limiter.until_ready().await;

            // Accept a new connection
            let (stream, address) = match listener.accept().await {
                Ok((stream, address)) => (stream, address),
                Err(e) => {
                    debug!(error = ?e, "failed to accept connection");
                    continue;
                }
            };
            debug!(ip = ?address.ip(), port = ?address.port(), "accepted incoming connection");

            // Set TCP_NODELAY
            if let Err(e) = stream.set_nodelay(self.connection.tcp_nodelay) {
                debug!(ip = ?address.ip(), port = ?address.port(), error = ?e, "failed to set TCP_NODELAY")
            }

            // Spawn a new handshaker to upgrade connection
            tokio::spawn(Self::handshake(
                self.connection.clone(),
                stream,
                tracker.clone(),
                supervisor.clone(),
            ));
        }
    }
}

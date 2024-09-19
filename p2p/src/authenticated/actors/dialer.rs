//! Actor responsible for dialing peers and establishing connections.

use crate::authenticated::{
    actors::{spawner, tracker},
    connection::{self, Stream},
    metrics,
};
use commonware_cryptography::{utils::hex, PublicKey, Scheme};
use commonware_runtime::Spawner;
use governor::{DefaultDirectRateLimiter, Jitter, Quota, RateLimiter};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use std::{net::SocketAddr, time::Duration};
use std::{
    ops::Add,
    sync::{Arc, Mutex},
};
use tokio::net::TcpStream;
use tokio::time::{self, Instant};
use tracing::debug;

pub struct Config<C: Scheme> {
    pub registry: Arc<Mutex<Registry>>,
    pub connection: connection::Config<C>,
    pub dial_frequency: Duration,
    pub dial_rate: Quota,
}

pub struct Actor<E: Spawner, C: Scheme> {
    context: E,

    connection: connection::Config<C>,
    dial_frequency: Duration,

    dial_limiter: DefaultDirectRateLimiter,

    dial_attempts: Family<metrics::Peer, Counter>,
}

impl<E: Spawner, C: Scheme> Actor<E, C> {
    pub fn new(context: E, cfg: Config<C>) -> Self {
        let dial_attempts = Family::<metrics::Peer, Counter>::default();
        {
            let mut registry = cfg.registry.lock().unwrap();
            registry.register(
                "dial_attempts",
                "number of dial attempts",
                dial_attempts.clone(),
            );
        }
        Self {
            context,
            connection: cfg.connection,
            dial_frequency: cfg.dial_frequency,
            dial_limiter: RateLimiter::direct(cfg.dial_rate),
            dial_attempts,
        }
    }

    async fn dial_peers(&self, tracker: &tracker::Mailbox<E>, supervisor: &spawner::Mailbox<E, C>) {
        for (peer, address, reservation) in tracker.dialable().await {
            // Check if we have hit rate limit for dialing and if so, skip (we don't
            // want to block the loop)
            //
            // Check will invoke the rate limiter if there is room to dial, so we don't
            // need to invoke until_ready below.
            //
            // If we hit this check, we will count as a dial attempt for the peer. This isn't
            // ideal but it shouldn't end up being a problem in practice (we'll eventually redial).
            if self.dial_limiter.check().is_err() {
                debug!("dial rate limit exceeded");
                break;
            }

            // Spawn dialer to connect to peer
            self.dial_attempts
                .get_or_create(&metrics::Peer::new(&peer))
                .inc();
            self.context.spawn(Self::dial(
                self.connection.clone(),
                peer.clone(),
                address,
                reservation,
                supervisor.clone(),
            ));
        }
    }

    async fn dial(
        config: connection::Config<C>,
        peer: PublicKey,
        address: SocketAddr,
        reservation: tracker::Reservation<E>,
        supervisor: spawner::Mailbox<E, C>,
    ) {
        // Attempt to dial peer
        let connection = match TcpStream::connect(address).await {
            Ok(stream) => stream,
            Err(e) => {
                debug!(peer=hex(&peer), error = ?e, "failed to dial peer");
                return;
            }
        };
        debug!(
            peer = hex(&peer),
            address = address.to_string(),
            "dialed peer"
        );

        // Set TCP_NODELAY
        if let Some(nodelay) = config.tcp_nodelay {
            if let Err(e) = connection.set_nodelay(nodelay) {
                debug!(peer = hex(&peer), error = ?e, "failed to set TCP_NODELAY")
            }
        }

        // Upgrade connection
        let stream = match Stream::upgrade_dialer(config, connection, peer.clone()).await {
            Ok(stream) => stream,
            Err(e) => {
                debug!(peer=hex(&peer), error = ?e, "failed to upgrade connection");
                return;
            }
        };
        debug!(peer = hex(&peer), "upgraded connection");

        // Start peer to handle messages
        supervisor.spawn(peer, stream, reservation).await;
    }

    pub async fn run(self, tracker: tracker::Mailbox<E>, supervisor: spawner::Mailbox<E, C>) {
        let mut next_update = Instant::now();
        loop {
            time::sleep_until(next_update).await;

            // Attempt to dial peers we know about
            self.dial_peers(&tracker, &supervisor).await;

            // Ensure we reset the timer with a new jitter
            let jitter = Jitter::up_to(self.dial_frequency);
            next_update = Instant::now().add(jitter + self.dial_frequency);
        }
    }
}

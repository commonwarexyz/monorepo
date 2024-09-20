//! Actor responsible for dialing peers and establishing connections.

use crate::authenticated::{
    actors::{spawner, tracker},
    connection::{self, Stream},
    metrics,
};
use commonware_cryptography::{utils::hex, PublicKey, Scheme};
use commonware_runtime::{Clock, Network, Spawner, Stream as RStream};
use governor::{DefaultDirectRateLimiter, Jitter, Quota, RateLimiter};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use std::{marker::PhantomData, net::SocketAddr, time::Duration};
use std::{
    ops::Add,
    sync::{Arc, Mutex},
};
use tracing::debug;

pub struct Config<C: Scheme> {
    pub registry: Arc<Mutex<Registry>>,
    pub connection: connection::Config<C>,
    pub dial_frequency: Duration,
    pub dial_rate: Quota,
}

pub struct Actor<S: RStream, E: Spawner + Clock + Network<S>, C: Scheme> {
    context: E,

    connection: connection::Config<C>,
    dial_frequency: Duration,

    dial_limiter: DefaultDirectRateLimiter,

    dial_attempts: Family<metrics::Peer, Counter>,

    _phantom: PhantomData<S>,
}

impl<S: RStream, E: Spawner + Clock + Network<S>, C: Scheme> Actor<S, E, C> {
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
            _phantom: PhantomData,
        }
    }

    async fn dial_peers(
        &self,
        tracker: &mut tracker::Mailbox<E>,
        supervisor: &spawner::Mailbox<E, C>,
    ) {
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
                self.context.clone(),
                self.connection.clone(),
                peer.clone(),
                address,
                reservation,
                supervisor.clone(),
            ));
        }
    }

    async fn dial(
        context: E,
        config: connection::Config<C>,
        peer: PublicKey,
        address: SocketAddr,
        reservation: tracker::Reservation<E>,
        supervisor: spawner::Mailbox<E, C>,
    ) {
        // Attempt to dial peer
        let connection = match context.dial(address).await {
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

        // Upgrade connection
        let stream = match Stream::upgrade_dialer(context, config, connection, peer.clone()).await {
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

    pub async fn run(self, mut tracker: tracker::Mailbox<E>, supervisor: spawner::Mailbox<E, C>) {
        let mut next_update = self.context.current();
        loop {
            self.context.sleep_until(next_update).await;

            // Attempt to dial peers we know about
            self.dial_peers(&mut tracker, &supervisor).await;

            // Ensure we reset the timer with a new jitter
            let jitter = Jitter::up_to(self.dial_frequency);
            next_update = self.context.current().add(jitter + self.dial_frequency);
        }
    }
}

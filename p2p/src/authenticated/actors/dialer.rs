//! Actor responsible for dialing peers and establishing connections.

use crate::authenticated::{
    actors::{spawner, tracker},
    connection::{self, Instance},
    metrics,
};
use commonware_cryptography::{utils::hex, Scheme};
use commonware_runtime::{Clock, Listener, Network, Sink, Spawner, Stream};
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use rand::{CryptoRng, Rng};
use std::{marker::PhantomData, time::Duration};
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

pub struct Actor<
    Si: Sink,
    St: Stream,
    L: Listener<Si, St>,
    E: Spawner + Clock + Network<L, Si, St>,
    C: Scheme,
> {
    context: E,

    connection: connection::Config<C>,
    dial_frequency: Duration,

    dial_limiter: DefaultDirectRateLimiter,

    dial_attempts: Family<metrics::Peer, Counter>,

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
            _phantom_si: PhantomData,
            _phantom_st: PhantomData,
            _phantom_l: PhantomData,
        }
    }

    async fn dial_peers(
        &self,
        tracker: &mut tracker::Mailbox<E>,
        supervisor: &mut spawner::Mailbox<E, C, Si, St>,
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
            self.dial_attempts
                .get_or_create(&metrics::Peer::new(&peer))
                .inc();

            // Spawn dialer to connect to peer
            self.context.spawn({
                let context = self.context.clone();
                let config = self.connection.clone();
                let mut supervisor = supervisor.clone();
                async move {
                    // Attempt to dial peer
                    let (sink, stream) = match context.dial(address).await {
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
                    let instance =
                        match Instance::upgrade_dialer(context, config, sink, stream, peer.clone())
                            .await
                        {
                            Ok(instance) => instance,
                            Err(e) => {
                                debug!(peer=hex(&peer), error = ?e, "failed to upgrade connection");
                                return;
                            }
                        };
                    debug!(peer = hex(&peer), "upgraded connection");

                    // Start peer to handle messages
                    supervisor.spawn(peer, instance, reservation).await;
                }
            });
        }
    }

    pub async fn run(
        mut self,
        mut tracker: tracker::Mailbox<E>,
        mut supervisor: spawner::Mailbox<E, C, Si, St>,
    ) {
        let mut next_update = self.context.current();
        loop {
            self.context.sleep_until(next_update).await;

            // Attempt to dial peers we know about
            self.dial_peers(&mut tracker, &mut supervisor).await;

            // Ensure we reset the timer with a new jitter
            let jitter_millis = self
                .context
                .gen_range(0..self.dial_frequency.as_millis() as u64);
            let jitter = Duration::from_millis(jitter_millis);
            next_update = self.context.current().add(jitter + self.dial_frequency);
        }
    }
}

//! Actor responsible for dialing peers and establishing connections.

use crate::authenticated::{
    actors::{spawner, tracker},
    metrics,
};
use commonware_cryptography::Scheme;
use commonware_runtime::{Clock, Listener, Network, Sink, Spawner, Stream};
use commonware_stream::public_key::{Config as StreamConfig, Connection};
use commonware_utils::hex;
use governor::{
    clock::Clock as GClock,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use rand::{CryptoRng, Rng};
use std::sync::{Arc, Mutex};
use std::{marker::PhantomData, time::Duration};
use tracing::debug;

pub struct Config<C: Scheme> {
    pub registry: Arc<Mutex<Registry>>,
    pub stream_cfg: StreamConfig<C>,
    pub dial_frequency: Duration,
    pub dial_rate: Quota,
}

pub struct Actor<
    Si: Sink,
    St: Stream,
    L: Listener<Si, St>,
    E: Spawner + Clock + GClock + Network<L, Si, St>,
    C: Scheme,
> {
    runtime: E,

    stream_cfg: StreamConfig<C>,
    dial_frequency: Duration,

    dial_limiter: RateLimiter<NotKeyed, InMemoryState, E, NoOpMiddleware<E::Instant>>,

    dial_attempts: Family<metrics::Peer, Counter>,

    _phantom_si: PhantomData<Si>,
    _phantom_st: PhantomData<St>,
    _phantom_l: PhantomData<L>,
}

impl<
        Si: Sink,
        St: Stream,
        L: Listener<Si, St>,
        E: Spawner + Clock + GClock + Network<L, Si, St> + Rng + CryptoRng,
        C: Scheme,
    > Actor<Si, St, L, E, C>
{
    pub fn new(runtime: E, cfg: Config<C>) -> Self {
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
            runtime: runtime.clone(),
            stream_cfg: cfg.stream_cfg,
            dial_frequency: cfg.dial_frequency,
            dial_limiter: RateLimiter::direct_with_clock(cfg.dial_rate, &runtime),
            dial_attempts,
            _phantom_si: PhantomData,
            _phantom_st: PhantomData,
            _phantom_l: PhantomData,
        }
    }

    async fn dial_peers(
        &self,
        tracker: &mut tracker::Mailbox<E>,
        supervisor: &mut spawner::Mailbox<E, Si, St>,
    ) {
        for (peer, address, reservation) in tracker.dialable().await {
            // Check if we have hit the rate limit for dialing and if so, skip (we don't
            // want to block the loop)
            if self.dial_limiter.check().is_err() {
                debug!("dial rate limit exceeded");
                break;
            }
            self.dial_attempts
                .get_or_create(&metrics::Peer::new(&peer))
                .inc();

            // Spawn dialer to connect to peer
            self.runtime.spawn("dialer", {
                let runtime = self.runtime.clone();
                let config = self.stream_cfg.clone();
                let mut supervisor = supervisor.clone();
                async move {
                    // Attempt to dial peer
                    let (sink, stream) = match runtime.dial(address).await {
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
                    let instance = match Connection::upgrade_dialer(
                        runtime,
                        config,
                        sink,
                        stream,
                        peer.clone(),
                    )
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
        mut supervisor: spawner::Mailbox<E, Si, St>,
    ) {
        loop {
            // Attempt to dial peers we know about
            self.dial_peers(&mut tracker, &mut supervisor).await;

            // Sleep for a random amount of time up to the dial frequency
            let wait = self
                .runtime
                .gen_range(Duration::default()..self.dial_frequency);
            self.runtime.sleep(wait).await;
        }
    }
}

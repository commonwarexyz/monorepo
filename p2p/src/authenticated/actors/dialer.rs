//! Actor responsible for dialing peers and establishing connections.

use crate::authenticated::{
    actors::{spawner, tracker},
    metrics,
};
use commonware_cryptography::Scheme;
use commonware_runtime::{
    telemetry::traces::status, Clock, Handle, Listener, Metrics, Network, Sink, Spawner, Stream,
};
use commonware_stream::public_key::{Config as StreamConfig, Connection};
use governor::{
    clock::Clock as GClock,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use rand::{CryptoRng, Rng};
use std::{marker::PhantomData, time::Duration};
use tracing::{debug, debug_span, Instrument};

pub struct Config<C: Scheme> {
    pub stream_cfg: StreamConfig<C>,
    pub dial_frequency: Duration,
    pub dial_rate: Quota,
}

pub struct Actor<
    Si: Sink,
    St: Stream,
    L: Listener<Si, St>,
    E: Spawner + Clock + GClock + Network<L, Si, St> + Metrics,
    C: Scheme,
> {
    context: E,

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
        E: Spawner + Clock + GClock + Network<L, Si, St> + Rng + CryptoRng + Metrics,
        C: Scheme,
    > Actor<Si, St, L, E, C>
{
    pub fn new(context: E, cfg: Config<C>) -> Self {
        let dial_attempts = Family::<metrics::Peer, Counter>::default();
        context.register(
            "dial_attempts",
            "number of dial attempts",
            dial_attempts.clone(),
        );
        Self {
            context: context.clone(),
            stream_cfg: cfg.stream_cfg,
            dial_frequency: cfg.dial_frequency,
            dial_limiter: RateLimiter::direct_with_clock(cfg.dial_rate, &context),
            dial_attempts,
            _phantom_si: PhantomData,
            _phantom_st: PhantomData,
            _phantom_l: PhantomData,
        }
    }

    async fn dial_peers(
        &self,
        tracker: &mut tracker::Mailbox<E, C>,
        supervisor: &mut spawner::Mailbox<E, Si, St, C>,
    ) {
        for (peer, address, reservation) in tracker.dialable().await {
            // Check if we have hit rate limit for dialing and if so, skip (we don't
            // want to block the loop)
            if self.dial_limiter.check().is_err() {
                debug!("dial rate limit exceeded");
                break;
            }
            self.dial_attempts
                .get_or_create(&metrics::Peer::new(&peer))
                .inc();

            // Spawn dialer to connect to peer
            self.context.with_label("dialer").spawn({
                let config = self.stream_cfg.clone();
                let mut supervisor = supervisor.clone();
                move |context| async move {
                    // Create span
                    let span = debug_span!("dialer", ?peer, ?address);
                    let guard = span.enter();

                    // Attempt to dial peer
                    let (sink, stream) =
                        match context.dial(address).instrument(debug_span!("dial")).await {
                            Ok(stream) => stream,
                            Err(e) => {
                                status::error(&span, "failed to dial peer", Some(&e));
                                return;
                            }
                        };
                    debug!("dialed peer");

                    // Upgrade connection
                    let instance = match Connection::upgrade_dialer(
                        context,
                        config,
                        sink,
                        stream,
                        peer.clone(),
                    )
                    .instrument(debug_span!("upgrade"))
                    .await
                    {
                        Ok(instance) => instance,
                        Err(e) => {
                            status::error(&span, "failed to upgrade connection", Some(&e));
                            return;
                        }
                    };
                    debug!("upgraded connection");

                    // Set status to OK
                    status::ok(&span);
                    drop(guard);

                    // Start peer to handle messages
                    supervisor.spawn(peer, instance, reservation).await;
                }
            });
        }
    }

    pub fn start(
        self,
        tracker: tracker::Mailbox<E, C>,
        supervisor: spawner::Mailbox<E, Si, St, C>,
    ) -> Handle<()> {
        self.context
            .clone()
            .spawn(|_| self.run(tracker, supervisor))
    }

    async fn run(
        mut self,
        mut tracker: tracker::Mailbox<E, C>,
        mut supervisor: spawner::Mailbox<E, Si, St, C>,
    ) {
        loop {
            // Attempt to dial peers we know about
            self.dial_peers(&mut tracker, &mut supervisor).await;

            // Sleep for a random amount of time up to the dial frequency
            let wait = self
                .context
                .gen_range(Duration::default()..self.dial_frequency);
            self.context.sleep(wait).await;
        }
    }
}

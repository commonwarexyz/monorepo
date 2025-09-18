//! P2P resolver initialization and config.

use crate::{
    marshal::ingress::handler::{self, Handler},
    Block,
};
use commonware_cryptography::PublicKey;
use commonware_p2p::{utils::requester, Receiver, Sender};
use commonware_resolver::p2p::{self, Coordinator};
use commonware_runtime::{Clock, Metrics, Spawner};
use futures::channel::mpsc;
use governor::{clock::Clock as GClock, Quota};
use rand::Rng;
use std::{num::NonZeroU32, time::Duration};

/// Configuration for the P2P [Resolver](commonware_resolver::Resolver).
pub struct Config<P: PublicKey, C: Coordinator<PublicKey = P>> {
    pub public_key: P,
    pub coordinator: C,
    pub mailbox_size: usize,
}

/// Initialize a P2P resolver.
pub fn init_p2p_resolver<E, C, B, S, R, P>(
    ctx: &E,
    config: Config<P, C>,
    backfill: (S, R),
) -> (
    mpsc::Receiver<handler::Message<B>>,
    p2p::Mailbox<handler::Request<B>>,
)
where
    E: Rng + Spawner + Clock + GClock + Metrics,
    C: Coordinator<PublicKey = P>,
    B: Block,
    S: Sender<PublicKey = P>,
    R: Receiver<PublicKey = P>,
    P: PublicKey,
{
    let (handler, receiver) = mpsc::channel(config.mailbox_size);
    let handler = Handler::new(handler);
    let (resolver_engine, resolver) = p2p::Engine::new(
        ctx.with_label("resolver"),
        p2p::Config {
            coordinator: config.coordinator,
            consumer: handler.clone(),
            producer: handler,
            mailbox_size: config.mailbox_size,
            requester_config: requester::Config {
                public_key: config.public_key,
                rate_limit: Quota::per_second(NonZeroU32::new(5).unwrap()),
                initial: Duration::from_secs(1),
                timeout: Duration::from_secs(2),
            },
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        },
    );
    resolver_engine.start(backfill);
    (receiver, resolver)
}

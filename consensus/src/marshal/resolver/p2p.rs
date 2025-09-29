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
use governor::clock::Clock as GClock;
use rand::Rng;
use std::time::Duration;

/// Configuration for the P2P [Resolver](commonware_resolver::Resolver).
pub struct Config<P: PublicKey, C: Coordinator<PublicKey = P>> {
    /// The public key to identify this node.
    pub public_key: P,

    /// The coordinator of peers that can be consulted for fetching data.
    pub coordinator: C,

    /// The size of the request mailbox backlog.
    pub mailbox_size: usize,

    /// The requester configuration.
    pub requester_config: requester::Config<P>,

    /// Retry timeout for the fetcher.
    pub fetch_retry_timeout: Duration,

    /// Whether requests are sent with priority over other network messages
    pub priority_requests: bool,

    /// Whether responses are sent with priority over other network messages
    pub priority_responses: bool,
}

/// Initialize a P2P resolver.
pub fn init<E, C, B, S, R, P>(
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
    let resolver_context = ctx.with_label("resolver");
    let (resolver_engine, resolver) = p2p::Engine::new(
        resolver_context.clone(),
        p2p::Config {
            coordinator: config.coordinator,
            consumer: handler.clone(),
            producer: handler,
            mailbox_size: config.mailbox_size,
            requester_config: config.requester_config,
            fetch_retry_timeout: config.fetch_retry_timeout,
            priority_requests: config.priority_requests,
            priority_responses: config.priority_responses,
        },
    );
    resolver_engine.start(resolver_context, backfill);
    (receiver, resolver)
}

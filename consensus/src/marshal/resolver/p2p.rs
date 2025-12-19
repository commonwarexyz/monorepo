//! P2P resolver initialization and config.

use crate::{
    marshal::ingress::handler::{self, Handler},
    Block,
};
use commonware_cryptography::PublicKey;
use commonware_p2p::{Blocker, Manager, Receiver, Sender};
use commonware_resolver::p2p;
use commonware_runtime::{Clock, Metrics, Spawner};
use futures::channel::mpsc;
use rand::Rng;
use std::time::Duration;

/// Configuration for the P2P [Resolver](commonware_resolver::Resolver).
pub struct Config<P: PublicKey, C: Manager<PublicKey = P>, B: Blocker<PublicKey = P>> {
    /// The public key to identify this node.
    pub public_key: P,

    /// The provider of peers that can be consulted for fetching data.
    pub manager: C,

    /// The blocker that will be used to block peers that send invalid responses.
    pub blocker: B,

    /// The size of the request mailbox backlog.
    pub mailbox_size: usize,

    /// Initial expected performance for new participants.
    pub initial: Duration,

    /// Timeout for requests.
    pub timeout: Duration,

    /// Retry timeout for the fetcher.
    pub fetch_retry_timeout: Duration,

    /// Whether requests are sent with priority over other network messages
    pub priority_requests: bool,

    /// Whether responses are sent with priority over other network messages
    pub priority_responses: bool,
}

/// Initialize a P2P resolver.
pub fn init<E, C, Bl, B, S, R, P>(
    ctx: &E,
    config: Config<P, C, Bl>,
    backfill: (S, R),
) -> (
    mpsc::Receiver<handler::Message<B>>,
    p2p::Mailbox<handler::Request<B>, P>,
)
where
    E: Rng + Spawner + Clock + Metrics,
    C: Manager<PublicKey = P>,
    Bl: Blocker<PublicKey = P>,
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
            manager: config.manager,
            blocker: config.blocker,
            consumer: handler.clone(),
            producer: handler,
            mailbox_size: config.mailbox_size,
            me: Some(config.public_key),
            initial: config.initial,
            timeout: config.timeout,
            fetch_retry_timeout: config.fetch_retry_timeout,
            priority_requests: config.priority_requests,
            priority_responses: config.priority_responses,
        },
    );
    resolver_engine.start(backfill);
    (receiver, resolver)
}

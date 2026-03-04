//! P2P resolver plumbing reused by the standard and coding marshal variants.

use crate::marshal::resolver::handler;
use commonware_cryptography::{Digest, PublicKey};
use commonware_p2p::{Blocker, Provider, Receiver, Sender};
use commonware_resolver::p2p;
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner};
use commonware_utils::channel::mpsc;
use rand::Rng;
use std::time::Duration;

/// Configuration for the P2P [Resolver](commonware_resolver::Resolver).
pub struct Config<P, C, B>
where
    P: PublicKey,
    C: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
{
    /// The public key to identify this node.
    pub public_key: P,

    /// The provider of peers that can be consulted for fetching data.
    pub provider: C,

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
pub fn init<E, C, B, D, S, R, P>(
    ctx: &E,
    config: Config<P, C, B>,
    backfill: (S, R),
) -> (
    mpsc::Receiver<handler::Message<D>>,
    p2p::Mailbox<handler::Request<D>, P>,
)
where
    E: BufferPooler + Rng + Spawner + Clock + Metrics,
    C: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    D: Digest,
    S: Sender<PublicKey = P>,
    R: Receiver<PublicKey = P>,
    P: PublicKey,
{
    let (sender, receiver) = mpsc::channel(config.mailbox_size);
    let handler = handler::Handler::new(sender);
    let (resolver_engine, resolver) = p2p::Engine::new(
        ctx.with_label("resolver"),
        p2p::Config {
            provider: config.provider,
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

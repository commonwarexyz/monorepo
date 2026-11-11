//! P2P resolver plumbing reused by the standard and coding marshal variants.

use crate::marshal::resolver::handler::{self, Annotation, Key, Receiver as HandlerReceiver};
use commonware_actor::mailbox;
use commonware_cryptography::{Digest, PublicKey};
use commonware_p2p::{Blocker, Provider, Receiver as P2pReceiver, Sender};
use commonware_resolver::p2p;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::NonZeroDuration;
use rand_core::Rng;
use std::{num::NonZeroUsize, time::Duration};

/// Configuration for the P2P [Resolver](commonware_resolver::Resolver).
pub struct Config<P, C, B>
where
    P: PublicKey,
    C: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
{
    /// The public key to identify this node.
    pub public_key: P,

    /// The provider of the peer set that fetches are sent to.
    ///
    /// A fetch without targets may be sent to any peer of the latest set, primary or secondary.
    /// A fetch with targets, such as one from
    /// [`hint_finalized`](crate::marshal::core::Mailbox::hint_finalized), is sent only to its
    /// targets in that set.
    pub peer_provider: C,

    /// The blocker that will be used to block peers that send invalid responses.
    pub blocker: B,

    /// The size of the request mailbox backlog.
    pub mailbox_size: NonZeroUsize,

    /// Timeout for requests.
    pub fetch_timeout: NonZeroDuration,

    /// Delay after an unresolved attempt before retrying its fetch.
    /// Zero permits immediate retries, subject to the sender's rate limit.
    pub fetch_retry_delay: Duration,

    /// Whether requests are sent with priority over other network messages
    pub priority_requests: bool,

    /// Whether responses are sent with priority over other network messages
    pub priority_responses: bool,
}

/// Mailbox for issuing marshal backfill requests.
pub type Mailbox<D, P> = p2p::Mailbox<Key<D>, P, Annotation>;

/// Initialize a P2P resolver.
pub fn init<E, C, B, D, S, R, P>(
    context: E,
    config: Config<P, C, B>,
    backfill: (S, R),
) -> (HandlerReceiver<D>, Mailbox<D, P>)
where
    E: Rng + Spawner + Clock + Metrics,
    C: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    D: Digest,
    S: Sender<PublicKey = P>,
    R: P2pReceiver<PublicKey = P>,
    P: PublicKey,
{
    // Every handler entry is one message the network admitted on the backfill channel, and peer
    // requests are dropped once the ready queue is full, so hold as many as the channel.
    let (sender, receiver) = mailbox::new(context.child("handler"), backfill.1.capacity());
    let handler = handler::Handler::new(sender);
    let (resolver_engine, resolver) = p2p::Engine::new(
        context.child("resolver"),
        p2p::Config {
            peer_provider: config.peer_provider,
            blocker: config.blocker,
            consumer: handler.clone(),
            producer: handler,
            mailbox_size: config.mailbox_size,
            me: Some(config.public_key),
            fetch_timeout: config.fetch_timeout,
            fetch_retry_delay: config.fetch_retry_delay,
            priority_requests: config.priority_requests,
            priority_responses: config.priority_responses,
        },
    );
    resolver_engine.start(backfill);
    (HandlerReceiver::new(receiver), resolver)
}

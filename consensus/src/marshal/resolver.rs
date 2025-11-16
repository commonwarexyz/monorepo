//! Resolver backfill helpers shared by all marshal variants.
//!
//! Marshal has two networking paths:
//! - `ingress`, which accepts deliveries from local subsystems (e.g. the resolver engine handing
//!   a block to the actor)
//! - `resolver`, which issues outbound fetches when we need data stored on remote peers
//!
//! This module powers the second path. It exposes a single helper for wiring up a
//! [`commonware_resolver::p2p::Engine`] and lets each marshal variant plug in its own message
//! handler while reusing the same transport plumbing.

pub mod p2p {
    //! P2P resolver plumbing reused by the standard and coding marshal variants.

    use bytes::Bytes;
    use commonware_cryptography::PublicKey;
    use commonware_p2p::{utils::requester, Manager, Receiver, Sender};
    use commonware_resolver::{p2p, p2p::Producer, Consumer};
    use commonware_runtime::{Clock, Metrics, Spawner};
    use commonware_utils::Span;
    use futures::channel::mpsc;
    use governor::clock::Clock as GClock;
    use rand::Rng;
    use std::time::Duration;

    /// Configuration for the P2P [Resolver](commonware_resolver::Resolver).
    pub struct Config<P: PublicKey, C: Manager<PublicKey = P>> {
        /// The public key to identify this node.
        pub public_key: P,

        /// The provider of peers that can be consulted for fetching data.
        pub manager: C,

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

    /// Initialize a P2P resolver using a custom ingress handler.
    pub fn init<E, C, S, R, P, H, M, K>(
        ctx: &E,
        config: Config<P, C>,
        backfill: (S, R),
        make_handler: impl FnOnce(mpsc::Sender<M>) -> H,
    ) -> (mpsc::Receiver<M>, p2p::Mailbox<K>)
    where
        E: Rng + Spawner + Clock + GClock + Metrics,
        C: Manager<PublicKey = P>,
        S: Sender<PublicKey = P>,
        R: Receiver<PublicKey = P>,
        P: PublicKey,
        H: Clone
            + Consumer<Key = K, Value = Bytes, Failure = ()>
            + Producer<Key = K>
            + Send
            + 'static,
        M: Send + 'static,
        K: Span + Send + 'static,
    {
        let (sender, receiver) = mpsc::channel(config.mailbox_size);
        let handler = make_handler(sender);
        let (resolver_engine, resolver) = p2p::Engine::new(
            ctx.with_label("resolver"),
            p2p::Config {
                manager: config.manager,
                consumer: handler.clone(),
                producer: handler,
                mailbox_size: config.mailbox_size,
                requester_config: config.requester_config,
                fetch_retry_timeout: config.fetch_retry_timeout,
                priority_requests: config.priority_requests,
                priority_responses: config.priority_responses,
            },
        );
        resolver_engine.start(backfill);
        (receiver, resolver)
    }
}

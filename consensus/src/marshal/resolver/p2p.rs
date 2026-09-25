//! P2P resolver plumbing reused by the standard and coding marshal variants.

use crate::marshal::{
    Limits,
    resolver::handler::{self, Annotation, Key, Receiver as HandlerReceiver},
};
use commonware_actor::mailbox;
use commonware_cryptography::{Digest, PublicKey};
use commonware_p2p::{Blocker, Provider, Receiver as P2pReceiver, Sender};
use commonware_resolver::p2p;
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner};
use commonware_utils::Widen;
use rand_core::Rng;
use std::{num::NonZeroUsize, time::Duration};

/// Configuration for the P2P [Resolver](commonware_resolver::Resolver).
pub struct Config<P, C, B, D>
where
    P: PublicKey,
    C: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    D: Digest,
{
    /// The public key to identify this node.
    pub public_key: P,

    /// The provider of peers that can be consulted for fetching data.
    ///
    /// We only fetch data from peers in `latest.primary` (see [commonware_p2p::Provider]).
    pub peer_provider: C,

    /// The blocker that will be used to block peers that send invalid responses.
    pub blocker: B,

    /// The size of the request mailbox backlog.
    pub mailbox_size: NonZeroUsize,

    /// Timeout for requests.
    pub timeout: Duration,

    /// Retry timeout for the fetcher.
    pub fetch_retry_timeout: Duration,

    /// Whether requests are sent with priority over other network messages
    pub priority_requests: bool,

    /// Whether responses are sent with priority over other network messages
    pub priority_responses: bool,

    /// Size limits for the values this resolver serves.
    pub limits: Limits<D>,
}

/// Mailbox for issuing marshal backfill requests.
pub type Mailbox<D, P> = p2p::Mailbox<Key<D>, P, Annotation>;

/// Initialize a P2P resolver.
///
/// # Panics
///
/// Panics if the largest value under [`Limits`] plus
/// [`MAX_MESSAGE_OVERHEAD`](commonware_resolver::p2p::MAX_MESSAGE_OVERHEAD) exceeds the `backfill`
/// sender's [`max_message_size`](commonware_p2p::LimitedSender::max_message_size).
pub fn init<E, C, B, D, S, R, P>(
    context: E,
    config: Config<P, C, B, D>,
    backfill: (S, R),
) -> (HandlerReceiver<D>, Mailbox<D, P>)
where
    E: BufferPooler + Rng + Spawner + Clock + Metrics,
    C: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    D: Digest,
    S: Sender<PublicKey = P>,
    R: P2pReceiver<PublicKey = P>,
    P: PublicKey,
{
    let limit: usize = Widen::widen(backfill.0.max_message_size());
    assert!(
        config.limits.response() <= limit,
        "backfill size {} exceeds sender limit {limit}",
        config.limits.response()
    );

    let (sender, receiver) = mailbox::new(context.child("handler"), config.mailbox_size);
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
            timeout: config.timeout,
            fetch_retry_timeout: config.fetch_retry_timeout,
            priority_requests: config.priority_requests,
            priority_responses: config.priority_responses,
        },
    );
    resolver_engine.start(backfill);
    (HandlerReceiver::new(receiver), resolver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshal::{
        mocks::harness::{self, B, D, TEST_QUOTA, default_leader},
        standard::Standard,
    };
    use commonware_p2p::simulated::{self, Network};
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::NZUsize;

    /// Initializes a resolver whose backfill sender accepts at most `max_size` bytes.
    fn init_with(max_size: u32) {
        deterministic::Runner::default().start(|context| async move {
            let me = default_leader();
            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                simulated::Config {
                    max_size,
                    max_peers_per_set: NZUsize!(1),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                [me.clone()],
            )
            .await;
            network.start();
            let control = oracle.control(me.clone());
            let backfill = control.register(0, TEST_QUOTA).await.unwrap();
            let _ = init::<_, _, _, D, _, _, _>(
                context.child("resolver"),
                Config {
                    public_key: me,
                    peer_provider: oracle.manager(),
                    blocker: control,
                    mailbox_size: NZUsize!(1),
                    timeout: Duration::from_secs(1),
                    fetch_retry_timeout: Duration::from_secs(1),
                    priority_requests: false,
                    priority_responses: false,
                    limits: harness::limits::<Standard<B>>(),
                },
                backfill,
            );
        });
    }

    #[test]
    fn test_backfill_fits_sender() {
        let response = harness::limits::<Standard<B>>().response();
        init_with(u32::try_from(response).unwrap());
    }

    #[test]
    #[should_panic(expected = "backfill size 1292 exceeds sender limit 1291")]
    fn test_backfill_exceeds_sender() {
        let response = harness::limits::<Standard<B>>().response();
        init_with(u32::try_from(response).unwrap() - 1);
    }
}

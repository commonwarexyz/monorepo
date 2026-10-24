//! P2P resolver plumbing reused by the standard and coding marshal variants.

use crate::marshal::resolver::handler::{self, Annotation, Key, Receiver as HandlerReceiver};
use commonware_actor::mailbox;
use commonware_cryptography::{Digest, PublicKey};
use commonware_p2p::{Blocker, Provider, Receiver as P2pReceiver, Sender};
use commonware_resolver::p2p::{self, MAX_MESSAGE_OVERHEAD};
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::Widen;
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
    /// A fetch without targets is sent only to primary peers of the latest set. A fetch with
    /// targets, such as one from [`hint_finalized`](crate::marshal::core::Mailbox::hint_finalized),
    /// is sent to its targets whether they are primary or secondary peers of that set.
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
}

/// Mailbox for issuing marshal backfill requests.
pub type Mailbox<D, P> = p2p::Mailbox<Key<D>, P, Annotation>;

/// Initialize a P2P resolver.
///
/// The returned receiver carries values up to the `backfill` sender's
/// [`max_message_size`](commonware_p2p::LimitedSender::max_message_size) minus
/// [`MAX_MESSAGE_OVERHEAD`], and marshal derives its [block bound](crate::marshal#message-sizes)
/// from that size.
///
/// # Panics
///
/// Panics if the `backfill` sender's `max_message_size` is below [`MAX_MESSAGE_OVERHEAD`].
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
    // Every response adds resolver framing to its value.
    let max_value_size = Widen::<usize>::widen(backfill.0.max_message_size())
        .checked_sub(Widen::widen(MAX_MESSAGE_OVERHEAD))
        .expect("backfill sender must carry resolver framing");

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
    (HandlerReceiver::new(receiver, max_value_size), resolver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshal::mocks::harness::{D, TEST_QUOTA, default_leader};
    use commonware_p2p::simulated::{self, Network};
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::NZUsize;

    /// Initializes a resolver whose backfill sender accepts at most `max_size` bytes and returns
    /// the largest value its receiver carries.
    fn init_with(max_size: u32) -> usize {
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
            let (receiver, _) = init::<_, _, _, D, _, _, _>(
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
                },
                backfill,
            );
            receiver.max_value_size()
        })
    }

    #[test]
    fn test_backfill_value_follows_sender() {
        for max_size in [MAX_MESSAGE_OVERHEAD, 1024, 1024 * 1024] {
            assert_eq!(
                init_with(max_size),
                Widen::<usize>::widen(max_size - MAX_MESSAGE_OVERHEAD)
            );
        }
    }

    #[test]
    #[should_panic(expected = "backfill sender must carry resolver framing")]
    fn test_backfill_sender_below_framing() {
        init_with(MAX_MESSAGE_OVERHEAD - 1);
    }
}

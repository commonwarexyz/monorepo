mod discovery;
mod serving;

use super::mailbox::{Mailbox, Message};
use commonware_actor::mailbox::Receiver as ActorReceiver;
use commonware_consensus::{marshal::core::Variant, simplex::scheme::Scheme, types::Epoch};
use commonware_cryptography::{certificate::Provider, PublicKey};
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::NonZeroDuration;
use discovery::Discovery;
use rand_core::CryptoRngCore;
use std::num::NonZeroUsize;

/// Configuration for the [`FloorDiscovery`] actor.
pub struct Config<E, D, T, P, B>
where
    E: Spawner + CryptoRngCore + Clock + Metrics,
    D: Provider<Scope = Epoch>,
    T: Strategy,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
{
    /// The runtime context.
    pub context: E,
    /// Provider of epoch-specific certificate schemes for finalization verification.
    pub provider: D,
    /// The strategy to use for signature verification.
    pub strategy: T,
    /// The mailbox capacity.
    pub capacity: NonZeroUsize,
    /// Blocker used to block peers that send invalid finalizations.
    pub blocker: B,
    /// How long to wait for a threshold of matching finalizations before clearing
    /// the pending responses and re-requesting.
    pub retry_timeout: NonZeroDuration,
}

/// Discovers a sync floor by soliciting peers' latest finalizations and adopting the first one
/// reported by a threshold (`f + 1`) of distinct peers.
///
/// The actor is a two-phase state machine. It starts in discovery, waits until a subscriber needs
/// a floor, then solicits and tallies peers' finalizations without serving any of its own. Once a
/// marshal is attached, it hands off to serving, answering peers' requests from that marshal and
/// never issuing outbound requests. A source node that never needed a floor attaches a marshal
/// without consuming one and transitions straight to serving without soliciting peers.
pub struct FloorDiscovery<E, S, D, V, T, P, B>
where
    E: Spawner + CryptoRngCore + Clock + Metrics,
    S: Scheme<V::Commitment>,
    D: Provider<Scope = Epoch, Scheme = S>,
    V: Variant,
    T: Strategy,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
{
    context: ContextCell<E>,
    mailbox: ActorReceiver<Message<S, V>>,
    provider: D,
    strategy: T,
    blocker: B,
    retry_timeout: NonZeroDuration,
}

impl<E, S, D, V, T, P, B> FloorDiscovery<E, S, D, V, T, P, B>
where
    E: Spawner + CryptoRngCore + Clock + Metrics,
    S: Scheme<V::Commitment>,
    D: Provider<Scope = Epoch, Scheme = S>,
    V: Variant,
    T: Strategy,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
{
    /// Create a floor discovery actor and mailbox.
    pub fn new(config: Config<E, D, T, P, B>) -> (Self, Mailbox<S, V>) {
        let (sender, receiver) =
            commonware_actor::mailbox::new(config.context.child("mailbox"), config.capacity);
        let mailbox = Mailbox::new(sender);
        (
            Self {
                context: ContextCell::new(config.context),
                mailbox: receiver,
                provider: config.provider,
                strategy: config.strategy,
                blocker: config.blocker,
                retry_timeout: config.retry_timeout,
            },
            mailbox,
        )
    }

    /// Start the floor discovery actor.
    pub fn start(
        mut self,
        net: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(net))
    }

    async fn run(
        self,
        (mut sender, mut receiver): (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        Discovery {
            context: self.context,
            mailbox: self.mailbox,
            provider: self.provider,
            strategy: self.strategy,
            blocker: self.blocker,
            retry_timeout: self.retry_timeout,
            floor: None,
            floor_subscribers: Vec::new(),
        }
        .run(&mut sender, &mut receiver)
        .await;
    }
}

use super::{
    mailbox::{Mailbox, Message},
    sample::Sample,
};
use commonware_actor::mailbox::Receiver as ActorReceiver;
use commonware_consensus::{marshal::core::Variant, simplex::scheme::Scheme, types::Epoch};
use commonware_cryptography::{PublicKey, certificate::Provider};
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_utils::NonZeroDuration;
use discovery::Discovery;
use rand_core::CryptoRng;
use std::num::NonZeroUsize;

mod discovery;
mod service;

/// Configuration for the [`Probe`] actor.
pub struct Config<E, D, T, P, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
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
    pub mailbox_size: NonZeroUsize,
    /// Blocker used to block malicious peers.
    pub blocker: B,
    /// Lowest epoch whose finalizations are accepted.
    ///
    /// Requests go to this epoch's participants, only they may contribute replies, and its
    /// committee size sets the `f + 1` sample threshold.
    pub minimum_epoch: Epoch,
    /// Time to wait for a complete sample before starting a new request round.
    pub retry_timeout: NonZeroDuration,
}

/// Discovers a floor from a peer sample, then serves this node's latest finalization to peers.
///
/// See the [module documentation](crate::stateful::probe#lifecycle) for when each phase runs.
pub struct Probe<E, S, D, V, T, P, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    S: Scheme<V::Commitment, PublicKey = P>,
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
    minimum_epoch: Epoch,
    retry_timeout: NonZeroDuration,
}

impl<E, S, D, V, T, P, B> Probe<E, S, D, V, T, P, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    S: Scheme<V::Commitment, PublicKey = P>,
    D: Provider<Scope = Epoch, Scheme = S>,
    V: Variant,
    T: Strategy,
    P: PublicKey,
    B: Blocker<PublicKey = P>,
{
    /// Creates a probe actor and its mailbox.
    pub fn new(config: Config<E, D, T, P, B>) -> (Self, Mailbox<S, V>) {
        let (sender, receiver) =
            commonware_actor::mailbox::new(config.context.child("mailbox"), config.mailbox_size);
        let mailbox = Mailbox::new(sender);
        (
            Self {
                context: ContextCell::new(config.context),
                mailbox: receiver,
                provider: config.provider,
                strategy: config.strategy,
                blocker: config.blocker,
                minimum_epoch: config.minimum_epoch,
                retry_timeout: config.retry_timeout,
            },
            mailbox,
        )
    }

    /// Starts the actor on the probe channel `net`.
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
            sample: Sample::new(self.minimum_epoch),
            subscribers: Vec::new(),
        }
        .run(&mut sender, &mut receiver)
        .await;
    }
}

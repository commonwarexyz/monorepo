use super::mailbox::{Mailbox, Message};
use crate::{
    dkg::{
        ReshareBlock,
        types::{EpochInfo, Participants},
    },
    stateful::probe::sample::Sample,
};
use commonware_actor::mailbox::{self as actor_mailbox, Receiver as ActorReceiver};
use commonware_codec::Read;
use commonware_consensus::{
    marshal::core::Variant,
    simplex::scheme::Scheme,
    types::{Epoch, FixedEpocher},
};
use commonware_cryptography::Signer;
use commonware_p2p::{Blocker, Manager, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_utils::NonZeroDuration;
use discovery::Discovery;
use rand_core::CryptoRng;
use std::num::{NonZeroU64, NonZeroUsize};

mod discovery;
mod service;

/// Configuration for the DKG probe actor.
pub struct Config<E, M, S, V, T, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    M: Manager<PublicKey = S::PublicKey>,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
    T: Strategy,
    B: Blocker<PublicKey = S::PublicKey>,
{
    /// Runtime context.
    pub context: E,
    /// P2P manager used to track the bootstrap participants when discovery
    /// begins.
    pub manager: M,
    /// The complete participant snapshot of [`Config::bootstrap_epoch`].
    ///
    /// Discovery solicits and samples `f + 1` of the snapshot's dealers,
    /// which are the epoch's active committee (its share holders and
    /// certificate signers), so the dealers must be that complete committee:
    /// a subset mis-derives `f`. See the module docs for the trust model and
    /// the budgets on faulty, stale, and unreachable members.
    ///
    /// The snapshot must match the epoch's canonical [`Participants`]: when
    /// discovery begins, the actor tracks the snapshot's
    /// [`tracked_peers`](Participants::tracked_peers) at the epoch's own
    /// peer-set ID, and all peers must track the same set contents at the
    /// same ID. The orchestrator tracks the identical contents if it later
    /// enters the bootstrap epoch, so the duplicate registration is benign.
    pub bootstrap_participants: Participants<S::PublicKey>,
    /// Epoch whose participant snapshot is [`Config::bootstrap_participants`].
    ///
    /// Latest-finalization replies below this epoch are ignored, so the
    /// discovered floor is never older than the configured trust point.
    pub bootstrap_epoch: Epoch,
    /// All-epoch certificate verifier built from the constant BLS identity.
    pub verifier: S,
    /// Public epoch information carried by genesis.
    pub genesis: EpochInfo<<V::ApplicationBlock as ReshareBlock>::Variant, S::PublicKey>,
    /// Strategy for certificate verification.
    pub strategy: T,
    /// Blocker used to block peers that send invalid bootstrap data.
    pub blocker: B,
    /// Number of blocks in each epoch.
    pub blocks_per_epoch: NonZeroU64,
    /// How long to wait before trying another boundary responder or re-broadcasting discovery.
    pub retry_timeout: NonZeroDuration,
    /// Mailbox capacity.
    pub mailbox_size: NonZeroUsize,
    /// Codec configuration for application blocks received in boundary responses.
    pub block_codec_config: <V::ApplicationBlock as Read>::Cfg,
}

/// DKG probe actor.
pub struct Actor<E, M, S, V, T, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    M: Manager<PublicKey = S::PublicKey>,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
    T: Strategy,
    B: Blocker<PublicKey = S::PublicKey>,
{
    context: ContextCell<E>,
    mailbox: ActorReceiver<Message<S, V>>,
    manager: M,
    bootstrap_participants: Participants<S::PublicKey>,
    bootstrap_epoch: Epoch,
    verifier: S,
    genesis: EpochInfo<<V::ApplicationBlock as ReshareBlock>::Variant, S::PublicKey>,
    strategy: T,
    blocker: B,
    blocks_per_epoch: NonZeroU64,
    retry_timeout: NonZeroDuration,
    block_codec_config: <V::ApplicationBlock as Read>::Cfg,
}

impl<E, M, S, V, T, B> Actor<E, M, S, V, T, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    M: Manager<PublicKey = S::PublicKey>,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
    T: Strategy,
    B: Blocker<PublicKey = S::PublicKey>,
{
    /// Create a probe actor and mailbox.
    pub fn new(config: Config<E, M, S, V, T, B>) -> (Self, Mailbox<S, V>) {
        let (sender, mailbox) =
            actor_mailbox::new(config.context.child("mailbox"), config.mailbox_size);
        let mailbox_handle = Mailbox::new(sender);
        (
            Self {
                context: ContextCell::new(config.context),
                mailbox,
                manager: config.manager,
                bootstrap_participants: config.bootstrap_participants,
                bootstrap_epoch: config.bootstrap_epoch,
                verifier: config.verifier,
                genesis: config.genesis,
                strategy: config.strategy,
                blocker: config.blocker,
                blocks_per_epoch: config.blocks_per_epoch,
                retry_timeout: config.retry_timeout,
                block_codec_config: config.block_codec_config,
            },
            mailbox_handle,
        )
    }

    /// Start the probe actor.
    ///
    /// The boundary network is the probe request channel used to sample the
    /// configured committee's latest finalizations, fetch the target epoch's
    /// boundary finalization and block, and later serve the same requests to
    /// other joining peers.
    pub fn start<BSE, BRE>(mut self, boundaries: (BSE, BRE)) -> Handle<()>
    where
        BSE: Sender<PublicKey = S::PublicKey>,
        BRE: Receiver<PublicKey = S::PublicKey>,
    {
        spawn_cell!(self.context, self.run(boundaries,))
    }

    async fn run<BSE, BRE>(self, (boundary_sender, boundary_receiver): (BSE, BRE))
    where
        BSE: Sender<PublicKey = S::PublicKey>,
        BRE: Receiver<PublicKey = S::PublicKey>,
    {
        Discovery {
            context: self.context,
            mailbox: self.mailbox,
            manager: self.manager,
            bootstrap_participants: self.bootstrap_participants,
            verifier: self.verifier,
            genesis: self.genesis,
            strategy: self.strategy,
            blocker: self.blocker,
            epocher: FixedEpocher::new(self.blocks_per_epoch),
            block_codec_config: self.block_codec_config,
            retry_timeout: self.retry_timeout,
            artifact: None,
            sample: Sample::new(self.bootstrap_epoch),
            subscribers: Vec::new(),
            pending: None,
        }
        .run(boundary_sender, boundary_receiver)
        .await;
    }
}

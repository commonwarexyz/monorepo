use super::mailbox::{Mailbox, Message};
use crate::{
    dkg::{ReshareBlock, network::Manager, probe::Bootstrap, types::EpochInfo},
    stateful::probe::sample::Sample,
};
use commonware_actor::mailbox::{self as actor_mailbox, Receiver as ActorReceiver};
use commonware_codec::Read;
use commonware_consensus::{
    Epochable as _,
    simplex::{marshal::core::Variant, scheme::Scheme, types::Finalization},
    types::FixedEpocher,
};
use commonware_cryptography::Signer;
use commonware_p2p::{Blocker, Receiver, Sender};
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
    M: Manager<
            PublicKey = S::PublicKey,
            Directory = <V::ApplicationBlock as ReshareBlock>::Directory,
        >,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
    T: Strategy,
    B: Blocker<PublicKey = S::PublicKey>,
{
    /// Runtime context.
    pub context: E,
    /// Peer manager that activates the bootstrap snapshot when discovery begins.
    pub manager: M,
    /// The weakly subjective checkpoint to bootstrap from.
    pub bootstrap: Bootstrap<S::PublicKey, <V::ApplicationBlock as ReshareBlock>::Directory>,
    /// State-sync floor persisted by an interrupted sync, if any.
    ///
    /// Pass it on restart so discovery ignores earlier epochs and returns info
    /// for the later of this floor and the sampled floor. Otherwise
    /// [`state_sync::Plan::init`](crate::dkg::state_sync::Plan::init) may panic
    /// on a floor paired with info from an older epoch.
    pub floor: Option<Finalization<S, V::Commitment>>,
    /// All-epoch certificate verifier built from the constant BLS identity.
    pub verifier: S,
    /// Public epoch information carried by genesis.
    pub genesis: EpochInfo<
        <V::ApplicationBlock as ReshareBlock>::Variant,
        S::PublicKey,
        <V::ApplicationBlock as ReshareBlock>::Directory,
    >,
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

/// Discovers and serves DKG bootstrap material (see the
/// [module docs](crate::dkg::probe)).
pub struct Actor<E, M, S, V, T, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    M: Manager<
            PublicKey = S::PublicKey,
            Directory = <V::ApplicationBlock as ReshareBlock>::Directory,
        >,
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
    bootstrap: Bootstrap<S::PublicKey, <V::ApplicationBlock as ReshareBlock>::Directory>,
    floor: Option<Finalization<S, V::Commitment>>,
    verifier: S,
    genesis: EpochInfo<
        <V::ApplicationBlock as ReshareBlock>::Variant,
        S::PublicKey,
        <V::ApplicationBlock as ReshareBlock>::Directory,
    >,
    strategy: T,
    blocker: B,
    blocks_per_epoch: NonZeroU64,
    retry_timeout: NonZeroDuration,
    block_codec_config: <V::ApplicationBlock as Read>::Cfg,
}

impl<E, M, S, V, T, B> Actor<E, M, S, V, T, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    M: Manager<
            PublicKey = S::PublicKey,
            Directory = <V::ApplicationBlock as ReshareBlock>::Directory,
        >,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
    T: Strategy,
    B: Blocker<PublicKey = S::PublicKey>,
{
    /// Creates a probe actor and its mailbox.
    pub fn new(config: Config<E, M, S, V, T, B>) -> (Self, Mailbox<S, V>) {
        let (sender, mailbox) =
            actor_mailbox::new(config.context.child("mailbox"), config.mailbox_size);
        let mailbox_handle = Mailbox::new(sender);
        (
            Self {
                context: ContextCell::new(config.context),
                mailbox,
                manager: config.manager,
                bootstrap: config.bootstrap,
                floor: config.floor,
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

    /// Starts the probe actor.
    ///
    /// `boundaries` carries probe requests and responses in both directions:
    /// this node's discovery and its service to other joining peers.
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
        // Ignore replies below the bootstrap epoch or the persisted floor's epoch.
        let minimum = self
            .floor
            .map_or(self.bootstrap.epoch, |floor| floor.epoch())
            .max(self.bootstrap.epoch);
        Discovery {
            context: self.context,
            mailbox: self.mailbox,
            manager: self.manager,
            sample: Sample::new(minimum),
            bootstrap: self.bootstrap,
            verifier: self.verifier,
            genesis: self.genesis,
            strategy: self.strategy,
            blocker: self.blocker,
            epocher: FixedEpocher::new(self.blocks_per_epoch),
            block_codec_config: self.block_codec_config,
            retry_timeout: self.retry_timeout,
            artifact: None,
            subscribers: Vec::new(),
            pending: None,
        }
        .run(boundary_sender, boundary_receiver)
        .await;
    }
}

use super::mailbox::{Mailbox, Message};
use crate::dkg::{types::EpochInfo, ReshareBlock};
use commonware_actor::mailbox::{self as actor_mailbox, Receiver as ActorReceiver};
use commonware_codec::Read;
use commonware_consensus::{marshal::core::Variant, simplex::scheme::Scheme, types::FixedEpocher};
use commonware_cryptography::Signer;
use commonware_p2p::{Blocker, Channel, Manager, Message as P2pMessage, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::{channel::mpsc, ordered::Set, NonZeroDuration};
use discovery::Discovery;
use rand_core::CryptoRngCore;
use std::num::{NonZeroU64, NonZeroUsize};

mod discovery;
mod serving;

/// Peer-set slot used before epoch-scoped tracking can supersede bootstrap peers.
const BOOTSTRAP_PEER_SET_INDEX: u64 = 0;

/// Configuration for the anchor actor.
pub struct Config<E, M, S, V, T, B>
where
    E: Spawner + CryptoRngCore + Clock + Metrics,
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
    /// P2P manager used to track the configured bootstrap peers.
    pub manager: M,
    /// Bootstrap peers used before epoch-scoped participants are known.
    pub peers: Set<S::PublicKey>,
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
    /// How long to wait for a boundary response before re-broadcasting the request.
    pub retry_timeout: NonZeroDuration,
    /// Mailbox capacity.
    pub mailbox_size: NonZeroUsize,
    /// Codec configuration for application blocks received in boundary responses.
    pub block_codec_config: <V::ApplicationBlock as Read>::Cfg,
}

/// Anchor actor.
pub struct Actor<E, M, S, V, T, B>
where
    E: Spawner + CryptoRngCore + Clock + Metrics,
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
    peers: Set<S::PublicKey>,
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
    E: Spawner + CryptoRngCore + Clock + Metrics,
    M: Manager<PublicKey = S::PublicKey>,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
    T: Strategy,
    B: Blocker<PublicKey = S::PublicKey>,
{
    /// Create a anchor actor and mailbox.
    pub fn new(config: Config<E, M, S, V, T, B>) -> (Self, Mailbox<S, V>) {
        let (sender, mailbox) =
            actor_mailbox::new(config.context.child("mailbox"), config.mailbox_size);
        let mailbox_handle = Mailbox::new(sender);
        (
            Self {
                context: ContextCell::new(config.context),
                mailbox,
                manager: config.manager,
                peers: config.peers,
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

    /// Start the anchor actor.
    ///
    /// The certificate backup channel is the mux backup receiver for the
    /// physical Simplex certificate channel. The boundary network is the
    /// anchor request channel used to fetch and later serve finalized boundary
    /// blocks.
    pub fn start<BSE, BRE>(
        mut self,
        certificates: mpsc::Receiver<(Channel, P2pMessage<S::PublicKey>)>,
        boundaries: (BSE, BRE),
    ) -> Handle<()>
    where
        BSE: Sender<PublicKey = S::PublicKey>,
        BRE: Receiver<PublicKey = S::PublicKey>,
    {
        spawn_cell!(self.context, self.run(certificates, boundaries,))
    }

    async fn run<BSE, BRE>(
        mut self,
        certificate_receiver: mpsc::Receiver<(Channel, P2pMessage<S::PublicKey>)>,
        (boundary_sender, boundary_receiver): (BSE, BRE),
    ) where
        BSE: Sender<PublicKey = S::PublicKey>,
        BRE: Receiver<PublicKey = S::PublicKey>,
    {
        let _ = self
            .manager
            .track(BOOTSTRAP_PEER_SET_INDEX, self.peers.clone());

        Discovery {
            context: self.context,
            mailbox: self.mailbox,
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
        .run(certificate_receiver, boundary_sender, boundary_receiver)
        .await;
    }
}

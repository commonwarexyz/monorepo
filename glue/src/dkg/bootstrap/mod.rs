//! One-shot engine for generating an initial BLS threshold output.
//!
//! The engine runs an independent Ed25519 Simplex chain for one epoch and
//! performs a single ceremony among the configured participants, using the
//! dealing and inclusion protocol of [`reshare`]. The resulting [`EpochInfo`]
//! describes only the ceremony participants (see [`Completion::info`] before
//! using it as the genesis of a continuously reshared chain).
//!
//! # Message Sizes
//!
//! The engine runs Simplex on its vote, certificate, and resolver channels, marshal on its backfill
//! and broadcast channels, and the [`reshare`] dealing protocol on its DKG channel. Marshal sends
//! each one-shot [`Block`] whole:
//!
//! ```text
//! Block:
//! +----------------------+---------------------+-------------------------+
//! | epoch (varint, 1-10) | view (varint, 1-10) | leader (32)             |
//! +----------------------+-----+---------------+-----+-------------------+
//! | parent view (varint, 1-10) | context parent (32) | block parent (32) |
//! +-----------------------+----+-------------+-------+-------------------+
//! | height (varint, 1-10) | payload flag (1) | payload                   |
//! +-----------------------+------------------+---------------------------+
//! ```
//!
//! The payload follows only when the flag is 1 and is at most
//! [`Payload::max_encode_size`](crate::dkg::types::Payload::max_encode_size) for the configured
//! participants and directory, so [`Block::max_encode_size`] is the size of the widest block.
//!
//! [`Limits`] holds the limits of Simplex, of marshal for that block, and of the DKG, and its
//! footprint is the largest of the three. Fold [`Limits`] into the network's `max_message_size`
//! with [`commonware_p2p::max_message_size`].
//!
//! ```
//! use commonware_cryptography::bls12381::primitives::variant::MinSig;
//! use commonware_glue::dkg::bootstrap::Limits;
//! use commonware_p2p::max_message_size;
//! use commonware_utils::sequence::Unit;
//!
//! // Fold the limits of a ceremony among 4 participants with a key-only directory.
//! let size = max_message_size(&[&Limits::new::<MinSig, _>(4, &Unit)]);
//! ```

use crate::dkg::{
    self, ParticipantsProvider, Registrar, ReshareBlock, SecretStore,
    fence::Fence,
    network::{Directory, Manager},
    reshare::{self, DkgConfig},
    state_sync::Plan as StateSyncPlan,
    types::{EpochInfo, Payload, SchemeInfo, max_participants},
};
use commonware_broadcast::buffered;
use commonware_codec::{
    Buf, Encode, EncodeSize, Error as CodecError, FixedSize, MaxEncodeSize, Read, ReadExt as _,
    Write,
};
use commonware_consensus::{
    Application, Block as ConsensusBlock, CertifiableBlock, Heightable,
    marshal::{
        self, Start,
        ancestry::Ancestry,
        core::Actor as MarshalActor,
        resolver::p2p as marshal_resolver,
        standard::{Deferred, Standard},
    },
    simplex::{
        self, Floor,
        config::{ForwardPolicy, SkipBudget, SkipPolicy},
        elector::RoundRobin,
        types::Context,
    },
    types::{Epoch, Epocher, FixedEpocher, Height, Round, View, ViewDelta},
};
use commonware_cryptography::{
    Digest as _, Digested, Digestible, Hasher, PublicKey, Sha256, Signer as _,
    bls12381::{
        dkg::feldman_desmedt::Reveal,
        primitives::{
            sharing::{Mode as SharingMode, ModeVersion},
            variant::Variant,
        },
    },
    certificate::{ConstantProvider, Verifier as _},
    ed25519,
    sha256::{self, Digest as Sha256Digest},
};
use commonware_p2p::{Blocker, Footprint, Receiver, Sender, max_footprint};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufMut, Clock, ContextCell, Handle, Metrics, Spawner, Storage, buffer::paged::CacheRef,
    spawn_cell,
};
use commonware_storage::{archive::prunable, translator::TwoCap};
use commonware_utils::{
    NZU32, NZUsize, TryCollect,
    channel::{fallible::OneshotExt, oneshot},
    ordered::Set,
    sequence::Unit,
    vec::NonEmptyVec,
};
use rand_core::CryptoRng;
use std::{
    marker::PhantomData,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    time::Duration,
};

type ConsensusScheme = simplex::scheme::ed25519::Scheme;

/// Configuration for [`Engine`].
pub struct Config<M, X, SS, T, D = Unit> {
    /// Ed25519 signer used for the one-shot consensus chain and DKG protocol messages.
    pub signer: ed25519::PrivateKey,

    /// Peer manager for the one-shot chain.
    ///
    /// Do not register peer sets before passing this manager to the engine.
    pub manager: M,

    /// Blocker used for invalid peer behavior.
    pub blocker: X,

    /// Application-owned store for this ceremony's secret material.
    ///
    /// Do not share this store with a [`reshare`] actor: both write epoch-zero
    /// dealer seeds and dealings. Copy only the resulting epoch-zero share.
    /// The engine never prunes this store.
    pub secret_store: SS,

    /// Parallel verification strategy.
    pub strategy: T,

    /// Application namespace for DKG transcript separation.
    pub namespace: &'static [u8],

    /// Sharing mode used for the generated threshold output.
    pub sharing_mode: SharingMode,

    /// Revealed-share calculation used for the DKG ceremony.
    pub reveal: Reveal,

    /// Maximum sharing mode version accepted when decoding blocks.
    pub max_supported_mode: ModeVersion,

    /// Runtime-storage partition prefix.
    pub partition_prefix: String,

    /// Page cache for the one-shot chain's journals and archives.
    pub page_cache: CacheRef,

    /// The size of the write buffer to use for each blob in the one-shot chain's storage.
    pub write_buffer: NonZeroUsize,

    /// Number of bytes to buffer when replaying the one-shot chain's storage during startup.
    pub replay_buffer: NonZeroUsize,

    /// Maximum number of messages to buffer in each of the engine's mailboxes.
    pub mailbox_size: NonZeroUsize,

    /// Maximum number of messages to buffer in the DKG channel muxer.
    pub muxer_size: usize,

    /// Number of items per section in each of the one-shot chain's archives, including
    /// marshal's cache.
    pub items_per_section: NonZeroU64,

    /// Participants in the DKG.
    pub participants: Set<ed25519::PublicKey>,

    /// Transport directory for the participants.
    ///
    /// Used to activate the one-shot chain's peer set and embedded verbatim in
    /// the resulting [`EpochInfo`]. It must contain exactly `participants`, and
    /// every participant must configure the same directory.
    ///
    /// The directory must stay byte-identical across restarts while the ceremony's stored blocks
    /// remain.
    pub directory: D,

    /// Number of blocks in the single epoch of the dedicated DKG chain.
    ///
    /// The second half of the epoch is the inclusion window, subject to the same
    /// [liveness](crate::dkg::reshare#liveness) requirement as resharing.
    pub blocks_per_epoch: NonZeroU64,
}

/// Outcome of the one-shot ceremony, reported at most once per engine start.
///
/// The engine reports it when this node processes the one-shot chain's final
/// block, or at startup if a previous run already persisted this node's share
/// or processed that block. It reports a completion without an artifact if the
/// ceremony cannot activate its peer set.
pub struct Completion<V: Variant, D: Directory<ed25519::PublicKey> = Unit> {
    /// Final DKG artifact, if the ceremony succeeded.
    ///
    /// Its `next_players` set is empty and its directory covers the one-shot
    /// ceremony participants. Before using it as continuous-resharing genesis,
    /// the application must choose a nonempty next-player set and ensure the
    /// directory exactly covers the resulting participant union.
    pub info: Option<EpochInfo<V, ed25519::PublicKey, D>>,
}

/// Block type used by the one-shot DKG chain.
///
/// Its codec decodes an epoch artifact only when it carries the ceremony's configured directory,
/// so no decoded block exceeds [`Block::max_encode_size`] for that directory.
#[derive(Clone, PartialEq, Eq)]
pub struct Block<V: Variant, D: Directory<ed25519::PublicKey> = Unit> {
    context: Context<sha256::Digest, ed25519::PublicKey>,
    parent: sha256::Digest,
    height: Height,
    payload: Option<Payload<V, ed25519::PublicKey, D>>,
}

impl<V: Variant, D: Directory<ed25519::PublicKey>> Block<V, D> {
    /// Returns the encoded size of the largest block the codec decodes for a ceremony among
    /// `participants` participants with the configured `directory`, or `None` if it overflows.
    pub fn max_encode_size(participants: NonZeroU32, directory: &D) -> Option<usize> {
        let payload = Payload::<V, ed25519::PublicKey, D>::max_encode_size(
            participants,
            directory.encode_size(),
        )?;
        payload.checked_add(
            Context::<sha256::Digest, ed25519::PublicKey>::MAX_ENCODE_SIZE
                + sha256::Digest::SIZE
                + Height::MAX_ENCODE_SIZE
                + bool::SIZE,
        )
    }

    const fn new(
        context: Context<sha256::Digest, ed25519::PublicKey>,
        parent: sha256::Digest,
        height: Height,
        payload: Option<Payload<V, ed25519::PublicKey, D>>,
    ) -> Self {
        Self {
            context,
            parent,
            height,
            payload,
        }
    }

    const fn genesis(leader: ed25519::PublicKey) -> Self {
        Self::new(
            Context {
                round: Round::new(Epoch::zero(), View::zero()),
                leader,
                parent: (View::zero(), Sha256Digest::EMPTY),
            },
            Sha256Digest::EMPTY,
            Height::zero(),
            None,
        )
    }

    /// Returns the DKG result carried by this block, if present.
    pub const fn epoch_info(&self) -> Option<&EpochInfo<V, ed25519::PublicKey, D>> {
        match &self.payload {
            Some(Payload::EpochInfo(info)) => Some(info),
            _ => None,
        }
    }
}

impl<V: Variant, D: Directory<ed25519::PublicKey>> Write for Block<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.payload.write(buf);
    }
}

impl<V: Variant, D: Directory<ed25519::PublicKey>> EncodeSize for Block<V, D> {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.payload.encode_size()
    }
}

impl<V: Variant, D: Directory<ed25519::PublicKey>> Read for Block<V, D> {
    /// Maximum participants, maximum supported sharing mode, and the configured directory.
    type Cfg = (NonZeroU32, ModeVersion, D);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let (max_participants, max_supported_mode, directory) = cfg;
        let context = Context::read(buf)?;
        let parent = sha256::Digest::read(buf)?;
        let height = Height::read(buf)?;
        let payload = Option::<Payload<V, ed25519::PublicKey, D>>::read_cfg(
            buf,
            &(*max_participants, *max_supported_mode),
        )?;
        if let Some(Payload::EpochInfo(info)) = &payload
            && info.directory != *directory
        {
            return Err(CodecError::Invalid(
                "Block",
                "directory does not match the ceremony",
            ));
        }
        Ok(Self::new(context, parent, height, payload))
    }
}

impl<V: Variant, D: Directory<ed25519::PublicKey>> Digestible for Block<V, D> {
    type Digest = sha256::Digest;

    fn digest(&self) -> sha256::Digest {
        Sha256::hash(&[&self.encode()])
    }
}

impl<V: Variant, D: Directory<ed25519::PublicKey>> Heightable for Block<V, D> {
    fn height(&self) -> Height {
        self.height
    }
}

impl<V: Variant, D: Directory<ed25519::PublicKey>> ConsensusBlock for Block<V, D> {
    fn parent(&self) -> sha256::Digest {
        self.parent
    }
}

impl<V: Variant, D: Directory<ed25519::PublicKey>> CertifiableBlock for Block<V, D> {
    type Context = Context<sha256::Digest, ed25519::PublicKey>;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

impl<V: Variant, D: Directory<ed25519::PublicKey>> ReshareBlock for Block<V, D> {
    type Variant = V;
    type PublicKey = ed25519::PublicKey;
    type Directory = D;

    fn payload(&self) -> Option<Payload<Self::Variant, Self::PublicKey, Self::Directory>> {
        self.payload.clone()
    }
}

/// Largest payloads the bootstrap [`Engine`] sends, as [message sizes](self#message-sizes) draws
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Limits of the one-shot chain's Simplex engine.
    simplex: simplex::Limits,
    /// Limits of marshal for the widest block the codec decodes.
    marshal: marshal::Limits,
    /// Limits of the dealing protocol.
    dkg: dkg::Limits,
}

impl Limits {
    /// Returns the limits for a ceremony among `participants` participants with the configured
    /// `directory`.
    ///
    /// # Panics
    ///
    /// Panics if `participants` is zero or exceeds `u32::MAX`, if the widest block with its
    /// certificate exceeds the `u32::MAX` bytes a resolver response carries, or if a bound
    /// overflows `usize`.
    pub fn new<V: Variant, D: Directory<ed25519::PublicKey>>(
        participants: usize,
        directory: &D,
    ) -> Self {
        let dkg = dkg::Limits::new::<V, ed25519::PublicKey>(participants);
        let block = Block::<V, D>::max_encode_size(max_participants(participants), directory)
            .expect("block size must fit in usize");
        let marshal =
            marshal::Limits::new::<Standard<Block<V, D>>, ConsensusScheme>(participants, block);

        Self {
            simplex: simplex::Limits::new::<ConsensusScheme, sha256::Digest>(participants),
            marshal,
            dkg,
        }
    }
}

impl Footprint for Limits {
    fn footprint(&self) -> usize {
        max_footprint(&[&self.simplex, &self.marshal, &self.dkg])
    }
}

/// Self-contained DKG engine.
///
/// After reporting [`Completion`], the engine keeps running and serves the
/// one-shot chain so participants that have not completed can catch up. Keep
/// it running until every participant has completed.
///
/// At startup, the engine requests the final block's finalization in the
/// background, retrying until it is available. This lets lagging participants
/// catch up from peers that only serve the chain.
///
/// A restarted engine does not run the ceremony again once this node has
/// persisted its share or processed the final block. It reports the outcome
/// carried by the stored final block and keeps serving.
pub struct Engine<E, V, M, X, SS, T, D = Unit>
where
    V: Variant,
{
    context: ContextCell<E>,
    config: Config<M, X, SS, T, D>,
    _variant: PhantomData<V>,
}

impl<E, V, M, X, SS, T, D> Engine<E, V, M, X, SS, T, D>
where
    V: Variant,
{
    /// Creates a new engine.
    ///
    /// # Panics
    ///
    /// Panics if `max_supported_mode` does not support `sharing_mode`. The
    /// started engine panics if `participants` is empty, exceeds `u32::MAX`
    /// entries, or does not contain `signer`. It also panics if a successful
    /// ceremony's `directory` does not contain exactly `participants`, if a
    /// component fails, or if startup finds an epoch-zero share in `secret_store`
    /// without the one-shot chain's final block under `partition_prefix`.
    pub const fn new(context: E, config: Config<M, X, SS, T, D>) -> Self {
        assert!(
            config.max_supported_mode.supports(&config.sharing_mode),
            "sharing mode must be supported by max supported mode",
        );
        Self {
            context: ContextCell::new(context),
            config,
            _variant: PhantomData,
        }
    }
}

impl<E, V, M, X, SS, T, D> Engine<E, V, M, X, SS, T, D>
where
    E: CryptoRng + Spawner + Metrics + Clock + Storage,
    V: Variant,
    M: Manager<PublicKey = ed25519::PublicKey, Directory = D>,
    X: Blocker<PublicKey = ed25519::PublicKey>,
    SS: SecretStore,
    T: Strategy,
    D: Directory<ed25519::PublicKey>,
{
    /// Starts the engine and returns its handle and a receiver for its [`Completion`].
    ///
    /// The receiver closes without a value if the engine stops before reporting a completion.
    ///
    /// The network carrying these channels must have a `max_message_size` of at least the footprint
    /// of the [`Limits`] for the configured participants and directory.
    pub fn start(
        mut self,
        votes: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        certificates: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        resolver: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        backfill: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        broadcast: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        dkg: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
    ) -> (Handle<()>, oneshot::Receiver<Completion<V, D>>) {
        let (completion_tx, completion_rx) = oneshot::channel();
        let handle = spawn_cell!(
            self.context,
            self.run(
                votes,
                certificates,
                resolver,
                backfill,
                broadcast,
                dkg,
                completion_tx
            )
        );
        (handle, completion_rx)
    }

    #[allow(clippy::too_many_arguments)]
    async fn run(
        self,
        votes: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        certificates: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        resolver_network: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        backfill: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        broadcast: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        dkg: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        completion: oneshot::Sender<Completion<V, D>>,
    ) {
        assert!(
            !self.config.participants.is_empty(),
            "DKG requires at least one participant"
        );
        let participants = self
            .config
            .participants
            .len()
            .try_into()
            .expect("too many DKG participants");
        let max_participants = NZU32!(participants);
        let block_codec_config = (
            max_participants,
            self.config.max_supported_mode,
            self.config.directory.clone(),
        );

        let context = self.context.into_present();
        let page_cache = self.config.page_cache;
        let write_buffer = self.config.write_buffer;
        let replay_buffer = self.config.replay_buffer;
        let items_per_section = self.config.items_per_section;
        let public_key = self.config.signer.public_key();
        let consensus_namespace = [self.config.namespace, b"_INITIAL_CONSENSUS"].concat();
        let scheme = ConsensusScheme::signer(
            &consensus_namespace,
            self.config.participants.clone(),
            self.config.signer.clone(),
        )
        .expect("DKG signer must be a participant");
        let provider = ConstantProvider::<_, Epoch>::new(scheme.clone());
        let genesis = Block::<V, D>::genesis(
            self.config
                .participants
                .iter()
                .next()
                .expect("participants must be non-empty")
                .clone(),
        );

        let genesis = Digested::compute(genesis, &self.config.strategy).await;

        let (buffer, buffer_mailbox) = buffered::Engine::new(
            context.child("buffer"),
            buffered::Config {
                public_key: public_key.clone(),
                mailbox_size: self.config.mailbox_size,
                deque_size: 16,
                priority: false,
                codec_config: block_codec_config.clone(),
                peer_provider: self.config.manager.clone(),
                strategy: self.config.strategy.clone(),
            },
        );
        let buffer_handle = buffer.start(broadcast);

        let (backfill_handler, backfill_resolver) = marshal_resolver::init(
            context.child("backfill"),
            marshal_resolver::Config {
                public_key: public_key.clone(),
                peer_provider: self.config.manager.clone(),
                blocker: self.config.blocker.clone(),
                mailbox_size: self.config.mailbox_size,
                timeout: Duration::from_secs(2),
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
            backfill,
        );

        let finalizations = prunable::Archive::init(
            context.child("finalizations"),
            archive_config(
                &self.config.partition_prefix,
                "finalizations",
                page_cache.clone(),
                write_buffer,
                replay_buffer,
                items_per_section,
                ConsensusScheme::certificate_codec_config_unbounded(),
            ),
        )
        .await
        .expect("failed to initialize DKG finalization archive");
        let blocks = prunable::Archive::init(
            context.child("blocks"),
            archive_config(
                &self.config.partition_prefix,
                "blocks",
                page_cache.clone(),
                write_buffer,
                replay_buffer,
                items_per_section,
                block_codec_config.clone(),
            ),
        )
        .await
        .expect("failed to initialize DKG block archive");

        let (marshal_actor, marshal_mailbox, _) = MarshalActor::init(
            context.child("marshal"),
            finalizations,
            blocks,
            marshal::Config {
                provider: provider.clone(),
                epocher: FixedEpocher::new(self.config.blocks_per_epoch),
                start: Start::Genesis(genesis.clone()),
                partition_prefix: format!("{}-marshal", self.config.partition_prefix),
                mailbox_size: self.config.mailbox_size,
                view_retention: ViewDelta::new(10),
                prunable_items_per_section: items_per_section,
                page_cache: page_cache.clone(),
                replay_buffer,
                key_write_buffer: write_buffer,
                value_write_buffer: write_buffer,
                block_codec_config,
                max_repair: NZUsize!(10),
                max_pending_acks: NZUsize!(1),
                strategy: self.config.strategy.clone(),
            },
        )
        .await;

        // The one-shot chain ends at the epoch-zero final block.
        let last = FixedEpocher::new(self.config.blocks_per_epoch)
            .last(Epoch::zero())
            .expect("epocher must know epoch zero");
        if let Ok(targets) = self
            .config
            .participants
            .iter()
            .filter(|participant| **participant != public_key)
            .cloned()
            .try_collect::<NonEmptyVec<_>>()
        {
            marshal_mailbox.hint_finalized(last, targets);
        }

        // Run the ceremony in a DKG-mode reshare actor. Bootstrap runs the
        // one-shot chain's Simplex engine itself, without an orchestrator, so
        // nothing waits on the fence.
        let (fence, _gate) = Fence::new();
        let (reshare_actor, reshare_mailbox) = reshare::Actor::new_dkg(
            context.child("reshare"),
            reshare::Config {
                signer: self.config.signer.clone(),
                manager: self.config.manager.clone(),
                blocker: self.config.blocker.clone(),
                participants_provider: StaticParticipants {
                    participants: self.config.participants.clone(),
                    directory: self.config.directory.clone(),
                },
                secret_store: self.config.secret_store,
                strategy: self.config.strategy.clone(),
                registrar: NoopRegistrar(PhantomData),
                marshal: marshal_mailbox.clone(),
                state_sync: StateSyncPlan::disabled(),
                fence,
                namespace: self.config.namespace,
                sharing_mode: self.config.sharing_mode,
                reveal: self.config.reveal,
                mailbox_size: self.config.mailbox_size,
                muxer_size: self.config.muxer_size,
                partition_prefix: format!("{}-reshare", self.config.partition_prefix),
                page_cache: page_cache.clone(),
                write_buffer,
                replay_buffer,
                max_participants,
                blocks_per_epoch: self.config.blocks_per_epoch,
            },
            DkgConfig {
                participants: self.config.participants.clone(),
                directory: self.config.directory.clone(),
                completion: Box::new(move |info| {
                    let _ = completion.send_lossy(Completion { info });
                }),
            },
        );

        let app = reshare::Application::new(
            DkgApp {
                _marker: PhantomData,
                strategy: self.config.strategy.clone(),
            },
            reshare_mailbox.clone(),
            self.config.blocks_per_epoch,
        );
        let deferred = Deferred::new(
            context.child("deferred"),
            app,
            marshal_mailbox.clone(),
            FixedEpocher::new(self.config.blocks_per_epoch),
        );
        let floor = Floor::Genesis(genesis.digest());
        let simplex = simplex::Engine::new(
            context.child("simplex"),
            simplex::Config {
                scheme,
                elector: RoundRobin::<Sha256>::default(),
                blocker: self.config.blocker,
                automaton: deferred.clone(),
                relay: deferred.clone(),
                reporter: deferred,
                strategy: self.config.strategy,
                partition: format!("{}-simplex", self.config.partition_prefix),
                mailbox_size: self.config.mailbox_size,
                epoch: Epoch::zero(),
                floor,
                replay_buffer,
                write_buffer,
                page_cache,
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_millis(500),
                view_retention: ViewDelta::new(10),
                skip: SkipPolicy::Enabled {
                    timeout: Duration::from_secs(5),
                    budget: SkipBudget::Participants,
                },
                fetch_timeout: Duration::from_secs(2),
                forward: ForwardPolicy::Disabled,
                track_historical_votes: false,
            },
        );

        let reshare_handle = reshare_actor.start(dkg);
        let marshal_handle = marshal_actor.start(
            reshare_mailbox,
            buffer_mailbox,
            (backfill_handler, backfill_resolver),
        );
        let simplex_handle = simplex.start(votes, certificates, resolver_network);

        Handle::select([
            buffer_handle,
            reshare_handle,
            marshal_handle,
            simplex_handle,
        ])
        .await
        .expect("failed dkg");
    }
}

#[derive(Clone)]
struct DkgApp<V: Variant, D, T> {
    _marker: PhantomData<(V, D)>,
    strategy: T,
}

impl<E, V, D, T> Application<E> for DkgApp<V, D, T>
where
    E: Send,
    V: Variant,
    D: Directory<ed25519::PublicKey>,
    T: Strategy,
{
    type SigningScheme = ConsensusScheme;
    type Context = Context<sha256::Digest, ed25519::PublicKey>;
    type Block = Block<V, D>;
    type Input = reshare::Input<(), V, ed25519::PrivateKey, D>;

    async fn propose(
        &mut self,
        (_, context): (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        input: Self::Input,
    ) -> Option<Digested<Self::Block>> {
        let parent = ancestry.peek()?.clone();
        let height = parent.height().next();
        let block = Block::new(context, parent.digest(), height, input.payload);
        Some(Digested::compute(block, &self.strategy).await)
    }

    async fn verify(
        &mut self,
        _: (E, Self::Context),
        _ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        // reshare::Application already rejects a mismatched final block and an
        // earlier block carrying any payload except a dealer log from the
        // midpoint onward. The chain has no other state.
        true
    }
}

#[derive(Clone)]
struct StaticParticipants<P, D> {
    participants: Set<P>,
    directory: D,
}

impl<P, D> ParticipantsProvider for StaticParticipants<P, D>
where
    P: PublicKey,
    D: Directory<P>,
{
    type PublicKey = P;
    type Directory = D;

    async fn participants(&mut self, _: Epoch) -> Set<Self::PublicKey> {
        self.participants.clone()
    }

    async fn directory(&mut self, _: Epoch, _: Set<Self::PublicKey>) -> Self::Directory {
        self.directory.clone()
    }
}

#[derive(Clone)]
struct NoopRegistrar<V, P>(PhantomData<(V, P)>);

impl<V, P> Registrar for NoopRegistrar<V, P>
where
    V: Variant,
    P: PublicKey,
{
    type Variant = V;
    type PublicKey = P;

    async fn register(&self, _: Epoch, _: SchemeInfo<Self::Variant, Self::PublicKey>) {}
}

fn archive_config<C>(
    prefix: &str,
    name: &str,
    page_cache: CacheRef,
    write_buffer: NonZeroUsize,
    replay_buffer: NonZeroUsize,
    items_per_section: NonZeroU64,
    codec_config: C,
) -> prunable::Config<TwoCap, C> {
    prunable::Config {
        translator: TwoCap,
        metadata_partition: format!("{prefix}-{name}-metadata"),
        key_partition: format!("{prefix}-{name}-key"),
        key_page_cache: page_cache,
        value_partition: format!("{prefix}-{name}-value"),
        compression: None,
        codec_config,
        items_per_section,
        key_write_buffer: write_buffer,
        value_write_buffer: write_buffer,
        replay_buffer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::network::Addresses;
    use bytes::Bytes;
    use commonware_codec::Decode;
    use commonware_cryptography::{
        bls12381::primitives::{
            group::Scalar,
            variant::{MinPk, MinSig},
        },
        transcript::{Transcript, Version},
    };
    use commonware_math::poly::Poly;
    use commonware_p2p::{Address, Ingress};
    use commonware_utils::{Hostname, NZU16, NZU64, test_rng};
    use std::net::SocketAddr;

    /// Namespace for the transcripts these tests summarize.
    const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_BOOTSTRAP";

    /// Returns `count` sorted participants.
    fn participants(count: u32) -> Set<ed25519::PublicKey> {
        Set::from_iter_dedup(
            (0..u64::from(count)).map(|seed| ed25519::PrivateKey::from_seed(seed).public_key()),
        )
    }

    /// Returns a directory holding `address` for every peer.
    fn addresses(
        peers: &Set<ed25519::PublicKey>,
        address: Address,
    ) -> Addresses<ed25519::PublicKey> {
        peers
            .iter()
            .cloned()
            .map(|peer| (peer, address.clone()))
            .collect()
    }

    /// Returns the encoding of the widest block for a ceremony among `peers` with `directory`.
    /// Every varint is at its widest, and every set in its epoch artifact names every peer.
    fn widest_block<D: Directory<ed25519::PublicKey>>(
        peers: &Set<ed25519::PublicKey>,
        directory: &D,
    ) -> Bytes {
        // Start from the widest payload-free block and set its payload flag.
        let count = u32::try_from(peers.len()).unwrap();
        let mut bytes = Block::<MinSig, D> {
            context: Context {
                round: Round::new(Epoch::new(u64::MAX), View::new(u64::MAX)),
                leader: ed25519::PrivateKey::from_seed(0).public_key(),
                parent: (View::new(u64::MAX), Sha256::hash(&[b"parent"])),
            },
            parent: Sha256::hash(&[b"parent"]),
            height: Height::new(u64::MAX),
            payload: None,
        }
        .encode()
        .to_vec();
        assert_eq!(bytes.pop(), Some(0));
        1u8.write(&mut bytes);

        // An epoch artifact: tag, outcome, epoch, and an output with a summary, a sharing of
        // `count` coefficients, and its dealer, player, and revealed sets
        1u8.write(&mut bytes);
        0u8.write(&mut bytes);
        Epoch::new(u64::MAX).write(&mut bytes);
        Transcript::new(NAMESPACE, Version::V1)
            .summarize()
            .write(&mut bytes);
        0u8.write(&mut bytes);
        count.write(&mut bytes);
        Poly::<<MinSig as Variant>::Public>::commit(Poly::<Scalar>::new(test_rng(), count - 1))
            .write(&mut bytes);
        for _ in 0..3 {
            peers.write(&mut bytes);
        }

        // The artifact's player and next player sets, then the directory
        peers.write(&mut bytes);
        peers.write(&mut bytes);
        directory.write(&mut bytes);
        Bytes::from(bytes)
    }

    /// `Block::max_encode_size` is exactly the encoded size of the widest block the codec decodes.
    #[test]
    fn limits_cover_widest_decodable_block() {
        for participants in [1u32, 4, 128] {
            let count = NZU32!(participants);
            let peers = self::participants(participants);
            let directory = addresses(
                &peers,
                Address::Symmetric(SocketAddr::from(([127, 0, 0, 1], 3000))),
            );

            // With a key-only directory
            let cfg = (count, ModeVersion::v0(), Unit);
            let key_only = Block::<MinSig, Unit>::decode_cfg(widest_block(&peers, &Unit), &cfg)
                .expect("the widest block with a key-only directory must decode");
            assert_eq!(
                Some(key_only.encode().len()),
                Block::<MinSig, Unit>::max_encode_size(count, &Unit)
            );

            // With an address directory
            let cfg = (count, ModeVersion::v0(), directory.clone());
            let addressed = Block::<MinSig, _>::decode_cfg(widest_block(&peers, &directory), &cfg)
                .expect("the widest block with the configured directory must decode");
            assert_eq!(
                Some(addressed.encode().len()),
                Block::<MinSig, _>::max_encode_size(count, &directory)
            );
        }
    }

    /// The block codec rejects an epoch artifact whose directory is not the ceremony's.
    #[test]
    fn codec_rejects_other_directories() {
        let peers = participants(4);
        let socket = SocketAddr::from(([127, 0, 0, 1], 3000));
        let configured = addresses(&peers, Address::Symmetric(socket));
        let cfg = (NZU32!(4), ModeVersion::v0(), configured.clone());

        // The same keys behind longer addresses encode a block larger than
        // `Block::max_encode_size` for the configured directory, and the codec rejects it.
        let host = Hostname::new(format!("{}.{}", "a".repeat(40), "b".repeat(40))).unwrap();
        let widened = addresses(
            &peers,
            Address::Asymmetric {
                ingress: Ingress::Dns { host, port: 3000 },
                egress: socket,
            },
        );
        let encoded = widest_block(&peers, &widened);
        assert!(
            encoded.len() > Block::<MinSig, _>::max_encode_size(NZU32!(4), &configured).unwrap()
        );
        assert!(matches!(
            Block::<MinSig, Addresses<_>>::decode_cfg(encoded, &cfg),
            Err(CodecError::Invalid(
                _,
                "directory does not match the ceremony"
            ))
        ));
    }

    #[test]
    #[should_panic(expected = "sharing mode must be supported by max supported mode")]
    fn rejects_unsupported_sharing_mode() {
        let config = Config {
            signer: ed25519::PrivateKey::from_seed(0),
            manager: (),
            blocker: (),
            secret_store: (),
            strategy: (),
            namespace: b"test",
            sharing_mode: SharingMode::RootsOfUnity,
            reveal: Reveal::V1,
            max_supported_mode: ModeVersion::v0(),
            partition_prefix: "test".into(),
            page_cache: CacheRef::new(NZU16!(1024), NZUsize!(1)),
            write_buffer: NZUsize!(2048),
            replay_buffer: NZUsize!(2048),
            mailbox_size: NZUsize!(16),
            muxer_size: 16,
            items_per_section: NZU64!(10),
            participants: Set::default(),
            directory: Unit,
            blocks_per_epoch: NZU64!(1),
        };

        let _ = Engine::<_, MinPk, _, _, _, _, _>::new((), config);
    }
}

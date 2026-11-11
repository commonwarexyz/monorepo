//! One-shot engine for generating an initial BLS threshold output.
//!
//! The engine runs an independent Simplex chain for one epoch, signed with the
//! participants' [`CeremonyIdentity`] keys (such as Ed25519 or Secp256r1), and
//! performs a single ceremony among the configured participants, using the
//! dealing and inclusion protocol of [`reshare`]. The resulting [`EpochInfo`]
//! describes only the ceremony participants (see [`Completion::info`] before
//! using it as the genesis of a continuously reshared chain).
//!
//! # Message Sizes
//!
//! The engine runs Simplex on its vote, certificate, and resolver channels, marshal on its backfill
//! and broadcast channels, and the [`reshare`] dealing protocol on its DKG channel. Marshal's
//! backfill responses and broadcast messages carry the one-shot [`Block`]:
//!
//! ```text
//! Block:
//! +----------------------+---------------------+-------------------------+
//! | epoch (varint, 1-10) | view (varint, 1-10) | leader (public key)     |
//! +----------------------+-----+---------------+-----+-------------------+
//! | parent view (varint, 1-10) | context parent (32) | block parent (32) |
//! +-----------------------+----+-------------+-------+-------------------+
//! | height (varint, 1-10) | payload flag (1) | payload                   |
//! +-----------------------+------------------+---------------------------+
//! ```
//!
//! The payload follows only when the flag is 1 and is at most
//! [`Payload::max_encode_size`](crate::dkg::types::Payload::max_encode_size) for the configured
//! participants. [`BoundedBlock::max_encode_size`] bounds every block the block codec
//! configuration admits.
//!
//! [`max_payload_size`] is the largest of the payload bounds of Simplex, of marshal for that block,
//! and of the DKG.
//!
//! ```
//! use commonware_cryptography::{
//!     bls12381::primitives::{sharing::ModeVersion, variant::MinSig},
//!     ed25519,
//! };
//! use commonware_glue::dkg::bootstrap::max_payload_size;
//! use commonware_p2p::max_message_size;
//! use commonware_utils::{NZU32, sequence::Unit};
//!
//! // The network limit for a ceremony among 4 Ed25519 participants with a key-only directory.
//! let size = max_message_size([max_payload_size::<MinSig, ed25519::PrivateKey, Unit>(
//!     NZU32!(4),
//!     ModeVersion::v0(),
//! )]);
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
    Application, Block as ConsensusBlock, BoundedBlock, CertifiableBlock, Heightable,
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
    BatchVerifier, Digest as _, Digested, Digestible, Hasher, PublicKey, Sha256, Signer,
    bls12381::{
        dkg::feldman_desmedt::Reveal,
        primitives::{
            sharing::{Mode as SharingMode, ModeVersion},
            variant::Variant,
        },
    },
    certificate::{ConstantProvider, Verifier as _},
    ed25519, secp256r1,
    sha256::{self, Digest as Sha256Digest},
};
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufMut, Clock, ContextCell, Handle, Metrics, Spawner, Storage, buffer::paged::CacheRef,
    spawn_cell,
};
use commonware_storage::{archive::prunable, translator::TwoCap};
use commonware_utils::{
    NZUsize, NonZeroDuration, TryCollect,
    channel::{fallible::OneshotExt, oneshot},
    ordered::{BiMap, Set},
    sequence::Unit,
    vec::NonEmptyVec,
};
use rand_core::CryptoRng;
use std::{
    marker::PhantomData,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    time::Duration,
};

/// A node identity that can take part in the one-shot ceremony.
///
/// The identity signs the one-shot chain's votes and the DKG protocol messages,
/// and names the Simplex signing scheme its votes use. It is implemented for
/// [`ed25519::PrivateKey`] and [`secp256r1::standard::PrivateKey`]. A signer whose
/// key is held elsewhere (for example, in an HSM or a key management service)
/// implements it next to its [`Signer`] implementation.
pub trait CeremonyIdentity: Signer<PublicKey: BatchVerifier> {
    /// Simplex signing scheme of the one-shot chain.
    type Scheme: simplex::scheme::Scheme<Sha256Digest, PublicKey = Self::PublicKey>;

    /// Returns the scheme that signs as `signer` among `participants`, or `None`
    /// if `signer` is not a participant.
    fn consensus_signer(
        namespace: &[u8],
        participants: Set<Self::PublicKey>,
        signer: Self,
    ) -> Option<Self::Scheme>;
}

impl CeremonyIdentity for ed25519::PrivateKey {
    type Scheme = simplex::scheme::ed25519::Scheme;

    fn consensus_signer(
        namespace: &[u8],
        participants: Set<Self::PublicKey>,
        signer: Self,
    ) -> Option<Self::Scheme> {
        simplex::scheme::ed25519::Scheme::signer(namespace, participants, signer)
    }
}

impl CeremonyIdentity for secp256r1::standard::PrivateKey {
    type Scheme = simplex::scheme::secp256r1::Scheme<secp256r1::standard::PublicKey>;

    fn consensus_signer(
        namespace: &[u8],
        participants: Set<Self::PublicKey>,
        signer: Self,
    ) -> Option<Self::Scheme> {
        simplex::scheme::secp256r1::Scheme::signer(namespace, identity_keys(participants), signer)
    }
}

/// Maps each participant to itself, for schemes whose signing key is the
/// participant's identity key.
fn identity_keys<P: PublicKey>(participants: Set<P>) -> BiMap<P, P> {
    participants
        .into_iter()
        .map(|participant| (participant.clone(), participant))
        .try_collect()
        .expect("participants are distinct")
}

/// Configuration for [`Engine`].
pub struct Config<C: Signer, M, X, SS, T, D = Unit> {
    /// Signer used for the one-shot consensus chain and DKG protocol messages.
    pub signer: C,

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

    /// Maximum wait for a peer to respond to a resolver request.
    pub fetch_timeout: NonZeroDuration,

    /// Delay after an unresolved attempt before retrying its fetch.
    /// Zero permits immediate retries, subject to the sender's rate limit.
    pub fetch_retry_delay: Duration,

    /// Number of items per section in each of the one-shot chain's archives, including
    /// marshal's cache.
    pub items_per_section: NonZeroU64,

    /// Participants in the DKG.
    pub participants: Set<C::PublicKey>,

    /// Transport directory for the participants.
    ///
    /// Used to activate the one-shot chain's peer set and embedded verbatim in
    /// the resulting [`EpochInfo`]. It must contain exactly `participants`, and
    /// every participant must configure the same directory.
    pub directory: D,

    /// Number of blocks in the single epoch of the dedicated DKG chain.
    ///
    /// The second half of the epoch is the inclusion window, subject to the same
    /// [liveness](crate::dkg::reshare#liveness) requirement as resharing.
    pub blocks_per_epoch: NonZeroU64,

    /// Time to wait for the leader's proposal in each view of the one-shot chain.
    ///
    /// Every vote costs one signature, so a signer with a slow round trip (such
    /// as a remote key) needs longer timeouts.
    pub leader_timeout: Duration,

    /// Time to wait for a view of the one-shot chain to be certified after its proposal.
    pub certification_timeout: Duration,

    /// Time between retries of a view's timeout vote.
    pub timeout_retry: Duration,
}

/// Outcome of the one-shot ceremony, reported at most once per engine start.
///
/// The engine reports it when this node processes the one-shot chain's final
/// block, or at startup if a previous run already persisted this node's share
/// or processed that block. It reports a completion without an artifact if the
/// ceremony cannot activate its peer set.
pub struct Completion<V: Variant, P: PublicKey, D: Directory<P> = Unit> {
    /// Final DKG artifact, if the ceremony succeeded.
    ///
    /// Its `next_players` set is empty and its directory covers the one-shot
    /// ceremony participants. Before using it as continuous-resharing genesis,
    /// the application must choose a nonempty next-player set and ensure the
    /// directory exactly covers the resulting participant union.
    pub info: Option<EpochInfo<V, P, D>>,
}

/// Block type used by the one-shot DKG chain.
#[derive(Clone, PartialEq, Eq)]
pub struct Block<V: Variant, P: PublicKey, D: Directory<P> = Unit> {
    context: Context<sha256::Digest, P>,
    parent: sha256::Digest,
    height: Height,
    payload: Option<Payload<V, P, D>>,
}

impl<V: Variant, P: PublicKey, D: Directory<P>> Block<V, P, D> {
    const fn new(
        context: Context<sha256::Digest, P>,
        parent: sha256::Digest,
        height: Height,
        payload: Option<Payload<V, P, D>>,
    ) -> Self {
        Self {
            context,
            parent,
            height,
            payload,
        }
    }

    const fn genesis(leader: P) -> Self {
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
    pub const fn epoch_info(&self) -> Option<&EpochInfo<V, P, D>> {
        match &self.payload {
            Some(Payload::EpochInfo(info)) => Some(info),
            _ => None,
        }
    }
}

impl<V: Variant, P: PublicKey, D: Directory<P>> Write for Block<V, P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.payload.write(buf);
    }
}

impl<V: Variant, P: PublicKey, D: Directory<P>> EncodeSize for Block<V, P, D> {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.payload.encode_size()
    }
}

impl<V: Variant, P: PublicKey, D: Directory<P>> Read for Block<V, P, D> {
    /// Maximum participants and maximum supported sharing mode.
    type Cfg = (NonZeroU32, ModeVersion);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let context = Context::read(buf)?;
        let parent = sha256::Digest::read(buf)?;
        let height = Height::read(buf)?;
        let payload = Option::<Payload<V, P, D>>::read_cfg(buf, cfg)?;
        Ok(Self::new(context, parent, height, payload))
    }
}

impl<V: Variant, P: PublicKey, D: Directory<P>> BoundedBlock for Block<V, P, D> {
    fn max_encode_size((participants, _): &Self::Cfg) -> usize {
        // `Payload::max_encode_size` covers payloads of every sharing mode.
        Payload::<V, P, D>::max_encode_size(*participants)
            + Context::<sha256::Digest, P>::MAX_ENCODE_SIZE
            + sha256::Digest::SIZE
            + Height::MAX_ENCODE_SIZE
            + bool::SIZE
    }
}

impl<V: Variant, P: PublicKey, D: Directory<P>> Digestible for Block<V, P, D> {
    type Digest = sha256::Digest;

    fn digest(&self) -> sha256::Digest {
        Sha256::hash(&[&self.encode()])
    }
}

impl<V: Variant, P: PublicKey, D: Directory<P>> Heightable for Block<V, P, D> {
    fn height(&self) -> Height {
        self.height
    }
}

impl<V: Variant, P: PublicKey, D: Directory<P>> ConsensusBlock for Block<V, P, D> {
    fn parent(&self) -> sha256::Digest {
        self.parent
    }
}

impl<V: Variant, P: PublicKey, D: Directory<P>> CertifiableBlock for Block<V, P, D> {
    type Context = Context<sha256::Digest, P>;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

impl<V: Variant, P: PublicKey, D: Directory<P>> ReshareBlock for Block<V, P, D> {
    type Variant = V;
    type PublicKey = P;
    type Directory = D;

    fn payload(&self) -> Option<Payload<Self::Variant, Self::PublicKey, Self::Directory>> {
        self.payload.clone()
    }
}

/// Returns an upper bound on the payloads the bootstrap [`Engine`] sends for a ceremony among
/// `participants` participants with identity `C` and [`Config::max_supported_mode`] set to
/// `max_supported_mode`.
pub fn max_payload_size<V: Variant, C: CeremonyIdentity, D: Directory<C::PublicKey>>(
    participants: NonZeroU32,
    max_supported_mode: ModeVersion,
) -> usize {
    // Bound blocks by the codec configuration the engine decodes them with.
    let block_codec_config = (participants, max_supported_mode);
    simplex::max_payload_size::<C::Scheme, sha256::Digest>(participants.get())
        .max(marshal::max_payload_size::<
            Standard<Block<V, C::PublicKey, D>>,
            C::Scheme,
        >(participants.get(), &block_codec_config))
        .max(dkg::max_payload_size::<V, C::PublicKey>(participants))
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
pub struct Engine<E, V, C, M, X, SS, T, D = Unit>
where
    V: Variant,
    C: Signer,
{
    context: ContextCell<E>,
    config: Config<C, M, X, SS, T, D>,
    _variant: PhantomData<V>,
}

impl<E, V, C, M, X, SS, T, D> Engine<E, V, C, M, X, SS, T, D>
where
    V: Variant,
    C: Signer,
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
    pub const fn new(context: E, config: Config<C, M, X, SS, T, D>) -> Self {
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

impl<E, V, C, M, X, SS, T, D> Engine<E, V, C, M, X, SS, T, D>
where
    E: CryptoRng + Spawner + Metrics + Clock + Storage,
    V: Variant,
    C: CeremonyIdentity,
    M: Manager<PublicKey = C::PublicKey, Directory = D>,
    X: Blocker<PublicKey = C::PublicKey>,
    SS: SecretStore,
    T: Strategy,
    D: Directory<C::PublicKey>,
{
    /// Starts the engine and returns its handle and a receiver for its [`Completion`].
    ///
    /// The receiver closes without a value if the engine stops before reporting a completion.
    ///
    /// The network carrying these channels must have a `max_message_size` of at least
    /// [`max_payload_size`] for the configured participants, mode, and directory type.
    #[allow(clippy::type_complexity)]
    pub fn start(
        mut self,
        votes: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        certificates: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        resolver: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        backfill: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        broadcast: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        dkg: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) -> (
        Handle<()>,
        oneshot::Receiver<Completion<V, C::PublicKey, D>>,
    ) {
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
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        certificates: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        resolver_network: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        backfill: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        broadcast: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        dkg: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        completion: oneshot::Sender<Completion<V, C::PublicKey, D>>,
    ) {
        assert!(
            !self.config.participants.is_empty(),
            "DKG requires at least one participant"
        );
        let max_participants = max_participants(self.config.participants.len());
        let block_codec_config = (max_participants, self.config.max_supported_mode);

        let context = self.context.into_present();
        let page_cache = self.config.page_cache;
        let write_buffer = self.config.write_buffer;
        let replay_buffer = self.config.replay_buffer;
        let items_per_section = self.config.items_per_section;
        let public_key = self.config.signer.public_key();
        let consensus_namespace = [self.config.namespace, b"_INITIAL_CONSENSUS"].concat();
        let scheme = C::consensus_signer(
            &consensus_namespace,
            self.config.participants.clone(),
            self.config.signer.clone(),
        )
        .expect("DKG signer must be a participant");
        let provider = ConstantProvider::<_, Epoch>::new(scheme.clone());
        let genesis = Block::<V, C::PublicKey, D>::genesis(
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
                codec_config: block_codec_config,
                peer_provider: self.config.manager.clone(),
                blocker: self.config.blocker.clone(),
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
                fetch_timeout: self.config.fetch_timeout,
                fetch_retry_delay: self.config.fetch_retry_delay,
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
                C::Scheme::certificate_codec_config_unbounded(),
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
                block_codec_config,
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
                leader_timeout: self.config.leader_timeout,
                certification_timeout: self.config.certification_timeout,
                timeout_retry: self.config.timeout_retry,
                view_retention: ViewDelta::new(10),
                skip: SkipPolicy::Enabled {
                    timeout: Duration::from_secs(5),
                    budget: SkipBudget::Participants,
                },
                fetch_timeout: self.config.fetch_timeout,
                fetch_retry_delay: self.config.fetch_retry_delay,
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
struct DkgApp<V: Variant, C, D, T> {
    _marker: PhantomData<(V, C, D)>,
    strategy: T,
}

impl<E, V, C, D, T> Application<E> for DkgApp<V, C, D, T>
where
    E: Send,
    V: Variant,
    C: CeremonyIdentity,
    D: Directory<C::PublicKey>,
    T: Strategy,
{
    type SigningScheme = C::Scheme;
    type Context = Context<sha256::Digest, C::PublicKey>;
    type Block = Block<V, C::PublicKey, D>;
    type Input = reshare::Input<(), V, C, D>;

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
    use crate::dkg::{network::Addresses, tests::mocks::widest_addresses};
    use bytes::Bytes;
    use commonware_codec::{Decode, varint::MAX_U32_VARINT_SIZE};
    use commonware_cryptography::{
        bls12381::primitives::{
            group::Scalar,
            variant::{MinPk, MinSig},
        },
        certificate::{Membership, Scheme as _},
        transcript::{Transcript, Version},
    };
    use commonware_math::poly::Poly;
    use commonware_p2p::Address;
    use commonware_utils::{
        NZDuration, NZU16, NZU32, NZU64, Widen, ordered::Quorum as _, test_rng,
    };

    /// Namespace for the transcripts these tests summarize.
    const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_BOOTSTRAP";

    /// A one-shot block with a key-only directory.
    type KeyOnly = Block<MinSig, ed25519::PublicKey, Unit>;

    /// A one-shot block with an address directory.
    type Addressed = Block<MinSig, ed25519::PublicKey, Addresses<ed25519::PublicKey>>;

    /// Returns `count` sorted participants.
    fn participants(count: u32) -> Set<ed25519::PublicKey> {
        Set::from_iter_dedup(
            (0..u64::from(count)).map(|seed| ed25519::PrivateKey::from_seed(seed).public_key()),
        )
    }

    /// Returns the encoding of the widest block whose epoch artifact names `sets[0]` in its
    /// output, `sets[1]` as players, and `sets[2]` as next players, ending with `directory`.
    /// Epochs, views, and height use their widest encodings.
    fn widest_block<D: Directory<ed25519::PublicKey>>(
        sets: [&Set<ed25519::PublicKey>; 3],
        directory: &D,
    ) -> Bytes {
        // Start from the widest payload-free block and set its payload flag.
        let count = u32::try_from(sets[0].len()).unwrap();
        let mut bytes = Block::<MinSig, ed25519::PublicKey, D> {
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

        // Append the epoch artifact's tag, outcome, and epoch, then its output: a summary, a
        // sharing of `count` coefficients, and dealer, player, and revealed sets naming `sets[0]`.
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
            sets[0].write(&mut bytes);
        }

        // Append the artifact's player and next player sets, then the directory.
        sets[1].write(&mut bytes);
        sets[2].write(&mut bytes);
        directory.write(&mut bytes);
        Bytes::from(bytes)
    }

    /// Checks the block bound against the widest encoding and the unused width of its prefixes.
    #[test]
    fn max_encode_size_covers_widest_block() {
        for participants in [1u32, 4, 128] {
            let cfg = (NZU32!(participants), ModeVersion::v0());
            let count: usize = Widen::widen(participants);
            let prefix_slack = MAX_U32_VARINT_SIZE - count.encode_size();

            // The widest block with a key-only directory names every peer in every set. Its bound
            // adds the unused width of the artifact's commitment prefix and five participant-set
            // prefixes.
            let peers = self::participants(participants);
            let key_only = KeyOnly::decode_cfg(widest_block([&peers; 3], &Unit), &cfg)
                .expect("the widest block with a key-only directory must decode");
            assert_eq!(
                key_only.encode().len() + 6 * prefix_slack,
                KeyOnly::max_encode_size(&cfg)
            );

            // The widest block with an address directory names disjoint output players, players,
            // and next players, so its directory holds three times `participants` peers, each
            // behind the widest address. Its bound also adds the unused width of the directory's
            // key-set and address-list prefixes and of each address's hostname prefix.
            let peers = self::participants(3 * participants);
            let sets: Vec<Set<ed25519::PublicKey>> = (0..3)
                .map(|i| Set::from_iter_dedup(peers.iter().skip(i * count).take(count).cloned()))
                .collect();
            let directory = widest_addresses(&peers);
            let entries = 3 * count;
            let address_slack =
                Address::MAX_ENCODE_SIZE - directory.get(&peers[0]).unwrap().encode_size();
            let directory_slack =
                2 * (MAX_U32_VARINT_SIZE - entries.encode_size()) + entries * address_slack;
            let addressed = Addressed::decode_cfg(
                widest_block([&sets[0], &sets[1], &sets[2]], &directory),
                &cfg,
            )
            .expect("the widest block with an address directory must decode");
            assert_eq!(
                addressed.encode().len() + 6 * prefix_slack + directory_slack,
                Addressed::max_encode_size(&cfg)
            );
        }
    }

    /// `max_payload_size` is the largest of the Simplex, marshal, and DKG payload bounds for
    /// both directory types.
    #[test]
    fn covers_every_component() {
        type Scheme = simplex::scheme::ed25519::Scheme;
        for participants in [1u32, 4, 128] {
            let cfg = (NZU32!(participants), ModeVersion::v0());
            let simplex = simplex::max_payload_size::<Scheme, sha256::Digest>(participants);
            let dkg = dkg::max_payload_size::<MinSig, ed25519::PublicKey>(cfg.0);
            for (bound, marshal) in [
                (
                    max_payload_size::<MinSig, ed25519::PrivateKey, Unit>(cfg.0, ModeVersion::v0()),
                    marshal::max_payload_size::<Standard<KeyOnly>, Scheme>(participants, &cfg),
                ),
                (
                    max_payload_size::<MinSig, ed25519::PrivateKey, Addresses<ed25519::PublicKey>>(
                        cfg.0,
                        ModeVersion::v0(),
                    ),
                    marshal::max_payload_size::<Standard<Addressed>, Scheme>(participants, &cfg),
                ),
            ] {
                let terms = [simplex, marshal, dkg];
                assert!(terms.iter().all(|term| *term <= bound));
                assert!(terms.contains(&bound));
            }
        }
    }

    /// `max_payload_size` covers the Simplex, marshal, and DKG payloads of a Secp256r1 ceremony,
    /// whose votes, certificates, and keys are wider than Ed25519's.
    #[test]
    fn covers_every_component_secp256r1() {
        type Identity = secp256r1::standard::PrivateKey;
        type Key = secp256r1::standard::PublicKey;
        type Scheme = <Identity as CeremonyIdentity>::Scheme;
        for participants in [1u32, 4, 128] {
            let cfg = (NZU32!(participants), ModeVersion::v0());
            let bound = max_payload_size::<MinSig, Identity, Unit>(cfg.0, ModeVersion::v0());
            let terms = [
                simplex::max_payload_size::<Scheme, sha256::Digest>(participants),
                marshal::max_payload_size::<Standard<Block<MinSig, Key, Unit>>, Scheme>(
                    participants,
                    &cfg,
                ),
                dkg::max_payload_size::<MinSig, Key>(cfg.0),
            ];
            assert!(terms.iter().all(|term| *term <= bound));
            assert!(terms.contains(&bound));
            assert!(
                bound
                    > max_payload_size::<MinSig, ed25519::PrivateKey, Unit>(
                        cfg.0,
                        ModeVersion::v0()
                    )
            );
        }
    }

    /// Each built-in identity builds the scheme that signs as itself, and no scheme for a
    /// signer outside the participants.
    #[test]
    fn consensus_signer_requires_participant() {
        fn check<C: CeremonyIdentity>() {
            let signers: Vec<C> = (0..4).map(C::from_seed).collect();
            let participants = Set::from_iter_dedup(signers.iter().map(Signer::public_key));
            for signer in signers {
                let index = participants.index(&signer.public_key()).unwrap();
                let scheme = C::consensus_signer(NAMESPACE, participants.clone(), signer)
                    .expect("a participant must get a signing scheme");
                assert_eq!(scheme.me(), Some(Membership::Signer(index)));
                assert_eq!(scheme.participants(), &participants);
            }
            assert!(C::consensus_signer(NAMESPACE, participants, C::from_seed(4)).is_none());
        }
        check::<ed25519::PrivateKey>();
        check::<secp256r1::standard::PrivateKey>();
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
            fetch_timeout: NZDuration!(Duration::from_secs(2)),
            fetch_retry_delay: Duration::from_millis(100),
            items_per_section: NZU64!(10),
            participants: Set::default(),
            directory: Unit,
            blocks_per_epoch: NZU64!(1),
            leader_timeout: Duration::from_secs(1),
            certification_timeout: Duration::from_secs(2),
            timeout_retry: Duration::from_millis(500),
        };

        let _ = Engine::<_, MinPk, _, _, _, _, _, _>::new((), config);
    }
}

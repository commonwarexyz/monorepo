//! One-shot engine for generating an initial BLS threshold output.
//!
//! The engine runs an independent Ed25519 Simplex chain for one epoch and uses
//! the reshare actor's crate-private DKG mode to perform the ceremony.
//! The resulting [`EpochInfo`] can be used as the genesis threshold artifact for
//! a separate application that will later run continuous resharing.
//!
//! See [`reshare`] for the protocol flow that this engine reuses and for the
//! application contract of a continuously reshared chain.

use crate::dkg::{
    fence::Fence,
    reshare::{self, DkgConfig},
    types::{EpochInfo, Payload, SchemeInfo},
    ParticipantsProvider, Registrar, ReshareBlock, SecretStore,
};
use commonware_broadcast::buffered;
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_consensus::{
    marshal::{
        self, ancestry::Ancestry, core::Actor as MarshalActor, resolver::p2p as marshal_resolver,
        standard::Deferred, Start,
    },
    simplex::{self, config::ForwardingPolicy, elector::RoundRobin, types::Context, Floor},
    types::{Epoch, Epocher as _, FixedEpocher, Height, Round, View, ViewDelta},
    Application, Block as ConsensusBlock, CertifiableBlock, Heightable,
};
use commonware_cryptography::{
    bls12381::primitives::{sharing::Mode as SharingMode, variant::Variant},
    certificate::{ConstantProvider, Verifier as _},
    ed25519,
    sha256::{self, Digest as Sha256Digest},
    BatchVerifier, Digest as _, Digestible, Hasher, PublicKey, Sha256, Signer as _,
};
use commonware_p2p::{Blocker, Manager, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    buffer::paged::CacheRef, spawn_cell, Buf, BufMut, BufferPooler, Clock, ContextCell, Handle,
    Metrics, Spawner, Storage,
};
use commonware_storage::{archive::prunable, translator::TwoCap};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    ordered::Set,
    NZUsize, NZU16, NZU32, NZU64,
};
use futures::try_join;
use rand::{CryptoRng, Rng};
use rand_core::CryptoRngCore;
use std::{
    marker::PhantomData,
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    time::Duration,
};

const MAILBOX_SIZE: NonZeroUsize = NZUsize!(100);
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_PAGES: NonZeroUsize = NZUsize!(16);
const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(2048);
const ARCHIVE_ITEMS_PER_SECTION: NonZeroU64 = NZU64!(10);

type ConsensusScheme = simplex::scheme::ed25519::Scheme;

/// Configuration for [`Engine`].
pub struct Config<M, X, SS, T> {
    /// Ed25519 signer used for the one-shot consensus chain and DKG protocol messages.
    pub signer: ed25519::PrivateKey,

    /// P2P manager used for peer tracking.
    pub manager: M,

    /// Blocker used for invalid peer behavior.
    pub blocker: X,

    /// User-owned store for private DKG material.
    pub secret_store: SS,

    /// Parallel verification strategy.
    pub strategy: T,

    /// Application namespace for DKG transcript separation.
    pub namespace: &'static [u8],

    /// Sharing mode used for the generated threshold output.
    pub sharing_mode: SharingMode,

    /// Runtime-storage partition prefix.
    pub partition_prefix: String,

    /// Participants in the DKG.
    pub participants: Set<ed25519::PublicKey>,

    /// Length of the one-shot consensus epoch.
    pub blocks_per_epoch: NonZeroU64,
}

/// Completion produced when the one-shot DKG chain finalizes its final block.
pub struct Completion<V: Variant> {
    /// Final DKG artifact, if the ceremony succeeded.
    pub info: Option<EpochInfo<V, ed25519::PublicKey>>,
}

/// Block type used by the one-shot DKG chain.
#[derive(Clone, PartialEq, Eq)]
pub struct Block<V: Variant> {
    context: Context<sha256::Digest, ed25519::PublicKey>,
    parent: sha256::Digest,
    height: Height,
    payload: Option<Payload<V, ed25519::PrivateKey>>,
}

impl<V: Variant> Block<V> {
    const fn genesis(leader: ed25519::PublicKey) -> Self {
        Self {
            context: Context {
                round: Round::new(Epoch::zero(), View::zero()),
                leader,
                parent: (View::zero(), Sha256Digest::EMPTY),
            },
            parent: Sha256Digest::EMPTY,
            height: Height::zero(),
            payload: None,
        }
    }

    /// Returns the DKG result carried by this block, if present.
    pub const fn epoch_info(&self) -> Option<&EpochInfo<V, ed25519::PublicKey>> {
        match &self.payload {
            Some(Payload::EpochInfo(info)) => Some(info),
            _ => None,
        }
    }
}

impl<V: Variant> Write for Block<V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.payload.write(buf);
    }
}

impl<V: Variant> EncodeSize for Block<V> {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.payload.encode_size()
    }
}

impl<V: Variant> Read for Block<V> {
    type Cfg = NonZeroU32;

    fn read_cfg(buf: &mut impl Buf, max_participants: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            context: Context::read(buf)?,
            parent: sha256::Digest::read(buf)?,
            height: Height::read(buf)?,
            payload: Option::<Payload<V, ed25519::PrivateKey>>::read_cfg(buf, max_participants)?,
        })
    }
}

impl<V: Variant> Digestible for Block<V> {
    type Digest = sha256::Digest;

    fn digest(&self) -> sha256::Digest {
        Sha256::hash(&self.encode())
    }
}

impl<V: Variant> Heightable for Block<V> {
    fn height(&self) -> Height {
        self.height
    }
}

impl<V: Variant> ConsensusBlock for Block<V> {
    fn parent(&self) -> sha256::Digest {
        self.parent
    }
}

impl<V: Variant> CertifiableBlock for Block<V> {
    type Context = Context<sha256::Digest, ed25519::PublicKey>;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

impl<V: Variant> ReshareBlock for Block<V> {
    type Variant = V;
    type Signer = ed25519::PrivateKey;

    fn payload(&self) -> Option<Payload<Self::Variant, Self::Signer>> {
        self.payload.clone()
    }
}

/// Self-contained DKG engine.
pub struct Engine<E, V, M, X, SS, T>
where
    V: Variant,
{
    context: ContextCell<E>,
    config: Config<M, X, SS, T>,
    _variant: PhantomData<V>,
}

impl<E, V, M, X, SS, T> Engine<E, V, M, X, SS, T>
where
    V: Variant,
{
    /// Creates a new engine.
    pub const fn new(context: E, config: Config<M, X, SS, T>) -> Self {
        Self {
            context: ContextCell::new(context),
            config,
            _variant: PhantomData,
        }
    }
}

impl<E, V, M, X, SS, T> Engine<E, V, M, X, SS, T>
where
    E: Rng + CryptoRng + CryptoRngCore + Spawner + Metrics + Clock + Storage + BufferPooler,
    V: Variant,
    M: Manager<PublicKey = ed25519::PublicKey> + Clone,
    X: Blocker<PublicKey = ed25519::PublicKey> + Clone,
    SS: SecretStore,
    T: Strategy + Clone,
    ed25519::Batch: BatchVerifier<PublicKey = ed25519::PublicKey> + Send + 'static,
{
    /// Starts consensus, marshal, broadcast, and the private reshare DKG actor.
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
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
    ) -> (Handle<()>, oneshot::Receiver<Completion<V>>) {
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
        completion: oneshot::Sender<Completion<V>>,
    ) {
        assert!(
            !self.config.participants.is_empty(),
            "DKG requires at least one participant"
        );
        assert!(
            self.config.blocks_per_epoch.get() >= 4,
            "DKG epoch must have at least four blocks"
        );
        let participants = self
            .config
            .participants
            .len()
            .try_into()
            .expect("too many DKG participants");
        let max_participants = NZU32!(participants);

        let context = self.context.into_present();
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_PAGES);
        let public_key = self.config.signer.public_key();
        let consensus_namespace = [self.config.namespace, b"_INITIAL_CONSENSUS"].concat();
        let scheme = ConsensusScheme::signer(
            &consensus_namespace,
            self.config.participants.clone(),
            self.config.signer.clone(),
        )
        .expect("DKG signer must be a participant");
        let provider = ConstantProvider::<_, Epoch>::new(scheme.clone());
        let genesis = Block::<V>::genesis(
            self.config
                .participants
                .iter()
                .next()
                .expect("participants must be non-empty")
                .clone(),
        );

        let (buffer, buffer_mailbox) = buffered::Engine::new(
            context.child("buffer"),
            buffered::Config {
                public_key: public_key.clone(),
                mailbox_size: MAILBOX_SIZE,
                deque_size: 16,
                priority: false,
                codec_config: max_participants,
                peer_provider: self.config.manager.clone(),
            },
        );
        let buffer_handle = buffer.start(broadcast);

        let (backfill_handler, backfill_resolver) = marshal_resolver::init(
            context.child("backfill"),
            marshal_resolver::Config {
                public_key: public_key.clone(),
                peer_provider: self.config.manager.clone(),
                blocker: self.config.blocker.clone(),
                mailbox_size: MAILBOX_SIZE,
                initial: Duration::from_secs(1),
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
                max_participants,
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
                mailbox_size: MAILBOX_SIZE,
                view_retention_timeout: ViewDelta::new(10),
                prunable_items_per_section: ARCHIVE_ITEMS_PER_SECTION,
                page_cache: page_cache.clone(),
                replay_buffer: IO_BUFFER_SIZE,
                key_write_buffer: IO_BUFFER_SIZE,
                value_write_buffer: IO_BUFFER_SIZE,
                block_codec_config: max_participants,
                max_repair: NZUsize!(10),
                max_pending_acks: NZUsize!(1),
                strategy: self.config.strategy.clone(),
            },
        )
        .await;

        let (fence, _gate) = Fence::new(Epoch::zero());
        let (reshare_actor, reshare_mailbox) = reshare::Actor::new_dkg(
            context.child("reshare"),
            reshare::Config {
                signer: self.config.signer.clone(),
                manager: self.config.manager.clone(),
                blocker: self.config.blocker.clone(),
                participants_provider: StaticParticipants {
                    participants: self.config.participants.clone(),
                },
                secret_store: self.config.secret_store,
                strategy: self.config.strategy.clone(),
                registrar: NoopRegistrar(PhantomData),
                marshal: marshal_mailbox.clone(),
                fence,
                namespace: self.config.namespace,
                sharing_mode: self.config.sharing_mode,
                mailbox_size: MAILBOX_SIZE,
                partition_prefix: format!("{}-reshare", self.config.partition_prefix),
                max_participants,
                blocks_per_epoch: self.config.blocks_per_epoch,
                batch_verifier: PhantomData::<ed25519::Batch>,
            },
            DkgConfig {
                participants: self.config.participants.clone(),
                completion: Box::new(move |info| {
                    let _ = completion.send_lossy(Completion { info });
                }),
            },
        );

        let app = DkgApp {
            reshare: reshare_mailbox.clone(),
            blocks_per_epoch: self.config.blocks_per_epoch,
        };
        let deferred = Deferred::new(
            context.child("deferred"),
            app,
            marshal_mailbox.clone(),
            FixedEpocher::new(self.config.blocks_per_epoch),
        );
        let simplex = simplex::Engine::new(
            context.child("simplex"),
            simplex::Config {
                scheme,
                elector: RoundRobin::<Sha256>::default(),
                blocker: self.config.blocker,
                automaton: deferred.clone(),
                relay: deferred,
                reporter: marshal_mailbox.clone(),
                strategy: self.config.strategy,
                partition: format!("{}-simplex", self.config.partition_prefix),
                mailbox_size: MAILBOX_SIZE,
                epoch: Epoch::zero(),
                floor: Floor::Genesis(genesis.digest()),
                replay_buffer: IO_BUFFER_SIZE,
                write_buffer: IO_BUFFER_SIZE,
                page_cache,
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_millis(500),
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                fetch_timeout: Duration::from_secs(2),
                fetch_concurrent: NZUsize!(4),
                forwarding: ForwardingPolicy::Disabled,
            },
        );

        let reshare_handle = reshare_actor.start(dkg);
        let marshal_handle = marshal_actor.start(
            reshare_mailbox,
            buffer_mailbox,
            (backfill_handler, backfill_resolver),
        );
        let simplex_handle = simplex.start(votes, certificates, resolver_network);

        try_join!(
            buffer_handle,
            reshare_handle,
            marshal_handle,
            simplex_handle
        )
        .expect("failed dkg");
    }
}

#[derive(Clone)]
struct DkgApp<V: Variant> {
    reshare: reshare::Mailbox<Block<V>, V, ed25519::PrivateKey>,
    blocks_per_epoch: NonZeroU64,
}

impl<E, V> Application<E> for DkgApp<V>
where
    E: Rng + Spawner + Metrics + Clock,
    V: Variant,
{
    type SigningScheme = ConsensusScheme;
    type Context = Context<sha256::Digest, ed25519::PublicKey>;
    type Block = Block<V>;

    async fn propose(
        &mut self,
        (_, context): (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> Option<Self::Block> {
        let parent = ancestry.peek()?.clone();
        let height = parent.height().next();
        let payload = if self.final_block(height) {
            self.reshare.epoch_info(ancestry).await
        } else {
            self.reshare.next_log(height).await
        };
        Some(Block {
            context,
            parent: parent.digest(),
            height,
            payload,
        })
    }

    async fn verify(
        &mut self,
        _: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        let tip = ancestry.peek().cloned();
        let Some(tip) = tip else {
            return false;
        };
        if self.final_block(tip.height()) {
            let payload = self.reshare.epoch_info(ancestry).await;
            return payload == tip.payload();
        }
        true
    }
}

impl<V: Variant> DkgApp<V> {
    fn final_block(&self, height: Height) -> bool {
        FixedEpocher::new(self.blocks_per_epoch).last(Epoch::zero()) == Some(height)
    }
}

#[derive(Clone)]
struct StaticParticipants<P> {
    participants: Set<P>,
}

impl<P> ParticipantsProvider for StaticParticipants<P>
where
    P: PublicKey,
{
    type PublicKey = P;

    async fn participants(&mut self, _: Epoch) -> Set<Self::PublicKey> {
        self.participants.clone()
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
    codec_config: C,
) -> prunable::Config<TwoCap, C> {
    prunable::Config {
        translator: TwoCap,
        key_partition: format!("{prefix}-{name}-key"),
        key_page_cache: page_cache,
        value_partition: format!("{prefix}-{name}-value"),
        compression: None,
        codec_config,
        items_per_section: ARCHIVE_ITEMS_PER_SECTION,
        key_write_buffer: IO_BUFFER_SIZE,
        value_write_buffer: IO_BUFFER_SIZE,
        replay_buffer: IO_BUFFER_SIZE,
    }
}

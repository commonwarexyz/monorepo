use crate::{
    dkg::{
        anchor,
        fence::Fence,
        orchestrator, reshare,
        tests::mocks::{FilteredReceiver, MemorySecretStore},
        types::*,
        ParticipantsProvider, Registrar, ReshareBlock,
    },
    simulate::{
        engine::{EngineDefinition, InitContext},
        processed::ProcessedHeight,
        reporter::MonitorReporter,
    },
    stateful::{
        db::{
            p2p::standard as qmdb_resolver, DatabaseSet, Merkleized as _, SyncEngineConfig,
            Unmerkleized as _,
        },
        probe::{Config as ProbeConfig, Probe},
        Application, Config as StatefulConfig, Proposed, Stateful as StatefulActor, SyncPlan,
    },
};
use commonware_broadcast::buffered;
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_consensus::{
    marshal::{
        self,
        core::{Actor as MarshalActor, CommitmentFallback, Mailbox as MarshalMailbox},
        resolver::p2p as marshal_resolver,
        standard::{Deferred, Standard},
    },
    simplex::{self, config::ForwardingPolicy, elector::RoundRobin, types::Context},
    types::{Epoch, Epocher as _, FixedEpocher, Height, Round, View, ViewDelta},
    Block as ConsensusBlock, CertifiableBlock, Heightable, Reporters,
};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::deal,
        primitives::{group::Share, sharing::Mode, variant::MinPk},
    },
    certificate::{Provider as CertificateProvider, Scoped},
    ed25519,
    sha256::{self, Digest as Sha256Digest},
    Digest as _, Digestible, Hasher, Sha256, Signer as _,
};
use commonware_formatting::hex;
use commonware_math::algebra::Random;
use commonware_p2p::utils::mux::{Builder, Muxer};
use commonware_parallel::Sequential;
use commonware_runtime::{
    buffer::paged::CacheRef, deterministic::Context as DeterministicContext, Buf, BufMut, Clock,
    Handle, Metrics, Quota, Spawner, Storage, Supervisor as _,
};
use commonware_storage::{
    archive::prunable,
    journal::contiguous::fixed::Config as FixedLogConfig,
    mmr::{self, full::Config as MmrJournalConfig, Location},
    qmdb::{
        any::{unordered::fixed, FixedConfig},
        sync::Target,
    },
    translator::TwoCap,
};
use commonware_utils::{
    non_empty_range,
    ordered::{Map, Set},
    range::NonEmptyRange,
    sync::{Mutex, TracedAsyncRwLock},
    test_rng, test_rng_seeded, N3f1, NZDuration, NZUsize, NZU16, NZU32, NZU64,
};
use futures::{Stream, StreamExt};
use rand::Rng;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    marker::PhantomData,
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

type Qmdb<E> =
    fixed::Db<mmr::Family, E, sha256::Digest, sha256::Digest, Sha256, TwoCap, Sequential>;
type Database<E> = Arc<TracedAsyncRwLock<Qmdb<E>>>;
type Scheme = simplex::scheme::bls12381_threshold::vrf::Scheme<ed25519::PublicKey, MinPk>;
type MarshalVariant = Standard<Block>;
type ReshareMailbox = reshare::Mailbox<Block, MinPk, ed25519::PrivateKey>;
type Marshal = MarshalMailbox<Scheme, MarshalVariant>;

pub(super) const EPOCH_LENGTH: NonZeroU64 = NZU64!(32);
const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_RESHARE_E2E";
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(2048);
const TEST_QUOTA: Quota = Quota::per_second(NZU32!(1_000_000));
const MAX_PARTICIPANTS: NonZeroU32 = NZU32!(16);

const VOTE_CHANNEL: u64 = 0;
const CERTIFICATE_CHANNEL: u64 = 1;
const RESOLVER_CHANNEL: u64 = 2;
const BACKFILL_CHANNEL: u64 = 3;
const BROADCAST_CHANNEL: u64 = 4;
const QMDB_CHANNEL: u64 = 5;
const DKG_CHANNEL: u64 = 6;
const PROBE_CHANNEL: u64 = 7;
const ANCHOR_BOUNDARY_CHANNEL: u64 = 8;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Block {
    context: Context<sha256::Digest, ed25519::PublicKey>,
    parent: sha256::Digest,
    height: Height,
    state_root: sha256::Digest,
    range: NonEmptyRange<Location>,
    payload: Option<Payload<MinPk, ed25519::PrivateKey>>,
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.state_root.write(buf);
        self.range.write(buf);
        self.payload.write(buf);
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.state_root.encode_size()
            + self.range.encode_size()
            + self.payload.encode_size()
    }
}

impl Read for Block {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            context: Context::read(buf)?,
            parent: sha256::Digest::read(buf)?,
            height: Height::read(buf)?,
            state_root: sha256::Digest::read(buf)?,
            range: NonEmptyRange::read(buf)?,
            payload: Option::<Payload<MinPk, ed25519::PrivateKey>>::read_cfg(
                buf,
                &MAX_PARTICIPANTS,
            )?,
        })
    }
}

impl Digestible for Block {
    type Digest = sha256::Digest;

    fn digest(&self) -> sha256::Digest {
        Sha256::hash(&self.encode())
    }
}

impl Heightable for Block {
    fn height(&self) -> Height {
        self.height
    }
}

impl ConsensusBlock for Block {
    fn parent(&self) -> sha256::Digest {
        self.parent
    }
}

impl CertifiableBlock for Block {
    type Context = Context<sha256::Digest, ed25519::PublicKey>;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

impl ReshareBlock for Block {
    type Variant = MinPk;
    type Signer = ed25519::PrivateKey;

    fn payload(&self) -> Option<Payload<Self::Variant, Self::Signer>> {
        self.payload.clone()
    }
}

impl Block {
    fn genesis(leader: ed25519::PublicKey, info: EpochInfo<MinPk, ed25519::PublicKey>) -> Self {
        Self {
            context: Context {
                round: Round::new(Epoch::zero(), View::zero()),
                leader,
                parent: (View::zero(), sha256::Digest::EMPTY),
            },
            parent: sha256::Digest::EMPTY,
            height: Height::zero(),
            state_root: empty_db_root(),
            range: non_empty_range!(Location::new(0), Location::new(1)),
            payload: Some(Payload::EpochInfo(info)),
        }
    }
}

#[derive(Clone)]
struct App {
    genesis: Block,
    reshare: ReshareMailbox,
}

impl App {
    fn final_block(height: Height) -> bool {
        FixedEpocher::new(EPOCH_LENGTH)
            .containing(height)
            .is_some_and(|info| info.last() == height)
    }

    async fn execute<E: Rng + Spawner + Metrics + Clock + Storage>(
        height: Height,
        mut batches: <Database<E> as DatabaseSet<E>>::Unmerkleized,
    ) -> <Database<E> as DatabaseSet<E>>::Merkleized {
        let key = Sha256::hash(b"height");
        batches = batches.write(key, Some(u64_to_digest(height.get())));
        batches.merkleize().await.unwrap()
    }
}

impl<E: Rng + Spawner + Metrics + Clock + Storage> Application<E> for App {
    type SigningScheme = Scheme;
    type Context = Context<sha256::Digest, ed25519::PublicKey>;
    type Block = Block;
    type Databases = Database<E>;
    type InputProvider = ();

    async fn genesis(&mut self) -> Self::Block {
        self.genesis.clone()
    }

    async fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Stream<Item = Self::Block> + Send + 'static,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        _input: &mut Self::InputProvider,
    ) -> Option<Proposed<Self, E>> {
        let mut ancestry = Box::pin(ancestry.peekable());
        let parent = ancestry.as_mut().peek().await?.clone();
        let height = Height::new(parent.height().get() + 1);
        let payload = if Self::final_block(height) {
            self.reshare.epoch_info(ancestry).await
        } else {
            self.reshare.next_log(height).await
        };
        let merkleized = Self::execute(height, batches).await;
        let bounds = merkleized.bounds();
        let block = Block {
            context: context.1,
            parent: parent.digest(),
            height,
            state_root: merkleized.root(),
            range: non_empty_range!(bounds.inactivity_floor, Location::new(bounds.total_size)),
            payload,
        };
        Some(Proposed { block, merkleized })
    }

    async fn verify(
        &mut self,
        _context: (E, Self::Context),
        ancestry: impl Stream<Item = Self::Block> + Send + 'static,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        let mut ancestry = Box::pin(ancestry.peekable());
        let tip = ancestry.as_mut().peek().await?.clone();
        if Self::final_block(tip.height()) {
            let payload = self.reshare.epoch_info(ancestry).await;
            if payload != tip.payload() {
                return None;
            }
        }
        let merkleized = Self::execute(tip.height(), batches).await;
        Some(merkleized)
    }

    async fn apply(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<E>>::Merkleized {
        Self::execute(block.height(), batches).await
    }

    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        Target::new(block.state_root, block.range.clone())
    }
}

#[derive(Clone)]
struct DynamicProvider {
    schemes: Arc<Mutex<HashMap<Epoch, Arc<Scheme>>>>,
}

impl DynamicProvider {
    pub(super) fn new() -> Self {
        Self {
            schemes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn register(&self, epoch: Epoch, scheme: Scheme) {
        self.schemes.lock().insert(epoch, Arc::new(scheme));
    }
}

impl CertificateProvider for DynamicProvider {
    type Scope = Epoch;
    type Scheme = Scheme;

    fn scoped(&self, scope: Self::Scope) -> Option<Scoped<Self::Scheme>> {
        self.schemes.lock().get(&scope).cloned().map(Scoped::scheme)
    }

    fn scheme(&self, scope: Self::Scope) -> Option<Arc<Self::Scheme>> {
        self.schemes.lock().get(&scope).cloned()
    }
}

#[derive(Clone)]
struct TestRegistrar {
    provider: DynamicProvider,
    events: Arc<Mutex<BTreeMap<ed25519::PublicKey, Vec<Registration>>>>,
    public_key: ed25519::PublicKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RegistrationRole {
    Signer,
    Verifier,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Registration {
    pub(super) epoch: Epoch,
    pub(super) role: RegistrationRole,
}

impl Registrar for TestRegistrar {
    type Variant = MinPk;
    type PublicKey = ed25519::PublicKey;

    async fn register(&self, epoch: Epoch, info: SchemeInfo<Self::Variant, Self::PublicKey>) {
        let (scheme, role) = match info {
            SchemeInfo::Verifier {
                participants,
                sharing,
            } => (
                Scheme::verifier(NAMESPACE, participants, sharing),
                RegistrationRole::Verifier,
            ),
            SchemeInfo::Signer {
                participants,
                sharing,
                share,
            } => (
                Scheme::signer(NAMESPACE, participants, sharing, share)
                    .expect("share must match participant set"),
                RegistrationRole::Signer,
            ),
        };
        self.provider.register(epoch, scheme);
        self.events
            .lock()
            .entry(self.public_key.clone())
            .or_default()
            .push(Registration { epoch, role });
    }
}

#[derive(Clone)]
struct ScheduleProvider {
    pub(super) schedule: Arc<CommitteeSchedule>,
}

impl ParticipantsProvider for ScheduleProvider {
    type PublicKey = ed25519::PublicKey;

    async fn participants(&mut self, epoch: Epoch) -> Set<Self::PublicKey> {
        self.schedule.players(epoch)
    }
}

#[derive(Clone)]
pub(super) struct CommitteeSchedule {
    participants: Vec<ed25519::PublicKey>,
    committee_sizes: Vec<usize>,
}

impl CommitteeSchedule {
    pub(super) fn players(&self, epoch: Epoch) -> Set<ed25519::PublicKey> {
        let offset = epoch.get() as usize % self.participants.len();
        let committee_size =
            self.committee_sizes[epoch.get() as usize % self.committee_sizes.len()];
        let players = (0..committee_size)
            .map(|i| self.participants[(offset + i) % self.participants.len()].clone());
        Set::from_iter_dedup(players)
    }
}

#[derive(Clone)]
pub(super) struct ReshareEngine {
    signers: Vec<ed25519::PrivateKey>,
    pub(super) participants: Vec<ed25519::PublicKey>,
    pub(super) schedule: Arc<CommitteeSchedule>,
    initial: Arc<InitialState>,
    sharing_mode: Mode,
    stores: Arc<Mutex<BTreeMap<ed25519::PublicKey, MemorySecretStore>>>,
    pub(super) registrations: Arc<Mutex<BTreeMap<ed25519::PublicKey, Vec<Registration>>>>,
    pub(super) state_syncs: Arc<Mutex<BTreeMap<ed25519::PublicKey, u64>>>,
    failures: Arc<HashSet<u64>>,
}

pub(super) struct ValidatorEngine {
    context: DeterministicContext,
    handles: ValidatorHandles,
}

struct ValidatorHandles {
    anchor: Handle<()>,
    probe: Handle<()>,
    qmdb: Handle<()>,
    reshare: Handle<()>,
    orchestrator: Handle<()>,
    marshal: Handle<()>,
    stateful: Handle<()>,
}

impl ValidatorHandles {
    async fn join(mut self) {
        futures::try_join!(
            &mut self.anchor,
            &mut self.probe,
            &mut self.qmdb,
            &mut self.reshare,
            &mut self.orchestrator,
            &mut self.marshal,
            &mut self.stateful,
        )
        .expect("validator actor failed");
    }
}

impl Drop for ValidatorHandles {
    fn drop(&mut self) {
        self.anchor.abort();
        self.probe.abort();
        self.qmdb.abort();
        self.reshare.abort();
        self.orchestrator.abort();
        self.marshal.abort();
        self.stateful.abort();
    }
}

#[derive(Clone)]
struct InitialState {
    info: EpochInfo<MinPk, ed25519::PublicKey>,
    shares: Map<ed25519::PublicKey, Share>,
}

impl ReshareEngine {
    pub(super) fn new() -> Self {
        Self::with_committee(5, 4)
    }

    pub(super) fn with_committee(total: u32, committee_size: usize) -> Self {
        Self::with_committees(total, vec![committee_size])
    }

    pub(super) fn with_committees(total: u32, committee_sizes: Vec<usize>) -> Self {
        assert!(!committee_sizes.is_empty());
        for committee_size in &committee_sizes {
            assert!(*committee_size > 0);
            assert!(*committee_size <= total as usize);
        }
        let mut rng = test_rng();
        let signers = (0..total)
            .map(|_| ed25519::PrivateKey::random(&mut rng))
            .collect::<Vec<_>>();
        let participants = signers.iter().map(|s| s.public_key()).collect::<Vec<_>>();
        let schedule = Arc::new(CommitteeSchedule {
            participants: participants.clone(),
            committee_sizes,
        });
        let players = schedule.players(Epoch::zero());
        let (output, shares) =
            deal::<MinPk, _, N3f1>(test_rng_seeded(10), Mode::NonZeroCounter, players.clone())
                .expect("trusted initial deal");
        let info = EpochInfo {
            outcome: EpochOutcome::Success,
            epoch: Epoch::zero(),
            output,
            players,
            next_players: schedule.players(Epoch::new(1)),
        };
        Self {
            signers,
            participants,
            schedule,
            initial: Arc::new(InitialState { info, shares }),
            sharing_mode: Mode::NonZeroCounter,
            stores: Arc::new(Mutex::new(BTreeMap::new())),
            registrations: Arc::new(Mutex::new(BTreeMap::new())),
            state_syncs: Arc::new(Mutex::new(BTreeMap::new())),
            failures: Arc::new(HashSet::new()),
        }
    }

    pub(super) fn with_failures(mut self, failures: impl IntoIterator<Item = u64>) -> Self {
        self.failures = Arc::new(failures.into_iter().collect());
        self
    }

    pub(super) const fn with_sharing_mode(mut self, sharing_mode: Mode) -> Self {
        self.sharing_mode = sharing_mode;
        self
    }
}

impl EngineDefinition for ReshareEngine {
    type PublicKey = ed25519::PublicKey;
    type Engine = ValidatorEngine;
    type State = ValidatorState;

    fn participants(&self) -> Vec<Self::PublicKey> {
        self.participants.clone()
    }

    fn channels(&self) -> Vec<(u64, Quota)> {
        vec![
            (VOTE_CHANNEL, TEST_QUOTA),
            (CERTIFICATE_CHANNEL, TEST_QUOTA),
            (RESOLVER_CHANNEL, TEST_QUOTA),
            (BACKFILL_CHANNEL, TEST_QUOTA),
            (BROADCAST_CHANNEL, TEST_QUOTA),
            (QMDB_CHANNEL, TEST_QUOTA),
            (DKG_CHANNEL, TEST_QUOTA),
            (PROBE_CHANNEL, TEST_QUOTA),
            (ANCHOR_BOUNDARY_CHANNEL, TEST_QUOTA),
        ]
    }

    async fn init(&self, ctx: InitContext<'_, Self::PublicKey>) -> (Self::Engine, Self::State) {
        let InitContext {
            context,
            index,
            delayed,
            public_key,
            oracle,
            channels,
            participants: _,
            monitor,
        } = ctx;

        let signer = self.signers[index].clone();
        let partition_prefix = format!("reshare-e2e-{index}");
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);

        let mut channels = channels.into_iter();
        let vote_network = channels.next().unwrap();
        let certificate_network = channels.next().unwrap();
        let resolver_network = channels.next().unwrap();
        let backfill_network = channels.next().unwrap();
        let broadcast_network = channels.next().unwrap();
        let qmdb_network = channels.next().unwrap();
        let dkg_network = channels.next().unwrap();
        let probe_network = channels.next().unwrap();
        let anchor_boundary_network = channels.next().unwrap();

        let (certificate_mux, certificate_mux_handle, certificate_backup) = Muxer::builder(
            context.child("certificate_mux"),
            certificate_network.0.clone(),
            certificate_network.1,
            128,
        )
        .with_backup()
        .build();
        certificate_mux.start();
        let provider = DynamicProvider::new();
        let store = self
            .stores
            .lock()
            .entry(public_key.clone())
            .or_default()
            .clone();
        if let Some(share) = self.initial.shares.get_value(public_key).cloned() {
            store.seed_share(Epoch::zero(), share.clone());
            provider.register(
                Epoch::zero(),
                Scheme::signer(
                    NAMESPACE,
                    self.initial.info.output.players().clone(),
                    self.initial.info.output.public().clone(),
                    share,
                )
                .expect("initial signer share"),
            );
        } else {
            provider.register(
                Epoch::zero(),
                Scheme::verifier(
                    NAMESPACE,
                    self.initial.info.output.players().clone(),
                    self.initial.info.output.public().clone(),
                ),
            );
        }

        let resolver = marshal_resolver::init(
            context.child("marshal_resolver"),
            marshal_resolver::Config {
                public_key: public_key.clone(),
                peer_provider: oracle.manager(),
                blocker: oracle.control(public_key.clone()),
                mailbox_size: NZUsize!(100),
                initial: Duration::from_secs(1),
                timeout: Duration::from_secs(2),
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
            backfill_network,
        );

        let broadcast_config = buffered::Config {
            public_key: public_key.clone(),
            mailbox_size: NZUsize!(100),
            deque_size: 10,
            priority: false,
            codec_config: (),
            peer_provider: oracle.manager(),
        };
        let (broadcast_engine, buffer) =
            buffered::Engine::new(context.child("broadcast"), broadcast_config);
        broadcast_engine.start(broadcast_network);

        let finalizations_by_height = prunable::Archive::init(
            context.child("finalizations_by_height"),
            archive_config(&partition_prefix, "finalizations", page_cache.clone(), ()),
        )
        .await
        .expect("finalizations archive");
        let finalized_blocks = prunable::Archive::init(
            context.child("finalized_blocks"),
            archive_config(&partition_prefix, "blocks", page_cache.clone(), ()),
        )
        .await
        .expect("blocks archive");

        let genesis = Block::genesis(self.participants[0].clone(), self.initial.info.clone());
        let (anchor_actor, anchor_mailbox) = anchor::Actor::new(anchor::Config {
            context: context.child("anchor"),
            manager: oracle.manager(),
            peers: Set::from_iter_dedup(self.participants.iter().cloned()),
            verifier: Scheme::certificate_verifier(
                NAMESPACE,
                *self.initial.info.output.public().public(),
            ),
            genesis: self.initial.info.clone(),
            strategy: Sequential,
            blocker: oracle.control(public_key.clone()),
            blocks_per_epoch: EPOCH_LENGTH,
            retry_timeout: NZDuration!(Duration::from_millis(500)),
            mailbox_size: NZUsize!(100),
            block_codec_config: (),
        });
        let anchor_handle = anchor_actor.start(certificate_backup, anchor_boundary_network);

        let stateful_startup_context = context.child("stateful_startup");
        let mut plan = SyncPlan::init(&stateful_startup_context, partition_prefix.clone()).await;
        let should_state_sync = plan.should_state_sync(delayed);
        let anchor_artifact = if should_state_sync {
            let artifact = anchor_mailbox.subscribe().await.expect("anchor stopped");
            provider.register(
                artifact.epoch,
                Scheme::verifier(
                    NAMESPACE,
                    artifact.info.output.players().clone(),
                    artifact.info.output.public().clone(),
                ),
            );
            Some(artifact)
        } else {
            None
        };
        let minimum_probe_epoch = anchor_artifact
            .as_ref()
            .map_or_else(Epoch::zero, |artifact| artifact.epoch);
        let (probe_actor, probe_mailbox) = Probe::new(ProbeConfig {
            context: context.child("probe"),
            provider: provider.clone(),
            strategy: Sequential,
            capacity: NZUsize!(100),
            blocker: oracle.control(public_key.clone()),
            minimum_epoch: minimum_probe_epoch,
            retry_timeout: NZDuration!(Duration::from_millis(100)),
        });
        let probe_handle = probe_actor.start(probe_network);
        if should_state_sync {
            let finalization = probe_mailbox.subscribe().await.expect("probe stopped");
            plan = plan.with_floor(finalization);
        }
        let (marshal_actor, marshal, _) = MarshalActor::init(
            context.child("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider: provider.clone(),
                epocher: FixedEpocher::new(EPOCH_LENGTH),
                start: plan.marshal_start(genesis.clone()),
                partition_prefix: partition_prefix.clone(),
                mailbox_size: NZUsize!(100),
                view_retention_timeout: ViewDelta::new(10),
                prunable_items_per_section: NZU64!(10),
                page_cache: page_cache.clone(),
                replay_buffer: IO_BUFFER_SIZE,
                key_write_buffer: IO_BUFFER_SIZE,
                value_write_buffer: IO_BUFFER_SIZE,
                block_codec_config: (),
                max_repair: NZUsize!(10),
                max_pending_acks: NZUsize!(1),
                strategy: Sequential,
            },
        )
        .await;

        let db_config = FixedConfig {
            merkle_config: MmrJournalConfig {
                journal_partition: format!("{partition_prefix}-qmdb-mmr-journal"),
                metadata_partition: format!("{partition_prefix}-qmdb-mmr-metadata"),
                items_per_blob: NZU64!(11),
                write_buffer: IO_BUFFER_SIZE,
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            journal_config: FixedLogConfig {
                partition: format!("{partition_prefix}-qmdb-log-journal"),
                items_per_blob: NZU64!(7),
                page_cache: page_cache.clone(),
                write_buffer: IO_BUFFER_SIZE,
            },
            translator: TwoCap,
        };

        let (qmdb_resolver_actor, qmdb_sync_resolver) = qmdb_resolver::Actor::new(
            context.child("qmdb_resolver"),
            qmdb_resolver::Config {
                peer_provider: oracle.manager(),
                blocker: oracle.control(public_key.clone()),
                database: None,
                mailbox_size: NZUsize!(100),
                me: Some(public_key.clone()),
                initial: Duration::from_secs(1),
                timeout: Duration::from_secs(2),
                fetch_retry_timeout: Duration::from_millis(100),
                max_serve_ops: NZU64!(16),
                priority_requests: false,
                priority_responses: false,
            },
        );
        let qmdb_handle = qmdb_resolver_actor.start(qmdb_network);

        let fence_epoch = anchor_artifact
            .as_ref()
            .map_or_else(Epoch::zero, |artifact| artifact.epoch);
        let state_sync = anchor_artifact.map(|artifact| {
            let floor = plan
                .floor()
                .cloned()
                .expect("state-sync startup must have a probe floor");
            orchestrator::StateSync { artifact, floor }
        });
        let registrar = TestRegistrar {
            provider: provider.clone(),
            events: self.registrations.clone(),
            public_key: public_key.clone(),
        };
        let (fence, gate) = Fence::new(fence_epoch);
        let (reshare_actor, reshare_mailbox) = reshare::Actor::new(
            context.child("reshare"),
            reshare::Config {
                signer: signer.clone(),
                manager: oracle.manager(),
                blocker: oracle.control(public_key.clone()),
                participants_provider: ScheduleProvider {
                    schedule: self.schedule.clone(),
                },
                secret_store: store,
                strategy: Sequential,
                registrar,
                marshal: marshal.clone(),
                fence,
                namespace: NAMESPACE,
                sharing_mode: self.sharing_mode,
                mailbox_size: NZUsize!(100),
                partition_prefix: format!("{partition_prefix}-reshare"),
                max_participants: MAX_PARTICIPANTS,
                blocks_per_epoch: EPOCH_LENGTH,
                batch_verifier: PhantomData::<ed25519::Batch>,
            },
        );
        let dkg_network = (
            dkg_network.0,
            FilteredReceiver::epochs(dkg_network.1, self.failures.clone()),
        );
        let reshare_handle = reshare_actor.start(dkg_network);

        let application = App {
            genesis: genesis.clone(),
            reshare: reshare_mailbox.clone(),
        };
        let sync_floor = plan.floor().cloned();
        let (stateful_actor, stateful_mailbox) = StatefulActor::init(
            context.child("stateful"),
            StatefulConfig {
                application,
                db_config,
                input_provider: (),
                marshal: marshal.clone(),
                mailbox_size: NZUsize!(100),
                plan,
                resolvers: qmdb_sync_resolver,
                sync_config: SyncEngineConfig {
                    fetch_batch_size: NZU64!(16),
                    apply_batch_size: 64,
                    max_outstanding_requests: 8,
                    update_channel_size: NZUsize!(256),
                    max_retained_roots: 8,
                },
                prune_config: None,
            },
        );

        let deferred = Deferred::new(
            context.child("deferred"),
            stateful_mailbox.clone(),
            marshal.clone(),
            FixedEpocher::new(EPOCH_LENGTH),
        );

        let (orchestrator_actor, orchestrator_mailbox) = orchestrator::Actor::new(
            context.child("orchestrator"),
            orchestrator::Config {
                oracle: oracle.control(public_key.clone()),
                manager: oracle.manager(),
                provider: provider.clone(),
                marshal: marshal.clone(),
                application: deferred.clone(),
                strategy: Sequential,
                simplex: orchestrator::SimplexConfig {
                    elector: RoundRobin::<Sha256>::default(),
                    mailbox_size: NZUsize!(3),
                    replay_buffer: IO_BUFFER_SIZE,
                    write_buffer: IO_BUFFER_SIZE,
                    page_cache_page_size: PAGE_SIZE,
                    page_cache_pages: PAGE_CACHE_SIZE,
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_millis(500),
                    fetch_timeout: Duration::from_secs(2),
                    fetch_concurrent: NZUsize!(3),
                    activity_timeout: ViewDelta::new(10),
                    skip_timeout: ViewDelta::new(5),
                    forwarding: ForwardingPolicy::Disabled,
                },
                gate,
                state_sync,
                blocks_per_epoch: EPOCH_LENGTH,
                muxer_size: 128,
                mailbox_size: NZUsize!(100),
                partition_prefix: format!("{partition_prefix}-orchestrator"),
            },
        );
        let orchestrator_handle =
            orchestrator_actor.start(vote_network, certificate_mux_handle, resolver_network);

        let reporters = Reporters::from((
            stateful_mailbox.clone(),
            Reporters::from((orchestrator_mailbox, reshare_mailbox)),
        ));
        let marshal_handle = marshal_actor.start(
            MonitorReporter::new(public_key.clone(), monitor, reporters),
            buffer,
            resolver,
        );
        anchor_mailbox.attach(marshal.clone());
        probe_mailbox.attach(marshal.clone());
        if let Some(finalization) = sync_floor {
            let block = marshal
                .subscribe_by_commitment(finalization.proposal.payload, CommitmentFallback::Wait)
                .await
                .expect("sync floor block must be available");
            self.state_syncs
                .lock()
                .insert(public_key.clone(), block.height().get());
        }
        let stateful_handle = stateful_actor.start();

        (
            ValidatorEngine {
                context,
                handles: ValidatorHandles {
                    anchor: anchor_handle,
                    probe: probe_handle,
                    qmdb: qmdb_handle,
                    reshare: reshare_handle,
                    orchestrator: orchestrator_handle,
                    marshal: marshal_handle,
                    stateful: stateful_handle,
                },
            },
            ValidatorState {
                marshal,
                registrations: self.registrations.clone(),
                state_syncs: self.state_syncs.clone(),
                public_key: public_key.clone(),
            },
        )
    }

    fn start(engine: Self::Engine) -> Handle<()> {
        let ValidatorEngine { context, handles } = engine;
        context.spawn(move |_| handles.join())
    }
}

#[derive(Clone)]
pub(super) struct ValidatorState {
    pub(super) marshal: Marshal,
    registrations: Arc<Mutex<BTreeMap<ed25519::PublicKey, Vec<Registration>>>>,
    pub(super) state_syncs: Arc<Mutex<BTreeMap<ed25519::PublicKey, u64>>>,
    public_key: ed25519::PublicKey,
}

impl PartialEq for ValidatorState {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}

impl ProcessedHeight for ValidatorState {
    async fn processed_height(&self) -> u64 {
        self.marshal
            .get_processed_height()
            .await
            .map_or(0, |height| height.get())
    }
}

impl ValidatorState {
    pub(super) fn public_key(&self) -> &ed25519::PublicKey {
        &self.public_key
    }

    pub(super) fn registrations(&self) -> Vec<Registration> {
        self.registrations
            .lock()
            .get(&self.public_key)
            .cloned()
            .unwrap_or_default()
    }

    pub(super) fn state_sync_height(&self) -> Option<u64> {
        self.state_syncs.lock().get(&self.public_key).copied()
    }
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
        items_per_section: NZU64!(10),
        key_write_buffer: IO_BUFFER_SIZE,
        value_write_buffer: IO_BUFFER_SIZE,
        replay_buffer: IO_BUFFER_SIZE,
    }
}

fn empty_db_root() -> sha256::Digest {
    Sha256Digest::from(hex!(
        "ea6e0567a525372add5e4ef4d0600c18ed47fa5dd041a0ab0d25b60ea8c35978"
    ))
}

fn u64_to_digest(v: u64) -> sha256::Digest {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&v.to_be_bytes());
    sha256::Digest::from(bytes)
}

pub(super) fn final_height(epoch: u64) -> Height {
    FixedEpocher::new(EPOCH_LENGTH)
        .last(Epoch::new(epoch))
        .expect("test epoch should be supported")
}

pub(super) fn height_round(height: Height) -> Round {
    let info = FixedEpocher::new(EPOCH_LENGTH)
        .containing(height)
        .expect("test height should be supported");
    Round::new(info.epoch(), View::new(info.relative().get()))
}

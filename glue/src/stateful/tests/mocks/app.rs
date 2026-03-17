use super::db::{MockDb, MockSyncResolver};
use crate::{
    simulate::{
        engine::{EngineDefinition, InitContext},
        reporter::MonitorReporter,
    },
    stateful::{
        db::{DatabaseSet, Merkleized as _, SyncableDatabaseSet, Unmerkleized as _},
        Application, Config as StatefulConfig, Stateful,
    },
};
use commonware_broadcast::buffered;
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_consensus::{
    marshal::{
        self,
        ancestry::{AncestorStream, BlockProvider},
        core::{Actor as MarshalActor, Mailbox as MarshalMailbox},
        resolver::p2p as marshal_resolver,
        standard::{Deferred, Standard},
        Update,
    },
    simplex::{
        self,
        elector::RoundRobin,
        mocks::scheme::{self as scheme_mocks, Scheme as MockScheme},
        types::{Activity, Context},
    },
    types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
    Block as ConsensusBlock, CertifiableBlock, Heightable, Reporter, Reporters,
};
use commonware_cryptography::{
    certificate::{mocks::Fixture, ConstantProvider, Scheme as _},
    ed25519, sha256, Digest as _, Digestible, Hasher, Sha256, Signer as _,
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    buffer::paged::CacheRef, deterministic, Buf, BufMut, Clock, Handle, Metrics, Quota, Spawner,
};
use commonware_storage::archive::immutable;
use commonware_utils::{sync::AsyncRwLock, test_rng, Acknowledgement as _, NZUsize, NZU16, NZU64};
use std::{
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

const BLOCKS_PER_EPOCH: NonZeroU64 = NZU64!(20);
const NAMESPACE: &[u8] = b"stateful_e2e_test";
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

pub(crate) type MockDatabaseSet = Arc<AsyncRwLock<MockDb>>;

/// A block carrying key-value mutations with embedded consensus context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Block {
    context: Context<sha256::Digest, ed25519::PublicKey>,
    parent: sha256::Digest,
    height: Height,
    digest: sha256::Digest,
    state_root: sha256::Digest,
    writes: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.digest.write(buf);
        self.state_root.write(buf);
        self.writes.write(buf);
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.digest.encode_size()
            + self.state_root.encode_size()
            + self.writes.encode_size()
    }
}

impl Read for Block {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let context = Context::read(buf)?;
        let parent = sha256::Digest::read(buf)?;
        let height = Height::read(buf)?;
        let digest = sha256::Digest::read(buf)?;
        let state_root = sha256::Digest::read(buf)?;
        let unbounded: RangeCfg<usize> = (..).into();
        let byte_vec_cfg = (unbounded, ());
        let writes_cfg = (unbounded, (byte_vec_cfg, byte_vec_cfg));
        let writes = Vec::read_cfg(buf, &writes_cfg)?;
        Ok(Self {
            context,
            parent,
            height,
            digest,
            state_root,
            writes,
        })
    }
}

impl Digestible for Block {
    type Digest = sha256::Digest;

    fn digest(&self) -> sha256::Digest {
        self.digest
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

impl Block {
    fn genesis() -> Self {
        let digest = Sha256::hash(b"genesis");
        Self {
            context: Context {
                round: Round::new(Epoch::zero(), View::zero()),
                leader: ed25519::PrivateKey::from_seed(0).public_key(),
                parent: (View::zero(), sha256::Digest::EMPTY),
            },
            parent: sha256::Digest::EMPTY,
            height: Height::zero(),
            digest,
            state_root: sha256::Digest::EMPTY,
            writes: Vec::new(),
        }
    }

    pub(crate) fn sync_target(view: u64, marker: u8, target: u8) -> Self {
        Self {
            context: Context {
                round: Round::new(Epoch::zero(), View::new(view)),
                leader: ed25519::PrivateKey::from_seed(0).public_key(),
                parent: (View::zero(), sha256::Digest::EMPTY),
            },
            parent: sha256::Digest::EMPTY,
            height: Height::new(view + 1),
            digest: sha256::Digest::from([marker; 32]),
            state_root: sha256::Digest::from([target; 32]),
            writes: Vec::new(),
        }
    }

    pub(crate) fn state_root(&self) -> sha256::Digest {
        self.state_root
    }
}

/// Standard variant where commitment = digest (identity mapping).
type AppVariant = Standard<Block>;

/// A stateful application that increments a counter each block.
#[derive(Clone)]
struct App {
    genesis: Block,
}

impl App {
    fn new() -> Self {
        Self {
            genesis: Block::genesis(),
        }
    }

    /// Execute a block: increment "counter" and write `height -> height_bytes`.
    async fn execute(
        height: Height,
        mut batches: <MockDatabaseSet as DatabaseSet>::Unmerkleized<'_>,
    ) -> (
        Vec<(Vec<u8>, Vec<u8>)>,
        <MockDatabaseSet as DatabaseSet>::Merkleized,
    ) {
        // Read current counter
        let counter_key = b"counter".to_vec();
        let current: u64 = batches
            .get(&counter_key)
            .await
            .unwrap()
            .map_or(0, |v| u64::from_be_bytes(v.try_into().unwrap()));
        let next = current + 1;
        batches = batches.write(counter_key.clone(), Some(next.to_be_bytes().to_vec()));

        // Write height marker
        let height_key = format!("height_{}", height.get()).into_bytes();
        let height_val = height.get().to_be_bytes().to_vec();
        batches = batches.write(height_key.clone(), Some(height_val.clone()));

        let writes = vec![
            (counter_key, next.to_be_bytes().to_vec()),
            (height_key, height_val),
        ];

        let merkleized = batches.merkleize().await.unwrap();
        (writes, merkleized)
    }
}

impl<E> Application<E> for App
where
    E: rand::Rng + Spawner + Metrics + Clock,
{
    type SigningScheme = MockScheme<ed25519::PublicKey>;
    type Context = Context<sha256::Digest, ed25519::PublicKey>;
    type Block = Block;
    type MarshalVariant = AppVariant;
    type Databases = MockDatabaseSet;
    type InputProvider = ();

    fn sync_targets(
        block: &Self::Block,
    ) -> Option<<Self::Databases as SyncableDatabaseSet>::SyncTargets> {
        Some(block.state_root)
    }

    async fn genesis(&mut self) -> Self::Block {
        self.genesis.clone()
    }

    async fn propose<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        context: (E, Self::Context),
        ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet>::Unmerkleized<'_>,
        _input: &mut Self::InputProvider,
    ) -> Option<(Self::Block, <Self::Databases as DatabaseSet>::Merkleized)> {
        let parent = ancestry.peek()?;
        let parent_digest = parent.digest();
        let height = Height::new(parent.height().get() + 1);
        let (_, ctx) = &context;

        let (writes, merkleized) = Self::execute(height, batches).await;
        let state_root = merkleized.root();

        // Compute block digest from context, parent, height, state_root.
        // Including the context ensures different proposals at different views
        // produce different digests (required by Deferred's context check).
        let mut hasher = Sha256::new();
        hasher.update(b"e2e_block");
        hasher.update(&ctx.encode());
        hasher.update(parent_digest.as_ref());
        hasher.update(&height.get().to_be_bytes());
        hasher.update(state_root.as_ref());
        let digest = hasher.finalize();

        let block = Block {
            context: ctx.clone(),
            parent: parent_digest,
            height,
            digest,
            state_root,
            writes,
        };
        Some((block, merkleized))
    }

    async fn verify<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        _context: (E, Self::Context),
        ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet>::Unmerkleized<'_>,
    ) -> Option<<Self::Databases as DatabaseSet>::Merkleized> {
        let tip = ancestry.peek()?;
        let height = tip.height();

        let (_, merkleized) = Self::execute(height, batches).await;
        let computed_root = merkleized.root();

        if computed_root != tip.state_root {
            return None;
        }

        Some(merkleized)
    }

    async fn replay(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet>::Unmerkleized<'_>,
    ) -> <Self::Databases as DatabaseSet>::Merkleized {
        let (_, merkleized) = Self::execute(block.height(), batches).await;
        merkleized
    }
}

/// Acknowledges marshal `Update::Block` events.
#[derive(Clone)]
struct AckReporter;

impl Reporter for AckReporter {
    type Activity = Update<Block>;

    async fn report(&mut self, activity: Self::Activity) {
        if let Update::Block(_, ack) = activity {
            ack.acknowledge();
        }
    }
}

/// Engine definition implementing `EngineDefinition` for the simulation harness.
#[derive(Clone)]
pub(crate) struct ConsensusEngine {
    participants: Vec<ed25519::PublicKey>,
    schemes: Vec<MockScheme<ed25519::PublicKey>>,
    pub(crate) databases: Vec<MockDatabaseSet>,
}

impl ConsensusEngine {
    pub(crate) fn new(n: u32) -> Self {
        let mut rng = test_rng();
        let Fixture {
            participants,
            schemes,
            ..
        } = scheme_mocks::fixture(&mut rng, NAMESPACE, n);

        let databases = (0..n)
            .map(|_| Arc::new(AsyncRwLock::new(MockDb::default())))
            .collect();

        Self {
            participants,
            schemes,
            databases,
        }
    }
}

impl EngineDefinition for ConsensusEngine {
    type PublicKey = ed25519::PublicKey;
    type Engine = Handle<()>;
    type State = MockDatabaseSet;

    fn participants(&self) -> Vec<Self::PublicKey> {
        self.participants.clone()
    }

    fn channels(&self) -> Vec<(u64, Quota)> {
        vec![
            (0, TEST_QUOTA), // votes
            (1, TEST_QUOTA), // certificates
            (2, TEST_QUOTA), // resolver
            (3, TEST_QUOTA), // backfill
            (4, TEST_QUOTA), // broadcast
        ]
    }

    async fn init(&self, ctx: InitContext<'_, Self::PublicKey>) -> (Self::Engine, Self::State) {
        let InitContext {
            context,
            index,
            public_key,
            oracle,
            channels,
            participants: _,
            monitor,
        } = ctx;

        let db = self.databases[index].clone();
        let scheme = self.schemes[index].clone();

        let partition_prefix = format!("validator-{index}");
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);

        // Destructure the 5 channels
        let mut channels = channels.into_iter();
        let vote_network = channels.next().unwrap();
        let certificate_network = channels.next().unwrap();
        let resolver_network = channels.next().unwrap();
        let backfill_network = channels.next().unwrap();
        let broadcast_network = channels.next().unwrap();

        // Marshal resolver
        let resolver_cfg = marshal_resolver::Config {
            public_key: public_key.clone(),
            peer_provider: oracle.manager(),
            blocker: oracle.control(public_key.clone()),
            mailbox_size: 100,
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let resolver = marshal_resolver::init(&context, resolver_cfg, backfill_network);

        // Buffered broadcast engine
        let broadcast_config = buffered::Config {
            public_key: public_key.clone(),
            mailbox_size: 100,
            deque_size: 10,
            priority: false,
            codec_config: (),
            peer_provider: oracle.manager(),
        };
        let (broadcast_engine, buffer) = buffered::Engine::new(context.clone(), broadcast_config);
        broadcast_engine.start(broadcast_network);

        // Immutable archives
        let finalizations_by_height = immutable::Archive::init(
            context.with_label("finalizations_by_height"),
            immutable::Config {
                metadata_partition: format!("{partition_prefix}-finalizations-metadata"),
                freezer_table_partition: format!("{partition_prefix}-finalizations-freezer-table"),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!("{partition_prefix}-finalizations-freezer-key"),
                freezer_key_page_cache: page_cache.clone(),
                freezer_value_partition: format!("{partition_prefix}-finalizations-freezer-value"),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{partition_prefix}-finalizations-ordinal"),
                items_per_section: NZU64!(10),
                codec_config: MockScheme::<ed25519::PublicKey>::certificate_codec_config_unbounded(
                ),
                replay_buffer: NZUsize!(1024),
                freezer_key_write_buffer: NZUsize!(1024),
                freezer_value_write_buffer: NZUsize!(1024),
                ordinal_write_buffer: NZUsize!(1024),
            },
        )
        .await
        .expect("failed to initialize finalizations archive");

        let finalized_blocks = immutable::Archive::init(
            context.with_label("finalized_blocks"),
            immutable::Config {
                metadata_partition: format!("{partition_prefix}-blocks-metadata"),
                freezer_table_partition: format!("{partition_prefix}-blocks-freezer-table"),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!("{partition_prefix}-blocks-freezer-key"),
                freezer_key_page_cache: page_cache.clone(),
                freezer_value_partition: format!("{partition_prefix}-blocks-freezer-value"),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{partition_prefix}-blocks-ordinal"),
                items_per_section: NZU64!(10),
                codec_config: (),
                replay_buffer: NZUsize!(1024),
                freezer_key_write_buffer: NZUsize!(1024),
                freezer_value_write_buffer: NZUsize!(1024),
                ordinal_write_buffer: NZUsize!(1024),
            },
        )
        .await
        .expect("failed to initialize blocks archive");

        // Marshal actor
        let provider = ConstantProvider::new(scheme.clone());
        let marshal_config = marshal::Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            partition_prefix: partition_prefix.clone(),
            mailbox_size: 100,
            view_retention_timeout: ViewDelta::new(10),
            prunable_items_per_section: NZU64!(10),
            page_cache: page_cache.clone(),
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            block_codec_config: (),
            max_repair: NZUsize!(10),
            max_pending_acks: NZUsize!(1),
            strategy: Sequential,
        };
        let (marshal_actor, marshal_mailbox, _last_height) =
            MarshalActor::<_, Standard<Block>, _, _, _, _, _>::init(
                context.clone(),
                finalizations_by_height,
                finalized_blocks,
                marshal_config,
            )
            .await;

        let app = App::new();
        let source_idx = (index + 1) % self.databases.len();
        let stateful = Stateful::new(
            context.clone(),
            StatefulConfig {
                app,
                databases: db.clone(),
                input_provider: (),
                block_provider: marshal_mailbox.clone(),
                finalized_digest: None,
                sync: crate::stateful::sync::Config {
                    sync_configs: (),
                    sync_resolvers: MockSyncResolver::new(&self.databases[source_idx]),
                },
            },
        );
        // Deferred wrapper -- clone shares pending state
        let deferred = Deferred::new(
            context.clone(),
            stateful.clone(),
            marshal_mailbox.clone(),
            FixedEpocher::new(BLOCKS_PER_EPOCH),
        );

        // Marshal application reporter (acknowledges blocks)
        let ack_reporter = AckReporter;

        // Start marshal actor
        marshal_actor.start(ack_reporter, buffer, resolver);

        // Simplex reporter = MonitorReporter(Reporters(MarshalMailbox, Stateful))
        #[allow(clippy::type_complexity)]
        let reporters: Reporters<
            Activity<MockScheme<ed25519::PublicKey>, sha256::Digest>,
            MarshalMailbox<MockScheme<ed25519::PublicKey>, Standard<Block>>,
            Stateful<
                deterministic::Context,
                App,
                MarshalMailbox<MockScheme<ed25519::PublicKey>, Standard<Block>>,
            >,
        > = Reporters::from((marshal_mailbox, stateful));

        let monitor_reporter = MonitorReporter::new(public_key.clone(), monitor, reporters);

        // Simplex engine
        let simplex_config = simplex::Config {
            scheme,
            elector: RoundRobin::<Sha256>::default(),
            blocker: oracle.control(public_key.clone()),
            automaton: deferred.clone(),
            relay: deferred,
            reporter: monitor_reporter,
            strategy: Sequential,
            partition: format!("{partition_prefix}-simplex"),
            mailbox_size: 100,
            epoch: Epoch::zero(),
            replay_buffer: NZUsize!(1024),
            write_buffer: NZUsize!(1024),
            page_cache,
            leader_timeout: Duration::from_secs(1),
            certification_timeout: Duration::from_secs(2),
            timeout_retry: Duration::from_millis(500),
            activity_timeout: ViewDelta::new(10),
            skip_timeout: ViewDelta::new(5),
            fetch_timeout: Duration::from_secs(2),
            fetch_concurrent: 3,
        };

        let engine = simplex::Engine::new(context, simplex_config);
        let handle = engine.start(vote_network, certificate_network, resolver_network);

        (handle, db)
    }

    fn start(engine: Self::Engine) -> Handle<()> {
        engine
    }
}

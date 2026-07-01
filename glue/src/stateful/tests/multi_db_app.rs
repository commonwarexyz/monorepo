use super::common::*;
use crate::{
    simulate::{
        engine::{EngineDefinition, InitContext},
        reporter::MonitorReporter,
    },
    stateful::{
        db::{
            p2p::{compact as compact_resolver, standard as qmdb_resolver},
            DatabaseSet, Merkleized as _, SyncEngineConfig, Unmerkleized as _,
        },
        probe::{Config as ProbeConfig, Probe},
        Application, Config as StatefulConfig, Proposed, PruneConfig, Stateful as StatefulActor,
        SyncPlan,
    },
};
use commonware_broadcast::buffered;
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_consensus::{
    marshal::{
        self,
        ancestry::Ancestry,
        core::{Actor as MarshalActor, CommitmentFallback},
        resolver::p2p as marshal_resolver,
        standard::{Deferred, Standard},
    },
    simplex::{
        self,
        config::ForwardingPolicy,
        elector::RoundRobin,
        mocks::scheme::{self as scheme_mocks, Scheme as MockScheme},
        types::Context,
    },
    types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
    Block as ConsensusBlock, CertifiableBlock, Heightable,
};
use commonware_cryptography::{
    certificate::{mocks::Fixture, ConstantProvider},
    ed25519,
    sha256::{self, Digest as Sha256Digest},
    Digest as _, Digestible, Hasher, Sha256, Signer as _,
};
use commonware_formatting::hex;
use commonware_p2p::utils::mux::Muxer;
use commonware_parallel::Sequential;
use commonware_runtime::{
    buffer::paged::CacheRef, Buf, BufMut, Clock, Handle, Metrics, Quota, Spawner, Storage,
    Supervisor as _,
};
use commonware_storage::{
    archive::prunable,
    journal::contiguous::{fixed::Config as FixedLogConfig, variable::Config as VariableLogConfig},
    mmr::{self, full::Config as MmrJournalConfig, Location},
    qmdb::{
        any::{unordered::fixed, FixedConfig},
        immutable,
        sync::{compact as compact_sync, Target},
    },
    translator::TwoCap,
};
use commonware_utils::{
    non_empty_range,
    range::NonEmptyRange,
    sync::{Mutex, TracedAsyncRwLock},
    test_rng, NZDuration, NZUsize, NZU64,
};
use futures::StreamExt;
use rand::Rng;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

/// The full (journaled) QMDB used as DB-A in the multi-db e2e tests.
type QmdbA<E> =
    fixed::Db<mmr::Family, E, sha256::Digest, sha256::Digest, Sha256, TwoCap, Sequential>;

/// The compact (witness-only) QMDB used as DB-B, so the suite drives deep rewind,
/// pruning, and state sync through the compact path as well.
type QmdbB<E> =
    immutable::fixed::CompactDb<mmr::Family, E, sha256::Digest, sha256::Digest, Sha256, Sequential>;

/// A single QMDB database behind a lock.
type DbA<E> = Arc<TracedAsyncRwLock<QmdbA<E>>>;
type DbB<E> = Arc<TracedAsyncRwLock<QmdbB<E>>>;

/// A full and a compact QMDB as a tuple.
pub(crate) type MultiDatabaseSet<E> = (DbA<E>, DbB<E>);

/// A block carrying state from two QMDB databases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Block {
    context: Context<sha256::Digest, ed25519::PublicKey>,
    parent: sha256::Digest,
    height: Height,
    root_a: sha256::Digest,
    range_a: NonEmptyRange<Location>,
    root_b: sha256::Digest,
    range_b: NonEmptyRange<Location>,
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.root_a.write(buf);
        self.range_a.write(buf);
        self.root_b.write(buf);
        self.range_b.write(buf);
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.root_a.encode_size()
            + self.range_a.encode_size()
            + self.root_b.encode_size()
            + self.range_b.encode_size()
    }
}

impl Read for Block {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            context: Context::read(buf)?,
            parent: sha256::Digest::read(buf)?,
            height: Height::read(buf)?,
            root_a: sha256::Digest::read(buf)?,
            range_a: NonEmptyRange::read(buf)?,
            root_b: sha256::Digest::read(buf)?,
            range_b: NonEmptyRange::read(buf)?,
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

impl Block {
    fn genesis(
        root_a: sha256::Digest,
        range_a: NonEmptyRange<Location>,
        root_b: sha256::Digest,
        range_b: NonEmptyRange<Location>,
    ) -> Self {
        Self {
            context: Context {
                round: Round::new(Epoch::zero(), View::zero()),
                leader: ed25519::PrivateKey::from_seed(0).public_key(),
                parent: (View::zero(), sha256::Digest::EMPTY),
            },
            parent: sha256::Digest::EMPTY,
            height: Height::zero(),
            root_a,
            range_a,
            root_b,
            range_b,
        }
    }
}

/// A stateful application that writes to two QMDB databases.
///
/// DB-A stores a counter incremented each block.
/// DB-B stores height markers (height -> height_val).
#[derive(Clone)]
struct App {
    genesis: Block,
}

impl App {
    fn new(genesis: Block) -> Self {
        Self { genesis }
    }

    /// Execute a block against two databases.
    async fn execute<E: Rng + Spawner + Metrics + Clock + Storage>(
        height: Height,
        batches: (
            <DbA<E> as DatabaseSet<E>>::Unmerkleized,
            <DbB<E> as DatabaseSet<E>>::Unmerkleized,
        ),
    ) -> (
        <DbA<E> as DatabaseSet<E>>::Merkleized,
        <DbB<E> as DatabaseSet<E>>::Merkleized,
    ) {
        let (mut batch_a, batch_b) = batches;

        // DB-A: increment counter and write a height marker, mirroring the single-db app's
        // per-block operation count so its state sync spans the same crash windows.
        let counter = Sha256::hash(b"counter");
        let current: u64 = batch_a
            .get(&counter)
            .await
            .unwrap()
            .map_or(0, |v| digest_to_u64(&v));
        batch_a = batch_a.write(counter, Some(u64_to_digest(current + 1)));
        batch_a = batch_a.write(
            Sha256::hash(&height.get().to_be_bytes()),
            Some(u64_to_digest(height.get())),
        );

        // DB-B: write height marker
        let batch_b = batch_b.set(
            Sha256::hash(&height.get().to_be_bytes()),
            u64_to_digest(height.get()),
        );

        let merkleized_a = batch_a.merkleize().await.unwrap();
        let merkleized_b = batch_b.merkleize().await.unwrap();
        (merkleized_a, merkleized_b)
    }
}

impl<E: Rng + Spawner + Metrics + Clock + Storage> Application<E> for App {
    type SigningScheme = MockScheme<ed25519::PublicKey>;
    type Context = Context<sha256::Digest, ed25519::PublicKey>;
    type Block = Block;
    type Databases = MultiDatabaseSet<E>;
    type InputProvider = ();

    async fn genesis(&mut self) -> Self::Block {
        self.genesis.clone()
    }

    async fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        _input: &mut Self::InputProvider,
    ) -> Option<Proposed<Self, E>> {
        let mut ancestry = Box::pin(ancestry);
        let parent = ancestry.next().await?;
        let height = Height::new(parent.height().get() + 1);
        let (merkleized_a, merkleized_b) = Self::execute(height, batches).await;
        let bounds_a = merkleized_a.bounds();
        let bounds_b = merkleized_b.bounds();
        let block = Block {
            context: context.1.clone(),
            parent: parent.digest(),
            height,
            root_a: merkleized_a.root(),
            range_a: non_empty_range!(
                bounds_a.inactivity_floor,
                Location::new(bounds_a.total_size)
            ),
            root_b: merkleized_b.root(),
            range_b: non_empty_range!(
                bounds_b.inactivity_floor,
                Location::new(bounds_b.total_size)
            ),
        };
        Some(Proposed {
            block,
            merkleized: (merkleized_a, merkleized_b),
        })
    }

    async fn verify(
        &mut self,
        _context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        let mut ancestry = Box::pin(ancestry);
        let tip = ancestry.next().await?;
        let (merkleized_a, merkleized_b) = Self::execute(tip.height(), batches).await;
        let bounds_a = merkleized_a.bounds();
        let bounds_b = merkleized_b.bounds();
        let matches_a = merkleized_a.root() == tip.root_a
            && non_empty_range!(
                bounds_a.inactivity_floor,
                Location::new(bounds_a.total_size)
            ) == tip.range_a;
        let matches_b = merkleized_b.root() == tip.root_b
            && non_empty_range!(
                bounds_b.inactivity_floor,
                Location::new(bounds_b.total_size)
            ) == tip.range_b;
        if !matches_a || !matches_b {
            return None;
        }
        Some((merkleized_a, merkleized_b))
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
        (
            Target::new(block.root_a, block.range_a.clone()),
            compact_sync::Target {
                root: block.root_b,
                leaf_count: block.range_b.end(),
            },
        )
    }
}

/// Multi-database engine definition for the simulation harness.
#[derive(Clone)]
pub(crate) struct MultiDbEngine {
    participants: Vec<ed25519::PublicKey>,
    schemes: Vec<MockScheme<ed25519::PublicKey>>,
    enable_state_sync: bool,
    sync_config: SyncEngineConfig,
    sync_entries: Arc<Mutex<BTreeMap<ed25519::PublicKey, u64>>>,
    sync_heights: Arc<Mutex<BTreeMap<ed25519::PublicKey, u64>>>,
}

impl MultiDbEngine {
    pub(crate) fn new(n: u32) -> Self {
        let mut rng = test_rng();
        let Fixture {
            participants,
            schemes,
            ..
        } = scheme_mocks::fixture(&mut rng, NAMESPACE, n);

        Self {
            participants,
            schemes,
            enable_state_sync: false,
            sync_config: SyncEngineConfig {
                fetch_batch_size: NZU64!(16),
                apply_batch_size: 64,
                max_outstanding_requests: 8,
                update_channel_size: NZUsize!(256),
                max_retained_roots: 32,
            },
            sync_entries: Arc::new(Mutex::new(BTreeMap::new())),
            sync_heights: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub(crate) fn with_state_sync(mut self) -> Self {
        self.enable_state_sync = true;
        self
    }

    /// Forces state sync to progress in the smallest possible batches.
    pub(crate) fn with_slow_state_sync(mut self) -> Self {
        self.sync_config = SyncEngineConfig {
            fetch_batch_size: NZU64!(1),
            apply_batch_size: 1,
            max_outstanding_requests: 1,
            update_channel_size: NZUsize!(4),
            max_retained_roots: 32,
        };
        self
    }
}

impl EngineDefinition for MultiDbEngine {
    type PublicKey = ed25519::PublicKey;
    type Engine = Handle<()>;
    type State = MockValidatorState<Standard<Block>>;

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
            (5, TEST_QUOTA), // qmdb sync resolvers (muxed)
            (6, TEST_QUOTA), // probe
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

        let scheme = self.schemes[index].clone();

        let partition_prefix = format!("validator-{index}");
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);

        // QMDB database configs (one per database)
        let db_config_a = FixedConfig {
            merkle_config: MmrJournalConfig {
                journal_partition: format!("{partition_prefix}-qmdb-a-mmr-journal"),
                metadata_partition: format!("{partition_prefix}-qmdb-a-mmr-metadata"),
                items_per_blob: NZU64!(11),
                write_buffer: IO_BUFFER_SIZE,
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            journal_config: FixedLogConfig {
                partition: format!("{partition_prefix}-qmdb-a-log-journal"),
                items_per_blob: NZU64!(7),
                page_cache: page_cache.clone(),
                write_buffer: IO_BUFFER_SIZE,
            },
            translator: TwoCap,
            init_cache_size: Some(NZUsize!(1024)),
        };
        // One witness entry per section so the periodic prune actually drops entries
        // (pruning is section-aligned).
        let db_config_b = immutable::fixed::CompactConfig {
            strategy: Sequential,
            witness: VariableLogConfig {
                partition: format!("{partition_prefix}-qmdb-b-witness"),
                items_per_section: NZU64!(1),
                compression: None,
                codec_config: (),
                page_cache: page_cache.clone(),
                write_buffer: IO_BUFFER_SIZE,
            },
            commit_codec_config: (),
        };
        let db_config = (db_config_a, db_config_b);

        // Destructure the 7 channels.
        let mut channels = channels.into_iter();
        let vote_network = channels.next().unwrap();
        let certificate_network = channels.next().unwrap();
        let resolver_network = channels.next().unwrap();
        let backfill_network = channels.next().unwrap();
        let broadcast_network = channels.next().unwrap();
        let qmdb_resolver_network = channels.next().unwrap();
        let probe_network = channels.next().unwrap();

        // Mux the QMDB resolver channel into two subchannels (one per database).
        let (mux, mut mux_handle) = Muxer::new(
            context.child("qmdb_mux"),
            qmdb_resolver_network.0,
            qmdb_resolver_network.1,
            100,
        );
        mux.start();
        let qmdb_a_resolver_network = mux_handle.register(0).await.unwrap();
        let qmdb_b_resolver_network = mux_handle.register(1).await.unwrap();

        // Marshal resolver
        let resolver_cfg = marshal_resolver::Config {
            public_key: public_key.clone(),
            peer_provider: oracle.manager(),
            blocker: oracle.control(public_key.clone()),
            mailbox_size: NZUsize!(100),
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let resolver = marshal_resolver::init(
            context.child("marshal_resolver"),
            resolver_cfg,
            backfill_network,
        );

        // Buffered broadcast engine
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

        // Prunable archives so marshal pruning takes effect.
        let finalizations_by_height = prunable::Archive::init(
            context.child("finalizations_by_height"),
            archive_config(&partition_prefix, "finalizations", page_cache.clone(), ()),
        )
        .await
        .expect("failed to initialize finalizations archive");
        let finalized_blocks = prunable::Archive::init(
            context.child("finalized_blocks"),
            archive_config(&partition_prefix, "blocks", page_cache.clone(), ()),
        )
        .await
        .expect("failed to initialize blocks archive");

        let genesis_block = {
            let empty_db_root = Sha256Digest::from(hex!(
                "ea6e0567a525372add5e4ef4d0600c18ed47fa5dd041a0ab0d25b60ea8c35978"
            ));
            let empty_compact_db_root = Sha256Digest::from(hex!(
                "290cbd39f3eaaca7cb4a92f4a2740fc438cabb99144258b24ba0cf54b3f4cfec"
            ));
            Block::genesis(
                empty_db_root,
                non_empty_range!(Location::new(0), Location::new(1)),
                empty_compact_db_root,
                non_empty_range!(Location::new(0), Location::new(1)),
            )
        };

        let stateful_startup_context = context.child("stateful_startup");
        let mut plan = SyncPlan::init(&stateful_startup_context, partition_prefix.clone()).await;
        let should_state_sync = plan.should_state_sync(self.enable_state_sync && delayed);
        let provider = ConstantProvider::new(scheme.clone());

        let (probe, probe_mailbox) = Probe::new(ProbeConfig {
            context: context.child("probe"),
            provider: provider.clone(),
            strategy: Sequential,
            capacity: NZUsize!(100),
            blocker: oracle.control(public_key.clone()),
            minimum_epoch: Epoch::zero(),
            retry_timeout: NZDuration!(Duration::from_millis(100)),
        });
        probe.start(probe_network);
        let mut state_sync_height = if should_state_sync {
            let finalization = probe_mailbox.subscribe().await.expect("probe stopped");
            plan = plan.with_floor(finalization);
            None
        } else {
            self.sync_heights.lock().get(public_key).copied()
        };

        // Marshal actor
        let max_pending_acks = NZUsize!(1);
        let marshal_config = marshal::Config {
            provider: provider.clone(),
            epocher: FixedEpocher::new(EPOCH_LENGTH),
            start: plan.marshal_start(genesis_block.clone()),
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
            max_pending_acks,
            strategy: Sequential,
        };
        let (marshal_actor, marshal_mailbox, _last_height) =
            MarshalActor::<_, Standard<Block>, _, _, _, _, _>::init(
                context.child("marshal"),
                finalizations_by_height,
                finalized_blocks,
                marshal_config,
            )
            .await;
        let sync_floor = plan.floor().cloned();

        // QMDB state-sync resolvers (one per database).
        let (qmdb_resolver_actor_a, qmdb_sync_resolver_a) =
            qmdb_resolver::Actor::<_, ed25519::PublicKey, _, _, mmr::Family, QmdbA<_>>::new(
                context.child("qmdb_resolver_a"),
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
        qmdb_resolver_actor_a.start(qmdb_a_resolver_network);

        let (qmdb_resolver_actor_b, qmdb_sync_resolver_b) = compact_resolver::Actor::<
            _,
            ed25519::PublicKey,
            _,
            _,
            mmr::Family,
            QmdbB<_>,
            Sha256,
        >::new(
            context.child("qmdb_resolver_b"),
            compact_resolver::Config {
                peer_provider: oracle.manager(),
                blocker: oracle.control(public_key.clone()),
                database: None,
                mailbox_size: NZUsize!(100),
                me: Some(public_key.clone()),
                initial: Duration::from_secs(1),
                timeout: Duration::from_secs(2),
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
        );
        qmdb_resolver_actor_b.start(qmdb_b_resolver_network);

        // Stateful actor
        let application = App::new(genesis_block.clone());
        let (stateful_actor, stateful_mailbox) = StatefulActor::init(
            context.child("stateful"),
            StatefulConfig {
                application,
                db_config,
                input_provider: (),
                marshal: marshal_mailbox.clone(),
                mailbox_size: NZUsize!(100),
                plan,
                resolvers: (qmdb_sync_resolver_a, qmdb_sync_resolver_b),
                sync_config: self.sync_config,
                prune_config: Some(PruneConfig {
                    max_pending_acks,
                    maintenance_interval: NZUsize!(5),
                    retained_marshal_blocks: 10,
                    retained_qmdb_blocks: 0,
                }),
            },
        );

        // Observe the oldest operation the full QMDB still retains, to assert pruning ran.
        // The compact db keeps no operation history to observe.
        let prune_observer = stateful_mailbox.clone();
        let oldest_retained: OldestRetained = Arc::new(move || {
            let mailbox = prune_observer.clone();
            Box::pin(async move {
                let (a, _b) = mailbox.subscribe_databases().await;
                let oldest_a = *a.read().await.bounds().start;
                oldest_a
            })
        });

        // Deferred wrapper
        let deferred = Deferred::new(
            context.child("deferred"),
            stateful_mailbox.clone(),
            marshal_mailbox.clone(),
            FixedEpocher::new(EPOCH_LENGTH),
        );

        // Marshal reporter: stateful mailbox, wrapped by monitor.
        let marshal_reporters = MonitorReporter::new(public_key.clone(), monitor, stateful_mailbox);

        // Start marshal actor with monitored reporters.
        marshal_actor.start(marshal_reporters, buffer, resolver);

        // Attach the marshal to probe, entering service. A syncing node has
        // already consumed its floor above; a source attaches without ever soliciting peers.
        probe_mailbox.attach(marshal_mailbox.clone());

        if should_state_sync {
            let finalization = sync_floor.expect("sync floor missing");
            let block = marshal_mailbox
                .subscribe_by_commitment(finalization.proposal.payload, CommitmentFallback::Wait)
                .await
                .expect("sync floor block must be available");
            let height = block.height();
            *self
                .sync_entries
                .lock()
                .entry(public_key.clone())
                .or_insert(0) += 1;
            self.sync_heights
                .lock()
                .insert(public_key.clone(), height.get());
            state_sync_height = Some(height.get());
        }

        // Initialize stateful from marshal's processed frontier.
        stateful_actor.start();

        // Simplex engine
        let simplex_config = simplex::Config {
            scheme,
            elector: RoundRobin::<Sha256>::default(),
            blocker: oracle.control(public_key.clone()),
            automaton: deferred.clone(),
            relay: deferred,
            reporter: marshal_mailbox.clone(),
            strategy: Sequential,
            partition: format!("{partition_prefix}-simplex"),
            mailbox_size: NZUsize!(100),
            epoch: Epoch::zero(),
            floor: simplex::config::Floor::Genesis(genesis_block.digest()),
            replay_buffer: IO_BUFFER_SIZE,
            write_buffer: IO_BUFFER_SIZE,
            page_cache,
            leader_timeout: Duration::from_secs(1),
            certification_timeout: Duration::from_secs(2),
            timeout_retry: Duration::from_millis(500),
            activity_timeout: ViewDelta::new(10),
            skip_timeout: ViewDelta::new(5),
            fetch_timeout: Duration::from_secs(2),
            fetch_concurrent: NZUsize!(3),
            forwarding: ForwardingPolicy::Disabled,
        };

        let engine = simplex::Engine::new(context, simplex_config);
        let handle = engine.start(vote_network, certificate_network, resolver_network);

        (
            handle,
            MockValidatorState {
                marshal: marshal_mailbox,
                state_sync_entries: self
                    .sync_entries
                    .lock()
                    .get(public_key)
                    .copied()
                    .unwrap_or(0),
                state_sync_height,
                oldest_retained,
            },
        )
    }

    fn start(engine: Self::Engine) -> Handle<()> {
        engine
    }
}

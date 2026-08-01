use super::common::*;
use crate::{
    simulate::{
        engine::{EngineDefinition, InitContext},
        reporter::MonitorReporter,
    },
    stateful::{
        Application, Config as StatefulConfig, Input, Proposed, PruneConfig,
        Stateful as StatefulActor, SyncPlan,
        db::{
            DatabaseSet, Merkleized as _, Shared, SyncEngineConfig, Unmerkleized as _,
            p2p::standard as qmdb_resolver,
        },
        probe::{Config as ProbeConfig, Probe},
    },
};
use commonware_broadcast::buffered;
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_consensus::{
    Block as ConsensusBlock, CertifiableBlock, Heightable,
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
};
use commonware_cryptography::{
    Digest as _, Digestible, Hasher, Sha256, Signer as _,
    certificate::{ConstantProvider, mocks::Fixture},
    ed25519, sha256,
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Buf, BufMut, Handle, Quota, Spawner, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    Context as StorageContext,
    archive::prunable,
    journal::contiguous::fixed::Config as FixedLogConfig,
    mmr::{self, Location, full::Config as MmrJournalConfig},
    qmdb::{
        any::{FixedConfig, unordered::fixed},
        sync::Target,
    },
    translator::TwoCap,
};
use commonware_utils::{
    NZDuration, NZU64, NZUsize, non_empty_range, range::NonEmptyRange, sync::Mutex, test_rng,
};
use futures::StreamExt;
use rand_core::Rng;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

/// The QMDB database type used by the single-db e2e tests.
type Qmdb<E> =
    fixed::Db<mmr::Family, E, sha256::Digest, sha256::Digest, Sha256, TwoCap, Sequential>;

pub(crate) type SingleDatabaseSet<E> = Shared<Qmdb<E>>;

fn qmdb_config(prefix: &str, page_cache: CacheRef) -> FixedConfig<TwoCap, Sequential> {
    FixedConfig {
        merkle_config: MmrJournalConfig {
            journal_partition: format!("{prefix}-qmdb-mmr-journal"),
            metadata_partition: format!("{prefix}-qmdb-mmr-metadata"),
            items_per_blob: NZU64!(11),
            write_buffer: IO_BUFFER_SIZE,
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: FixedLogConfig {
            partition: format!("{prefix}-qmdb-log-journal"),
            items_per_blob: NZU64!(7),
            page_cache,
            write_buffer: IO_BUFFER_SIZE,
        },
        translator: TwoCap,
        init_cache_size: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

/// A block carrying key-value mutations with embedded consensus context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Block {
    context: Context<sha256::Digest, ed25519::PublicKey>,
    parent: sha256::Digest,
    height: Height,
    state_root: sha256::Digest,
    range: NonEmptyRange<Location>,
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.state_root.write(buf);
        self.range.write(buf);
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.state_root.encode_size()
            + self.range.encode_size()
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
        })
    }
}

impl Digestible for Block {
    type Digest = sha256::Digest;

    fn digest(&self) -> sha256::Digest {
        Sha256::hash(&[&self.encode()])
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
    fn genesis(state_root: sha256::Digest, range: NonEmptyRange<Location>) -> Self {
        Self {
            context: Context {
                round: Round::new(Epoch::zero(), View::zero()),
                leader: ed25519::PrivateKey::from_seed(0).public_key(),
                parent: (View::zero(), sha256::Digest::EMPTY),
            },
            parent: sha256::Digest::EMPTY,
            height: Height::zero(),
            state_root,
            range,
        }
    }
}

/// A stateful application that increments a counter each block.
#[derive(Clone)]
struct App {
    genesis: Block,
}

impl App {
    fn new(genesis: Block) -> Self {
        Self { genesis }
    }

    /// Execute a block: increment "counter" and write `height -> height_val`.
    async fn execute<E: Rng + Spawner + StorageContext>(
        height: Height,
        mut batches: <SingleDatabaseSet<E> as DatabaseSet<E>>::Unmerkleized,
    ) -> <SingleDatabaseSet<E> as DatabaseSet<E>>::Merkleized {
        let counter = Sha256::hash(&[b"counter"]);
        let current: u64 = batches
            .get(&counter)
            .await
            .unwrap()
            .map_or(0, |v| digest_to_u64(&v));
        batches = batches.write(counter, Some(u64_to_digest(current + 1)));
        batches = batches.write(
            Sha256::hash(&[&height.get().to_be_bytes()]),
            Some(u64_to_digest(height.get())),
        );
        batches.merkleize().await.unwrap()
    }
}

impl<E: Rng + Spawner + StorageContext> Application<E> for App {
    type SigningScheme = MockScheme<ed25519::PublicKey>;
    type Context = Context<sha256::Digest, ed25519::PublicKey>;
    type Block = Block;
    type Databases = SingleDatabaseSet<E>;
    type Provider = ();
    type Input = ();

    async fn genesis(&mut self) -> Self::Block {
        self.genesis.clone()
    }

    async fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        _input: Input<Self::Input, Self::Provider>,
    ) -> Option<Proposed<Self, E>> {
        let mut ancestry = Box::pin(ancestry);
        let parent = ancestry.next().await?;
        let height = Height::new(parent.height().get() + 1);
        let merkleized = Self::execute(height, batches).await;
        let bounds = merkleized.bounds();
        let block = Block {
            context: context.1.clone(),
            parent: parent.digest(),
            height,
            state_root: merkleized.root(),
            range: non_empty_range!(bounds.inactivity_floor, Location::new(bounds.total_size)),
        };
        Some(Proposed { block, merkleized })
    }

    async fn verify(
        &mut self,
        _context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        let mut ancestry = Box::pin(ancestry);
        let tip = ancestry.next().await?;
        let merkleized = Self::execute(tip.height(), batches).await;
        let bounds = merkleized.bounds();
        if merkleized.root() != tip.state_root
            || non_empty_range!(bounds.inactivity_floor, Location::new(bounds.total_size))
                != tip.range
        {
            return None;
        }
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

/// Engine definition implementing `EngineDefinition` for the simulation harness.
#[derive(Clone)]
pub(crate) struct SingleDbEngine {
    participants: Vec<ed25519::PublicKey>,
    schemes: Vec<MockScheme<ed25519::PublicKey>>,
    enable_state_sync: bool,
    sync_config: SyncEngineConfig,
    sync_entries: Arc<Mutex<BTreeMap<ed25519::PublicKey, u64>>>,
    sync_heights: Arc<Mutex<BTreeMap<ed25519::PublicKey, u64>>>,
}

impl SingleDbEngine {
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
                max_retained_roots: 8,
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
            max_retained_roots: 8,
        };
        self
    }
}

impl EngineDefinition for SingleDbEngine {
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
            (5, TEST_QUOTA), // qmdb sync resolver
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

        // QMDB database config (created by Stateful::start)
        let db_config = qmdb_config(&partition_prefix, page_cache.clone());

        // Destructure the 7 channels.
        let mut channels = channels.into_iter();
        let vote_network = channels.next().unwrap();
        let certificate_network = channels.next().unwrap();
        let resolver_network = channels.next().unwrap();
        let backfill_network = channels.next().unwrap();
        let broadcast_network = channels.next().unwrap();
        let qmdb_resolver_network = channels.next().unwrap();
        let probe_network = channels.next().unwrap();

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

        let initial_target =
            <SingleDatabaseSet<deterministic::Context> as DatabaseSet<_>>::initial_sync_targets();
        let genesis_block = Block::genesis(initial_target.root, initial_target.range);

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
            view_retention: ViewDelta::new(10),
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

        // QMDB state-sync resolver.
        let (qmdb_resolver_actor, qmdb_sync_resolver) =
            qmdb_resolver::Actor::<_, ed25519::PublicKey, _, _, mmr::Family, Qmdb<_>>::new(
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
        let _qmdb_resolver_handle = qmdb_resolver_actor.start(qmdb_resolver_network);

        // Stateful actor
        let application = App::new(genesis_block.clone());
        let (stateful_actor, stateful_mailbox) = StatefulActor::init(
            context.child("stateful"),
            StatefulConfig {
                application,
                db_config,
                provider: (),
                marshal: marshal_mailbox.clone(),
                mailbox_size: NZUsize!(100),
                plan,
                resolvers: qmdb_sync_resolver,
                sync_config: self.sync_config,
                prune_config: Some(PruneConfig {
                    max_pending_acks,
                    maintenance_interval: NZUsize!(5),
                    retained_marshal_blocks: 10,
                    retained_qmdb_blocks: 0,
                }),
            },
        );

        // Observe the oldest operation QMDB still retains, to assert pruning ran.
        let prune_observer = stateful_mailbox.clone();
        let oldest_retained: OldestRetained = Arc::new(move || {
            let mailbox = prune_observer.clone();
            Box::pin(async move {
                let databases = mailbox.subscribe_databases().await;
                let guard = databases.read().await;
                let bounds = guard.bounds();
                *bounds.start
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
            mailbox_size: NZUsize!(3),
            epoch: Epoch::zero(),
            floor: simplex::config::Floor::Genesis(genesis_block.digest()),
            replay_buffer: IO_BUFFER_SIZE,
            write_buffer: IO_BUFFER_SIZE,
            page_cache,
            leader_timeout: Duration::from_secs(1),
            certification_timeout: Duration::from_secs(2),
            timeout_retry: Duration::from_millis(500),
            view_retention: ViewDelta::new(10),
            skip_timeout: Duration::from_secs(5),
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

#[cfg(test)]
mod certification_tests {
    use super::*;
    use crate::stateful::db::AttachableResolver;
    use commonware_actor::Feedback;
    use commonware_consensus::{
        CertifiableAutomaton as _, Reporter,
        marshal::{self, resolver::handler},
    };
    use commonware_macros::select;
    use commonware_resolver::{Fetch, Resolver as MarshalResolver, TargetedResolver};
    use commonware_runtime::{Clock as _, Runner as _};
    use commonware_storage::{
        merkle::Location,
        qmdb::sync::resolver::{FetchResult, Resolver as QmdbResolver},
    };
    use commonware_utils::{Acknowledgement as _, vec::NonEmptyVec};
    use std::{convert::Infallible, future::Future, num::NonZeroU64};

    #[derive(Clone)]
    struct NoopQmdbResolver;

    impl QmdbResolver for NoopQmdbResolver {
        type Family = mmr::Family;
        type Digest = sha256::Digest;
        type Op = fixed::Operation<mmr::Family, sha256::Digest, sha256::Digest>;
        type Error = Infallible;

        fn get_operations<'a>(
            &'a self,
            _op_count: Location<Self::Family>,
            _start_loc: Location<Self::Family>,
            _max_ops: NonZeroU64,
            _include_pinned_nodes: bool,
        ) -> impl Future<
            Output = Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error>,
        > + Send
        + 'a {
            std::future::pending()
        }
    }

    impl AttachableResolver<Qmdb<deterministic::Context>> for NoopQmdbResolver {
        async fn attach_database(&self, _db: Shared<Qmdb<deterministic::Context>>) {}
    }

    #[derive(Clone)]
    struct NoopMarshalResolver;

    #[derive(Clone)]
    struct NoopMarshalApplication;

    impl Reporter for NoopMarshalApplication {
        type Activity = marshal::Update<Block>;

        fn report(&mut self, activity: Self::Activity) -> Feedback {
            if let marshal::Update::Block(_, acknowledgement) = activity {
                acknowledgement.acknowledge();
            }
            Feedback::Ok
        }
    }

    impl MarshalResolver for NoopMarshalResolver {
        type Key = handler::Key<sha256::Digest>;
        type Subscriber = handler::Annotation;

        fn fetch<F>(&mut self, _fetch: F) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            Feedback::Ok
        }

        fn fetch_all<F>(&mut self, _fetches: Vec<F>) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            Feedback::Ok
        }

        fn retain(
            &mut self,
            _predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
        ) -> Feedback {
            Feedback::Ok
        }
    }

    impl TargetedResolver for NoopMarshalResolver {
        type PublicKey = ed25519::PublicKey;

        fn fetch_targeted(
            &mut self,
            _fetch: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
            _targets: NonEmptyVec<Self::PublicKey>,
        ) -> Feedback {
            Feedback::Ok
        }

        fn fetch_all_targeted<F>(
            &mut self,
            _fetches: Vec<(F, NonEmptyVec<Self::PublicKey>)>,
        ) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            Feedback::Ok
        }
    }

    async fn build_chain(context: &deterministic::Context, blocks: u64) -> (Block, Vec<Block>) {
        let initial_target =
            <SingleDatabaseSet<deterministic::Context> as DatabaseSet<_>>::initial_sync_targets();
        let genesis = Block::genesis(initial_target.root, initial_target.range);
        let page_cache = CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let databases = <SingleDatabaseSet<deterministic::Context> as DatabaseSet<_>>::init(
            context.child("chain_builder"),
            qmdb_config("certify-chain-builder", page_cache),
        )
        .await;
        let mut batches = databases.new_batches().await;
        let mut parent = genesis.clone();
        let mut chain = Vec::with_capacity(blocks as usize);
        // QMDB descendants retain uncommitted ancestry by weak reference after
        // merkleization, so keep the complete speculative chain alive here.
        let mut speculative = Vec::with_capacity(blocks as usize);

        for height in 1..=blocks {
            let height = Height::new(height);
            let merkleized = App::execute(height, batches).await;
            let bounds = merkleized.bounds();
            let block = Block {
                context: Context {
                    round: Round::new(Epoch::zero(), View::new(height.get())),
                    leader: ed25519::PrivateKey::from_seed(0).public_key(),
                    parent: (parent.context.round.view(), parent.digest()),
                },
                parent: parent.digest(),
                height,
                state_root: merkleized.root(),
                range: non_empty_range!(bounds.inactivity_floor, Location::new(bounds.total_size)),
            };
            speculative.push(merkleized);
            batches = <SingleDatabaseSet<deterministic::Context> as DatabaseSet<_>>::fork_batches(
                speculative.last().expect("speculative batch missing"),
            );
            parent = block.clone();
            chain.push(block);
        }

        (genesis, chain)
    }

    #[test]
    fn out_of_order_certifications_complete_on_qmdb() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (genesis, blocks) = build_chain(&context, 6).await;
            let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
            let mut signing_context = context.child("signing");
            let fixture = scheme_mocks::fixture(
                &mut signing_context,
                b"_COMMONWARE_GLUE_QMDB_OUT_OF_ORDER_CERTIFY",
                1,
            );
            let provider = ConstantProvider::new(fixture.schemes[0].clone());
            let finalizations_by_height = prunable::Archive::init(
                context.child("finalizations_by_height"),
                archive_config(
                    "certify-qmdb-marshal",
                    "finalizations",
                    page_cache.clone(),
                    (),
                ),
            )
            .await
            .expect("failed to initialize finalizations archive");
            let finalized_blocks = prunable::Archive::init(
                context.child("finalized_blocks"),
                archive_config("certify-qmdb-marshal", "blocks", page_cache.clone(), ()),
            )
            .await
            .expect("failed to initialize blocks archive");
            let (marshal_actor, marshal, _height) =
                MarshalActor::<_, Standard<Block>, _, _, _, _, _>::init(
                    context.child("marshal"),
                    finalizations_by_height,
                    finalized_blocks,
                    marshal::Config {
                        provider,
                        epocher: FixedEpocher::new(EPOCH_LENGTH),
                        start: marshal::Start::Genesis(genesis.clone()),
                        partition_prefix: "certify-qmdb-marshal".to_string(),
                        mailbox_size: NZUsize!(8),
                        view_retention: ViewDelta::new(10),
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
            let (resolver_receiver, _resolver_handler) =
                handler::init(context.child("marshal_resolver"), NZUsize!(8));
            let marshal_actor = marshal_actor.start_unbuffered(
                NoopMarshalApplication,
                (resolver_receiver, NoopMarshalResolver),
            );

            let plan = SyncPlan::init(&context, "certify-qmdb-stateful".to_string()).await;
            let (stateful, stateful_mailbox) = StatefulActor::init(
                context.child("stateful"),
                StatefulConfig {
                    application: App::new(genesis),
                    db_config: qmdb_config("certify-qmdb-stateful", page_cache),
                    provider: (),
                    marshal: marshal.clone(),
                    mailbox_size: NZUsize!(1),
                    plan,
                    resolvers: NoopQmdbResolver,
                    sync_config: SyncEngineConfig {
                        fetch_batch_size: NZU64!(1),
                        apply_batch_size: 1,
                        max_outstanding_requests: 1,
                        update_channel_size: NZUsize!(1),
                        max_retained_roots: 1,
                    },
                    prune_config: None,
                },
            );
            let stateful_actor = stateful.start();
            let _databases = stateful_mailbox.subscribe_databases().await;

            for block in &blocks {
                assert!(marshal.verified(block.context.round, block.clone()).await);
            }

            let mut deferred = Deferred::new(
                context.child("deferred"),
                stateful_mailbox,
                marshal,
                FixedEpocher::new(EPOCH_LENGTH),
            );
            let mut certifications = Vec::with_capacity(blocks.len());
            for index in [5, 1, 4, 0, 3, 2] {
                let block = &blocks[index];
                certifications.push(deferred.certify(block.context.round, block.digest()).await);
            }

            select! {
                results = futures::future::join_all(certifications) => {
                    assert_eq!(results.len(), blocks.len());
                    for result in results {
                        assert!(result.expect("certification result missing"));
                    }
                },
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("out-of-order QMDB certifications did not all complete");
                },
            }

            stateful_actor.abort();
            marshal_actor.abort();
            let _ = stateful_actor.await;
            let _ = marshal_actor.await;
        });
    }
}

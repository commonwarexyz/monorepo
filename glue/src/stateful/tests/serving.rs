//! Late-joiner state sync of a compact member while barriers span several blocks.
//!
//! A compact member serves only its exact published tip, so every height a joiner may target must
//! be published. These tests slow every barrier, run a mixed set (full + compact) and an
//! all-compact set under the same barrier delay and acknowledgement window, and record what the
//! joiner requested and what servers published.

use super::{
    NUM_VALIDATORS,
    common::*,
    delay_first,
    multi_db_app::{self, Block, MultiDatabaseSet, QmdbB},
};
use crate::{
    simulate::{
        engine::{EngineDefinition, InitContext},
        exit::ExitCondition,
        plan::PlanBuilder,
        reporter::MonitorReporter,
        tracker::ProgressTracker,
    },
    stateful::{
        Application, Config as StatefulConfig, ExecutionError, Input, Proposed, PruneConfig,
        Stateful as StatefulActor, SyncPlan,
        db::{
            Anchor, Barrier, DatabaseSet, Merkleized as _, MerkleizedOf, ReadersOf, Single,
            StateSyncSet, SyncEngineConfig, TipUpdate, Unmerkleized as _, UnmerkleizedOf,
            p2p as qmdb_resolver,
        },
        probe::{Config as ProbeConfig, Probe},
    },
};
use commonware_broadcast::buffered;
use commonware_consensus::{
    Heightable,
    marshal::{
        self,
        ancestry::Ancestry,
        core::{Actor as MarshalActor, CommitmentFallback},
        resolver::p2p as marshal_resolver,
        standard::{Deferred, Standard},
    },
    simplex::{
        self,
        config::{ForwardPolicy, SkipPolicy},
        elector::RoundRobin,
        mocks::scheme::{self as scheme_mocks, Scheme as MockScheme},
        types::Context,
    },
    types::{Epoch, FixedEpocher, Height, ViewDelta},
};
use commonware_cryptography::{
    Digestible, Hasher, Sha256,
    certificate::{ConstantProvider, mocks::Fixture},
    ed25519, sha256,
};
use commonware_p2p::utils::mux::Muxer;
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock, Error as RuntimeError, Handle, Quota, Supervisor as _, buffer::paged::CacheRef,
    deterministic,
};
use commonware_storage::{
    archive::prunable,
    journal::contiguous::variable::Config as VariableLogConfig,
    mmr::Location,
    qmdb::{
        immutable,
        sync::{CompactTarget, Request, Source as QmdbSource, Target, source},
    },
};
use commonware_utils::{
    NZDuration, NZU64, NZUsize, channel::ring, non_empty_range, range::NonEmptyRange, sync::Mutex,
    test_rng,
};
use futures::StreamExt;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

type Ctx = deterministic::Context;

/// Milliseconds of simulated time.
fn now_ms(clock: &impl Clock) -> u64 {
    clock
        .current()
        .duration_since(UNIX_EPOCH)
        .expect("simulated clock is past the epoch")
        .as_millis() as u64
}

/// Events recorded across every validator in one run.
#[derive(Default)]
pub(super) struct Events {
    /// Compact member size at each finalized height (identical on every node).
    size_at_height: BTreeMap<u64, u64>,
    /// First time any node proposed or verified each height, with the block's compact size.
    consensus: BTreeMap<u64, (u64, u64)>,
    /// Latest finalized height per node.
    height: BTreeMap<usize, u64>,
    /// Publications: (node, ms, compact size, starts a barrier).
    published: Vec<(usize, u64, u64, bool)>,
    /// Barrier completions: (node, ms).
    barriers_done: Vec<(usize, u64)>,
    /// Joiner fetch starts: (ms, member, requested size).
    requests: Vec<(u64, usize, u64)>,
    /// Joiner fetches answered: (ms, member, requested size).
    served: Vec<(u64, usize, u64)>,
    /// State sync start: (ms, anchor height).
    sync_start: Option<(u64, u64)>,
    /// State sync result: (ms, converged anchor height).
    synced: Option<(u64, u64)>,
}

/// Shared event log.
#[derive(Clone, Default)]
pub(super) struct Log(Arc<Mutex<Events>>);

impl Log {
    fn servers_height(&self, joiner: usize) -> u64 {
        let events = self.0.lock();
        events
            .height
            .iter()
            .filter(|(node, _)| **node != joiner)
            .map(|(_, height)| *height)
            .max()
            .unwrap_or(0)
    }
}

/// Slows every barrier by `delay` and logs publications and state sync.
#[derive(Clone)]
pub(super) struct Slow {
    node: usize,
    delay: Duration,
    log: Log,
}

/// The database layout under test.
pub(super) trait Layout: Clone + Send + Sync + 'static {
    type Set: DatabaseSet<Ctx>;

    fn config(prefix: &str, page_cache: CacheRef) -> <Self::Set as DatabaseSet<Ctx>>::Config;

    fn genesis() -> Block;

    fn execute(
        height: Height,
        batches: UnmerkleizedOf<Self::Set, Ctx>,
    ) -> impl Future<Output = Result<MerkleizedOf<Self::Set, Ctx>, ExecutionError>> + Send;

    /// The block fields committing to `merkleized`: (root A, range A, root B, range B).
    fn header(merkleized: &<Self::Set as DatabaseSet<Ctx>>::Merkleized) -> Header;

    fn targets(block: &Block) -> <Self::Set as DatabaseSet<Ctx>>::SyncTargets;

    /// The compact member's (DB-B) size in `targets`.
    fn compact_size(targets: &<Self::Set as DatabaseSet<Ctx>>::SyncTargets) -> u64;
}

type Header = (
    sha256::Digest,
    NonEmptyRange<Location>,
    sha256::Digest,
    NonEmptyRange<Location>,
);

/// A full QMDB (DB-A) and a compact QMDB (DB-B).
#[derive(Clone)]
pub(super) struct Mixed;

impl Layout for Mixed {
    type Set = MultiDatabaseSet<Ctx>;

    fn config(prefix: &str, page_cache: CacheRef) -> <Self::Set as DatabaseSet<Ctx>>::Config {
        multi_db_app::qmdb_config(prefix, page_cache)
    }

    fn genesis() -> Block {
        let (a, b) = <Self::Set as DatabaseSet<Ctx>>::initial_sync_targets();
        Block::genesis(
            a.root,
            a.range,
            b.root,
            non_empty_range!(Location::new(0), b.size),
        )
    }

    async fn execute(
        height: Height,
        batches: UnmerkleizedOf<Self::Set, Ctx>,
    ) -> Result<MerkleizedOf<Self::Set, Ctx>, ExecutionError> {
        multi_db_app::App::execute::<Ctx>(height, batches).await
    }

    fn header(merkleized: &<Self::Set as DatabaseSet<Ctx>>::Merkleized) -> Header {
        let (a, b) = merkleized;
        let (bounds_a, bounds_b) = (a.bounds(), b.bounds());
        (
            a.root(),
            non_empty_range!(bounds_a.inactivity_floor, bounds_a.tip.size),
            b.root(),
            non_empty_range!(bounds_b.inactivity_floor, bounds_b.tip.size),
        )
    }

    fn targets(block: &Block) -> <Self::Set as DatabaseSet<Ctx>>::SyncTargets {
        (
            Target::new(block.root_a, block.range_a.clone()),
            CompactTarget {
                root: block.root_b,
                size: block.range_b.end(),
            },
        )
    }

    fn compact_size(targets: &<Self::Set as DatabaseSet<Ctx>>::SyncTargets) -> u64 {
        *targets.1.size
    }
}

/// Two compact QMDBs.
#[derive(Clone)]
pub(super) struct AllCompact;

type CompactPair = (Single<QmdbB<Ctx>>, Single<QmdbB<Ctx>>);

fn compact_config(
    prefix: &str,
    member: &str,
    page_cache: CacheRef,
) -> immutable::fixed::CompactConfig<Sequential> {
    immutable::fixed::CompactConfig {
        strategy: Sequential,
        witness: VariableLogConfig {
            partition: format!("{prefix}-qmdb-{member}-witness"),
            items_per_section: NZU64!(1),
            compression: None,
            codec_config: (),
            page_cache,
            write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
        },
        commit_codec_config: (),
    }
}

impl Layout for AllCompact {
    type Set = CompactPair;

    fn config(prefix: &str, page_cache: CacheRef) -> <Self::Set as DatabaseSet<Ctx>>::Config {
        (
            compact_config(prefix, "a", page_cache.clone()),
            compact_config(prefix, "b", page_cache),
        )
    }

    fn genesis() -> Block {
        let (a, b) = <Self::Set as DatabaseSet<Ctx>>::initial_sync_targets();
        Block::genesis(
            a.root,
            non_empty_range!(Location::new(0), a.size),
            b.root,
            non_empty_range!(Location::new(0), b.size),
        )
    }

    async fn execute(
        height: Height,
        batches: UnmerkleizedOf<Self::Set, Ctx>,
    ) -> Result<MerkleizedOf<Self::Set, Ctx>, ExecutionError> {
        let (batch_a, batch_b) = batches;
        let key = Sha256::hash(&[&height.get().to_be_bytes()]);
        let batch_a = batch_a.set(key, u64_to_digest(height.get()));
        let batch_b = batch_b.set(key, u64_to_digest(height.get()));
        Ok((batch_a.merkleize().await?, batch_b.merkleize().await?))
    }

    fn header(merkleized: &<Self::Set as DatabaseSet<Ctx>>::Merkleized) -> Header {
        let (a, b) = merkleized;
        let (bounds_a, bounds_b) = (a.bounds(), b.bounds());
        (
            a.root(),
            non_empty_range!(bounds_a.inactivity_floor, bounds_a.tip.size),
            b.root(),
            non_empty_range!(bounds_b.inactivity_floor, bounds_b.tip.size),
        )
    }

    fn targets(block: &Block) -> <Self::Set as DatabaseSet<Ctx>>::SyncTargets {
        (
            CompactTarget {
                root: block.root_a,
                size: block.range_a.end(),
            },
            CompactTarget {
                root: block.root_b,
                size: block.range_b.end(),
            },
        )
    }

    fn compact_size(targets: &<Self::Set as DatabaseSet<Ctx>>::SyncTargets) -> u64 {
        *targets.1.size
    }
}

/// A layout's set with slowed barriers.
pub(super) struct SlowSet<L: Layout> {
    inner: L::Set,
    clock: Arc<Ctx>,
    slow: Slow,
}

impl<L: Layout> SlowSet<L> {
    async fn record_publication(&self, barrier: bool) {
        let size = L::compact_size(&self.inner.committed_targets().await);
        let at = now_ms(&*self.clock);
        self.slow
            .log
            .0
            .lock()
            .published
            .push((self.slow.node, at, size, barrier));
    }
}

impl<L: Layout> DatabaseSet<Ctx> for SlowSet<L> {
    type Unmerkleized = <L::Set as DatabaseSet<Ctx>>::Unmerkleized;
    type Merkleized = <L::Set as DatabaseSet<Ctx>>::Merkleized;
    const CHEAP_SNAPSHOT: bool = <L::Set as DatabaseSet<Ctx>>::CHEAP_SNAPSHOT;
    const ANY_CHEAP_SNAPSHOT: bool = <L::Set as DatabaseSet<Ctx>>::ANY_CHEAP_SNAPSHOT;
    type Readers = <L::Set as DatabaseSet<Ctx>>::Readers;
    type Snapshots = <L::Set as DatabaseSet<Ctx>>::Snapshots;
    type Config = (<L::Set as DatabaseSet<Ctx>>::Config, Slow);
    type SyncTargets = <L::Set as DatabaseSet<Ctx>>::SyncTargets;

    async fn init(
        context: Ctx,
        (config, slow): Self::Config,
        expected: Option<Self::SyncTargets>,
    ) -> Self {
        let clock = Arc::new(context.child("slow_set"));
        let inner = L::Set::init(context, config, expected).await;
        Self { inner, clock, slow }
    }

    fn initial_sync_targets() -> Self::SyncTargets {
        L::Set::initial_sync_targets()
    }

    fn readers(&self) -> Self::Readers {
        self.inner.readers()
    }

    fn new_batches(readers: &Self::Readers) -> impl Future<Output = Self::Unmerkleized> + Send {
        L::Set::new_batches(readers)
    }

    fn fork_batches(parent: &Self::Merkleized) -> Self::Unmerkleized {
        L::Set::fork_batches(parent)
    }

    fn matches_sync_targets(batches: &Self::Merkleized, targets: &Self::SyncTargets) -> bool {
        L::Set::matches_sync_targets(batches, targets)
    }

    fn committed_targets(&self) -> impl Future<Output = Self::SyncTargets> + Send {
        self.inner.committed_targets()
    }

    async fn apply(self, batches: Self::Merkleized) -> Self {
        let Self { inner, clock, slow } = self;
        let inner = inner.apply(batches).await;
        Self { inner, clock, slow }
    }

    async fn finalize(self) -> (Self, Self::Snapshots, Barrier) {
        let Self { inner, clock, slow } = self;
        let (inner, snapshots, barrier) = inner.finalize().await;
        let set = Self { inner, clock, slow };
        set.record_publication(true).await;
        if set.slow.delay.is_zero() {
            return (set, snapshots, barrier);
        }
        let clock = set.clock.clone();
        let (delay, node, log) = (set.slow.delay, set.slow.node, set.slow.log.clone());
        let slowed = Handle::from_future(async move {
            clock.sleep(delay).await;
            if !barrier.durable().await {
                return Err(RuntimeError::Closed);
            }
            let at = now_ms(&*clock);
            log.0.lock().barriers_done.push((node, at));
            Ok(())
        });
        (set, snapshots, Barrier::from_handles::<Self>([slowed]))
    }

    async fn snapshot(self) -> (Self, Self::Snapshots) {
        let Self { inner, clock, slow } = self;
        let (inner, snapshots) = inner.snapshot().await;
        let set = Self { inner, clock, slow };
        set.record_publication(false).await;
        (set, snapshots)
    }

    async fn refresh_cheap(self, served: &Self::Snapshots) -> (Self, Self::Snapshots) {
        let Self { inner, clock, slow } = self;
        let (inner, snapshots) = inner.refresh_cheap(served).await;
        let set = Self { inner, clock, slow };
        set.record_publication(false).await;
        (set, snapshots)
    }

    async fn prune(self, targets: &Self::SyncTargets) -> Self {
        let Self { inner, clock, slow } = self;
        let inner = inner.prune(targets).await;
        Self { inner, clock, slow }
    }
}

impl<L, R> StateSyncSet<Ctx, R, sha256::Digest> for SlowSet<L>
where
    L: Layout,
    L::Set: StateSyncSet<Ctx, R, sha256::Digest>,
    R: Send,
{
    type Error = <L::Set as StateSyncSet<Ctx, R, sha256::Digest>>::Error;

    async fn sync(
        context: Ctx,
        (config, slow): Self::Config,
        sources: R,
        anchor: Anchor<sha256::Digest>,
        targets: Self::SyncTargets,
        tip_updates: ring::Receiver<TipUpdate<sha256::Digest, Self::SyncTargets>>,
        sync_config: SyncEngineConfig,
    ) -> Result<(Self, Anchor<sha256::Digest>), Self::Error> {
        let clock = Arc::new(context.child("slow_set"));
        let started = now_ms(&*clock);
        slow.log.0.lock().sync_start = Some((started, anchor.height.get()));
        let (inner, anchor) = L::Set::sync(
            context,
            config,
            sources,
            anchor,
            targets,
            tip_updates,
            sync_config,
        )
        .await?;
        let finished = now_ms(&*clock);
        slow.log.0.lock().synced = Some((finished, anchor.height.get()));
        Ok((Self { inner, clock, slow }, anchor))
    }
}

/// Logs a joiner's fetches for one member.
#[derive(Clone)]
pub(super) struct Recorded<R> {
    inner: R,
    member: usize,
    clock: Arc<Ctx>,
    log: Log,
}

impl<R: QmdbSource> QmdbSource for Recorded<R> {
    type Family = R::Family;
    type Digest = R::Digest;
    type Op = R::Op;
    type Error = R::Error;

    async fn serve(&self, request: Request<Self::Family>) -> source::Result<Self> {
        let size = *request.size();
        let started = now_ms(&*self.clock);
        self.log
            .0
            .lock()
            .requests
            .push((started, self.member, size));
        let result = self.inner.serve(request).await;
        if result.is_ok() {
            let at = now_ms(&*self.clock);
            self.log.0.lock().served.push((at, self.member, size));
        }
        result
    }
}

/// Writes every finalized height to the log.
#[derive(Clone)]
pub(super) struct ServingApp<L: Layout> {
    genesis: Block,
    node: usize,
    log: Log,
    _layout: std::marker::PhantomData<L>,
}

impl<L: Layout> ServingApp<L> {
    fn saw(&self, context: &Ctx, block: &Block) {
        let at = now_ms(context);
        self.log
            .0
            .lock()
            .consensus
            .entry(block.height().get())
            .or_insert((at, *block.range_b.end()));
    }
}

impl<L: Layout> Application<Ctx> for ServingApp<L> {
    type SigningScheme = MockScheme<ed25519::PublicKey>;
    type Context = Context<sha256::Digest, ed25519::PublicKey>;
    type Block = Block;
    type Databases = SlowSet<L>;
    type Captured = ();
    type Provider = ();
    type Input = ();

    async fn genesis(&mut self) -> Self::Block {
        self.genesis.clone()
    }

    async fn propose(
        &mut self,
        context: (Ctx, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: UnmerkleizedOf<Self::Databases, Ctx>,
        _input: Input<Self::Input, Self::Provider>,
    ) -> Result<Option<Proposed<Self, Ctx>>, ExecutionError> {
        let mut ancestry = Box::pin(ancestry);
        let Some(parent) = ancestry.next().await else {
            return Ok(None);
        };
        let height = parent.height().next();
        let merkleized = L::execute(height, batches).await?;
        let (root_a, range_a, root_b, range_b) = L::header(&merkleized);
        let block = Block {
            context: context.1.clone(),
            parent: parent.digest(),
            height,
            root_a,
            range_a,
            root_b,
            range_b,
        };
        self.saw(&context.0, &block);
        Ok(Some(Proposed { block, merkleized }))
    }

    async fn verify(
        &mut self,
        context: (Ctx, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: UnmerkleizedOf<Self::Databases, Ctx>,
    ) -> Result<Option<MerkleizedOf<Self::Databases, Ctx>>, ExecutionError> {
        let mut ancestry = Box::pin(ancestry);
        let Some(tip) = ancestry.next().await else {
            return Ok(None);
        };
        self.saw(&context.0, &tip);
        let merkleized = L::execute(tip.height(), batches).await?;
        let header = (
            tip.root_a,
            tip.range_a.clone(),
            tip.root_b,
            tip.range_b.clone(),
        );
        Ok((L::header(&merkleized) == header).then_some(merkleized))
    }

    async fn apply(
        &mut self,
        _context: (Ctx, Self::Context),
        block: &Self::Block,
        batches: UnmerkleizedOf<Self::Databases, Ctx>,
    ) -> Result<Option<MerkleizedOf<Self::Databases, Ctx>>, ExecutionError> {
        L::execute(block.height(), batches).await.map(Some)
    }

    async fn capture(
        &mut self,
        _context: (Ctx, Self::Context),
        block: &Self::Block,
        _batches: &MerkleizedOf<Self::Databases, Ctx>,
        _readers: ReadersOf<Self::Databases, Ctx>,
    ) {
        let height = block.height().get();
        let mut events = self.log.0.lock();
        events.size_at_height.insert(height, *block.range_b.end());
        let latest = events.height.entry(self.node).or_insert(0);
        *latest = (*latest).max(height);
    }

    async fn finalized(
        &mut self,
        _context: (Ctx, Self::Context),
        _block: &Self::Block,
        _captured: Self::Captured,
        _readers: ReadersOf<Self::Databases, Ctx>,
    ) {
    }

    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<Ctx>>::SyncTargets {
        L::targets(block)
    }
}

/// Engine for one layout, barrier delay, and acknowledgement window.
#[derive(Clone)]
pub(super) struct ServingEngine<L: Layout> {
    participants: Vec<ed25519::PublicKey>,
    schemes: Vec<MockScheme<ed25519::PublicKey>>,
    delay: Duration,
    max_pending_acks: usize,
    log: Log,
    _layout: std::marker::PhantomData<L>,
}

impl<L: Layout> ServingEngine<L> {
    pub(super) fn new(delay: Duration, max_pending_acks: usize, log: Log) -> Self {
        let mut rng = test_rng();
        let Fixture {
            participants,
            schemes,
            ..
        } = scheme_mocks::fixture(&mut rng, NAMESPACE, NUM_VALIDATORS);
        Self {
            participants,
            schemes,
            delay,
            max_pending_acks,
            log,
            _layout: std::marker::PhantomData,
        }
    }
}

/// Builds and starts one validator for layout `$layout`. A macro rather than a generic body so
/// every actor sees the layout's concrete types.
macro_rules! serving_engine {
    ($layout:ty) => {
        impl EngineDefinition for ServingEngine<$layout> {
            type PublicKey = ed25519::PublicKey;
            type Engine = Handle<()>;
            type State = MockValidatorState<Standard<Block>>;

            fn participants(&self) -> Vec<Self::PublicKey> {
                self.participants.clone()
            }

            fn channels(&self) -> Vec<(u64, Quota)> {
                (0..7).map(|channel| (channel, TEST_QUOTA)).collect()
            }

            async fn init(
                &self,
                ctx: InitContext<'_, Self::PublicKey>,
            ) -> (Self::Engine, Self::State) {
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
                let slow = Slow {
                    node: index,
                    delay: self.delay,
                    log: self.log.clone(),
                };
                let db_config = (
                    <$layout as Layout>::config(&partition_prefix, page_cache.clone()),
                    slow,
                );

                let mut channels = channels.into_iter();
                let vote_network = channels.next().unwrap();
                let certificate_network = channels.next().unwrap();
                let resolver_network = channels.next().unwrap();
                let backfill_network = channels.next().unwrap();
                let broadcast_network = channels.next().unwrap();
                let qmdb_resolver_network = channels.next().unwrap();
                let probe_network = channels.next().unwrap();

                let (mux, mut mux_handle) = Muxer::new(
                    context.child("qmdb_mux"),
                    qmdb_resolver_network.0,
                    qmdb_resolver_network.1,
                    100,
                );
                mux.start();
                let qmdb_a_network = mux_handle.register(0).await.unwrap();
                let qmdb_b_network = mux_handle.register(1).await.unwrap();

                let resolver = marshal_resolver::init(
                    context.child("marshal_resolver"),
                    marshal_resolver::Config {
                        public_key: public_key.clone(),
                        peer_provider: oracle.manager(),
                        blocker: oracle.control(public_key.clone()),
                        mailbox_size: NZUsize!(100),
                        timeout: Duration::from_secs(2),
                        fetch_retry_timeout: Duration::from_millis(100),
                        priority_requests: false,
                        priority_responses: false,
                    },
                    backfill_network,
                );
                let (broadcast_engine, buffer) = buffered::Engine::new(
                    context.child("broadcast"),
                    buffered::Config {
                        public_key: public_key.clone(),
                        mailbox_size: NZUsize!(100),
                        deque_size: 10,
                        priority: false,
                        codec_config: (),
                        peer_provider: oracle.manager(),
                    },
                );
                broadcast_engine.start(broadcast_network);

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

                let genesis_block = <$layout as Layout>::genesis();
                let startup = context.child("stateful_startup");
                let mut plan =
                    SyncPlan::init(startup.child("plan"), partition_prefix.clone()).await;
                let should_state_sync = plan.should_sync(delayed);
                let provider = ConstantProvider::new(scheme.clone());
                let (probe, probe_mailbox) = Probe::new(ProbeConfig {
                    context: context.child("probe"),
                    provider: provider.clone(),
                    strategy: Sequential,
                    mailbox_size: NZUsize!(100),
                    blocker: oracle.control(public_key.clone()),
                    minimum_epoch: Epoch::zero(),
                    retry_timeout: NZDuration!(Duration::from_millis(100)),
                });
                probe.start(probe_network);
                if should_state_sync {
                    let finalization = probe_mailbox.subscribe().await.expect("probe stopped");
                    plan = plan.set_floor(finalization).await;
                }

                let (marshal_actor, marshal_mailbox, floor) =
                    MarshalActor::<_, Standard<Block>, _, _, _, _, _>::init(
                        context.child("marshal"),
                        finalizations_by_height,
                        finalized_blocks,
                        marshal::Config {
                            provider: provider.clone(),
                            epocher: FixedEpocher::new(EPOCH_LENGTH),
                            start: plan.marshal_start(genesis_block.clone().into()),
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
                            max_pending_acks: NZUsize!(self.max_pending_acks),
                            strategy: Sequential,
                        },
                    )
                    .await;
                let sync_floor = plan.floor().cloned();

                let publication_context = context.child("publication");
                let (snapshot_publisher, snapshot_subscriber) = crate::stateful::db::Publisher::<
                    crate::stateful::db::SnapshotsOf<SlowSet<$layout>, Ctx>,
                >::new(&publication_context);
                let resolver_config = || qmdb_resolver::Config {
                    peer_provider: oracle.manager(),
                    blocker: oracle.control(public_key.clone()),
                    mailbox_size: NZUsize!(100),
                    me: Some(public_key.clone()),
                    timeout: Duration::from_secs(2),
                    fetch_retry_timeout: Duration::from_millis(100),
                    max_serve_ops: NZU64!(16),
                    serve_timeout: Duration::from_secs(10),
                    priority_requests: false,
                    priority_responses: false,
                };
                let (qmdb_actor_a, qmdb_mailbox_a) = qmdb_resolver::Actor::new(
                    context.child("qmdb_resolver_a"),
                    resolver_config(),
                    snapshot_subscriber.view(|snapshots| &snapshots.0),
                );
                qmdb_actor_a.start(qmdb_a_network);
                let (qmdb_actor_b, qmdb_mailbox_b) = qmdb_resolver::Actor::new(
                    context.child("qmdb_resolver_b"),
                    resolver_config(),
                    snapshot_subscriber.view(|snapshots| &snapshots.1),
                );
                qmdb_actor_b.start(qmdb_b_network);
                let clock = Arc::new(context.child("recorded"));
                let resolvers = (
                    Recorded {
                        inner: qmdb_mailbox_a,
                        member: 0,
                        clock: clock.clone(),
                        log: self.log.clone(),
                    },
                    Recorded {
                        inner: qmdb_mailbox_b,
                        member: 1,
                        clock: clock.clone(),
                        log: self.log.clone(),
                    },
                );

                let (stateful_actor, stateful_mailbox) = StatefulActor::new(
                    context.child("stateful"),
                    StatefulConfig {
                        application: ServingApp::<$layout> {
                            genesis: genesis_block.clone(),
                            node: index,
                            log: self.log.clone(),
                            _layout: std::marker::PhantomData,
                        },
                        db_config,
                        provider: (),
                        marshal: (marshal_mailbox.clone(), floor),
                        mailbox_size: NZUsize!(100),
                        plan,
                        resolvers,
                        snapshot_publisher,
                        sync_config: SyncEngineConfig {
                            fetch_batch_size: NZU64!(16),
                            apply_batch_size: NZU64!(64),
                            max_outstanding_requests: 8,
                            update_channel_size: NZUsize!(256),
                            max_retained_roots: 32,
                        },
                        prune_config: Some(PruneConfig {
                            maintenance_interval: NZUsize!(5),
                            retained_marshal_blocks: 10,
                            retained_qmdb_blocks: 0,
                        }),
                    },
                );

                let deferred = Deferred::new(
                    context.child("deferred"),
                    stateful_mailbox.clone(),
                    marshal_mailbox.clone(),
                    FixedEpocher::new(EPOCH_LENGTH),
                );
                let reporters = MonitorReporter::new(public_key.clone(), monitor, stateful_mailbox);
                marshal_actor.start(reporters, buffer, resolver);
                probe_mailbox.attach(marshal_mailbox.clone());

                let mut state_sync_height = None;
                if should_state_sync {
                    let finalization = sync_floor.expect("sync floor missing");
                    let block = marshal_mailbox
                        .subscribe_by_commitment(
                            finalization.proposal.payload,
                            CommitmentFallback::Wait,
                        )
                        .await
                        .expect("sync floor block must be available");
                    state_sync_height = Some(block.height().get());
                }
                stateful_actor.start();

                let engine = simplex::Engine::new(
                    context,
                    simplex::Config {
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
                        view_retention: ViewDelta::new(10),
                        skip: SkipPolicy::Enabled {
                            timeout: Duration::from_secs(5),
                            budget: simplex::SkipBudget::Participants,
                        },
                        fetch_timeout: Duration::from_secs(2),
                        forward: ForwardPolicy::Disabled,
                        track_historical_votes: false,
                    },
                );
                let handle = engine.start(vote_network, certificate_network, resolver_network);
                (
                    handle,
                    MockValidatorState {
                        marshal: marshal_mailbox,
                        state_sync_entries: u64::from(should_state_sync),
                        state_sync_height,
                        oldest_retained: Arc::new(|| None),
                    },
                )
            }

            fn start(engine: Self::Engine) -> Handle<()> {
                engine
            }
        }
    };
}

serving_engine!(Mixed);
serving_engine!(AllCompact);

/// Exits once the joiner has synced and servers moved a few blocks past it, or once servers are
/// `bound` blocks past the joiner's sync start without it converging.
#[derive(Clone)]
struct SyncedOrBound {
    log: Log,
    joiner: usize,
    bound: u64,
}

impl<S: Send + Sync> ExitCondition<ed25519::PublicKey, S> for SyncedOrBound {
    fn name(&self) -> &str {
        "synced_or_bound"
    }

    fn requires_polling(&self) -> bool {
        true
    }

    fn reached<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        _states: &'a [&'a S],
        _target_count: usize,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move {
            let height = self.log.servers_height(self.joiner);
            let (synced, started) = {
                let events = self.log.0.lock();
                (events.synced, events.sync_start)
            };
            Ok(match (synced, started) {
                (Some((_, synced)), _) => height >= synced + 3,
                (None, Some((_, started))) => height >= started + self.bound,
                (None, None) => false,
            })
        })
    }
}

/// One run's outcome, printed through `Debug`.
#[derive(Debug)]
struct Outcome {
    /// Distinct compact sizes the joiner requested.
    compact_targets: usize,
    /// Compact targets below the servers' newest compact publication that no server published.
    never_published: usize,
}

fn summarize(log: &Log, joiner: usize) -> Outcome {
    let events = log.0.lock();
    let requested: BTreeSet<u64> = events
        .requests
        .iter()
        .filter(|(_, member, _)| *member == 1)
        .map(|(_, _, size)| *size)
        .collect();
    let published: BTreeSet<u64> = events
        .published
        .iter()
        .filter(|(node, ..)| *node != joiner)
        .map(|(_, _, size, _)| *size)
        .collect();
    let newest = published.last().copied().unwrap_or(0);
    Outcome {
        compact_targets: requested.len(),
        never_published: requested
            .iter()
            .filter(|size| **size < newest && !published.contains(size))
            .count(),
    }
}

/// Runs one late-joiner simulation and summarizes it.
fn run<L>(delay: Duration, max_pending_acks: usize, seed: u64, bound: u64) -> Outcome
where
    L: Layout,
    ServingEngine<L>: EngineDefinition<
            PublicKey = ed25519::PublicKey,
            State = MockValidatorState<Standard<Block>>,
        >,
{
    let log = Log::default();
    let engine = ServingEngine::<L>::new(delay, max_pending_acks, log.clone());
    let joiner = 0;
    let delay_round = delay_first(&engine.participants(), 40);
    PlanBuilder::new(engine)
        .seed(seed)
        .crash(delay_round)
        .exit_condition(SyncedOrBound {
            log: log.clone(),
            joiner,
            bound,
        })
        .run()
        .unwrap();
    summarize(&log, joiner)
}

/// Every compact target a late joiner requests is published by the servers, for a mixed set as
/// for an all-compact one, even when barriers span several blocks.
///
/// A compact member serves only the exact state it published. With a 250 ms barrier and an
/// acknowledgement window of 4, seed 3 phase-locks every server's barrier starts to heights 0 and
/// 1 mod 4, while the joiner retargets at heights 3 mod 4. A mixed set that published only when
/// a barrier starts would never publish any of those targets, so its compact member could never
/// be served. Refreshing the cheap members every block publishes them all. Whether the joiner
/// then converges depends on whether servers keep up with consensus, which this does not check.
#[test]
fn mixed_set_publishes_every_compact_target() {
    const BOUND: u64 = 60;
    let delay = Duration::from_millis(250);
    for seed in [3u64, 4] {
        for (layout, outcome) in [
            ("all-compact", run::<AllCompact>(delay, 4, seed, BOUND)),
            ("mixed", run::<Mixed>(delay, 4, seed, BOUND)),
        ] {
            assert!(
                outcome.compact_targets > 0,
                "{layout} joiner requested nothing"
            );
            assert_eq!(
                outcome.never_published, 0,
                "{layout} servers skipped compact targets (seed {seed}): {outcome:?}"
            );
        }
    }
}

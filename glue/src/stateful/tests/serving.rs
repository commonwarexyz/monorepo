//! Late-joiner state sync of a compact member while barriers span several blocks.
//!
//! A compact member serves only the tips it published, so its served state must follow every
//! finalized block even while a barrier is in flight. These tests slow every barrier, run a mixed
//! set (full + compact) and an all-compact set under the same barrier delay and acknowledgement
//! window, and check what each node serves and whether a late joiner converges.

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
        Application, Config as StatefulConfig, Input, Proposed, PruneConfig,
        Stateful as StatefulActor, SyncPlan,
        db::{
            Anchor, Barrier, DatabaseSet, Merkleized as _, Shared, SnapshotsOf, StateSyncSet,
            Subscriber, SyncEngineConfig, TipUpdate, Unmerkleized as _, p2p as qmdb_resolver,
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
use commonware_macros::test_group;
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
    /// Latest finalized height per node.
    height: BTreeMap<usize, u64>,
    /// Compact member size after each finalized height (identical on every node).
    compact_size: BTreeMap<u64, u64>,
    /// Served-state checks made at a finalized hook.
    served_checks: usize,
    /// Of those, the checks the joiner made (in its state-sync handoff and after it).
    joiner_checks: usize,
    /// Checks whose served compact size lagged the previous block: (node, height, served,
    /// expected).
    served_lags: Vec<(usize, u64, u64, u64)>,
    /// Joiner fetch starts: (member, requested size).
    requests: Vec<(usize, u64)>,
    /// Members of the joiner's answered fetches.
    served: Vec<usize>,
    /// State sync start: anchor height.
    sync_start: Option<u64>,
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

/// Slows every barrier by `delay` and logs state sync.
#[derive(Clone)]
pub(super) struct Slow {
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
        batches: <Self::Set as DatabaseSet<Ctx>>::Unmerkleized,
    ) -> impl Future<Output = <Self::Set as DatabaseSet<Ctx>>::Merkleized> + Send;

    /// The block fields committing to `merkleized`: (root A, range A, root B, range B).
    fn header(merkleized: &<Self::Set as DatabaseSet<Ctx>>::Merkleized) -> Header;

    fn targets(block: &Block) -> <Self::Set as DatabaseSet<Ctx>>::SyncTargets;

    /// The size the compact member (DB-B) of `snapshots` serves at its latest tip.
    fn served_compact_size(snapshots: &<Self::Set as DatabaseSet<Ctx>>::Snapshots) -> u64;
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
        batches: <Self::Set as DatabaseSet<Ctx>>::Unmerkleized,
    ) -> <Self::Set as DatabaseSet<Ctx>>::Merkleized {
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

    fn served_compact_size(snapshots: &<Self::Set as DatabaseSet<Ctx>>::Snapshots) -> u64 {
        *snapshots.1.latest().size()
    }
}

/// Two compact QMDBs.
#[derive(Clone)]
pub(super) struct AllCompact;

type CompactPair = (Shared<QmdbB<Ctx>>, Shared<QmdbB<Ctx>>);

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
        batches: <Self::Set as DatabaseSet<Ctx>>::Unmerkleized,
    ) -> <Self::Set as DatabaseSet<Ctx>>::Merkleized {
        let (batch_a, batch_b) = batches;
        let key = Sha256::hash(&[&height.get().to_be_bytes()]);
        let batch_a = batch_a.set(key, u64_to_digest(height.get()));
        let batch_b = batch_b.set(key, u64_to_digest(height.get()));
        (
            batch_a.merkleize().await.unwrap(),
            batch_b.merkleize().await.unwrap(),
        )
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

    fn served_compact_size(snapshots: &<Self::Set as DatabaseSet<Ctx>>::Snapshots) -> u64 {
        *snapshots.1.latest().size()
    }
}

/// A layout's set with slowed barriers.
pub(super) struct SlowSet<L: Layout> {
    inner: L::Set,
    clock: Arc<Ctx>,
    slow: Slow,
}

impl<L: Layout> Clone for SlowSet<L> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            clock: self.clock.clone(),
            slow: self.slow.clone(),
        }
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

    fn new_batches(&self) -> impl Future<Output = Self::Unmerkleized> + Send {
        self.inner.new_batches()
    }

    fn fork_batches(parent: &Self::Merkleized) -> Self::Unmerkleized {
        L::Set::fork_batches(parent)
    }

    fn matches_sync_targets(batches: &Self::Merkleized, targets: &Self::SyncTargets) -> bool {
        L::Set::matches_sync_targets(batches, targets)
    }

    fn readers(&self) -> Self::Readers {
        self.inner.readers()
    }

    fn apply(&self, batches: Self::Merkleized) -> impl Future<Output = ()> + Send {
        self.inner.apply(batches)
    }

    async fn finalize(&self) -> (Self::Snapshots, Barrier) {
        let (snapshots, barrier) = self.inner.finalize().await;
        if self.slow.delay.is_zero() {
            return (snapshots, barrier);
        }
        let clock = self.clock.clone();
        let delay = self.slow.delay;
        let slowed = Handle::from_future(async move {
            clock.sleep(delay).await;
            if !barrier.durable().await {
                return Err(RuntimeError::Closed);
            }
            Ok(())
        });
        (snapshots, Barrier::from_handles::<Self>([slowed]))
    }

    fn snapshot(&self) -> impl Future<Output = Self::Snapshots> + Send {
        self.inner.snapshot()
    }

    fn refresh_cheap(
        &self,
        served: &Self::Snapshots,
    ) -> impl Future<Output = Self::Snapshots> + Send {
        self.inner.refresh_cheap(served)
    }

    fn merge_snapshots(served: &Self::Snapshots, fresh: Self::Snapshots) -> Self::Snapshots {
        L::Set::merge_snapshots(served, fresh)
    }

    fn prune(&self, targets: &Self::SyncTargets) -> impl Future<Output = ()> + Send {
        self.inner.prune(targets)
    }

    fn committed_targets(&self) -> impl Future<Output = Self::SyncTargets> + Send {
        self.inner.committed_targets()
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
        slow.log.0.lock().sync_start = Some(anchor.height.get());
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
    log: Log,
}

impl<R: QmdbSource> QmdbSource for Recorded<R> {
    type Family = R::Family;
    type Digest = R::Digest;
    type Op = R::Op;
    type Error = R::Error;

    async fn serve(&self, request: Request<Self::Family>) -> source::Result<Self> {
        let size = *request.size();
        self.log.0.lock().requests.push((self.member, size));
        let result = self.inner.serve(request).await;
        if result.is_ok() {
            self.log.0.lock().served.push(self.member);
        }
        result
    }
}

/// Writes every finalized height to the log, and checks at each finalized hook that the node
/// serves the compact state of the previous block.
#[derive(Clone)]
pub(super) struct ServingApp<L: Layout> {
    genesis: Block,
    node: usize,
    log: Log,
    served: Subscriber<SnapshotsOf<SlowSet<L>, Ctx>>,
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
        batches: <Self::Databases as DatabaseSet<Ctx>>::Unmerkleized,
        _input: Input<Self::Input, Self::Provider>,
    ) -> Option<Proposed<Self, Ctx>> {
        let mut ancestry = Box::pin(ancestry);
        let parent = ancestry.next().await?;
        let height = parent.height().next();
        let merkleized = L::execute(height, batches).await;
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
        Some(Proposed { block, merkleized })
    }

    async fn verify(
        &mut self,
        _context: (Ctx, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<Ctx>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<Ctx>>::Merkleized> {
        let mut ancestry = Box::pin(ancestry);
        let tip = ancestry.next().await?;
        let merkleized = L::execute(tip.height(), batches).await;
        let header = (
            tip.root_a,
            tip.range_a.clone(),
            tip.root_b,
            tip.range_b.clone(),
        );
        (L::header(&merkleized) == header).then_some(merkleized)
    }

    async fn apply(
        &mut self,
        _context: (Ctx, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<Ctx>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<Ctx>>::Merkleized> {
        Some(L::execute(block.height(), batches).await)
    }

    async fn capture(
        &mut self,
        _context: (Ctx, Self::Context),
        block: &Self::Block,
        _batches: &<Self::Databases as DatabaseSet<Ctx>>::Merkleized,
        _readers: <Self::Databases as DatabaseSet<Ctx>>::Readers,
    ) {
        let height = block.height().get();
        let mut events = self.log.0.lock();
        events.compact_size.insert(height, *block.range_b.end());
        let latest = events.height.entry(self.node).or_insert(0);
        *latest = (*latest).max(height);
    }

    async fn finalized(
        &mut self,
        _context: (Ctx, Self::Context),
        block: &Self::Block,
        _captured: Self::Captured,
        _readers: <Self::Databases as DatabaseSet<Ctx>>::Readers,
    ) {
        // Every block before this one was published before this block applied.
        let Some(snapshots) = self.served.latest() else {
            return;
        };
        let served = L::served_compact_size(&snapshots);
        let height = block.height().get();
        let mut events = self.log.0.lock();
        let Some(expected) = events.compact_size.get(&(height - 1)).copied() else {
            return;
        };
        events.served_checks += 1;
        if self.node == JOINER {
            events.joiner_checks += 1;
        }
        if served != expected {
            events
                .served_lags
                .push((self.node, height, served, expected));
        }
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
                let state_sync_resumed = plan.floor().is_some();
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
                    serve_timeout: Duration::from_secs(2),
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
                let resolvers = (
                    Recorded {
                        inner: qmdb_mailbox_a,
                        member: 0,
                        log: self.log.clone(),
                    },
                    Recorded {
                        inner: qmdb_mailbox_b,
                        member: 1,
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
                            served: snapshot_subscriber.clone(),
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
                        state_sync_resumed,
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
                (None, Some(started)) => height >= started + self.bound,
                (None, None) => false,
            })
        })
    }
}

/// One run's outcome, printed through `Debug`.
#[derive(Debug)]
struct Outcome {
    /// The joiner's state sync result: (ms, converged anchor height).
    synced: Option<(u64, u64)>,
    /// Distinct compact sizes the joiner requested.
    compact_targets: usize,
    /// Answered fetches per member.
    served: [usize; 2],
    /// Served-state checks made at finalized hooks.
    served_checks: usize,
    /// Of those, the checks the joiner made.
    joiner_checks: usize,
    /// Checks whose served compact size lagged the previous block.
    served_lags: Vec<(usize, u64, u64, u64)>,
}

fn summarize(log: &Log) -> Outcome {
    let events = log.0.lock();
    let compact_targets: BTreeSet<u64> = events
        .requests
        .iter()
        .filter(|(member, _)| *member == 1)
        .map(|(_, size)| *size)
        .collect();
    let mut served = [0; 2];
    for member in &events.served {
        served[*member] += 1;
    }
    Outcome {
        synced: events.synced,
        compact_targets: compact_targets.len(),
        served,
        served_checks: events.served_checks,
        joiner_checks: events.joiner_checks,
        served_lags: events.served_lags.clone(),
    }
}

/// The validator that joins late and state-syncs.
const JOINER: usize = 0;

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
    let delay_round = delay_first(&engine.participants(), 40);
    PlanBuilder::new(engine)
        .seed(seed)
        .crash(delay_round)
        .timeout(Duration::from_secs(120))
        .exit_condition(SyncedOrBound {
            log: log.clone(),
            joiner: JOINER,
            bound,
        })
        .run()
        .unwrap();
    summarize(&log)
}

/// Every node serves each finalized block's compact state before the next block applies, for a
/// mixed set as for an all-compact one, even while barriers span several blocks.
///
/// A compact member serves only the tips it published. A mixed set that published only when a
/// barrier starts would leave its compact member behind for the whole barrier. Checks cover
/// servers and a joiner's state-sync handoff alike, so the joiner must converge: a 250 ms barrier
/// with a window of 8 spans several blocks while servers still keep pace (see
/// [`late_joiner_converges`]).
#[test_group("slow")]
#[test]
fn cheap_members_serve_every_finalized_block() {
    let delay = Duration::from_millis(250);
    let mut joiner_checks = 0;
    for seed in [3u64, 4] {
        for (layout, outcome) in [
            ("all-compact", run::<AllCompact>(delay, 8, seed, BOUND)),
            ("mixed", run::<Mixed>(delay, 8, seed, BOUND)),
        ] {
            assert!(
                outcome.served_checks > 0,
                "{layout} made no checks (seed {seed})"
            );
            assert!(
                outcome.served_lags.is_empty(),
                "{layout} served a stale compact state (seed {seed}): {outcome:?}"
            );
            joiner_checks += outcome.joiner_checks;
        }
    }
    assert!(joiner_checks > 0, "no joiner reached its handoff");
}

/// Blocks servers may finalize past a joiner's sync start before it must have converged.
const BOUND: u64 = 60;

/// A late joiner converges, with answers for both members, for a mixed set as for an all-compact
/// one, even when barriers span several blocks.
///
/// The joiner must finish before servers finalize [`BOUND`] blocks past the height it started
/// syncing from. A server applies at most an acknowledgement window of blocks per barrier, so once
/// a barrier lasts about that many block intervals every server trails a joiner's targets and it
/// converges only by chance, for any layout (a 250 ms barrier with a window of 4 is at that edge
/// here). The combinations stay clear of it.
#[test_group("slow")]
#[test]
fn late_joiner_converges() {
    for (delay_ms, max_pending_acks) in [(0, 2), (100, 4), (250, 8)] {
        let delay = Duration::from_millis(delay_ms);
        for seed in [3u64, 4] {
            for (layout, outcome) in [
                (
                    "all-compact",
                    run::<AllCompact>(delay, max_pending_acks, seed, BOUND),
                ),
                ("mixed", run::<Mixed>(delay, max_pending_acks, seed, BOUND)),
            ] {
                let case = format!(
                    "{layout} delay={delay_ms}ms window={max_pending_acks} seed={seed}: {outcome:?}"
                );
                assert!(outcome.synced.is_some(), "joiner did not converge ({case})");
                assert!(
                    outcome.compact_targets > 0,
                    "joiner requested nothing ({case})"
                );
                assert!(
                    outcome.served.iter().all(|served| *served > 0),
                    "a member got no answers ({case})"
                );
            }
        }
    }
}

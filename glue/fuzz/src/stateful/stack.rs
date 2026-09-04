//! Construction of one engine: channels, broadcast, archives, marshal, the
//! stateful actor, QMDB, and the Simplex engine.
//!
//! An engine is spawned as a single supervised task. Every actor it starts is a
//! descendant of that task, so aborting the task crashes the whole node at
//! once, and rebuilding it on the same storage partitions is a restart.

use super::{
    Ctx, Databases, EPOCH_LENGTH, IO_BUFFER_SIZE, MAILBOX_SIZE, PAGE_CACHE_SIZE, PAGE_SIZE,
    PublicKey, QMDB_INIT_BUFFER, QMDB_INIT_CACHE, Qmdb, Scheme,
    app::Block,
    invariants::{EngineObservations, ObservingReporter},
};
use commonware_broadcast::buffered;
use commonware_consensus::{
    marshal::{
        self,
        core::Actor as MarshalActor,
        resolver::p2p as marshal_resolver,
        standard::{Deferred, Standard},
    },
    simplex::{
        self,
        config::{ForwardPolicy, SkipPolicy},
        elector,
        elector::RoundRobin,
    },
    types::{Epoch, FixedEpocher, TermLength, ViewDelta},
};
use commonware_cryptography::{Digestible, Sha256, certificate::ConstantProvider};
use commonware_glue::stateful::{
    Application, Config as StatefulConfig, Stateful as StatefulActor, SyncPlan,
    db::{SyncEngineConfig, p2p as qmdb_resolver},
};
use commonware_p2p::{
    Receiver as ReceiverTrait, Sender as SenderTrait,
    simulated::{Oracle, Receiver, Sender},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Handle, Quota, Spawner, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    archive::prunable,
    journal::contiguous::fixed::Config as FixedLogConfig,
    mmr::{self, full::Config as MmrJournalConfig},
    qmdb::any::FixedConfig,
    translator::TwoCap,
};
use commonware_utils::{NZU64, NZUsize};
use std::{
    num::{NonZeroU32, NonZeroU64},
    time::Duration,
};

/// Rate limit applied to every simulated channel.
pub(super) const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

/// Channel ids. Each identity registers all six; the compromised identity's
/// are split before they reach an engine.
pub(super) const CHANNEL_VOTE: u64 = 0;
pub(super) const CHANNEL_CERTIFICATE: u64 = 1;
pub(super) const CHANNEL_SIMPLEX_RESOLVER: u64 = 2;
pub(super) const CHANNEL_BACKFILL: u64 = 3;
pub(super) const CHANNEL_BROADCAST: u64 = 4;
pub(super) const CHANNEL_DATABASE: u64 = 5;

const LEADER_TIMEOUT: Duration = Duration::from_millis(250);
const CERTIFICATION_TIMEOUT: Duration = Duration::from_millis(500);
const TIMEOUT_RETRY: Duration = Duration::from_millis(250);
const FETCH_TIMEOUT: Duration = Duration::from_millis(500);
const SKIP_TIMEOUT: Duration = Duration::from_secs(2);
const RESOLVER_TIMEOUT: Duration = Duration::from_millis(500);
const RESOLVER_RETRY: Duration = Duration::from_millis(100);
const VIEW_RETENTION: ViewDelta = ViewDelta::new(10);
const MAX_PENDING_ACKS: std::num::NonZeroUsize = NZUsize!(2);

/// How long a stable leader may stall before its term is abandoned.
const TERM_STALL_TIMEOUT: Duration = Duration::from_secs(3);

/// Items per storage blob and per archive section.
const MERKLE_BLOB_ITEMS: NonZeroU64 = NZU64!(11);
const LOG_BLOB_ITEMS: NonZeroU64 = NZU64!(7);
const SECTION_ITEMS: NonZeroU64 = NZU64!(10);

/// What an engine needs of a leader-election configuration.
pub(super) trait ElectorConfig:
    elector::Config<Scheme> + Clone + Send + Sync + 'static
{
}

impl<T> ElectorConfig for T where T: elector::Config<Scheme> + Clone + Send + Sync + 'static {}

/// The fallback elector, built for the run's term length so that the elector and
/// the channel split agree on where each term begins.
pub(super) fn round_robin(term_length: TermLength) -> RoundRobin<Sha256> {
    if term_length.get() == 1 {
        RoundRobin::default()
    } else {
        RoundRobin::default().with_term(term_length, TERM_STALL_TIMEOUT, ViewDelta::zero())
    }
}

/// State-sync tuning. No node attaches a finalized floor, so the sync engines
/// are never entered; the configuration is still required to build the actor.
const SYNC_CONFIG: SyncEngineConfig = SyncEngineConfig {
    fetch_batch_size: NZU64!(16),
    apply_batch_size: NZU64!(64),
    max_outstanding_requests: 8,
    update_channel_size: NZUsize!(256),
    max_retained_roots: 8,
};

/// The QMDB configuration every engine uses.
fn qmdb_config(prefix: &str, page_cache: CacheRef) -> FixedConfig<TwoCap, Sequential> {
    FixedConfig {
        merkle_config: MmrJournalConfig {
            journal_partition: format!("{prefix}-qmdb-mmr-journal"),
            metadata_partition: format!("{prefix}-qmdb-mmr-metadata"),
            items_per_blob: MERKLE_BLOB_ITEMS,
            write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: FixedLogConfig {
            partition: format!("{prefix}-qmdb-log-journal"),
            items_per_blob: LOG_BLOB_ITEMS,
            page_cache,
            write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
        },
        translator: TwoCap,
        init_cache_size: Some(QMDB_INIT_CACHE),
        init_buffer: QMDB_INIT_BUFFER,
        init_concurrency: (),
    }
}

/// Prunable archive configuration for marshal's finalization and block stores.
fn archive_config<C>(
    prefix: &str,
    name: &str,
    page_cache: CacheRef,
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
        items_per_section: SECTION_ITEMS,
        key_write_buffer: IO_BUFFER_SIZE,
        value_write_buffer: IO_BUFFER_SIZE,
        replay_buffer: IO_BUFFER_SIZE,
    }
}

/// An unsplit simulated channel endpoint.
type Endpoint = (
    Sender<PublicKey, deterministic::Context>,
    Receiver<PublicKey>,
);

/// The channels a correct identity's single engine owns, none of them split.
pub(super) type WholeChannels = EngineChannels<
    Sender<PublicKey, deterministic::Context>,
    Sender<PublicKey, deterministic::Context>,
    Sender<PublicKey, deterministic::Context>,
    Sender<PublicKey, deterministic::Context>,
    Sender<PublicKey, deterministic::Context>,
>;

/// The six channel endpoints one engine owns.
pub(super) struct EngineChannels<VS, CS, RS, BS, FS> {
    pub(super) vote: (VS, Receiver<PublicKey>),
    pub(super) certificate: (CS, Receiver<PublicKey>),
    pub(super) simplex_resolver: (RS, Receiver<PublicKey>),
    pub(super) broadcast: (BS, Receiver<PublicKey>),
    pub(super) backfill: (FS, Receiver<PublicKey>),
    pub(super) database: Endpoint,
}

/// Everything one engine needs, so a restart can rebuild it unchanged.
pub(super) struct EngineConfig<A, EC> {
    pub(super) identity: PublicKey,
    pub(super) scheme: Scheme,
    pub(super) elector: EC,
    pub(super) genesis: Block,
    pub(super) partition_prefix: String,
    pub(super) application: A,
    pub(super) observations: EngineObservations,
}

/// Spawn one engine as a supervised task.
///
/// The task never returns, so the whole node stays alive until the handle is
/// aborted; aborting it takes every descendant actor down with it.
pub(super) fn spawn_engine<A, EC, VS, CS, RS, BS, FS>(
    context: deterministic::Context,
    oracle: Oracle<PublicKey, deterministic::Context>,
    config: EngineConfig<A, EC>,
    channels: EngineChannels<VS, CS, RS, BS, FS>,
) -> Handle<()>
where
    A: Application<
            deterministic::Context,
            SigningScheme = Scheme,
            Context = Ctx,
            Block = Block,
            Databases = Databases,
            Provider = (),
            Input = (),
        >,
    VS: SenderTrait<PublicKey = PublicKey>,
    CS: SenderTrait<PublicKey = PublicKey>,
    RS: SenderTrait<PublicKey = PublicKey>,
    BS: SenderTrait<PublicKey = PublicKey>,
    FS: SenderTrait<PublicKey = PublicKey>,
    EC: ElectorConfig,
{
    context.spawn(move |context| async move {
        run_engine(context, oracle, config, channels).await;
    })
}

async fn run_engine<A, EC, VS, CS, RS, BS, FS>(
    context: deterministic::Context,
    oracle: Oracle<PublicKey, deterministic::Context>,
    config: EngineConfig<A, EC>,
    channels: EngineChannels<VS, CS, RS, BS, FS>,
) where
    A: Application<
            deterministic::Context,
            SigningScheme = Scheme,
            Context = Ctx,
            Block = Block,
            Databases = Databases,
            Provider = (),
            Input = (),
        >,
    VS: SenderTrait<PublicKey = PublicKey>,
    CS: SenderTrait<PublicKey = PublicKey>,
    RS: SenderTrait<PublicKey = PublicKey>,
    BS: SenderTrait<PublicKey = PublicKey>,
    FS: SenderTrait<PublicKey = PublicKey>,
    EC: ElectorConfig,
{
    let EngineConfig {
        identity,
        scheme,
        elector,
        genesis,
        partition_prefix,
        application,
        observations,
    } = config;
    let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
    let db_config = qmdb_config(&partition_prefix, page_cache.clone());
    let provider = ConstantProvider::new(scheme.clone());

    // Marshal's backfill resolver.
    let resolver = marshal_resolver::init(
        context.child("marshal_resolver"),
        marshal_resolver::Config {
            public_key: identity.clone(),
            peer_provider: oracle.manager(),
            blocker: oracle.control(identity.clone()),
            mailbox_size: MAILBOX_SIZE,
            timeout: RESOLVER_TIMEOUT,
            fetch_retry_timeout: RESOLVER_RETRY,
            priority_requests: false,
            priority_responses: false,
        },
        channels.backfill,
    );

    // Block broadcast.
    let (broadcast_engine, buffer) = buffered::Engine::new(
        context.child("broadcast"),
        buffered::Config {
            public_key: identity.clone(),
            mailbox_size: MAILBOX_SIZE,
            deque_size: 10,
            priority: false,
            codec_config: (),
            peer_provider: oracle.manager(),
        },
    );
    broadcast_engine.start(channels.broadcast);

    // Marshal archives.
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

    // No finalized floor is ever attached, so startup is marshal reconciliation
    // and peer state sync is never entered.
    let startup = context.child("stateful_startup");
    let plan = SyncPlan::init(&startup, partition_prefix.clone()).await;

    let (marshal_actor, marshal_mailbox, floor) =
        MarshalActor::<_, Standard<Block>, _, _, _, _, _>::init(
            context.child("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider,
                epocher: FixedEpocher::new(EPOCH_LENGTH),
                start: plan.marshal_start(genesis.clone()),
                partition_prefix: partition_prefix.clone(),
                mailbox_size: MAILBOX_SIZE,
                view_retention: VIEW_RETENTION,
                prunable_items_per_section: SECTION_ITEMS,
                page_cache: page_cache.clone(),
                replay_buffer: IO_BUFFER_SIZE,
                key_write_buffer: IO_BUFFER_SIZE,
                value_write_buffer: IO_BUFFER_SIZE,
                block_codec_config: (),
                max_repair: NZUsize!(10),
                max_pending_acks: MAX_PENDING_ACKS,
                strategy: Sequential,
            },
        )
        .await;

    // Database sync resolver. It never fetches because no node state syncs, but
    // the stateful actor requires one and it serves peers once attached.
    let (database_resolver, database_sync) =
        qmdb_resolver::Actor::<_, PublicKey, _, _, mmr::Family, Qmdb>::new(
            context.child("database_resolver"),
            qmdb_resolver::Config {
                peer_provider: oracle.manager(),
                blocker: oracle.control(identity.clone()),
                database: None,
                mailbox_size: MAILBOX_SIZE,
                me: Some(identity.clone()),
                timeout: RESOLVER_TIMEOUT,
                fetch_retry_timeout: RESOLVER_RETRY,
                max_serve_ops: NZU64!(16),
                priority_requests: false,
                priority_responses: false,
            },
        );
    database_resolver.start(channels.database);

    let (stateful_actor, stateful_mailbox) = StatefulActor::init(
        context.child("stateful"),
        StatefulConfig {
            application,
            db_config,
            provider: (),
            marshal: (marshal_mailbox.clone(), floor),
            mailbox_size: MAILBOX_SIZE,
            plan,
            resolvers: database_sync,
            sync_config: SYNC_CONFIG,
            prune_config: None,
        },
    );

    let deferred = Deferred::new(
        context.child("deferred"),
        stateful_mailbox.clone(),
        marshal_mailbox.clone(),
        FixedEpocher::new(EPOCH_LENGTH),
    );

    marshal_actor.start(
        ObservingReporter::new(observations, stateful_mailbox),
        buffer,
        resolver,
    );
    stateful_actor.start();

    let engine = simplex::Engine::new(
        context.child("engine"),
        simplex::Config {
            scheme,
            elector,
            blocker: oracle.control(identity),
            automaton: deferred.clone(),
            relay: deferred,
            reporter: marshal_mailbox,
            strategy: Sequential,
            partition: format!("{partition_prefix}-simplex"),
            mailbox_size: MAILBOX_SIZE,
            epoch: Epoch::zero(),
            floor: simplex::config::Floor::Genesis(genesis.digest()),
            replay_buffer: IO_BUFFER_SIZE,
            write_buffer: IO_BUFFER_SIZE,
            page_cache,
            leader_timeout: LEADER_TIMEOUT,
            certification_timeout: CERTIFICATION_TIMEOUT,
            timeout_retry: TIMEOUT_RETRY,
            view_retention: VIEW_RETENTION,
            skip: SkipPolicy::Enabled {
                timeout: SKIP_TIMEOUT,
                budget: simplex::SkipBudget::Participants,
            },
            fetch_timeout: FETCH_TIMEOUT,
            forward: ForwardPolicy::Disabled,
            track_historical_votes: false,
        },
    );
    engine.start(
        channels.vote,
        channels.certificate,
        channels.simplex_resolver,
    );

    // Park so the supervised subtree stays alive until the node is crashed.
    std::future::pending::<()>().await
}

/// Register one identity's six channels.
pub(super) async fn register_channels(
    oracle: &Oracle<PublicKey, deterministic::Context>,
    identity: &PublicKey,
) -> RawChannels {
    let control = oracle.control(identity.clone());
    let register = async |channel| {
        control
            .register(channel, TEST_QUOTA)
            .await
            .expect("channel registration failed")
    };
    RawChannels {
        vote: register(CHANNEL_VOTE).await,
        certificate: register(CHANNEL_CERTIFICATE).await,
        simplex_resolver: register(CHANNEL_SIMPLEX_RESOLVER).await,
        backfill: register(CHANNEL_BACKFILL).await,
        broadcast: register(CHANNEL_BROADCAST).await,
        database: register(CHANNEL_DATABASE).await,
    }
}

/// One identity's unsplit channel endpoints.
pub(super) struct RawChannels {
    pub(super) vote: Endpoint,
    pub(super) certificate: Endpoint,
    pub(super) simplex_resolver: Endpoint,
    pub(super) backfill: Endpoint,
    pub(super) broadcast: Endpoint,
    pub(super) database: Endpoint,
}

impl RawChannels {
    /// Hand a correct identity's channels to its single engine unchanged.
    pub(super) fn whole(self) -> WholeChannels {
        EngineChannels {
            vote: self.vote,
            certificate: self.certificate,
            simplex_resolver: self.simplex_resolver,
            backfill: self.backfill,
            broadcast: self.broadcast,
            database: self.database,
        }
    }
}

/// Assert the receiver trait is in scope for both channel shapes.
const _: fn() = || {
    fn assert_receiver<R: ReceiverTrait<PublicKey = PublicKey>>() {}
    assert_receiver::<Receiver<PublicKey>>();
};

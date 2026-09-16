//! Construction of one engine: channels, dissemination, archives, marshal, the
//! stateful actor, QMDB, and the Simplex engine.
//!
//! An engine is spawned as a single supervised task. Every actor it starts is a
//! descendant of that task, so aborting the task crashes the whole node at
//! once, and rebuilding it on the same storage partitions is a restart.
//!
//! The marshal variant selects dissemination, the marshal actor's block type,
//! and the wrapper Simplex drives; the stateful actor's mailbox is erased
//! before it reaches that wrapper, so everything above the stateful actor is
//! monomorphized once per variant rather than once per backend.
//!
//! An engine may request peer state sync at startup. The startup plan decides
//! whether that request is honoured: a fresh node discovers a finalized floor
//! through its probe and syncs from it, an interrupted sync resumes from its
//! persisted floor, and a node whose sync completed ignores the request and
//! recovers through marshal instead. Every engine serves floors to probing
//! peers once its marshal is attached.

use super::{
    Ctx, EPOCH_LENGTH, IO_BUFFER_SIZE, MAILBOX_SIZE, PAGE_CACHE_SIZE, PAGE_SIZE, PublicKey, Scheme,
    app::Block,
    backend::{Backend, Databases},
    invariants::{EngineObservations, ObservingReporter, Startup},
    marshal::{ErasedApplication, ErasedReporter, Marshal},
};
use commonware_consensus::{
    marshal::{
        self,
        ancestry::BlockProvider,
        core::{Actor as MarshalActor, Mailbox as MarshalMailbox},
        resolver::p2p as marshal_resolver,
    },
    simplex::{
        self,
        config::{ForwardPolicy, SkipPolicy},
        elector,
        elector::RoundRobin,
    },
    types::{Epoch, FixedEpocher, TermLength, ViewDelta},
};
use commonware_cryptography::{Sha256, certificate::ConstantProvider};
use commonware_glue::stateful::{
    Application, Config as StatefulConfig, PruneConfig, Stateful as StatefulActor, SyncPlan,
    db::{SyncEngineConfig, p2p as qmdb_resolver},
    probe::{Config as ProbeConfig, Probe},
};
use commonware_p2p::{
    Receiver as ReceiverTrait, Sender as SenderTrait,
    simulated::{Oracle, Receiver, Sender},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Handle, Quota, Spawner, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{archive::prunable, mmr, translator::TwoCap};
use commonware_utils::{NZDuration, NZU64, NZUsize};
use std::{
    num::{NonZeroU32, NonZeroU64},
    time::Duration,
};

/// Rate limit applied to every simulated channel.
pub(super) const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

/// Channel ids. Each identity registers all seven; the compromised identity's
/// are split before they reach an engine.
pub(super) const CHANNEL_VOTE: u64 = 0;
pub(super) const CHANNEL_CERTIFICATE: u64 = 1;
pub(super) const CHANNEL_SIMPLEX_RESOLVER: u64 = 2;
pub(super) const CHANNEL_BACKFILL: u64 = 3;
pub(super) const CHANNEL_BROADCAST: u64 = 4;
pub(super) const CHANNEL_DATABASE: u64 = 5;
pub(super) const CHANNEL_PROBE: u64 = 6;

const LEADER_TIMEOUT: Duration = Duration::from_millis(250);
const CERTIFICATION_TIMEOUT: Duration = Duration::from_millis(500);
const TIMEOUT_RETRY: Duration = Duration::from_millis(250);
const FETCH_TIMEOUT: Duration = Duration::from_millis(500);
const SKIP_TIMEOUT: Duration = Duration::from_secs(2);
const RESOLVER_TIMEOUT: Duration = Duration::from_millis(500);
const RESOLVER_RETRY: Duration = Duration::from_millis(100);
const PROBE_RETRY: Duration = Duration::from_millis(500);
const VIEW_RETENTION: ViewDelta = ViewDelta::new(10);

/// Finalized blocks marshal may hold unacknowledged. Pruning retains this
/// many blocks plus one behind the newest finalized height before any
/// configured retention.
pub(super) const MAX_PENDING_ACKS: std::num::NonZeroUsize = NZUsize!(2);

/// How long a stable leader may stall before its term is abandoned.
const TERM_STALL_TIMEOUT: Duration = Duration::from_secs(3);

/// Items per archive section.
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

/// State-sync tuning for the drivers whose nodes never attach a finalized
/// floor: the sync engines are never entered there, but the configuration is
/// still required to build the actor.
pub(super) const SYNC_CONFIG: SyncEngineConfig = SyncEngineConfig {
    fetch_batch_size: NZU64!(16),
    apply_batch_size: NZU64!(64),
    max_outstanding_requests: 8,
    update_channel_size: NZUsize!(256),
    max_retained_roots: 8,
};

/// Prunable archive configuration for marshal's finalization and block stores.
pub(super) fn archive_config<C>(
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

/// The channel endpoints one engine owns. An engine without a probe channel
/// neither discovers nor serves finalized floors.
pub(super) struct EngineChannels<VS, CS, RS, BS, FS> {
    pub(super) vote: (VS, Receiver<PublicKey>),
    pub(super) certificate: (CS, Receiver<PublicKey>),
    pub(super) simplex_resolver: (RS, Receiver<PublicKey>),
    pub(super) broadcast: (BS, Receiver<PublicKey>),
    pub(super) backfill: (FS, Receiver<PublicKey>),
    pub(super) database: Endpoint,
    pub(super) probe: Option<Endpoint>,
}

/// Everything one engine needs, so a restart can rebuild it unchanged.
pub(super) struct EngineConfig<M: Marshal, A, EC> {
    pub(super) identity: PublicKey,
    pub(super) scheme: Scheme,
    pub(super) elector: EC,
    pub(super) genesis: Block<M>,
    pub(super) partition_prefix: String,
    pub(super) application: A,
    pub(super) observations: EngineObservations,
    /// Periodic marshal and database pruning, or none.
    pub(super) prune: Option<PruneConfig>,
    /// Sync engine tuning.
    pub(super) sync: SyncEngineConfig,
    /// Request peer state sync at startup. Requires a probe channel.
    pub(super) state_sync: bool,
}

/// Spawn one engine as a supervised task.
///
/// The task never returns, so the whole node stays alive until the handle is
/// aborted; aborting it takes every descendant actor down with it.
pub(super) fn spawn_engine<B, M, A, EC, VS, CS, RS, BS, FS>(
    context: deterministic::Context,
    oracle: Oracle<PublicKey, deterministic::Context>,
    config: EngineConfig<M, A, EC>,
    channels: EngineChannels<VS, CS, RS, BS, FS>,
) -> Handle<()>
where
    B: Backend,
    M: Marshal,
    MarshalMailbox<Scheme, M::Variant>: BlockProvider<Block = Block<M>>,
    A: Application<
            deterministic::Context,
            SigningScheme = Scheme,
            Context = Ctx<M>,
            Block = Block<M>,
            Databases = Databases<B>,
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
        run_engine::<B, M, _, _, _, _, _, _, _>(context, oracle, config, channels).await;
    })
}

async fn run_engine<B, M, A, EC, VS, CS, RS, BS, FS>(
    context: deterministic::Context,
    oracle: Oracle<PublicKey, deterministic::Context>,
    config: EngineConfig<M, A, EC>,
    channels: EngineChannels<VS, CS, RS, BS, FS>,
) where
    B: Backend,
    M: Marshal,
    MarshalMailbox<Scheme, M::Variant>: BlockProvider<Block = Block<M>>,
    A: Application<
            deterministic::Context,
            SigningScheme = Scheme,
            Context = Ctx<M>,
            Block = Block<M>,
            Databases = Databases<B>,
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
        prune,
        sync,
        state_sync,
    } = config;
    let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
    let db_config = B::config(&partition_prefix, page_cache.clone());
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

    // Block dissemination: buffered broadcast or shards, per the variant.
    let buffer = M::start_dissemination(
        context.child("broadcast"),
        &oracle,
        identity.clone(),
        provider.clone(),
        channels.broadcast,
    );

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

    // The startup plan decides between marshal reconciliation and peer state
    // sync. A node that syncs discovers its floor through its probe first.
    let startup = context.child("stateful_startup");
    let mut plan = SyncPlan::init(&startup, partition_prefix.clone()).await;
    let should_state_sync = plan.should_state_sync(state_sync);
    assert!(
        !should_state_sync || channels.probe.is_some(),
        "an engine requesting state sync must own a probe channel"
    );
    let probe = channels.probe.map(|channel| {
        let (probe, mailbox) = Probe::<_, _, _, M::Variant, _, _, _>::new(ProbeConfig {
            context: context.child("probe"),
            provider: provider.clone(),
            strategy: Sequential,
            capacity: MAILBOX_SIZE,
            blocker: oracle.control(identity.clone()),
            minimum_epoch: Epoch::zero(),
            retry_timeout: NZDuration!(PROBE_RETRY),
        });
        probe.start(channel);
        mailbox
    });
    let mut floor_round = None;
    if should_state_sync {
        let floor = probe
            .as_ref()
            .expect("checked above")
            .subscribe()
            .await
            .expect("probe stopped before a floor was discovered");
        floor_round = Some(floor.round());
        plan = plan.with_floor(floor);
    }
    observations.note_startup(Startup {
        requested: state_sync,
        should_sync: should_state_sync,
        resumed: plan.requires_state_sync_floor(),
        sync_height: plan.sync_height(),
        floor_round: plan.floor().map(|floor| floor.round()).or(floor_round),
    });

    let (marshal_actor, marshal_mailbox, floor) =
        MarshalActor::<_, M::Variant, _, _, _, _, _>::init(
            context.child("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider: provider.clone(),
                epocher: FixedEpocher::new(EPOCH_LENGTH),
                start: plan.marshal_start(M::stored_genesis(&genesis)),
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

    // Database sync resolver: fetches during state sync and serves peers once
    // the stateful actor attaches the database.
    let (database_resolver, database_sync) =
        qmdb_resolver::Actor::<_, PublicKey, _, _, mmr::Family, B::Db>::new(
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
            sync_config: sync,
            prune_config: prune,
        },
    );

    // Consensus sees the stateful mailbox only through the erased application
    // and reporter, so nothing above this point varies with the backend.
    let automaton = M::automaton(
        context.child("automaton"),
        ErasedApplication::new(stateful_mailbox.clone()),
        marshal_mailbox.clone(),
        buffer.clone(),
        provider,
    );

    marshal_actor.start(
        ObservingReporter::new(observations, ErasedReporter::<M>::new(stateful_mailbox)),
        buffer,
        resolver,
    );
    // A syncing node consumed its floor above; every node serves floors from
    // here on.
    if let Some(probe) = probe {
        probe.attach(marshal_mailbox.clone());
    }
    stateful_actor.start();

    let engine = simplex::Engine::new(
        context.child("engine"),
        simplex::Config {
            scheme,
            elector,
            blocker: oracle.control(identity),
            automaton: automaton.clone(),
            relay: automaton,
            reporter: marshal_mailbox,
            strategy: Sequential,
            partition: format!("{partition_prefix}-simplex"),
            mailbox_size: MAILBOX_SIZE,
            epoch: Epoch::zero(),
            floor: simplex::config::Floor::Genesis(M::genesis_payload(&genesis)),
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

/// Register one identity's seven channels.
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
        probe: register(CHANNEL_PROBE).await,
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
    pub(super) probe: Endpoint,
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
            probe: Some(self.probe),
        }
    }
}

/// Assert the receiver trait is in scope for both channel shapes.
const _: fn() = || {
    fn assert_receiver<R: ReceiverTrait<PublicKey = PublicKey>>() {}
    assert_receiver::<Receiver<PublicKey>>();
};

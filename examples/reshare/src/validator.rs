//! `validator` subcommand: run a validator node.

use crate::{
    application::App,
    config::{NetworkConfig, NodeConfig},
    types::{
        self, AGGREGATION_ACK_CHANNEL, AGGREGATION_ACTIVE_EPOCHS, AGGREGATION_RECOVERY_CHANNEL,
        AggregationScheme, BACKFILL_CHANNEL, BLOCKS_PER_EPOCH, BROADCAST_CHANNEL, Block,
        CERTIFICATE_CHANNEL, DKG_CHANNEL, DKG_PROBE_CHANNEL, DynamicProvider, FileSecretStore,
        IO_BUFFER_SIZE, LogReporter, MAILBOX_SIZE, MAX_MESSAGE_SIZE, MAX_PARTICIPANTS,
        MAX_SUPPORTED_MODE, MESSAGE_RATE, NAMESPACE, PAGE_CACHE_SIZE, PAGE_SIZE, Participants,
        QMDB_CHANNEL, RESOLVER_CHANNEL, REVEAL, Registrar, RetainedSecretStore, SHARING_MODE,
        Scheme, VOTE_CHANNEL,
    },
};
use clap::Args;
use commonware_broadcast::buffered;
use commonware_consensus::{
    Reporters,
    aggregation::RecoveryCoordinator,
    marshal::{
        self, core::Actor as MarshalActor, resolver::p2p as marshal_resolver, standard::Deferred,
    },
    simplex::{
        SkipBudget,
        config::{ForwardPolicy, SkipPolicy},
        elector::RoundRobin,
    },
    types::{Epoch, FixedEpocher, ViewDelta},
};
use commonware_cryptography::{
    certificate::Provider as _,
    ed25519,
    sha256::{Digest as Sha256Digest, Sha256},
};
use commonware_glue::{
    dkg::{
        SecretStore as _,
        fence::Fence,
        orchestrator, probe, reshare,
        state_sync::{Config as StateSyncConfig, Plan as StateSyncPlan, StateSync},
    },
    stateful::{
        Config as StatefulConfig, Stateful, SyncPlan,
        db::{DatabaseSet, p2p as qmdb_resolver},
    },
};
use commonware_macros::boxed;
use commonware_p2p::{
    authenticated::{self, discovery},
    utils::mux::Muxer,
};
use commonware_parallel::Sequential;
use commonware_resolver::p2p as aggregation_resolver;
use commonware_runtime::{Handle, Spawner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_storage::{
    archive::{immutable, prunable},
    metadata,
    translator::TwoCap,
};
use commonware_utils::{NZDuration, NZU64, NZUsize, acknowledgement::Exact, sequence::Unit};
use std::{marker::PhantomData, num::NonZeroUsize, path::PathBuf, time::Duration};
use tracing::error;

/// Start a validator node.
#[derive(Args)]
pub struct Validator {
    /// Validator node directory containing config, genesis, secrets, and runtime storage.
    #[arg(long, default_value = "./data/validator-0")]
    pub node_dir: PathBuf,

    /// Run one-time peer state sync for a new late joiner.
    #[arg(long, default_value_t = false)]
    pub state_sync: bool,
}

/// Start every validator actor and run until one stops.
#[boxed]
pub async fn run(context: tokio::Context, args: Validator) {
    let node = NodeConfig::load(&args.node_dir).expect("failed to load node config");
    let network = NetworkConfig::load(&args.node_dir).expect("failed to load network config");
    network.validate().expect("invalid network config");
    let genesis_info = types::read_genesis(&args.node_dir).expect("genesis is required");
    let participants = Participants::new(&network).expect("invalid participants");
    let local = node.public_key();
    let partition_prefix = "validator";
    let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
    let bootstrappers = network.bootstrappers(&local);
    let max_peers_per_set = authenticated::peer_set_limit(&network.participants, &local);

    let mut p2p_config = discovery::Config::local(
        node.signing_key.clone(),
        &[NAMESPACE, b"_P2P"].concat(),
        node.listen,
        node.dial,
        bootstrappers,
        max_peers_per_set,
        MAX_MESSAGE_SIZE,
    );
    p2p_config.mailbox_size = MAILBOX_SIZE;
    p2p_config.tracked_peer_sets = AGGREGATION_ACTIVE_EPOCHS;
    let (mut p2p, oracle) = discovery::Network::new(context.child("network"), p2p_config);

    // Channel rates are enforced independently per peer. The network derives each shared inbound
    // mailbox capacity from the retained-peer bound and quota burst size.
    let vote_network = p2p.register(VOTE_CHANNEL, MESSAGE_RATE);
    let certificate_network = p2p.register(CERTIFICATE_CHANNEL, MESSAGE_RATE);
    let resolver_network = p2p.register(RESOLVER_CHANNEL, MESSAGE_RATE);
    let backfill_network = p2p.register(BACKFILL_CHANNEL, MESSAGE_RATE);
    let broadcast_network = p2p.register(BROADCAST_CHANNEL, MESSAGE_RATE);
    let qmdb_network = p2p.register(QMDB_CHANNEL, MESSAGE_RATE);
    let dkg_network = p2p.register(DKG_CHANNEL, MESSAGE_RATE);
    let dkg_probe_network = p2p.register(DKG_PROBE_CHANNEL, MESSAGE_RATE);
    let aggregation_ack_network = p2p.register(AGGREGATION_ACK_CHANNEL, MESSAGE_RATE);
    let aggregation_recovery_network = p2p.register(AGGREGATION_RECOVERY_CHANNEL, MESSAGE_RATE);
    let p2p_handle = p2p.start();

    let provider = DynamicProvider::default();
    let store = FileSecretStore::load(args.node_dir.join("secrets.json"))
        .expect("failed to load secret store");
    let aggregation_provider = DynamicProvider::<AggregationScheme>::load(store.clone())
        .expect("failed to load aggregation epochs");
    let mut store_for_genesis = store.clone();
    if let Some(share) = store_for_genesis.get_share(Epoch::zero()).await {
        aggregation_provider
            .register_authenticated(
                Epoch::zero(),
                genesis_info.output.players().clone(),
                genesis_info.output.public().clone(),
                Some(share.clone()),
            )
            .expect("failed to persist epoch-0 aggregation scheme");
        provider.register(
            Epoch::zero(),
            Scheme::signer(
                NAMESPACE,
                types::committee(genesis_info.output.players()),
                genesis_info.output.public().clone(),
                share,
            )
            .expect("epoch-0 share must match genesis"),
        );
    } else {
        aggregation_provider
            .register_authenticated(
                Epoch::zero(),
                genesis_info.output.players().clone(),
                genesis_info.output.public().clone(),
                None,
            )
            .expect("failed to persist epoch-0 aggregation scheme");
        provider.register(
            Epoch::zero(),
            Scheme::verifier(
                NAMESPACE,
                types::committee(genesis_info.output.players()),
                genesis_info.output.public().clone(),
            )
            .expect("genesis threshold committee must be uniform"),
        );
    }

    let aggregation_scheme = aggregation_provider
        .scheme(Epoch::zero())
        .expect("genesis aggregation scheme");
    let aggregation_namespace =
        <AggregationScheme as commonware_consensus::aggregation::scheme::Scheme<
            Sha256Digest,
        >>::recovery_namespace(&aggregation_scheme);
    let (history_actor, history) =
        orchestrator::aggregation::Actor::<_, AggregationScheme, Sha256Digest, _, _>::init(
            context.child("aggregation_history"),
            orchestrator::aggregation::Config {
                namespace: aggregation_namespace,
                archive: immutable_archive_config(
                    partition_prefix,
                    "aggregation_history",
                    page_cache.clone(),
                    (),
                ),
                metadata: metadata::Config {
                    partition: format!("{partition_prefix}-aggregation-retirement"),
                    codec_config: (),
                },
                mailbox_size: MAILBOX_SIZE,
            },
            aggregation_provider.clone(),
            Sequential,
        )
        .await
        .expect("aggregation history");
    let history_task = history_actor.start();
    let history_handle = context
        .child("aggregation_history_supervisor")
        .spawn(|_| async move {
            history_task
                .await
                .expect("aggregation history task")
                .expect("aggregation history failure");
        });

    let (recovery_coordinator, recovery) = RecoveryCoordinator::staged(
        context.child("aggregation_recovery_coordinator"),
        NZUsize!(64),
        MAILBOX_SIZE,
    );
    let (router_actor, router_consumer, router_registry) =
        orchestrator::aggregation_router::Actor::<_, AggregationScheme, Sha256Digest, _, _>::new(
            context.child("aggregation_router"),
            history.clone(),
            aggregation_provider.clone(),
            recovery.clone(),
            MAILBOX_SIZE,
        );
    let router_handle = router_actor.start();
    let (resolver_engine, resolver) = aggregation_resolver::Engine::new_with_all_peers(
        context.child("aggregation_resolver"),
        aggregation_resolver::Config {
            peer_provider: oracle.clone(),
            blocker: oracle.clone(),
            consumer: router_consumer,
            producer: history.clone(),
            mailbox_size: MAILBOX_SIZE,
            me: Some(local.clone()),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(250),
            priority_requests: false,
            priority_responses: false,
        },
    );
    let aggregation_resolver_handle = resolver_engine.start(aggregation_recovery_network);
    let recovery_handle = recovery_coordinator.attach(resolver).start();
    let (aggregation_muxer, aggregation_mux) = Muxer::new(
        context.child("aggregation_ack_mux"),
        aggregation_ack_network.0,
        aggregation_ack_network.1,
        MAILBOX_SIZE.get(),
    );
    let aggregation_muxer_task = aggregation_muxer.start();
    let aggregation_muxer_handle =
        context
            .child("aggregation_ack_mux_supervisor")
            .spawn(|_| async move {
                aggregation_muxer_task
                    .await
                    .expect("aggregation ack mux task")
                    .expect("aggregation ack mux failure");
            });
    let store = RetainedSecretStore::new(
        store,
        history.clone(),
        aggregation_namespace,
        aggregation_provider.clone(),
    );

    let aggregation_window = NZU64!(64);
    let checkpoint_capacity = NonZeroUsize::new(
        AGGREGATION_ACTIVE_EPOCHS
            .get()
            .checked_mul(aggregation_window.get() as usize)
            .expect("aggregation checkpoint capacity overflow"),
    )
    .expect("aggregation checkpoint capacity must be non-zero");
    let (checkpoint_actor, checkpoint_automaton) =
        orchestrator::checkpoints::Actor::<_, Block, Exact>::init(
            context.child("aggregation_checkpoints"),
            orchestrator::checkpoints::Config {
                archive: immutable_archive_config(
                    partition_prefix,
                    "aggregation_checkpoints",
                    page_cache.clone(),
                    (),
                ),
                mailbox_size: MAILBOX_SIZE,
                max_pending_requests: checkpoint_capacity,
            },
        )
        .await
        .expect("aggregation checkpoints");
    let checkpoint_task = checkpoint_actor.start();
    let checkpoint_handle =
        context
            .child("aggregation_checkpoints_supervisor")
            .spawn(|_| async move {
                checkpoint_task
                    .await
                    .expect("aggregation checkpoint task")
                    .expect("aggregation checkpoint failure");
            });

    let resolver = marshal_resolver::init(
        context.child("marshal_resolver"),
        marshal_resolver::Config {
            public_key: local.clone(),
            peer_provider: oracle.clone(),
            blocker: oracle.clone(),
            mailbox_size: MAILBOX_SIZE,
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
            public_key: local.clone(),
            mailbox_size: MAILBOX_SIZE,
            deque_size: 16,
            priority: false,
            codec_config: (),
            peer_provider: oracle.clone(),
        },
    );
    let broadcast_handle = broadcast_engine.start(broadcast_network);

    let finalizations_by_height = prunable::Archive::init(
        context.child("finalizations_by_height"),
        archive_config(partition_prefix, "finalizations", page_cache.clone(), ()),
    )
    .await
    .expect("finalizations archive");
    let finalized_blocks = prunable::Archive::init(
        context.child("finalized_blocks"),
        archive_config(partition_prefix, "blocks", page_cache.clone(), ()),
    )
    .await
    .expect("blocks archive");

    let genesis_target =
        <types::Database<tokio::Context> as DatabaseSet<tokio::Context>>::initial_sync_targets();
    let genesis = Block::genesis(
        network.participants[0].clone(),
        genesis_info.clone(),
        genesis_target,
    );
    let (probe_actor, probe_mailbox) = probe::Actor::new(probe::Config {
        context: context.child("dkg_probe"),
        manager: oracle.clone(),
        bootstrap: probe::Bootstrap {
            epoch: Epoch::zero(),
            participants: genesis_info.participants(),
            directory: Unit,
        },
        verifier: Scheme::certificate_verifier(
            NAMESPACE,
            types::committee(genesis_info.output.players()),
            *genesis_info.output.public().public(),
        )
        .expect("genesis threshold committee must be uniform"),
        genesis: genesis_info.clone(),
        strategy: Sequential,
        blocker: oracle.clone(),
        blocks_per_epoch: BLOCKS_PER_EPOCH,
        retry_timeout: NZDuration!(Duration::from_millis(500)),
        mailbox_size: MAILBOX_SIZE,
        block_codec_config: (),
    });
    let probe_handle = probe_actor.start(dkg_probe_network);

    let stateful_startup = context.child("stateful_startup");
    let mut plan = SyncPlan::init(&stateful_startup, partition_prefix).await;
    let should_state_sync = plan.should_state_sync(args.state_sync);
    let probe_artifact = if should_state_sync {
        let artifact = probe_mailbox.subscribe().await.expect("probe stopped");
        aggregation_provider
            .register_authenticated(
                artifact.info.epoch,
                artifact.info.output.players().clone(),
                artifact.info.output.public().clone(),
                None,
            )
            .expect("failed to persist state-sync aggregation epoch");
        aggregation_provider
            .set_discovery_floor(artifact.info.epoch)
            .expect("failed to persist state-sync aggregation floor");
        provider.register(
            artifact.info.epoch,
            Scheme::verifier(
                NAMESPACE,
                types::committee(artifact.info.output.players()),
                artifact.info.output.public().clone(),
            )
            .expect("reshared threshold committee must be uniform"),
        );
        plan = plan.with_floor(artifact.floor.clone());
        Some(artifact)
    } else {
        None
    };

    let (marshal_actor, marshal, floor) = MarshalActor::init(
        context.child("marshal"),
        finalizations_by_height,
        finalized_blocks,
        marshal::Config {
            provider: provider.clone(),
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            start: plan.marshal_start(genesis.clone()),
            partition_prefix: partition_prefix.to_string(),
            mailbox_size: MAILBOX_SIZE,
            view_retention: ViewDelta::new(10),
            prunable_items_per_section: NZU64!(10),
            page_cache: page_cache.clone(),
            replay_buffer: types::IO_BUFFER_SIZE,
            key_write_buffer: types::IO_BUFFER_SIZE,
            value_write_buffer: types::IO_BUFFER_SIZE,
            block_codec_config: (),
            max_repair: NZUsize!(10),
            max_pending_acks: NZUsize!(1),
            strategy: Sequential,
        },
    )
    .await;

    let (qmdb_actor, qmdb_sync_resolver) = qmdb_resolver::Actor::new(
        context.child("qmdb_resolver"),
        qmdb_resolver::Config {
            peer_provider: oracle.clone(),
            blocker: oracle.clone(),
            database: None,
            mailbox_size: MAILBOX_SIZE,
            me: Some(local.clone()),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            max_serve_ops: NZU64!(16),
            priority_requests: false,
            priority_responses: false,
        },
    );
    let qmdb_handle = qmdb_actor.start(qmdb_network);

    let fence_epoch = probe_artifact
        .as_ref()
        .map_or_else(Epoch::zero, |artifact| artifact.info.epoch);
    let state_sync = probe_artifact.map(|artifact| {
        let floor = plan
            .floor()
            .cloned()
            .expect("state sync startup must have floor");
        StateSync {
            info: artifact.info,
            floor,
        }
    });
    let state_sync = StateSyncPlan::init(
        context.child("dkg_state_sync_plan"),
        StateSyncConfig {
            partition_prefix: partition_prefix.to_string(),
            max_participants: MAX_PARTICIPANTS,
            max_supported_mode: MAX_SUPPORTED_MODE,
        },
        state_sync,
    )
    .await;

    let (fence, gate) = Fence::new(fence_epoch);
    let aggregation_current = aggregation_provider
        .latest_epoch()
        .expect("genesis aggregation epoch");
    let (aggregation_actor, aggregation_mailbox): (
        _,
        orchestrator::aggregation_lifecycle::Handler<Block, Exact>,
    ) = orchestrator::aggregation_lifecycle::Actor::new(
        context.child("aggregation_lifecycle"),
        orchestrator::aggregation_lifecycle::Config {
            namespace: aggregation_namespace,
            current_epoch: aggregation_current,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            active_old_epochs: AGGREGATION_ACTIVE_EPOCHS.get() - 1,
            mailbox_size: MAILBOX_SIZE,
            certificate_mailbox_size: MAILBOX_SIZE,
            parked_interval: Duration::from_secs(2),
            parked_missing_batch: NZUsize!(64),
            automaton: checkpoint_automaton.clone(),
            blocker: oracle.clone(),
            strategy: Sequential,
            engine: orchestrator::aggregation_lifecycle::EngineConfig {
                priority_acks: false,
                rebroadcast_timeout: NZDuration!(Duration::from_secs(1)),
                recovery_after_rebroadcasts: NZU64!(3),
                window: aggregation_window,
                journal_partition_prefix: format!("{partition_prefix}-aggregation-engine"),
                journal_write_buffer: IO_BUFFER_SIZE,
                journal_replay_buffer: IO_BUFFER_SIZE,
                journal_heights_per_section: NZU64!(64),
                journal_compression: None,
                journal_page_cache: page_cache.clone(),
            },
        },
        aggregation_provider.clone(),
        history.clone(),
        router_registry,
        gate.clone(),
        recovery,
        aggregation_mux,
    );
    let aggregation_task = aggregation_actor.start();
    let aggregation_handle =
        context
            .child("aggregation_lifecycle_supervisor")
            .spawn(|_| async move {
                aggregation_task
                    .await
                    .expect("aggregation lifecycle task")
                    .expect("aggregation lifecycle failure");
            });
    let (reshare_actor, reshare_mailbox) = reshare::Actor::new(
        context.child("reshare"),
        reshare::Config {
            signer: node.signing_key,
            manager: oracle.clone(),
            blocker: oracle.clone(),
            participants_provider: participants,
            secret_store: store,
            strategy: Sequential,
            registrar: Registrar::new(provider.clone(), aggregation_provider.clone()),
            marshal: marshal.clone(),
            state_sync: state_sync.clone(),
            fence,
            namespace: NAMESPACE,
            sharing_mode: SHARING_MODE,
            reveal: REVEAL,
            mailbox_size: MAILBOX_SIZE,
            partition_prefix: format!("{partition_prefix}-reshare"),
            max_participants: MAX_PARTICIPANTS,
            blocks_per_epoch: BLOCKS_PER_EPOCH,
            batch_verifier: PhantomData::<ed25519::Batch>,
        },
    );
    let reshare_handle = reshare_actor.start(dkg_network);

    let (stateful_actor, stateful_mailbox) = Stateful::init(
        context.child("stateful"),
        StatefulConfig {
            application: App::new(genesis.clone()),
            db_config: types::db_config(partition_prefix, page_cache.clone()),
            provider: (),
            marshal: (marshal.clone(), floor),
            mailbox_size: MAILBOX_SIZE,
            plan,
            resolvers: qmdb_sync_resolver,
            sync_config: types::sync_config(),
            prune_config: None,
        },
    );

    // The reshare wrapper drives the payload for the stateful application.
    let deferred = Deferred::new(
        context.child("deferred"),
        reshare::Application::new(
            stateful_mailbox.clone(),
            reshare_mailbox.clone(),
            BLOCKS_PER_EPOCH,
        ),
        marshal.clone(),
        FixedEpocher::new(BLOCKS_PER_EPOCH),
    );
    let (orchestrator_actor, orchestrator_mailbox) = orchestrator::Actor::new(
        context.child("orchestrator"),
        orchestrator::Config {
            oracle: oracle.clone(),
            manager: oracle.clone(),
            provider: provider.clone(),
            marshal: marshal.clone(),
            application: deferred,
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
                view_retention: ViewDelta::new(10),
                skip: SkipPolicy::Enabled {
                    timeout: Duration::from_secs(5),
                    budget: SkipBudget::Participants,
                },
                forward: ForwardPolicy::Disabled,
                track_historical_votes: false,
            },
            gate,
            state_sync,
            blocks_per_epoch: BLOCKS_PER_EPOCH,
            peer_set_retention: (AGGREGATION_ACTIVE_EPOCHS.get() - 1) as u64,
            peer_set_capacity: AGGREGATION_ACTIVE_EPOCHS,
            muxer_size: 128,
            mailbox_size: MAILBOX_SIZE,
            partition_prefix: format!("{partition_prefix}-orchestrator"),
        },
    );
    let orchestrator_handle =
        orchestrator_actor.start(vote_network, certificate_network, resolver_network);

    let reporters = Reporters::from((
        stateful_mailbox.clone(),
        Reporters::from((
            checkpoint_automaton,
            Reporters::from((
                aggregation_mailbox,
                Reporters::from((
                    orchestrator_mailbox,
                    Reporters::from((reshare_mailbox, LogReporter)),
                )),
            )),
        )),
    ));
    let marshal_handle = marshal_actor.start(reporters, buffer, resolver);
    probe_mailbox.attach(marshal.clone());
    let stateful_handle = stateful_actor.start();

    if let Err(err) = Handle::select([
        p2p_handle,
        broadcast_handle,
        probe_handle,
        qmdb_handle,
        history_handle,
        checkpoint_handle,
        router_handle,
        aggregation_resolver_handle,
        recovery_handle,
        aggregation_muxer_handle,
        aggregation_handle,
        reshare_handle,
        orchestrator_handle,
        marshal_handle,
        stateful_handle,
    ])
    .await
    {
        error!(?err, "validator task failed");
    }
}

fn immutable_archive_config<C>(
    prefix: &str,
    name: &str,
    page_cache: CacheRef,
    codec_config: C,
) -> immutable::Config<C> {
    immutable::Config {
        metadata_partition: format!("{prefix}-{name}-metadata"),
        freezer_table_partition: format!("{prefix}-{name}-table"),
        freezer_table_initial_size: 64,
        freezer_table_resize_frequency: 4,
        freezer_table_resize_chunk_size: 32,
        freezer_key_partition: format!("{prefix}-{name}-keys"),
        freezer_key_page_cache: page_cache,
        freezer_value_partition: format!("{prefix}-{name}-values"),
        freezer_value_target_size: 1024 * 1024,
        freezer_value_compression: None,
        ordinal_partition: format!("{prefix}-{name}-ordinal"),
        items_per_section: NZU64!(64),
        freezer_key_write_buffer: IO_BUFFER_SIZE,
        freezer_value_write_buffer: IO_BUFFER_SIZE,
        ordinal_write_buffer: IO_BUFFER_SIZE,
        replay_buffer: IO_BUFFER_SIZE,
        codec_config,
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
        metadata_partition: format!("{prefix}-{name}-metadata"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{FutureExt as _, future::pending};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct CountDrop(Arc<AtomicUsize>);

    impl Drop for CountDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn pending_handle(dropped: Arc<AtomicUsize>) -> Handle<()> {
        let count_drop = CountDrop(dropped);
        Handle::from_future(async move {
            let _count_drop = count_drop;
            pending().await
        })
    }

    #[test]
    fn successful_actor_completion_stops_validator() {
        let dropped = Arc::new(AtomicUsize::new(0));

        // Model a clean actor exit alongside siblings that would otherwise run forever.
        let actors = [
            Handle::ready(Ok(())),
            pending_handle(dropped.clone()),
            pending_handle(dropped.clone()),
            pending_handle(dropped.clone()),
            pending_handle(dropped.clone()),
            pending_handle(dropped.clone()),
            pending_handle(dropped.clone()),
            pending_handle(dropped.clone()),
        ];

        // Supervision must complete and abort every pending sibling.
        assert!(matches!(
            Handle::select(actors).now_or_never(),
            Some(Ok(()))
        ));
        assert_eq!(dropped.load(Ordering::Relaxed), 7);
    }
}

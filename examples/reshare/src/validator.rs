use crate::{
    application::App,
    config::{NetworkConfig, NodeConfig},
    types::{
        self, Block, DynamicProvider, FileSecretStore, LogReporter, Participants, Registrar,
        Scheme, ANCHOR_BOUNDARY_CHANNEL, BACKFILL_CHANNEL, BLOCKS_PER_EPOCH, BROADCAST_CHANNEL,
        CERTIFICATE_CHANNEL, DKG_CHANNEL, IO_BUFFER_SIZE, MAILBOX_SIZE, MAX_MESSAGE_SIZE,
        MAX_PARTICIPANTS, MESSAGE_BACKLOG, NAMESPACE, PAGE_CACHE_SIZE, PAGE_SIZE, PROBE_CHANNEL,
        QMDB_CHANNEL, RESOLVER_CHANNEL, VOTE_CHANNEL,
    },
};
use clap::Args;
use commonware_broadcast::buffered;
use commonware_consensus::{
    marshal::{
        self, core::Actor as MarshalActor, resolver::p2p as marshal_resolver, standard::Deferred,
    },
    simplex::{config::ForwardingPolicy, elector::RoundRobin, types::Finalization},
    types::{Epoch, FixedEpocher, ViewDelta},
    Reporters,
};
use commonware_cryptography::{
    bls12381::primitives::sharing::Mode,
    ed25519,
    sha256::{Digest as Sha256Digest, Sha256},
};
use commonware_glue::{
    dkg::{anchor, fence::Fence, orchestrator, reshare, SecretStore as _},
    stateful::{
        db::p2p::standard as qmdb_resolver,
        probe::{Config as ProbeConfig, Probe},
        Config as StatefulConfig, Stateful, SyncPlan,
    },
};
use commonware_p2p::{
    authenticated::discovery,
    utils::mux::{Builder, Muxer},
};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, tokio, Quota, Supervisor as _};
use commonware_storage::{archive::prunable, translator::TwoCap};
use commonware_utils::{ordered::Set, NZDuration, NZUsize, NZU32, NZU64};
use futures::future::try_join_all;
use std::{marker::PhantomData, path::PathBuf, time::Duration};
use tracing::error;

#[derive(Args)]
pub struct Validator {
    /// Validator node directory containing config, genesis, secrets, and runtime storage.
    #[arg(long, default_value = "./data/validator-0")]
    pub node_dir: PathBuf,

    /// Run one-time peer state sync for a new late joiner.
    #[arg(long, default_value_t = false)]
    pub state_sync: bool,
}

pub async fn run(context: tokio::Context, args: Validator) {
    let node = NodeConfig::load(&args.node_dir).expect("failed to load node config");
    let network = NetworkConfig::load(&args.node_dir).expect("failed to load network config");
    network.validate().expect("invalid network config");
    let genesis_info = types::read_genesis(&args.node_dir).expect("genesis is required");
    let participants = Participants::new(&network).expect("invalid participants");
    let local = node.public_key();
    let partition_prefix = "validator";
    let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);

    let mut p2p_config = discovery::Config::local(
        node.signing_key.clone(),
        &[NAMESPACE, b"_P2P"].concat(),
        node.listen,
        node.dial,
        network.bootstrappers(&local),
        MAX_MESSAGE_SIZE,
    );
    p2p_config.mailbox_size = MAILBOX_SIZE;
    let (mut p2p, oracle) = discovery::Network::new(context.child("network"), p2p_config);

    let vote_network = p2p.register(
        VOTE_CHANNEL,
        Quota::per_second(NZU32!(128)),
        MESSAGE_BACKLOG,
    );
    let certificate_network = p2p.register(
        CERTIFICATE_CHANNEL,
        Quota::per_second(NZU32!(128)),
        MESSAGE_BACKLOG,
    );
    let resolver_network = p2p.register(
        RESOLVER_CHANNEL,
        Quota::per_second(NZU32!(128)),
        MESSAGE_BACKLOG,
    );
    let backfill_network = p2p.register(
        BACKFILL_CHANNEL,
        Quota::per_second(NZU32!(128)),
        MESSAGE_BACKLOG,
    );
    let broadcast_network = p2p.register(
        BROADCAST_CHANNEL,
        Quota::per_second(NZU32!(128)),
        MESSAGE_BACKLOG,
    );
    let qmdb_network = p2p.register(
        QMDB_CHANNEL,
        Quota::per_second(NZU32!(128)),
        MESSAGE_BACKLOG,
    );
    let dkg_network = p2p.register(DKG_CHANNEL, Quota::per_second(NZU32!(128)), MESSAGE_BACKLOG);
    let probe_network = p2p.register(
        PROBE_CHANNEL,
        Quota::per_second(NZU32!(128)),
        MESSAGE_BACKLOG,
    );
    let anchor_boundary_network = p2p.register(
        ANCHOR_BOUNDARY_CHANNEL,
        Quota::per_second(NZU32!(128)),
        MESSAGE_BACKLOG,
    );

    let (certificate_mux, certificate_mux_handle, certificate_backup) = Muxer::builder(
        context.child("certificate_mux"),
        certificate_network.0.clone(),
        certificate_network.1,
        128,
    )
    .with_backup()
    .build();
    certificate_mux.start();

    let provider = DynamicProvider::default();
    let store = FileSecretStore::load(args.node_dir.join("secrets.json"))
        .expect("failed to load secret store");
    let mut store_for_genesis = store.clone();
    if let Some(share) = store_for_genesis.get_share(Epoch::zero()).await {
        provider.register(
            Epoch::zero(),
            Scheme::signer(
                NAMESPACE,
                genesis_info.output.players().clone(),
                genesis_info.output.public().clone(),
                share,
            )
            .expect("epoch-0 share must match genesis"),
        );
    } else {
        provider.register(
            Epoch::zero(),
            Scheme::verifier(
                NAMESPACE,
                genesis_info.output.players().clone(),
                genesis_info.output.public().clone(),
            ),
        );
    }

    let resolver = marshal_resolver::init(
        context.child("marshal_resolver"),
        marshal_resolver::Config {
            public_key: local.clone(),
            peer_provider: oracle.clone(),
            blocker: oracle.clone(),
            mailbox_size: MAILBOX_SIZE,
            initial: Duration::from_secs(1),
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

    let genesis_state_root = types::empty_db_root(
        context.child("genesis_qmdb"),
        types::db_config(partition_prefix, page_cache.clone()),
    )
    .await;
    let genesis = Block::genesis(
        network.participants[0].clone(),
        genesis_info.clone(),
        genesis_state_root,
    );
    let (anchor_actor, anchor_mailbox) = anchor::Actor::new(anchor::Config {
        context: context.child("anchor"),
        manager: oracle.clone(),
        peers: Set::from_iter_dedup(network.participants.iter().cloned()),
        verifier: Scheme::certificate_verifier(NAMESPACE, *genesis_info.output.public().public()),
        genesis: genesis_info.clone(),
        strategy: Sequential,
        blocker: oracle.clone(),
        blocks_per_epoch: BLOCKS_PER_EPOCH,
        retry_timeout: NZDuration!(Duration::from_millis(500)),
        mailbox_size: MAILBOX_SIZE,
        block_codec_config: (),
    });
    let anchor_handle = anchor_actor.start(certificate_backup, anchor_boundary_network);

    let stateful_startup = context.child("stateful_startup");
    let mut plan = SyncPlan::init(&stateful_startup, partition_prefix).await;
    let should_state_sync = plan.should_state_sync(args.state_sync);
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

    let minimum_epoch = anchor_artifact
        .as_ref()
        .map_or_else(Epoch::zero, |artifact| artifact.epoch);
    let (probe_actor, probe_mailbox) = Probe::new(ProbeConfig {
        context: context.child("probe"),
        provider: provider.clone(),
        strategy: Sequential,
        capacity: MAILBOX_SIZE,
        blocker: oracle.clone(),
        minimum_epoch,
        retry_timeout: NZDuration!(Duration::from_millis(100)),
    });
    let probe_handle = probe_actor.start(probe_network);
    if should_state_sync {
        let floor = probe_mailbox.subscribe().await.expect("probe stopped");
        plan = plan.with_floor(floor);
    }

    let (marshal_actor, marshal, _) = MarshalActor::init(
        context.child("marshal"),
        finalizations_by_height,
        finalized_blocks,
        marshal::Config {
            provider: provider.clone(),
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            start: plan.marshal_start(genesis.clone()),
            partition_prefix: partition_prefix.to_string(),
            mailbox_size: MAILBOX_SIZE,
            view_retention_timeout: ViewDelta::new(10),
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
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            max_serve_ops: NZU64!(16),
            priority_requests: false,
            priority_responses: false,
        },
    );
    let qmdb_handle = qmdb_actor.start(qmdb_network);

    let fence_epoch = anchor_artifact
        .as_ref()
        .map_or_else(Epoch::zero, |artifact| artifact.epoch);
    let state_sync = anchor_artifact.map(|artifact| {
        let floor = plan
            .floor()
            .cloned()
            .expect("state sync startup must have floor");
        orchestrator::StateSync { artifact, floor }
    });

    let (fence, gate) = Fence::new(fence_epoch);
    let sync_floor: Option<Finalization<Scheme, Sha256Digest>> = plan.floor().cloned();
    let state_sync_floor: Option<Sha256Digest> =
        sync_floor.as_ref().map(|floor| floor.proposal.payload);
    let (reshare_actor, reshare_mailbox) = reshare::Actor::new(
        context.child("reshare"),
        reshare::Config {
            signer: node.signing_key,
            manager: oracle.clone(),
            blocker: oracle.clone(),
            participants_provider: participants,
            secret_store: store,
            strategy: Sequential,
            registrar: Registrar::new(provider.clone()),
            marshal: marshal.clone(),
            state_sync_floor,
            fence,
            namespace: NAMESPACE,
            sharing_mode: Mode::RootsOfUnity,
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
            marshal: marshal.clone(),
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
                fetch_concurrent: NZUsize!(3),
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                forwarding: ForwardingPolicy::Disabled,
            },
            gate,
            state_sync,
            blocks_per_epoch: BLOCKS_PER_EPOCH,
            muxer_size: 128,
            mailbox_size: MAILBOX_SIZE,
            partition_prefix: format!("{partition_prefix}-orchestrator"),
        },
    );
    let orchestrator_handle =
        orchestrator_actor.start(vote_network, certificate_mux_handle, resolver_network);

    let reporters = Reporters::from((
        stateful_mailbox.clone(),
        Reporters::from((
            orchestrator_mailbox,
            Reporters::from((reshare_mailbox, LogReporter)),
        )),
    ));
    let marshal_handle = marshal_actor.start(reporters, buffer, resolver);
    anchor_mailbox.attach(marshal.clone());
    probe_mailbox.attach(marshal.clone());
    let stateful_handle = stateful_actor.start();
    let p2p_handle = p2p.start();

    if let Err(err) = try_join_all(vec![
        p2p_handle,
        broadcast_handle,
        anchor_handle,
        probe_handle,
        qmdb_handle,
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

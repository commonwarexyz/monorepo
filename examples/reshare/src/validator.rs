//! Validator node service entrypoint.

use crate::{
    application::{self, Supervisor, B},
    dkg, orchestrator,
    setup::{ParticipantConfig, PeerConfig},
};
use commonware_broadcast::buffered;
use commonware_consensus::{
    marshal::{self, resolver::p2p as p2p_resolver},
    threshold_simplex, Reporters,
};
use commonware_cryptography::{
    bls12381::primitives::{poly::public, variant::MinSig},
    Signer,
};
use commonware_p2p::{authenticated::discovery, utils::requester};
use commonware_runtime::{buffer::PoolRef, tokio, Metrics};
use commonware_utils::{union_unique, NZUsize, NZU64};
use futures::future::try_join_all;
use governor::Quota;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::{NonZero, NonZeroU32},
    time::Duration,
};
use tracing::{error, info};

const NAMESPACE: &[u8] = b"RESHARE_EXAMPLE";

const PENDING_CHANNEL: u32 = 0;
const RECOVERED_CHANNEL: u32 = 1;
const RESOLVER_CHANNEL: u32 = 2;
const BROADCASTER_CHANNEL: u32 = 3;
const BACKFILL_BY_DIGEST_CHANNEL: u32 = 4;
const DKG_CHANNEL: u32 = 5;

const MAILBOX_SIZE: usize = 10;
const DEQUE_SIZE: usize = 10;
const MESSAGE_BACKLOG: usize = 10;
const LEADER_TIMEOUT: Duration = Duration::from_secs(1);
const NOTARIZATION_TIMEOUT: Duration = Duration::from_secs(2);
const NULLIFY_RETRY: Duration = Duration::from_secs(10);
const ACTIVITY_TIMEOUT: u64 = 256;
const SKIP_TIMEOUT: u64 = 32;
const FETCH_TIMEOUT: Duration = Duration::from_secs(2);
const FETCH_CONCURRENT: usize = 4;
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
const MAX_FETCH_COUNT: usize = 16;
const SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER: u64 = 10;
const PRUNABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(4_096);
const IMMUTABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(262_144);
const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;
const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 2u32.pow(16); // 3MB
const FREEZER_JOURNAL_TARGET_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
const FREEZER_JOURNAL_COMPRESSION: Option<u8> = Some(3);
const REPLAY_BUFFER: NonZero<usize> = NZUsize!(8 * 1024 * 1024); // 8MB
const WRITE_BUFFER: NonZero<usize> = NZUsize!(1024 * 1024); // 1MB
const BUFFER_POOL_PAGE_SIZE: NonZero<usize> = NZUsize!(4_096); // 4KB
const BUFFER_POOL_CAPACITY: NonZero<usize> = NZUsize!(8_192); // 32MB
const MAX_REPAIR: u64 = 20;
const FINALIZED_FREEZER_TABLE_INITIAL_SIZE: u32 = 2u32.pow(21); // 100MB

/// Run the validator node service.
pub async fn run(context: tokio::Context, args: super::ValidatorArgs) {
    // Load the participant configuration.
    let config_str = std::fs::read_to_string(&args.config_path)
        .expect("Failed to read participant configuration file");
    let config: ParticipantConfig =
        serde_json::from_str(&config_str).expect("Failed to deserialize participant configuration");

    // Load the peer configuration.
    let peers_str =
        std::fs::read_to_string(&args.peers_path).expect("Failed to read peers configuration file");
    let peer_config: PeerConfig =
        serde_json::from_str(&peers_str).expect("Failed to deserialize peers configuration");

    let threshold = peer_config.threshold();
    let polynomial = config.polynomial(threshold);

    info!(
        public_key = %config.p2p_key.public_key(),
        share = %config.share,
        ?polynomial,
        "Loaded participant configuration"
    );

    let p2p_namespace = union_unique(NAMESPACE, b"_P2P");
    let mut p2p_cfg = discovery::Config::local(
        config.p2p_key.clone(),
        &p2p_namespace,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.port),
        config.bootstrappers.into_iter().collect::<Vec<_>>(),
        MAX_MESSAGE_SIZE,
    );
    p2p_cfg.mailbox_size = MAILBOX_SIZE;

    let (mut network, mut oracle) = discovery::Network::new(context.with_label("network"), p2p_cfg);

    oracle.register(0, peer_config.peers.clone()).await;

    let pending_limit = Quota::per_second(NonZeroU32::new(128).unwrap());
    let pending = network.register(PENDING_CHANNEL, pending_limit, MESSAGE_BACKLOG);

    let recovered_limit = Quota::per_second(NonZeroU32::new(128).unwrap());
    let recovered = network.register(RECOVERED_CHANNEL, recovered_limit, MESSAGE_BACKLOG);

    let resolver_limit = Quota::per_second(NonZeroU32::new(128).unwrap());
    let resolver = network.register(RESOLVER_CHANNEL, resolver_limit, MESSAGE_BACKLOG);

    let broadcaster_limit = Quota::per_second(NonZeroU32::new(8).unwrap());
    let broadcaster = network.register(BROADCASTER_CHANNEL, broadcaster_limit, MESSAGE_BACKLOG);

    let backfill_quota = Quota::per_second(NonZeroU32::new(8).unwrap());
    let backfill = network.register(BACKFILL_BY_DIGEST_CHANNEL, backfill_quota, MESSAGE_BACKLOG);

    let dkg_limit = Quota::per_second(NonZeroU32::new(128).unwrap());
    let dkg_channel = network.register(DKG_CHANNEL, dkg_limit, MESSAGE_BACKLOG);

    let identity = *public::<MinSig>(&polynomial);
    let buffer_pool = PoolRef::new(BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);

    let (dkg, dkg_mailbox) = dkg::Actor::new(
        context.with_label("dkg"),
        config.p2p_key.clone(),
        peer_config.peers.clone(),
        MAILBOX_SIZE,
    );

    let (application, application_mailbox) =
        application::Actor::new(context.with_label("application"), MAILBOX_SIZE);

    let (buffer, buffered_mailbox) = buffered::Engine::new(
        context.with_label("buffer"),
        buffered::Config {
            public_key: config.p2p_key.public_key(),
            mailbox_size: MAILBOX_SIZE,
            deque_size: DEQUE_SIZE,
            priority: true,
            codec_config: threshold as usize,
        },
    );

    let (marshal, marshal_mailbox): (_, marshal::Mailbox<MinSig, B>) = marshal::Actor::init(
        context.with_label("marshal"),
        marshal::Config {
            identity,
            partition_prefix: "engine".to_string(),
            mailbox_size: MAILBOX_SIZE,
            view_retention_timeout: ACTIVITY_TIMEOUT
                .saturating_mul(SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER),
            namespace: NAMESPACE.to_vec(),
            prunable_items_per_section: PRUNABLE_ITEMS_PER_SECTION,
            immutable_items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
            freezer_table_initial_size: FINALIZED_FREEZER_TABLE_INITIAL_SIZE,
            freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
            freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
            freezer_journal_target_size: FREEZER_JOURNAL_TARGET_SIZE,
            freezer_journal_compression: FREEZER_JOURNAL_COMPRESSION,
            freezer_journal_buffer_pool: buffer_pool.clone(),
            replay_buffer: REPLAY_BUFFER,
            write_buffer: WRITE_BUFFER,
            codec_config: threshold as usize,
            max_repair: MAX_REPAIR,
        },
    )
    .await;

    let (orchestrator, orchestrator_mailbox) = orchestrator::Actor::new(
        context.with_label("orchestrator"),
        orchestrator::Config {
            oracle,
            signer: config.p2p_key.clone(),
            application: application_mailbox.clone(),
            marshal: marshal_mailbox.clone(),
            namespace: NAMESPACE.to_vec(),
            validators: peer_config.peers.clone(),
            muxer_size: MAILBOX_SIZE,
            mailbox_size: MAILBOX_SIZE,
            partition_prefix: "consensus".to_string(),
        },
    );

    // Create a static resolver for backfill
    let supervisor = Supervisor::new(
        polynomial.clone(),
        peer_config.peers.clone(),
        config.share.clone(),
    );
    let resolver_cfg = p2p_resolver::Config {
        public_key: config.p2p_key.public_key(),
        coordinator: supervisor.clone(),
        mailbox_size: 200,
        requester_config: requester::Config {
            public_key: config.p2p_key.public_key(),
            rate_limit: Quota::per_second(NonZeroU32::new(5).unwrap()),
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
        },
        fetch_retry_timeout: Duration::from_millis(100),
        priority_requests: false,
        priority_responses: false,
    };
    let p2p_resolver = p2p_resolver::init(&context, resolver_cfg, backfill);

    let finalized_reporter = Reporters::from((application_mailbox, dkg_mailbox.clone()));

    let p2p_handle = network.start();
    let dkg_handle = dkg.start(
        polynomial.clone(),
        config.share.clone(),
        orchestrator_mailbox,
        dkg_channel,
    );
    let application_handle = application.start(marshal_mailbox, dkg_mailbox);
    let buffer_handle = buffer.start(broadcaster);
    let marshal_handle = marshal.start(finalized_reporter, buffered_mailbox, p2p_resolver);
    let orchestrator_handle =
        orchestrator.start(pending, recovered, resolver, polynomial, config.share);

    if let Err(e) = try_join_all(vec![
        p2p_handle,
        dkg_handle,
        application_handle,
        buffer_handle,
        marshal_handle,
        orchestrator_handle,
    ])
    .await
    {
        error!(?e, "task failed");
    }
}

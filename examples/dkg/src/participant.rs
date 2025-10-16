//! Validator node service entrypoint.

use crate::{
    application::Supervisor,
    engine,
    setup::{ParticipantConfig, PeerConfig},
};
use commonware_consensus::marshal::resolver::p2p as p2p_resolver;
use commonware_cryptography::{bls12381::primitives::variant::MinSig, Sha256, Signer};
use commonware_p2p::{authenticated::discovery, utils::requester};
use commonware_runtime::{
    tokio::{self, telemetry::Logging},
    Metrics, Runner,
};
use commonware_utils::union_unique;
use futures::future::try_join_all;
use governor::Quota;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
    time::Duration,
};
use tracing::{error, info};

const NAMESPACE: &[u8] = b"DKG_EXAMPLE";

const PENDING_CHANNEL: u32 = 0;
const RECOVERED_CHANNEL: u32 = 1;
const RESOLVER_CHANNEL: u32 = 2;
const BROADCASTER_CHANNEL: u32 = 3;
const BACKFILL_BY_DIGEST_CHANNEL: u32 = 4;
const DKG_CHANNEL: u32 = 5;

const MAILBOX_SIZE: usize = 10;
const MESSAGE_BACKLOG: usize = 10;
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Run the validator node service.
pub fn run(runtime_args: super::RuntimeArgs, args: super::ParticipantArgs) {
    let config = tokio::Config::new()
        .with_worker_threads(runtime_args.worker_threads)
        .with_tcp_nodelay(Some(true))
        .with_catch_panics(false);
    let runner = tokio::Runner::new(config);
    runner.start(|context| async move {
        // Initialize telemetry.
        tokio::telemetry::init(
            context.with_label("telemetry"),
            Logging {
                level: runtime_args.log_level,
                json: false,
            },
            None,
            None,
        );

        // Load the participant configuration.
        let config_str = std::fs::read_to_string(&args.config_path)
            .expect("Failed to read participant configuration file");
        let config: ParticipantConfig = serde_json::from_str(&config_str)
            .expect("Failed to deserialize participant configuration");

        // Load the peer configuration.
        let peers_str = std::fs::read_to_string(&args.peers_path)
            .expect("Failed to read peers configuration file");
        let peer_config: PeerConfig =
            serde_json::from_str(&peers_str).expect("Failed to deserialize peers configuration");

        info!(
            public_key = %config.signing_key.public_key(),
            "Loaded participant configuration"
        );

        let p2p_namespace = union_unique(NAMESPACE, b"_P2P");
        let mut p2p_cfg = discovery::Config::local(
            config.signing_key.clone(),
            &p2p_namespace,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.port),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.port),
            config.bootstrappers.into_iter().collect::<Vec<_>>(),
            MAX_MESSAGE_SIZE,
        );
        p2p_cfg.mailbox_size = MAILBOX_SIZE;

        let (mut network, mut oracle) =
            discovery::Network::new(context.with_label("network"), p2p_cfg);

        // Register all possible peers
        oracle.register(0, peer_config.active.clone()).await;

        let pending_limit = Quota::per_second(NonZeroU32::new(128).unwrap());
        let pending = network.register(PENDING_CHANNEL, pending_limit, MESSAGE_BACKLOG);

        let recovered_limit = Quota::per_second(NonZeroU32::new(128).unwrap());
        let recovered = network.register(RECOVERED_CHANNEL, recovered_limit, MESSAGE_BACKLOG);

        let resolver_limit = Quota::per_second(NonZeroU32::new(128).unwrap());
        let resolver = network.register(RESOLVER_CHANNEL, resolver_limit, MESSAGE_BACKLOG);

        let broadcaster_limit = Quota::per_second(NonZeroU32::new(8).unwrap());
        let broadcaster = network.register(BROADCASTER_CHANNEL, broadcaster_limit, MESSAGE_BACKLOG);

        let backfill_quota = Quota::per_second(NonZeroU32::new(8).unwrap());
        let backfill =
            network.register(BACKFILL_BY_DIGEST_CHANNEL, backfill_quota, MESSAGE_BACKLOG);

        let dkg_limit = Quota::per_second(NonZeroU32::new(128).unwrap());
        let dkg_channel = network.register(DKG_CHANNEL, dkg_limit, MESSAGE_BACKLOG);

        // Create a static resolver for backfill
        let coordinator = Supervisor::new(config.signing_key.clone(), peer_config.active.clone());
        let resolver_cfg = p2p_resolver::Config {
            public_key: config.signing_key.public_key(),
            coordinator: coordinator.clone(),
            mailbox_size: 200,
            requester_config: requester::Config {
                public_key: config.signing_key.public_key(),
                rate_limit: Quota::per_second(NonZeroU32::new(8).unwrap()),
                initial: Duration::from_secs(1),
                timeout: Duration::from_secs(2),
            },
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let p2p_resolver = p2p_resolver::init(&context, resolver_cfg, backfill);

        let engine = engine::Engine::<_, _, Sha256, MinSig>::new(
            context.with_label("engine"),
            engine::Config {
                signer: config.signing_key,
                blocker: oracle,
                namespace: NAMESPACE.to_vec(),
                active_participants: peer_config.active,
                partition_prefix: "engine".to_string(),
                freezer_table_initial_size: 1024 * 1024, // 100mb
            },
        )
        .await;

        let p2p_handle = network.start();
        let engine_handle = engine.start(
            pending,
            recovered,
            resolver,
            broadcaster,
            dkg_channel,
            p2p_resolver,
        );

        if let Err(e) = try_join_all(vec![p2p_handle, engine_handle]).await {
            error!(?e, "task failed");
        }
    });
}

use clap::{value_parser, Arg, Command};
use commonware_broadcast::buffered;
use commonware_consensus::marshal::{self, resolver::p2p as marshal_resolver};
use commonware_cryptography::{
    bls12381::{
        dkg::ops,
        primitives::{poly, variant::MinSig},
    },
    ed25519, PrivateKeyExt as _, Signer as _,
};
use commonware_epocher::{
    application::Application, orchestrator, poller, ACTIVE_VALIDATORS, THRESHOLD,
};
use commonware_p2p::{authenticated::discovery, utils::requester};
use commonware_resolver::p2p::mocks as resolver_mocks;
use commonware_runtime::{buffer::PoolRef, tokio, Metrics, Runner};
use commonware_utils::{NZUsize, NZU32, NZU64};
use governor::Quota;
use rand::{rngs::StdRng, SeedableRng};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};

fn main() {
    let matches = Command::new("epocher-validator")
        .about("run epocher validator")
        .arg(Arg::new("me").long("me").required(true))
        .arg(
            Arg::new("bootstrappers")
                .long("bootstrappers")
                .required(false)
                .value_delimiter(',')
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("indexer")
                .long("indexer")
                .required(false)
                .value_delimiter(',')
                .value_parser(value_parser!(String)),
        )
        .arg(Arg::new("storage-dir").long("storage-dir").required(true))
        .get_matches();
    let indexers: Vec<String> = matches
        .get_many::<String>("indexer")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Identity/port
    let me = matches.get_one::<String>("me").expect("provide --me");
    let parts = me.split('@').collect::<Vec<&str>>();
    let key = parts[0].parse::<u64>().expect("key not well-formed");
    let signer = ed25519::PrivateKey::from_seed(key);
    let port = parts[1].parse::<u16>().expect("port not well-formed");

    // Fixed participants (network authorization) - 10 total validators
    let mut validators = (1u64..=10u64)
        .map(|s| ed25519::PrivateKey::from_seed(s).public_key())
        .collect::<Vec<_>>();
    validators.sort();

    // Optional bootstrappers
    let bootstrappers = matches.get_many::<String>("bootstrappers");
    let mut bootstrapper_identities = Vec::new();
    if let Some(bootstrappers) = bootstrappers {
        for bootstrapper in bootstrappers {
            let parts = bootstrapper.split('@').collect::<Vec<&str>>();
            let key = parts[0].parse::<u64>().expect("bootstrapper key bad");
            let verifier = ed25519::PrivateKey::from_seed(key).public_key();
            let addr = SocketAddr::from_str(parts[1]).expect("bootstrapper addr bad");
            bootstrapper_identities.push((verifier, addr));
        }
    }

    // Configure storage directory
    let storage_directory = matches
        .get_one::<String>("storage-dir")
        .expect("Please provide storage directory");

    // Start runtime
    let runtime_cfg = tokio::Config::new().with_storage_directory(storage_directory);
    let executor = tokio::Runner::new(runtime_cfg);
    executor.start(|context| async move {
        // Setup P2P.
        // Tracks at least 3 peer sets since the epoch+2 set is established at end-of-epoch.
        let mut p2p_cfg = discovery::Config::aggressive(
            signer.clone(),
            b"EPOCHER",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            bootstrapper_identities,
            1024 * 1024,
        );
        p2p_cfg.tracked_peer_sets = 3;
        p2p_cfg.query_frequency = Duration::from_secs(2);
        let (mut network, oracle) = discovery::Network::new(context.with_label("network"), p2p_cfg);

        // Create shares.
        let mut rng = StdRng::seed_from_u64(0);
        let (polynomial, mut shares) =
            ops::generate_shares::<_, MinSig>(&mut rng, None, ACTIVE_VALIDATORS, THRESHOLD);
        shares.sort_by(|a, b| a.index.cmp(&b.index));
        let identity = *poly::public::<MinSig>(&polynomial);

        // Register physical channels for consensus, broadcast, and backfill
        let channel_p = network.register(0, Quota::per_second(NZU32!(10)), 256);
        let channel_rc = network.register(1, Quota::per_second(NZU32!(10)), 256);
        let channel_rs = network.register(2, Quota::per_second(NZU32!(10)), 256);
        let channel_br = network.register(3, Quota::per_second(NZU32!(10)), 256);
        let channel_backfill = network.register(4, Quota::per_second(NZU32!(10)), 256);

        // Start network after registering channels
        let _network_handle = network.start();

        // Start broadcast engine and obtain mailbox
        let (broadcast_engine, broadcast_mailbox) = buffered::Engine::new(
            context.with_label("broadcast"),
            buffered::Config {
                public_key: signer.public_key(),
                mailbox_size: 1024,
                deque_size: 64,
                priority: false,
                codec_config: (),
            },
        );
        broadcast_engine.start(channel_br);

        // Create a static resolver coordinator for backfill
        let coordinator = resolver_mocks::Coordinator::new(validators.clone());

        // Initialize marshal actor (single instance) and start it
        let namespace = b"EPOCHER".to_vec();
        let marshal_cfg = marshal::Config {
            identity,
            partition_prefix: format!("marshal-{}", signer.public_key()),
            mailbox_size: 1024,
            view_retention_timeout: 10,
            namespace: namespace.clone(),
            prunable_items_per_section: NZU64!(10),
            immutable_items_per_section: NZU64!(10),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_journal_target_size: 1024,
            freezer_journal_compression: None,
            freezer_journal_buffer_pool: PoolRef::new(NZUsize!(16_384), NZUsize!(10_000)),
            replay_buffer: NZUsize!(1024),
            write_buffer: NZUsize!(1024),
            codec_config: (),
            max_repair: 10,
        };
        // Initialize resolver for backfill outside of marshal
        let resolver_cfg = marshal_resolver::Config {
            public_key: signer.public_key(),
            coordinator: coordinator.clone(),
            mailbox_size: marshal_cfg.mailbox_size,
            requester_config: requester::Config {
                public_key: signer.public_key(),
                rate_limit: Quota::per_second(NZU32!(5)),
                initial: Duration::from_secs(1),
                timeout: Duration::from_secs(2),
            },
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: true,
            priority_responses: false,
        };
        let resolver = marshal_resolver::init(&context, resolver_cfg, channel_backfill);
        let (marshal_actor, marshal) =
            marshal::Actor::init(context.with_label("marshal"), marshal_cfg).await;

        // Initialize application once (Automaton + Relay + Reporter for finalized blocks)
        let (app_actor, application) =
            Application::new(context.with_label("application"), 1024, marshal.clone());

        // Initialize orchestrator
        // Supervisor will be constructed per-epoch in orchestrator using selected participants
        let orchestrator_cfg = orchestrator::Config {
            oracle,
            signer: signer.clone(),
            application: application.clone(),
            marshal,
            polynomial,
            shares,
            namespace,
            validators,
            muxer_size: 1024,
            mailbox_size: 1024,
            indexers: indexers.clone(),
            partition_prefix: format!("epocher-orchestrator-{}", signer.public_key()),
        };
        let (orchestrator_actor, orchestrator) =
            orchestrator::Orchestrator::new(context.with_label("orchestrator"), orchestrator_cfg);

        // Start the indexer poller (if indexers configured)
        let poller_cfg = poller::Config {
            identity,
            indexers: indexers.clone(),
            orchestrator: orchestrator.clone(),
            poll_interval: Duration::from_secs(5),
        };
        let poller_actor = poller::Poller::new(context.with_label("poller"), poller_cfg);

        // Start the actors
        poller_actor.start();
        app_actor.start(orchestrator.clone());
        marshal_actor.start(application, broadcast_mailbox, resolver);

        // Start the orchestrator, awaiting completion.
        orchestrator_actor
            .run(channel_p, channel_rc, channel_rs)
            .await;
    });
}

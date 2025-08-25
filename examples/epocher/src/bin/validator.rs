use clap::{value_parser, Arg, Command};
use commonware_broadcast::buffered;
use commonware_consensus::marshal;
use commonware_cryptography::{
    bls12381::primitives::{
        group::{Element, Scalar, Share},
        poly,
        variant::{MinSig, Variant},
    },
    ed25519, PrivateKeyExt as _, Signer as _,
};
use commonware_epocher::{application::Application, orchestrator};
use commonware_p2p::authenticated::discovery;
use commonware_resolver::p2p::mocks as resolver_mocks;
use commonware_runtime::{buffer::PoolRef, tokio, Metrics, Runner};
use commonware_utils::{NZUsize, NZU32, NZU64};
use governor::Quota;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
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
        .get_matches();

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

    // Start runtime
    let executor = tokio::Runner::default();
    executor.start(|context| async move {
        // Setup P2P
        let p2p_cfg = discovery::Config::aggressive(
            signer.clone(),
            b"EPOCHER",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            bootstrapper_identities,
            1024 * 1024,
        );
        let (mut network, oracle) = discovery::Network::new(context.with_label("network"), p2p_cfg);
        // Helper to build trivial identity and share
        let polynomial = poly::Public::<MinSig>::from(vec![<MinSig as Variant>::Public::one()]);
        let identity = *poly::public::<MinSig>(&polynomial);
        let my_index = validators
            .iter()
            .position(|pk| pk == &signer.public_key())
            .expect("me must be in validators") as u32;
        let my_share = Share {
            index: my_index,
            private: Scalar::one(),
        };

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
            public_key: signer.public_key(),
            identity,
            coordinator: coordinator.clone(),
            partition_prefix: format!("marshal-{}", signer.public_key()),
            mailbox_size: 1024,
            backfill_quota: Quota::per_second(NZU32!(5)),
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
            share: my_share,
            namespace,
            validators,
            muxer_size: 1024,
            mailbox_size: 1024,
        };
        let (orchestrator_actor, orchestrator) =
            orchestrator::Orchestrator::new(context.with_label("orchestrator"), orchestrator_cfg);

        // Start the actors
        app_actor.start(orchestrator.clone());
        marshal_actor.start(application, broadcast_mailbox, channel_backfill);

        // Start the orchestrator, awaiting completion.
        orchestrator_actor
            .run(channel_p, channel_rc, channel_rs)
            .await;
    });
}

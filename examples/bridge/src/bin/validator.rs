use clap::{value_parser, Arg, Command};
use commonware_bridge::{
    application, APPLICATION_NAMESPACE, CONSENSUS_SUFFIX, INDEXER_NAMESPACE, P2P_SUFFIX,
};
use commonware_consensus::threshold_simplex::{self, Engine, Prover};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        poly::{self, Poly},
    },
    Ed25519, Sha256, Signer,
};
use commonware_p2p::authenticated;
use commonware_runtime::{
    tokio::{self, Executor},
    Metrics, Network, Runner,
};
use commonware_storage::journal::variable::{Config, Journal};
use commonware_stream::public_key::{self, Connection};
use commonware_utils::{from_hex, quorum, union};
use governor::Quota;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
};
use std::{str::FromStr, time::Duration};

fn main() {
    // Parse arguments
    let matches = Command::new("validator")
        .about("produce finality certificates and verify external finality certificates")
        .arg(
            Arg::new("bootstrappers")
                .long("bootstrappers")
                .required(false)
                .value_delimiter(',')
                .value_parser(value_parser!(String)),
        )
        .arg(Arg::new("me").long("me").required(true))
        .arg(
            Arg::new("participants")
                .long("participants")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(u64))
                .help("All participants"),
        )
        .arg(Arg::new("storage-dir").long("storage-dir").required(true))
        .arg(Arg::new("indexer").long("indexer").required(true))
        .arg(Arg::new("identity").long("identity").required(true))
        .arg(Arg::new("share").long("share").required(true))
        .arg(
            Arg::new("other-identity")
                .long("other-identity")
                .required(true),
        )
        .get_matches();

    // Create logger
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Configure my identity
    let me = matches
        .get_one::<String>("me")
        .expect("Please provide identity");
    let parts = me.split('@').collect::<Vec<&str>>();
    if parts.len() != 2 {
        panic!("Identity not well-formed");
    }
    let key = parts[0].parse::<u64>().expect("Key not well-formed");
    let signer = Ed25519::from_seed(key);
    tracing::info!(key = ?signer.public_key(), "loaded signer");

    // Configure my port
    let port = parts[1].parse::<u16>().expect("Port not well-formed");
    tracing::info!(port, "loaded port");

    // Configure allowed peers
    let mut validators = Vec::new();
    let participants = matches
        .get_many::<u64>("participants")
        .expect("Please provide allowed keys")
        .copied();
    if participants.len() == 0 {
        panic!("Please provide at least one participant");
    }
    for peer in participants {
        let verifier = Ed25519::from_seed(peer).public_key();
        tracing::info!(key = ?verifier, "registered authorized key");
        validators.push(verifier);
    }

    // Configure bootstrappers (if provided)
    let bootstrappers = matches.get_many::<String>("bootstrappers");
    let mut bootstrapper_identities = Vec::new();
    if let Some(bootstrappers) = bootstrappers {
        for bootstrapper in bootstrappers {
            let parts = bootstrapper.split('@').collect::<Vec<&str>>();
            let bootstrapper_key = parts[0]
                .parse::<u64>()
                .expect("Bootstrapper key not well-formed");
            let verifier = Ed25519::from_seed(bootstrapper_key).public_key();
            let bootstrapper_address =
                SocketAddr::from_str(parts[1]).expect("Bootstrapper address not well-formed");
            bootstrapper_identities.push((verifier, bootstrapper_address));
        }
    }

    // Configure storage directory
    let storage_directory = matches
        .get_one::<String>("storage-dir")
        .expect("Please provide storage directory");

    // Configure threshold
    let threshold = quorum(validators.len() as u32).expect("Threshold not well-formed");
    let identity = matches
        .get_one::<String>("identity")
        .expect("Please provide identity");
    let identity = from_hex(identity).expect("Identity not well-formed");
    let identity: Poly<group::Public> =
        Poly::deserialize(&identity, threshold).expect("Identity not well-formed");
    let public = *poly::public(&identity);
    let share = matches
        .get_one::<String>("share")
        .expect("Please provide share");
    let share = from_hex(share).expect("Share not well-formed");
    let share = group::Share::deserialize(&share).expect("Share not well-formed");

    // Configure indexer
    let indexer = matches
        .get_one::<String>("indexer")
        .expect("Please provide indexer");
    let parts = indexer.split('@').collect::<Vec<&str>>();
    let indexer_key = parts[0]
        .parse::<u64>()
        .expect("Indexer key not well-formed");
    let indexer = Ed25519::from_seed(indexer_key).public_key();
    let indexer_address = SocketAddr::from_str(parts[1]).expect("Indexer address not well-formed");

    // Configure other identity
    let other_identity = matches
        .get_one::<String>("other-identity")
        .expect("Please provide other identity");
    let other_identity = from_hex(other_identity).expect("Other identity not well-formed");
    let other_identity =
        group::Public::deserialize(&other_identity).expect("Other identity not well-formed");

    // Initialize context
    let runtime_cfg = tokio::Config {
        storage_directory: storage_directory.into(),
        ..Default::default()
    };
    let (executor, context) = Executor::init(runtime_cfg.clone());

    // Configure indexer
    let indexer_cfg = public_key::Config {
        crypto: signer.clone(),
        namespace: INDEXER_NAMESPACE.to_vec(),
        max_message_size: 1024 * 1024,
        synchrony_bound: Duration::from_secs(1),
        max_handshake_age: Duration::from_secs(60),
        handshake_timeout: Duration::from_secs(5),
    };

    // Configure network
    let p2p_cfg = authenticated::Config::aggressive(
        signer.clone(),
        &union(APPLICATION_NAMESPACE, P2P_SUFFIX),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        bootstrapper_identities.clone(),
        1024 * 1024, // 1MB
    );

    // Start context
    executor.start(async move {
        // Dial indexer
        let (sink, stream) = context
            .dial(indexer_address)
            .await
            .expect("Failed to dial indexer");
        let indexer =
            Connection::upgrade_dialer(context.clone(), indexer_cfg, sink, stream, indexer)
                .await
                .expect("Failed to upgrade connection with indexer");

        // Setup p2p
        let (mut network, mut oracle) =
            authenticated::Network::new(context.with_label("network"), p2p_cfg);

        // Provide authorized peers
        //
        // In a real-world scenario, this would be updated as new peer sets are created (like when
        // the composition of a validator set changes).
        oracle.register(0, validators.clone()).await;

        // Register consensus channels
        //
        // If you want to maximize the number of views per second, increase the rate limit
        // for this channel.
        let (voter_sender, voter_receiver) = network.register(
            0,
            Quota::per_second(NonZeroU32::new(10).unwrap()),
            256, // 256 messages in flight
            Some(3),
        );
        let (resolver_sender, resolver_receiver) = network.register(
            1,
            Quota::per_second(NonZeroU32::new(10).unwrap()),
            256, // 256 messages in flight
            Some(3),
        );

        // Initialize storage
        let journal = Journal::init(
            context.clone(),
            &context,
            Config {
                partition: String::from("log"),
            },
        )
        .await
        .expect("Failed to initialize journal");

        // Initialize application
        let consensus_namespace = union(APPLICATION_NAMESPACE, CONSENSUS_SUFFIX);
        let prover = Prover::new(public, &consensus_namespace);
        let other_prover = Prover::new(other_identity, &consensus_namespace);
        let (application, supervisor, mailbox) = application::Application::new(
            context.with_label("application"),
            application::Config {
                indexer,
                prover,
                other_prover,
                other_network: other_identity,
                hasher: Sha256::default(),
                mailbox_size: 1024,
                identity,
                participants: validators.clone(),
                share,
            },
        );

        // Initialize consensus
        let engine = Engine::new(
            context.with_label("engine"),
            journal,
            threshold_simplex::Config {
                crypto: signer.clone(),
                automaton: mailbox.clone(),
                relay: mailbox.clone(),
                committer: mailbox,
                supervisor,
                namespace: consensus_namespace,
                mailbox_size: 1024,
                replay_concurrency: 1,
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: 10,
                skip_timeout: 5,
                max_fetch_count: 32,
                max_fetch_size: 1024 * 512,
                fetch_concurrent: 2,
                fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
            },
        );

        // Start consensus
        network.start();
        engine.start(
            (voter_sender, voter_receiver),
            (resolver_sender, resolver_receiver),
        );

        // Block on application
        application.run().await;
    });
}

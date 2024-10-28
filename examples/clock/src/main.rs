//! TBD
//!
//! # Tips
//!
//! * If you want to maximize consensus decisions per second, increase rate limits from the default configuration
//!   of 10 messages per peer per second on the voter channel.

mod application;

use bytes::Bytes;
use clap::{value_parser, Arg, Command};
use commonware_consensus::authority::{Config, Engine};
use commonware_cryptography::{Ed25519, Scheme, Sha256};
use commonware_p2p::authenticated::{self, Network};
use commonware_runtime::{
    tokio::{self, Context, Executor},
    Runner, Spawner,
};
use commonware_utils::hex;
use governor::Quota;
use prometheus_client::registry::Registry;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
};
use std::{str::FromStr, time::Duration};

fn main() {
    // Initialize runtime
    let runtime_cfg = tokio::Config::default();
    let (executor, runtime) = Executor::init(runtime_cfg.clone());

    // Parse arguments
    let matches = Command::new("commonware-clock")
        .about("TBD")
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
                .help("All participants (arbiter and contributors)"),
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
    tracing::info!(key = hex(&signer.public_key()), "loaded signer");

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
        tracing::info!(key = hex(&verifier), "registered authorized key",);
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

    // Configure network
    let p2p_cfg = authenticated::Config::aggressive(
        signer.clone(),
        Arc::new(Mutex::new(Registry::default())),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        bootstrapper_identities.clone(),
        runtime_cfg.max_message_size,
    );

    // Start runtime
    executor.start(async move {
        let (mut network, mut oracle) = Network::new(runtime.clone(), p2p_cfg);

        // Provide authorized peers
        //
        // In a real-world scenario, this would be updated as new peer sets are created (like when
        // the composition of a validator set changes).
        oracle.register(0, validators.clone()).await;

        // Create validator
        let (resolver_sender, resolver_receiver) = network.register(
            0,
            Quota::per_second(NonZeroU32::new(10).unwrap()),
            1024 * 1024, // 1 MB max message size
            256,         // 256 messages in flight
            Some(3),
        );
        let (voter_sender, voter_receiver) = network.register(
            1,
            Quota::per_second(NonZeroU32::new(10).unwrap()),
            1024 * 1024, // 1 MB max message size
            256,         // 256 messages in flight
            Some(3),
        );

        // Create validator BTree
        let mut validators_map = BTreeMap::new();
        validators_map.insert(0, validators.clone());

        // Start validator
        let namespace: Bytes = "clock".into();
        let hasher = Sha256::default();
        let application = application::Application::<Context, Ed25519, Sha256>::new(
            runtime.clone(),
            hasher.clone(),
            namespace.clone(),
            validators,
        );
        let engine = Engine::new(
            runtime.clone(),
            Config {
                crypto: signer.clone(),
                hasher,
                application,
                registry: Arc::new(Mutex::new(Registry::default())),
                namespace,
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                null_vote_retry: Duration::from_secs(10),
                proposal_retry: Duration::from_millis(100),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: 10,
                max_fetch_count: 32,
                max_fetch_size: 1024 * 512,
                fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                validators: validators_map,
            },
        );
        runtime.spawn(
            "engine",
            engine.run(
                (resolver_sender, resolver_receiver),
                (voter_sender, voter_receiver),
            ),
        );

        // Wait on network
        network.run().await;
    });
}

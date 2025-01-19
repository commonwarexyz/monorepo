//! Commit to a secret log and agree to its hash.
//!
//! This example demonstrates how to build an application that employs [commonware_consensus::simplex].
//! Whenever it is a participant's turn to build a block, they randomly generate a 16-byte secret message and send the
//! hashed message to other participants. Participants use consensus to ensure everyone agrees on the same hash in the same
//! view.
//!
//! # Persistence
//!
//! All consensus data is persisted to disk in the `storage-dir` directory. If you shutdown (whether unclean or not),
//! consensus will resume where it left off when you restart.
//!
//! # Broadcast and Backfilling
//!
//! This example demonstrates how [commonware_consensus::simplex] can minimally be used. It purposely avoids introducing
//! logic to handle broadcasting secret messages and/or backfilling old hashes/messages. Think of this as an exercise
//! for the reader.
//!
//! # Usage (Run at Least 3 to Make Progress)
//!
//! _To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install) and [protoc](https://grpc.io/docs/protoc-installation)._
//!
//! ## Participant 0 (Bootstrapper)
//!
//! ```sh
//! cargo run --release -- --me 0@3000 --participants 0,1,2,3 --storage-dir /tmp/commonware-log/0
//! ```
//!
//! ## Participant 1
//!
//! ```sh
//! cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 1@3001 --participants 0,1,2,3 --storage-dir /tmp/commonware-log/1
//! ```
//!
//! ## Participant 2
//!
//! ```sh
//! cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 2@3002 --participants 0,1,2,3 --storage-dir /tmp/commonware-log/2
//! ```
//!
//! ## Participant 3
//!
//! ```sh
//! cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 3@3003 --participants 0,1,2,3 --storage-dir /tmp/commonware-log/3
//! ```

mod application;
mod gui;

use clap::{value_parser, Arg, Command};
use commonware_consensus::simplex::{self, Engine, Prover};
use commonware_cryptography::{Ed25519, Scheme, Sha256};
use commonware_p2p::authenticated::{self, Network};
use commonware_runtime::{
    tokio::{self, Executor},
    Runner, Spawner,
};
use commonware_storage::journal::{self, Journal};
use commonware_utils::{hex, union};
use governor::Quota;
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
};
use std::{str::FromStr, time::Duration};

/// Unique namespace to avoid message replay attacks.
const APPLICATION_NAMESPACE: &[u8] = b"_COMMONWARE_LOG";

fn main() {
    // Parse arguments
    let matches = Command::new("commonware-log")
        .about("generate secret logs and agree on their hash")
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
        .arg(Arg::new("storage-dir").long("storage-dir").required(true))
        .get_matches();

    // Create GUI
    let gui = gui::Gui::new();

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

    // Configure storage directory
    let storage_directory = matches
        .get_one::<String>("storage-dir")
        .expect("Please provide storage directory");

    // Initialize runtime
    let runtime_cfg = tokio::Config {
        storage_directory: storage_directory.into(),
        ..Default::default()
    };
    let (executor, runtime) = Executor::init(runtime_cfg.clone());

    // Configure network
    let p2p_cfg = authenticated::Config::aggressive(
        signer.clone(),
        &union(APPLICATION_NAMESPACE, b"_P2P"),
        Arc::new(Mutex::new(Registry::default())),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        bootstrapper_identities.clone(),
        1024 * 1024, // 1MB
    );

    // Start runtime
    executor.start(async move {
        let (mut network, mut oracle) = Network::new(runtime.clone(), p2p_cfg);

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
            runtime.clone(),
            journal::Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                partition: String::from("log"),
            },
        )
        .await
        .expect("Failed to initialize journal");

        // Initialize application
        let namespace = union(APPLICATION_NAMESPACE, b"_CONSENSUS");
        let hasher = Sha256::default();
        let prover: Prover<Ed25519, Sha256> = Prover::new(&namespace);
        let (application, supervisor, mailbox) = application::Application::new(
            runtime.clone(),
            application::Config {
                prover,
                hasher: hasher.clone(),
                mailbox_size: 1024,
                participants: validators.clone(),
            },
        );

        // Initialize consensus
        let engine = Engine::new(
            runtime.clone(),
            journal,
            simplex::Config {
                crypto: signer.clone(),
                hasher,
                automaton: mailbox.clone(),
                relay: mailbox.clone(),
                committer: mailbox,
                supervisor,
                registry: Arc::new(Mutex::new(Registry::default())),
                namespace,
                mailbox_size: 1024,
                replay_concurrency: 1,
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: 10,
                max_fetch_count: 32,
                max_fetch_size: 1024 * 512,
                fetch_concurrent: 2,
                fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
            },
        );

        // Start consensus
        runtime.spawn("application", application.run());
        runtime.spawn("network", network.run());
        runtime.spawn(
            "engine",
            engine.run(
                (voter_sender, voter_receiver),
                (resolver_sender, resolver_receiver),
            ),
        );

        // Block on GUI
        gui.run(runtime).await;
    });
}

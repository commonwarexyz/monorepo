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
//! _To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install)._
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
use commonware_consensus::simplex;
use commonware_cryptography::{ed25519, PrivateKeyExt as _, Sha256, Signer as _};
use commonware_p2p::authenticated::discovery;
use commonware_runtime::{tokio, Metrics, Runner};
use commonware_utils::{union, NZU32};
use governor::Quota;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};

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

    // Configure my identity
    let me = matches
        .get_one::<String>("me")
        .expect("Please provide identity");
    let parts = me.split('@').collect::<Vec<&str>>();
    if parts.len() != 2 {
        panic!("Identity not well-formed");
    }
    let key = parts[0].parse::<u64>().expect("Key not well-formed");
    let signer = ed25519::PrivateKey::from_seed(key);
    tracing::info!(key = ?signer.public_key(), "loaded signer");

    // Configure my port
    let port = parts[1].parse::<u16>().expect("Port not well-formed");
    tracing::info!(port, "loaded port");

    // Configure allowed peers
    let mut validators = Vec::new();
    let participants = matches
        .get_many::<u64>("participants")
        .expect("Please provide allowed keys")
        .cloned()
        .collect::<Vec<_>>();
    if participants.is_empty() {
        panic!("Please provide at least one participant");
    }
    for peer in &participants {
        let verifier = ed25519::PrivateKey::from_seed(*peer).public_key();
        tracing::info!(key = ?verifier, "registered authorized key",);
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
            let verifier = ed25519::PrivateKey::from_seed(bootstrapper_key).public_key();
            let bootstrapper_address =
                SocketAddr::from_str(parts[1]).expect("Bootstrapper address not well-formed");
            bootstrapper_identities.push((verifier, bootstrapper_address));
        }
    }

    // Configure storage directory
    let storage_directory = matches
        .get_one::<String>("storage-dir")
        .expect("Please provide storage directory");

    // Initialize context
    let runtime_cfg = tokio::Config::new().with_storage_directory(storage_directory);
    let executor = tokio::Runner::new(runtime_cfg.clone());

    // Configure network
    let p2p_cfg = discovery::Config::aggressive(
        signer.clone(),
        &union(APPLICATION_NAMESPACE, b"_P2P"),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        bootstrapper_identities.clone(),
        1024 * 1024, // 1MB
    );

    // Start context
    executor.start(async |context| {
        // Initialize network
        let (mut network, mut oracle) =
            discovery::Network::new(context.with_label("network"), p2p_cfg);

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
            Quota::per_second(NZU32!(10)),
            256, // 256 messages in flight
        );
        let (resolver_sender, resolver_receiver) = network.register(
            1,
            Quota::per_second(NZU32!(10)),
            256, // 256 messages in flight
        );

        // Initialize application
        let namespace = union(APPLICATION_NAMESPACE, b"_CONSENSUS");
        let (application, supervisor, mailbox) = application::Application::new(
            context.with_label("application"),
            application::Config {
                hasher: Sha256::default(),
                mailbox_size: 1024,
                participants: validators.clone(),
            },
        );

        // Initialize consensus
        let cfg = simplex::Config::<_, _, _, _, _, _> {
            crypto: signer.clone(),
            automaton: mailbox.clone(),
            relay: mailbox.clone(),
            reporter: supervisor.clone(),
            supervisor,
            namespace,
            partition: String::from("log"),
            compression: Some(3),
            mailbox_size: 1024,
            replay_buffer: 1024 * 1024,
            write_buffer: 1024 * 1024,
            leader_timeout: Duration::from_secs(1),
            notarization_timeout: Duration::from_secs(2),
            nullify_retry: Duration::from_secs(10),
            fetch_timeout: Duration::from_secs(1),
            activity_timeout: 10,
            skip_timeout: 5,
            max_fetch_count: 32,
            max_participants: participants.len(),
            fetch_concurrent: 2,
            fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
        };
        let engine = simplex::Engine::new(context.with_label("engine"), cfg);

        // Start consensus
        application.start();
        network.start();
        engine.start(
            (voter_sender, voter_receiver),
            (resolver_sender, resolver_receiver),
        );

        // Block on GUI
        let gui = gui::Gui::new(context.with_label("gui"));
        gui.run().await;
    });
}

//! Commit to a secret log and agree to its hash.
//!
//! This example demonstrates how to build an application that employs [commonware-consensus::simplex`](https://docs.rs/commonware-consensus/latest/commonware_consensus/simplex/index.html).
//! Whenever it is a participants turn to build a block, they randomly generate a 16-byte secret message and send the
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
//! This example demonstrates how `commonware-consensus` can minimally be used. It purposely avoids introducing
//! logic to handle broadcasting secret messages and/or backfilling old hashes/messages. Think of this as an exercise
//! for the reader.
//!
//! # Usage (Run at Least 3 to Make Progress)
//!
//! _To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install) and [protoc](https://grpc.io/docs/protoc-installation)._
//!
//! ## Generate Shared Secrets
//!
//! _In production, this should be done using a DKG (and with Resharing whenever changing set)._
//!
//! We assign shares to validators based on their order in the sorted list of participants (by public key).
//! The assignments seen below are just the seeds used to derive the public keys and as such do not necessarily
//! align with the share indices.
//!
//! ### Network 1
//!
//! ```sh
//! cargo run --release --bin dealer -- --seed 1 --participants 1,2,3,4
//! ```
//!
//! ```txt
//! polynomial: a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd8e754b2a66d247e9937e35326a36415adfe606082c86bb823a63ba9a2a9c87f146f3d55d067b5f08f768e76f8ea382f2aa2a5bfcfc67656703f15fb905bc271514bfb0be0eb54becaba4743754638b7a1d9d2fbf3d4e2ea07850601f82a1d3ac
//! public: a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd
//! share (index=0 validator=2): 000000003521e062da79bd64dc8c5e0d07f07d64c805a137153ef2e6fa5485d28026990e
//! share (index=1 validator=4): 000000016b63f2c22039b703a52e4903a00986d2ea63361d3a6ef33b00330a52d4dce155
//! share (index=2 validator=3): 000000023fa89505734c5ab4d8727e5011e17fd0fee654d1f05496f0a9660025432adc38
//! share (index=3 validator=1): 0000000325dd6e7ffd4f25c0a992d5fa671a4064594ca15836ee3a06f5ed6748cb1089b8
//! ```
//!
//! ### Network 2
//!
//! ```sh
//! cargo run --release --bin dealer -- --seed 2 --participants 5,6,7,8
//! ```
//!
//! ```txt
//! polynomial: a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f58ff12f093cfbe796aa417ffa938be43cfe13ac8fe8c9bc1fddddfe8de840b8372d3165aa172fe930ed6ade9501dbe2ac80e9c5debaaad3eed786c1670b3f13a03712bfe6f326e57f48bb536522c3fb0a465e95a2de83ef3159675523842ef892
//! public: a311e2573501053c4b0dc00b64462d5d47c787d143a5b3cfe22c16a9023b89734074356ea0ce70ab71fe2042c2e426f5
//! share (index=0 validator=6): 000000004dba2ad66b0bb0760cdfc1b1e51fb96fb3b6bdd8cdd451beca1fb0247b2071c0
//! share (index=1 validator=7): 000000014342ca6e1877c338e416dc67bb836c996ca78e5c99dc12e937008e810c59ba44
//! share (index=2 validator=8): 0000000255ccd5a1f8962ce3e665d75f504d27e33db466838eb38476a162a32e4e73341a
//! share (index=3 validator=5): 00000003116aa51ee1c9702ee092da9099db1347d31fa24aac5c4a680945ee2d416cdf41
//! ```
//!
//!
//! ## Indexer
//!
//! _Stores blocks and threshold finalizations. This isn't necessary in practice (could use separate mechanisms)._
//!
//! ```sh
//! cargo run --release --bin indexer -- --me 0@3000 --participants 1,2,3,4,5,6,7,8 --identity-1 --identity-2
//! ```
//!
//! ## Network 1
//!
//! ### Participant 1 (Bootstrapper)
//!
//! ```sh
//! cargo run --release -- --me 1@3001 --participants 1,2,3,4 --storage-dir /tmp/log/1 --indexer 0@127.0.0.1:3000 --identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd8e754b2a66d247e9937e35326a36415adfe606082c86bb823a63ba9a2a9c87f146f3d55d067b5f08f768e76f8ea382f2aa2a5bfcfc67656703f15fb905bc271514bfb0be0eb54becaba4743754638b7a1d9d2fbf3d4e2ea07850601f82a1d3ac --share 0000000325dd6e7ffd4f25c0a992d5fa671a4064594ca15836ee3a06f5ed6748cb1089b8
//! ```
//!
//! ### Participant 2
//!
//! ```sh
//! cargo run --release -- --me 2@3002 --bootstrappers 1@127.0.0.1:3001 --participants 1,2,3,4 --storage-dir /tmp/log/2 --indexer 0@127.0.0.1:3000 --identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd8e754b2a66d247e9937e35326a36415adfe606082c86bb823a63ba9a2a9c87f146f3d55d067b5f08f768e76f8ea382f2aa2a5bfcfc67656703f15fb905bc271514bfb0be0eb54becaba4743754638b7a1d9d2fbf3d4e2ea07850601f82a1d3ac --share 000000003521e062da79bd64dc8c5e0d07f07d64c805a137153ef2e6fa5485d28026990e
//! ```
//!
//! ### Participant 3
//!
//! ```sh
//! cargo run --release -- --me 3@3003 --bootstrappers 1@127.0.0.1:3001 --participants 1,2,3,4 --storage-dir /tmp/log/3 --indexer 0@127.0.0.1:3000 --identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd8e754b2a66d247e9937e35326a36415adfe606082c86bb823a63ba9a2a9c87f146f3d55d067b5f08f768e76f8ea382f2aa2a5bfcfc67656703f15fb905bc271514bfb0be0eb54becaba4743754638b7a1d9d2fbf3d4e2ea07850601f82a1d3ac --share 000000023fa89505734c5ab4d8727e5011e17fd0fee654d1f05496f0a9660025432adc38
//! ```
//!
//! ### Participant 4
//!
//! ```sh
//! cargo run --release -- --me 4@3004 --bootstrappers 1@127.0.0.1:3001 --participants 1,2,3,4 --storage-dir /tmp/log/4 --indexer 0@127.0.0.1:3000 --identity a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd8e754b2a66d247e9937e35326a36415adfe606082c86bb823a63ba9a2a9c87f146f3d55d067b5f08f768e76f8ea382f2aa2a5bfcfc67656703f15fb905bc271514bfb0be0eb54becaba4743754638b7a1d9d2fbf3d4e2ea07850601f82a1d3ac --share 000000016b63f2c22039b703a52e4903a00986d2ea63361d3a6ef33b00330a52d4dce155
//! ```
//!
//! ## Network 2
//!
//! ### Participant 5
//!
//! ```sh
//! ```

mod application;

use clap::{value_parser, Arg, Command};
use commonware_consensus::simplex::{self, Engine, Prover};
use commonware_cryptography::{
    bls12381::primitives::{
        group,
        poly::{self, Poly},
    },
    Ed25519, Scheme, Sha256,
};
use commonware_p2p::authenticated::{self, Network};
use commonware_runtime::{
    tokio::{self, Executor},
    Runner, Spawner,
};
use commonware_storage::journal::{self, Journal};
use commonware_utils::{from_hex, hex, quorum, union};
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
        .arg(Arg::new("indexer").long("indexer").required(true))
        .arg(Arg::new("identity").long("identity").required(true))
        .arg(Arg::new("share").long("share").required(true))
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

    // Configure storage directory
    let storage_directory = matches
        .get_one::<String>("storage-dir")
        .expect("Please provide storage directory");

    // Configure indexer
    // let indexer = matches
    //     .get_one::<String>("indexer")
    //     .expect("Please provide indexer");
    // let parts = indexer.split('@').collect::<Vec<&str>>();
    // let indexer_key = parts[0]
    //     .parse::<u64>()
    //     .expect("Indexer key not well-formed");
    // let indexer_address = SocketAddr::from_str(parts[1]);
    // TODO: dial indexer (block if can't connect)

    // Configure threshold
    let threshold = quorum(validators.len() as u32).expect("Threshold not well-formed");
    let identity = matches
        .get_one::<String>("identity")
        .expect("Please provide identity");
    let identity = from_hex(identity).expect("Identity not well-formed");
    let identity: Poly<group::Public> =
        Poly::deserialize(&identity, threshold).expect("Identity not well-formed");
    let public = poly::public(&identity);
    let share = matches
        .get_one::<String>("share")
        .expect("Please provide share");
    let share = from_hex(share).expect("Share not well-formed");
    let share = group::Share::deserialize(&share).expect("Share not well-formed");

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
        let prover: Prover<Sha256> = Prover::new(public, &namespace);
        let (application, supervisor, mailbox) = application::Application::new(
            runtime.clone(),
            application::Config {
                prover,
                hasher: hasher.clone(),
                mailbox_size: 1024,
                identity,
                participants: validators.clone(),
                share,
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
        runtime.spawn("network", network.run());
        runtime.spawn(
            "engine",
            engine.run(
                (voter_sender, voter_receiver),
                (resolver_sender, resolver_receiver),
            ),
        );

        // Block on application
        application.run().await;
    });
}

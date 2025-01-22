//! Aggregate signatures from multiple contributors over the BN254 curve.
//!
//! # Usage (3 of 4 Threshold)
//!
//! _To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install) and [protoc](https://grpc.io/docs/protoc-installation)._
//!
//! ## Orchestrator
//! ```bash
//! cargo run --release -- --me 0@3000 --participants 0,1,2,3,4 --contributors 1,2,3,4
//! ```
//!
//! ## Contributor 1
//! ```bash
//! cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 1@3001 --participants 0,1,2,3,4  --orchestrator 0 --contributors 1,2,3,4
//! ```
//!
//! ## Contributor 2
//! ```bash
//! cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 2@3002 --participants 0,1,2,3,4  --orchestrator 0 --contributors 1,2,3,4
//! ```
//!
//! ## Contributor 3
//! ```bash
//! cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 3@3003 --participants 0,1,2,3,4  --orchestrator 0 --contributors 1,2,3,4
//! ```
//!
//! ## Contributor 4
//!
//! ```bash
//! cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 4@3004 --participants 0,1,2,3,4 --orchestrator 0 --contributors 1,2,3,4
//! ```

mod bn254;
mod handlers;

use bn254::Bn254;
use clap::{value_parser, Arg, Command};
use commonware_cryptography::Scheme;
use commonware_p2p::authenticated::{self, Network};
use commonware_runtime::{
    tokio::{self, Executor},
    Runner, Spawner,
};
use commonware_utils::{hex, quorum};
use governor::Quota;
use prometheus_client::registry::Registry;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
};
use std::{str::FromStr, time::Duration};
use tracing::info;

// Unique namespace to avoid message replay attacks.
const APPLICATION_NAMESPACE: &[u8] = b"_COMMONWARE_AGGREGATION_";

fn main() {
    // Initialize runtime
    let runtime_cfg = tokio::Config::default();
    let (executor, runtime) = Executor::init(runtime_cfg.clone());

    // Parse arguments
    let matches = Command::new("commonware-aggregation")
        .about("generate and verify BN254 Multi-Signatures")
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
                .help("All participants (orchestrator and contributors)"),
        )
        .arg(
            Arg::new("orchestrator")
                .long("orchestrator")
                .required(false)
                .value_parser(value_parser!(u64))
                .help("If set, run as a contributor otherwise run as the orchestrator"),
        )
        .arg(
            Arg::new("contributors")
                .long("contributors")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(u64))
                .help("contributors"),
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
    let signer = Bn254::from_seed(key);
    tracing::info!(key = hex(&signer.public_key()), "loaded signer");

    // Configure my port
    let port = parts[1].parse::<u16>().expect("Port not well-formed");
    tracing::info!(port, "loaded port");

    // Configure allowed peers
    let mut recipients = Vec::new();
    let participants = matches
        .get_many::<u64>("participants")
        .expect("Please provide allowed keys")
        .copied();
    if participants.len() == 0 {
        panic!("Please provide at least one participant");
    }
    for peer in participants {
        let verifier = Bn254::from_seed(peer).public_key();
        tracing::info!(key = hex(&verifier), "registered authorized key",);
        recipients.push(verifier);
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
            let verifier = Bn254::from_seed(bootstrapper_key).public_key();
            let bootstrapper_address =
                SocketAddr::from_str(parts[1]).expect("Bootstrapper address not well-formed");
            bootstrapper_identities.push((verifier, bootstrapper_address));
        }
    }

    // Configure network
    const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1 MB
    let p2p_cfg = authenticated::Config::aggressive(
        signer.clone(),
        APPLICATION_NAMESPACE,
        Arc::new(Mutex::new(Registry::default())),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        bootstrapper_identities.clone(),
        MAX_MESSAGE_SIZE,
    );

    // Start runtime
    executor.start(async move {
        let (mut network, mut oracle) = Network::new(runtime.clone(), p2p_cfg);

        // Provide authorized peers
        //
        // In a real-world scenario, this would be updated as new peer sets are created (like when
        // the composition of a validator set changes).
        oracle.register(0, recipients).await;

        // Parse contributors
        let mut contributors = Vec::new();
        let mut contributors_map = HashMap::new();
        let participants = matches
            .get_many::<u64>("contributors")
            .expect("Please provide contributors")
            .copied();
        if participants.len() == 0 {
            panic!("Please provide at least one contributor");
        }
        for peer in participants {
            let signer = Bn254::from_seed(peer);
            let verifier = signer.public_key();
            let verifier_g1 = signer.public_g1();
            tracing::info!(key = hex(&verifier), "registered contributor",);
            contributors.push(verifier.clone());
            contributors_map.insert(verifier, verifier_g1);
        }

        // Infer threshold
        let threshold = quorum(contributors.len() as u32).expect("insufficient participants");
        info!(threshold, "inferred parameters");

        // Check if I am the orchestrator
        const DEFAULT_MESSAGE_BACKLOG: usize = 256;
        const COMPRESSION_LEVEL: Option<i32> = Some(3);
        const AGGREGATION_FREQUENCY: Duration = Duration::from_secs(10);
        if let Some(orchestrator) = matches.get_one::<u64>("orchestrator") {
            // Create contributor
            let (sender, receiver) = network.register(
                0,
                Quota::per_second(NonZeroU32::new(10).unwrap()),
                DEFAULT_MESSAGE_BACKLOG,
                COMPRESSION_LEVEL,
            );
            let orchestrator = Bn254::from_seed(*orchestrator).public_key();
            let contributor =
                handlers::Contributor::new(orchestrator, signer, contributors, threshold as usize);
            runtime.spawn("contributor", contributor.run(sender, receiver));
        } else {
            let (sender, receiver) = network.register(
                0,
                Quota::per_second(NonZeroU32::new(10).unwrap()),
                DEFAULT_MESSAGE_BACKLOG,
                COMPRESSION_LEVEL,
            );
            let orchestrator = handlers::Orchestrator::new(
                runtime.clone(),
                AGGREGATION_FREQUENCY,
                contributors,
                contributors_map,
                threshold as usize,
            );
            runtime.spawn("orchestrator", orchestrator.run(sender, receiver));
        }
        network.run().await;
    });
}

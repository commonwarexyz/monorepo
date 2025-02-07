//! Generate bias-resistant randomness with untrusted contributors using commonware-cryptography and commonware-p2p.
//!
//! Contributors to this VRF connect to each other over commonware-p2p (using ED25519 identities), perform an initial
//! Distributed Key Generation (DKG) to generate a static public key, and then perform a proactive Resharing every 10
//! seconds. After a successful DKG and/or Reshare, contributors generate partial signatures over the round number and
//! gossip them to others in the group (again using commonware-p2p). These partial signatures, when aggregated, form
//! a threshold signature that was not knowable by any contributor prior to collecting `2f + 1` partial signatures.
//!
//! To demonstrate how malicious contributors are handled, the CLI also lets you behave as a "rogue" dealer that generates
//! invalid dealings, a "lazy" dealer only distributes `2f` dealings (force reveal `f`), and/or a "forger" dealer that
//! forges a signature for all contributors.
//!
//! # Joining After a DKG
//!
//! If a new contributor joins the group after a successful DKG, the new contributor will become a player during the next resharing
//! (waiting for dealings on the previous group polynomial). As long as `2f + 1` contributors are online and honest at a time,
//! the new contributor will be able to recover the group public polynomial and generate a share that can be used to generate valid
//! partial signatures. They will also be able to participate (share commitment/shares) in future resharings.
//!
//! # Trust Assumptions
//!
//! In this example, the arbiter is trusted. It tracks commitments, acknowledgements, and reveals submitted
//! by contributors. As alluded to in the arbiter docs, production deployments of the arbiter should be run by all
//! contributors over a replicated log (commonly instantiated with a BFT consensus algorithm). This ensures that all
//! correct contributors have the same view of the arbiter's state at the end of a round.
//!
//! `2f + 1` contributors are assumed to be honest and online and any `2f + 1` partial signatures can be used to construct
//! a threshold signature. `f` contributors can behave arbitrarily and will not be able to interrupt a DKG, Resharing, or Threshold
//! Signature. Incorrect contributors will be identified by the arbiter and reported at the end of each DKG/Resharing.
//!
//! # Usage (3 of 4 Threshold)
//!
//! _To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install) and [protoc](https://grpc.io/docs/protoc-installation)._
//!
//! ## Arbiter
//! ```bash
//! cargo run --release -- --me 0@3000 --participants 0,1,2,3,4 --contributors 1,2,3,4
//! ```
//!
//! ## Contributor 1
//! ```bash
//! cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 1@3001 --participants 0,1,2,3,4  --arbiter 0 --contributors 1,2,3,4
//! ```
//!
//! ## Contributor 2
//! ```bash
//! cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 2@3002 --participants 0,1,2,3,4  --arbiter 0 --contributors 1,2,3,4
//! ```
//!
//! ## Contributor 3
//! ```bash
//! cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 3@3003 --participants 0,1,2,3,4  --arbiter 0 --contributors 1,2,3,4
//! ```
//!
//! ## Contributor 4 (Corrupt)
//!
//! _Send invalid dealings to contributors._
//!
//! ```bash
//! cargo run --release -- --corrupt --bootstrappers 0@127.0.0.1:3000 --me 4@3004 --participants 0,1,2,3,4 --arbiter 0 --contributors 1,2,3,4
//! ```
//!
//! ## Contributor 4 (Lazy)
//!
//! _Only send `2f` dealings to contributors (force reveal `f`)._
//!
//! ```bash
//! cargo run --release -- --lazy --bootstrappers 0@127.0.0.1:3000 --me 4@3004 --participants 0,1,2,3,4 --arbiter 0 --contributors 1,2,3,4
//! ```
//!
//! ## Contributor 4 (Forger)
//!
//! _Forge acknowledgements from contributors._
//!
//! ```bash
//! cargo run --release -- --forger --bootstrappers 0@127.0.0.1:3000 --me 4@3004 --participants 0,1,2,3,4 --arbiter 0 --contributors 1,2,3,4
//! ```

mod handlers;

use clap::{value_parser, Arg, Command};
use commonware_cryptography::{Ed25519, Scheme};
use commonware_p2p::authenticated::{self, Network};
use commonware_runtime::{
    tokio::{self, Executor},
    Runner, Spawner,
};
use commonware_utils::quorum;
use governor::Quota;
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
};
use std::{str::FromStr, time::Duration};
use tracing::info;

// Unique namespace to avoid message replay attacks.
const APPLICATION_NAMESPACE: &[u8] = b"_COMMONWARE_VRF_";

fn main() {
    // Initialize runtime
    let runtime_cfg = tokio::Config::default();
    let (executor, runtime) = Executor::init(runtime_cfg.clone());

    // Parse arguments
    let matches = Command::new("commonware-vrf")
        .about("generate bias-resistant randomness with friends")
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
        .arg(
            Arg::new("arbiter")
                .long("arbiter")
                .required(false)
                .value_parser(value_parser!(u64))
                .help("If set, run as a contributor otherwise run as the arbiter"),
        )
        .arg(
            Arg::new("contributors")
                .long("contributors")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(u64))
                .help("contributors"),
        )
        .arg(
            Arg::new("corrupt")
                .long("corrupt")
                .num_args(0)
                .help("Send invalid dealings to contributors"),
        )
        .arg(
            Arg::new("lazy")
                .long("lazy")
                .num_args(0)
                .help("Only send 2f dealings to contributors (force reveal f)"),
        )
        .arg(
            Arg::new("forger")
                .long("forger")
                .num_args(0)
                .help("Forge acknowledgements from contributors"),
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
    let mut recipients = Vec::new();
    let participants = matches
        .get_many::<u64>("participants")
        .expect("Please provide allowed keys")
        .copied();
    if participants.len() == 0 {
        panic!("Please provide at least one participant");
    }
    for peer in participants {
        let verifier = Ed25519::from_seed(peer).public_key();
        tracing::info!(key = ?verifier, "registered authorized key",);
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
            let verifier = Ed25519::from_seed(bootstrapper_key).public_key();
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
        let participants = matches
            .get_many::<u64>("contributors")
            .expect("Please provide contributors")
            .copied();
        if participants.len() == 0 {
            panic!("Please provide at least one contributor");
        }
        for peer in participants {
            let verifier = Ed25519::from_seed(peer).public_key();
            tracing::info!(key = ?verifier, "registered contributor",);
            contributors.push(verifier);
        }

        // Infer threshold
        let threshold = quorum(contributors.len() as u32).expect("insufficient participants");
        info!(threshold, "inferred parameters");

        // Check if I am the arbiter
        const DEFAULT_MESSAGE_BACKLOG: usize = 256;
        const COMPRESSION_LEVEL: Option<i32> = Some(3);
        const DKG_FREQUENCY: Duration = Duration::from_secs(10);
        const DKG_PHASE_TIMEOUT: Duration = Duration::from_secs(1);
        if let Some(arbiter) = matches.get_one::<u64>("arbiter") {
            // Create contributor
            let corrupt = matches.get_flag("corrupt");
            let lazy = matches.get_flag("lazy");
            let forger = matches.get_flag("forger");
            let (contributor_sender, contributor_receiver) = network.register(
                handlers::DKG_CHANNEL,
                Quota::per_second(NonZeroU32::new(10).unwrap()),
                DEFAULT_MESSAGE_BACKLOG,
                COMPRESSION_LEVEL,
            );
            let arbiter = Ed25519::from_seed(*arbiter).public_key();
            let (contributor, requests) = handlers::Contributor::new(
                runtime.clone(),
                signer,
                DKG_PHASE_TIMEOUT,
                arbiter,
                contributors.clone(),
                corrupt,
                lazy,
                forger,
            );
            runtime.spawn(
                "contributor",
                contributor.run(contributor_sender, contributor_receiver),
            );

            // Create vrf
            let (vrf_sender, vrf_receiver) = network.register(
                handlers::VRF_CHANNEL,
                Quota::per_second(NonZeroU32::new(10).unwrap()),
                DEFAULT_MESSAGE_BACKLOG,
                None,
            );
            let signer = handlers::Vrf::new(
                runtime.clone(),
                Duration::from_secs(5),
                threshold,
                contributors,
                requests,
            );
            runtime.spawn("signer", signer.run(vrf_sender, vrf_receiver));
        } else {
            let (arbiter_sender, arbiter_receiver) = network.register(
                handlers::DKG_CHANNEL,
                Quota::per_second(NonZeroU32::new(10).unwrap()),
                DEFAULT_MESSAGE_BACKLOG,
                COMPRESSION_LEVEL,
            );
            let arbiter: handlers::Arbiter<_, Ed25519> = handlers::Arbiter::new(
                runtime.clone(),
                DKG_FREQUENCY,
                DKG_PHASE_TIMEOUT,
                contributors,
                threshold,
            );
            runtime.spawn("arbiter", arbiter.run(arbiter_sender, arbiter_receiver));
        }
        network.run().await;
    });
}

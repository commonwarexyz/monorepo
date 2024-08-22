//! Send encrypted messages to a group of friends using [commonware-p2p](https://crates.io/crates/commonware-p2p).
//!
//! # Usage (4 Friends)
//!
//! ## Friend 1 (Bootstrapper)
//!
//! ```sh
//! cargo run --release -- --me=1@3001 --friends=1,2,3,4
//! ```
//!
//! ## Friend 2
//!
//! ```sh
//! cargo run --release -- --me=2@3002 --friends=1,2,3,4 --bootstrappers=1@127.0.0.1:3001
//! ```
//!
//! ### Friend 3
//!
//! ```sh
//! cargo run --release -- --me=3@3003 --friends=1,2,3,4 --bootstrappers=1@127.0.0.1:3001
//! ```
//!
//! ### Friend 4 (Different Friend as Bootstrapper)
//!
//! ```sh
//! cargo run --release -- --me=4@3004 --friends=1,2,3,4 --bootstrappers=3@127.0.0.1:3003
//! ```
//!
//! ### Not Friend (Blocked)
//!
//! ```sh
//! cargo run --release -- --me=5@3005 --friends=1,2,3,4,5 --bootstrappers=1@127.0.0.1:3001
//! ```

#[doc(hidden)]
mod handler;
#[doc(hidden)]
mod logger;

use clap::{value_parser, Arg, Command};
use commonware_cryptography::{ed25519, Scheme};
use commonware_p2p::{Config, Network};
use governor::Quota;
use prometheus_client::registry::Registry;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tracing::info;

#[doc(hidden)]
#[tokio::main]
async fn main() {
    // Parse arguments
    let matches = Command::new("commonware-chat")
        .about("send encrypted messages to a group of friends")
        .arg(Arg::new("me").long("me").required(true))
        .arg(
            Arg::new("friends")
                .long("friends")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(u16)),
        )
        .arg(
            Arg::new("bootstrappers")
                .long("bootstrappers")
                .required(false)
                .value_delimiter(',')
                .value_parser(value_parser!(String)),
        )
        .get_matches();

    // Create logger
    let logs = Arc::new(Mutex::new(Vec::new()));
    let writer = logger::Writer::new(logs.clone());
    tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(writer)
        .init();

    // Configure my identity
    let me = matches
        .get_one::<String>("me")
        .expect("Please provide identity");
    let parts = me.split('@').collect::<Vec<&str>>();
    let key = parts[0].parse::<u16>().expect("Key not well-formed");
    let signer = ed25519::insecure_signer(key);
    info!(key = hex::encode(signer.me()), "loaded signer");

    // Configure my port
    let port = parts[1].parse::<u16>().expect("Port not well-formed");
    info!(port, "loaded port");

    // Configure allowed peers
    let mut recipients = Vec::new();
    let allowed_keys = matches
        .get_many::<u16>("friends")
        .expect("Please provide friends to chat with")
        .copied();
    if allowed_keys.len() == 0 {
        panic!("Please provide at least one friend");
    }
    for peer in allowed_keys {
        let verifier = ed25519::insecure_signer(peer).me();
        info!(key = hex::encode(&verifier), "registered authorized key",);
        recipients.push(verifier);
    }

    // Configure bootstrappers (if provided)
    let bootstrappers = matches.get_many::<String>("bootstrappers");
    let mut bootstrapper_identities = Vec::new();
    if let Some(bootstrappers) = bootstrappers {
        for bootstrapper in bootstrappers {
            let parts = bootstrapper.split('@').collect::<Vec<&str>>();
            let bootstrapper_key = parts[0]
                .parse::<u16>()
                .expect("Bootstrapper key not well-formed");
            let verifier = ed25519::insecure_signer(bootstrapper_key).me();
            let bootstrapper_address =
                SocketAddr::from_str(parts[1]).expect("Bootstrapper address not well-formed");
            bootstrapper_identities.push((verifier, bootstrapper_address));
        }
    }

    // Configure network
    let registry = Arc::new(Mutex::new(Registry::with_prefix("p2p")));
    let config = Config::aggressive(
        signer.clone(),
        registry.clone(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        bootstrapper_identities.clone(),
    );
    let (mut network, oracle) = Network::new(config);

    // Provide authorized peers
    //
    // In a real-world scenario, this would be updated as new peer sets are created (like when
    // the composition of a validator set changes).
    oracle.register(0, recipients).await;

    // Initialize chat
    let (chat_sender, chat_receiver) = network.register(
        handler::CHANNEL,
        Quota::per_second(NonZeroU32::new(1).unwrap()),
        1024, // 1 KB max message size
        128,  // 128 messages inflight
    );

    // Start network
    let network_handler = tokio::spawn(network.run());

    // Start chat
    handler::run(
        hex::encode(signer.me()),
        registry,
        logs,
        chat_sender,
        chat_receiver,
    )
    .await;

    // Abort network
    network_handler.abort();
}

//! Send encrypted messages to a group of friends using [commonware-cryptography::ed25519](https://docs.rs/commonware-cryptography/latest/commonware_cryptography/ed25519/index.html)
//! and [commonware-p2p::authenticated](https://docs.rs/commonware-p2p/latest/commonware_p2p/authenticated/index.html).
//!
//! # Offline Friends
//!
//! `commonware-chat` only sends messages to connected friends. If a friend is offline at the time a message is sent,
//! `commonware-p2p::authenticated` will drop the message. You can confirm you are connected to all your friends by
//! checking the value of `p2p_connections` in the "Metrics Panel" in the right corner of the window. This metric should
//! be equal to `count(friends)- 1` (you don't connect to yourself).
//!
//! # Synchronized Friends
//!
//! `commonware-p2p::authenticated` requires all friends to have the same set of friends for friend discovery to work
//! correctly. If you do not synchronize friends, you may be able to form connections between specific friends but may
//! not be able to form connections with all friends. You can learn more about why
//! this is [here](https://docs.rs/commonware-p2p/latest/commonware_p2p/authenticated/index.html#discovery). Other
//! dialects of `commonware-p2p` may not have this requirement.
//!
//! # Usage (4 Friends)
//!
//! _To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install) and [protoc](https://grpc.io/docs/protoc-installation)._
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
use commonware_cryptography::{Ed25519, Signer};
use commonware_p2p::authenticated::{self, Network};
use commonware_runtime::Metrics;
use commonware_runtime::{
    tokio::blob_non_linux::Storage as NonLinuxStorage, tokio::Executor, Runner,
};
use governor::Quota;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tracing::info;

/// Unique namespace to avoid message replay attacks.
const APPLICATION_NAMESPACE: &[u8] = b"commonware-chat";

#[doc(hidden)]
fn main() {
    // Initialize context
    let (executor, context) = Executor::<NonLinuxStorage>::default();

    // Parse arguments
    let matches = Command::new("commonware-chat")
        .about("send encrypted messages to a group of friends")
        .arg(Arg::new("me").long("me").required(true))
        .arg(
            Arg::new("friends")
                .long("friends")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(u64)),
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
    let key = parts[0].parse::<u64>().expect("Key not well-formed");
    let signer = Ed25519::from_seed(key);
    info!(key = ?signer.public_key(), "loaded signer");

    // Configure my port
    let port = parts[1].parse::<u16>().expect("Port not well-formed");
    info!(port, "loaded port");

    // Configure allowed peers
    let mut recipients = Vec::new();
    let allowed_keys = matches
        .get_many::<u64>("friends")
        .expect("Please provide friends to chat with")
        .copied();
    if allowed_keys.len() == 0 {
        panic!("Please provide at least one friend");
    }
    for peer in allowed_keys {
        let verifier = Ed25519::from_seed(peer).public_key();
        info!(key = ?verifier, "registered authorized key");
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
    const MAX_MESSAGE_SIZE: usize = 1024; // 1 KB
    let p2p_cfg = authenticated::Config::aggressive(
        signer.clone(),
        APPLICATION_NAMESPACE,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        bootstrapper_identities.clone(),
        MAX_MESSAGE_SIZE,
    );

    // Start context
    executor.start(async move {
        // Initialize network
        let (mut network, mut oracle) = Network::new(context.with_label("network"), p2p_cfg);

        // Provide authorized peers
        //
        // In a real-world scenario, this would be updated as new peer sets are created (like when
        // the composition of a validator set changes).
        oracle.register(0, recipients).await;

        // Initialize chat
        const MAX_MESSAGE_BACKLOG: usize = 128;
        const COMPRESSION_LEVEL: Option<i32> = Some(3);
        let (chat_sender, chat_receiver) = network.register(
            handler::CHANNEL,
            Quota::per_second(NonZeroU32::new(128).unwrap()),
            MAX_MESSAGE_BACKLOG,
            COMPRESSION_LEVEL,
        );

        // Start network
        let network_handler = network.start();

        // Block on GUI
        handler::run(
            context.with_label("handler"),
            signer.public_key().to_string(),
            logs,
            chat_sender,
            chat_receiver,
        )
        .await;

        // Abort network
        network_handler.abort();
    });
}

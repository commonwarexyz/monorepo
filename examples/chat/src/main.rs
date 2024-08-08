//! Send encrypted messages to a group of friends using [commonware-p2p](https://crates.io/crates/commonware-p2p).

mod handler;
mod logger;

use clap::{value_parser, Arg, Command};
use commonware_p2p::{
    crypto::{self, Crypto},
    Config, Network,
};
use governor::Quota;
use prometheus_client::registry::Registry;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tracing::info;

#[tokio::main]
async fn main() {
    // Parse arguments
    let matches = Command::new("chat")
        .version("0.1")
        .author("Patrick O'Grady <patrick@commonware.xyz>")
        .about("encrypted chat between authorized peers")
        .arg(Arg::new("me").long("me").required(true))
        .arg(
            Arg::new("allowed_keys")
                .long("allowed_keys")
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
    let signer = crypto::ed25519::insecure_signer(key);
    info!(key = hex::encode(signer.me()), "loaded signer");

    // Configure my port
    let port = parts[1].parse::<u16>().expect("Port not well-formed");
    info!(port, "loaded port");

    // Configure allowed peers
    let mut recipients = Vec::new();
    let allowed_keys = matches
        .get_many::<u16>("allowed_keys")
        .expect("Please provide allowed keys")
        .copied();
    if allowed_keys.len() == 0 {
        panic!("Please provide at least one allowed key");
    }
    for peer in allowed_keys {
        let verifier = crypto::ed25519::insecure_signer(peer).me();
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
            let verifier = crypto::ed25519::insecure_signer(bootstrapper_key).me();
            let bootstrapper_address =
                SocketAddr::from_str(parts[1]).expect("Bootstrapper address not well-formed");
            bootstrapper_identities.push((verifier, bootstrapper_address));
        }
    }

    // Configure network
    let registry = Arc::new(Mutex::new(Registry::with_prefix("p2p")));
    let config = Config::default(
        signer.clone(),
        registry.clone(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        bootstrapper_identities.clone(),
        true,
    );
    let (mut network, oracle) = Network::new(config);

    // Provide authorized peers
    //
    // In a real-world scenario, this would be updated as new peer sets are created (like when
    // the composition of a validator set changes).
    oracle.register(0, recipients.clone()).await;

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
        recipients,
        chat_sender,
        chat_receiver,
    )
    .await;

    // Abort network
    network_handler.abort();
}

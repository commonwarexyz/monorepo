use clap::{Arg, Command};
use commonware_cryptography::{
    ed25519::{self, PrivateKey},
    Ed25519, Scheme,
};
use commonware_deployer::Peers;
use commonware_utils::{from_hex, from_hex_formatted};
use reqwest::blocking;
use serde::{Deserialize, Serialize};
use tracing::info;

const FLOOD_NAMESPACE: &[u8] = b"_COMMONWARE_FLOOD";

#[derive(Deserialize, Serialize)]
pub struct Bootstrapper {
    pub public_key: String,
    pub ip: String,
}

#[derive(Deserialize, Serialize)]
pub struct Config {
    pub private_key: String,
    pub port: u16,
    pub allowed_peers: Vec<String>,
    pub bootstrappers: Vec<Bootstrapper>,
    pub message_size: usize,
}

fn main() {
    // Parse arguments
    let matches = Command::new("commonware-flood")
        .about("flood the network with messages")
        .arg(Arg::new("peers").required(true))
        .arg(Arg::new("config").required(true))
        .get_matches();

    // Get public IP
    let ip = blocking::get("http://icanhazip.com")
        .expect("Could not get public IP")
        .text()
        .expect("Could not parse public IP")
        .trim()
        .to_string();

    // Load peers
    let peer_file = matches.get_one::<String>("peers").unwrap();
    let peers_file = std::fs::read_to_string(peer_file).expect("Could not read peers file");
    let peers: Peers = serde_yaml::from_str(&peers_file).expect("Could not parse peers file");
    info!(peers = peers.peers.len(), "loaded peers");

    // Load config
    let config_file = matches.get_one::<String>("config").unwrap();
    let config_file = std::fs::read_to_string(config_file).expect("Could not read config file");
    let config: Config = serde_yaml::from_str(&config_file).expect("Could not parse config file");
    let key = from_hex_formatted(&config.private_key).expect("Could not parse private key");
    let key = PrivateKey::try_from(key).expect("Private key is invalid");
    let signer = <Ed25519 as Scheme>::from(key).expect("Could not create signer");
    info!(
        key = ?signer.public_key(),
        ip,
        port = config.port,
        message_size = config.message_size,
        "loaded config"
    );
}

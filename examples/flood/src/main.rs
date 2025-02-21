use axum::{routing::get, serve, Extension, Router};
use clap::{Arg, Command};
use commonware_cryptography::{
    ed25519::{self, PrivateKey, PublicKey},
    Ed25519, Scheme,
};
use commonware_deployer::Peers;
use commonware_p2p::authenticated;
use commonware_runtime::{
    tokio::{self, Executor},
    Network, Runner, Spawner,
};
use commonware_utils::{from_hex, from_hex_formatted, union};
use governor::Quota;
use prometheus_client::{encoding::text::encode, registry::Registry};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
    str::FromStr,
    sync::{Arc, Mutex},
    u32,
};
use tracing::{info, Level};

const FLOOD_NAMESPACE: &[u8] = b"_COMMONWARE_FLOOD";
const METRICS_PORT: u16 = 9090;

#[derive(Deserialize, Serialize)]
pub struct Config {
    pub private_key: String,
    pub port: u16,
    pub allowed_peers: Vec<String>,
    pub bootstrappers: Vec<String>,
    pub message_size: usize,
}

async fn metrics_handler(registries: Extension<Vec<Arc<Mutex<Registry>>>>) -> String {
    let mut buffer = String::new();
    for registry in registries.iter() {
        let registry = registry.lock().unwrap();
        encode(&mut buffer, &registry).expect("Could not encode metrics");
    }
    buffer
}

fn main() {
    // Create logger
    tracing_subscriber::fmt()
        .json()
        .with_max_level(Level::DEBUG)
        .with_line_number(true)
        .with_file(true)
        .init();

    // Parse arguments
    let matches = Command::new("commonware-flood")
        .about("flood the network with messages")
        .arg(Arg::new("peers").required(true))
        .arg(Arg::new("config").required(true))
        .get_matches();

    // Load peers
    let peer_file = matches.get_one::<String>("peers").unwrap();
    let peers_file = std::fs::read_to_string(peer_file).expect("Could not read peers file");
    let peers: Peers = serde_yaml::from_str(&peers_file).expect("Could not parse peers file");
    let peers: HashMap<PublicKey, String> = peers
        .peers
        .into_iter()
        .map(|peer| {
            let key = from_hex_formatted(&peer.name).expect("Could not parse peer key");
            let key = PublicKey::try_from(key).expect("Peer key is invalid");
            (key, peer.ip)
        })
        .collect();
    info!(peers = peers.len(), "loaded peers");

    // Load config
    let config_file = matches.get_one::<String>("config").unwrap();
    let config_file = std::fs::read_to_string(config_file).expect("Could not read config file");
    let config: Config = serde_yaml::from_str(&config_file).expect("Could not parse config file");
    let key = from_hex_formatted(&config.private_key).expect("Could not parse private key");
    let key = PrivateKey::try_from(key).expect("Private key is invalid");
    let signer = <Ed25519 as Scheme>::from(key).expect("Could not create signer");
    let public_key = signer.public_key();
    let ip = peers
        .get(&public_key)
        .expect("Could not find self in IPs")
        .clone();
    info!(
        ?public_key,
        ip,
        port = config.port,
        message_size = config.message_size,
        "loaded config"
    );

    // Configure peers and bootstrappers
    let peer_keys = peers.keys().cloned().collect::<Vec<_>>();
    let mut bootstrappers = Vec::new();
    for bootstrapper in &config.bootstrappers {
        let key = from_hex_formatted(bootstrapper).expect("Could not parse bootstrapper key");
        let key = PublicKey::try_from(key).expect("Bootstrapper key is invalid");
        let ip = peers.get(&key).expect("Could not find bootstrapper in IPs");
        let bootstrapper_socket = format!("{}:{}", ip, config.port);
        let bootstrapper_socket = SocketAddr::from_str(&bootstrapper_socket)
            .expect("Could not parse bootstrapper socket");
        bootstrappers.push((key, bootstrapper_socket));
    }

    // Initialize runtime
    let runtime_registry = Arc::new(Mutex::new(Registry::with_prefix("runtime")));
    let runtime_cfg = tokio::Config {
        registry: runtime_registry.clone(),
        ..Default::default()
    };
    let (executor, runtime) = Executor::init(runtime_cfg);

    // Configure network
    let p2p_registry = Arc::new(Mutex::new(Registry::with_prefix("p2p")));
    let p2p_cfg = authenticated::Config::aggressive(
        signer.clone(),
        &union(FLOOD_NAMESPACE, b"_P2P"),
        p2p_registry.clone(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.port),
        bootstrappers,
        config.message_size,
    );

    // Start runtime
    executor.start(async move {
        // Start p2p
        let (mut network, mut oracle) = authenticated::Network::new(runtime.clone(), p2p_cfg);

        // Provide authorized peers
        oracle.register(0, peer_keys).await;

        // Register flood channel
        let (flood_sender, flood_receiver) = network.register(
            0,
            Quota::per_second(NonZeroU32::new(u32::MAX).unwrap()),
            256,
            None,
        );

        // Serve metrics
        let metrics = runtime.spawn("metrics", {
            let runtime = runtime.clone();
            async move {
                let app = Router::new()
                    .route("/metrics", get(metrics_handler))
                    .layer(Extension(vec![
                        runtime_registry.clone(),
                        p2p_registry.clone(),
                    ]));
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), METRICS_PORT);
                let listener = runtime
                    .bind(addr)
                    .await
                    .expect("Could not bind to metrics address");
                serve(listener, app.into_make_service())
                    .await
                    .expect("Could not serve metrics");
            }
        });

        // Create p2p
        let p2p = runtime.spawn("p2p", network.run());

        // Create flood
        let flood = runtime.spawn("flood", async move {
            let mut count = 0;
            loop {
                flood_sender
                    .send(count.to_string().into())
                    .await
                    .expect("Could not send flood message");
                count += 1;
            }
        });
    });
}

use axum::{routing::get, serve, Extension, Router};
use clap::{Arg, Command};
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    Ed25519, Scheme,
};
use commonware_deployer::Peers;
use commonware_flood::Config;
use commonware_p2p::{authenticated, Receiver, Recipients, Sender};
use commonware_runtime::{
    tokio::{Context, Executor},
    Metrics, Network, Runner, Spawner,
};
use commonware_utils::{from_hex_formatted, union};
use futures::future::try_join_all;
use governor::Quota;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
    str::FromStr,
};
use tracing::{error, info, Level};

const FLOOD_NAMESPACE: &[u8] = b"_COMMONWARE_FLOOD";
const METRICS_PORT: u16 = 9090;

fn main() {
    // Parse arguments
    let matches = Command::new("runner")
        .about("flood the network with messages")
        .arg(Arg::new("peers").required(true))
        .arg(Arg::new("config").required(true))
        .get_matches();

    // Create logger
    tracing_subscriber::fmt()
        .json()
        .with_max_level(Level::DEBUG)
        .with_line_number(true)
        .with_file(true)
        .init();

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
    let (executor, context) = Executor::default();

    // Configure network
    let p2p_cfg = authenticated::Config::aggressive(
        signer.clone(),
        &union(FLOOD_NAMESPACE, b"_P2P"),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.port),
        bootstrappers,
        config.message_size,
    );

    // Start runtime
    executor.start(async move {
        // Start p2p
        let (mut network, mut oracle) =
            authenticated::Network::new(context.with_label("network"), p2p_cfg);

        // Provide authorized peers
        oracle.register(0, peer_keys).await;

        // Register flood channel
        let (mut flood_sender, mut flood_receiver) = network.register(
            0,
            Quota::per_second(NonZeroU32::new(u32::MAX).unwrap()),
            256,
            None,
        );

        // Serve metrics
        let metrics = context.with_label("metrics").spawn(|context| async move {
            let app = Router::new().route(
                "/metrics",
                get(|extension: Extension<Context>| async move { extension.0.encode() }),
            );
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), METRICS_PORT);
            let listener = context
                .bind(addr)
                .await
                .expect("Could not bind to metrics address");
            serve(listener, app.into_make_service())
                .await
                .expect("Could not serve metrics");
        });

        // Create network
        let p2p = network.start();

        // Create flood
        let flood_sender = context
            .with_label("flood_sender")
            .spawn(move |_| async move {
                let mut rng = StdRng::seed_from_u64(0);
                loop {
                    // Create message
                    let mut msg = Vec::with_capacity(config.message_size);
                    rng.fill_bytes(&mut msg);

                    // Send to all peers
                    if let Err(e) = flood_sender.send(Recipients::All, msg.into(), false).await {
                        error!(?e, "could not send flood message");
                    }
                }
            });
        let flood_receiver = context.with_label("flood_receiver").spawn(|_| async move {
            loop {
                if let Err(e) = flood_receiver.recv().await {
                    error!(?e, "could not receive flood message");
                }
            }
        });

        // Wait for any task to error
        if let Err(e) = try_join_all(vec![metrics, p2p, flood_sender, flood_receiver]).await {
            error!(?e, "task failed");
        }
    });
}

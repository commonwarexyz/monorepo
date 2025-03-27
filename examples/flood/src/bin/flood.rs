use clap::{Arg, Command};
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    Ed25519, Signer,
};
use commonware_deployer::ec2::{Peers, METRICS_PORT};
use commonware_flood::Config;
use commonware_p2p::{authenticated, Receiver, Recipients, Sender};
use commonware_runtime::{telemetry, tokio, Metrics, Runner, Spawner};
use commonware_utils::{from_hex_formatted, union};
use futures::future::try_join_all;
use governor::Quota;
use prometheus_client::metrics::counter::Counter;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
    str::FromStr,
    sync::atomic::AtomicU64,
};
use tracing::{error, info, Level};

const FLOOD_NAMESPACE: &[u8] = b"_COMMONWARE_FLOOD";

fn main() {
    // Parse arguments
    let matches = Command::new("runner")
        .about("Spam peers with random messages.")
        .arg(Arg::new("peers").long("peers").required(true))
        .arg(Arg::new("config").long("config").required(true))
        .get_matches();

    // Load peers
    let peer_file = matches.get_one::<String>("peers").unwrap();
    let peers_file = std::fs::read_to_string(peer_file).expect("Could not read peers file");
    let peers: Peers = serde_yaml::from_str(&peers_file).expect("Could not parse peers file");
    let peers: HashMap<PublicKey, IpAddr> = peers
        .peers
        .into_iter()
        .map(|peer| {
            let key = from_hex_formatted(&peer.name).expect("Could not parse peer key");
            let key = PublicKey::try_from(key).expect("Peer key is invalid");
            (key, peer.ip)
        })
        .collect();

    // Load config
    let config_file = matches.get_one::<String>("config").unwrap();
    let config_file = std::fs::read_to_string(config_file).expect("Could not read config file");
    let config: Config = serde_yaml::from_str(&config_file).expect("Could not parse config file");

    // Initialize runtime
    let cfg = tokio::Config {
        worker_threads: config.worker_threads,
        ..Default::default()
    };
    let (executor, context) = tokio::Executor::init(cfg);

    // Start runtime
    executor.start(async move {
        // Configure telemetry
        telemetry::init(
            context.with_label("telemetry"),
            Level::DEBUG.as_str(),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                METRICS_PORT,
            )),
            Some(telemetry::traces::exporter::Config {
                endpoint: format!("http://{}:4318/v1/traces", peers.private_monitoring_ip),
                name: "flood".to_string(),
                rate: 0.001,
            }),
        );

        // Parse config
        info!(peers = peers.len(), "loaded peers");
        let key = from_hex_formatted(&config.private_key).expect("Could not parse private key");
        let key = PrivateKey::try_from(key).expect("Private key is invalid");
        let signer = <Ed25519 as Signer>::from(key).expect("Could not create signer");
        let public_key = signer.public_key();
        let ip = peers.get(&public_key).expect("Could not find self in IPs");
        info!(
            ?public_key,
            ?ip,
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

        // Configure network
        let mut p2p_cfg = authenticated::Config::aggressive(
            signer.clone(),
            &union(FLOOD_NAMESPACE, b"_P2P"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), config.port),
            SocketAddr::new(*ip, config.port),
            bootstrappers,
            config.message_size,
        );
        p2p_cfg.mailbox_size = config.mailbox_size;

        // Start p2p
        let (mut network, mut oracle) =
            authenticated::Network::new(context.with_label("network"), p2p_cfg);

        // Provide authorized peers
        oracle.register(0, peer_keys.clone()).await;

        // Register flood channel
        let (mut flood_sender, mut flood_receiver) = network.register(
            0,
            Quota::per_second(NonZeroU32::new(u32::MAX).unwrap()),
            config.message_backlog,
            None,
        );

        // Create network
        let p2p = network.start();

        // Remove self from valid recipients
        let valid_recipients: Vec<PublicKey> = peer_keys
            .into_iter()
            .filter(|key| *key != public_key)
            .collect();

        // Create flood
        let flood_sender = context
            .with_label("flood_sender")
            .spawn(move |context| async move {
                let mut rng = StdRng::seed_from_u64(0);
                let messages: Counter<u64, AtomicU64> = Counter::default();
                context.register("messages", "Sent messages", messages.clone());
                loop {
                    // Create message
                    let mut msg = vec![0; config.message_size];
                    rng.fill_bytes(&mut msg);

                    // Send to all peers
                    let recipient_index = rng.gen_range(0..valid_recipients.len());
                    let recipient = Recipients::One(valid_recipients[recipient_index].clone());
                    if let Err(e) = flood_sender.send(recipient, msg.into(), false).await {
                        error!(?e, "could not send flood message");
                    }
                    messages.inc();
                }
            });
        let flood_receiver =
            context
                .with_label("flood_receiver")
                .spawn(move |context| async move {
                    let messages: Counter<u64, AtomicU64> = Counter::default();
                    context.register("messages", "Received messages", messages.clone());
                    loop {
                        if let Err(e) = flood_receiver.recv().await {
                            error!(?e, "could not receive flood message");
                        }
                        messages.inc();
                    }
                });

        // Wait for any task to error
        if let Err(e) = try_join_all(vec![p2p, flood_sender, flood_receiver]).await {
            error!(?e, "task failed");
        }
    });
}

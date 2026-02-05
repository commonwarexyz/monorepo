use clap::{Arg, Command};
use commonware_codec::DecodeExt;
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    Signer as _,
};
use commonware_deployer::aws::{Hosts, METRICS_PORT};
use commonware_flood::Config;
use commonware_p2p::{authenticated::discovery, Manager, Receiver, Recipients, Sender};
use commonware_runtime::{
    telemetry::metrics::histogram::HistogramExt, tokio, Buf, Metrics, Quota, Runner, Spawner,
};
use commonware_utils::{from_hex_formatted, ordered::Set, union, TryCollect, NZU32};
use futures::future::try_join_all;
use prometheus_client::metrics::{counter::Counter, histogram::Histogram};
use rand::{rngs::SmallRng, RngCore, SeedableRng};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::atomic::AtomicU64,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{error, info, Level};

/// Histogram buckets for latency measurement (in seconds).
/// Range from 1ms to 1s for cross-machine network latency.
const LATENCY_BUCKETS: [f64; 10] = [
    0.001, 0.002, 0.005, 0.010, 0.020, 0.050, 0.100, 0.200, 0.500, 1.0,
];

const FLOOD_NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_FLOOD";

fn main() {
    // Parse arguments
    let matches = Command::new("runner")
        .about("Spam peers with random messages.")
        .arg(Arg::new("hosts").long("hosts").required(true))
        .arg(Arg::new("config").long("config").required(true))
        .get_matches();

    // Load hosts
    let hosts_file = matches.get_one::<String>("hosts").unwrap();
    let hosts_file = std::fs::read_to_string(hosts_file).expect("Could not read hosts file");
    let hosts: Hosts = serde_yaml::from_str(&hosts_file).expect("Could not parse hosts file");
    let peers: HashMap<PublicKey, IpAddr> = hosts
        .hosts
        .into_iter()
        .map(|host| {
            let key = from_hex_formatted(&host.name).expect("Could not parse host key");
            let key = PublicKey::decode(key.as_ref()).expect("Peer key is invalid");
            (key, host.ip)
        })
        .collect();

    // Load config
    let config_file = matches.get_one::<String>("config").unwrap();
    let config_file = std::fs::read_to_string(config_file).expect("Could not read config file");
    let mut config: Config =
        serde_yaml::from_str(&config_file).expect("Could not parse config file");

    // Parse config
    info!(peers = peers.len(), "loaded peers");
    let key = from_hex_formatted(&config.private_key).expect("Could not parse private key");
    let key = PrivateKey::decode(key.as_ref()).expect("Private key is invalid");
    let public_key = key.public_key();

    // Initialize runtime
    let cfg = tokio::Config::new().with_worker_threads(config.worker_threads);
    let executor = tokio::Runner::new(cfg);

    // Enforce minimum message size of 8 bytes for timestamp
    config.message_size = config.message_size.max(8);

    // Start runtime
    executor.start(|context| async move {
        // Configure telemetry
        let tracing = if config.instrument {
            Some(tokio::tracing::Config {
                endpoint: format!("http://{}:4318/v1/traces", hosts.monitoring),
                name: public_key.to_string(),
                rate: 1.0,
            })
        } else {
            None
        };
        tokio::telemetry::init(
            context.with_label("telemetry"),
            tokio::telemetry::Logging {
                level: Level::DEBUG,
                json: true,
            },
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                METRICS_PORT,
            )),
            tracing,
        );

        // Log configuration
        let ip = peers.get(&public_key).expect("Could not find self in IPs");
        info!(
            ?public_key,
            ?ip,
            port = config.port,
            message_size = config.message_size,
            "loaded config"
        );

        // Configure peers and bootstrappers
        let peer_keys: Set<_> = peers
            .keys()
            .cloned()
            .try_collect()
            .expect("public keys are unique");
        let mut bootstrappers = Vec::new();
        for bootstrapper in &config.bootstrappers {
            let key = from_hex_formatted(bootstrapper).expect("Could not parse bootstrapper key");
            let key = PublicKey::decode(key.as_ref()).expect("Bootstrapper key is invalid");
            let ip = peers.get(&key).expect("Could not find bootstrapper in IPs");
            let bootstrapper_socket = format!("{}:{}", ip, config.port);
            let bootstrapper_socket = SocketAddr::from_str(&bootstrapper_socket)
                .expect("Could not parse bootstrapper socket");
            bootstrappers.push((key, bootstrapper_socket.into()));
        }

        // Configure network
        let mut p2p_cfg = discovery::Config::local(
            key.clone(),
            &union(FLOOD_NAMESPACE, b"_P2P"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), config.port),
            SocketAddr::new(*ip, config.port),
            bootstrappers,
            config.message_size,
        );
        p2p_cfg.mailbox_size = config.mailbox_size;

        // Start p2p
        let (mut network, mut oracle) =
            discovery::Network::new(context.with_label("network"), p2p_cfg);

        // Provide authorized peers
        oracle.register(0, peer_keys.clone()).await;

        // Register flood channel
        let (mut flood_sender, mut flood_receiver) = network.register(
            0,
            Quota::per_second(NZU32!(u32::MAX)),
            config.message_backlog,
        );

        // Create network
        let p2p = network.start();

        // Create flood
        let flood_sender = context
            .with_label("flood_sender")
            .spawn(move |context| async move {
                let mut rng = SmallRng::seed_from_u64(0);
                let messages: Counter<u64, AtomicU64> = Counter::default();
                context.register("messages", "Sent messages", messages.clone());
                loop {
                    // Create message with timestamp in first 8 bytes
                    let mut msg = vec![0u8; config.message_size as usize];
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64;
                    msg[0..8].copy_from_slice(&now.to_le_bytes());
                    rng.fill_bytes(&mut msg[8..]);

                    // Send to all peers
                    if let Err(e) = flood_sender.send(Recipients::All, msg, true).await {
                        error!(?e, "could not send flood message");
                    }
                    messages.inc();
                }
            });
        let flood_receiver =
            context
                .with_label("flood_receiver")
                .spawn(move |context| async move {
                    let latency = Histogram::new(LATENCY_BUCKETS);
                    context.register("latency", "Message latency in seconds", latency.clone());
                    loop {
                        match flood_receiver.recv().await {
                            Ok((_sender, mut msg)) => {
                                if msg.len() < 8 {
                                    continue;
                                }
                                let sent_ns = msg.get_u64_le();
                                let sent_time = UNIX_EPOCH + Duration::from_nanos(sent_ns);
                                latency.observe_between(sent_time, SystemTime::now());
                            }
                            Err(e) => {
                                error!(?e, "could not receive flood message");
                            }
                        }
                    }
                });

        // Wait for any task to error
        if let Err(e) = try_join_all(vec![p2p, flood_sender, flood_receiver]).await {
            error!(?e, "task failed");
        }
    });
}

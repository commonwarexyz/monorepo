use clap::{Arg, Command};
use commonware_codec::DecodeExt;
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    Signer as _,
};
use commonware_deployer::ec2::{Hosts, METRICS_PORT};
use commonware_flood::Config;
use commonware_p2p::{authenticated::discovery, Manager, Receiver, Recipients, Sender};
use commonware_runtime::{tokio, Metrics, Quota, Runner, Spawner};
use commonware_utils::{from_hex_formatted, ordered::Set, union, TryCollect, NZU32};
use futures::future::try_join_all;
use prometheus_client::metrics::counter::Counter;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::atomic::AtomicU64,
};
use tracing::{error, info, Level};

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
    let config: Config = serde_yaml::from_str(&config_file).expect("Could not parse config file");

    // Parse config
    info!(peers = peers.len(), "loaded peers");
    let key = from_hex_formatted(&config.private_key).expect("Could not parse private key");
    let key = PrivateKey::decode(key.as_ref()).expect("Private key is invalid");
    let public_key = key.public_key();

    // Initialize runtime
    let cfg = tokio::Config::new().with_worker_threads(config.worker_threads);
    let executor = tokio::Runner::new(cfg);

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
        oracle.update(0, peer_keys.clone()).await;

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
                let mut rng = StdRng::seed_from_u64(0);
                let messages: Counter<u64, AtomicU64> = Counter::default();
                context.register("messages", "Sent messages", messages.clone());
                loop {
                    // Create message
                    let mut msg = vec![0; config.message_size as usize];
                    rng.fill_bytes(&mut msg);

                    // Send to all peers
                    if let Err(e) = flood_sender.send(Recipients::All, msg.into(), true).await {
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

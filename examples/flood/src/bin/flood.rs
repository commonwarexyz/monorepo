use axum::{routing::get, serve, Extension, Router};
use clap::{Arg, Command};
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    Ed25519, Scheme,
};
use commonware_deployer::ec2::Peers;
use commonware_flood::Config;
use commonware_p2p::{authenticated, Receiver, Recipients, Sender};
use commonware_runtime::{tokio, Clock, Metrics, Network, Runner, Spawner};
use commonware_utils::{from_hex_formatted, union};
use futures::future::try_join_all;
use governor::Quota;
use opentelemetry::{
    global,
    trace::{TraceError, TracerProvider},
};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::{
    trace::{BatchSpanProcessor, Sampler, SdkTracerProvider, Tracer},
    Resource,
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
    str::FromStr,
    sync::atomic::{AtomicI64, AtomicU64},
    time::Duration,
};
use sysinfo::{Disks, System};
use tracing::{error, info, info_span};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

const SYSTEM_METRICS_REFRESH: Duration = Duration::from_secs(5);
const FLOOD_NAMESPACE: &[u8] = b"_COMMONWARE_FLOOD";
const METRICS_PORT: u16 = 9090;

fn init_tracer(endpoint: &str) -> Result<Tracer, TraceError> {
    // Create the OTLP HTTP exporter
    let exporter = SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .build()?;

    // Configure the batch processor
    let batch_processor = BatchSpanProcessor::builder(exporter).build();

    // Define the resource with service name
    let resource = Resource::builder().with_service_name("flood").build();

    // Build the tracer provider
    let sampler = Sampler::TraceIdRatioBased(0.01);
    let tracer_provider = SdkTracerProvider::builder()
        .with_span_processor(batch_processor)
        .with_resource(resource)
        .with_sampler(sampler)
        .build();

    // Create the tracer and set it globally
    let tracer = tracer_provider.tracer("flood");
    global::set_tracer_provider(tracer_provider);

    Ok(tracer)
}

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
    let monitoring_ip = peers.monitoring_private_ip;
    let peers: HashMap<PublicKey, IpAddr> = peers
        .peers
        .into_iter()
        .map(|peer| {
            let key = from_hex_formatted(&peer.name).expect("Could not parse peer key");
            let key = PublicKey::try_from(key).expect("Peer key is invalid");
            (key, peer.ip)
        })
        .collect();

    // Initialize tracing
    let endpoint = format!("http://{}:4318/v1/traces", monitoring_ip);
    let tracer = init_tracer(&endpoint).expect("Failed to initialize tracer");

    // Create fmt layer for logging
    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_line_number(true)
        .with_file(true);

    // Create a filter layer to set the maximum level to INFO
    let filter = tracing_subscriber::EnvFilter::new("debug");

    // Create OpenTelemetry layer for tracing
    let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    // Combine layers into a single subscriber
    let subscriber = Registry::default()
        .with(filter)
        .with(fmt_layer)
        .with(telemetry_layer);

    // Set the combined subscriber as the global default
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    // Load config
    info!(peers = peers.len(), "loaded peers");
    let config_file = matches.get_one::<String>("config").unwrap();
    let config_file = std::fs::read_to_string(config_file).expect("Could not read config file");
    let config: Config = serde_yaml::from_str(&config_file).expect("Could not parse config file");
    let key = from_hex_formatted(&config.private_key).expect("Could not parse private key");
    let key = PrivateKey::try_from(key).expect("Private key is invalid");
    let signer = <Ed25519 as Scheme>::from(key).expect("Could not create signer");
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

    // Initialize runtime
    let cfg = tokio::Config {
        worker_threads: config.worker_threads,
        ..Default::default()
    };
    let (executor, context) = tokio::Executor::init(cfg);

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

    // Start runtime
    executor.start(async move {
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
                    // Start span
                    let span = info_span!("build_message");
                    let enter = span.enter();

                    // Create message
                    let mut msg = vec![0; config.message_size];
                    rng.fill_bytes(&mut msg);

                    // Send to all peers
                    let recipient_index = rng.gen_range(0..valid_recipients.len());
                    let recipient = Recipients::One(valid_recipients[recipient_index].clone());
                    drop(enter);
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
                        // Receive message
                        if let Err(e) = flood_receiver.recv().await {
                            error!(?e, "could not receive flood message");
                        }
                        messages.inc();
                    }
                });

        // Start system metrics collector
        let system = context.with_label("system").spawn(|context| async move {
            // Register metrics
            let cpu_usage: Gauge<f64, AtomicU64> = Gauge::default();
            context.register("cpu_usage", "CPU usage", cpu_usage.clone());
            let memory_used: Gauge<i64, AtomicI64> = Gauge::default();
            context.register("memory_used", "Memory used", memory_used.clone());
            let memory_free: Gauge<i64, AtomicI64> = Gauge::default();
            context.register("memory_free", "Memory free", memory_free.clone());
            let swap_used: Gauge<i64, AtomicI64> = Gauge::default();
            context.register("swap_used", "Swap used", swap_used.clone());
            let swap_free: Gauge<i64, AtomicI64> = Gauge::default();
            context.register("swap_free", "Swap free", swap_free.clone());
            let disk_used: Gauge<i64, AtomicI64> = Gauge::default();
            context.register("disk_used", "Disk used", disk_used.clone());
            let disk_free: Gauge<i64, AtomicI64> = Gauge::default();
            context.register("disk_free", "Disk free", disk_free.clone());

            // Initialize system info
            let mut sys = System::new_all();
            let mut disks = Disks::new_with_refreshed_list();

            // Check metrics every
            loop {
                // Refresh system info
                sys.refresh_all();
                disks.refresh(true);

                // Update metrics
                cpu_usage.set(sys.global_cpu_usage() as f64);
                memory_used.set(sys.used_memory() as i64);
                memory_free.set(sys.free_memory() as i64);
                swap_used.set(sys.used_swap() as i64);
                swap_free.set(sys.free_swap() as i64);

                // Update disk metrics for root disk
                for disk in disks.list() {
                    if disk.mount_point() == std::path::Path::new("/") {
                        let total = disk.total_space();
                        let available = disk.available_space();
                        let used = total.saturating_sub(available);
                        disk_used.set(used as i64);
                        disk_free.set(available as i64);
                        break;
                    }
                }

                // Wait to pull metrics again
                context.sleep(SYSTEM_METRICS_REFRESH).await;
            }
        });

        // Serve metrics
        let metrics = context.with_label("metrics").spawn(|context| async move {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), METRICS_PORT);
            let listener = context
                .bind(addr)
                .await
                .expect("Could not bind to metrics address");
            let app = Router::new()
                .route(
                    "/metrics",
                    get(|extension: Extension<tokio::Context>| async move { extension.0.encode() }),
                )
                .layer(Extension(context));
            serve(listener, app.into_make_service())
                .await
                .expect("Could not serve metrics");
        });

        // Wait for any task to error
        if let Err(e) = try_join_all(vec![p2p, flood_sender, flood_receiver, system, metrics]).await
        {
            error!(?e, "task failed");
        }
    });
}

//! Commit to a secret log across concurrent producer chains with Multimmit.
//!
//! This is [`examples/log`](https://docs.rs/commonware-log) rebuilt on
//! [commonware_consensus::multimmit]. The difference is the shape of the problem it solves: in
//! Simplex one leader per view proposes one payload, so the log advances one block at a time. In
//! Multimmit configured producers own independent chains and append without waiting for a turn.
//! Consensus authenticates sparse ordering checkpoints; dense history and application delivery are
//! deliberately outside this example. The terminal UI shows producer-chain progress and traces.
//!
//! # Persistence
//!
//! All consensus data is persisted to disk in the `storage-dir` directory. If you shutdown
//! (whether unclean or not), consensus will resume where it left off when you restart.
//!
//! # Key Material
//!
//! Multimmit uses one ordinary BLS12-381 roster plus two independent threshold sharings, one for
//! data availability and one for nullification. This example derives all of it deterministically
//! from the participant list so every node computes the same committee with no setup. A real
//! deployment runs a distributed key generation instead and never shares private material.
//!
//! # Payloads
//!
//! Like `examples/log`, this example omits payload custody and dissemination. Consensus exchanges
//! only commitments and protocol metadata. A production attachment would keep payload bytes
//! outside Multimmit, report their validity and availability through `Automaton`, and use `Relay`
//! notifications to drive its own transport.
//!
//! # Usage (Run at Least 6 to Make Progress)
//!
//! _To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install)._
//!
//! With [mprocs](https://github.com/pvolok/mprocs), `cargo build --release && mprocs` runs the
//! whole committee, one participant per pane. To run them by hand:
//!
//! ## Participant 0 (Bootstrapper)
//!
//! ```sh
//! cargo run --release -- --me 0@3000 --participants 0,1,2,3,4,5 --producers 0,1 --storage-dir /tmp/commonware-log-multimmit/0
//! ```
//!
//! ## Participant 1
//!
//! ```sh
//! cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 1@3001 --participants 0,1,2,3,4,5 --producers 0,1 --storage-dir /tmp/commonware-log-multimmit/1
//! ```
//!
//! Repeat for participants 2 through 5, incrementing the key and port.

mod application;
mod deploy;
mod gui;

use clap::{Parser, Subcommand};
use commonware_consensus::{
    multimmit::{
        Engine, EngineConfig, Profile, Role, Tuning,
        config::Limits,
        mocks::{Committee, NoopReporter},
    },
    types::{Participant, ViewDelta},
};
use commonware_cryptography::{Sha256, Signer as _, bls12381::primitives::variant::MinPk, ed25519};
use commonware_deployer::aws::{Hosts, METRICS_PORT};
use commonware_p2p::{Manager as _, authenticated::discovery};
use commonware_parallel::Rayon;
use commonware_runtime::{
    BufferPoolConfig, Clock as _, Quota, Runner, Spawner as _, Supervisor as _, tokio,
};
use commonware_utils::{NZU32, NZUsize, ordered::Set};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    path::PathBuf,
    str::FromStr,
    time::Duration,
};
use tracing::Level;

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Signature namespace for this example's consensus deployment.
const CONSENSUS_NAMESPACE: &[u8] = b"_COMMONWARE_LOG_MULTIMMIT_CONSENSUS";

/// Network namespace for this example's authenticated peer traffic.
const P2P_NAMESPACE: &[u8] = b"_COMMONWARE_LOG_MULTIMMIT_P2P";

/// Seed every node uses to derive the same committee material.
const COMMITTEE_SEED: u64 = 42;

/// Views kept below the current view.
///
/// The committee is fixed and the engine runs indefinitely, so this window is what bounds memory.
const VIEW_RETENTION: u64 = 64;

/// Tracked payload capacity available to each network and storage buffer size class.
///
/// Equal byte budgets favor the small buffers that dominate this workload without multiplying the
/// largest classes by the same factor.
const BUFFER_POOL_BYTES_PER_CLASS: usize = 128 * 1024 * 1024;

/// How long consensus waits before retrying an empty proposal request.
///
/// This example's automaton always proposes immediately, but keeping the retry bounded makes that
/// policy explicit if the attachment is changed to occasionally decline a request.
const PRODUCTION_RETRY_INTERVAL: Duration = Duration::from_millis(250);

/// How often the status pane requests a fresh machine inspection.
const INSPECTION_INTERVAL: Duration = Duration::from_millis(250);

/// Emit a headless progress log line every this many inspections.
const PROGRESS_EVERY: u64 = 4;

/// Generate secret logs across concurrent producer chains with Multimmit.
#[derive(Parser)]
#[command(name = "commonware-log-multimmit")]
struct Cli {
    /// Generate deployment artifacts.
    #[command(subcommand)]
    command: Option<Command>,

    /// Peers to dial on startup, as `key@host:port`.
    #[arg(long, value_delimiter = ',')]
    bootstrappers: Vec<String>,

    /// This node's identity, as `key@port`.
    #[arg(long)]
    me: Option<String>,

    /// Every participant's key, in committee order.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    participants: Vec<u64>,

    /// Producer keys in chain order. Defaults to every participant.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    producers: Vec<u64>,

    /// Directory for all persisted consensus state.
    #[arg(long)]
    storage_dir: Option<PathBuf>,

    /// Deployer-generated host inventory.
    #[arg(long, requires = "config")]
    hosts: Option<PathBuf>,

    /// Deployer-generated node configuration.
    #[arg(long, requires = "hosts")]
    config: Option<PathBuf>,

    /// Tokio worker threads for local runs.
    #[arg(long, default_value_t = 2)]
    worker_threads: usize,

    /// Parallel verification threads for local runs.
    #[arg(long, default_value_t = 2)]
    compute_threads: usize,

    /// Run without the terminal UI and emit structured logs.
    #[arg(long)]
    headless: bool,

    /// Include debug diagnostics in headless logs.
    #[arg(long, requires = "headless")]
    debug: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a remote deployment bundle.
    Deploy(deploy::Deploy),
}

struct RunConfig {
    key: u64,
    port: u16,
    participants: Vec<u64>,
    producers: Vec<u64>,
    bootstrappers: Vec<(u64, SocketAddr)>,
    listen_ip: IpAddr,
    public_ip: IpAddr,
    storage_dir: PathBuf,
    worker_threads: usize,
    compute_threads: usize,
    headless: bool,
    monitoring_ip: Option<IpAddr>,
    trace_sampling: f64,
    log_level: Level,
}

/// Builds the immutable profile every node in the committee shares.
fn profile(committee: &Committee<MinPk>, index: usize) -> Profile<Sha256, MinPk> {
    Profile::new(
        committee.config.clone(),
        Role::Validator(Participant::new(index as u32)),
        Tuning {
            view_timeout: Duration::from_secs(2),
            production_interval: PRODUCTION_RETRY_INTERVAL,
            view_retention: ViewDelta::new(VIEW_RETENTION),
            ..Tuning::default()
        },
    )
    .expect("profile is valid")
}

fn producer_participants(participants: &[u64], producers: &[u64]) -> Vec<Participant> {
    assert!(
        !participants.is_empty(),
        "please provide at least one participant"
    );
    assert_eq!(
        participants.iter().collect::<BTreeSet<_>>().len(),
        participants.len(),
        "participants must be unique"
    );

    let producers = if producers.is_empty() {
        participants
    } else {
        producers
    };
    assert!(
        !producers.is_empty(),
        "please provide at least one producer"
    );
    assert_eq!(
        producers.iter().collect::<BTreeSet<_>>().len(),
        producers.len(),
        "producers must be unique"
    );
    producers
        .iter()
        .map(|producer| {
            let index = participants
                .iter()
                .position(|participant| participant == producer)
                .expect("every producer must be a participant");
            Participant::from_usize(index)
        })
        .collect()
}

fn main() {
    let cli = Cli::parse();

    if let Some(Command::Deploy(args)) = cli.command {
        tracing_subscriber::fmt().init();
        args.run();
        return;
    }

    let config = load_run_config(cli);

    // Configure allowed peers
    let producers = producer_participants(&config.participants, &config.producers);
    let index = config
        .participants
        .iter()
        .position(|participant| *participant == config.key)
        .expect("this node must be a participant");

    // Configure my identity
    let key = config.key;
    let port = config.port;
    let signer = ed25519::PrivateKey::from_seed(key);

    // Derive the committee every node shares.
    //
    // The mock committee exists so tests can build real BLS material without a ceremony; this
    // example reuses it for the same reason, which is why every node passes the same seed.
    let committee = Committee::<MinPk>::new_with_namespace_and_producers(
        COMMITTEE_SEED,
        CONSENSUS_NAMESPACE,
        u32::try_from(config.participants.len()).expect("too many participants"),
        producers,
        Limits::new(2, 1).expect("limits are valid"),
    );
    let validators = Set::try_from(committee.identities.clone()).expect("participants are unique");

    // Configure bootstrappers (if provided)
    let mut bootstrapper_identities = Vec::new();
    for (key, address) in &config.bootstrappers {
        let position = config
            .participants
            .iter()
            .position(|participant| participant == key)
            .expect("bootstrapper must be a participant");
        bootstrapper_identities.push((committee.identities[position].clone(), (*address).into()));
    }

    // Initialize context
    let buffer_pool_parallelism = NZUsize!(config.worker_threads);
    let network_buffer_pool = BufferPoolConfig::for_network()
        .with_bytes_per_class(NZUsize!(BUFFER_POOL_BYTES_PER_CLASS))
        .with_parallelism(buffer_pool_parallelism);
    let storage_buffer_pool = BufferPoolConfig::for_storage()
        .with_bytes_per_class(NZUsize!(BUFFER_POOL_BYTES_PER_CLASS))
        .with_parallelism(buffer_pool_parallelism);
    let runtime_cfg = tokio::Config::new()
        .with_worker_threads(config.worker_threads)
        .with_storage_directory(&config.storage_dir)
        .with_network_buffer_pool_config(network_buffer_pool)
        .with_storage_buffer_pool_config(storage_buffer_pool);
    let executor = tokio::Runner::new(runtime_cfg);

    // Configure network
    let p2p_cfg = discovery::Config::local(
        committee.network_keys[index].clone(),
        P2P_NAMESPACE,
        SocketAddr::new(config.listen_ip, port),
        SocketAddr::new(config.public_ip, port),
        bootstrapper_identities,
        1024 * 1024, // 1MB
    );

    executor.start(async |context| {
        let gui = if config.headless {
            let traces = config.monitoring_ip.and_then(|monitoring_ip| {
                (config.trace_sampling > 0.0).then(|| tokio::tracing::Config {
                    endpoint: format!("http://{monitoring_ip}:4318/v1/traces"),
                    name: key.to_string(),
                    rate: config.trace_sampling,
                })
            });
            tokio::telemetry::init(
                context.child("telemetry"),
                tokio::telemetry::Logs {
                    level: config.log_level,
                    json: true,
                },
                config
                    .monitoring_ip
                    .map(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), METRICS_PORT)),
                traces,
            );
            None
        } else {
            let status = gui::EngineStatus::default();
            let local_chain = committee
                .config
                .producer_chain(Participant::from_usize(index))
                .map(|chain| chain.get());
            let gui = gui::Gui::new(
                context.child("gui"),
                status.clone(),
                u32::try_from(index).expect("participant index is representable"),
                local_chain,
            );
            Some((gui, status))
        };
        tracing::info!(key = ?signer.public_key(), port, "loaded signer");

        // Initialize network
        let (mut network, mut oracle) = discovery::Network::new(context.child("network"), p2p_cfg);
        oracle.track(0, validators);

        // Register one channel per Multimmit protocol plane.
        //
        // Views here are not paced by a timer: a view exits as soon as its V-QC forms, so the
        // consensus plane carries n-f votes per view at whatever rate the network sustains. A
        // quota sized for one view per second (as in `examples/log`, which runs Simplex) would
        // throttle view exits while the producer chains, paced separately by their own
        // certificates, kept running.
        let quota = Quota::per_second(NZU32!(1_024));
        let data = network.register(0, quota, 256);
        let consensus = network.register(1, quota, 256);
        let certificates = network.register(2, quota, 256);
        let resolver = network.register(3, quota, 256);

        // Initialize the application and its shared view
        let application = application::Application::<Sha256>::new(key);

        // Initialize consensus
        let profile = profile(&committee, index);
        let compute_threads =
            NonZeroUsize::new(config.compute_threads).expect("compute threads must be non-zero");
        let strategy = Rayon::new(compute_threads).expect("verification pool starts");
        let engine = Engine::new(
            context.child("engine"),
            EngineConfig {
                scheme: committee.signers[index].clone(),
                automaton: application.clone(),
                relay: application,
                reporter: NoopReporter::default(),
                strategy,
                blocker: oracle,
                profile,
                partition_prefix: String::from("log-multimmit"),
                mailbox_size: NZUsize!(1_024),
            },
        );

        // Start consensus
        network.start();
        let mut running = Box::pin(engine.start(data, consensus, certificates, resolver))
            .await
            .expect("engine starts");
        assert!(running.ready().await, "engine becomes ready");
        let inspector = running.inspector();

        if config.headless {
            let mut ticks = 0u64;
            loop {
                let Some(inspection) = inspector.inspect().await else {
                    break;
                };
                // Emit one progress line per second so external tooling can detect
                // frozen views, halted producers, and unbounded lag from the logs.
                if ticks.is_multiple_of(PROGRESS_EVERY) {
                    let chains = inspection
                        .chain_progress()
                        .iter()
                        .map(|progress| {
                            format!(
                                "C{} known={} certified={} finalized={}",
                                progress.chain(),
                                progress.known(),
                                progress.certified(),
                                progress.finalized(),
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" ");
                    let producer = inspection.producer().map(|producer| {
                        format!(
                            "produced={} certified={} blocked={} credit={}",
                            producer.produced(),
                            producer.certified(),
                            producer.pipeline_blocked(),
                            producer.production_credit(),
                        )
                    });
                    tracing::info!(
                        view = inspection.view().get(),
                        floor = inspection.finality_floor().get(),
                        retired = inspection.retired_view().get(),
                        live = inspection.is_live(),
                        outbox = inspection.outbox().len(),
                        cached = inspection.cached_artifacts(),
                        verify_jobs = inspection.verification_jobs().len(),
                        resolution_jobs = inspection.resolution_jobs(),
                        chains = %chains,
                        producer = producer.as_deref().unwrap_or("none"),
                        "progress"
                    );
                }
                ticks += 1;
                context.sleep(INSPECTION_INTERVAL).await;
            }
            running.abort();
            running.join().await;
            return;
        }

        // Poll outside the GUI so a stuck voter leaves the last snapshot visible. The UI derives
        // unresponsiveness from the snapshot age.
        let (gui, status) = gui.expect("GUI mode initializes tracing before consensus");
        let status_reporter = status.clone();
        context
            .child("inspection")
            .spawn(move |context| async move {
                loop {
                    let Some(inspection) = inspector.inspect().await else {
                        status_reporter.stopped();
                        return;
                    };
                    status_reporter.observed(&inspection);
                    context.sleep(INSPECTION_INTERVAL).await;
                }
            });

        // Block on GUI
        gui.run().await;

        // Keep lifecycle ownership until the UI exits while diagnostics use the cloneable inspector.
        running.abort();
        running.join().await;
    });
}

fn load_run_config(cli: Cli) -> RunConfig {
    if let Some(config_path) = cli.config {
        return load_remote_config(config_path, cli.hosts.expect("hosts are required"));
    }

    let me = cli
        .me
        .expect("--me is required when --config is not provided");
    let (key, port) = me.split_once('@').expect("identity not well-formed");
    let bootstrappers = cli
        .bootstrappers
        .iter()
        .map(|bootstrapper| {
            let (key, address) = bootstrapper
                .split_once('@')
                .expect("bootstrapper not well-formed");
            (
                key.parse::<u64>()
                    .expect("bootstrapper key not well-formed"),
                SocketAddr::from_str(address).expect("bootstrapper address not well-formed"),
            )
        })
        .collect();

    RunConfig {
        key: key.parse().expect("key not well-formed"),
        port: port.parse().expect("port not well-formed"),
        participants: cli.participants,
        producers: cli.producers,
        bootstrappers,
        listen_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        public_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        storage_dir: cli
            .storage_dir
            .expect("--storage-dir is required when --config is not provided"),
        worker_threads: cli.worker_threads,
        compute_threads: cli.compute_threads,
        headless: cli.headless,
        monitoring_ip: None,
        trace_sampling: 0.0,
        log_level: if cli.debug { Level::DEBUG } else { Level::INFO },
    }
}

fn load_remote_config(config_path: PathBuf, hosts_path: PathBuf) -> RunConfig {
    let raw = std::fs::read_to_string(config_path).expect("failed to read node config");
    let config: deploy::NodeConfig = serde_yaml::from_str(&raw).expect("invalid node config");
    let raw = std::fs::read_to_string(hosts_path).expect("failed to read hosts config");
    let hosts: Hosts = serde_yaml::from_str(&raw).expect("invalid hosts config");
    let public_ip = hosts
        .hosts
        .iter()
        .find(|host| host.name == config.key.to_string())
        .expect("node missing from hosts config")
        .ip;
    let bootstrappers = config
        .bootstrappers
        .iter()
        .filter(|key| **key != config.key)
        .map(|key| {
            let host = hosts
                .hosts
                .iter()
                .find(|host| host.name == key.to_string())
                .expect("bootstrapper missing from hosts config");
            (*key, SocketAddr::new(host.ip, config.port))
        })
        .collect();

    RunConfig {
        key: config.key,
        port: config.port,
        participants: config.participants,
        producers: config.producers,
        bootstrappers,
        listen_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        public_ip,
        storage_dir: config.storage_dir,
        worker_threads: config.worker_threads,
        compute_threads: config.compute_threads,
        headless: true,
        monitoring_ip: Some(hosts.monitoring.private),
        trace_sampling: config.trace_sampling,
        log_level: Level::INFO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_is_valid_for_the_shipped_committee() {
        // The profile cross-checks its own bounds, so an over-tight resource limit only shows up
        // at startup. Build it here so the example cannot ship a manifest it rejects.
        for participants in [6u32, 7, 11] {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                COMMITTEE_SEED,
                CONSENSUS_NAMESPACE,
                participants,
                vec![Participant::new(1), Participant::new(participants - 1)],
                Limits::new(2, 1).expect("limits are valid"),
            );
            let _ = profile(&committee, 0);
            let _ = profile(&committee, 1);
        }
    }

    #[test]
    fn producer_keys_define_chain_order() {
        assert_eq!(
            producer_participants(&[10, 20, 30, 40], &[40, 20]),
            [Participant::new(3), Participant::new(1)]
        );
        assert_eq!(
            producer_participants(&[10, 20], &[]),
            [Participant::new(0), Participant::new(1)]
        );
    }
}

//! Commit to a secret log across concurrent producer chains with Multimmit.
//!
//! This is [`examples/log`](https://docs.rs/commonware-log) rebuilt on
//! [commonware_consensus::multimmit]. The difference is the shape of the problem it solves: in
//! Simplex one leader per view proposes one payload, so the log advances one block at a time. In
//! Multimmit configured producers own independent chains and append without waiting for a turn.
//! Consensus authenticates sparse ordering checkpoints, while Multimmit marshal retains complete
//! blocks, repairs missing bodies, reconstructs dense order, and drives an acknowledged
//! application reporter. The terminal UI shows producer-chain progress and that total order.
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
//! Each producer constructs configurable junk bytes in a background task, wraps them in the
//! canonical transaction block, and stages it with marshal before returning its body digest to
//! consensus. Consensus may prepare subsequent blocks while marshal coalesces durability, but it
//! cannot sign a prepared header until the exact block is crash-recoverable. Relay broadcasts the
//! block only after that custody fence. Remote validation subscribes for the exact block and makes
//! it durable before returning success; accepted data-availability evidence activates
//! `commonware-resolver` backfill after loss. Marshal reconstructs finalized order and sends it to
//! a reporter that acknowledges every block after exposing its compact coordinates to the
//! terminal UI.
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
use commonware_actor::Feedback;
use commonware_broadcast::buffered;
use commonware_consensus::{
    Reporter,
    multimmit::{
        Engine, EngineConfig, Profile, Role, Tuning,
        config::Limits,
        marshal::{
            ArchiveConfig, ArchiveMode, Config as MarshalConfig, LqcVerifier, Start, Update,
            open as open_marshal,
        },
        mocks::Committee,
        scheme::bls12381_threshold::Scheme,
        types::Lqc,
    },
    types::{Participant, ViewDelta},
};
use commonware_cryptography::{
    Sha256, Signer as _, bls12381::primitives::variant::MinPk, ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_deployer::aws::{Hosts, METRICS_PORT};
use commonware_p2p::{
    Manager as _,
    authenticated::{self, discovery},
};
use commonware_parallel::{Rayon, Strategy as _};
use commonware_resolver::p2p as resolver;
use commonware_runtime::{
    BufferPoolConfig, Clock as _, Quota, Runner, Spawner as _, Supervisor as _,
    buffer::paged::{self, CacheRef},
    tokio,
};
use commonware_storage::translator::EightCap;
use commonware_utils::{NZU32, NZUsize, ordered::Set};
use std::{
    collections::BTreeSet,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
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

const MARSHAL_RESOLVER_CHANNEL: u64 = 4;
const MARSHAL_BROADCAST_CHANNEL: u64 = 5;

/// Seed every node uses to derive the same committee material.
const COMMITTEE_SEED: u64 = 42;

/// Views kept below the current view.
///
/// The committee is fixed and the engine runs indefinitely, so this window is what bounds memory.
const VIEW_RETENTION: u64 = 64;

/// Maximum blocks appended by one producer-chain proposal.
const PIPELINE_DEPTH: u32 = 32;

/// Maximum blocks carried by one vote extension.
const EXTENSION_BOUND: u32 = 16;

/// Tracked payload capacity available to an ordinary network or storage buffer size class.
const BUFFER_POOL_BASE_CLASS_BYTES: usize = 128 * 1024 * 1024;

/// Tracked payload capacity available to size classes with sustained high concurrency.
const BUFFER_POOL_HOT_CLASS_BYTES: usize = 256 * 1024 * 1024;

fn hot_class_limit(size: NonZeroUsize) -> NonZeroU32 {
    NonZeroU32::new(
        u32::try_from(BUFFER_POOL_HOT_CLASS_BYTES / size.get())
            .expect("hot buffer class count fits u32"),
    )
    .expect("hot buffer classes fit within their byte budget")
}

fn buffer_pool_configs(parallelism: NonZeroUsize) -> (BufferPoolConfig, BufferPoolConfig) {
    // Small network frames and journal/body I/O have the highest sustained buffer concurrency.
    // Other classes retain a uniform byte budget so large, infrequent buffers stay bounded.
    let network = BufferPoolConfig::for_network()
        .with_bytes_per_class(NZUsize!(BUFFER_POOL_BASE_CLASS_BYTES))
        .with_size_class(NZUsize!(1024), hot_class_limit(NZUsize!(1024)))
        .with_size_class(NZUsize!(8 * 1024), hot_class_limit(NZUsize!(8 * 1024)))
        .with_parallelism(parallelism);
    let storage = BufferPoolConfig::for_storage()
        .with_bytes_per_class(NZUsize!(BUFFER_POOL_BASE_CLASS_BYTES));
    let storage_min = storage.min_size();
    let storage = storage
        .with_size_class(storage_min, hot_class_limit(storage_min))
        .with_size_class(
            NZUsize!(1024 * 1024),
            hot_class_limit(NZUsize!(1024 * 1024)),
        )
        .with_size_class(
            NZUsize!(2 * 1024 * 1024),
            hot_class_limit(NZUsize!(2 * 1024 * 1024)),
        )
        .with_parallelism(parallelism);
    (network, storage)
}

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

    /// Bytes of junk data placed in every producer block body.
    #[arg(long, default_value_t = 1_024)]
    body_size: usize,

    /// Bytes reserved for live producer blocks awaiting ordered delivery.
    #[arg(long, default_value_t = deploy::DEFAULT_MARSHAL_LIVE_CACHE_BYTES)]
    marshal_live_cache_bytes: usize,

    /// Bytes reserved for reused historical producer-block reads.
    #[arg(long, default_value_t = deploy::DEFAULT_MARSHAL_MATERIALIZED_CACHE_BYTES)]
    marshal_materialized_cache_bytes: usize,

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
    body_size: usize,
    marshal_live_cache_bytes: usize,
    marshal_materialized_cache_bytes: usize,
    headless: bool,
    monitoring_ip: Option<IpAddr>,
    trace_sampling: f64,
    log_level: Level,
}

#[derive(Clone)]
enum ApplicationReporter {
    Headless(application::NoopReporter),
    Gui(gui::OrderedReporter),
}

impl Reporter for ApplicationReporter {
    type Activity = Update<application::Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match self {
            Self::Headless(reporter) => reporter.report(activity),
            Self::Gui(reporter) => reporter.report(activity),
        }
    }
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

struct CommitteeVerifier(Scheme<ed25519::PublicKey, MinPk>, Rayon, tokio::Context);

impl Clone for CommitteeVerifier {
    fn clone(&self) -> Self {
        Self(self.0.clone(), self.1.clone(), self.2.child("clone"))
    }
}

impl LqcVerifier<Sha256, MinPk> for CommitteeVerifier {
    type Error = &'static str;

    fn verify(
        &mut self,
        proof: &Lqc<MinPk, Sha256Digest>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let scheme = self.0.clone();
        let strategy = self.1.clone();
        let mut context = self.2.child("verify");
        let proof = proof.clone();
        async move {
            let valid = strategy
                .spawn(move |strategy| {
                    scheme
                        .verify_lqc::<_, Sha256, _>(&mut context, &proof, &strategy)
                        .is_some()
                })
                .await;
            if valid {
                Ok(())
            } else {
                Err("committee rejected LQC")
            }
        }
    }
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
    assert!(
        u32::try_from(config.body_size).is_ok(),
        "body size must fit in the canonical bytes codec"
    );
    let max_block_size = application::Body::max_block_size(config.body_size);
    let max_network_message_size = u32::try_from(
        max_block_size
            .checked_add(1_024)
            .expect("encoded block and transport envelope must fit in memory")
            .max(1024 * 1024),
    )
    .expect("encoded block and transport envelope must fit in the network codec");

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
        Limits::new(PIPELINE_DEPTH, EXTENSION_BOUND).expect("limits are valid"),
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
    let (network_buffer_pool, storage_buffer_pool) =
        buffer_pool_configs(NZUsize!(config.worker_threads));
    let runtime_cfg = tokio::Config::new()
        .with_worker_threads(config.worker_threads)
        .with_storage_directory(&config.storage_dir)
        .with_network_buffer_pool_config(network_buffer_pool)
        .with_storage_buffer_pool_config(storage_buffer_pool);
    let executor = tokio::Runner::new(runtime_cfg);

    // Configure network
    let network_key = committee.network_keys[index].clone();
    let max_peers_per_set =
        authenticated::peer_set_limit(validators.iter(), &network_key.public_key());
    let p2p_cfg = discovery::Config::local(
        network_key,
        P2P_NAMESPACE,
        SocketAddr::new(config.listen_ip, port),
        SocketAddr::new(config.public_ip, port),
        bootstrapper_identities,
        max_peers_per_set,
        max_network_message_size,
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
            let (gui, reporter) = gui::Gui::new(
                context.child("gui"),
                status.clone(),
                u32::try_from(index).expect("participant index is representable"),
                local_chain,
            );
            Some((gui, status, reporter))
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
        let data = network.register(0, quota);
        let consensus = network.register(1, quota);
        let certificates = network.register(2, quota);
        let engine_resolver = network.register(3, quota);
        let marshal_resolver = network.register(MARSHAL_RESOLVER_CHANNEL, quota);
        let marshal_broadcast = network.register(MARSHAL_BROADCAST_CHANNEL, quota);
        network.start();

        // Start complete-block broadcast, durable marshal storage, and exact peer backfill.
        let identity = committee.identities[index].clone();
        let (broadcast_engine, buffer) = buffered::Engine::new(
            context.child("body_broadcast"),
            buffered::Config {
                public_key: identity.clone(),
                mailbox_size: NZUsize!(1_024),
                deque_size: 1_024,
                priority: false,
                codec_config: application::Body::codec_config(config.body_size),
                peer_provider: oracle.clone(),
            },
        );
        let broadcast_handle = broadcast_engine.start(marshal_broadcast);
        let archive = ArchiveConfig::new(
            EightCap,
            CacheRef::from_pooler(&context, paged::page_size(4_096), NZUsize!(1_024)),
        );
        let mut marshal_config = MarshalConfig::<EightCap, MinPk, application::Body>::new(
            committee.config.epoch(),
            NonZeroU32::new(
                u32::try_from(committee.codec().chains()).expect("chain count is representable"),
            )
            .expect("the committee has at least one producer chain"),
            Start::Genesis(committee.config.genesis().clone()),
            "log_multimmit_marshal".into(),
            committee.codec(),
            application::Body::codec_config(config.body_size),
            archive,
        )
        .expect("marshal configuration is valid");
        marshal_config.resolver_max_value_bytes =
            NonZeroUsize::new(max_block_size).expect("encoded blocks are non-empty");
        marshal_config.max_hot_block_bytes = NonZeroUsize::new(config.marshal_live_cache_bytes)
            .expect("marshal live cache is non-empty");
        marshal_config.max_materialized_block_bytes =
            NonZeroUsize::new(config.marshal_materialized_cache_bytes)
                .expect("marshal materialized cache is non-empty");
        // Bound one sealed pending segment (the unit of custody reclamation and sealed-reader
        // recovery) to roughly 128 MiB regardless of the configured body size, and keep one
        // maximum admission cut within one segment.
        const PENDING_SEGMENT_TARGET_BYTES: u64 = 128 * 1024 * 1024;
        let pending_segment_items = (PENDING_SEGMENT_TARGET_BYTES
            / u64::try_from(max_block_size).expect("encoded blocks fit in u64"))
        .max(1);
        marshal_config.pending_segment_items = NonZeroU64::new(pending_segment_items)
            .expect("pending segment holds at least one block");
        marshal_config.admission_cut_capacity = NonZeroUsize::new(
            usize::try_from(pending_segment_items.min(1_024)).expect("cut capacity fits usize"),
        )
        .expect("admission cut holds at least one block");
        marshal_config.finalized_lqc = ArchiveMode::Prunable;
        marshal_config.finalized_history = ArchiveMode::Prunable;
        marshal_config.finalized_blocks = ArchiveMode::Prunable;
        let (marshal_service, resolver_bridge) =
            open_marshal::<_, EightCap, Sha256, MinPk, application::Body, ed25519::PublicKey>(
                context.child("marshal"),
                marshal_config,
                buffer,
            )
            .await
            .expect("marshal storage opens");
        let (resolver_engine, resolver_mailbox) = resolver::Engine::new(
            context.child("body_resolver"),
            resolver::Config {
                peer_provider: oracle.clone(),
                blocker: oracle.clone(),
                consumer: resolver_bridge.clone(),
                producer: resolver_bridge,
                mailbox_size: NZUsize!(1_024),
                me: Some(identity),
                initial: Duration::from_secs(1),
                timeout: Duration::from_secs(2),
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
        );
        let resolver_handle = resolver_engine.start(marshal_resolver);
        let compute_threads =
            NonZeroUsize::new(config.compute_threads).expect("compute threads must be non-zero");
        let strategy = Rayon::new(compute_threads).expect("verification pool starts");
        let application_context = context.child("application");
        let application_reporter = gui.as_ref().map_or(
            ApplicationReporter::Headless(application::NoopReporter),
            |(_, _, reporter)| ApplicationReporter::Gui(reporter.clone()),
        );
        let (marshal, marshal_handle) = marshal_service.start(
            resolver_mailbox,
            CommitteeVerifier(
                committee.verifier.clone(),
                strategy.clone(),
                context.child("marshal_verifier"),
            ),
            application_reporter,
        );

        // Match the in-memory body window to consensus's bound on live publication effects.
        let profile = profile(&committee, index);
        let publication_retention = NonZeroUsize::new(profile.resources().max_outbox_effects())
            .expect("the consensus outbox bound is non-zero");
        let proposal_latency =
            application::ProposalLatency::new(&application_context, publication_retention);

        // The automaton owns bodies; consensus receives only their canonical header digests.
        let application = application::Application::new(
            application_context,
            key,
            config.body_size,
            publication_retention,
            marshal.clone(),
            proposal_latency,
        );

        // Initialize consensus
        let engine = Engine::new(
            context.child("engine"),
            EngineConfig {
                scheme: committee.signers[index].clone(),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: application,
                strategy,
                blocker: oracle,
                profile,
                partition_prefix: String::from("log-multimmit"),
                mailbox_size: NZUsize!(1_024),
            },
        );

        // Start consensus
        let mut running = Box::pin(engine.start(data, consensus, certificates, engine_resolver))
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
        } else {
            // Poll outside the GUI so a stuck voter leaves the last snapshot visible. The UI
            // derives unresponsiveness from the snapshot age.
            let (gui, status, _) = gui.expect("GUI mode initializes tracing before consensus");
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
        }

        // Stop every explicitly owned service after the UI exits or consensus stops.
        running.abort();
        running.join().await;
        marshal_handle.abort();
        marshal_handle
            .join()
            .await
            .expect("marshal shuts down cleanly");
        resolver_handle.abort();
        broadcast_handle.abort();
        let _ = resolver_handle.await;
        let _ = broadcast_handle.await;
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
        body_size: cli.body_size,
        marshal_live_cache_bytes: cli.marshal_live_cache_bytes,
        marshal_materialized_cache_bytes: cli.marshal_materialized_cache_bytes,
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
        body_size: config.body_size,
        marshal_live_cache_bytes: config.marshal_live_cache_bytes,
        marshal_materialized_cache_bytes: config.marshal_materialized_cache_bytes,
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
                Limits::new(PIPELINE_DEPTH, EXTENSION_BOUND).expect("limits are valid"),
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

    #[test]
    fn buffer_pools_reserve_headroom_for_hot_classes() {
        let (network, storage) = buffer_pool_configs(NZUsize!(8));
        for size in [1024, 8 * 1024] {
            let class = network.class_for(size).expect("network class is enabled");
            assert_eq!(
                class.size.get() * class.max_buffers.get() as usize,
                BUFFER_POOL_HOT_CLASS_BYTES
            );
        }
        for size in [storage.min_size().get(), 1024 * 1024, 2 * 1024 * 1024] {
            let class = storage.class_for(size).expect("storage class is enabled");
            assert_eq!(
                class.size.get() * class.max_buffers.get() as usize,
                BUFFER_POOL_HOT_CLASS_BYTES
            );
        }
        for pool in [network, storage] {
            assert!(pool.max_tracked_bytes() <= 2 * 1024 * 1024 * 1024);
        }
    }
}

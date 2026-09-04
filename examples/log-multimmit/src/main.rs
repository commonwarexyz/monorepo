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
//! # Network Planes
//!
//! Every node runs two authenticated networks over one identity key. The consensus plane
//! (`port`) carries the data-availability channel, consensus artifacts, certificates, and the
//! engine's artifact resolver. The bulk plane (`port + 1`) carries only complete block bodies:
//! `commonware-broadcast` gossip and the `commonware-resolver` body backfill. A peer sender
//! writes whole messages in priority order, so a vote queued behind a 512 KiB body waits for
//! that body to drain; separate listeners give the two planes separate TCP connections per peer
//! and remove that head-of-line term from every consensus hop.
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
//! cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 1@3002 --participants 0,1,2,3,4,5 --producers 0,1 --storage-dir /tmp/commonware-log-multimmit/1
//! ```
//!
//! Repeat for participants 2 through 5, incrementing the key and advancing the port by two: each
//! node also binds `port + 1` for the bulk plane.

mod application;
mod deploy;
mod gui;

use clap::{Parser, Subcommand};
use commonware_actor::Feedback;
use commonware_broadcast::buffered;
use commonware_codec::EncodeSize as _;
use commonware_consensus::{
    Reporter,
    multimmit::{
        Engine, EngineConfig, Profile, ProposalPolicy, Role, Tuning,
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
    Blocker, Manager as _,
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

/// Network namespace for this example's authenticated consensus-plane traffic.
const P2P_NAMESPACE: &[u8] = b"_COMMONWARE_LOG_MULTIMMIT_P2P";

/// Network namespace for this example's authenticated bulk-plane traffic.
///
/// The bulk plane is a second network reachable on its own port, so it signs handshakes under
/// its own namespace and a handshake for one plane cannot authenticate the other.
const P2P_BULK_NAMESPACE: &[u8] = b"_COMMONWARE_LOG_MULTIMMIT_P2P_BULK";

/// Ports between the consensus listener and the bulk listener.
const BULK_PORT_OFFSET: u16 = 1;

/// Bulk-plane channel carrying exact block backfill.
const MARSHAL_RESOLVER_CHANNEL: u64 = 4;
/// Bulk-plane channel carrying complete block bodies.
const MARSHAL_BROADCAST_CHANNEL: u64 = 5;

/// Body resolver traffic bypasses ordinary outbound traffic.
const BODY_RESOLVER_PRIORITY: bool = true;
/// Maximum producer blocks carried by one bounded finalized-backfill response.
const RESOLVER_RESPONSE_BLOCKS: usize = 16;
/// Maximum bounded finalized-backfill responses held in memory concurrently.
const RESOLVER_CONCURRENT_RESPONSES: usize = 128;

/// Seed every node uses to derive the same committee material.
const COMMITTEE_SEED: u64 = 42;

/// Views kept below the current view.
///
/// The committee is fixed and the engine runs indefinitely, so this window is what bounds memory.
const VIEW_RETENTION: u64 = 64;

/// Default maximum blocks appended by one producer-chain proposal.
///
/// Both pipeline limits are time windows expressed in blocks: they must cover the
/// DA-certificate lag (pipeline depth) and the proposal-tip-to-frontier gap (extension bound)
/// at the configured block rate, so smaller bodies at the same byte throughput need
/// proportionally larger values.
const PIPELINE_DEPTH: u32 = 32;

/// Default maximum blocks carried by one vote extension.
const EXTENSION_BOUND: u32 = 16;

/// Exact application acknowledgements retained while a durable cursor publication is pending.
const DELIVERY_ACK_WINDOW: NonZeroUsize = NZUsize!(2_048);

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

    /// Port for this node's bulk block plane. Defaults to the consensus port plus one.
    #[arg(long)]
    bulk_port: Option<u16>,

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

    /// View-critical cryptography threads for local runs.
    ///
    /// Defaults to the committee-derived width, so a local run only needs this to reproduce a
    /// specific deployment's pool.
    #[arg(long)]
    critical_threads: Option<usize>,

    /// Bytes of junk data placed in every producer block body.
    #[arg(long, default_value_t = 1_024)]
    body_size: usize,

    /// Maximum blocks appended by one producer-chain proposal.
    #[arg(long, default_value_t = PIPELINE_DEPTH)]
    pipeline_depth: u32,

    /// Maximum blocks carried by one vote extension per chain.
    #[arg(long, default_value_t = EXTENSION_BOUND)]
    extension_bound: u32,

    /// How far above its anchor a leader's proposal reaches on each producer chain.
    #[arg(long, value_enum, default_value_t)]
    proposal_policy: deploy::ProposalPolicyArg,

    /// Minimum milliseconds between two blocks built by this producer; zero is unpaced.
    #[arg(long, default_value_t = 0)]
    production_interval_ms: u64,

    /// Independent payload arrival rate per producer; omitted means saturated input.
    #[arg(long)]
    offered_bytes_per_second: Option<NonZeroU64>,

    /// Bytes reserved for live producer blocks awaiting ordered delivery.
    #[arg(long, default_value_t = deploy::DEFAULT_MARSHAL_LIVE_CACHE_BYTES)]
    marshal_live_cache_bytes: usize,

    /// Bytes reserved for reused historical producer-block reads.
    #[arg(long, default_value_t = deploy::DEFAULT_MARSHAL_MATERIALIZED_CACHE_BYTES)]
    marshal_materialized_cache_bytes: usize,

    /// Target encoded bytes per cold application-delivery read.
    #[arg(long)]
    marshal_delivery_bytes: Option<NonZeroUsize>,

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
    bulk_port: u16,
    participants: Vec<u64>,
    producers: Vec<u64>,
    bootstrappers: Vec<(u64, SocketAddr)>,
    preferred_participants: Vec<u64>,
    listen_ip: IpAddr,
    public_ip: IpAddr,
    storage_dir: PathBuf,
    worker_threads: usize,
    compute_threads: usize,
    critical_threads: Option<usize>,
    body_size: usize,
    pipeline_depth: u32,
    extension_bound: u32,
    proposal_policy: ProposalPolicy,
    production_interval: Duration,
    offered_bytes_per_second: Option<NonZeroU64>,
    marshal_live_cache_bytes: usize,
    marshal_materialized_cache_bytes: usize,
    marshal_delivery_bytes: Option<NonZeroUsize>,
    headless: bool,
    monitoring_ip: Option<IpAddr>,
    trace_sampling: f64,
    log_level: Level,
}

/// Consumes the total order: stamps this producer's ordering latency, then hands the block to
/// the configured sink.
#[derive(Clone)]
struct ApplicationReporter {
    latency: application::ProposalLatency,
    sink: OrderedSink,
}

#[derive(Clone)]
enum OrderedSink {
    Headless(application::NoopReporter),
    Gui(gui::OrderedReporter),
}

impl Reporter for ApplicationReporter {
    type Activity = Update<application::Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let Update::Block { block, .. } = &activity;
        self.latency.order(block.reference());
        match &mut self.sink {
            OrderedSink::Headless(reporter) => reporter.report(activity),
            OrderedSink::Gui(reporter) => reporter.report(activity),
        }
    }
}

/// Blocks a peer on the consensus plane and the bulk plane together.
///
/// Each network keeps its own connection to a peer, so a block applied to one plane leaves the
/// other connected. Misbehavior observed anywhere disconnects the peer everywhere.
#[derive(Clone)]
struct BothPlanes {
    consensus: discovery::Oracle<ed25519::PublicKey>,
    bulk: discovery::Oracle<ed25519::PublicKey>,
}

impl BothPlanes {
    const fn new(
        consensus: discovery::Oracle<ed25519::PublicKey>,
        bulk: discovery::Oracle<ed25519::PublicKey>,
    ) -> Self {
        Self { consensus, bulk }
    }
}

impl Blocker for BothPlanes {
    type PublicKey = ed25519::PublicKey;

    #[allow(
        clippy::disallowed_methods,
        reason = "fans out a block already logged by the caller's block! site"
    )]
    fn block(&mut self, peer: Self::PublicKey) -> Feedback {
        // Always attempt both planes, then report the least successful outcome so a caller that
        // treats `Closed` as fatal sees a closed tracker on either plane.
        let consensus = self.consensus.block(peer.clone());
        let bulk = self.bulk.block(peer);
        match (consensus, bulk) {
            (Feedback::Closed, _) | (_, Feedback::Closed) => Feedback::Closed,
            (Feedback::Backoff, _) | (_, Feedback::Backoff) => Feedback::Backoff,
            (Feedback::Ok, Feedback::Ok) => Feedback::Ok,
        }
    }
}

/// Builds the immutable profile every node in the committee shares.
fn profile(
    committee: &Committee<MinPk>,
    index: usize,
    proposal_policy: ProposalPolicy,
) -> Profile<Sha256, MinPk> {
    // The largest artifact grows with participants, chains, pipeline depth, and extension bound
    // together, so the limit follows the committee instead of a fixed figure.
    let defaults = Tuning::default();
    let max_artifact_bytes = committee
        .config
        .codec_config()
        .max_artifact_bytes::<MinPk, Sha256Digest>()
        .expect("protocol bounds are representable")
        .max(defaults.max_artifact_bytes);
    Profile::new(
        committee.config.clone(),
        Role::Validator(Participant::new(index as u32)),
        Tuning {
            view_timeout: Duration::from_secs(2),
            production_interval: PRODUCTION_RETRY_INTERVAL,
            view_retention: ViewDelta::new(VIEW_RETENTION),
            max_artifact_bytes,
            proposal_policy,
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
            let valid = strategy.clone()
                .manual()
                .spawn(1, move |_| {
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

/// Derives a peer's bulk-plane address from its consensus-plane address.
///
/// Every node shifts its bulk listener off its consensus listener by the same offset, so this is
/// the only rule needed to dial a peer on the bulk plane once its consensus address is known.
const fn bulk_address(consensus: SocketAddr, offset: u16) -> SocketAddr {
    let port = consensus
        .port()
        .checked_add(offset)
        .expect("bulk port must be representable");
    SocketAddr::new(consensus.ip(), port)
}

fn resolver_response_capacity(max_block_size: usize) -> usize {
    max_block_size
        .checked_mul(RESOLVER_RESPONSE_BLOCKS)
        .and_then(|bytes| bytes.checked_add(RESOLVER_RESPONSE_BLOCKS.encode_size()))
        .expect("bounded resolver response must fit in memory")
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
    let resolver_max_value_bytes = resolver_response_capacity(max_block_size);
    let max_network_message_size = u32::try_from(
        resolver_max_value_bytes
            .checked_add(1_024)
            .expect("resolver response and transport envelope must fit in memory")
            .max(1024 * 1024),
    )
    .expect("resolver response and transport envelope must fit in the network codec");

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
        Limits::new(config.pipeline_depth, config.extension_bound).expect("limits are valid"),
    );
    let validators = Set::try_from(committee.identities.clone()).expect("participants are unique");
    let preferred_resolver_peers = config
        .preferred_participants
        .iter()
        .map(|key| {
            let position = config
                .participants
                .iter()
                .position(|participant| participant == key)
                .expect("preferred participant must be in the committee");
            committee.identities[position].clone()
        })
        .collect::<Vec<_>>();

    // Configure bootstrappers (if provided)
    //
    // Every node shifts its bulk listener off its consensus listener by the same amount, so a
    // bootstrapper's bulk address is its consensus address shifted by the local offset.
    assert!(
        config.bulk_port > port,
        "bulk port must be above the consensus port"
    );
    let bulk_port_offset = config.bulk_port - port;
    let mut bootstrapper_identities = Vec::new();
    let mut bulk_bootstrapper_identities = Vec::new();
    for (key, address) in &config.bootstrappers {
        let position = config
            .participants
            .iter()
            .position(|participant| participant == key)
            .expect("bootstrapper must be a participant");
        let identity = committee.identities[position].clone();
        bulk_bootstrapper_identities.push((
            identity.clone(),
            bulk_address(*address, bulk_port_offset).into(),
        ));
        bootstrapper_identities.push((identity, (*address).into()));
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
        network_key.clone(),
        P2P_NAMESPACE,
        SocketAddr::new(config.listen_ip, port),
        SocketAddr::new(config.public_ip, port),
        bootstrapper_identities,
        max_peers_per_set,
        max_network_message_size,
    );
    // The bulk plane carries the largest message in the deployment (a bounded backfill response),
    // so it keeps the same ceiling as the consensus plane rather than a tighter one.
    let p2p_bulk_cfg = discovery::Config::local(
        network_key,
        P2P_BULK_NAMESPACE,
        SocketAddr::new(config.listen_ip, config.bulk_port),
        SocketAddr::new(config.public_ip, config.bulk_port),
        bulk_bootstrapper_identities,
        max_peers_per_set,
        max_network_message_size,
    );

    executor.start(async |context| {
        let gui = if config.headless {
            let traces = config.monitoring_ip.and_then(|monitoring_ip| {
                (config.trace_sampling > 0.0).then(|| tokio::tracing::Config {
                    endpoint: format!("http://{monitoring_ip}:4318/v1/traces"),
                    name: key.to_string(),
                    rate: config.trace_sampling.try_into().expect("valid sampling probability"),
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
        tracing::info!(key = ?signer.public_key(), port, bulk_port = config.bulk_port, "loaded signer");

        // Initialize both networks.
        //
        // Complete block bodies get their own listener, and therefore their own TCP connection
        // per peer. A peer sender writes whole messages in priority order, so a vote sharing a
        // connection with a 512 KiB body waits for that body to drain. Both networks track the
        // same peer set at the same index under one identity key.
        let (mut network, mut oracle) = discovery::Network::new(context.child("network"), p2p_cfg);
        oracle.track(0, validators.clone());
        let (mut bulk_network, mut bulk_oracle) =
            discovery::Network::new(context.child("bulk_network"), p2p_bulk_cfg);
        bulk_oracle.track(0, validators);

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
        let marshal_resolver = bulk_network.register(MARSHAL_RESOLVER_CHANNEL, quota);
        let marshal_broadcast = bulk_network.register(MARSHAL_BROADCAST_CHANNEL, quota);
        network.start();
        bulk_network.start();
        let blocker = BothPlanes::new(oracle.clone(), bulk_oracle.clone());

        // Start complete-block broadcast, durable marshal storage, and exact peer backfill.
        // Body decode embeds the full-body digest check, so inbound bodies are decoded on the
        // shared verification pool instead of the broadcast engine's event loop.
        let compute_threads =
            NonZeroUsize::new(config.compute_threads).expect("compute threads must be non-zero");
        let strategy = Rayon::new(compute_threads).expect("verification pool starts");
        let identity = committee.identities[index].clone();
        let (broadcast_engine, buffer) = buffered::Engine::new(
            context.child("body_broadcast"),
            buffered::Config {
                public_key: identity.clone(),
                mailbox_size: NZUsize!(1_024),
                deque_size: 1_024,
                priority: false,
                codec_config: application::Body::codec_config(config.body_size),
                peer_provider: bulk_oracle.clone(),
                blocker: blocker.clone(),
                strategy: strategy.clone(),
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
        marshal_config.max_block_bytes =
            NonZeroUsize::new(max_block_size).expect("encoded blocks are non-empty");
        marshal_config.resolver_max_value_bytes =
            NonZeroUsize::new(resolver_max_value_bytes).expect("resolver responses are non-empty");
        marshal_config.max_backfill_bytes = NonZeroUsize::new(
            resolver_max_value_bytes
                .checked_mul(RESOLVER_CONCURRENT_RESPONSES)
                .expect("concurrent resolver responses fit in memory"),
        )
        .expect("backfill capacity is non-empty");
        marshal_config.max_hot_block_bytes = NonZeroUsize::new(config.marshal_live_cache_bytes)
            .expect("marshal live cache is non-empty");
        marshal_config.max_materialized_block_bytes =
            NonZeroUsize::new(config.marshal_materialized_cache_bytes)
                .expect("marshal materialized cache is non-empty");
        marshal_config.max_pending_acks = DELIVERY_ACK_WINDOW;
        if let Some(bytes) = config.marshal_delivery_bytes {
            marshal_config.max_delivery_bytes = bytes;
        }
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
        let (resolver_engine, resolver_mailbox) = resolver::Engine::new_with_preferred_peers(
            context.child("body_resolver"),
            resolver::Config {
                peer_provider: bulk_oracle,
                blocker: blocker.clone(),
                consumer: resolver_bridge.clone(),
                producer: resolver_bridge,
                mailbox_size: NZUsize!(1_024),
                me: Some(identity),
                timeout: Duration::from_secs(2),
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: BODY_RESOLVER_PRIORITY,
                priority_responses: BODY_RESOLVER_PRIORITY,
            },
            preferred_resolver_peers,
        );
        let resolver_handle = resolver_engine.start(marshal_resolver);
        let application_context = context.child("application");
        // Match the in-memory body window to consensus's bound on live publication effects.
        let profile = profile(&committee, index, config.proposal_policy);
        let publication_retention = NonZeroUsize::new(profile.resources().max_outbox_effects())
            .expect("the consensus outbox bound is non-zero");
        let application_metrics =
            application::ApplicationMetrics::new(&application_context, publication_retention);
        let application_reporter = ApplicationReporter {
            latency: application_metrics.proposal_latency.clone(),
            sink: gui.as_ref().map_or(
                OrderedSink::Headless(application::NoopReporter),
                |(_, _, reporter)| OrderedSink::Gui(reporter.clone()),
            ),
        };
        let (marshal, marshal_handle) = marshal_service.start(
            resolver_mailbox,
            CommitteeVerifier(
                committee.verifier.clone(),
                strategy.clone(),
                context.child("marshal_verifier"),
            ),
            application_reporter,
        );
        let producer_chain = profile
            .protocol()
            .producer_chain(Participant::from_usize(index));

        // The automaton owns bodies; consensus receives only their canonical header digests.
        let application = application::Application::new(
            application_context,
            key,
            application::Production {
                body_size: config.body_size,
                interval: config.production_interval,
                offered_bytes_per_second: config.offered_bytes_per_second,
            },
            publication_retention,
            producer_chain,
            marshal.clone(),
            application_metrics,
        );

        // View-critical cryptography gets its own pool: signing, certificate assembly, and the
        // verdicts the round waits on never queue behind the data plane's bulk verification.
        let critical_threads = config.critical_threads.map_or_else(
            || profile.critical_threads(),
            |threads| NonZeroUsize::new(threads).expect("critical threads must be non-zero"),
        );
        let critical_strategy = Rayon::new(critical_threads).expect("critical pool starts");

        // Initialize consensus
        let engine = Engine::new(
            context.child("engine"),
            EngineConfig {
                scheme: committee.signers[index].clone(),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: application,
                strategy,
                critical_strategy,
                blocker,
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

    let port = port.parse::<u16>().expect("port not well-formed");
    let bulk_port = cli.bulk_port.unwrap_or_else(|| {
        port.checked_add(BULK_PORT_OFFSET)
            .expect("bulk port must be representable")
    });

    RunConfig {
        key: key.parse().expect("key not well-formed"),
        port,
        bulk_port,
        participants: cli.participants,
        producers: cli.producers,
        bootstrappers,
        preferred_participants: Vec::new(),
        listen_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        public_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        storage_dir: cli
            .storage_dir
            .expect("--storage-dir is required when --config is not provided"),
        worker_threads: cli.worker_threads,
        compute_threads: cli.compute_threads,
        critical_threads: cli.critical_threads,
        body_size: cli.body_size,
        pipeline_depth: cli.pipeline_depth,
        extension_bound: cli.extension_bound,
        proposal_policy: cli.proposal_policy.into(),
        production_interval: Duration::from_millis(cli.production_interval_ms),
        offered_bytes_per_second: cli.offered_bytes_per_second,
        marshal_live_cache_bytes: cli.marshal_live_cache_bytes,
        marshal_materialized_cache_bytes: cli.marshal_materialized_cache_bytes,
        marshal_delivery_bytes: cli.marshal_delivery_bytes,
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
    let local_host = hosts
        .hosts
        .iter()
        .find(|host| host.name == config.key.to_string())
        .expect("node missing from hosts config");
    let public_ip = local_host.ip;
    let preferred_participants = hosts
        .hosts
        .iter()
        .filter(|host| host.region == local_host.region)
        .map(|host| {
            host.name
                .parse::<u64>()
                .expect("validator host name must be its participant key")
        })
        .filter(|key| config.participants.contains(key))
        .collect();
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
        bulk_port: config.bulk_port,
        participants: config.participants,
        producers: config.producers,
        bootstrappers,
        preferred_participants,
        listen_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        public_ip,
        storage_dir: config.storage_dir,
        worker_threads: config.worker_threads,
        compute_threads: config.compute_threads,
        critical_threads: config.critical_threads,
        body_size: config.body_size,
        pipeline_depth: config.pipeline_depth,
        extension_bound: config.extension_bound,
        proposal_policy: config.proposal_policy.into(),
        production_interval: Duration::from_millis(config.production_interval_ms),
        offered_bytes_per_second: config.offered_bytes_per_second,
        marshal_live_cache_bytes: config.marshal_live_cache_bytes,
        marshal_materialized_cache_bytes: config.marshal_materialized_cache_bytes,
        marshal_delivery_bytes: config.marshal_delivery_bytes,
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
    fn local_offered_load_is_optional_and_nonzero() {
        let args = ["log-multimmit", "--me", "0@3000", "--storage-dir", "unused"];
        let default = load_run_config(Cli::try_parse_from(args).unwrap());
        assert_eq!(default.offered_bytes_per_second, None);
        let explicit = load_run_config(
            Cli::try_parse_from(
                args.into_iter()
                    .chain(["--offered-bytes-per-second", "5120000"]),
            )
            .unwrap(),
        );
        assert_eq!(
            explicit.offered_bytes_per_second,
            NonZeroU64::new(5_120_000)
        );
        assert_eq!(explicit.production_interval, Duration::ZERO);
        assert!(
            Cli::try_parse_from(args.into_iter().chain(["--offered-bytes-per-second", "0"]))
                .is_err()
        );
    }

    #[test]
    fn local_delivery_budget_is_optional_and_nonzero() {
        let args = ["log-multimmit", "--me", "0@3000", "--storage-dir", "unused"];
        let default = load_run_config(Cli::try_parse_from(args).unwrap());
        assert_eq!(default.marshal_delivery_bytes, None);
        let explicit = load_run_config(
            Cli::try_parse_from(
                args.into_iter()
                    .chain(["--marshal-delivery-bytes", "134217728"]),
            )
            .unwrap(),
        );
        assert_eq!(
            explicit.marshal_delivery_bytes,
            Some(NZUsize!(128 * 1024 * 1024))
        );
        assert!(
            Cli::try_parse_from(args.into_iter().chain(["--marshal-delivery-bytes", "0"])).is_err()
        );
    }

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
            let _ = profile(&committee, 0, ProposalPolicy::Certified);
            let _ = profile(&committee, 1, ProposalPolicy::Certified);
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

    #[test]
    fn bulk_addresses_shift_the_consensus_port() {
        let consensus = SocketAddr::from_str("127.0.0.1:3000").expect("address parses");
        assert_eq!(
            bulk_address(consensus, BULK_PORT_OFFSET),
            SocketAddr::from_str("127.0.0.1:3001").expect("address parses")
        );
        let remote = SocketAddr::from_str("10.0.0.7:4000").expect("address parses");
        assert_eq!(
            bulk_address(remote, 100),
            SocketAddr::from_str("10.0.0.7:4100").expect("address parses")
        );
    }

    #[test]
    fn body_resolver_traffic_is_prioritized() {
        const { assert!(BODY_RESOLVER_PRIORITY) };
    }

    #[test]
    fn resolver_response_capacity_pages_large_blocks() {
        let max_block_size = application::Body::max_block_size(512 * 1024);
        assert_eq!(
            resolver_response_capacity(max_block_size),
            max_block_size * RESOLVER_RESPONSE_BLOCKS + RESOLVER_RESPONSE_BLOCKS.encode_size()
        );
        assert!(resolver_response_capacity(max_block_size) > max_block_size * 8);
    }
}

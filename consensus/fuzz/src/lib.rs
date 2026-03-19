pub mod bounds;
pub mod disrupter;
pub mod invariants;
pub mod simplex;
pub mod strategy;
pub mod tracing;
pub mod types;
pub mod utils;

use crate::{
    disrupter::Disrupter,
    strategy::{AnyScope, FutureScope, SmallScope, SmallScopeForTracing, StrategyChoice},
    tracing::{
        data::TraceData,
        sniffer::{ChannelKind, SniffingReceiver, TraceLog},
    },
    utils::{link_peers, register, Action, Partition},
};
use arbitrary::Arbitrary;
use commonware_codec::{Decode, DecodeExt};
use commonware_consensus::{
    simplex::{
        config,
        elector::RoundRobin,
        mocks::{application, relay, reporter, twins::Strategy},
        types::{Certificate, Vote},
        Engine,
    },
    types::{Delta, Epoch, View},
    Monitor, Viewable,
};
use commonware_cryptography::{
    certificate::{mocks::Fixture, Scheme},
    ed25519::PublicKey as Ed25519PublicKey,
    sha256::{Digest as Sha256Digest, Sha256 as Sha256Hasher},
    Sha256,
};
use commonware_p2p::{
    simulated::{Config as NetworkConfig, Link, Network, Oracle, SplitOrigin, SplitTarget},
    Recipients,
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    buffer::paged::CacheRef, deterministic, Clock, IoBuf, Metrics, Runner, Spawner,
};
use commonware_utils::{channel::mpsc::Receiver, sync::Mutex, FuzzRng, NZUsize, NZU16};
use futures::future::join_all;
use sha1::Digest;
pub use simplex::{
    SimplexBls12381MinPk, SimplexBls12381MinSig, SimplexBls12381MultisigMinPk,
    SimplexBls12381MultisigMinSig, SimplexEd25519, SimplexSecp256r1,
};
use std::{
    collections::HashMap,
    fs,
    num::{NonZeroU16, NonZeroUsize},
    panic,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

pub const EPOCH: u64 = 333;

const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
const FAULT_INJECTION_RATIO: u64 = 5;
const MIN_NUMBER_OF_FAULTS: u64 = 2;
const MIN_REQUIRED_CONTAINERS: u64 = 5;
const MAX_REQUIRED_CONTAINERS: u64 = 50;
const MAX_SLEEP_DURATION: Duration = Duration::from_secs(10);
const NAMESPACE: &[u8] = b"consensus_fuzz";
const MAX_RAW_BYTES: usize = 32_768;

/// Network configuration for fuzz testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Configuration {
    /// Total number of nodes.
    pub n: u32,
    /// Number of faulty (Byzantine) nodes.
    pub faults: u32,
    /// Number of correct (honest) nodes.
    pub correct: u32,
}

impl Configuration {
    pub const fn new(n: u32, faults: u32, correct: u32) -> Self {
        Self { n, faults, correct }
    }

    /// Returns true if this configuration can make progress (liveness).
    pub fn can_finalize(&self) -> bool {
        self.faults <= bounds::max_faults(self.n)
    }
}

/// 4 nodes, 1 faulty, 3 correct (standard BFT config)
pub const N4F1C3: Configuration = Configuration::new(4, 1, 3);
/// 4 nodes, 3 faulty, 1 correct (adversarial majority, no liveness)
pub const N4F3C1: Configuration = Configuration::new(4, 3, 1);

async fn setup_degraded_network<E: Clock>(
    oracle: &mut Oracle<Ed25519PublicKey, E>,
    participants: &[Ed25519PublicKey],
) {
    let Some(victim) = participants.last() else {
        return;
    };
    let victim_idx = participants.len() - 1;
    let degraded = Link {
        latency: Duration::from_millis(50),
        jitter: Duration::from_millis(50),
        success_rate: 0.6,
    };
    for (peer_idx, peer) in participants.iter().enumerate() {
        if peer_idx == victim_idx {
            continue;
        }
        oracle.remove_link(victim.clone(), peer.clone()).await.ok();
        oracle.remove_link(peer.clone(), victim.clone()).await.ok();
        oracle
            .add_link(victim.clone(), peer.clone(), degraded.clone())
            .await
            .unwrap();
        oracle
            .add_link(peer.clone(), victim.clone(), degraded.clone())
            .await
            .unwrap();
    }
}

#[derive(Debug, Clone)]
pub struct FuzzInput {
    pub raw_bytes: Vec<u8>,
    pub required_containers: u64,
    pub degraded_network: bool,
    pub configuration: Configuration,
    pub partition: Partition,
    pub strategy: StrategyChoice,
}

impl Arbitrary<'_> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        // Bias towards Connected partition
        let partition = match u.int_in_range(0..=99)? {
            0..=79 => Partition::Connected,                    // 80%
            80..=84 => Partition::Isolated,                    // 5%
            85..=89 => Partition::TwoPartitionsWithByzantine,  // 5%
            90..=94 => Partition::ManyPartitionsWithByzantine, // 5%
            _ => Partition::Ring,                              // 5%
        };

        let configuration = match u.int_in_range(1..=100)? {
            1..=95 => N4F1C3, // 95%
            _ => N4F3C1,      // 5%
        };

        // Bias degraded networking - 1%
        let degraded_network = partition == Partition::Connected
            && configuration == N4F1C3
            && u.int_in_range(0..=99)? == 1;

        let required_containers =
            u.int_in_range(MIN_REQUIRED_CONTAINERS..=MAX_REQUIRED_CONTAINERS)?;

        // SmallScope mutations with round-based injections - 80%,
        // AnyScope mutations - 10%,
        // FutureScope mutations with round-based injections - 10%
        let fault_rounds_bound = u.int_in_range(1..=required_containers)?;
        let max_faults = fault_rounds_bound / FAULT_INJECTION_RATIO;
        let min_faults = MIN_NUMBER_OF_FAULTS.min(fault_rounds_bound);
        let fault_rounds = u.int_in_range(0..=max_faults)?.max(min_faults);
        let strategy = match u.int_in_range(0..=9)? {
            0 => StrategyChoice::AnyScope,
            1 => StrategyChoice::FutureScope {
                fault_rounds,
                fault_rounds_bound,
            },
            _ => StrategyChoice::SmallScope {
                fault_rounds,
                fault_rounds_bound,
            },
        };

        // Collect bytes for RNG
        let remaining = u.len().min(MAX_RAW_BYTES);
        let raw_bytes = u.bytes(remaining)?.to_vec();

        Ok(Self {
            raw_bytes,
            partition,
            configuration,
            degraded_network,
            required_containers,
            strategy,
        })
    }
}

type NetworkChannels = (
    (
        commonware_p2p::simulated::Sender<Ed25519PublicKey, deterministic::Context>,
        commonware_p2p::simulated::Receiver<Ed25519PublicKey>,
    ),
    (
        commonware_p2p::simulated::Sender<Ed25519PublicKey, deterministic::Context>,
        commonware_p2p::simulated::Receiver<Ed25519PublicKey>,
    ),
    (
        commonware_p2p::simulated::Sender<Ed25519PublicKey, deterministic::Context>,
        commonware_p2p::simulated::Receiver<Ed25519PublicKey>,
    ),
);

/// Common setup for fuzz tests: network, participants, links.
async fn setup_network<P: simplex::Simplex>(
    context: &mut deterministic::Context,
    input: &FuzzInput,
) -> (
    Oracle<Ed25519PublicKey, deterministic::Context>,
    Vec<Ed25519PublicKey>,
    Vec<P::Scheme>,
    HashMap<Ed25519PublicKey, NetworkChannels>,
) {
    let (network, mut oracle) = Network::new(
        context.with_label("network"),
        NetworkConfig {
            max_size: 1024 * 1024,
            disconnect_on_block: false,
            tracked_peer_sets: None,
        },
    );
    network.start();

    let Fixture {
        participants,
        schemes,
        verifier: _,
        ..
    } = P::fixture(context, NAMESPACE, input.configuration.n);

    let registrations = register(&mut oracle, &participants).await;

    let link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };
    link_peers(
        &mut oracle,
        &participants,
        Action::Link(link),
        input.partition.filter(),
    )
    .await;

    if input.partition == Partition::Connected
        && input.configuration == N4F1C3
        && input.degraded_network
    {
        setup_degraded_network(&mut oracle, &participants).await;
    }

    (oracle, participants, schemes, registrations)
}

/// Start a Disrupter with the given strategy and network channels.
fn start_disrupter<P: simplex::Simplex>(
    context: deterministic::Context,
    scheme: P::Scheme,
    strategy: &StrategyChoice,
    vote_network: (
        impl commonware_p2p::Sender<PublicKey = Ed25519PublicKey> + 'static,
        impl commonware_p2p::Receiver<PublicKey = Ed25519PublicKey> + 'static,
    ),
    certificate_network: (
        impl commonware_p2p::Sender<PublicKey = Ed25519PublicKey> + 'static,
        impl commonware_p2p::Receiver<PublicKey = Ed25519PublicKey> + 'static,
    ),
    resolver_network: (
        impl commonware_p2p::Sender<PublicKey = Ed25519PublicKey> + 'static,
        impl commonware_p2p::Receiver<PublicKey = Ed25519PublicKey> + 'static,
    ),
) {
    match *strategy {
        StrategyChoice::SmallScope {
            fault_rounds,
            fault_rounds_bound,
        } => {
            let disrupter = Disrupter::new(
                context,
                scheme,
                SmallScope {
                    fault_rounds,
                    fault_rounds_bound,
                },
            );
            disrupter.start(vote_network, certificate_network, resolver_network);
        }
        StrategyChoice::AnyScope => {
            let disrupter = Disrupter::new(context, scheme, AnyScope);
            disrupter.start(vote_network, certificate_network, resolver_network);
        }
        StrategyChoice::FutureScope {
            fault_rounds,
            fault_rounds_bound,
        } => {
            let disrupter = Disrupter::new(
                context,
                scheme,
                FutureScope {
                    fault_rounds,
                    fault_rounds_bound,
                },
            );
            disrupter.start(vote_network, certificate_network, resolver_network);
        }
    }
}

/// Spawn a Disrupter for a Byzantine node.
fn spawn_disrupter<P: simplex::Simplex>(
    context: deterministic::Context,
    scheme: P::Scheme,
    input: &FuzzInput,
    channels: NetworkChannels,
) {
    let (vote_network, certificate_network, resolver_network) = channels;
    start_disrupter::<P>(
        context.with_label("disrupter"),
        scheme,
        &input.strategy,
        vote_network,
        certificate_network,
        resolver_network,
    );
}

/// Spawn an honest validator with application, reporter, and engine.
fn spawn_honest_validator<P: simplex::Simplex>(
    context: deterministic::Context,
    oracle: &Oracle<Ed25519PublicKey, deterministic::Context>,
    participants: &[Ed25519PublicKey],
    scheme: P::Scheme,
    validator: Ed25519PublicKey,
    relay: Arc<relay::Relay<Sha256Digest, Ed25519PublicKey>>,
    channels: NetworkChannels,
) -> reporter::Reporter<deterministic::Context, P::Scheme, P::Elector, Sha256Digest> {
    let elector = P::Elector::default();
    let reporter_cfg = reporter::Config {
        participants: participants.try_into().expect("public keys are unique"),
        scheme: scheme.clone(),
        elector: elector.clone(),
    };
    let reporter = reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);

    let (pending, recovered, resolver) = channels;

    let app_cfg = application::Config {
        hasher: Sha256::default(),
        relay,
        me: validator.clone(),
        propose_latency: (10.0, 5.0),
        verify_latency: (10.0, 5.0),
        certify_latency: (10.0, 5.0),
        should_certify: application::Certifier::Sometimes,
    };
    let (actor, application) =
        application::Application::new(context.with_label("application"), app_cfg);
    actor.start();

    let blocker = oracle.control(validator.clone());
    let engine_cfg = config::Config {
        blocker,
        scheme,
        elector,
        automaton: application.clone(),
        relay: application.clone(),
        reporter: reporter.clone(),
        partition: validator.to_string(),
        mailbox_size: 1024,
        epoch: Epoch::new(EPOCH),
        leader_timeout: Duration::from_secs(1),
        certification_timeout: Duration::from_secs(2),
        timeout_retry: Duration::from_secs(10),
        fetch_timeout: Duration::from_secs(1),
        activity_timeout: Delta::new(10),
        skip_timeout: Delta::new(5),
        fetch_concurrent: 1,
        replay_buffer: NZUsize!(1024 * 1024),
        write_buffer: NZUsize!(1024 * 1024),
        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
        strategy: Sequential,
    };
    let engine = Engine::new(context.with_label("engine"), engine_cfg);
    engine.start(pending, recovered, resolver);

    reporter
}

fn run<P: simplex::Simplex>(input: FuzzInput) {
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let (oracle, participants, schemes, mut registrations) =
            setup_network::<P>(&mut context, &input).await;

        let relay = Arc::new(relay::Relay::new());
        let mut reporters = Vec::new();
        let config = input.configuration;

        // Spawn Byzantine nodes (Disrupters only)
        for i in 0..config.faults as usize {
            let validator = participants[i].clone();
            let channels = registrations.remove(&validator).unwrap();
            let ctx = context.with_label(&format!("validator_{validator}"));
            spawn_disrupter::<P>(ctx, schemes[i].clone(), &input, channels);
        }

        // Spawn honest validators
        for i in (config.faults as usize)..(config.n as usize) {
            let validator = participants[i].clone();
            let channels = registrations.remove(&validator).unwrap();
            let ctx = context.with_label(&format!("validator_{validator}"));
            let reporter = spawn_honest_validator::<P>(
                ctx,
                &oracle,
                &participants,
                schemes[i].clone(),
                validator,
                relay.clone(),
                channels,
            );
            reporters.push(reporter);
        }

        // Wait for finalization or timeout
        if input.partition == Partition::Connected && config.can_finalize() {
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let required_containers = input.required_containers;
                let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest.get() < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;
        } else {
            context.sleep(MAX_SLEEP_DURATION).await;
        }

        let states = invariants::extract(reporters, config.n as usize);
        invariants::check::<P>(config.n, states);
    });
}

fn run_with_twin_mutator<P: simplex::Simplex>(input: FuzzInput) {
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let (oracle, participants, schemes, mut registrations) =
            setup_network::<P>(&mut context, &input).await;
        let participants: Arc<[_]> = participants.into();

        let strategy = Strategy::View;
        let relay = Arc::new(relay::Relay::new());
        let mut reporters = Vec::new();
        let config = input.configuration;

        // Spawn Byzantine twins: primary (legitimate engine) + secondary (Disrupter)
        for (idx, validator) in participants.iter().enumerate().take(config.faults as usize) {
            let context = context.with_label(&format!("twin_{idx}"));
            let scheme = schemes[idx].clone();
            let (vote_network, certificate_network, resolver_network) = registrations
                .remove(validator)
                .expect("validator should be registered");

            let make_vote_forwarder = || {
                let participants = participants.clone();
                move |origin: SplitOrigin, recipients: &Recipients<_>, message: &IoBuf| {
                    let Ok(msg) = Vote::<P::Scheme, Sha256Digest>::decode(message.clone()) else {
                        return Some(recipients.clone());
                    };
                    let (primary, secondary) =
                        strategy.partitions(msg.view(), participants.as_ref());
                    match origin {
                        SplitOrigin::Primary => Some(Recipients::Some(primary)),
                        SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
                    }
                }
            };
            let make_certificate_forwarder = || {
                let codec = schemes[idx].certificate_codec_config();
                let participants = participants.clone();
                move |origin: SplitOrigin, recipients: &Recipients<_>, message: &IoBuf| {
                    let Ok(msg) = Certificate::<P::Scheme, Sha256Digest>::decode_cfg(
                        &mut message.as_ref(),
                        &codec,
                    ) else {
                        return Some(recipients.clone());
                    };
                    let (primary, secondary) =
                        strategy.partitions(msg.view(), participants.as_ref());
                    match origin {
                        SplitOrigin::Primary => Some(Recipients::Some(primary)),
                        SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
                    }
                }
            };
            let make_resolver_forwarder = || {
                move |_: SplitOrigin, recipients: &Recipients<_>, _: &IoBuf| {
                    Some(recipients.clone())
                }
            };

            let make_vote_router = || {
                let participants = participants.clone();
                move |(sender, message): &(_, IoBuf)| {
                    let Ok(msg) = Vote::<P::Scheme, Sha256Digest>::decode(message.clone()) else {
                        return SplitTarget::None;
                    };
                    strategy.route(msg.view(), sender, participants.as_ref())
                }
            };
            let make_certificate_router = || {
                let codec = schemes[idx].certificate_codec_config();
                let participants = participants.clone();
                move |(sender, message): &(_, IoBuf)| {
                    let Ok(msg) = Certificate::<P::Scheme, Sha256Digest>::decode_cfg(
                        &mut message.as_ref(),
                        &codec,
                    ) else {
                        return SplitTarget::None;
                    };
                    strategy.route(msg.view(), sender, participants.as_ref())
                }
            };
            let make_resolver_router = || move |(_sender, _message): &(_, IoBuf)| SplitTarget::Both;

            let (vote_sender, vote_receiver) = vote_network;
            let (certificate_sender, certificate_receiver) = certificate_network;
            let (resolver_sender, resolver_receiver) = resolver_network;

            let (vote_sender_primary, vote_sender_secondary) =
                vote_sender.split_with(make_vote_forwarder());
            let (vote_receiver_primary, vote_receiver_secondary) = vote_receiver.split_with(
                context.with_label(&format!("pending_split_{idx}")),
                make_vote_router(),
            );
            let (certificate_sender_primary, certificate_sender_secondary) =
                certificate_sender.split_with(make_certificate_forwarder());
            let (certificate_receiver_primary, certificate_receiver_secondary) =
                certificate_receiver.split_with(
                    context.with_label(&format!("recovered_split_{idx}")),
                    make_certificate_router(),
                );
            let (resolver_sender_primary, resolver_sender_secondary) =
                resolver_sender.split_with(make_resolver_forwarder());
            let (resolver_receiver_primary, resolver_receiver_secondary) = resolver_receiver
                .split_with(
                    context.with_label(&format!("resolver_split_{idx}")),
                    make_resolver_router(),
                );

            // Primary: legitimate engine
            let primary_label = format!("twin_{idx}_primary");
            let primary_context = context.with_label(&primary_label);
            let primary_elector = P::Elector::default();
            let reporter_cfg = reporter::Config {
                participants: participants
                    .as_ref()
                    .try_into()
                    .expect("public keys are unique"),
                scheme: scheme.clone(),
                elector: primary_elector.clone(),
            };
            let reporter =
                reporter::Reporter::new(primary_context.with_label("reporter"), reporter_cfg);

            let app_cfg = application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: validator.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: application::Certifier::Sometimes,
            };
            let (actor, application) =
                application::Application::new(primary_context.with_label("application"), app_cfg);
            actor.start();

            let blocker = oracle.control(validator.clone());
            let engine_cfg = config::Config {
                blocker,
                scheme: scheme.clone(),
                elector: primary_elector,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: primary_label,
                mailbox_size: 1024,
                epoch: Epoch::new(EPOCH),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&primary_context, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
            };
            let engine = Engine::new(primary_context.with_label("engine"), engine_cfg);
            engine.start(
                (vote_sender_primary, vote_receiver_primary),
                (certificate_sender_primary, certificate_receiver_primary),
                (resolver_sender_primary, resolver_receiver_primary),
            );

            // Secondary: Disrupter
            start_disrupter::<P>(
                context.with_label(&format!("twin_{idx}_secondary")),
                scheme.clone(),
                &input.strategy,
                (vote_sender_secondary, vote_receiver_secondary),
                (certificate_sender_secondary, certificate_receiver_secondary),
                (resolver_sender_secondary, resolver_receiver_secondary),
            );
        }

        // Spawn honest validators
        for (idx, validator) in participants.iter().enumerate().skip(config.faults as usize) {
            let ctx = context.with_label(&format!("honest_{idx}"));
            let channels = registrations
                .remove(validator)
                .expect("validator should be registered");
            let reporter = spawn_honest_validator::<P>(
                ctx,
                &oracle,
                participants.as_ref(),
                schemes[idx].clone(),
                validator.clone(),
                relay.clone(),
                channels,
            );
            reporters.push(reporter);
        }

        // Wait for finalization or timeout
        if input.partition == Partition::Connected && config.can_finalize() {
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let required_containers = input.required_containers;
                let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest.get() < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;
        } else {
            context.sleep(MAX_SLEEP_DURATION).await;
        }

        let states = invariants::extract(reporters, config.n as usize);
        invariants::check::<P>(config.n, states);
    });
}

pub trait FuzzMode {
    const TWIN: bool;
}

pub struct Standard;

impl FuzzMode for Standard {
    const TWIN: bool = false;
}

pub struct Twinable;

impl FuzzMode for Twinable {
    const TWIN: bool = true;
}

/// Returns `true` if the trace is interesting enough to save.
///
/// Computes a feature vector from Byzantine node 0 activity (votes sent,
/// certificates sent), finalization height, and last view. If the Euclidean
/// distance of this vector is <= 3.0, the trace is considered uninteresting.
fn is_interesting_trace(entries: &[tracing::sniffer::TraceEntry], max_view: u64) -> bool {
    use tracing::sniffer::{TracedCert, TracedVote, TraceEntry};

    let mut notarize_by_n0: u64 = 0;
    let mut nullify_by_n0: u64 = 0;
    let mut finalize_by_n0: u64 = 0;
    let mut certs_by_n0: u64 = 0;
    let mut finalized_views = std::collections::HashSet::new();
    for entry in entries {
        match entry {
            TraceEntry::Vote { vote, .. } => {
                // Count votes signed by n0 (sig field)
                let sig = match vote {
                    TracedVote::Notarize { sig, .. } => sig,
                    TracedVote::Nullify { sig, .. } => sig,
                    TracedVote::Finalize { sig, .. } => sig,
                };
                if sig == "n0" {
                    match vote {
                        TracedVote::Notarize { .. } => notarize_by_n0 += 1,
                        TracedVote::Nullify { .. } => nullify_by_n0 += 1,
                        TracedVote::Finalize { .. } => finalize_by_n0 += 1,
                    }
                }
            }
            TraceEntry::Certificate { sender, cert, .. } => {
                if sender == "n0" {
                    certs_by_n0 += 1;
                }
                if let TracedCert::Finalization { view, .. } = cert {
                    finalized_views.insert(*view);
                }
            }
        }
    }
    let height = finalized_views.len() as u64;

    // Distance uses only Byzantine-specific metrics (not max_view/height
    // which dominate and make every trace appear interesting).
    let vec = [
        notarize_by_n0 as f64,
        nullify_by_n0 as f64,
        finalize_by_n0 as f64,
        certs_by_n0 as f64,
    ];
    let distance = vec.iter().map(|x| x * x).sum::<f64>().sqrt();

    // Count how many distinct vote types n0 used
    let vote_types = (notarize_by_n0 > 0) as u64
        + (nullify_by_n0 > 0) as u64
        + (finalize_by_n0 > 0) as u64;

    // Interesting = meaningful Byzantine activity: distance > 3, at least 2
    // vote types, more than 1 of each vote type, and at least 1 certificate.
    let interesting = distance > 3.0
        && vote_types >= 2
        && certs_by_n0 > 0
        && notarize_by_n0 > 1
        && nullify_by_n0 > 1
        && finalize_by_n0 > 1;

    if !interesting {
        println!(
            "skipping uninteresting trace (distance={:.2}, vote_types={}, notarize_n0={}, nullify_n0={}, finalize_n0={}, certs_n0={}, height={}, max_view={})",
            distance, vote_types, notarize_by_n0, nullify_by_n0, finalize_by_n0, certs_by_n0, height, max_view
        );
        return false;
    }
    println!(
        "interesting trace (distance={:.2}, vote_types={}, notarize_n0={}, nullify_n0={}, finalize_n0={}, certs_n0={}, height={}, max_view={})",
        distance, vote_types, notarize_by_n0, nullify_by_n0, finalize_by_n0, certs_by_n0, height, max_view
    );
    true
}

/// Run consensus with a Byzantine twin- and disruptor-node and quint tracing, capturing messages as JSON.
pub fn run_quint_tracing(input: FuzzInput, corpus_bytes: &[u8]) {
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    // Hash the raw corpus entry for a unique artifact filename (matches libFuzzer's SHA1 naming)
    let hash = sha1::Sha1::digest(corpus_bytes);
    let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

    executor.start(|mut context| async move {
        // N4F1C3: node 0 is Byzantine twin, nodes 1-3 are honest
        let tracing_input = FuzzInput {
            raw_bytes: input.raw_bytes.clone(),
            required_containers: input.required_containers,
            degraded_network: false,
            configuration: N4F1C3,
            partition: Partition::Connected,
            strategy: input.strategy,
        };

        let (oracle, participants, schemes, mut registrations) =
            setup_network::<SimplexEd25519>(&mut context, &tracing_input).await;
        let participants_arc: Arc<[_]> = participants.clone().into();

        let trace = Arc::new(Mutex::new(TraceLog::default()));
        let relay = Arc::new(relay::Relay::new());
        let elector = RoundRobin::<Sha256Hasher>::default();
        let mut reporters = Vec::new();
        let config = tracing_input.configuration;

        // Node 0: Byzantine twin
        {
            let idx = 0;
            let validator = participants[idx].clone();
            let twin_ctx = context.with_label(&format!("twin_{idx}"));
            let scheme = schemes[idx].clone();
            let (vote_network, certificate_network, resolver_network) = registrations
                .remove(&validator)
                .expect("validator should be registered");

            let strategy = Strategy::View;

            let make_vote_forwarder = || {
                let participants = participants_arc.clone();
                move |origin: SplitOrigin, recipients: &Recipients<_>, message: &IoBuf| {
                    let Ok(msg) =
                        Vote::<
                            <SimplexEd25519 as simplex::Simplex>::Scheme,
                            Sha256Digest,
                        >::decode(message.clone())
                    else {
                        return Some(recipients.clone());
                    };
                    let (primary, secondary) =
                        strategy.partitions(msg.view(), participants.as_ref());
                    match origin {
                        SplitOrigin::Primary => Some(Recipients::Some(primary)),
                        SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
                    }
                }
            };
            let make_certificate_forwarder = || {
                let codec = schemes[idx].certificate_codec_config();
                let participants = participants_arc.clone();
                move |origin: SplitOrigin, recipients: &Recipients<_>, message: &IoBuf| {
                    let Ok(msg) = Certificate::<
                        <SimplexEd25519 as simplex::Simplex>::Scheme,
                        Sha256Digest,
                    >::decode_cfg(
                        &mut message.as_ref(), &codec
                    ) else {
                        return Some(recipients.clone());
                    };
                    let (primary, secondary) =
                        strategy.partitions(msg.view(), participants.as_ref());
                    match origin {
                        SplitOrigin::Primary => Some(Recipients::Some(primary)),
                        SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
                    }
                }
            };
            let make_resolver_forwarder = || {
                move |_: SplitOrigin, recipients: &Recipients<_>, _: &IoBuf| {
                    Some(recipients.clone())
                }
            };

            let make_vote_router = || {
                let participants = participants_arc.clone();
                move |(sender, message): &(_, IoBuf)| {
                    let Ok(msg) = Vote::<
                        <SimplexEd25519 as simplex::Simplex>::Scheme,
                        Sha256Digest,
                    >::decode(message.clone())
                    else {
                        return SplitTarget::None;
                    };
                    strategy.route(msg.view(), sender, participants.as_ref())
                }
            };
            let make_certificate_router = || {
                let codec = schemes[idx].certificate_codec_config();
                let participants = participants_arc.clone();
                move |(sender, message): &(_, IoBuf)| {
                    let Ok(msg) = Certificate::<
                        <SimplexEd25519 as simplex::Simplex>::Scheme,
                        Sha256Digest,
                    >::decode_cfg(
                        &mut message.as_ref(), &codec
                    ) else {
                        return SplitTarget::None;
                    };
                    strategy.route(msg.view(), sender, participants.as_ref())
                }
            };
            let make_resolver_router =
                || move |(_sender, _message): &(_, IoBuf)| SplitTarget::Both;

            let (vote_sender, vote_receiver) = vote_network;
            let (certificate_sender, certificate_receiver) = certificate_network;
            let (resolver_sender, resolver_receiver) = resolver_network;

            let (vote_sender_primary, vote_sender_secondary) =
                vote_sender.split_with(make_vote_forwarder());
            let (vote_receiver_primary, vote_receiver_secondary) = vote_receiver.split_with(
                twin_ctx.with_label(&format!("pending_split_{idx}")),
                make_vote_router(),
            );
            let (certificate_sender_primary, certificate_sender_secondary) =
                certificate_sender.split_with(make_certificate_forwarder());
            let (certificate_receiver_primary, certificate_receiver_secondary) =
                certificate_receiver.split_with(
                    twin_ctx.with_label(&format!("recovered_split_{idx}")),
                    make_certificate_router(),
                );
            let (resolver_sender_primary, resolver_sender_secondary) =
                resolver_sender.split_with(make_resolver_forwarder());
            let (resolver_receiver_primary, resolver_receiver_secondary) =
                resolver_receiver.split_with(
                    twin_ctx.with_label(&format!("resolver_split_{idx}")),
                    make_resolver_router(),
                );

            // Wrap primary split receivers with sniffers (captures messages
            // received by the twin's legitimate engine). The Disrupter's
            // secondary receivers are NOT sniffed because it generates
            // mutated/garbage traffic that would cause unbounded trace growth.
            let node_id = format!("n{}", idx);
            let sniffing_vote_primary = SniffingReceiver::new(
                vote_receiver_primary,
                ChannelKind::Vote,
                node_id.clone(),
                participants.clone(),
                trace.clone(),
            );
            let sniffing_cert_primary = SniffingReceiver::new(
                certificate_receiver_primary,
                ChannelKind::Certificate,
                node_id,
                participants.clone(),
                trace.clone(),
            );

            // Primary: legitimate engine
            let primary_label = format!("twin_{idx}_primary");
            let primary_context = twin_ctx.with_label(&primary_label);
            let primary_elector = RoundRobin::<Sha256Hasher>::default();
            let reporter_cfg = reporter::Config {
                participants: participants
                    .as_slice()
                    .try_into()
                    .expect("public keys are unique"),
                scheme: scheme.clone(),
                elector: primary_elector.clone(),
            };
            let reporter =
                reporter::Reporter::new(primary_context.with_label("reporter"), reporter_cfg);

            let app_cfg = application::Config {
                hasher: Sha256Hasher::default(),
                relay: relay.clone(),
                me: validator.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: application::Certifier::Sometimes,
            };
            let (actor, application) =
                application::Application::new(primary_context.with_label("application"), app_cfg);
            actor.start();

            let blocker = oracle.control(validator.clone());
            let engine_cfg = config::Config {
                blocker,
                scheme: scheme.clone(),
                elector: primary_elector,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: primary_label,
                mailbox_size: 1024,
                epoch: Epoch::new(EPOCH),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&primary_context, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
            };
            let engine = Engine::new(primary_context.with_label("engine"), engine_cfg);
            engine.start(
                (vote_sender_primary, sniffing_vote_primary),
                (certificate_sender_primary, sniffing_cert_primary),
                (resolver_sender_primary, resolver_receiver_primary),
            );

            // Secondary: twin engine with sniffing receivers
            let secondary_label = format!("twin_{idx}_secondary");
            let secondary_context = twin_ctx.with_label(&secondary_label);
            let secondary_elector = RoundRobin::<Sha256Hasher>::default();
            let secondary_reporter_cfg = reporter::Config {
                participants: participants
                    .as_slice()
                    .try_into()
                    .expect("public keys are unique"),
                scheme: scheme.clone(),
                elector: secondary_elector.clone(),
            };
            let secondary_reporter = reporter::Reporter::new(
                secondary_context.with_label("reporter"),
                secondary_reporter_cfg,
            );

            let secondary_app_cfg = application::Config {
                hasher: Sha256Hasher::default(),
                relay: relay.clone(),
                me: validator.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: application::Certifier::Sometimes,
            };
            let (secondary_actor, secondary_application) = application::Application::new(
                secondary_context.with_label("application"),
                secondary_app_cfg,
            );
            secondary_actor.start();

            let sniffing_vote_secondary = SniffingReceiver::new(
                vote_receiver_secondary,
                ChannelKind::Vote,
                format!("n{}", idx),
                participants.clone(),
                trace.clone(),
            );
            let sniffing_cert_secondary = SniffingReceiver::new(
                certificate_receiver_secondary,
                ChannelKind::Certificate,
                format!("n{}", idx),
                participants.clone(),
                trace.clone(),
            );

            let secondary_blocker = oracle.control(validator.clone());
            let secondary_engine_cfg = config::Config {
                blocker: secondary_blocker,
                scheme: scheme.clone(),
                elector: secondary_elector,
                automaton: secondary_application.clone(),
                relay: secondary_application.clone(),
                reporter: secondary_reporter.clone(),
                partition: secondary_label,
                mailbox_size: 1024,
                epoch: Epoch::new(EPOCH),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(
                    &secondary_context,
                    PAGE_SIZE,
                    PAGE_CACHE_SIZE,
                ),
                strategy: Sequential,
            };
            let secondary_engine =
                Engine::new(secondary_context.with_label("engine"), secondary_engine_cfg);
            secondary_engine.start(
                (vote_sender_secondary, sniffing_vote_secondary),
                (certificate_sender_secondary, sniffing_cert_secondary),
                (resolver_sender_secondary, resolver_receiver_secondary),
            );
        }

        // Nodes 1-3: honest validators with sniffing receivers
        for i in (config.faults as usize)..(config.n as usize) {
            let validator = participants[i].clone();
            let (vote_network, cert_network, resolver_network) =
                registrations.remove(&validator).unwrap();
            let ctx = context.with_label(&format!("validator_{validator}"));
            let node_id = format!("n{}", i);

            let (vote_sender, vote_receiver) = vote_network;
            let (cert_sender, cert_receiver) = cert_network;
            let (resolver_sender, resolver_receiver) = resolver_network;

            let sniffing_vote = SniffingReceiver::new(
                vote_receiver,
                ChannelKind::Vote,
                node_id.clone(),
                participants.clone(),
                trace.clone(),
            );
            let sniffing_cert = SniffingReceiver::new(
                cert_receiver,
                ChannelKind::Certificate,
                node_id,
                participants.clone(),
                trace.clone(),
            );

            let reporter_cfg = reporter::Config {
                participants: participants
                    .as_slice()
                    .try_into()
                    .expect("public keys are unique"),
                scheme: schemes[i].clone(),
                elector: elector.clone(),
            };
            let reporter = reporter::Reporter::new(ctx.with_label("reporter"), reporter_cfg);
            reporters.push(reporter.clone());

            let app_cfg = application::Config {
                hasher: Sha256Hasher::default(),
                relay: relay.clone(),
                me: validator.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: application::Certifier::Sometimes,
            };
            let (actor, application) =
                application::Application::new(ctx.with_label("application"), app_cfg);
            actor.start();

            let blocker = oracle.control(validator.clone());
            let engine_cfg = config::Config {
                blocker,
                scheme: schemes[i].clone(),
                elector: elector.clone(),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: validator.to_string(),
                mailbox_size: 1024,
                epoch: Epoch::new(EPOCH),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
            };
            let engine = Engine::new(ctx.with_label("engine"), engine_cfg);
            engine.start(
                (vote_sender, sniffing_vote),
                (cert_sender, sniffing_cert),
                (resolver_sender, resolver_receiver),
            );
        }

        // Wait for finalization (honest nodes only)
        let mut finalizers = Vec::new();
        for reporter in reporters.iter_mut() {
            let required_containers = tracing_input.required_containers;
            let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
            finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                while latest.get() < required_containers {
                    latest = monitor.recv().await.expect("event missing");
                }
            }));
        }
        join_all(finalizers).await;

        // Run invariant checks
        let states = invariants::extract(reporters, config.n as usize);
        invariants::check::<SimplexEd25519>(config.n, states);

        // Serialize trace as JSON
        let trace = trace.lock();
        let max_view = trace
            .structured
            .iter()
            .map(|e| e.view())
            .max()
            .unwrap_or(1);

        let trace_data = TraceData {
            n: config.n as usize,
            faults: config.faults as usize,
            epoch: EPOCH,
            max_view,
            entries: trace.structured.clone(),
            required_containers: tracing_input.required_containers,
        };

        if !is_interesting_trace(&trace.structured, max_view) {
            return;
        }

        let artifacts_dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("artifacts/traces/simplex_ed25519_quint");
        fs::create_dir_all(&artifacts_dir).expect("failed to create artifacts directory");

        let json = serde_json::to_string_pretty(&trace_data).expect("failed to serialize trace");
        let json_path = artifacts_dir.join(format!("{}.json", hash_hex));
        fs::write(&json_path, &json).expect("failed to write trace JSON");
        println!(
            "wrote {} trace entries to {}",
            trace.structured.len(),
            json_path.display()
        );
    });
}

/// Run consensus with a Disrupter as node 0 and quint tracing, capturing messages as JSON.
pub fn run_quint_disrupter_tracing(input: FuzzInput, corpus_bytes: &[u8]) {
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    // Hash the raw corpus entry for a unique artifact filename (matches libFuzzer's SHA1 naming)
    let hash = sha1::Sha1::digest(corpus_bytes);
    let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

    executor.start(|mut context| async move {
        // N4F1C3: node 0 is Disrupter, nodes 1-3 are honest
        let tracing_input = FuzzInput {
            raw_bytes: input.raw_bytes.clone(),
            required_containers: input.required_containers,
            degraded_network: false,
            configuration: N4F1C3,
            partition: Partition::Connected,
            strategy: input.strategy,
        };

        let (oracle, participants, schemes, mut registrations) =
            setup_network::<SimplexEd25519>(&mut context, &tracing_input).await;

        let trace = Arc::new(Mutex::new(TraceLog::default()));
        let relay = Arc::new(relay::Relay::new());
        let elector = RoundRobin::<Sha256Hasher>::default();
        let mut reporters = Vec::new();
        let config = tracing_input.configuration;

        // Node 0: Disrupter with sniffing receivers
        {
            let validator = participants[0].clone();
            let (vote_network, cert_network, resolver_network) =
                registrations.remove(&validator).unwrap();
            let ctx = context.with_label(&format!("validator_{validator}"));
            let node_id = "n0".to_string();

            let (vote_sender, vote_receiver) = vote_network;
            let (cert_sender, cert_receiver) = cert_network;
            let (resolver_sender, resolver_receiver) = resolver_network;

            let sniffing_vote = SniffingReceiver::new(
                vote_receiver,
                ChannelKind::Vote,
                node_id.clone(),
                participants.clone(),
                trace.clone(),
            );
            let sniffing_cert = SniffingReceiver::new(
                cert_receiver,
                ChannelKind::Certificate,
                node_id,
                participants.clone(),
                trace.clone(),
            );

            let disrupter = Disrupter::new(
                ctx.with_label("disrupter"),
                schemes[0].clone(),
                SmallScopeForTracing::new(2, 5),
            );
            disrupter.start(
                (vote_sender, sniffing_vote),
                (cert_sender, sniffing_cert),
                (resolver_sender, resolver_receiver),
            );
        }

        // Nodes 1-3: honest validators with sniffing receivers
        for i in (config.faults as usize)..(config.n as usize) {
            let validator = participants[i].clone();
            let (vote_network, cert_network, resolver_network) =
                registrations.remove(&validator).unwrap();
            let ctx = context.with_label(&format!("validator_{validator}"));
            let node_id = format!("n{}", i);

            let (vote_sender, vote_receiver) = vote_network;
            let (cert_sender, cert_receiver) = cert_network;
            let (resolver_sender, resolver_receiver) = resolver_network;

            let sniffing_vote = SniffingReceiver::new(
                vote_receiver,
                ChannelKind::Vote,
                node_id.clone(),
                participants.clone(),
                trace.clone(),
            );
            let sniffing_cert = SniffingReceiver::new(
                cert_receiver,
                ChannelKind::Certificate,
                node_id,
                participants.clone(),
                trace.clone(),
            );

            let reporter_cfg = reporter::Config {
                participants: participants
                    .as_slice()
                    .try_into()
                    .expect("public keys are unique"),
                scheme: schemes[i].clone(),
                elector: elector.clone(),
            };
            let reporter = reporter::Reporter::new(ctx.with_label("reporter"), reporter_cfg);
            reporters.push(reporter.clone());

            let app_cfg = application::Config {
                hasher: Sha256Hasher::default(),
                relay: relay.clone(),
                me: validator.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: application::Certifier::Sometimes,
            };
            let (actor, application) =
                application::Application::new(ctx.with_label("application"), app_cfg);
            actor.start();

            let blocker = oracle.control(validator.clone());
            let engine_cfg = config::Config {
                blocker,
                scheme: schemes[i].clone(),
                elector: elector.clone(),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: validator.to_string(),
                mailbox_size: 1024,
                epoch: Epoch::new(EPOCH),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
            };
            let engine = Engine::new(ctx.with_label("engine"), engine_cfg);
            engine.start(
                (vote_sender, sniffing_vote),
                (cert_sender, sniffing_cert),
                (resolver_sender, resolver_receiver),
            );
        }

        // Wait for finalization (honest nodes only)
        let mut finalizers = Vec::new();
        for reporter in reporters.iter_mut() {
            let required_containers = tracing_input.required_containers;
            let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
            finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                while latest.get() < required_containers {
                    latest = monitor.recv().await.expect("event missing");
                }
            }));
        }
        join_all(finalizers).await;

        // Run invariant checks
        let states = invariants::extract(reporters, config.n as usize);
        invariants::check::<SimplexEd25519>(config.n, states);

        // Serialize trace as JSON
        let trace = trace.lock();
        let max_view = trace
            .structured
            .iter()
            .map(|e| e.view())
            .max()
            .unwrap_or(1);

        let trace_data = TraceData {
            n: config.n as usize,
            faults: config.faults as usize,
            epoch: EPOCH,
            max_view,
            entries: trace.structured.clone(),
            required_containers: tracing_input.required_containers
        };

        if !is_interesting_trace(&trace.structured, max_view) {
            return;
        }

        let artifacts_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("artifacts/traces/simplex_ed25519_quint_disrupter");
        fs::create_dir_all(&artifacts_dir).expect("failed to create artifacts directory");

        let json = serde_json::to_string_pretty(&trace_data).expect("failed to serialize trace");
        let json_path = artifacts_dir.join(format!("{}.json", hash_hex));
        fs::write(&json_path, &json).expect("failed to write trace JSON");
        println!(
            "wrote {} trace entries to {}",
            trace.structured.len(),
            json_path.display()
        );
    });
}

pub fn fuzz<P: simplex::Simplex, M: FuzzMode>(input: FuzzInput) {
    let raw_bytes = input.raw_bytes.clone();
    let run_result = if M::TWIN {
        panic::catch_unwind(panic::AssertUnwindSafe(|| {
            run_with_twin_mutator::<P>(input)
        }))
    } else {
        panic::catch_unwind(panic::AssertUnwindSafe(|| run::<P>(input)))
    };

    match run_result {
        Ok(()) => {}
        Err(payload) => {
            println!("Panicked with raw_bytes: {:?}", raw_bytes);
            panic::resume_unwind(payload);
        }
    }
}

pub mod apalache;
pub mod bounds;
pub mod disrupter;
pub mod invariants;
pub mod ist;
pub mod replayer;
pub mod simplex;
pub mod strategy;
pub mod tracing;
pub mod types;
pub mod utils;

use crate::{
    config::ForwardingPolicy,
    disrupter::Disrupter,
    strategy::{AnyScope, FutureScope, SmallScope, StrategyChoice},
    utils::{link_peers, register, Action, Partition},
};
use arbitrary::Arbitrary;
use commonware_codec::{Decode, DecodeExt};
use commonware_consensus::{
    simplex::{
        config,
        mocks::{application, relay, reporter, twins},
        types::{Certificate, Vote},
        Engine,
    },
    types::{Delta, Epoch, View},
    Monitor, Viewable,
};
use commonware_cryptography::{
    certificate::{mocks::Fixture, Scheme},
    ed25519::PublicKey as Ed25519PublicKey,
    sha256::Digest as Sha256Digest,
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
use commonware_utils::{channel::mpsc::Receiver, FuzzRng, NZUsize, NZU16};
use futures::future::join_all;
pub use simplex::{
    SimplexBls12381MinPk, SimplexBls12381MinSig, SimplexBls12381MultisigMinPk,
    SimplexBls12381MultisigMinSig, SimplexEd25519, SimplexSecp256r1,
};
use std::{
    collections::HashMap,
    num::{NonZeroU16, NonZeroUsize},
    panic,
    sync::{Arc, OnceLock},
    time::Duration,
};

pub const EPOCH: u64 = 333;

const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
const FAULT_INJECTION_RATIO: u64 = 5;
const MIN_NUMBER_OF_FAULTS: u64 = 2;
const DEFAULT_MIN_REQUIRED_CONTAINERS: u64 = 5;
const DEFAULT_MAX_REQUIRED_CONTAINERS: u64 = 50;
const MIN_REQUIRED_CONTAINERS_ENV: &str = "MIN_REQUIRED_CONTAINERS";
const MAX_REQUIRED_CONTAINERS_ENV: &str = "MAX_REQUIRED_CONTAINERS";
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

/// 4 nodes, 0 faulty, 4 correct (honest, no Byzantine)
pub const N4F0C4: Configuration = Configuration::new(4, 0, 4);
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

/// Which byzantine actor to use for node 0 in tracing runs.
#[derive(Debug, Clone, Copy)]
pub enum ByzantineActor {
    Disrupter,
    Equivocator,
    Conflicter,
    Nuller,
    NullifyOnly,
    Outdated,
}

impl ByzantineActor {
    pub fn label(self) -> &'static str {
        match self {
            Self::Disrupter => "simplex_ed25519_quint_disrupter",
            Self::Equivocator => "simplex_ed25519_quint_equivocator",
            Self::Conflicter => "simplex_ed25519_quint_conflicter",
            Self::Nuller => "simplex_ed25519_quint_nuller",
            Self::NullifyOnly => "simplex_ed25519_quint_nullify_only",
            Self::Outdated => "simplex_ed25519_quint_outdated",
        }
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
    pub byzantine_actor: ByzantineActor,
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

        let required_containers_range = configured_required_containers_range();
        let required_containers =
            u.int_in_range(required_containers_range.min..=required_containers_range.max)?;

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

        let byzantine_actor = match u.int_in_range(0..=4)? {
            0 => ByzantineActor::Equivocator,
            1 => ByzantineActor::Conflicter,
            2 => ByzantineActor::Nuller,
            3 => ByzantineActor::NullifyOnly,
            _ => ByzantineActor::Outdated,
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
            byzantine_actor,
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
        impl commonware_p2p::Sender<PublicKey = Ed25519PublicKey>,
        impl commonware_p2p::Receiver<PublicKey = Ed25519PublicKey>,
    ),
    certificate_network: (
        impl commonware_p2p::Sender<PublicKey = Ed25519PublicKey>,
        impl commonware_p2p::Receiver<PublicKey = Ed25519PublicKey>,
    ),
    resolver_network: (
        impl commonware_p2p::Sender<PublicKey = Ed25519PublicKey>,
        impl commonware_p2p::Receiver<PublicKey = Ed25519PublicKey>,
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
#[allow(clippy::too_many_arguments)]
fn spawn_honest_validator<
    P,
    PendingSender,
    PendingReceiver,
    RecoveredSender,
    RecoveredReceiver,
    ResolverSender,
    ResolverReceiver,
>(
    context: deterministic::Context,
    oracle: &Oracle<Ed25519PublicKey, deterministic::Context>,
    participants: &[Ed25519PublicKey],
    scheme: P::Scheme,
    validator: Ed25519PublicKey,
    relay: Arc<relay::Relay<Sha256Digest, Ed25519PublicKey>>,
    leader_timeout: Duration,
    certification_timeout: Duration,
    pending: (PendingSender, PendingReceiver),
    recovered: (RecoveredSender, RecoveredReceiver),
    resolver: (ResolverSender, ResolverReceiver),
) -> reporter::Reporter<deterministic::Context, P::Scheme, P::Elector, Sha256Digest>
where
    P: simplex::Simplex,
    PendingSender: commonware_p2p::Sender<PublicKey = Ed25519PublicKey>,
    PendingReceiver: commonware_p2p::Receiver<PublicKey = Ed25519PublicKey>,
    RecoveredSender: commonware_p2p::Sender<PublicKey = Ed25519PublicKey>,
    RecoveredReceiver: commonware_p2p::Receiver<PublicKey = Ed25519PublicKey>,
    ResolverSender: commonware_p2p::Sender<PublicKey = Ed25519PublicKey>,
    ResolverReceiver: commonware_p2p::Receiver<PublicKey = Ed25519PublicKey>,
{
    let elector = P::Elector::default();
    let reporter_cfg = reporter::Config {
        participants: participants.try_into().expect("public keys are unique"),
        scheme: scheme.clone(),
        elector: elector.clone(),
    };
    let reporter = reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);

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
        leader_timeout,
        certification_timeout,
        timeout_retry: Duration::from_secs(10),
        fetch_timeout: Duration::from_secs(1),
        activity_timeout: Delta::new(10),
        skip_timeout: Delta::new(5),
        fetch_concurrent: 1,
        replay_buffer: NZUsize!(1024 * 1024),
        write_buffer: NZUsize!(1024 * 1024),
        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
        strategy: Sequential,
        forwarding: ForwardingPolicy::Disabled,
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
            let (pending, recovered, resolver) = registrations.remove(&validator).unwrap();
            let ctx = context.with_label(&format!("validator_{validator}"));
            let reporter = spawn_honest_validator::<P, _, _, _, _, _, _>(
                ctx,
                &oracle,
                &participants,
                schemes[i].clone(),
                validator,
                relay.clone(),
                Duration::from_secs(1),
                Duration::from_secs(2),
                pending,
                recovered,
                resolver,
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

        let states = invariants::extract(&reporters, config.n as usize);
        invariants::check::<P>(config.n, &states);
    });
}

fn run_with_twin_mutator<P: simplex::Simplex>(input: FuzzInput) {
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let (mut oracle, participants, schemes, mut registrations) =
            setup_network::<P>(&mut context, &input).await;
        let participants: Arc<[_]> = participants.into();

        link_peers(
            &mut oracle,
            participants.as_ref(),
            Action::Update(Link {
                latency: Duration::from_millis(500),
                jitter: Duration::from_millis(500),
                success_rate: 1.0,
            }),
            input.partition.filter(),
        )
        .await;

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
                        twins::view_partitions(msg.view(), participants.as_ref());
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
                        twins::view_partitions(msg.view(), participants.as_ref());
                    match origin {
                        SplitOrigin::Primary => Some(Recipients::Some(primary)),
                        SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
                    }
                }
            };
            let make_vote_router = || {
                let participants = participants.clone();
                move |(sender, message): &(_, IoBuf)| {
                    let Ok(msg) = Vote::<P::Scheme, Sha256Digest>::decode(message.clone()) else {
                        return SplitTarget::None;
                    };
                    twins::view_route(msg.view(), sender, participants.as_ref())
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
                    twins::view_route(msg.view(), sender, participants.as_ref())
                }
            };
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
            let (resolver_sender_primary, resolver_sender_secondary) = resolver_sender
                .split_with(|_origin, recipients, _message| Some(recipients.clone()));
            let (resolver_receiver_primary, resolver_receiver_secondary) = resolver_receiver
                .split_with(context.with_label(&format!("resolver_split_{idx}")), |_| {
                    SplitTarget::Both
                });

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
                certification_timeout: Duration::from_millis(1_500),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&primary_context, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
                forwarding: ForwardingPolicy::Disabled,
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
            let (pending, recovered, resolver) = registrations
                .remove(validator)
                .expect("validator should be registered");
            let reporter = spawn_honest_validator::<P, _, _, _, _, _, _>(
                ctx,
                &oracle,
                participants.as_ref(),
                schemes[idx].clone(),
                validator.clone(),
                relay.clone(),
                Duration::from_secs(1),
                Duration::from_millis(1_500),
                pending,
                recovered,
                resolver,
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

        let states = invariants::extract(&reporters, config.n as usize);
        invariants::check::<P>(config.n, &states);
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

#[derive(Clone, Copy, Debug)]
struct RequiredContainersRange {
    min: u64,
    max: u64,
}

impl RequiredContainersRange {
    fn from_env() -> Result<Self, String> {
        let min = parse_u64_env(MIN_REQUIRED_CONTAINERS_ENV, DEFAULT_MIN_REQUIRED_CONTAINERS)?;
        let max = parse_u64_env(MAX_REQUIRED_CONTAINERS_ENV, DEFAULT_MAX_REQUIRED_CONTAINERS)?;
        if min == 0 {
            return Err(format!("{MIN_REQUIRED_CONTAINERS_ENV} must be at least 1"));
        }
        if min > max {
            return Err(format!(
                "{MIN_REQUIRED_CONTAINERS_ENV}={min} exceeds {MAX_REQUIRED_CONTAINERS_ENV}={max}"
            ));
        }
        Ok(Self { min, max })
    }
}

fn configured_required_containers_range() -> &'static RequiredContainersRange {
    static RANGE: OnceLock<RequiredContainersRange> = OnceLock::new();
    RANGE.get_or_init(|| RequiredContainersRange::from_env().unwrap_or_else(|msg| panic!("{msg}")))
}

fn parse_u64_env(name: &str, default: u64) -> Result<u64, String> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|err| format!("failed to parse {name}={value}: {err}")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(format!("failed to read {name}: {err}")),
    }
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

pub fn run_quint_twins_tracing(input: FuzzInput, corpus_bytes: &[u8]) {
    tracing::run_quint_twins_tracing(input, corpus_bytes);
}

pub fn run_quint_disrupter_tracing(input: FuzzInput, corpus_bytes: &[u8]) {
    tracing::run_quint_disrupter_tracing(input, corpus_bytes);
}

pub fn run_quint_byzantine_tracing(actor: ByzantineActor, input: FuzzInput, corpus_bytes: &[u8]) {
    tracing::run_quint_byzantine_tracing(actor, input, corpus_bytes);
}

pub fn run_quint_honest_tracing(input: FuzzInput, corpus_bytes: &[u8]) {
    tracing::run_quint_honest_tracing(input, corpus_bytes);
}

pub mod disrupter;
pub mod invariants;
pub mod simplex;
pub mod strategy;
pub mod types;
pub mod utils;

use crate::{
    disrupter::Disrupter,
    strategy::{AnyScope, FutureScope, SmallScope, StrategyChoice},
    utils::{link_peers, max_faults, register, Action, Partition},
};
use arbitrary::Arbitrary;
use bytes::Bytes;
use commonware_codec::{Decode, DecodeExt};
use commonware_consensus::{
    simplex::{
        config,
        mocks::{application, relay, reporter, twins::Strategy},
        types::{Certificate, Vote},
        Engine,
    },
    types::{Delta, Epoch, View},
    Monitor, Viewable,
};
use commonware_cryptography::{
    certificate::{mocks::Fixture, Scheme},
    sha256::Digest as Sha256Digest,
    Sha256,
};
use commonware_p2p::{
    simulated::{Config as NetworkConfig, Link, Network, SplitOrigin, SplitTarget},
    Recipients,
};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::PoolRef, deterministic, Clock, Metrics, Runner, Spawner};
use commonware_utils::{NZUsize, NZU16};
use futures::{channel::mpsc::Receiver, future::join_all, StreamExt};
use rand::{rngs::StdRng, RngCore, SeedableRng};
pub use simplex::{
    SimplexBls12381MinPk, SimplexBls12381MinSig, SimplexBls12381MultisigMinPk,
    SimplexBls12381MultisigMinSig, SimplexEd25519, SimplexSecp256r1,
};
use std::{
    cell::RefCell,
    num::{NonZeroU16, NonZeroUsize},
    panic,
    sync::Arc,
    time::Duration,
};

pub const EPOCH: u64 = 333;

const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
const MIN_REQUIRED_CONTAINERS: u64 = 5;
const MAX_REQUIRED_CONTINERS: u64 = 50;
const MAX_SLEEP_DURATION: Duration = Duration::from_secs(10);
const NAMESPACE: &[u8] = b"consensus_fuzz";
// 4 nodes, 1 faulty, 3 correct
const N4C3F1: (u32, u32, u32) = (4, 1, 3);
// 3 nodes, 1 faulty, 2 correct
const N3C2F1: (u32, u32, u32) = (3, 1, 2);
// 3 nodes, 2 faulty, 1 correct
const N4C1F3: (u32, u32, u32) = (4, 3, 1);
const MAX_RAW_BYTES: usize = 4096;

#[derive(Debug, Clone)]
pub struct FuzzInput {
    pub raw_bytes: Vec<u8>,
    pub seed: u64,
    pub required_containers: u64,
    pub degraded_network_node: bool,
    offset: RefCell<usize>,
    rng: RefCell<StdRng>,
    pub configuration: (u32, u32, u32),
    pub partition: Partition,
    pub strategy: StrategyChoice,
}

impl FuzzInput {
    pub fn random(&self, n: usize) -> Vec<u8> {
        if n == 0 {
            return Vec::new();
        }

        let mut offset = self.offset.borrow_mut();
        let remaining = self.raw_bytes.len().saturating_sub(*offset);

        if remaining >= n {
            let result = self.raw_bytes[*offset..*offset + n].to_vec();
            *offset += n;
            result
        } else {
            let mut result = Vec::with_capacity(n);
            if remaining > 0 {
                result.extend_from_slice(&self.raw_bytes[*offset..]);
                *offset = self.raw_bytes.len();
            }
            let mut extra = vec![0u8; n - result.len()];
            self.rng.borrow_mut().fill_bytes(&mut extra);
            result.extend(extra);
            result
        }
    }

    pub fn random_byte(&self) -> u8 {
        self.random(1)[0]
    }

    pub fn random_bool(&self) -> bool {
        self.random_byte() < 128
    }

    pub fn random_u64(&self) -> u64 {
        u64::from_le_bytes(self.random(8).try_into().unwrap())
    }
}

impl Arbitrary<'_> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let seed = u.arbitrary()?;

        // Bias towards Connected partition
        let partition = match u.int_in_range(0..=99)? {
            0..=79 => Partition::Connected,                    // 80%
            80..=84 => Partition::Isolated,                    // 5%
            85..=89 => Partition::TwoPartitionsWithByzantine,  // 5%
            90..=94 => Partition::ManyPartitionsWithByzantine, // 5%
            _ => Partition::Ring,                              // 5%
        };

        let configuration = match u.int_in_range(1..=100)? {
            1..=90 => N4C3F1,  // 90%
            91..=95 => N3C2F1, // 5%
            _ => N4C1F3,       // 5%
        };

        // Bias degraded networking - 1%
        let degraded_network_node = partition == Partition::Connected
            && configuration == N4C3F1
            && u.int_in_range(0..=99)? == 1;

        let required_containers =
            u.int_in_range(MIN_REQUIRED_CONTAINERS..=MAX_REQUIRED_CONTINERS)?;

        // SmallScope mutations - 50%, AnyScope mutations - 25%, FutureScope mutations - 25%
        let strategy = match u.int_in_range(0..=3)? {
            0 => StrategyChoice::AnyScope,
            1 => StrategyChoice::FutureScope,
            _ => StrategyChoice::SmallScope,
        };

        let mut raw_bytes = Vec::new();
        for _ in 0..MAX_RAW_BYTES {
            match u.arbitrary::<u8>() {
                Ok(byte) => raw_bytes.push(byte),
                Err(_) => break,
            }
        }

        let mut prng_seed = [0u8; 32];
        for (i, &b) in raw_bytes.iter().enumerate() {
            prng_seed[i % 32] ^= b;
        }

        Ok(Self {
            seed,
            partition,
            configuration,
            degraded_network_node,
            raw_bytes,
            required_containers,
            offset: RefCell::new(0),
            rng: RefCell::new(StdRng::from_seed(prng_seed)),
            strategy,
        })
    }
}

fn run<P: simplex::Simplex>(input: FuzzInput) {
    let (n, f, _) = input.configuration;
    let required_containers = input.required_containers;
    let cfg = deterministic::Config::new().with_seed(input.seed);
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
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
        } = P::fixture(&mut context, NAMESPACE, n);

        let mut registrations = register(&mut oracle, &participants).await;

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
            && input.configuration == N4C3F1
            && input.degraded_network_node
        {
            if let Some(victim) = participants.last() {
                let degraded = Link {
                    latency: Duration::from_millis(50),
                    jitter: Duration::from_millis(50),
                    success_rate: 0.6,
                };
                for (peer_idx, peer) in participants.iter().enumerate() {
                    if peer_idx == 3 {
                        continue;
                    }
                    // Replace links to/from the degraded node with degraded connectivity.
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
        }

        let relay = Arc::new(relay::Relay::new());
        let mut reporters = Vec::new();

        for i in 0..f as usize {
            let scheme = schemes[i].clone();
            let validator = participants[i].clone();
            let context = context.with_label(&format!("validator_{validator}"));

            let (vote_network, certificate_network, resolver_network) =
                registrations.remove(&validator).unwrap();
            let disrupter_context = context.with_label("disrupter");
            match input.strategy {
                StrategyChoice::SmallScope => {
                    let disrupter =
                        Disrupter::new(disrupter_context, scheme, input.clone(), SmallScope);
                    disrupter.start(vote_network, certificate_network, resolver_network);
                }
                StrategyChoice::AnyScope => {
                    let disrupter =
                        Disrupter::new(disrupter_context, scheme, input.clone(), AnyScope);
                    disrupter.start(vote_network, certificate_network, resolver_network);
                }
                StrategyChoice::FutureScope => {
                    let disrupter =
                        Disrupter::new(disrupter_context, scheme, input.clone(), FutureScope);
                    disrupter.start(vote_network, certificate_network, resolver_network);
                }
            }
        }

        for i in (f as usize)..(n as usize) {
            let validator = participants[i].clone();
            let context = context.with_label(&format!("validator_{validator}"));
            let elector = P::Elector::default();
            let reporter_cfg = reporter::Config {
                participants: participants
                    .clone()
                    .try_into()
                    .expect("public keys are unique"),
                scheme: schemes[i].clone(),
                elector: elector.clone(),
            };
            let reporter = reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);
            reporters.push(reporter.clone());

            let (pending, recovered, resolver) = registrations.remove(&validator).unwrap();

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
                application::Application::new(context.with_label("application"), app_cfg);
            actor.start();

            let blocker = oracle.control(validator.clone());
            let engine_cfg = config::Config {
                blocker,
                scheme: schemes[i].clone(),
                elector,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: validator.to_string(),
                mailbox_size: 1024,
                epoch: Epoch::new(EPOCH),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
            };
            let engine = Engine::new(context.with_label("engine"), engine_cfg);
            engine.start(pending, recovered, resolver);
        }

        if input.partition == Partition::Connected && max_faults(n) == f {
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest.get() < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;
        } else {
            context.sleep(MAX_SLEEP_DURATION).await;
        }

        let states = invariants::extract(reporters);
        invariants::check::<P>(n, states);
    });
}

fn run_with_twin_mutator<P: simplex::Simplex>(input: FuzzInput) {
    let (n, f, _) = input.configuration;
    let required_containers = input.required_containers;
    let cfg = deterministic::Config::new().with_seed(input.seed);
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
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
        } = P::fixture(&mut context, NAMESPACE, n);
        let participants: Arc<[_]> = participants.into();
        let mut registrations = register(&mut oracle, participants.as_ref()).await;

        let link = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(1),
            success_rate: 1.0,
        };
        link_peers(
            &mut oracle,
            participants.as_ref(),
            Action::Link(link),
            input.partition.filter(),
        )
        .await;

        if input.partition == Partition::Connected
            && input.configuration == N4C3F1
            && input.degraded_network_node
        {
            if let Some(victim) = participants.last() {
                let degraded = Link {
                    latency: Duration::from_millis(50),
                    jitter: Duration::from_millis(50),
                    success_rate: 0.6,
                };
                for (peer_idx, peer) in participants.iter().enumerate() {
                    if peer_idx == 3 {
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
        }

        let strategy = Strategy::View;
        let relay = Arc::new(relay::Relay::new());
        let mut reporters = Vec::new();

        for (idx, validator) in participants.iter().enumerate().take(f as usize) {
            let context = context.with_label(&format!("twin_{idx}"));
            let scheme = schemes[idx].clone();
            let (vote_network, certificate_network, resolver_network) = registrations
                .remove(validator)
                .expect("validator should be registered");

            let make_vote_forwarder = || {
                let participants = participants.clone();
                move |origin: SplitOrigin, recipients: &Recipients<_>, message: &Bytes| {
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
                move |origin: SplitOrigin, recipients: &Recipients<_>, message: &Bytes| {
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
                move |_: SplitOrigin, recipients: &Recipients<_>, _: &Bytes| {
                    Some(recipients.clone())
                }
            };

            let make_vote_router = || {
                let participants = participants.clone();
                move |(sender, message): &(_, Bytes)| {
                    let Ok(msg) = Vote::<P::Scheme, Sha256Digest>::decode(message.clone()) else {
                        return SplitTarget::None;
                    };
                    strategy.route(msg.view(), sender, participants.as_ref())
                }
            };
            let make_certificate_router = || {
                let codec = schemes[idx].certificate_codec_config();
                let participants = participants.clone();
                move |(sender, message): &(_, Bytes)| {
                    let Ok(msg) = Certificate::<P::Scheme, Sha256Digest>::decode_cfg(
                        &mut message.as_ref(),
                        &codec,
                    ) else {
                        return SplitTarget::None;
                    };
                    strategy.route(msg.view(), sender, participants.as_ref())
                }
            };
            let make_resolver_router = || move |(_sender, _message): &(_, Bytes)| SplitTarget::Both;

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
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
            };
            let engine = Engine::new(primary_context.with_label("engine"), engine_cfg);
            engine.start(
                (vote_sender_primary, vote_receiver_primary),
                (certificate_sender_primary, certificate_receiver_primary),
                (resolver_sender_primary, resolver_receiver_primary),
            );

            let mutator_label = format!("twin_{idx}_secondary");
            let mutator_context = context.with_label(&mutator_label);
            let disrupter_context = mutator_context.with_label("disrupter");
            match input.strategy {
                StrategyChoice::SmallScope => {
                    let disrupter = Disrupter::new(
                        disrupter_context,
                        scheme.clone(),
                        input.clone(),
                        SmallScope,
                    );
                    disrupter.start(
                        (vote_sender_secondary, vote_receiver_secondary),
                        (certificate_sender_secondary, certificate_receiver_secondary),
                        (resolver_sender_secondary, resolver_receiver_secondary),
                    );
                }
                StrategyChoice::AnyScope => {
                    let disrupter =
                        Disrupter::new(disrupter_context, scheme.clone(), input.clone(), AnyScope);
                    disrupter.start(
                        (vote_sender_secondary, vote_receiver_secondary),
                        (certificate_sender_secondary, certificate_receiver_secondary),
                        (resolver_sender_secondary, resolver_receiver_secondary),
                    );
                }
                StrategyChoice::FutureScope => {
                    let disrupter = Disrupter::new(
                        disrupter_context,
                        scheme.clone(),
                        input.clone(),
                        FutureScope,
                    );
                    disrupter.start(
                        (vote_sender_secondary, vote_receiver_secondary),
                        (certificate_sender_secondary, certificate_receiver_secondary),
                        (resolver_sender_secondary, resolver_receiver_secondary),
                    );
                }
            }
        }

        for (idx, validator) in participants.iter().enumerate().skip(f as usize) {
            let context = context.with_label(&format!("honest_{idx}"));
            let elector = P::Elector::default();
            let reporter_cfg = reporter::Config {
                participants: participants
                    .as_ref()
                    .try_into()
                    .expect("public keys are unique"),
                scheme: schemes[idx].clone(),
                elector: elector.clone(),
            };
            let reporter = reporter::Reporter::new(context.with_label("reporter"), reporter_cfg);
            reporters.push(reporter.clone());

            let (pending, recovered, resolver) = registrations
                .remove(validator)
                .expect("validator should be registered");

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
                application::Application::new(context.with_label("application"), app_cfg);
            actor.start();

            let blocker = oracle.control(validator.clone());
            let engine_cfg = config::Config {
                blocker,
                scheme: schemes[idx].clone(),
                elector,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: validator.to_string(),
                mailbox_size: 1024,
                epoch: Epoch::new(EPOCH),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
            };
            let engine = Engine::new(context.with_label("engine"), engine_cfg);
            engine.start(pending, recovered, resolver);
        }

        if input.partition == Partition::Connected && max_faults(n) == f {
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest.get() < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;
        } else {
            context.sleep(MAX_SLEEP_DURATION).await;
        }

        let states = invariants::extract(reporters);
        invariants::check::<P>(n, states);
    });
}

pub fn fuzz<P: simplex::Simplex>(input: FuzzInput) {
    let seed = input.seed;
    match panic::catch_unwind(panic::AssertUnwindSafe(|| run::<P>(input))) {
        Ok(()) => {}
        Err(payload) => {
            println!("Panicked with seed: {}", seed);
            panic::resume_unwind(payload);
        }
    }
}

pub fn fuzz_with_twin_mutator<P: simplex::Simplex>(input: FuzzInput) {
    let seed = input.seed;
    match panic::catch_unwind(panic::AssertUnwindSafe(|| {
        run_with_twin_mutator::<P>(input)
    })) {
        Ok(()) => {}
        Err(payload) => {
            println!("Panicked with seed: {}", seed);
            panic::resume_unwind(payload);
        }
    }
}

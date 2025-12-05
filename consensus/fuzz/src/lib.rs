pub mod disrupter;
pub mod invariants;
pub mod types;
pub mod utils;

use crate::{
    disrupter::Disrupter,
    utils::{link_peers, register, Action, Partition},
};
use arbitrary::Arbitrary;
use commonware_codec::Read;
use commonware_consensus::{
    simplex::{
        config,
        mocks::{application, fixtures::Fixture, relay, reporter},
        signing_scheme::Scheme as SimplexScheme,
        Engine,
    },
    types::{Delta, Epoch, View},
    Monitor,
};
use commonware_cryptography::{ed25519::PublicKey as Ed25519PublicKey, Sha256};
use commonware_p2p::simulated::{Config as NetworkConfig, Link, Network};
use commonware_runtime::{buffer::PoolRef, deterministic, Clock, Metrics, Runner, Spawner};
use commonware_utils::{max_faults, NZUsize, NZU32};
use futures::{channel::mpsc::Receiver, future::join_all, StreamExt};
use governor::Quota;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{cell::RefCell, num::NonZeroUsize, panic, sync::Arc, time::Duration};

pub const EPOCH: u64 = 333;

const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
const REQUIRED_CONTAINERS: u64 = 50;
const NAMESPACE: &[u8] = b"consensus_fuzz";
const CONFIGURATIONS: [(u32, u32, u32); 2] = [(3, 2, 1), (4, 3, 1)];
const MAX_RAW_BYTES: usize = 4096;

const EXPECTED_PANICS: [&str; 3] = [
    "invalid payload:",
    "invalid parent (in payload):",
    "invalid round (in payload)",
];

pub trait Simplex: 'static
where
    <<Self::Scheme as SimplexScheme>::Certificate as Read>::Cfg: Default,
{
    type Scheme: SimplexScheme<PublicKey = Ed25519PublicKey>;
    fn fixture(context: &mut deterministic::Context, n: u32) -> Fixture<Self::Scheme>;
}

#[derive(Debug, Clone)]
pub struct FuzzInput {
    pub seed: u64,
    pub partition: Partition,
    pub configuration: (u32, u32, u32),
    pub raw_bytes: Vec<u8>,
    offset: RefCell<usize>,
    rng: RefCell<StdRng>,
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
        let partition = u.arbitrary()?;
        let configuration = CONFIGURATIONS[u.int_in_range(0..=(CONFIGURATIONS.len() - 1))?];

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
            raw_bytes,
            offset: RefCell::new(0),
            rng: RefCell::new(StdRng::from_seed(prng_seed)),
        })
    }
}

fn run<P: Simplex>(input: FuzzInput) {
    let (n, _, f) = input.configuration;
    let namespace = NAMESPACE.to_vec();
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
        } = P::fixture(&mut context, n);

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

        let relay = Arc::new(relay::Relay::new());
        let mut reporters = Vec::new();

        for i in 0..f as usize {
            let scheme = schemes[i].clone();
            let validator = participants[i].clone();
            let context = context.with_label(&format!("validator-{validator}"));

            let (vote_network, certificate_network, _) = registrations.remove(&validator).unwrap();
            let disrupter = Disrupter::<_, _>::new(
                context.with_label("disrupter"),
                validator.clone(),
                scheme,
                participants
                    .clone()
                    .try_into()
                    .expect("public keys are unique"),
                namespace.clone(),
                input.clone(),
            );
            disrupter.start(vote_network, certificate_network);
        }

        for i in (f as usize)..(n as usize) {
            let validator = participants[i].clone();
            let context = context.with_label(&format!("validator-{validator}"));
            let reporter_cfg = reporter::Config {
                namespace: namespace.clone(),
                participants: participants
                    .clone()
                    .try_into()
                    .expect("public keys are unique"),
                scheme: schemes[i].clone(),
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
            };
            let (actor, application) =
                application::Application::new(context.with_label("application"), app_cfg);
            actor.start();

            let blocker = oracle.control(validator.clone());
            let engine_cfg = config::Config {
                blocker,
                scheme: schemes[i].clone(),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: validator.to_string(),
                mailbox_size: 1024,
                epoch: Epoch::new(EPOCH),
                namespace: namespace.clone(),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
                fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let engine = Engine::new(context.with_label("engine"), engine_cfg);
            engine.start(pending, recovered, resolver);
        }

        if input.partition == Partition::Connected && max_faults(n) == f {
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest.get() < REQUIRED_CONTAINERS {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;
        } else {
            context.sleep(Duration::from_secs(10)).await;
        }

        let states = invariants::extract(reporters);
        invariants::check(n, states);
    });
}

fn is_expected_panic(payload: &Box<dyn std::any::Any + Send>) -> bool {
    let msg = if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        return false;
    };

    EXPECTED_PANICS.iter().any(|pattern| msg.contains(pattern))
}

pub fn fuzz<P: Simplex>(input: FuzzInput) {
    match panic::catch_unwind(panic::AssertUnwindSafe(|| run::<P>(input))) {
        Ok(()) => {}
        Err(payload) => {
            if !is_expected_panic(&payload) {
                panic::resume_unwind(payload);
            }
        }
    }
}

pub mod fuzzer;
pub mod invariants;
pub mod types;
pub mod utils;
pub use crate::types::FuzzInput;
use crate::{
    fuzzer::Fuzzer,
    invariants::{check_invariants, extract_simplex_state},
    utils::{link_peers, register_validators, Action, PartitionStrategy},
};
use commonware_codec::Read;
use commonware_consensus::{
    simplex::{
        config,
        mocks::{
            application,
            fixtures::{bls_threshold_fixture, ed25519_fixture, Fixture},
            relay, reporter,
        },
        signing_scheme::{bls12381_threshold, ed25519 as simplex_ed25519, Scheme as SimplexScheme},
        Engine,
    },
    types::View,
    Monitor,
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest, Sha256, Signer as _,
};
use commonware_p2p::simulated::{Config as NetworkConfig, Link, Network};
use commonware_runtime::{buffer::PoolRef, deterministic, Clock, Metrics, Runner, Spawner};
use commonware_utils::{NZUsize, NZU32};
use futures::{channel::mpsc::Receiver, future::join_all, StreamExt};
use governor::Quota;
use std::{
    num::NonZeroUsize,
    panic,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

pub const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
pub const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

const VALID_PANICS: [&str; 3] = [
    "invalid payload:",
    "invalid parent (in payload):",
    "invalid round (in payload)",
];

static SHOULD_IGNORE_PANIC: AtomicBool = AtomicBool::new(false);

pub trait Simplex: 'static
where
    <<Self::Scheme as SimplexScheme>::Certificate as Read>::Cfg: Default,
{
    type Scheme: SimplexScheme;

    fn namespace() -> Vec<u8> {
        b"consensus_fuzz".to_vec()
    }

    fn node_count() -> u32 {
        4
    }

    fn required_containers() -> u64 {
        200
    }

    fn fixture(context: &mut deterministic::Context, n: u32) -> Fixture<Self::Scheme>;
}

pub struct SimplexEd25519;

impl Simplex for SimplexEd25519 {
    type Scheme = simplex_ed25519::Scheme;

    fn fixture(context: &mut deterministic::Context, n: u32) -> Fixture<Self::Scheme> {
        ed25519_fixture(context, n)
    }
}

pub struct SimplexBls12381MinPk;

impl Simplex for SimplexBls12381MinPk {
    type Scheme = bls12381_threshold::Scheme<MinPk>;

    fn fixture(context: &mut deterministic::Context, n: u32) -> Fixture<Self::Scheme> {
        bls_threshold_fixture::<MinPk, _>(context, n)
    }
}

fn run_fuzz<P: Simplex>(input: FuzzInput) {
    let n = P::node_count();
    let required_containers = P::required_containers();
    let namespace = P::namespace();
    let cfg = deterministic::Config::new().with_seed(input.seed);
    let executor = deterministic::Runner::new(cfg);
    executor.start(|mut context| async move {
        // Create simulated network
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            NetworkConfig {
                max_size: 1024 * 1024,
                disconnect_on_block: false, // Ignore blocking operation
            },
        );

        // Start network
        network.start();

        // Register participants
        let (mut validator_keys, validators, mut signing_schemes, _) = P::fixture(&mut context, n);
        let mut registrations = register_validators(&mut oracle, &validators).await;

        // Link validators.
        // The first validator is byzantine.
        let link = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(1),
            success_rate: 1.0,
        };

        link_peers(
            &mut oracle,
            &validators,
            Action::Link(link),
            input.partition.create(),
        )
        .await;

        // Create engines
        let relay = Arc::new(relay::Relay::new());
        let mut reporters = Vec::new();

        // Start a consensus engine for the fuzzing actor (first validator).
        let ed25519_key = validator_keys.remove(0);
        let scheme = signing_schemes.remove(0);
        let validator = validators[0].clone(); // Don't remove from validators list
        let context = context.with_label(&format!("validator-{}", ed25519_key.public_key()));
        let reporter_config = reporter::Config {
            namespace: namespace.clone(),
            participants: validators.clone().into(),
            scheme: scheme.clone(),
        };
        let reporter = reporter::Reporter::new(context.with_label("reporter"), reporter_config);

        let (pending, _recovered, _resolver) = registrations
            .remove(&validator)
            .expect("validator should be registered");
        let actor = Fuzzer::<_, _, Sha256Digest>::new(
            context.with_label("fuzzing_actor"),
            ed25519_key,
            scheme,
            reporter,
            namespace.clone(),
            input.clone(),
        );
        actor.start(pending);

        // Start regular consensus engines for the remaining validators.
        for (idx_key, private_key) in validator_keys.into_iter().enumerate() {
            let validator = private_key.public_key();
            let context = context.with_label(&format!("validator-{}", private_key.public_key()));
            let idx_scheme = idx_key; // We already removed the first scheme, so indices align
            let reporter_config = reporter::Config {
                namespace: namespace.clone(),
                participants: validators.clone().into(),
                scheme: signing_schemes[idx_scheme].clone(),
            };
            let reporter = reporter::Reporter::new(context.with_label("reporter"), reporter_config);
            reporters.push(reporter.clone());
            let (pending, recovered, resolver) = registrations
                .remove(&validator)
                .expect("validator should be registered");

            let application_cfg = application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                participant: validator.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
            };
            let (actor, application) =
                application::Application::new(context.with_label("application"), application_cfg);
            actor.start();
            let blocker = oracle.control(validator.clone());
            let cfg = config::Config {
                me: validator.clone(),
                blocker,
                participants: validators.clone().into(),
                scheme: signing_schemes[idx_scheme].clone(),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: validator.to_string(),
                mailbox_size: 1024,
                epoch: 333,
                namespace: namespace.clone(),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: 10,
                skip_timeout: 5,
                max_fetch_count: 1,
                fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let engine = Engine::new(context.with_label("engine"), cfg);
            engine.start(pending, recovered, resolver);
        }

        match input.partition {
            PartitionStrategy::Connected => {
                // Wait for all engines to finish
                let mut finalizers = Vec::new();
                for reporter in reporters.iter_mut() {
                    let (mut latest, mut monitor): (View, Receiver<View>) =
                        reporter.subscribe().await;
                    finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                        while latest < required_containers {
                            latest = monitor.next().await.expect("event missing");
                        }
                    }));
                }
                join_all(finalizers).await;
            }
            _ => {
                context.sleep(Duration::from_secs(10)).await;
            }
        }

        let replica_states = extract_simplex_state(reporters);
        check_invariants(n, replica_states);
    });
}
pub fn fuzz<P: Simplex>(input: FuzzInput) {
    // Set up a custom panic hook
    let original_hook = panic::take_hook();
    panic::set_hook(Box::new(|panic_info| {
        let panic_message = format!("{panic_info}");

        // Check if we should ignore this panic
        for pattern in VALID_PANICS {
            if panic_message.contains(pattern) {
                println!("Ignored panic: {panic_message}");
                SHOULD_IGNORE_PANIC.store(true, Ordering::SeqCst);
                return;
            }
        }

        // Let the original hook handle unexpected panics
        SHOULD_IGNORE_PANIC.store(false, Ordering::SeqCst);
        println!("Unexpected panic: {panic_message}");
    }));

    // Try to catch the panic
    let result = panic::catch_unwind(move || {
        run_fuzz::<P>(input);
    });

    // Restore original hook
    panic::set_hook(original_hook);

    // If we caught a panic, and it should be ignored, continue
    if result.is_err() && SHOULD_IGNORE_PANIC.load(Ordering::SeqCst) {
        return;
    }

    // If we caught a panic, and it shouldn't be ignored, re-panic
    if result.is_err() {
        panic!("Unexpected panic occurred");
    }
}

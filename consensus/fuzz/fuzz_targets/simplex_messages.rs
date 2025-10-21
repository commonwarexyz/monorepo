#![no_main]

mod mocks;
use crate::mocks::{check_invariants, extract_simplex_state};
use commonware_consensus::{
    simplex::{
        config,
        mocks::{application, fixtures::ed25519_fixture, relay, reporter},
        Engine,
    },
    Monitor,
};
use commonware_cryptography::{sha256::Digest as Sha256Digest, Sha256, Signer as _};
use commonware_p2p::simulated::{
    helpers::{link_peers, Action, PartitionStrategy},
    Config as NetworkConfig, Link, Network, Oracle, Receiver, Sender,
};
use commonware_runtime::{
    buffer::PoolRef,
    deterministic::{self},
    Clock, Metrics, Runner, Spawner,
};
use commonware_utils::{NZUsize, NZU32};
use futures::{future::join_all, StreamExt};
use governor::Quota;
use libfuzzer_sys::fuzz_target;
use mocks::{simplex_fuzzer::Fuzzer, FuzzInput, PAGE_CACHE_SIZE, PAGE_SIZE};
use std::{
    collections::HashMap,
    panic,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

const VALID_PANICS: [&str; 3] = [
    "invalid payload:",
    "invalid parent (in payload):",
    "invalid round (in payload)",
];

static SHOULD_IGNORE_PANIC: AtomicBool = AtomicBool::new(false);

async fn register_validators<P: commonware_cryptography::PublicKey>(
    oracle: &mut Oracle<P>,
    validators: &[P],
) -> HashMap<
    P,
    (
        (Sender<P>, Receiver<P>),
        (Sender<P>, Receiver<P>),
        (Sender<P>, Receiver<P>),
    ),
> {
    let mut registrations = HashMap::new();
    for validator in validators.iter() {
        let (pending_sender, pending_receiver) =
            oracle.register(validator.clone(), 0).await.unwrap();
        let (recovered_sender, recovered_receiver) =
            oracle.register(validator.clone(), 1).await.unwrap();
        let (resolver_sender, resolver_receiver) =
            oracle.register(validator.clone(), 2).await.unwrap();
        registrations.insert(
            validator.clone(),
            (
                (pending_sender, pending_receiver),
                (recovered_sender, recovered_receiver),
                (resolver_sender, resolver_receiver),
            ),
        );
    }
    registrations
}

fn fuzzer(input: FuzzInput) {
    // Create context
    let n = 4;
    let required_containers = 200;
    let namespace = b"consensus_fuzz".to_vec();
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
        let (mut schemes, validators, mut signing_schemes, _) = ed25519_fixture(&mut context, n);
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
        let ed25519_key = schemes.remove(0);
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
        for (idx_key, scheme) in schemes.into_iter().enumerate() {
            let validator = scheme.public_key();
            let context = context.with_label(&format!("validator-{}", scheme.public_key()));
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
                    let (mut latest, mut monitor) = reporter.subscribe().await;
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

fuzz_target!(|input: FuzzInput| {
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
    let result = panic::catch_unwind(|| {
        fuzzer(input);
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
});

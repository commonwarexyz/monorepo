#![no_main]

mod mocks;
use crate::mocks::{check_invariants, extract_threshold_simplex_state};
use commonware_consensus::{
    threshold_simplex::{
        config::Config,
        mocks::{
            application, relay,
            supervisor::{self, Supervisor},
        },
        Engine,
    },
    Monitor,
};
use commonware_cryptography::{
    bls12381::{dkg::ops, primitives::variant::MinPk},
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest as Sha256Digest,
    PrivateKeyExt as _, Sha256, Signer as _,
};
use commonware_p2p::simulated::{
    helpers::{link_peers, threshold_simplex_register_peers, Action, PartitionStrategy},
    Config as NetworkConfig, Link, Network,
};
use commonware_runtime::{
    buffer::PoolRef,
    deterministic::{self},
    Clock, Metrics, Runner, Spawner,
};
use commonware_utils::{quorum, NZUsize, NZU32};
use futures::{future::join_all, StreamExt};
use governor::Quota;
use libfuzzer_sys::fuzz_target;
use mocks::{threshold_simplex_fuzzer::ThresholdFuzzer, FuzzInput, PAGE_CACHE_SIZE, PAGE_SIZE};
use std::{
    collections::BTreeMap,
    panic,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

const VALID_PANICS: [&str; 2] = ["invalid view (in payload):", "invalid parent (in payload):"];

static SHOULD_IGNORE_PANIC: AtomicBool = AtomicBool::new(false);

fn fuzzer(input: FuzzInput) {
    // Create context
    let n = 4;
    let threshold = quorum(n);
    let required_containers = 10;
    let namespace = b"consensus_fuzz".to_vec();
    let cfg = deterministic::Config::new().with_seed(input.seed);
    let executor = deterministic::Runner::new(cfg);
    executor.start(|mut context| async move {
        // Create simulated network
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            NetworkConfig {
                max_size: 1024 * 1024,
                ignore_blocks: true, // Ignore block operation
            },
        );

        // Start network
        network.start();

        // Register participants
        let mut schemes = Vec::new();
        let mut validators = Vec::new();
        for i in 0..n {
            let scheme = PrivateKey::from_seed(i as u64);
            let pk = scheme.public_key();
            schemes.push(scheme);
            validators.push(pk);
        }
        validators.sort();
        schemes.sort_by_key(|s| s.public_key());
        let mut registrations = threshold_simplex_register_peers(&mut oracle, &validators).await;

        let partition = input.partition.clone();

        // Link all validators
        // The first validator is byzantine.
        let link = Link {
            latency: Duration::from_millis(0),
            jitter: Duration::from_millis(0),
            success_rate: 1.0,
        };
        link_peers(
            &mut oracle,
            &validators,
            Action::Link(link),
            input.partition.create(),
        )
        .await;

        // Derive threshold
        let (polynomial, shares) =
            ops::generate_shares::<_, MinPk>(&mut context, None, n, threshold);

        // Create engines
        let relay = Arc::new(relay::Relay::new());
        let mut supervisors = Vec::new();

        // Start a consensus engine for the fuzzing actor (first validator).
        let scheme = schemes.remove(0);
        let validator = scheme.public_key();
        let context = context.with_label(&format!("validator-{validator}"));
        let mut participants = BTreeMap::new();
        participants.insert(
            0,
            (
                polynomial.clone(),
                validators.clone(),
                Some(shares[0].clone()),
            ),
        );

        let supervisor_config = supervisor::Config::<_, MinPk> {
            namespace: namespace.clone(),
            participants,
        };
        let supervisor = Supervisor::<PublicKey, MinPk, Sha256Digest>::new(supervisor_config);
        let (pending, _, _) = registrations
            .remove(&validator)
            .expect("validator should be registered");
        let engine = ThresholdFuzzer::new(
            context.with_label("fuzzing_actor"),
            scheme,
            shares[0].clone(),
            supervisor,
            namespace.clone(),
            input,
        );
        engine.start(pending);

        // Start regular consensus engines for the remaining validators.
        for (idx, scheme) in schemes.into_iter().enumerate() {
            let validator = scheme.public_key();
            let context = context.with_label(&format!("validator-{validator}"));
            let mut participants = BTreeMap::new();
            participants.insert(
                0,
                (
                    polynomial.clone(),
                    validators.clone(),
                    Some(shares[idx + 1].clone()),
                ),
            );
            let supervisor_config = supervisor::Config::<_, MinPk> {
                namespace: namespace.clone(),
                participants,
            };
            let supervisor = Supervisor::<PublicKey, MinPk, Sha256Digest>::new(supervisor_config);
            supervisors.push(supervisor.clone());
            let (pending, recovered, resolver) = registrations
                .remove(&validator)
                .expect("validator should be registered");

            let application_cfg = application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                participant: validator.clone(),
                propose_latency: (0.01, 0.3),
                verify_latency: (0.01, 0.3),
            };
            let (actor, application) =
                application::Application::new(context.with_label("application"), application_cfg);
            actor.start();
            let blocker = oracle.control(scheme.public_key());
            let cfg = Config {
                crypto: scheme,
                blocker,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: supervisor.clone(),
                partition: validator.to_string(),
                supervisor: supervisor.clone(),
                mailbox_size: 1024,
                namespace: namespace.clone(),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(3),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: 5,
                skip_timeout: 3,
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

        match partition {
            PartitionStrategy::Connected => {
                // Wait for all engines to finish
                let mut finalizers = Vec::new();
                for supervisor in supervisors.iter_mut() {
                    let (mut latest, mut monitor) = supervisor.subscribe().await;
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

        // Extract data from supervisors and convert to generic format
        let replica_data = extract_threshold_simplex_state(supervisors);
        check_invariants(n, replica_data);
    });
}

fuzz_target!(|input: FuzzInput| {
    // Set up custom panic hook
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

    // If we caught a panic and it should be ignored, continue
    if result.is_err() && SHOULD_IGNORE_PANIC.load(Ordering::SeqCst) {
        return;
    }

    // If we caught a panic and it shouldn't be ignored, re-panic
    if result.is_err() {
        panic!("Unexpected panic occurred");
    }
});

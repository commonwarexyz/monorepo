#![no_main]

mod mocks;
use commonware_consensus::{
    simplex::{
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
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest as Sha256Digest,
    PrivateKeyExt as _, Sha256, Signer as _,
};
use commonware_p2p::simulated::{
    helpers::{link_peers, simplex_register_peers, Action, PartitionStrategy},
    Config as NetworkConfig, Link, Network,
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
    collections::BTreeMap,
    panic,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use crate::mocks::check_invariants;

const VALID_PANICS: [&str; 2] = ["invalid view (in payload):", "invalid parent (in payload):"];

static SHOULD_IGNORE_PANIC: AtomicBool = AtomicBool::new(false);

fn fuzzer(input: FuzzInput) {
    // Create context
    let n = 4;
    let required_containers = 10;
    let namespace = b"consensus_fuzz".to_vec();
    let cfg = deterministic::Config::new().with_seed(input.seed);
    let executor = deterministic::Runner::new(cfg);
    executor.start(|context| async move {
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
        let participants = BTreeMap::from_iter(vec![(0, validators.clone())]);
        let mut registrations = simplex_register_peers(&mut oracle, &validators).await;
        let partition = input.partition.clone();

        // Link all validators
        // The first validator is byzantine.
        let link = Link {
            latency: 0.0,
            jitter: 0.0,
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
        let mut supervisors = Vec::new();

        // Start a consensus engine for the fuzzing actor (first validator).
        let scheme = schemes.remove(0);
        let validator = scheme.public_key();
        let context = context.with_label(&format!("validator-{validator}"));
        let supervisor_config = supervisor::Config {
            namespace: namespace.clone(),
            participants: participants.clone(),
        };
        let supervisor = Supervisor::<PublicKey, Sha256Digest>::new(supervisor_config);

        let (voter, _) = registrations
            .remove(&validator)
            .expect("validator should be registered");
        let actor = Fuzzer::new(
            context.with_label("fuzzing_actor"),
            scheme,
            supervisor,
            namespace.clone(),
            input,
        );
        actor.start(voter);

        // Start regular consensus engines for the remaining validators.
        for scheme in schemes.into_iter() {
            let validator = scheme.public_key();
            let context = context.with_label(&format!("validator-{validator}"));
            let supervisor_config = supervisor::Config {
                namespace: namespace.clone(),
                participants: participants.clone(),
            };
            let supervisor = Supervisor::<PublicKey, Sha256Digest>::new(supervisor_config);
            supervisors.push(supervisor.clone());

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

            let cfg = Config {
                crypto: scheme,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: supervisor.clone(),
                partition: validator.to_string(),
                compression: Some(3),
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
                max_participants: n as usize,
                fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, resolver) = registrations
                .remove(&validator)
                .expect("validator should be registered");
            let engine = Engine::new(context.with_label("engine"), cfg);
            engine.start(voter, resolver);
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

        check_invariants(n, supervisors);
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

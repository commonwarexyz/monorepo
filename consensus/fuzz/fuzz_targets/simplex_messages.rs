#![no_main]

mod common;
use common::{link_validators, register_validators, Action};

mod mocks;
use commonware_consensus::simplex::{
    config::Config,
    mocks::{
        application, relay,
        supervisor::{self, Supervisor},
    },
    Engine,
};
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest as Sha256Digest,
    PrivateKeyExt as _, Sha256, Signer as _,
};
use commonware_p2p::simulated::{Config as NetworkConfig, Link, Network};
use commonware_runtime::{
    deterministic::{self},
    Clock, Metrics, Runner,
};
use commonware_utils::NZU32;
use governor::Quota;
use libfuzzer_sys::fuzz_target;
use mocks::{FuzzInput, Fuzzer};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

fn fuzzer(input: FuzzInput) {
    // Create context
    let n = 4;
    let namespace = b"consensus_fuzz".to_vec();
    let cfg = deterministic::Config::new()
        .with_seed(input.seed)
        .with_timeout(Some(Duration::from_secs(15))); // Reduced timeout for faster cleanup
    let executor = deterministic::Runner::new(cfg);
    executor.start(|context| async move {
        // Create simulated network
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            NetworkConfig {
                max_size: 1024 * 1024,
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
        let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);
        let mut registrations = register_validators(&mut oracle, &validators).await;

        // Link all validators
        // The first validator is byzantine.
        let link = Link {
            latency: 0.0,
            jitter: 0.0,
            success_rate: 1.0,
        };
        link_validators(&mut oracle, &validators, Action::Link(link), input.partition.create()).await;

        // Create engines
        let relay = Arc::new(relay::Relay::new());
        let mut supervisors = Vec::new();

        // Start fuzzing actor (first validator)
        let first_scheme = schemes.remove(0);
        let first_validator = first_scheme.public_key();
        let first_context = context.with_label(&format!("validator-{first_validator}"));
        let first_supervisor_config = supervisor::Config {
            namespace: namespace.clone(),
            participants: view_validators.clone(),
        };
        let first_supervisor = Supervisor::<PublicKey, Sha256Digest>::new(first_supervisor_config);

        let (voter, _) = registrations
            .remove(&first_validator)
            .expect("validator should be registered");
        let actor = Fuzzer::new(
            first_context.with_label("fuzzing_actor"),
            first_scheme,
            first_supervisor,
            namespace.clone(),
            input,
        );
        actor.start(voter);

        // Start regular consensus engines for the remaining validators
        for scheme in schemes.into_iter() {
            let context = context.with_label(&format!("validator-{}", scheme.public_key()));
            let validator = scheme.public_key();
            let supervisor_config = supervisor::Config {
                namespace: namespace.clone(),
                participants: view_validators.clone(),
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
                supervisor,
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
                replay_buffer: 1024 * 1024,
                write_buffer: 1024 * 1024,
            };
            let (voter, resolver) = registrations
                .remove(&validator)
                .expect("validator should be registered");
            let engine = Engine::new(context.with_label("engine"), cfg);
            engine.start(voter, resolver);
        }

        context.sleep(Duration::from_secs(1)).await;

        drop(supervisors);
        drop(relay);
        drop(registrations);
        drop(oracle);
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzzer(input);
});

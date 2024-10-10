//! Fixed
//!
//! PoA Consensus useful for running a DKG (round-robin leader selection, update participants with config).
//!
//! # Sync
//!
//! Wait for block finalization at tip (2f+1), fetch heights backwards (don't
//! need to backfill views).
//!
//! # Differences from Simplex Paper
//!
//! * Block timeout in addition to notarization timeout
//! * Backfill blocks from notarizing peers rather than passing along with notarization

mod config;
mod engine;
mod orchestrator;
mod utils;
mod voter;

mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Network closed")]
    NetworkClosed,
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Invalid block")]
    InvalidBlock,
    #[error("Invalid signature")]
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Application, Hash, Height, Payload};
    use bytes::Bytes;
    use commonware_cryptography::{Ed25519, PublicKey, Scheme};
    use commonware_p2p::simulated::{Config, Link, Network};
    use commonware_runtime::{deterministic::Executor, select, Clock, Runner, Spawner};
    use commonware_utils::{hash, hex};
    use engine::Engine;
    use futures::{channel::mpsc, SinkExt, StreamExt};
    use prometheus_client::registry::Registry;
    use std::{
        collections::{BTreeMap, HashMap, HashSet},
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tracing::{debug, Level};

    // TODO: break into official mock object that any consensus can use
    enum Progress {
        Notarized(Height),
        Finalized(Height),
    }
    struct MockApplication {
        participant: PublicKey,

        verified: HashMap<Hash, Height>,
        finalized: HashMap<Hash, Height>,

        progress: mpsc::UnboundedSender<(PublicKey, Progress)>,
    }

    impl MockApplication {
        fn new(
            participant: PublicKey,
            sender: mpsc::UnboundedSender<(PublicKey, Progress)>,
        ) -> Self {
            Self {
                participant,
                verified: HashMap::new(),
                finalized: HashMap::new(),
                progress: sender,
            }
        }

        fn verify_payload(height: Height, payload: &Payload) {
            if payload.len() != 32 + 8 {
                panic!("invalid payload length");
            }
            let parsed_height = Height::from_be_bytes(payload[32..].try_into().unwrap());
            if parsed_height != height {
                panic!("invalid height");
            }
        }
    }

    impl Application for MockApplication {
        fn genesis(&mut self) -> (Hash, Payload) {
            let payload = Bytes::from("genesis");
            let hash = hash(&payload);
            self.verified.insert(hash.clone(), 0);
            self.finalized.insert(hash.clone(), 0);
            (hash, payload)
        }

        async fn propose(&mut self, parent: Hash, height: Height) -> Option<Payload> {
            let parent = self.verified.get(&parent).expect("parent not verified");
            if parent + 1 != height {
                panic!("invalid height");
            }
            let mut payload = Vec::new();
            payload.extend_from_slice(&self.participant);
            payload.extend_from_slice(&height.to_be_bytes());
            Some(Bytes::from(payload))
        }

        fn parse(&self, _parent: Hash, height: Height, payload: Payload) -> Option<Hash> {
            Self::verify_payload(height, &payload);
            Some(hash(&payload))
        }

        async fn verify(
            &mut self,
            parent: Hash,
            height: Height,
            payload: Payload,
            hash: Hash,
        ) -> bool {
            if let Some(height) = self.verified.get(&hash) {
                panic!("hash already verified: {}:{:?}", height, hex(&hash));
            }
            Self::verify_payload(height, &payload);
            let parent = match self.verified.get(&parent) {
                Some(parent) => parent,
                None => {
                    panic!(
                        "[{:?}] parent {:?} of {}, not verified",
                        hex(&self.participant),
                        hex(&parent),
                        height
                    );
                }
            };
            if parent + 1 != height {
                panic!("invalid height");
            }
            self.verified.insert(hash.clone(), height);
            true
        }

        async fn notarized(&mut self, hash: Hash) {
            let height = self.verified.get(&hash).expect("hash not verified");
            if self.finalized.contains_key(&hash) {
                panic!("hash already finalized");
            }
            self.progress
                .send((self.participant.clone(), Progress::Notarized(*height)))
                .await
                .unwrap();
        }

        async fn finalized(&mut self, hash: Hash) {
            if let Some(height) = self.finalized.get(&hash) {
                panic!("hash already finalized: {}:{:?}", height, hex(&hash));
            }
            let height = self.verified.get(&hash).expect("hash not verified");
            self.finalized.insert(hash, *height);
            self.progress
                .send((self.participant.clone(), Progress::Finalized(*height)))
                .await
                .unwrap();
        }
    }

    // TODO: add test where vote broadcast very very close to timeout (to ensure no safety faults)
    // TODO: follow-up with updated links after x views to improve speed and ensure finalizes

    #[test]
    fn test_all_online() {
        // Configure logging
        tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_line_number(true)
            .init();

        // Create runtime
        let n = 5;
        let required_blocks = 100;
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for scheme in schemes.into_iter() {
                // Register on network
                let validator = scheme.public_key();
                let (block_sender, block_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency_mean: 10.0,
                                latency_stddev: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let cfg = config::Config {
                    crypto: scheme,
                    application: MockApplication::new(validator, done_sender.clone()),
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: Bytes::from("consensus"),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    null_vote_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    validators: view_validators.clone(),
                };
                let engine = Engine::new(runtime.clone(), cfg);
                runtime.spawn("engine", async move {
                    engine
                        .run((block_sender, block_receiver), (vote_sender, vote_receiver))
                        .await;
                });
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let Progress::Finalized(height) = event {
                    if height < required_blocks {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n {
                    break;
                }
            }
        });
    }

    #[test]
    fn test_one_offline() {
        // Configure logging
        tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_line_number(true)
            .init();

        // Create runtime
        let n = 5;
        let required_blocks = 100;
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for (idx, scheme) in schemes.into_iter().enumerate() {
                // Skip first peer
                if idx == 0 {
                    continue;
                }

                // Register on network
                let validator = scheme.public_key();
                let (block_sender, block_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency_mean: 10.0,
                                latency_stddev: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let cfg = config::Config {
                    crypto: scheme,
                    application: MockApplication::new(validator, done_sender.clone()),
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: Bytes::from("consensus"),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    null_vote_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    validators: view_validators.clone(),
                };
                let engine = Engine::new(runtime.clone(), cfg);
                runtime.spawn("engine", async move {
                    engine
                        .run((block_sender, block_receiver), (vote_sender, vote_receiver))
                        .await;
                });
            }

            // Wait for all online engines to finish
            let mut completed = HashSet::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let Progress::Finalized(height) = event {
                    if height < required_blocks {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n - 1 {
                    break;
                }
            }
        });
    }

    #[test]
    fn test_catchup() {
        // Configure logging
        tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_line_number(true)
            .init();

        // Create runtime
        let n = 5;
        let required_blocks = 100;
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for (idx, scheme) in schemes.into_iter().enumerate() {
                // Skip first peer
                if idx == 0 {
                    continue;
                }

                // Register on network
                let validator = scheme.public_key();
                let (block_sender, block_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency_mean: 10.0,
                                latency_stddev: 2.5,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let cfg = config::Config {
                    crypto: scheme,
                    application: MockApplication::new(validator, done_sender.clone()),
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: Bytes::from("consensus"),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    null_vote_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    max_fetch_count: 32,
                    max_fetch_size: 1024 * 512,
                    validators: view_validators.clone(),
                };
                let engine = Engine::new(runtime.clone(), cfg);
                runtime.spawn("engine", async move {
                    engine
                        .run((block_sender, block_receiver), (vote_sender, vote_receiver))
                        .await;
                });
            }

            // Wait for all online engines to finish
            let mut completed = HashSet::new();
            let mut highest_finalized = 0;
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let Progress::Finalized(height) = event {
                    if height > highest_finalized {
                        highest_finalized = height;
                    }
                    if height < required_blocks {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n - 1 {
                    break;
                }
            }

            // Start engine for first peer
            let scheme = Ed25519::from_seed(0);
            let validator = scheme.public_key();
            let (block_sender, block_receiver) = oracle
                .register(validator.clone(), 0, 1024 * 1024)
                .await
                .unwrap();
            let (vote_sender, vote_receiver) = oracle
                .register(validator.clone(), 1, 1024 * 1024)
                .await
                .unwrap();

            // Link to all other validators
            for other in validators.iter() {
                if other == &validator {
                    continue;
                }
                oracle
                    .add_link(
                        validator.clone(),
                        other.clone(),
                        Link {
                            latency_mean: 10.0,
                            latency_stddev: 2.5,
                            success_rate: 1.0,
                        },
                    )
                    .await
                    .unwrap();
            }

            // Start engine
            let cfg = config::Config {
                crypto: scheme,
                application: MockApplication::new(validator, done_sender.clone()),
                registry: Arc::new(Mutex::new(Registry::default())),
                namespace: Bytes::from("consensus"),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                null_vote_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                max_fetch_count: 32,
                max_fetch_size: 1024 * 512,
                validators: view_validators.clone(),
            };
            let engine = Engine::new(runtime.clone(), cfg);
            runtime.spawn("engine", async move {
                engine
                    .run((block_sender, block_receiver), (vote_sender, vote_receiver))
                    .await;
            });

            // Wait for new engine to finish
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if validator != validator {
                    continue;
                }
                if let Progress::Finalized(height) = event {
                    if height < highest_finalized + required_blocks {
                        // We want to see `required_blocks` once we catch up
                        continue;
                    }
                    return;
                }
            }
        });
    }

    #[test]
    fn test_all_recovery() {
        // Configure logging
        tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_line_number(true)
            .init();

        // Create runtime
        let n = 5;
        let required_blocks = 100;
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for scheme in schemes.iter() {
                // Register on network
                let validator = scheme.public_key();
                let (block_sender, block_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency_mean: 3000.0,
                                latency_stddev: 0.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    application: MockApplication::new(validator, done_sender.clone()),
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: Bytes::from("consensus"),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    null_vote_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    validators: view_validators.clone(),
                };
                let engine = Engine::new(runtime.clone(), cfg);
                runtime.spawn("engine", async move {
                    engine
                        .run((block_sender, block_receiver), (vote_sender, vote_receiver))
                        .await;
                });
            }

            // Wait for a few virtual minutes (shouldn't finalize anything)
            select! {
                _timeout = runtime.sleep(Duration::from_secs(60)) => {},
                _done = done_receiver.next() => {
                    panic!("engine should not notarize or finalize anything");
                }
            }

            // Update links
            for scheme in schemes.iter() {
                let validator = scheme.public_key();
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency_mean: 10.0,
                                latency_stddev: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let Progress::Finalized(height) = event {
                    if height < required_blocks {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n {
                    break;
                }
            }
        });
    }

    #[test]
    fn test_no_finality() {
        // Configure logging
        tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_line_number(true)
            .init();

        // Create runtime
        let n = 5;
        let required_blocks = 100;
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for scheme in schemes.iter() {
                // Register on network
                let validator = scheme.public_key();
                let (block_sender, block_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency_mean: 800.0,
                                latency_stddev: 0.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    application: MockApplication::new(validator, done_sender.clone()),
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: Bytes::from("consensus"),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(1),
                    null_vote_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    validators: view_validators.clone(),
                };
                let engine = Engine::new(runtime.clone(), cfg);
                runtime.spawn("engine", async move {
                    engine
                        .run((block_sender, block_receiver), (vote_sender, vote_receiver))
                        .await;
                });
            }

            // Wait for all engines to notarize
            let mut completed = HashSet::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                match event {
                    Progress::Notarized(height) => {
                        if height < required_blocks {
                            continue;
                        }
                        completed.insert(validator);
                    }
                    Progress::Finalized(_) => {
                        panic!("should not finalize");
                    }
                }
                if completed.len() == n {
                    break;
                }
            }
        });
    }

    #[test]
    fn test_partition() {
        // Configure logging
        tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_line_number(true)
            .init();

        // Create runtime
        let n = 10;
        let required_blocks = 100;
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for scheme in schemes.iter() {
                // Register on network
                let validator = scheme.public_key();
                let (block_sender, block_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency_mean: 10.0,
                                latency_stddev: 0.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    application: MockApplication::new(validator, done_sender.clone()),
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: Bytes::from("consensus"),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    null_vote_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    validators: view_validators.clone(),
                };
                let engine = Engine::new(runtime.clone(), cfg);
                runtime.spawn("engine", async move {
                    engine
                        .run((block_sender, block_receiver), (vote_sender, vote_receiver))
                        .await;
                });
            }

            // Wait for all engines to finalize
            let mut completed = HashSet::new();
            let mut highest_finalized = 0;
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let Progress::Finalized(height) = event {
                    if height > highest_finalized {
                        highest_finalized = height;
                    }
                    if height < required_blocks {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n {
                    break;
                }
            }

            // Cut all links between validator halves
            for (me_idx, me) in validators.iter().enumerate() {
                for (other_idx, other) in validators.iter().enumerate() {
                    if other == me {
                        continue;
                    }
                    if me_idx < n / 2 && other_idx >= n / 2 {
                        debug!("cutting link between {:?} and {:?}", me_idx, other_idx);
                        oracle.remove_link(me.clone(), other.clone()).await.unwrap();
                    }
                    if me_idx >= n / 2 && other_idx < n / 2 {
                        debug!("cutting link between {:?} and {:?}", me_idx, other_idx);
                        oracle.remove_link(me.clone(), other.clone()).await.unwrap();
                    }
                }
            }

            // Empty done receiver
            loop {
                if done_receiver.try_next().is_err() {
                    break;
                }
            }

            // Wait for a few virtual minutes (shouldn't finalize anything)
            select! {
                _timeout = runtime.sleep(Duration::from_secs(600)) => {},
                _done = done_receiver.next() => {
                    panic!("engine should not notarize or finalize anything");
                }
            }

            // Restore links
            debug!("restoring links");
            for scheme in schemes.iter() {
                let validator = scheme.public_key();
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency_mean: 10.0,
                                latency_stddev: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let Progress::Finalized(height) = event {
                    if height < required_blocks + highest_finalized {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n {
                    break;
                }
            }
        });
    }

    #[test]
    fn test_jank_links() {
        // Configure logging
        tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_line_number(true)
            .init();

        // TODO: failing because blocks in consecutive views have the same height (likely need to be
        // more particular about honoring notarizations)

        // Create runtime
        let n = 10;
        let required_blocks = 100;
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for scheme in schemes.into_iter() {
                // Register on network
                let validator = scheme.public_key();
                let (block_sender, block_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency_mean: 200.0,
                                latency_stddev: 10.0,
                                success_rate: 0.8,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let cfg = config::Config {
                    crypto: scheme,
                    application: MockApplication::new(validator, done_sender.clone()),
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: Bytes::from("consensus"),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    null_vote_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    validators: view_validators.clone(),
                };
                let engine = Engine::new(runtime.clone(), cfg);
                runtime.spawn("engine", async move {
                    engine
                        .run((block_sender, block_receiver), (vote_sender, vote_receiver))
                        .await;
                });
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let Progress::Finalized(height) = event {
                    if height < required_blocks {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n {
                    break;
                }
            }
        });
    }
}

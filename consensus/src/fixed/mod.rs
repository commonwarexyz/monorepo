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
    use commonware_runtime::{deterministic::Executor, Runner, Spawner};
    use commonware_utils::{hash, hex};
    use engine::Engine;
    use futures::{
        channel::{mpsc, oneshot},
        StreamExt,
    };
    use prometheus_client::registry::Registry;
    use std::{
        collections::{BTreeMap, HashMap},
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tracing::Level;

    // TODO: break into official mock object that any consensus can use
    struct MockApplication {
        participant: PublicKey,

        verified: HashMap<Hash, Height>,
        finalized: HashMap<Hash, Height>,

        done_height: Height,
        done: mpsc::Sender<()>,
    }

    impl MockApplication {
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

        fn propose(&mut self, parent: Hash, height: Height) -> Option<Payload> {
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

        fn verify(&mut self, parent: Hash, height: Height, payload: Payload, hash: Hash) -> bool {
            Self::verify_payload(height, &payload);
            let parent = self.verified.get(&parent).expect("parent not verified");
            if parent + 1 != height {
                panic!("invalid height");
            }
            self.verified.insert(hash.clone(), height);
            true
        }

        fn notarized(&mut self, hash: Hash) {
            if !self.verified.contains_key(&hash) {
                panic!("hash not verified");
            }
        }

        fn finalized(&mut self, hash: Hash) {
            if let Some(height) = self.finalized.get(&hash) {
                panic!("hash already finalized: {}:{:?}", height, hex(&hash));
            }
            let height = self.verified.get(&hash).expect("hash not finalized");
            self.finalized.insert(hash, *height);
            if *height == self.done_height {
                self.done.try_send(()).unwrap();
            }
        }
    }

    #[test]
    fn test_all_online() {
        // Configure logging
        tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_line_number(true)
            .init();

        // Create runtime
        let n = 5;
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
            let (done_sender, mut done_receiver) = mpsc::channel(schemes.len());
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
                    application: MockApplication {
                        participant: validator,
                        verified: HashMap::new(),
                        finalized: HashMap::new(),
                        done_height: 100,
                        done: done_sender.clone(),
                    },
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: Bytes::from("consensus"),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(1),
                    null_vote_retry: Duration::from_secs(1),
                    fetch_timeout: Duration::from_secs(1),
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
            for _ in 0..n {
                done_receiver.next().await.unwrap();
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
            let (done_sender, mut done_receiver) = mpsc::channel(schemes.len());
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
                    application: MockApplication {
                        participant: validator,
                        verified: HashMap::new(),
                        finalized: HashMap::new(),
                        done_height: 100,
                        done: done_sender.clone(),
                    },
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: Bytes::from("consensus"),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(1),
                    null_vote_retry: Duration::from_secs(1),
                    fetch_timeout: Duration::from_secs(1),
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
            for _ in 0..(n - 1) {
                done_receiver.next().await.unwrap();
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
            let (done_sender, mut done_receiver) = mpsc::channel(schemes.len());
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
                    application: MockApplication {
                        participant: validator,
                        verified: HashMap::new(),
                        finalized: HashMap::new(),
                        done_height: 100,
                        done: done_sender.clone(),
                    },
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: Bytes::from("consensus"),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(1),
                    null_vote_retry: Duration::from_secs(1),
                    fetch_timeout: Duration::from_secs(1),
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
            for _ in 0..(n - 1) {
                done_receiver.next().await.unwrap();
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
                application: MockApplication {
                    participant: validator,
                    verified: HashMap::new(),
                    finalized: HashMap::new(),
                    done_height: 100,
                    done: done_sender.clone(),
                },
                registry: Arc::new(Mutex::new(Registry::default())),
                namespace: Bytes::from("consensus"),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(1),
                null_vote_retry: Duration::from_secs(1),
                fetch_timeout: Duration::from_secs(1),
                validators: view_validators.clone(),
            };
            let engine = Engine::new(runtime.clone(), cfg);
            runtime.spawn("engine", async move {
                engine
                    .run((block_sender, block_receiver), (vote_sender, vote_receiver))
                    .await;
            });

            // Wait for new engine to finish
            done_receiver.next().await.unwrap();
        });
    }
}

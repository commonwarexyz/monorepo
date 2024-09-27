//! Simulate messaging between arbitrary peers with configurable performance (i.e. drops, latency, corruption, etc.).
//!
//! To make the simulation deterministic, employ `commonware-runtime`'s `deterministic::Executor` (with a given seed).

pub mod network;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("message too large: {0}")]
    MessageTooLarge(usize),
    #[error("network closed")]
    NetworkClosed,
    #[error("not valid to link self")]
    LinkingSelf,
    #[error("invalid success rate (must be in [0, 1]): {0}")]
    InvalidSuccessRate(f64),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Receiver, Recipients, Sender};
    use bytes::Bytes;
    use commonware_cryptography::{utils::hex, Ed25519, Scheme};
    use commonware_runtime::{deterministic::Executor, Runner, Spawner};
    use futures::{channel::mpsc, SinkExt, StreamExt};
    use prometheus_client::registry::Registry;
    use rand::Rng;
    use std::{
        collections::{BTreeMap, HashMap}, sync::{Arc, Mutex}, time::Duration
    };

    fn simulate_messages(seed: u64, size: usize) -> (String, Vec<usize>) {
        // Create simulated network
        let (executor, runtime, auditor) = Executor::init(seed, Duration::from_millis(1), Arc::new(Mutex::new(Registry::default())));
        executor.start(async move {
            let mut network = network::Network::new(
                runtime.clone(),
                network::Config {
                    max_message_size: 1024 * 1024,
                },
            );

            // Register agents
            let mut agents = BTreeMap::new();
            let (seen_sender, mut seen_receiver) = mpsc::channel(1024);
            for i in 0..size {
                let pk = Ed25519::from_seed(i as u64).public_key();
                let (sender, mut receiver) = network.register(pk.clone());
                agents.insert(pk, sender);
                let mut agent_sender = seen_sender.clone();
                runtime.spawn(async move {
                    for _ in 0..size {
                        receiver.recv().await.unwrap();
                    }
                    agent_sender.send(i).await.unwrap();

                    // Exiting early here tests the case where the recipient end of an agent is dropped
                });
            }

            // Randomly link agents
            let only_inbound = Ed25519::from_seed(0).public_key();
            for agent in agents.keys() {
                if agent == &only_inbound {
                    // Test that we can gracefully handle missing links
                    continue;
                }
                for other in agents.keys() {
                    let result = network.link(
                        agent.clone(),
                        other.clone(),
                        network::Link {
                            latency_mean: 5.0,
                            latency_stddev: 2.5,
                            success_rate: 0.75,
                        },
                    );
                    if agent == other {
                        assert!(matches!(result, Err(Error::LinkingSelf)));
                    } else {
                        assert!(result.is_ok());
                    }
                }
            }

            // Send messages
            runtime.spawn({
                let mut runtime = runtime.clone();
                async move {
                    // Sort agents for deterministic output
                    let keys = agents.keys().collect::<Vec<_>>();

                    // Send messages
                    loop {
                        let index = runtime.gen_range(0..keys.len());
                        let sender = keys[index];
                        let msg = format!("hello from {}", hex(sender));
                        let msg = Bytes::from(msg);
                        let mut message_sender = agents.get(sender).unwrap().clone();
                        let sent = message_sender
                            .send(Recipients::All, msg.clone(), false)
                            .await
                            .unwrap();
                        if sender == &only_inbound {
                            assert_eq!(sent.len(), 0);
                        } else {
                            assert_eq!(sent.len(), keys.len() - 1);
                        }
                    }
                }
            });

            // Start network
            runtime.spawn(network.run());

            // Wait for all recipients
            let mut results = Vec::new();
            for _ in 0..size {
                results.push(seen_receiver.next().await.unwrap());
            }
            (auditor.state(), results)
        })
    }

    fn compare_outputs(seeds: u64, size: usize) {
        // Collect outputs
        let mut outputs = Vec::new();
        for seed in 0..seeds {
            outputs.push(simulate_messages(seed, size));
        }

        // Confirm outputs are deterministic
        for seed in 0..seeds {
            let output = simulate_messages(seed, size);
            assert_eq!(output, outputs[seed as usize]);
        }
    }

    #[test]
    fn test_determinism() {
        compare_outputs(25, 25);
    }

    #[test]
    fn test_invalid_message() {
        let (executor, mut runtime, _) = Executor::init(0, Duration::from_millis(1), Arc::new(Mutex::new(Registry::default())));
        executor.start(async move {
            // Create simulated network
            let mut network = network::Network::new(
                runtime.clone(),
                network::Config {
                    max_message_size: 1024 * 1024,
                },
            );

            // Register agents
            let mut agents = HashMap::new();
            for i in 0..10 {
                let pk = Ed25519::from_seed(i as u64).public_key();
                let (sender, _) = network.register(pk.clone());
                agents.insert(pk, sender);
            }

            // Start network
            runtime.spawn(network.run());

            // Send invalid message
            let keys = agents.keys().collect::<Vec<_>>();
            let index = runtime.gen_range(0..keys.len());
            let sender = keys[index];
            let mut message_sender = agents.get(sender).unwrap().clone();
            let mut msg = vec![0u8; 1024 * 1024 + 1];
            runtime.fill(&mut msg[..]);
            let result = message_sender
                .send(Recipients::All, msg.into(), false)
                .await
                .unwrap_err();

            // Confirm error is correct
            assert!(matches!(result, Error::MessageTooLarge(_)));
        });
    }

    #[test]
    fn test_linking_self() {
        let (executor, runtime, _) = Executor::init(0, Duration::from_millis(1), Arc::new(Mutex::new(Registry::default())));
        executor.start(async move {
            // Create simulated network
            let mut network = network::Network::new(
                runtime.clone(),
                network::Config {
                    max_message_size: 1024 * 1024,
                },
            );

            // Register agents
            let pk = Ed25519::from_seed(0).public_key();
            network.register(pk.clone());

            // Attempt to link self
            let result = network.link(
                pk.clone(),
                pk.clone(),
                network::Link {
                    latency_mean: 5.0,
                    latency_stddev: 2.5,
                    success_rate: 0.75,
                },
            );

            // Confirm error is correct
            assert!(matches!(result, Err(Error::LinkingSelf)));
        });
    }

    #[test]
    fn test_invalid_success_rate() {
        let (executor, runtime, _) = Executor::init(0, Duration::from_millis(1), Arc::new(Mutex::new(Registry::default())));
        executor.start(async move {
            // Create simulated network
            let mut network = network::Network::new(
                runtime.clone(),
                network::Config {
                    max_message_size: 1024 * 1024,
                },
            );

            // Register agents
            let pk1 = Ed25519::from_seed(0).public_key();
            let pk2 = Ed25519::from_seed(1).public_key();
            network.register(pk1.clone());
            network.register(pk2.clone());

            // Attempt to link with invalid success rate
            let result = network.link(
                pk1.clone(),
                pk2.clone(),
                network::Link {
                    latency_mean: 5.0,
                    latency_stddev: 2.5,
                    success_rate: 1.5,
                },
            );

            // Confirm error is correct
            assert!(matches!(result, Err(Error::InvalidSuccessRate(_))));
        });
    }

    #[test]
    fn test_simple_message_delivery() {
        let (executor, runtime, _) = Executor::init(0, Duration::from_millis(1), Arc::new(Mutex::new(Registry::default())));
        executor.start(async move {
            // Create simulated network
            let mut network = network::Network::new(
                runtime.clone(),
                network::Config {
                    max_message_size: 1024 * 1024,
                },
            );

            // Register agents
            let pk1 = Ed25519::from_seed(0).public_key();
            let pk2 = Ed25519::from_seed(1).public_key();
            let (mut sender1, mut receiver1) = network.register(pk1.clone());
            let (mut sender2, mut receiver2) = network.register(pk2.clone());

            // Link agents
            network
                .link(
                    pk1.clone(),
                    pk2.clone(),
                    network::Link {
                        latency_mean: 5.0,
                        latency_stddev: 2.5,
                        success_rate: 1.0,
                    },
                )
                .unwrap();
            network
                .link(
                    pk2.clone(),
                    pk1.clone(),
                    network::Link {
                        latency_mean: 5.0,
                        latency_stddev: 2.5,
                        success_rate: 1.0,
                    },
                )
                .unwrap();

            // Start network
            runtime.spawn(network.run());

            // Send messages
            let msg1 = Bytes::from("hello from pk1");
            let msg2 = Bytes::from("hello from pk2");
            sender1
                .send(Recipients::One(pk2.clone()), msg1.clone(), false)
                .await
                .unwrap();
            sender2
                .send(Recipients::One(pk1.clone()), msg2.clone(), false)
                .await
                .unwrap();

            // Confirm message delivery
            let (sender, message) = receiver1.recv().await.unwrap();
            assert_eq!(sender, pk2);
            assert_eq!(message, msg2);
            let (sender, message) = receiver2.recv().await.unwrap();
            assert_eq!(sender, pk1);
            assert_eq!(message, msg1);
        });
    }
}

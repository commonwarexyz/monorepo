//! Simulate networking between peers with configurable link behavior (i.e. drops, latency, corruption, etc.).
//!
//! Both peer and link modification can be performed dynamically over the lifetime of the simulated network. This
//! can be used to mimic transient network partitions, offline nodes (that later connect), and/or degrading link
//! quality.
//!
//! # Determinism
//!
//! `commonware-p2p::simulated` can be run deterministically when paired with `commonware-runtime::deterministic`.
//! This makes it possible to reproduce an arbitrary order of delivered/dropped messages with a given seed.
//!
//! # Example
//!
//! ```rust
//! use commonware_p2p::simulated::{Config, Link, Network};
//! use commonware_cryptography::{Ed25519, Scheme};
//! use commonware_runtime::{deterministic::Executor, Spawner, Runner};
//! use prometheus_client::registry::Registry;
//! use std::sync::{Arc, Mutex};
//!
//! // Generate peers
//! let peers = vec![
//!     Ed25519::from_seed(0).public_key(),
//!     Ed25519::from_seed(1).public_key(),
//!     Ed25519::from_seed(2).public_key(),
//!     Ed25519::from_seed(3).public_key(),
//! ];
//!
//! // Configure network
//! let p2p_cfg = Config {
//!     registry: Arc::new(Mutex::new(Registry::with_prefix("p2p"))),
//! };
//!
//! // Start runtime
//! let (executor, runtime, _) = Executor::seeded(0);
//! executor.start(async move {
//!     // Initialize network
//!     let (network, mut oracle) = Network::new(runtime.clone(), p2p_cfg);
//!
//!     // Start network
//!     let network_handler = runtime.spawn("network", network.run());
//!
//!     // Link 2 peers
//!     oracle.add_link(
//!         peers[0].clone(),
//!         peers[1].clone(),
//!         Link {
//!             latency_mean: 5.0,
//!             latency_stddev: 2.5,
//!             success_rate: 0.75,
//!         },
//!     ).await.unwrap();
//!
//!     // Register some channel
//!     let (sender, receiver) = oracle.register(
//!         peers[0].clone(),
//!         0,
//!         1024 * 1024, // 1KB
//!     ).await.unwrap();
//!
//!     // ... Use sender and receiver ...
//!
//!     // Update link
//!     oracle.add_link(
//!         peers[0].clone(),
//!         peers[1].clone(),
//!         Link {
//!             latency_mean: 100.0,
//!             latency_stddev: 25.0,
//!             success_rate: 0.8,
//!         },
//!     ).await.unwrap();
//!
//!     // ... Use sender and receiver ...
//!
//!     // Shutdown network
//!     network_handler.abort();
//! });
//! ```

mod ingress;
mod metrics;
mod network;

use thiserror::Error;

/// Errors that can occur when interacting with the network.
#[derive(Debug, Error)]
pub enum Error {
    #[error("message too large: {0}")]
    MessageTooLarge(usize),
    #[error("network closed")]
    NetworkClosed,
    #[error("peer closed")]
    PeerClosed,
    #[error("not valid to link self")]
    LinkingSelf,
    #[error("link missing")]
    LinkMissing,
    #[error("invalid success rate (must be in [0, 1]): {0}")]
    InvalidSuccessRate(f64),
    #[error("channel already registered: {0}")]
    ChannelAlreadyRegistered(u32),
    #[error("peer missing")]
    PeerMissing,
}

pub use ingress::Oracle;
pub use network::{Config, Link, Network, Receiver, Sender};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Receiver, Recipients, Sender};
    use bytes::Bytes;
    use commonware_cryptography::{Ed25519, Scheme};
    use commonware_macros::select;
    use commonware_runtime::{deterministic::Executor, Clock, Runner, Spawner};
    use commonware_utils::hex;
    use futures::{channel::mpsc, SinkExt, StreamExt};
    use prometheus_client::registry::Registry;
    use rand::Rng;
    use std::sync::{Arc, Mutex};
    use std::{
        collections::{BTreeMap, HashMap},
        time::Duration,
    };

    fn simulate_messages(seed: u64, size: usize) -> (String, Vec<usize>) {
        let (executor, runtime, auditor) = Executor::seeded(seed);
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::with_prefix("p2p"))),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register agents
            let mut agents = BTreeMap::new();
            let (seen_sender, mut seen_receiver) = mpsc::channel(1024);
            for i in 0..size {
                let pk = Ed25519::from_seed(i as u64).public_key();
                let (sender, mut receiver) =
                    oracle.register(pk.clone(), 0, 1024 * 1024).await.unwrap();
                agents.insert(pk, sender);
                let mut agent_sender = seen_sender.clone();
                runtime.spawn("agent_receiver", async move {
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
                    let result = oracle
                        .add_link(
                            agent.clone(),
                            other.clone(),
                            Link {
                                latency_mean: 5.0,
                                latency_stddev: 2.5,
                                success_rate: 0.75,
                            },
                        )
                        .await;
                    if agent == other {
                        assert!(matches!(result, Err(Error::LinkingSelf)));
                    } else {
                        assert!(result.is_ok());
                    }
                }
            }

            // Send messages
            runtime.spawn("agent_sender", {
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
    fn test_message_too_big() {
        let (executor, mut runtime, _) = Executor::default();
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::with_prefix("p2p"))),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register agents
            let mut agents = HashMap::new();
            for i in 0..10 {
                let pk = Ed25519::from_seed(i as u64).public_key();
                let (sender, _) = oracle.register(pk.clone(), 0, 1024 * 1024).await.unwrap();
                agents.insert(pk, sender);
            }

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
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::with_prefix("p2p"))),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register agents
            let pk = Ed25519::from_seed(0).public_key();
            oracle.register(pk.clone(), 0, 1024 * 1024).await.unwrap();

            // Attempt to link self
            let result = oracle
                .add_link(
                    pk.clone(),
                    pk.clone(),
                    Link {
                        latency_mean: 5.0,
                        latency_stddev: 2.5,
                        success_rate: 0.75,
                    },
                )
                .await;

            // Confirm error is correct
            assert!(matches!(result, Err(Error::LinkingSelf)));
        });
    }

    #[test]
    fn test_duplicate_channel() {
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::with_prefix("p2p"))),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register agents
            let pk = Ed25519::from_seed(0).public_key();
            oracle.register(pk.clone(), 0, 1024 * 1024).await.unwrap();
            let result = oracle.register(pk, 0, 1024 * 1024).await;

            // Confirm error is correct
            assert!(matches!(result, Err(Error::ChannelAlreadyRegistered(0))));
        });
    }

    #[test]
    fn test_invalid_success_rate() {
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::with_prefix("p2p"))),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register agents
            let pk1 = Ed25519::from_seed(0).public_key();
            let pk2 = Ed25519::from_seed(1).public_key();
            oracle.register(pk1.clone(), 0, 1024 * 1024).await.unwrap();
            oracle.register(pk2.clone(), 0, 1024 * 1024).await.unwrap();

            // Attempt to link with invalid success rate
            let result = oracle
                .add_link(
                    pk1.clone(),
                    pk2.clone(),
                    Link {
                        latency_mean: 5.0,
                        latency_stddev: 2.5,
                        success_rate: 1.5,
                    },
                )
                .await;

            // Confirm error is correct
            assert!(matches!(result, Err(Error::InvalidSuccessRate(_))));
        });
    }

    #[test]
    fn test_simple_message_delivery() {
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::with_prefix("p2p"))),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register agents
            let pk1 = Ed25519::from_seed(0).public_key();
            let pk2 = Ed25519::from_seed(1).public_key();
            let (mut sender1, mut receiver1) =
                oracle.register(pk1.clone(), 0, 1024 * 1024).await.unwrap();
            let (mut sender2, mut receiver2) =
                oracle.register(pk2.clone(), 0, 1024 * 1024).await.unwrap();

            // Register unused channels
            let _ = oracle.register(pk1.clone(), 1, 1024 * 1024).await.unwrap();
            let _ = oracle.register(pk2.clone(), 2, 1024 * 1024).await.unwrap();

            // Link agents
            oracle
                .add_link(
                    pk1.clone(),
                    pk2.clone(),
                    Link {
                        latency_mean: 5.0,
                        latency_stddev: 2.5,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();
            oracle
                .add_link(
                    pk2.clone(),
                    pk1.clone(),
                    Link {
                        latency_mean: 5.0,
                        latency_stddev: 2.5,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

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

    #[test]
    fn test_send_wrong_channel() {
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::with_prefix("p2p"))),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register agents
            let pk1 = Ed25519::from_seed(0).public_key();
            let pk2 = Ed25519::from_seed(1).public_key();
            let (mut sender1, _) = oracle.register(pk1.clone(), 0, 1024 * 1024).await.unwrap();
            let (_, mut receiver2) = oracle.register(pk2.clone(), 1, 1024 * 1024).await.unwrap();

            // Link agents
            oracle
                .add_link(
                    pk1.clone(),
                    pk2.clone(),
                    Link {
                        latency_mean: 5.0,
                        latency_stddev: 0.0,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            // Send message
            let msg = Bytes::from("hello from pk1");
            sender1
                .send(Recipients::One(pk2.clone()), msg, false)
                .await
                .unwrap();

            // Confirm no message delivery
            select! {
                _ = receiver2.recv() => {
                    panic!("unexpected message");
                },
                _ = runtime.sleep(Duration::from_secs(1)) => {},
            }
        });
    }

    #[test]
    fn test_message_too_big_receiver() {
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::with_prefix("p2p"))),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register agents
            let pk1 = Ed25519::from_seed(0).public_key();
            let pk2 = Ed25519::from_seed(1).public_key();
            let (mut sender1, _) = oracle.register(pk1.clone(), 0, 1024 * 1024).await.unwrap();
            let (_, mut receiver2) = oracle.register(pk2.clone(), 0, 1).await.unwrap();

            // Link agents
            oracle
                .add_link(
                    pk1.clone(),
                    pk2.clone(),
                    Link {
                        latency_mean: 5.0,
                        latency_stddev: 0.0,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            // Send message
            let msg = Bytes::from("hello from pk1");
            sender1
                .send(Recipients::One(pk2.clone()), msg, false)
                .await
                .unwrap();

            // Confirm no message delivery
            select! {
                _ = receiver2.recv() => {
                    panic!("unexpected message");
                },
                _ = runtime.sleep(Duration::from_secs(1)) => {},
            }
        });
    }

    #[test]
    fn test_dynamic_peers() {
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::with_prefix("p2p"))),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Define agents
            let pk1 = Ed25519::from_seed(0).public_key();
            let pk2 = Ed25519::from_seed(1).public_key();
            let (mut sender1, mut receiver1) =
                oracle.register(pk1.clone(), 0, 1024 * 1024).await.unwrap();
            let (mut sender2, mut receiver2) =
                oracle.register(pk2.clone(), 0, 1024 * 1024).await.unwrap();

            // Link agents
            oracle
                .add_link(
                    pk1.clone(),
                    pk2.clone(),
                    Link {
                        latency_mean: 5.0,
                        latency_stddev: 2.5,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();
            oracle
                .add_link(
                    pk2.clone(),
                    pk1.clone(),
                    Link {
                        latency_mean: 5.0,
                        latency_stddev: 2.5,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            // Send messages
            let msg1 = Bytes::from("attempt 1: hello from pk1");
            let msg2 = Bytes::from("attempt 1: hello from pk2");
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

            // Deregister agent
            oracle.deregister(pk1.clone()).await.unwrap();
            oracle.deregister(pk2.clone()).await.unwrap();

            // Send messages
            let msg1 = Bytes::from("attempt 2: hello from pk1");
            let msg2 = Bytes::from("attempt 2: hello from pk2");
            sender1
                .send(Recipients::One(pk2.clone()), msg1.clone(), false)
                .await
                .unwrap();
            sender2
                .send(Recipients::One(pk1.clone()), msg2.clone(), false)
                .await
                .unwrap();

            // Ensure receivers show network closed
            let result = receiver1.recv().await;
            assert!(matches!(result, Err(Error::PeerClosed)));
            let result = receiver2.recv().await;
            assert!(matches!(result, Err(Error::PeerClosed)));

            // Remove non-existent agents
            let result = oracle.deregister(pk1.clone()).await;
            assert!(matches!(result, Err(Error::PeerMissing)));
        });
    }

    #[test]
    fn test_dynamic_links() {
        let (executor, runtime, _) = Executor::default();
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::with_prefix("p2p"))),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register agents
            let pk1 = Ed25519::from_seed(0).public_key();
            let pk2 = Ed25519::from_seed(1).public_key();
            let (mut sender1, mut receiver1) =
                oracle.register(pk1.clone(), 0, 1024 * 1024).await.unwrap();
            let (mut sender2, mut receiver2) =
                oracle.register(pk2.clone(), 0, 1024 * 1024).await.unwrap();

            // Send messages
            let msg1 = Bytes::from("attempt 1: hello from pk1");
            let msg2 = Bytes::from("attempt 1: hello from pk2");
            sender1
                .send(Recipients::One(pk2.clone()), msg1.clone(), false)
                .await
                .unwrap();
            sender2
                .send(Recipients::One(pk1.clone()), msg2.clone(), false)
                .await
                .unwrap();

            // Confirm no message delivery
            select! {
                _ = receiver1.recv() => {
                    panic!("unexpected message");
                },
                _ = receiver2.recv() => {
                    panic!("unexpected message");
                },
                _ = runtime.sleep(Duration::from_secs(1)) => {},
            }

            // Link agents
            oracle
                .add_link(
                    pk1.clone(),
                    pk2.clone(),
                    Link {
                        latency_mean: 5.0,
                        latency_stddev: 2.5,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();
            oracle
                .add_link(
                    pk2.clone(),
                    pk1.clone(),
                    Link {
                        latency_mean: 5.0,
                        latency_stddev: 2.5,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            // Send messages
            let msg1 = Bytes::from("attempt 2: hello from pk1");
            let msg2 = Bytes::from("attempt 2: hello from pk2");
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

            // Remove links
            oracle.remove_link(pk1.clone(), pk2.clone()).await.unwrap();
            oracle.remove_link(pk2.clone(), pk1.clone()).await.unwrap();

            // Send messages
            let msg1 = Bytes::from("attempt 3: hello from pk1");
            let msg2 = Bytes::from("attempt 3: hello from pk2");
            sender1
                .send(Recipients::One(pk2.clone()), msg1.clone(), false)
                .await
                .unwrap();
            sender2
                .send(Recipients::One(pk1.clone()), msg2.clone(), false)
                .await
                .unwrap();

            // Confirm no message delivery
            select! {
                _ = receiver1.recv() => {
                    panic!("unexpected message");
                },
                _ = receiver2.recv() => {
                    panic!("unexpected message");
                },
                _ = runtime.sleep(Duration::from_secs(1)) => {},
            }

            // Remove non-existent links
            let result = oracle.remove_link(pk1.clone(), pk2.clone()).await;
            assert!(matches!(result, Err(Error::LinkMissing)));
        });
    }
}

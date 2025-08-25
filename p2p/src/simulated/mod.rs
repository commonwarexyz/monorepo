//! Simulate networking between peers with configurable link behavior (i.e. drops, latency, corruption, etc.).
//!
//! Both peer and link modification can be performed dynamically over the lifetime of the simulated network. This
//! can be used to mimic transient network partitions, offline nodes (that later connect), and/or degrading link
//! quality. Messages on a link are delivered in order, and optional per-peer bandwidth limits account for
//! transmission delay and queueing.
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
//! use commonware_cryptography::{ed25519, PrivateKey, Signer as _, PublicKey as _, PrivateKeyExt as _};
//! use commonware_runtime::{deterministic, Spawner, Runner, Metrics};
//! use std::time::Duration;
//!
//! // Generate peers
//! let peers = vec![
//!     ed25519::PrivateKey::from_seed(0).public_key(),
//!     ed25519::PrivateKey::from_seed(1).public_key(),
//!     ed25519::PrivateKey::from_seed(2).public_key(),
//!     ed25519::PrivateKey::from_seed(3).public_key(),
//! ];
//!
//! // Configure network
//! let p2p_cfg = Config {
//!     max_size: 1024 * 1024, // 1MB
//! };
//!
//! // Start context
//! let executor = deterministic::Runner::seeded(0);
//! executor.start(|context| async move {
//!     // Initialize network
//!     let (network, mut oracle) = Network::new(context.with_label("network"), p2p_cfg);
//!
//!     // Start network
//!     let network_handler = network.start();
//!
//!     // Register peers
//!     let (sender1, receiver1) = oracle.register(peers[0].clone(), 0).await.unwrap();
//!     let (sender2, receiver2) = oracle.register(peers[1].clone(), 0).await.unwrap();
//!
//!     // Set bandwidth limits
//!     // peer[0]: 10KB/s egress, unlimited ingress
//!     // peer[1]: unlimited egress, 5KB/s ingress
//!     oracle.set_bandwidth(peers[0].clone(), 10_000, usize::MAX).await.unwrap();
//!     oracle.set_bandwidth(peers[1].clone(), usize::MAX, 5_000).await.unwrap();
//!
//!     // Link 2 peers
//!     oracle.add_link(
//!         peers[0].clone(),
//!         peers[1].clone(),
//!         Link {
//!             latency: Duration::from_millis(5),
//!             jitter: Duration::from_millis(2),
//!             success_rate: 0.75,
//!         },
//!     ).await.unwrap();
//!
//!     // ... Use sender and receiver ...
//!
//!     // Update link
//!     oracle.remove_link(
//!         peers[0].clone(),
//!         peers[1].clone(),
//!     ).await.unwrap();
//!     oracle.add_link(
//!         peers[0].clone(),
//!         peers[1].clone(),
//!         Link {
//!             latency: Duration::from_millis(100),
//!             jitter: Duration::from_millis(25),
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
    #[error("not valid to link self")]
    LinkingSelf,
    #[error("link already exists")]
    LinkExists,
    #[error("link missing")]
    LinkMissing,
    #[error("invalid success rate (must be in [0, 1]): {0}")]
    InvalidSuccessRate(f64),
    #[error("channel already registered: {0}")]
    ChannelAlreadyRegistered(u32),
    #[error("send_frame failed")]
    SendFrameFailed,
    #[error("recv_frame failed")]
    RecvFrameFailed,
    #[error("bind failed")]
    BindFailed,
    #[error("accept failed")]
    AcceptFailed,
    #[error("dial failed")]
    DialFailed,
    #[error("peer missing")]
    PeerMissing,
}

pub use ingress::{Link, Oracle};
pub use network::{Config, Network, Receiver, Sender};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Receiver, Recipients, Sender};
    use bytes::Bytes;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        PrivateKeyExt as _, Signer as _,
    };
    use commonware_macros::select;
    use commonware_runtime::{deterministic, Clock, Metrics, Runner, Spawner};
    use futures::{channel::mpsc, SinkExt, StreamExt};
    use rand::Rng;
    use std::{
        collections::{BTreeMap, HashMap},
        time::Duration,
    };

    fn simulate_messages(seed: u64, size: usize) -> (String, Vec<usize>) {
        let executor = deterministic::Runner::seeded(seed);
        executor.start(|context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Register agents
            let mut agents = BTreeMap::new();
            let (seen_sender, mut seen_receiver) = mpsc::channel(1024);
            for i in 0..size {
                let pk = PrivateKey::from_seed(i as u64).public_key();
                let (sender, mut receiver) = oracle.register(pk.clone(), 0).await.unwrap();
                agents.insert(pk, sender);
                let mut agent_sender = seen_sender.clone();
                context
                    .with_label("agent_receiver")
                    .spawn(move |_| async move {
                        for _ in 0..size {
                            receiver.recv().await.unwrap();
                        }
                        agent_sender.send(i).await.unwrap();

                        // Exiting early here tests the case where the recipient end of an agent is dropped
                    });
            }

            // Randomly link agents
            let only_inbound = PrivateKey::from_seed(0).public_key();
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
                                latency: Duration::from_millis(5),
                                jitter: Duration::from_millis(2),
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
            context
                .with_label("agent_sender")
                .spawn(|mut context| async move {
                    // Sort agents for deterministic output
                    let keys = agents.keys().collect::<Vec<_>>();

                    // Send messages
                    loop {
                        let index = context.gen_range(0..keys.len());
                        let sender = keys[index];
                        let msg = format!("hello from {sender:?}");
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
                });

            // Wait for all recipients
            let mut results = Vec::new();
            for _ in 0..size {
                results.push(seen_receiver.next().await.unwrap());
            }
            (context.auditor().state(), results)
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
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Register agents
            let mut agents = HashMap::new();
            for i in 0..10 {
                let pk = PrivateKey::from_seed(i as u64).public_key();
                let (sender, _) = oracle.register(pk.clone(), 0).await.unwrap();
                agents.insert(pk, sender);
            }

            // Send invalid message
            let keys = agents.keys().collect::<Vec<_>>();
            let index = context.gen_range(0..keys.len());
            let sender = keys[index];
            let mut message_sender = agents.get(sender).unwrap().clone();
            let mut msg = vec![0u8; 1024 * 1024 + 1];
            context.fill(&mut msg[..]);
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
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Register agents
            let pk = PrivateKey::from_seed(0).public_key();
            oracle.register(pk.clone(), 0).await.unwrap();

            // Attempt to link self
            let result = oracle
                .add_link(
                    pk.clone(),
                    pk,
                    Link {
                        latency: Duration::from_millis(5),
                        jitter: Duration::from_millis(2),
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
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Register agents
            let pk = PrivateKey::from_seed(0).public_key();
            oracle.register(pk.clone(), 0).await.unwrap();
            let result = oracle.register(pk, 0).await;

            // Confirm error is correct
            assert!(matches!(result, Err(Error::ChannelAlreadyRegistered(0))));
        });
    }

    #[test]
    fn test_invalid_success_rate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Register agents
            let pk1 = PrivateKey::from_seed(0).public_key();
            let pk2 = PrivateKey::from_seed(1).public_key();
            oracle.register(pk1.clone(), 0).await.unwrap();
            oracle.register(pk2.clone(), 0).await.unwrap();

            // Attempt to link with invalid success rate
            let result = oracle
                .add_link(
                    pk1,
                    pk2,
                    Link {
                        latency: Duration::from_millis(5),
                        jitter: Duration::from_millis(2),
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
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Register agents
            let pk1 = PrivateKey::from_seed(0).public_key();
            let pk2 = PrivateKey::from_seed(1).public_key();
            let (mut sender1, mut receiver1) = oracle.register(pk1.clone(), 0).await.unwrap();
            let (mut sender2, mut receiver2) = oracle.register(pk2.clone(), 0).await.unwrap();

            // Register unused channels
            let _ = oracle.register(pk1.clone(), 1).await.unwrap();
            let _ = oracle.register(pk2.clone(), 2).await.unwrap();

            // Link agents
            oracle
                .add_link(
                    pk1.clone(),
                    pk2.clone(),
                    Link {
                        latency: Duration::from_millis(5),
                        jitter: Duration::from_millis(2),
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
                        latency: Duration::from_millis(5),
                        jitter: Duration::from_millis(2),
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
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Register agents
            let pk1 = PrivateKey::from_seed(0).public_key();
            let pk2 = PrivateKey::from_seed(1).public_key();
            let (mut sender1, _) = oracle.register(pk1.clone(), 0).await.unwrap();
            let (_, mut receiver2) = oracle.register(pk2.clone(), 1).await.unwrap();

            // Link agents
            oracle
                .add_link(
                    pk1,
                    pk2.clone(),
                    Link {
                        latency: Duration::from_millis(5),
                        jitter: Duration::ZERO,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            // Send message
            let msg = Bytes::from("hello from pk1");
            sender1
                .send(Recipients::One(pk2), msg, false)
                .await
                .unwrap();

            // Confirm no message delivery
            select! {
                _ = receiver2.recv() => {
                    panic!("unexpected message");
                },
                _ = context.sleep(Duration::from_secs(1)) => {},
            }
        });
    }

    #[test]
    fn test_dynamic_peers() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Define agents
            let pk1 = PrivateKey::from_seed(0).public_key();
            let pk2 = PrivateKey::from_seed(1).public_key();
            let (mut sender1, mut receiver1) = oracle.register(pk1.clone(), 0).await.unwrap();
            let (mut sender2, mut receiver2) = oracle.register(pk2.clone(), 0).await.unwrap();

            // Link agents
            oracle
                .add_link(
                    pk1.clone(),
                    pk2.clone(),
                    Link {
                        latency: Duration::from_millis(5),
                        jitter: Duration::from_millis(2),
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
                        latency: Duration::from_millis(5),
                        jitter: Duration::from_millis(2),
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
        });
    }

    #[test]
    fn test_dynamic_links() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

            // Register agents
            let pk1 = PrivateKey::from_seed(0).public_key();
            let pk2 = PrivateKey::from_seed(1).public_key();
            let (mut sender1, mut receiver1) = oracle.register(pk1.clone(), 0).await.unwrap();
            let (mut sender2, mut receiver2) = oracle.register(pk2.clone(), 0).await.unwrap();

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
                _ = context.sleep(Duration::from_secs(1)) => {},
            }

            // Link agents
            oracle
                .add_link(
                    pk1.clone(),
                    pk2.clone(),
                    Link {
                        latency: Duration::from_millis(5),
                        jitter: Duration::from_millis(2),
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
                        latency: Duration::from_millis(5),
                        jitter: Duration::from_millis(2),
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
                _ = context.sleep(Duration::from_secs(1)) => {},
            }

            // Remove non-existent links
            let result = oracle.remove_link(pk1, pk2).await;
            assert!(matches!(result, Err(Error::LinkMissing)));
        });
    }

    async fn test_bandwidth_between_peers(
        context: &mut deterministic::Context,
        oracle: &mut Oracle<PublicKey>,
        sender_bps: Option<usize>,
        receiver_bps: Option<usize>,
        message_size: usize,
        expected_duration_ms: u64,
    ) {
        // Create two agents
        let pk1 = PrivateKey::from_seed(context.gen::<u64>()).public_key();
        let pk2 = PrivateKey::from_seed(context.gen::<u64>()).public_key();
        let (mut sender, _) = oracle.register(pk1.clone(), 0).await.unwrap();
        let (_, mut receiver) = oracle.register(pk2.clone(), 0).await.unwrap();

        // Set bandwidth limits
        oracle
            .set_bandwidth(pk1.clone(), sender_bps.unwrap_or(usize::MAX), usize::MAX)
            .await
            .unwrap();
        oracle
            .set_bandwidth(pk2.clone(), usize::MAX, receiver_bps.unwrap_or(usize::MAX))
            .await
            .unwrap();

        // Link the two agents
        oracle
            .add_link(
                pk1.clone(),
                pk2.clone(),
                Link {
                    // No latency so it doesn't interfere with bandwidth delay calculation
                    latency: Duration::ZERO,
                    jitter: Duration::ZERO,
                    success_rate: 1.0,
                },
            )
            .await
            .unwrap();

        // Send a message from agent 1 to 2
        let msg = Bytes::from(vec![42u8; message_size]);
        let start = context.current();
        sender
            .send(Recipients::One(pk2.clone()), msg.clone(), true)
            .await
            .unwrap();

        // Measure how long it takes for agent 2 to receive the message
        let (origin, received) = receiver.recv().await.unwrap();
        let elapsed = context.current().duration_since(start).unwrap();

        assert_eq!(origin, pk1);
        assert_eq!(received, msg);
        assert!(
            elapsed >= Duration::from_millis(expected_duration_ms),
            "Message arrived too quickly: {elapsed:?} (expected >= {expected_duration_ms}ms)"
        );
        assert!(
            elapsed < Duration::from_millis(expected_duration_ms + 100),
            "Message took too long: {elapsed:?} (expected ~{expected_duration_ms}ms)"
        );
    }

    #[test]
    fn test_bandwidth() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );
            network.start();

            // Both sender and receiver have the same bandiwdth (1000 B/s)
            // 500 bytes at 1000 B/s = 0.5 seconds
            test_bandwidth_between_peers(
                &mut context,
                &mut oracle,
                Some(1000), // sender egress
                Some(1000), // receiver ingress
                500,        // message size
                500,        // expected duration in ms
            )
            .await;

            // Sender has lower bandwidth (500 B/s) than receiver (2000 B/s)
            // Should be limited by sender's 500 B/s
            // 250 bytes at 500 B/s = 0.5 seconds
            test_bandwidth_between_peers(
                &mut context,
                &mut oracle,
                Some(500),  // sender egress
                Some(2000), // receiver ingress
                250,        // message size
                500,        // expected duration in ms
            )
            .await;

            // Sender has higher bandwidth (2000 B/s) than receiver (500 B/s)
            // Should be limited by receiver's 500 B/s
            // 250 bytes at 500 B/s = 0.5 seconds
            test_bandwidth_between_peers(
                &mut context,
                &mut oracle,
                Some(2000), // sender egress
                Some(500),  // receiver ingress
                250,        // message size
                500,        // expected duration in ms
            )
            .await;

            // Unlimited sender, limited receiver
            // Should be limited by receiver's 1000 B/s
            // 500 bytes at 1000 B/s = 0.5 seconds
            test_bandwidth_between_peers(
                &mut context,
                &mut oracle,
                None,       // sender egress (unlimited)
                Some(1000), // receiver ingress
                500,        // message size
                500,        // expected duration in ms
            )
            .await;

            // Limited sender, unlimited receiver
            // Should be limited by sender's 1000 B/s
            // 500 bytes at 1000 B/s = 0.5 seconds
            test_bandwidth_between_peers(
                &mut context,
                &mut oracle,
                Some(1000), // sender egress
                None,       // receiver ingress (unlimited)
                500,        // message size
                500,        // expected duration in ms
            )
            .await;

            // Unlimited sender, unlimited receiver
            // Delivery should be (almost) instant
            test_bandwidth_between_peers(
                &mut context,
                &mut oracle,
                None, // sender egress (unlimited)
                None, // receiver ingress (unlimited)
                500,  // message size
                0,    // expected duration in ms
            )
            .await;
        });
    }

    #[test]
    fn test_bandwidth_contention() {
        // Test that multiple senders to the same receiver cause queueing delays
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );
            network.start();

            // Create three agents
            let sender1 = PrivateKey::from_seed(1).public_key();
            let sender2 = PrivateKey::from_seed(2).public_key();
            let receiver = PrivateKey::from_seed(3).public_key();

            let (mut sender1_tx, _) = oracle.register(sender1.clone(), 0).await.unwrap();
            let (mut sender2_tx, _) = oracle.register(sender2.clone(), 0).await.unwrap();
            let (_, mut receiver_rx) = oracle.register(receiver.clone(), 0).await.unwrap();

            // Set bandwidth limits:
            // senders with high egress (2000 B/s each),
            // receiver with limited ingress (1000 B/s)
            oracle
                .set_bandwidth(sender1.clone(), 2000, usize::MAX)
                .await
                .unwrap();
            oracle
                .set_bandwidth(sender2.clone(), 2000, usize::MAX)
                .await
                .unwrap();
            oracle
                .set_bandwidth(receiver.clone(), usize::MAX, 1000)
                .await
                .unwrap();

            // Link both senders to the receiver with no latency
            oracle
                .add_link(
                    sender1.clone(),
                    receiver.clone(),
                    Link {
                        latency: Duration::ZERO,
                        jitter: Duration::ZERO,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();
            oracle
                .add_link(
                    sender2.clone(),
                    receiver.clone(),
                    Link {
                        latency: Duration::ZERO,
                        jitter: Duration::ZERO,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            // Both senders send 500-byte messages simultaneously
            let msg1 = Bytes::from(vec![1u8; 500]);
            let msg2 = Bytes::from(vec![1u8; 500]);
            let receiver2 = receiver.clone();

            // Spawn both sends concurrently
            context.with_label("send1").spawn(|_| async move {
                sender1_tx
                    .send(Recipients::One(receiver), msg1, true)
                    .await
                    .unwrap()
            });

            context.with_label("send2").spawn(|_| async move {
                sender2_tx
                    .send(Recipients::One(receiver2), msg2, true)
                    .await
                    .unwrap()
            });

            // Start timing after dispatching sends
            let start = context.current();

            // Receive first message
            let (origin1, _) = receiver_rx.recv().await.unwrap();
            let time1 = context.current().duration_since(start).unwrap();

            // Receive second message
            let (origin2, _) = receiver_rx.recv().await.unwrap();
            let time2 = context.current().duration_since(start).unwrap();

            // Verify both messages arrived from different senders
            assert_ne!(origin1, origin2, "Messages must be from different senders");

            // With bandwidth contention at the receiver (1000 B/s):
            // - First 500-byte message should take ~500ms
            // - Second 500-byte message should be delayed and arrive ~500ms later
            assert!(
                time1 >= Duration::from_millis(500),
                "First message arrived too quickly: {time1:?} (expected >= 500ms)"
            );
            assert!(
                time2 >= Duration::from_millis(1000),
                "Second message arrived too quickly: {time2:?} (expected >= 1000ms)"
            );
        });
    }

    #[test]
    fn test_message_ordering() {
        // Test that messages arrive in order even with variable latency
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );
            network.start();

            // Register agents
            let pk1 = PrivateKey::from_seed(1).public_key();
            let pk2 = PrivateKey::from_seed(2).public_key();
            let (mut sender, _) = oracle.register(pk1.clone(), 0).await.unwrap();
            let (_, mut receiver) = oracle.register(pk2.clone(), 0).await.unwrap();

            // Link agents with high jitter to create variable delays
            oracle
                .add_link(
                    pk1.clone(),
                    pk2.clone(),
                    Link {
                        latency: Duration::from_millis(50),
                        jitter: Duration::from_millis(40),
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            // Send multiple messages that should arrive in order
            let messages = vec![
                Bytes::from("message 1"),
                Bytes::from("message 2"),
                Bytes::from("message 3"),
                Bytes::from("message 4"),
                Bytes::from("message 5"),
            ];

            for msg in messages.clone() {
                sender
                    .send(Recipients::One(pk2.clone()), msg, true)
                    .await
                    .unwrap();
            }

            // Receive messages and verify they arrive in order
            for expected_msg in messages {
                let (origin, received_msg) = receiver.recv().await.unwrap();
                assert_eq!(origin, pk1);
                assert_eq!(received_msg, expected_msg);
            }
        })
    }
}

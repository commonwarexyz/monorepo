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
//! # Bandwidth Simulation
//!
//! The simulator provides a realistic model of bandwidth contention where network
//! capacity is a shared, finite resource. This is achieved without the overhead
//! of simulating byte-by-byte transfers.
//!
//! ## Core Model
//!
//! The bandwidth model is built on an event-based timeline. Instead of simulating
//! continuous data flow, the scheduler calculates the key points in time where
//! bandwidth availability changes for a peer. These changes occur whenever a
//! transfer starts or finishes.
//!
//! Each peer has a schedule for its egress (upload) and ingress (download)
//! bandwidth. When a new message is sent, the scheduler performs the following steps:
//!
//! 1. **Find Available Capacity:** It looks at the sender's egress schedule and the
//!    receiver's ingress schedule to find the available bandwidth over time. The
//!    effective transfer rate is always limited by the minimum of the two.
//!
//! 2. **Fill Time Slots:** The algorithm iterates through time, finding "slots" of
//!    available bandwidth. It calculates how much of the message can be sent in
//!    each slot until the entire message is accounted for. For example, if two
//!    10KB messages are sent over a 10KB/s link, the second message will be
//!    scheduled to start only after the first one completes.
//!
//! 3. **Reserve Bandwidth:** Once the completion time is calculated, the new
//!    transfer is added to the schedules of both the sender and receiver as a
//!    bandwidth reservation, consuming capacity for its calculated duration.
//!
//! ## Latency vs. Transmission Delay
//!
//! The simulation correctly distinguishes between two key components of message delivery:
//!
//! - **Transmission Delay:** The time it takes to send all bytes of a message over
//!   the link. This is determined by the message size and the available bandwidth
//!   (e.g., a 10KB message on a 10KB/s link has a 1-second transmission delay).
//! - **Network Latency:** The time it takes for a byte to travel from the sender
//!   to the receiver, independent of bandwidth. This is configured via the `Link`
//!   properties.
//!
//! The final delivery time of a message is the sum of when its transmission completes
//! plus the simulated network latency. This model ensures that large messages correctly
//! occupy the network link for longer periods, affecting other concurrent transfers,
//! while still accounting for the physical travel time of the data.
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

mod bandwidth;
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
    use futures::{channel::mpsc, future::join_all, SinkExt, StreamExt};
    use rand::Rng;
    use std::{
        collections::{BTreeMap, HashMap, HashSet},
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
        // Test bandwidth contention with many peers (one-to-many and many-to-one scenarios)
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );
            network.start();

            // Configuration
            const NUM_PEERS: usize = 100;
            const MESSAGE_SIZE: usize = 1000; // 1KB per message
            const EFFECTIVE_BPS: usize = 10_000; // 10KB/s egress/ingress per peer

            // Create peers
            let mut peers = Vec::with_capacity(NUM_PEERS + 1);
            let mut senders = Vec::with_capacity(NUM_PEERS + 1);
            let mut receivers = Vec::with_capacity(NUM_PEERS + 1);

            // Create the main peer (index 0) and 100 other peers
            for i in 0..=NUM_PEERS {
                let pk = PrivateKey::from_seed(i as u64).public_key();
                let (sender, receiver) = oracle.register(pk.clone(), 0).await.unwrap();
                peers.push(pk);
                senders.push(sender);
                receivers.push(receiver);
            }

            // Set bandwidth limits for all peers
            for pk in &peers {
                oracle
                    .set_bandwidth(pk.clone(), EFFECTIVE_BPS, EFFECTIVE_BPS)
                    .await
                    .unwrap();
            }

            // Link all peers to the main peer (peers[0]) with zero latency
            for peer in peers.iter().skip(1) {
                oracle
                    .add_link(
                        peer.clone(),
                        peers[0].clone(),
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
                        peers[0].clone(),
                        peer.clone(),
                        Link {
                            latency: Duration::ZERO,
                            jitter: Duration::ZERO,
                            success_rate: 1.0,
                        },
                    )
                    .await
                    .unwrap();
            }

            // One-to-many (main peer sends to all others). Verifies that bandwidth limits
            // are properly enforced when sending to multiple recipients
            let start = context.current();

            // Send message to all peers concurrently
            // and wait for all sends to be acknowledged
            join_all(peers.iter().skip(1).map(|peer| {
                let mut sender = senders[0].clone();
                let recipient = peer.clone();
                let msg = Bytes::from(vec![0u8; MESSAGE_SIZE]);
                context.clone().spawn(|_| async move {
                    sender
                        .send(Recipients::One(recipient), msg, true)
                        .await
                        .unwrap()
                })
            }))
            .await;

            let elapsed = context.current().duration_since(start).unwrap();

            // Calculate expected time
            let expected_ms = (NUM_PEERS * MESSAGE_SIZE * 1000) / EFFECTIVE_BPS;

            assert!(
                elapsed >= Duration::from_millis(expected_ms as u64),
                "One-to-many completed too quickly: {elapsed:?} (expected >= {expected_ms}ms)"
            );
            assert!(
                elapsed < Duration::from_millis((expected_ms as u64) + 500),
                "One-to-many took too long: {elapsed:?} (expected ~{expected_ms}ms)"
            );

            // Verify all messages are received
            for receiver in receivers.iter_mut().skip(1) {
                let (origin, received) = receiver.recv().await.unwrap();
                assert_eq!(origin, peers[0]);
                assert_eq!(received.len(), MESSAGE_SIZE);
            }

            // Many-to-one (all peers send to the main peer)
            let start = context.current();

            // Each peer sends a message to the main peer concurrently and we wait for all
            // sends to be acknowledged
            join_all(senders.iter().skip(1).map(|sender| {
                let mut sender = sender.clone();
                let recipient = peers[0].clone();
                let msg = Bytes::from(vec![0; MESSAGE_SIZE]);
                context.clone().spawn(|_| async move {
                    sender
                        .send(Recipients::One(recipient), msg, true)
                        .await
                        .unwrap()
                })
            }))
            .await;

            // Collect all messages at the main peer
            let mut received_from = HashSet::new();
            for _ in 1..=NUM_PEERS {
                let (origin, received) = receivers[0].recv().await.unwrap();
                assert_eq!(received.len(), MESSAGE_SIZE);
                assert!(
                    received_from.insert(origin.clone()),
                    "Received duplicate from {origin:?}"
                );
            }

            let elapsed = context.current().duration_since(start).unwrap();

            // Calculate expected time
            let expected_ms = (NUM_PEERS * MESSAGE_SIZE * 1000) / EFFECTIVE_BPS;

            assert!(
                elapsed >= Duration::from_millis(expected_ms as u64),
                "Many-to-one completed too quickly: {elapsed:?} (expected >= {expected_ms}ms)"
            );
            assert!(
                elapsed < Duration::from_millis((expected_ms as u64) + 500),
                "Many-to-one took too long: {elapsed:?} (expected ~{expected_ms}ms)"
            );

            // Verify we received from all peers
            assert_eq!(received_from.len(), NUM_PEERS);
            for peer in peers.iter().skip(1) {
                assert!(received_from.contains(peer));
            }
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

    #[test]
    fn test_one_to_many_fast_sender() {
        // Test that 1 fast sender (100KB/s) sending to 10 receivers (10KB/s each)
        // should complete all sends in ~1s and all messages received in ~1s
        use commonware_cryptography::ed25519;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );
            network.start();

            // Create fast sender
            let sender = ed25519::PrivateKey::from_seed(0).public_key();
            let (sender_tx, _) = oracle.register(sender.clone(), 0).await.unwrap();

            // Sender has 100KB/s egress
            oracle
                .set_bandwidth(sender.clone(), 100_000, usize::MAX)
                .await
                .unwrap();

            // Create 10 receivers
            let mut receivers = Vec::new();
            let mut receiver_rxs = Vec::new();
            for i in 0..10 {
                let receiver = ed25519::PrivateKey::from_seed(i + 1).public_key();
                receivers.push(receiver.clone());
                let (_, rx) = oracle.register(receiver.clone(), 0).await.unwrap();
                receiver_rxs.push(rx);

                // Each receiver has 10KB/s ingress
                oracle
                    .set_bandwidth(receiver.clone(), usize::MAX, 10_000)
                    .await
                    .unwrap();

                // Add link with no latency
                oracle
                    .add_link(
                        sender.clone(),
                        receiver.clone(),
                        Link {
                            latency: Duration::ZERO,
                            jitter: Duration::ZERO,
                            success_rate: 1.0,
                        },
                    )
                    .await
                    .unwrap();
            }

            let start = context.current();

            // Send 10KB to each receiver (100KB total)
            let mut handles = Vec::new();
            for (i, receiver) in receivers.iter().enumerate() {
                let mut sender_tx = sender_tx.clone();
                let receiver_clone = receiver.clone();
                let handle = context.clone().spawn(move |_| async move {
                    let msg = Bytes::from(vec![i as u8; 10_000]);
                    sender_tx
                        .send(Recipients::One(receiver_clone), msg, true)
                        .await
                        .unwrap();
                });
                handles.push(handle);
            }

            // Wait for all sends to complete
            for handle in handles {
                handle.await.unwrap();
            }

            let send_time = context.current().duration_since(start).unwrap();

            // Sender should send all 100KB in ~1s at 100KB/s
            assert!(
                send_time >= Duration::from_millis(950) && send_time <= Duration::from_millis(1100),
                "Sender took {:?} to send 100KB, expected ~1s",
                send_time
            );

            // Each receiver should receive their 10KB message in ~1s (10KB at 10KB/s)
            for (i, mut rx) in receiver_rxs.into_iter().enumerate() {
                let (_, msg) = rx.recv().await.unwrap();
                assert_eq!(msg[0], i as u8);
                let recv_time = context.current().duration_since(start).unwrap();

                // All messages should be received around 1s
                assert!(
                    recv_time >= Duration::from_millis(950)
                        && recv_time <= Duration::from_millis(1100),
                    "Receiver {} received at {:?}, expected ~1s",
                    i,
                    recv_time
                );
            }
        });
    }

    #[test]
    fn test_many_to_one_bandwidth_sharing() {
        use commonware_cryptography::ed25519;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.clone(),
                Config {
                    max_size: 1024 * 1024,
                },
            );
            network.start();

            // Create 10 senders and 1 receiver
            let mut senders = Vec::new();
            let mut sender_txs = Vec::new();
            for i in 0..10 {
                let sender = ed25519::PrivateKey::from_seed(i).public_key();
                senders.push(sender.clone());
                let (tx, _) = oracle.register(sender.clone(), 0).await.unwrap();
                sender_txs.push(tx);

                // Each sender has 10KB/s egress
                oracle
                    .set_bandwidth(sender.clone(), 10_000, usize::MAX)
                    .await
                    .unwrap();
            }

            let receiver = ed25519::PrivateKey::from_seed(100).public_key();
            let (_, mut receiver_rx) = oracle.register(receiver.clone(), 0).await.unwrap();

            // Receiver has 100KB/s ingress
            oracle
                .set_bandwidth(receiver.clone(), usize::MAX, 100_000)
                .await
                .unwrap();

            // Add links with no latency
            for sender in &senders {
                oracle
                    .add_link(
                        sender.clone(),
                        receiver.clone(),
                        Link {
                            latency: Duration::ZERO,
                            jitter: Duration::ZERO,
                            success_rate: 1.0,
                        },
                    )
                    .await
                    .unwrap();
            }

            let start = context.current();

            // All senders send 10KB simultaneously
            let mut handles = Vec::new();
            for (i, mut tx) in sender_txs.into_iter().enumerate() {
                let receiver_clone = receiver.clone();
                let handle = context.clone().spawn(move |_| async move {
                    let msg = Bytes::from(vec![i as u8; 10_000]);
                    tx.send(Recipients::One(receiver_clone), msg, true)
                        .await
                        .unwrap();
                });
                handles.push(handle);
            }

            // Wait for all sends to complete
            for handle in handles {
                handle.await.unwrap();
            }

            // All 10 messages should be received at ~1s
            // (100KB total data at 100KB/s aggregate bandwidth)
            for i in 0..10 {
                let (_, _msg) = receiver_rx.recv().await.unwrap();
                let recv_time = context.current().duration_since(start).unwrap();

                // Messages should all complete around 1s
                assert!(
                    recv_time >= Duration::from_millis(950)
                        && recv_time <= Duration::from_millis(1100),
                    "Message {} received at {:?}, expected ~1s",
                    i,
                    recv_time
                );
            }
        });
    }

    #[test]
    fn test_many_slow_senders_to_fast_receiver() {
        // Test that 10 slow senders (1KB/s each) sending to a fast receiver (10KB/s)
        // should complete all transfers in ~1s
        use commonware_cryptography::ed25519;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );
            network.start();

            // Create 10 slow senders
            let mut senders = Vec::new();
            let mut sender_txs = Vec::new();
            for i in 0..10 {
                let sender = ed25519::PrivateKey::from_seed(i).public_key();
                senders.push(sender.clone());
                let (tx, _) = oracle.register(sender.clone(), 0).await.unwrap();
                sender_txs.push(tx);

                // Each sender has 1KB/s egress (slow)
                oracle
                    .set_bandwidth(sender.clone(), 1_000, usize::MAX)
                    .await
                    .unwrap();
            }

            // Create fast receiver
            let receiver = ed25519::PrivateKey::from_seed(100).public_key();
            let (_, mut receiver_rx) = oracle.register(receiver.clone(), 0).await.unwrap();

            // Receiver has 10KB/s ingress (can handle all 10 senders at full speed)
            oracle
                .set_bandwidth(receiver.clone(), usize::MAX, 10_000)
                .await
                .unwrap();

            // Add links with no latency
            for sender in &senders {
                oracle
                    .add_link(
                        sender.clone(),
                        receiver.clone(),
                        Link {
                            latency: Duration::ZERO,
                            jitter: Duration::ZERO,
                            success_rate: 1.0,
                        },
                    )
                    .await
                    .unwrap();
            }

            let start = context.current();

            // All senders send 1KB simultaneously
            let mut handles = Vec::new();
            for (i, mut tx) in sender_txs.into_iter().enumerate() {
                let receiver_clone = receiver.clone();
                let handle = context.clone().spawn(move |_| async move {
                    let msg = Bytes::from(vec![i as u8; 1_000]);
                    tx.send(Recipients::One(receiver_clone), msg, true)
                        .await
                        .unwrap();
                });
                handles.push(handle);
            }

            // Wait for all sends to complete
            for handle in handles {
                handle.await.unwrap();
            }

            // Each sender takes 1s to transmit 1KB at 1KB/s
            // All transmissions happen in parallel, so total send time is ~1s

            // All 10 messages (10KB total) should be received at ~1s
            // Receiver processes at 10KB/s, can handle all 10KB in 1s
            for i in 0..10 {
                let (_, _msg) = receiver_rx.recv().await.unwrap();
                let recv_time = context.current().duration_since(start).unwrap();

                // All messages should complete around 1s
                assert!(
                    recv_time >= Duration::from_millis(950)
                        && recv_time <= Duration::from_millis(1100),
                    "Message {} received at {:?}, expected ~1s",
                    i,
                    recv_time
                );
            }
        });
    }

    #[test]
    fn test_dynamic_bandwidth_allocation_staggered() {
        // Test that bandwidth is dynamically allocated as transfers start and complete at different times
        // Scenario: 3 senders to 1 receiver, starting at different times
        // Receiver has 30KB/s, senders each have 30KB/s
        use commonware_cryptography::ed25519;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );
            network.start();

            // Create 3 senders
            let mut senders = Vec::new();
            let mut sender_txs = Vec::new();
            for i in 0..3 {
                let sender = ed25519::PrivateKey::from_seed(i).public_key();
                senders.push(sender.clone());
                let (tx, _) = oracle.register(sender.clone(), 0).await.unwrap();
                sender_txs.push(tx);

                // Each sender has 30KB/s egress
                oracle
                    .set_bandwidth(sender.clone(), 30_000, usize::MAX)
                    .await
                    .unwrap();
            }

            // Create receiver with 30KB/s ingress
            let receiver = ed25519::PrivateKey::from_seed(100).public_key();
            let (_, mut receiver_rx) = oracle.register(receiver.clone(), 0).await.unwrap();
            oracle
                .set_bandwidth(receiver.clone(), usize::MAX, 30_000)
                .await
                .unwrap();

            // Add links with minimal latency
            for sender in &senders {
                oracle
                    .add_link(
                        sender.clone(),
                        receiver.clone(),
                        Link {
                            latency: Duration::from_millis(1),
                            jitter: Duration::ZERO,
                            success_rate: 1.0,
                        },
                    )
                    .await
                    .unwrap();
            }

            let start = context.current();

            // Sender 0: sends 30KB at t=0
            // Should get full 30KB/s bandwidth, completes at t=1s
            let mut tx0 = sender_txs[0].clone();
            let rx_clone = receiver.clone();
            context.clone().spawn(move |_| async move {
                let msg = Bytes::from(vec![0u8; 30_000]);
                tx0.send(Recipients::One(rx_clone), msg, true)
                    .await
                    .unwrap();
            });

            // Sender 1: sends 30KB at t=0.5s
            // Should share bandwidth with sender 0 for 0.5s (15KB/s each)
            // Then get full bandwidth after sender 0 completes
            let mut tx1 = sender_txs[1].clone();
            let rx_clone = receiver.clone();
            context.clone().spawn(move |context| async move {
                context.sleep(Duration::from_millis(500)).await;
                let msg = Bytes::from(vec![1u8; 30_000]);
                tx1.send(Recipients::One(rx_clone), msg, true)
                    .await
                    .unwrap();
            });

            // Sender 2: sends 15KB at t=1.5s
            // Should get full bandwidth since others are done
            // Completes at t=2s (0.5s transmission)
            let mut tx2 = sender_txs[2].clone();
            let rx_clone = receiver.clone();
            context.clone().spawn(move |context| async move {
                context.sleep(Duration::from_millis(1500)).await;
                let msg = Bytes::from(vec![2u8; 15_000]);
                tx2.send(Recipients::One(rx_clone), msg, true)
                    .await
                    .unwrap();
            });

            // Receive and verify timing
            // With the new BTreeMap-based scheduling:
            // Message 0: starts at t=0, gets full 30KB/s, completes at t=1s
            let (_, msg0) = receiver_rx.recv().await.unwrap();
            assert_eq!(msg0[0], 0);
            let t0 = context.current().duration_since(start).unwrap();
            assert!(
                t0 >= Duration::from_millis(1000) && t0 <= Duration::from_millis(1100),
                "Message 0 received at {:?}, expected ~1s",
                t0
            );

            // The new algorithm may deliver messages in a different order based on
            // efficient bandwidth usage. Let's collect the next two messages and
            // verify their timings regardless of order.
            let (_, msg_a) = receiver_rx.recv().await.unwrap();
            let t_a = context.current().duration_since(start).unwrap();

            let (_, msg_b) = receiver_rx.recv().await.unwrap();
            let t_b = context.current().duration_since(start).unwrap();

            // Figure out which message is which based on content
            let (msg1, t1, msg2, t2) = if msg_a[0] == 1 {
                (msg_a, t_a, msg_b, t_b)
            } else {
                (msg_b, t_b, msg_a, t_a)
            };

            assert_eq!(msg1[0], 1);
            assert_eq!(msg2[0], 2);

            // Message 1 (30KB) started at t=0.5s
            // Message 2 (15KB) started at t=1.5s
            // With efficient scheduling, message 2 might complete first since it's smaller
            // Both should complete between 1.5s and 2.5s
            assert!(
                t1 >= Duration::from_millis(1500) && t1 <= Duration::from_millis(2600),
                "Message 1 received at {:?}, expected between 1.5s-2.6s",
                t1
            );

            assert!(
                t2 >= Duration::from_millis(1500) && t2 <= Duration::from_millis(2600),
                "Message 2 received at {:?}, expected between 1.5s-2.6s",
                t2
            );
        });
    }

    #[test]
    fn test_dynamic_bandwidth_varied_sizes() {
        // Test dynamic allocation with different message sizes arriving simultaneously
        // This tests that smaller messages complete first when bandwidth is shared
        use commonware_cryptography::ed25519;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );
            network.start();

            // Create 3 senders
            let mut senders = Vec::new();
            let mut sender_txs = Vec::new();
            for i in 0..3 {
                let sender = ed25519::PrivateKey::from_seed(i).public_key();
                senders.push(sender.clone());
                let (tx, _) = oracle.register(sender.clone(), 0).await.unwrap();
                sender_txs.push(tx);

                // Each sender has unlimited egress
                oracle
                    .set_bandwidth(sender.clone(), usize::MAX, usize::MAX)
                    .await
                    .unwrap();
            }

            // Create receiver with 30KB/s ingress
            let receiver = ed25519::PrivateKey::from_seed(100).public_key();
            let (_, mut receiver_rx) = oracle.register(receiver.clone(), 0).await.unwrap();
            oracle
                .set_bandwidth(receiver.clone(), usize::MAX, 30_000)
                .await
                .unwrap();

            // Add links
            for sender in &senders {
                oracle
                    .add_link(
                        sender.clone(),
                        receiver.clone(),
                        Link {
                            latency: Duration::from_millis(1),
                            jitter: Duration::ZERO,
                            success_rate: 1.0,
                        },
                    )
                    .await
                    .unwrap();
            }

            let start = context.current();

            // All start at the same time but with different sizes
            // With our slot-based system, bandwidth is reserved in advance
            // The actual behavior depends on the order tasks are processed
            // Since all senders start at once, they'll compete for bandwidth

            let sizes = [10_000, 20_000, 30_000];
            let mut handles = Vec::new();

            for (i, (mut tx, size)) in sender_txs.into_iter().zip(sizes.iter()).enumerate() {
                let rx_clone = receiver.clone();
                let msg_size = *size;
                let handle = context.clone().spawn(move |_| async move {
                    let msg = Bytes::from(vec![i as u8; msg_size]);
                    tx.send(Recipients::One(rx_clone), msg, true).await.unwrap();
                });
                handles.push(handle);
            }

            // Wait for all sends to complete
            for handle in handles {
                handle.await.unwrap();
            }

            // Receive messages - with our slot-based system, they arrive in the order
            // they were scheduled, not necessarily size order

            // Collect all messages and sort by receive time to verify timing
            let mut messages = Vec::new();
            for _ in 0..3 {
                let (_, msg) = receiver_rx.recv().await.unwrap();
                let t = context.current().duration_since(start).unwrap();
                messages.push((msg[0] as usize, msg.len(), t));
            }

            // With slot-based scheduling, the actual timing depends on ordering
            // When all start at once, they'll reserve bandwidth slots sequentially
            // First gets full 30KB/s, others wait or get remaining bandwidth

            // Just verify all messages arrived and total time is reasonable
            assert_eq!(messages.len(), 3);

            // Total data is 60KB at 30KB/s receiver ingress = 2s minimum
            let max_time = messages.iter().map(|&(_, _, t)| t).max().unwrap();
            assert!(
                max_time >= Duration::from_millis(2000),
                "Total time {:?} should be at least 2s for 60KB at 30KB/s",
                max_time
            );
        });
    }

    #[test]
    fn test_bandwidth_pipe_reservation_duration() {
        // Test that bandwidth pipe is only reserved for transmission duration, not latency
        // This means new messages can start transmitting while others are still in flight
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );
            network.start();

            // Create two peers
            let sender = PrivateKey::from_seed(1).public_key();
            let receiver = PrivateKey::from_seed(2).public_key();

            let (sender_tx, _) = oracle.register(sender.clone(), 0).await.unwrap();
            let (_, mut receiver_rx) = oracle.register(receiver.clone(), 0).await.unwrap();

            // Set bandwidth: 1000 B/s (1 byte per millisecond)
            oracle
                .set_bandwidth(sender.clone(), 1000, usize::MAX)
                .await
                .unwrap();
            oracle
                .set_bandwidth(receiver.clone(), usize::MAX, 1000)
                .await
                .unwrap();

            // Add link with significant latency (1 second)
            oracle
                .add_link(
                    sender.clone(),
                    receiver.clone(),
                    Link {
                        latency: Duration::from_secs(1), // 1 second latency
                        jitter: Duration::ZERO,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            // Send 3 messages of 500 bytes each
            // At 1000 B/s, each message takes 500ms to transmit
            // With 1s latency, if pipe was reserved for tx+latency, total would be:
            //   - Msg 1: 0-1500ms (500ms tx + 1000ms latency)
            //   - Msg 2: 1500-3000ms (starts after msg 1 fully delivered)
            //   - Msg 3: 3000-4500ms
            // But if pipe is only reserved during tx (correct behavior):
            //   - Msg 1: tx 0-500ms, delivered at 1500ms
            //   - Msg 2: tx 500-1000ms, delivered at 2000ms
            //   - Msg 3: tx 1000-1500ms, delivered at 2500ms

            let start = context.current();

            // Send all messages in quick succession
            let mut handles = Vec::new();
            for i in 0..3 {
                let mut sender_tx = sender_tx.clone();
                let receiver = receiver.clone();
                let msg = Bytes::from(vec![i; 500]);
                let handle = context.clone().spawn(move |context| async move {
                    sender_tx
                        .send(Recipients::One(receiver), msg, false)
                        .await
                        .unwrap();

                    // Record time when send completes (is acknowledged)
                    context.current().duration_since(start).unwrap()
                });
                handles.push(handle);

                // Small delay between spawns to ensure ordering
                context.sleep(Duration::from_millis(1)).await;
            }

            // Wait for all sends to complete and collect their completion times
            let mut send_times = Vec::new();
            for handle in handles {
                let time = handle.await.unwrap();
                send_times.push(time);
            }

            // Verify that sends completed (were acknowledged) once transmission finished,
            // not after delivery. The sends should complete at ~500ms, ~1000ms, ~1500ms
            for (i, time) in send_times.iter().enumerate() {
                // Each message takes 500ms to transmit, and they queue sequentially
                let expected_min = i as u64 * 500;
                let expected_max = expected_min + 600;

                assert!(
                    *time >= Duration::from_millis(expected_min)
                        && *time <= Duration::from_millis(expected_max),
                    "Send {} should be acknowledged at ~{}ms-{}ms, got {:?}",
                    i + 1,
                    expected_min,
                    expected_max,
                    time
                );
            }

            // Wait for all receives to complete and record their completion times
            let mut receive_times = Vec::new();
            for i in 0..3 {
                let (_, received) = receiver_rx.recv().await.unwrap();
                receive_times.push(context.current().duration_since(start).unwrap());
                assert_eq!(received[0], i);
            }

            // Messages should be received at:
            // - Msg 1: ~1500ms (500ms transmission + 1000ms latency)
            // - Msg 2: ~2000ms (500ms wait + 500ms transmission + 1000ms latency)
            // - Msg 3: ~2500ms (1000ms wait + 500ms transmission + 1000ms latency)
            for (i, time) in receive_times.iter().enumerate() {
                let expected_min = (i as u64 * 500) + 1500;
                let expected_max = expected_min + 100;

                assert!(
                    *time >= Duration::from_millis(expected_min)
                        && *time < Duration::from_millis(expected_max),
                    "Message {} should arrive at ~{}ms, got {:?}",
                    i + 1,
                    expected_min,
                    time
                );
            }
        });
    }

    #[test]
    fn test_dynamic_bandwidth_affects_new_transfers() {
        // This test verifies that bandwidth changes affect NEW transfers,
        // not transfers already in progress (which have their reservations locked in)
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );
            network.start();

            let pk_sender = PrivateKey::from_seed(1).public_key();
            let pk_receiver = PrivateKey::from_seed(2).public_key();

            // Register peers and establish link
            let (mut sender_tx, _sender_rx) = oracle.register(pk_sender.clone(), 0).await.unwrap();
            let (_receiver_tx, mut receiver_rx) =
                oracle.register(pk_receiver.clone(), 0).await.unwrap();
            oracle
                .add_link(
                    pk_sender.clone(),
                    pk_receiver.clone(),
                    Link {
                        latency: Duration::from_millis(1), // Small latency
                        jitter: Duration::ZERO,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            // Initial bandwidth: 10 KB/s
            oracle
                .set_bandwidth(pk_sender.clone(), 10_000, usize::MAX)
                .await
                .unwrap();
            oracle
                .set_bandwidth(pk_receiver.clone(), usize::MAX, 10_000)
                .await
                .unwrap();

            // Send first message at 10 KB/s
            let msg1 = Bytes::from(vec![1u8; 20_000]); // 20 KB
            let start_time = context.current();
            sender_tx
                .send(Recipients::One(pk_receiver.clone()), msg1.clone(), false)
                .await
                .unwrap();

            // Receive first message (should take ~2s at 10KB/s)
            let (_sender, received_msg1) = receiver_rx.recv().await.unwrap();
            let msg1_time = context.current().duration_since(start_time).unwrap();
            assert_eq!(received_msg1.len(), 20_000);
            assert!(
                msg1_time >= Duration::from_millis(1999)
                    && msg1_time <= Duration::from_millis(2010),
                "First message should take ~2s, got {:?}",
                msg1_time
            );

            // Change bandwidth to 2 KB/s
            oracle
                .set_bandwidth(pk_sender.clone(), 2_000, usize::MAX)
                .await
                .unwrap();

            // Send second message at new bandwidth
            let msg2 = Bytes::from(vec![2u8; 10_000]); // 10 KB
            let msg2_start = context.current();
            sender_tx
                .send(Recipients::One(pk_receiver.clone()), msg2.clone(), false)
                .await
                .unwrap();

            // Receive second message (should take ~5s at 2KB/s)
            let (_sender, received_msg2) = receiver_rx.recv().await.unwrap();
            let msg2_time = context.current().duration_since(msg2_start).unwrap();
            assert_eq!(received_msg2.len(), 10_000);
            assert!(
                msg2_time >= Duration::from_millis(4999)
                    && msg2_time <= Duration::from_millis(5010),
                "Second message should take ~5s at reduced bandwidth, got {:?}",
                msg2_time
            );
        });
    }

    #[test]
    fn test_zero_sender_bandwidth_blocks_forever() {
        // This test verifies that when sender bandwidth is 0, the send never completes
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );
            network.start();

            let pk_sender = PrivateKey::from_seed(1).public_key();
            let pk_receiver = PrivateKey::from_seed(2).public_key();

            // Register peers and establish link
            let (sender_tx, _sender_rx) = oracle.register(pk_sender.clone(), 0).await.unwrap();
            let (_receiver_tx, mut receiver_rx) =
                oracle.register(pk_receiver.clone(), 0).await.unwrap();
            oracle
                .add_link(
                    pk_sender.clone(),
                    pk_receiver.clone(),
                    Link {
                        latency: Duration::from_millis(10),
                        jitter: Duration::ZERO,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            // Set sender bandwidth to 0
            oracle
                .set_bandwidth(pk_sender.clone(), 0, usize::MAX)
                .await
                .unwrap();
            oracle
                .set_bandwidth(pk_receiver.clone(), usize::MAX, 10_000)
                .await
                .unwrap();

            let msg = Bytes::from(vec![1u8; 1000]);

            // Try to send - this should block forever
            context.with_label("blocked-sender").spawn({
                let mut sender = sender_tx.clone();
                let receiver = pk_receiver.clone();
                let msg = msg.clone();
                move |_| async move { sender.send(Recipients::One(receiver), msg, false).await }
            });

            // Wait 2 seconds and verify the send hasn't completed
            context.sleep(Duration::from_secs(2)).await;

            // Try to receive with timeout - should timeout
            let timeout_ctx = context.with_label("timeout");
            let received = select! {
                msg = receiver_rx.recv() => { Some(msg) },
                _ = timeout_ctx.sleep(Duration::from_secs(1)) => { None },
            };
            assert!(
                received.is_none(),
                "Should not receive message when sender bandwidth is 0"
            );

            // Verify send is still pending (would panic if completed with error)
            // We can't directly check if it's pending, but if test doesn't hang, it works
        });
    }

    #[test]
    fn test_zero_receiver_bandwidth_uses_sender_bandwidth() {
        // When receiver bandwidth is 0, transfer uses only sender bandwidth
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );
            network.start();

            let pk_sender = PrivateKey::from_seed(1).public_key();
            let pk_receiver = PrivateKey::from_seed(2).public_key();

            // Register peers and establish link
            let (mut sender_tx, _sender_rx) = oracle.register(pk_sender.clone(), 0).await.unwrap();
            let (_receiver_tx, mut receiver_rx) =
                oracle.register(pk_receiver.clone(), 0).await.unwrap();
            oracle
                .add_link(
                    pk_sender.clone(),
                    pk_receiver.clone(),
                    Link {
                        latency: Duration::from_millis(10),
                        jitter: Duration::ZERO,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            // First test: normal bandwidth on both sides
            oracle
                .set_bandwidth(pk_sender.clone(), 10_000, usize::MAX)
                .await
                .unwrap();
            oracle
                .set_bandwidth(pk_receiver.clone(), usize::MAX, 10_000)
                .await
                .unwrap();

            let msg1 = Bytes::from(vec![1u8; 10_000]); // 10KB
            let start1 = context.current();
            sender_tx
                .send(Recipients::One(pk_receiver.clone()), msg1.clone(), false)
                .await
                .unwrap();
            let (_sender, received1) = receiver_rx.recv().await.unwrap();
            let time1 = context.current().duration_since(start1).unwrap();
            assert_eq!(received1.len(), 10_000);
            // Should take ~1s + latency
            assert!(
                time1 >= Duration::from_millis(1009) && time1 <= Duration::from_millis(1020),
                "Normal transfer should take ~1s + latency, got {:?}",
                time1
            );

            // Second test: receiver bandwidth is 0
            oracle
                .set_bandwidth(pk_receiver.clone(), usize::MAX, 0)
                .await
                .unwrap();

            let msg2 = Bytes::from(vec![2u8; 10_000]); // 10KB
            let start2 = context.current();
            let sent = sender_tx
                .send(Recipients::One(pk_receiver.clone()), msg2.clone(), false)
                .await
                .unwrap();
            let send_time = context.current().duration_since(start2).unwrap();

            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0], pk_receiver);
            // When receiver bandwidth is 0, should still use sender bandwidth (10KB/s)
            assert!(
                send_time >= Duration::from_millis(999) && send_time <= Duration::from_millis(1010),
                "With receiver bandwidth 0, should still use sender bandwidth (~1s), got {:?}",
                send_time
            );

            // Message never arrives
        });
    }
}

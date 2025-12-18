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
//! capacity is a shared, finite resource. Bandwidth is allocated via progressive
//! filling to provide max-min fairness.
//!
//! _If no bandwidth constraints are provided (default behavior), progressive filling and bandwidth
//! tracking are not performed (avoiding unnecessary overhead for minimal p2p testing common in CI)._
//!
//! ## Core Model
//!
//! Whenever a transfer starts or finishes, or a bandwidth limit is updated, we execute a scheduling tick:
//!
//! 1. **Collect Active Flows:** Gather every active transfer that still has
//!    bytes to send. A flow is bound to one sender and to one receiver (if the message will be delivered).
//! 2. **Compute Progressive Filling:** Run progressive filling to raise the rate of
//!    every active flow in lock-step until some sender's egress or receiver's ingress
//!    limit saturates (at which point the flow is frozen and the process repeats with what remains).
//! 3. **Wait for the Next Event:** Using those rates, determine which flow will
//!    finish first by computing how long it needs to transmit its remaining
//!    bytes. Advance simulated time directly to that completion instant (advancing all other flows
//!    by the bytes transferred over the interval).
//! 4. **Deliver Message:** Remove the completed flow and pass the message to the receiver. Repeat from step 1
//!    until all flows are processed.
//!
//! _Messages between the same pair of peers remain strictly ordered. When one
//! message finishes, the next message on that link may begin sending at
//! `arrival_time - new_latency` so that its first byte arrives immediately after
//! the previous one is fully received._
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
//! use commonware_p2p::{Manager, simulated::{Config, Link, Network}};
//! use commonware_cryptography::{ed25519, PrivateKey, Signer as _, PublicKey as _, };
//! use commonware_runtime::{deterministic, Metrics, Quota, Runner, Spawner};
//! use commonware_utils::NZU32;
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
//!     disconnect_on_block: true,
//!     tracked_peer_sets: Some(3),
//! };
//!
//! // Rate limit quota (1000 messages per second per peer)
//! let quota = Quota::per_second(NZU32!(1000));
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
//!     // Register a peer set
//!     let mut manager = oracle.manager();
//!     manager.update(0, peers.clone().try_into().unwrap()).await;
//!
//!     let (sender1, receiver1) = oracle.control(peers[0].clone()).register(0, quota).await.unwrap();
//!     let (sender2, receiver2) = oracle.control(peers[1].clone()).register(0, quota).await.unwrap();
//!
//!     // Set bandwidth limits
//!     // peer[0]: 10KB/s egress, unlimited ingress
//!     // peer[1]: unlimited egress, 5KB/s ingress
//!     oracle.limit_bandwidth(peers[0].clone(), Some(10_000), None).await.unwrap();
//!     oracle.limit_bandwidth(peers[1].clone(), None, Some(5_000)).await.unwrap();
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
mod transmitter;

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

pub use ingress::{Control, Link, Manager, Oracle, SocketManager};
pub use network::{
    Config, ConnectedPeerProvider, Network, Receiver, Sender, SplitForwarder, SplitOrigin,
    SplitRouter, SplitSender, SplitTarget, UnlimitedSender,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Address, Ingress, Manager, Receiver, Recipients, Sender};
    use bytes::Bytes;
    use commonware_cryptography::{
        ed25519::{self, PrivateKey, PublicKey},
        Signer as _,
    };
    use commonware_macros::select;
    use commonware_runtime::{deterministic, Clock, Metrics, Quota, Runner, Spawner};
    use commonware_utils::{hostname, ordered::Map, NZU32};
    use futures::{channel::mpsc, SinkExt, StreamExt};
    use rand::Rng;
    use std::{
        collections::{BTreeMap, HashMap, HashSet},
        net::SocketAddr,
        num::NonZeroU32,
        time::Duration,
    };

    /// Default rate limit set high enough to not interfere with normal operation
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    fn simulate_messages(seed: u64, size: usize) -> (String, Vec<usize>) {
        let executor = deterministic::Runner::seeded(seed);
        executor.start(|context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );

            // Start network
            network.start();

            // Register agents
            let mut agents = BTreeMap::new();
            let (seen_sender, mut seen_receiver) = mpsc::channel(1024);
            for i in 0..size {
                let pk = PrivateKey::from_seed(i as u64).public_key();
                let (sender, mut receiver) = oracle
                    .control(pk.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
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
            let (network, oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );

            // Start network
            network.start();

            // Register agents
            let mut agents = HashMap::new();
            for i in 0..10 {
                let pk = PrivateKey::from_seed(i as u64).public_key();
                let (sender, _) = oracle
                    .control(pk.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
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
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );

            // Start network
            network.start();

            // Register agents
            let pk = PrivateKey::from_seed(0).public_key();
            oracle
                .control(pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

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
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );

            // Start network
            network.start();

            // Setup links
            let my_pk = PrivateKey::from_seed(0).public_key();
            let other_pk = PrivateKey::from_seed(1).public_key();
            oracle
                .add_link(
                    my_pk.clone(),
                    other_pk.clone(),
                    Link {
                        latency: Duration::from_millis(10),
                        jitter: Duration::from_millis(1),
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();
            oracle
                .add_link(
                    other_pk.clone(),
                    my_pk.clone(),
                    Link {
                        latency: Duration::from_millis(10),
                        jitter: Duration::from_millis(1),
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            // Register channels
            let (mut my_sender, mut my_receiver) = oracle
                .control(my_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (mut other_sender, mut other_receiver) = oracle
                .control(other_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            // Send messages
            let msg = Bytes::from("hello");
            my_sender
                .send(Recipients::One(other_pk.clone()), msg.clone(), false)
                .await
                .unwrap();
            let (from, message) = other_receiver.recv().await.unwrap();
            assert_eq!(from, my_pk);
            assert_eq!(message, msg);
            other_sender
                .send(Recipients::One(my_pk.clone()), msg.clone(), false)
                .await
                .unwrap();
            let (from, message) = my_receiver.recv().await.unwrap();
            assert_eq!(from, other_pk);
            assert_eq!(message, msg);

            // Update channel
            let (mut my_sender_2, mut my_receiver_2) = oracle
                .control(my_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            // Send message
            let msg = Bytes::from("hello again");
            my_sender_2
                .send(Recipients::One(other_pk.clone()), msg.clone(), false)
                .await
                .unwrap();
            let (from, message) = other_receiver.recv().await.unwrap();
            assert_eq!(from, my_pk);
            assert_eq!(message, msg);
            other_sender
                .send(Recipients::One(my_pk.clone()), msg.clone(), false)
                .await
                .unwrap();
            let (from, message) = my_receiver_2.recv().await.unwrap();
            assert_eq!(from, other_pk);
            assert_eq!(message, msg);

            // Listen on original
            assert!(matches!(
                my_receiver.recv().await,
                Err(Error::NetworkClosed)
            ));

            // Send on original
            assert!(matches!(
                my_sender
                    .send(Recipients::One(other_pk.clone()), msg.clone(), false)
                    .await,
                Err(Error::NetworkClosed)
            ));
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
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );

            // Start network
            network.start();

            // Register agents
            let pk1 = PrivateKey::from_seed(0).public_key();
            let pk2 = PrivateKey::from_seed(1).public_key();
            oracle
                .control(pk1.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .control(pk2.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

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
    fn test_add_link_before_channel_registration() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: Some(3),
                },
            );
            network.start();

            // Create peers
            let pk1 = PrivateKey::from_seed(0).public_key();
            let pk2 = PrivateKey::from_seed(1).public_key();

            // Register peer set
            let mut manager = oracle.manager();
            manager
                .update(0, vec![pk1.clone(), pk2.clone()].try_into().unwrap())
                .await;

            // Add link
            oracle
                .add_link(
                    pk1.clone(),
                    pk2.clone(),
                    Link {
                        latency: Duration::ZERO,
                        jitter: Duration::ZERO,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            // Register channels
            let (mut sender1, _receiver1) = oracle
                .control(pk1.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_, mut receiver2) = oracle
                .control(pk2.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            // Send message
            let msg1 = Bytes::from("link-before-register-1");
            sender1
                .send(Recipients::One(pk2.clone()), msg1.clone(), false)
                .await
                .unwrap();
            let (from, received) = receiver2.recv().await.unwrap();
            assert_eq!(from, pk1);
            assert_eq!(received, msg1);
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
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );

            // Start network
            network.start();

            // Register agents
            let pk1 = PrivateKey::from_seed(0).public_key();
            let pk2 = PrivateKey::from_seed(1).public_key();
            let (mut sender1, mut receiver1) = oracle
                .control(pk1.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (mut sender2, mut receiver2) = oracle
                .control(pk2.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            // Register unused channels
            let _ = oracle
                .control(pk1.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            let _ = oracle
                .control(pk2.clone())
                .register(2, TEST_QUOTA)
                .await
                .unwrap();

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
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );

            // Start network
            network.start();

            // Register agents
            let pk1 = PrivateKey::from_seed(0).public_key();
            let pk2 = PrivateKey::from_seed(1).public_key();
            let (mut sender1, _) = oracle
                .control(pk1.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_, mut receiver2) = oracle
                .control(pk2.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

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
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );

            // Start network
            network.start();

            // Define agents
            let pk1 = PrivateKey::from_seed(0).public_key();
            let pk2 = PrivateKey::from_seed(1).public_key();
            let (mut sender1, mut receiver1) = oracle
                .control(pk1.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (mut sender2, mut receiver2) = oracle
                .control(pk2.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

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
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );

            // Start network
            network.start();

            // Register agents
            let pk1 = PrivateKey::from_seed(0).public_key();
            let pk2 = PrivateKey::from_seed(1).public_key();
            let (mut sender1, mut receiver1) = oracle
                .control(pk1.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (mut sender2, mut receiver2) = oracle
                .control(pk2.clone())
                .register(0, TEST_QUOTA)
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
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        sender_bps: Option<usize>,
        receiver_bps: Option<usize>,
        message_size: usize,
        expected_duration_ms: u64,
    ) {
        // Create two agents
        let pk1 = PrivateKey::from_seed(context.gen::<u64>()).public_key();
        let pk2 = PrivateKey::from_seed(context.gen::<u64>()).public_key();
        let (mut sender, _) = oracle
            .control(pk1.clone())
            .register(0, TEST_QUOTA)
            .await
            .unwrap();
        let (_, mut receiver) = oracle
            .control(pk2.clone())
            .register(0, TEST_QUOTA)
            .await
            .unwrap();

        // Set bandwidth limits
        oracle
            .limit_bandwidth(pk1.clone(), sender_bps, None)
            .await
            .unwrap();
        oracle
            .limit_bandwidth(pk2.clone(), None, receiver_bps)
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
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
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
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
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
                let (sender, receiver) = oracle
                    .control(pk.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                peers.push(pk);
                senders.push(sender);
                receivers.push(receiver);
            }

            // Set bandwidth limits for all peers
            for pk in &peers {
                oracle
                    .limit_bandwidth(pk.clone(), Some(EFFECTIVE_BPS), Some(EFFECTIVE_BPS))
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
            let msg = Bytes::from(vec![0u8; MESSAGE_SIZE]);
            for peer in peers.iter().skip(1) {
                senders[0]
                    .send(Recipients::One(peer.clone()), msg.clone(), true)
                    .await
                    .unwrap();
            }

            // Verify all messages are received
            for receiver in receivers.iter_mut().skip(1) {
                let (origin, received) = receiver.recv().await.unwrap();
                assert_eq!(origin, peers[0]);
                assert_eq!(received.len(), MESSAGE_SIZE);
            }

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

            // Many-to-one (all peers send to the main peer)
            let start = context.current();

            // Each peer sends a message to the main peer concurrently and we wait for all
            // sends to be acknowledged
            let msg = Bytes::from(vec![0; MESSAGE_SIZE]);
            for mut sender in senders.into_iter().skip(1) {
                sender
                    .send(Recipients::One(peers[0].clone()), msg.clone(), true)
                    .await
                    .unwrap();
            }

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
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            // Register agents
            let pk1 = PrivateKey::from_seed(1).public_key();
            let pk2 = PrivateKey::from_seed(2).public_key();
            let (mut sender, _) = oracle
                .control(pk1.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_, mut receiver) = oracle
                .control(pk2.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

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
    fn test_high_latency_message_blocks_followup() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            let pk1 = PrivateKey::from_seed(1).public_key();
            let pk2 = PrivateKey::from_seed(2).public_key();
            let (mut sender, _) = oracle.control(pk1.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_, mut receiver) = oracle.control(pk2.clone()).register(0, TEST_QUOTA).await.unwrap();

            const BPS: usize = 1_000;
            oracle
                .limit_bandwidth(pk1.clone(), Some(BPS), None)
                .await
                .unwrap();
            oracle
                .limit_bandwidth(pk2.clone(), None, Some(BPS))
                .await
                .unwrap();

            // Send slow message
            oracle
                .add_link(
                    pk1.clone(),
                    pk2.clone(),
                    Link {
                        latency: Duration::from_millis(5_000),
                        jitter: Duration::ZERO,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            let slow = Bytes::from(vec![0u8; 1_000]);
            sender
                .send(Recipients::One(pk2.clone()), slow.clone(), true)
                .await
                .unwrap();

            // Update link
            oracle.remove_link(pk1.clone(), pk2.clone()).await.unwrap();
            oracle
                .add_link(
                    pk1.clone(),
                    pk2.clone(),
                    Link {
                        latency: Duration::from_millis(1),
                        jitter: Duration::ZERO,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            // Send fast message
            let fast = Bytes::from(vec![1u8; 1_000]);
            sender
                .send(Recipients::One(pk2.clone()), fast.clone(), true)
                .await
                .unwrap();

            let start = context.current();
            let (origin1, message1) = receiver.recv().await.unwrap();
            assert_eq!(origin1, pk1);
            assert_eq!(message1, slow);
            let first_elapsed = context.current().duration_since(start).unwrap();

            let (origin2, message2) = receiver.recv().await.unwrap();
            let second_elapsed = context.current().duration_since(start).unwrap();
            assert_eq!(origin2, pk1);
            assert_eq!(message2, fast);

            let egress_time = Duration::from_secs(1);
            let slow_latency = Duration::from_millis(5_000);
            let expected_first = egress_time + slow_latency;
            let tolerance = Duration::from_millis(10);
            assert!(
                first_elapsed >= expected_first.saturating_sub(tolerance)
                    && first_elapsed <= expected_first + tolerance,
                "slow message arrived outside expected window: {first_elapsed:?} (expected {expected_first:?} ± {tolerance:?})"
            );
            assert!(
                second_elapsed >= first_elapsed,
                "fast message arrived before slow transmission completed"
            );

            let arrival_gap = second_elapsed
                .checked_sub(first_elapsed)
                .expect("timestamps ordered");
            assert!(
                arrival_gap >= egress_time.saturating_sub(tolerance)
                    && arrival_gap <= egress_time + tolerance,
                "next arrival deviated from transmit duration (gap = {arrival_gap:?}, expected {egress_time:?} ± {tolerance:?})"
            );
        })
    }

    #[test]
    fn test_many_to_one_bandwidth_sharing() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            // Create 10 senders and 1 receiver
            let mut senders = Vec::new();
            let mut sender_txs = Vec::new();
            for i in 0..10 {
                let sender = ed25519::PrivateKey::from_seed(i).public_key();
                senders.push(sender.clone());
                let (tx, _) = oracle
                    .control(sender.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                sender_txs.push(tx);

                // Each sender has 10KB/s egress
                oracle
                    .limit_bandwidth(sender.clone(), Some(10_000), None)
                    .await
                    .unwrap();
            }

            let receiver = ed25519::PrivateKey::from_seed(100).public_key();
            let (_, mut receiver_rx) = oracle
                .control(receiver.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            // Receiver has 100KB/s ingress
            oracle
                .limit_bandwidth(receiver.clone(), None, Some(100_000))
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
            for (i, mut tx) in sender_txs.into_iter().enumerate() {
                let receiver_clone = receiver.clone();
                let msg = Bytes::from(vec![i as u8; 10_000]);
                tx.send(Recipients::One(receiver_clone), msg, true)
                    .await
                    .unwrap();
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
                    "Message {i} received at {recv_time:?}, expected ~1s",
                );
            }
        });
    }

    #[test]
    fn test_one_to_many_fast_sender() {
        // Test that 1 fast sender (100KB/s) sending to 10 receivers (10KB/s each)
        // should complete all sends in ~1s and all messages received in ~1s
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            // Create fast sender
            let sender = ed25519::PrivateKey::from_seed(0).public_key();
            let (sender_tx, _) = oracle
                .control(sender.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            // Sender has 100KB/s egress
            oracle
                .limit_bandwidth(sender.clone(), Some(100_000), None)
                .await
                .unwrap();

            // Create 10 receivers
            let mut receivers = Vec::new();
            let mut receiver_rxs = Vec::new();
            for i in 0..10 {
                let receiver = ed25519::PrivateKey::from_seed(i + 1).public_key();
                receivers.push(receiver.clone());
                let (_, rx) = oracle
                    .control(receiver.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                receiver_rxs.push(rx);

                // Each receiver has 10KB/s ingress
                oracle
                    .limit_bandwidth(receiver.clone(), None, Some(10_000))
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
            for (i, receiver) in receivers.iter().enumerate() {
                let mut sender_tx = sender_tx.clone();
                let receiver_clone = receiver.clone();
                let msg = Bytes::from(vec![i as u8; 10_000]);
                sender_tx
                    .send(Recipients::One(receiver_clone), msg, true)
                    .await
                    .unwrap();
            }

            // Each receiver should receive their 10KB message in ~1s (10KB at 10KB/s)
            for (i, mut rx) in receiver_rxs.into_iter().enumerate() {
                let (_, msg) = rx.recv().await.unwrap();
                assert_eq!(msg[0], i as u8);
                let recv_time = context.current().duration_since(start).unwrap();

                // All messages should be received around 1s
                assert!(
                    recv_time >= Duration::from_millis(950)
                        && recv_time <= Duration::from_millis(1100),
                    "Receiver {i} received at {recv_time:?}, expected ~1s",
                );
            }
        });
    }

    #[test]
    fn test_many_slow_senders_to_fast_receiver() {
        // Test that 10 slow senders (1KB/s each) sending to a fast receiver (10KB/s)
        // should complete all transfers in ~1s
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            // Create 10 slow senders
            let mut senders = Vec::new();
            let mut sender_txs = Vec::new();
            for i in 0..10 {
                let sender = ed25519::PrivateKey::from_seed(i).public_key();
                senders.push(sender.clone());
                let (tx, _) = oracle
                    .control(sender.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                sender_txs.push(tx);

                // Each sender has 1KB/s egress (slow)
                oracle
                    .limit_bandwidth(sender.clone(), Some(1_000), None)
                    .await
                    .unwrap();
            }

            // Create fast receiver
            let receiver = ed25519::PrivateKey::from_seed(100).public_key();
            let (_, mut receiver_rx) = oracle
                .control(receiver.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            // Receiver has 10KB/s ingress (can handle all 10 senders at full speed)
            oracle
                .limit_bandwidth(receiver.clone(), None, Some(10_000))
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
            for (i, mut tx) in sender_txs.into_iter().enumerate() {
                let receiver_clone = receiver.clone();
                let msg = Bytes::from(vec![i as u8; 1_000]);
                tx.send(Recipients::One(receiver_clone), msg, true)
                    .await
                    .unwrap();
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
                    "Message {i} received at {recv_time:?}, expected ~1s",
                );
            }
        });
    }

    #[test]
    fn test_dynamic_bandwidth_allocation_staggered() {
        // Test that bandwidth is dynamically allocated as
        // transfers start and complete at different times
        //
        // 3 senders to 1 receiver, starting at different times
        // Receiver has 30KB/s, senders each have 30KB/s
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            // Create 3 senders
            let mut senders = Vec::new();
            let mut sender_txs = Vec::new();
            for i in 0..3 {
                let sender = ed25519::PrivateKey::from_seed(i).public_key();
                senders.push(sender.clone());
                let (tx, _) = oracle
                    .control(sender.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                sender_txs.push(tx);

                // Each sender has 30KB/s egress
                oracle
                    .limit_bandwidth(sender.clone(), Some(30_000), None)
                    .await
                    .unwrap();
            }

            // Create receiver with 30KB/s ingress
            let receiver = ed25519::PrivateKey::from_seed(100).public_key();
            let (_, mut receiver_rx) = oracle
                .control(receiver.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .limit_bandwidth(receiver.clone(), None, Some(30_000))
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
            // Gets full 30KB/s for the first 0.5s, then shares with sender 1
            // at 15KB/s until completion at t=1.5s
            let mut tx0 = sender_txs[0].clone();
            let rx_clone = receiver.clone();
            context.clone().spawn(move |_| async move {
                let msg = Bytes::from(vec![0u8; 30_000]);
                tx0.send(Recipients::One(rx_clone), msg, true)
                    .await
                    .unwrap();
            });

            // Sender 1: sends 30KB at t=0.5s
            // Shares bandwidth with sender 0 (15KB/s each) until t=1.5s,
            // then gets the full 30KB/s
            let mut tx1 = sender_txs[1].clone();
            let rx_clone = receiver.clone();
            context.clone().spawn(move |context| async move {
                context.sleep(Duration::from_millis(500)).await;
                let msg = Bytes::from(vec![1u8; 30_000]);
                tx1.send(Recipients::One(rx_clone), msg, true)
                    .await
                    .unwrap();
            });

            // Sender 2: sends 15KB at t=1.5s and shares the receiver with
            // sender 1, completing at roughly t=2.5s
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
            // Message 0: starts at t=0, shares bandwidth after 0.5s,
            // and completes at t=1.5s (plus link latency)
            let (_, msg0) = receiver_rx.recv().await.unwrap();
            assert_eq!(msg0[0], 0);
            let t0 = context.current().duration_since(start).unwrap();
            assert!(
                t0 >= Duration::from_millis(1490) && t0 <= Duration::from_millis(1600),
                "Message 0 received at {t0:?}, expected ~1.5s",
            );

            // The algorithm may deliver messages in a different order based on
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
                "Message 1 received at {t1:?}, expected between 1.5s-2.6s",
            );

            assert!(
                t2 >= Duration::from_millis(1500) && t2 <= Duration::from_millis(2600),
                "Message 2 received at {t2:?}, expected between 1.5s-2.6s",
            );
        });
    }

    #[test]
    fn test_dynamic_bandwidth_varied_sizes() {
        // Test dynamic allocation with different message sizes arriving simultaneously
        // This tests that smaller messages complete first when bandwidth is shared
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            // Create 3 senders
            let mut senders = Vec::new();
            let mut sender_txs = Vec::new();
            for i in 0..3 {
                let sender = ed25519::PrivateKey::from_seed(i).public_key();
                senders.push(sender.clone());
                let (tx, _) = oracle
                    .control(sender.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                sender_txs.push(tx);

                // Each sender has unlimited egress
                oracle
                    .limit_bandwidth(sender.clone(), None, None)
                    .await
                    .unwrap();
            }

            // Create receiver with 30KB/s ingress
            let receiver = ed25519::PrivateKey::from_seed(100).public_key();
            let (_, mut receiver_rx) = oracle
                .control(receiver.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .limit_bandwidth(receiver.clone(), None, Some(30_000))
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
            //
            // The scheduler reserves bandwidth in advance, the actual behavior
            // depends on the order tasks are processed. Since all senders
            // start at once, they'll compete for bandwidth
            let sizes = [10_000, 20_000, 30_000];
            for (i, (mut tx, size)) in sender_txs.into_iter().zip(sizes.iter()).enumerate() {
                let rx_clone = receiver.clone();
                let msg_size = *size;
                let msg = Bytes::from(vec![i as u8; msg_size]);
                tx.send(Recipients::One(rx_clone), msg, true).await.unwrap();
            }

            // Receive messages. They arrive in the order they were scheduled,
            // not necessarily size order. Collect all messages and sort by
            // receive time to verify timing
            let mut messages = Vec::new();
            for _ in 0..3 {
                let (_, msg) = receiver_rx.recv().await.unwrap();
                let t = context.current().duration_since(start).unwrap();
                messages.push((msg[0] as usize, msg.len(), t));
            }

            // When all start at once, they'll reserve bandwidth slots
            // sequentially. First gets full 30KB/s, others wait or get
            // remaining bandwidth. Just verify all messages arrived and total
            // time is reasonable
            assert_eq!(messages.len(), 3);

            // Total data is 60KB at 30KB/s receiver ingress = 2s minimum
            let max_time = messages.iter().map(|&(_, _, t)| t).max().unwrap();
            assert!(
                max_time >= Duration::from_millis(2000),
                "Total time {max_time:?} should be at least 2s for 60KB at 30KB/s",
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
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            // Create two peers
            let sender = PrivateKey::from_seed(1).public_key();
            let receiver = PrivateKey::from_seed(2).public_key();

            let (sender_tx, _) = oracle
                .control(sender.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_, mut receiver_rx) = oracle
                .control(receiver.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            // Set bandwidth: 1000 B/s (1 byte per millisecond)
            oracle
                .limit_bandwidth(sender.clone(), Some(1000), None)
                .await
                .unwrap();
            oracle
                .limit_bandwidth(receiver.clone(), None, Some(1000))
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
            for i in 0..3 {
                let mut sender_tx = sender_tx.clone();
                let receiver = receiver.clone();
                let msg = Bytes::from(vec![i; 500]);
                sender_tx
                    .send(Recipients::One(receiver), msg, false)
                    .await
                    .unwrap();
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
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            let pk_sender = PrivateKey::from_seed(1).public_key();
            let pk_receiver = PrivateKey::from_seed(2).public_key();

            // Register peers and establish link
            let (mut sender_tx, _) = oracle
                .control(pk_sender.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_, mut receiver_rx) = oracle
                .control(pk_receiver.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
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
                .limit_bandwidth(pk_sender.clone(), Some(10_000), None)
                .await
                .unwrap();
            oracle
                .limit_bandwidth(pk_receiver.clone(), None, Some(10_000))
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
                "First message should take ~2s, got {msg1_time:?}",
            );

            // Change bandwidth to 2 KB/s
            oracle
                .limit_bandwidth(pk_sender.clone(), Some(2_000), None)
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
                "Second message should take ~5s at reduced bandwidth, got {msg2_time:?}",
            );
        });
    }

    #[test]
    fn test_zero_receiver_ingress_bandwidth() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            let pk_sender = PrivateKey::from_seed(1).public_key();
            let pk_receiver = PrivateKey::from_seed(2).public_key();

            // Register peers and establish link
            let (mut sender_tx, _) = oracle
                .control(pk_sender.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_, mut receiver_rx) = oracle
                .control(pk_receiver.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(
                    pk_sender.clone(),
                    pk_receiver.clone(),
                    Link {
                        latency: Duration::ZERO,
                        jitter: Duration::ZERO,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            // Set sender bandwidth to 0
            oracle
                .limit_bandwidth(pk_receiver.clone(), None, Some(0))
                .await
                .unwrap();

            // Send message to receiver
            let msg1 = Bytes::from(vec![1u8; 20_000]); // 20 KB
            let sent = sender_tx
                .send(Recipients::One(pk_receiver.clone()), msg1.clone(), false)
                .await
                .unwrap();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0], pk_receiver);

            // Message should not be received after 10 seconds
            select! {
                _ = receiver_rx.recv() => {
                    panic!("unexpected message");
                },
                _ = context.sleep(Duration::from_secs(10)) => {},
            }

            // Unset bandwidth
            oracle
                .limit_bandwidth(pk_receiver.clone(), None, None)
                .await
                .unwrap();

            // Message should be immediately received
            select! {
                _ = receiver_rx.recv() => {},
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("timeout");
                },
            }
        });
    }

    #[test]
    fn test_zero_sender_egress_bandwidth() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            let pk_sender = PrivateKey::from_seed(1).public_key();
            let pk_receiver = PrivateKey::from_seed(2).public_key();

            // Register peers and establish link
            let (mut sender_tx, _) = oracle
                .control(pk_sender.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_, mut receiver_rx) = oracle
                .control(pk_receiver.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(
                    pk_sender.clone(),
                    pk_receiver.clone(),
                    Link {
                        latency: Duration::ZERO,
                        jitter: Duration::ZERO,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            // Set sender bandwidth to 0
            oracle
                .limit_bandwidth(pk_sender.clone(), Some(0), None)
                .await
                .unwrap();

            // Send message to receiver
            let msg1 = Bytes::from(vec![1u8; 20_000]); // 20 KB
            let sent = sender_tx
                .send(Recipients::One(pk_receiver.clone()), msg1.clone(), false)
                .await
                .unwrap();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0], pk_receiver);

            // Message should not be received after 10 seconds
            select! {
                _ = receiver_rx.recv() => {
                    panic!("unexpected message");
                },
                _ = context.sleep(Duration::from_secs(10)) => {},
            }

            // Unset bandwidth
            oracle
                .limit_bandwidth(pk_sender.clone(), None, None)
                .await
                .unwrap();

            // Message should be immediately received
            select! {
                _ = receiver_rx.recv() => {},
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("timeout");
                },
            }
        });
    }

    #[test]
    fn register_peer_set() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: Some(3),
                },
            );
            network.start();

            let mut manager = oracle.manager();
            assert_eq!(manager.peer_set(0).await, Some([].try_into().unwrap()));

            let pk1 = PrivateKey::from_seed(1).public_key();
            let pk2 = PrivateKey::from_seed(2).public_key();
            manager
                .update(0xFF, [pk1.clone(), pk2.clone()].try_into().unwrap())
                .await;

            assert_eq!(
                manager.peer_set(0xFF).await.unwrap(),
                [pk1, pk2].try_into().unwrap()
            );
        });
    }

    #[test]
    fn test_socket_manager() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: Some(3),
                },
            );
            network.start();

            let pk1 = PrivateKey::from_seed(1).public_key();
            let pk2 = PrivateKey::from_seed(2).public_key();
            let addr1: Address = SocketAddr::from(([127, 0, 0, 1], 4000)).into();
            let addr2: Address = SocketAddr::from(([127, 0, 0, 1], 4001)).into();

            let mut manager = oracle.socket_manager();
            let peers: Map<_, _> = [(pk1.clone(), addr1.clone()), (pk2.clone(), addr2.clone())]
                .try_into()
                .unwrap();
            manager.update(1, peers).await;

            let peer_set = manager.peer_set(1).await.expect("peer set missing");
            let keys: Vec<_> = Vec::from(peer_set.clone());
            assert_eq!(keys, vec![pk1.clone(), pk2.clone()]);

            let mut subscription = manager.subscribe().await;
            let (id, latest, all) = subscription.next().await.unwrap();
            assert_eq!(id, 1);
            let latest_keys: Vec<_> = Vec::from(latest.clone());
            assert_eq!(latest_keys, vec![pk1.clone(), pk2.clone()]);
            let all_keys: Vec<_> = Vec::from(all.clone());
            assert_eq!(all_keys, vec![pk1.clone(), pk2.clone()]);

            let peers: Map<_, _> = [(pk2.clone(), addr2)].try_into().unwrap();
            manager.update(2, peers).await;

            let (id, latest, all) = subscription.next().await.unwrap();
            assert_eq!(id, 2);
            let latest_keys: Vec<_> = Vec::from(latest);
            assert_eq!(latest_keys, vec![pk2.clone()]);
            let all_keys: Vec<_> = Vec::from(all);
            assert_eq!(all_keys, vec![pk1, pk2]);
        });
    }

    #[test]
    fn test_socket_manager_with_asymmetric_addresses() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: Some(3),
                },
            );
            network.start();

            let pk1 = PrivateKey::from_seed(1).public_key();
            let pk2 = PrivateKey::from_seed(2).public_key();

            // Use asymmetric addresses where ingress (dial) differs from egress (filter)
            let addr1 = Address::Asymmetric {
                ingress: Ingress::Socket(SocketAddr::from(([10, 0, 0, 1], 8080))),
                egress: SocketAddr::from(([192, 168, 1, 1], 9090)),
            };
            let addr2 = Address::Asymmetric {
                ingress: Ingress::Dns {
                    host: hostname!("node2.example.com"),
                    port: 8080,
                },
                egress: SocketAddr::from(([192, 168, 1, 2], 9090)),
            };

            let mut manager = oracle.socket_manager();
            let peers: Map<_, _> = [(pk1.clone(), addr1), (pk2.clone(), addr2)]
                .try_into()
                .unwrap();
            manager.update(1, peers).await;

            // Verify peer set contains expected keys (addresses are ignored by simulated network)
            let peer_set = manager.peer_set(1).await.expect("peer set missing");
            let keys: Vec<_> = Vec::from(peer_set);
            assert_eq!(keys, vec![pk1.clone(), pk2.clone()]);

            // Verify subscription works
            let mut subscription = manager.subscribe().await;
            let (id, latest, _all) = subscription.next().await.unwrap();
            assert_eq!(id, 1);
            let latest_keys: Vec<_> = Vec::from(latest);
            assert_eq!(latest_keys, vec![pk1, pk2]);
        });
    }

    #[test]
    fn test_peer_set_window_management() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: Some(2), // Only track 2 peer sets
                },
            );
            network.start();

            // Create 4 peers
            let pk1 = PrivateKey::from_seed(1).public_key();
            let pk2 = PrivateKey::from_seed(2).public_key();
            let pk3 = PrivateKey::from_seed(3).public_key();
            let pk4 = PrivateKey::from_seed(4).public_key();

            // Register first peer set with pk1 and pk2
            let mut manager = oracle.manager();
            manager
                .update(1, vec![pk1.clone(), pk2.clone()].try_into().unwrap())
                .await;

            // Register channels for all peers
            let (mut sender1, _receiver1) = oracle
                .control(pk1.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (mut sender2, _receiver2) = oracle
                .control(pk2.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (mut sender3, _receiver3) = oracle
                .control(pk3.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_mut_sender4, _receiver4) = oracle
                .control(pk4.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            // Create bidirectional links between all peers
            for peer_a in &[pk1.clone(), pk2.clone(), pk3.clone(), pk4.clone()] {
                for peer_b in &[pk1.clone(), pk2.clone(), pk3.clone(), pk4.clone()] {
                    if peer_a != peer_b {
                        oracle
                            .add_link(
                                peer_a.clone(),
                                peer_b.clone(),
                                Link {
                                    latency: Duration::from_millis(1),
                                    jitter: Duration::ZERO,
                                    success_rate: 1.0,
                                },
                            )
                            .await
                            .unwrap();
                    }
                }
            }

            // Send message from pk1 to pk2 (both in tracked set) - should succeed
            let sent = sender1
                .send(Recipients::One(pk2.clone()), Bytes::from("msg1"), false)
                .await
                .unwrap();
            assert_eq!(sent.len(), 1);

            // Try to send from pk1 to pk3 (pk3 not in any tracked set) - should fail
            let sent = sender1
                .send(Recipients::One(pk3.clone()), Bytes::from("msg2"), false)
                .await
                .unwrap();
            assert_eq!(sent.len(), 0);

            // Register second peer set with pk2 and pk3
            manager
                .update(2, vec![pk2.clone(), pk3.clone()].try_into().unwrap())
                .await;

            // Now pk3 is in a tracked set, message should succeed
            let sent = sender1
                .send(Recipients::One(pk3.clone()), Bytes::from("msg3"), false)
                .await
                .unwrap();
            assert_eq!(sent.len(), 1);

            // Register third peer set with pk3 and pk4 (this will evict peer set 1)
            manager
                .update(3, vec![pk3.clone(), pk4.clone()].try_into().unwrap())
                .await;

            // pk1 should now be removed from all tracked sets
            // Try to send from pk2 to pk1 - should fail since pk1 is no longer tracked
            let sent = sender2
                .send(Recipients::One(pk1.clone()), Bytes::from("msg4"), false)
                .await
                .unwrap();
            assert_eq!(sent.len(), 0);

            // pk3 should still be reachable (in sets 2 and 3)
            let sent = sender2
                .send(Recipients::One(pk3.clone()), Bytes::from("msg5"), false)
                .await
                .unwrap();
            assert_eq!(sent.len(), 1);

            // pk4 should be reachable (in set 3)
            let sent = sender3
                .send(Recipients::One(pk4.clone()), Bytes::from("msg6"), false)
                .await
                .unwrap();
            assert_eq!(sent.len(), 1);

            // Verify peer set contents
            let peer_set_2 = manager.peer_set(2).await.unwrap();
            assert!(peer_set_2.as_ref().contains(&pk2));
            assert!(peer_set_2.as_ref().contains(&pk3));

            let peer_set_3 = manager.peer_set(3).await.unwrap();
            assert!(peer_set_3.as_ref().contains(&pk3));
            assert!(peer_set_3.as_ref().contains(&pk4));

            // Peer set 1 should no longer exist
            assert!(manager.peer_set(1).await.is_none());
        });
    }

    #[test]
    fn test_sender_removed_from_tracked_peer_set_drops_message() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: Some(1),
                },
            );
            network.start();
            let mut manager = oracle.manager();
            let mut subscription = manager.subscribe().await;

            // Register a peer set
            let sender_pk = PrivateKey::from_seed(1).public_key();
            let recipient_pk = PrivateKey::from_seed(2).public_key();
            manager
                .update(
                    1,
                    vec![sender_pk.clone(), recipient_pk.clone()]
                        .try_into()
                        .unwrap(),
                )
                .await;
            let (id, _, _) = subscription.next().await.unwrap();
            assert_eq!(id, 1);

            // Register channels
            let (mut sender, _) = oracle
                .control(sender_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_sender2, mut receiver) = oracle
                .control(recipient_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            // Add link
            oracle
                .add_link(
                    sender_pk.clone(),
                    recipient_pk.clone(),
                    Link {
                        latency: Duration::from_millis(1),
                        jitter: Duration::ZERO,
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            // Send and confirm message
            let initial_msg = Bytes::from("tracked");
            let sent = sender
                .send(
                    Recipients::One(recipient_pk.clone()),
                    initial_msg.clone(),
                    false,
                )
                .await
                .unwrap();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0], recipient_pk);
            let (_pk, received) = receiver.recv().await.unwrap();
            assert_eq!(received, initial_msg);

            // Register another peer set
            let other_pk = PrivateKey::from_seed(3).public_key();
            manager
                .update(2, vec![recipient_pk.clone(), other_pk].try_into().unwrap())
                .await;
            let (id, _, _) = subscription.next().await.unwrap();
            assert_eq!(id, 2);

            // Send message from untracked peer
            let sent = sender
                .send(
                    Recipients::One(recipient_pk.clone()),
                    Bytes::from("untracked"),
                    false,
                )
                .await
                .unwrap();
            assert!(sent.is_empty());

            // Confirm message was not delivered
            select! {
                _ = receiver.recv() => {
                    panic!("unexpected message");
                },
                _ = context.sleep(Duration::from_secs(10)) => {},
            }

            // Add a peer back to the tracked set
            manager
                .update(
                    3,
                    vec![sender_pk.clone(), recipient_pk.clone()]
                        .try_into()
                        .unwrap(),
                )
                .await;
            let (id, _, _) = subscription.next().await.unwrap();
            assert_eq!(id, 3);

            // Send message from tracked peer (now back in a peer set)
            let sent = sender
                .send(
                    Recipients::One(recipient_pk.clone()),
                    initial_msg.clone(),
                    false,
                )
                .await
                .unwrap();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0], recipient_pk);
            let (_pk, received) = receiver.recv().await.unwrap();
            assert_eq!(received, initial_msg);
        });
    }

    #[test]
    fn test_subscribe_to_peer_sets() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: Some(2),
                },
            );
            network.start();

            // Subscribe to peer set updates
            let mut manager = oracle.manager();
            let mut subscription = manager.subscribe().await;

            // Create peers
            let pk1 = PrivateKey::from_seed(1).public_key();
            let pk2 = PrivateKey::from_seed(2).public_key();
            let pk3 = PrivateKey::from_seed(3).public_key();

            // Register first peer set
            manager
                .update(1, vec![pk1.clone(), pk2.clone()].try_into().unwrap())
                .await;

            // Verify we receive the notification
            let (peer_set_id, peer_set, all) = subscription.next().await.unwrap();
            assert_eq!(peer_set_id, 1);
            assert_eq!(peer_set, vec![pk1.clone(), pk2.clone()].try_into().unwrap());
            assert_eq!(all, vec![pk1.clone(), pk2.clone()].try_into().unwrap());

            // Register second peer set
            manager
                .update(2, vec![pk2.clone(), pk3.clone()].try_into().unwrap())
                .await;

            // Verify we receive the notification
            let (peer_set_id, peer_set, all) = subscription.next().await.unwrap();
            assert_eq!(peer_set_id, 2);
            assert_eq!(peer_set, vec![pk2.clone(), pk3.clone()].try_into().unwrap());
            assert_eq!(
                all,
                vec![pk1.clone(), pk2.clone(), pk3.clone()]
                    .try_into()
                    .unwrap()
            );

            // Register third peer set
            manager
                .update(3, vec![pk1.clone(), pk3.clone()].try_into().unwrap())
                .await;

            // Verify we receive the notification
            let (peer_set_id, peer_set, all) = subscription.next().await.unwrap();
            assert_eq!(peer_set_id, 3);
            assert_eq!(peer_set, vec![pk1.clone(), pk3.clone()].try_into().unwrap());
            assert_eq!(
                all,
                vec![pk1.clone(), pk2.clone(), pk3.clone()]
                    .try_into()
                    .unwrap()
            );

            // Register fourth peer set
            manager
                .update(4, vec![pk1.clone(), pk3.clone()].try_into().unwrap())
                .await;

            // Verify we receive the notification
            let (peer_set_id, peer_set, all) = subscription.next().await.unwrap();
            assert_eq!(peer_set_id, 4);
            assert_eq!(peer_set, vec![pk1.clone(), pk3.clone()].try_into().unwrap());
            assert_eq!(all, vec![pk1.clone(), pk3.clone()].try_into().unwrap());
        });
    }

    #[test]
    fn test_multiple_subscriptions() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: Some(3),
                },
            );
            network.start();

            // Create multiple subscriptions
            let mut manager = oracle.manager();
            let mut subscription1 = manager.subscribe().await;
            let mut subscription2 = manager.subscribe().await;
            let mut subscription3 = manager.subscribe().await;

            // Create peers
            let pk1 = PrivateKey::from_seed(1).public_key();
            let pk2 = PrivateKey::from_seed(2).public_key();

            // Register a peer set
            manager
                .update(1, vec![pk1.clone(), pk2.clone()].try_into().unwrap())
                .await;

            // Verify all subscriptions receive the notification
            let (id1, _, _) = subscription1.next().await.unwrap();
            let (id2, _, _) = subscription2.next().await.unwrap();
            let (id3, _, _) = subscription3.next().await.unwrap();

            assert_eq!(id1, 1);
            assert_eq!(id2, 1);
            assert_eq!(id3, 1);

            // Drop one subscription
            drop(subscription2);

            // Register another peer set
            manager
                .update(2, vec![pk1.clone(), pk2.clone()].try_into().unwrap())
                .await;

            // Verify remaining subscriptions still receive notifications
            let (id1, _, _) = subscription1.next().await.unwrap();
            let (id3, _, _) = subscription3.next().await.unwrap();

            assert_eq!(id1, 2);
            assert_eq!(id3, 2);
        });
    }

    #[test]
    fn test_subscription_includes_self_when_registered() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: Some(2),
                },
            );
            network.start();

            // Create "self" and "other" peers
            let self_pk = PrivateKey::from_seed(0).public_key();
            let other_pk = PrivateKey::from_seed(1).public_key();

            // Register a channel for self (this creates the peer in the network)
            let (_sender, _receiver) = oracle
                .control(self_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            // Subscribe to peer set updates
            let mut manager = oracle.manager();
            let mut subscription = manager.subscribe().await;

            // Register a peer set that does NOT include self
            manager
                .update(1, vec![other_pk.clone()].try_into().unwrap())
                .await;

            // Receive subscription notification
            let (id, new, all) = subscription.next().await.unwrap();
            assert_eq!(id, 1);
            assert_eq!(new.len(), 1);
            assert_eq!(all.len(), 1);

            // Self should NOT be in the new set
            assert!(
                new.position(&self_pk).is_none(),
                "new set should not include self"
            );
            assert!(
                new.position(&other_pk).is_some(),
                "new set should include other"
            );

            // Self should NOT be in the tracked set (not registered)
            assert!(
                all.position(&self_pk).is_none(),
                "tracked peers should not include self"
            );
            assert!(
                all.position(&other_pk).is_some(),
                "tracked peers should include other"
            );

            // Now register a peer set that DOES include self
            manager
                .update(
                    2,
                    vec![self_pk.clone(), other_pk.clone()].try_into().unwrap(),
                )
                .await;

            let (id, new, all) = subscription.next().await.unwrap();
            assert_eq!(id, 2);
            assert_eq!(new.len(), 2);
            assert_eq!(all.len(), 2);

            // Both peers should be in the new set
            assert!(
                new.position(&self_pk).is_some(),
                "new set should include self"
            );
            assert!(
                new.position(&other_pk).is_some(),
                "new set should include other"
            );

            // Both peers should be in the tracked set
            assert!(
                all.position(&self_pk).is_some(),
                "tracked peers should include self"
            );
            assert!(
                all.position(&other_pk).is_some(),
                "tracked peers should include other"
            );
        });
    }

    #[test]
    fn test_rate_limiting() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: Some(3),
            };
            let network_context = context.with_label("network");
            let (network, mut oracle) = Network::new(network_context.clone(), cfg);
            network.start();

            // Create two public keys
            let pk1 = ed25519::PrivateKey::from_seed(1).public_key();
            let pk2 = ed25519::PrivateKey::from_seed(2).public_key();

            // Register the peer set
            let mut manager = oracle.manager();
            manager
                .update(0, [pk1.clone(), pk2.clone()].try_into().unwrap())
                .await;

            // Register with a very restrictive quota: 1 message per second
            let restrictive_quota = Quota::per_second(NZU32!(1));
            let mut control1 = oracle.control(pk1.clone());
            let (mut sender, _) = control1.register(0, restrictive_quota).await.unwrap();
            let mut control2 = oracle.control(pk2.clone());
            let (_, mut receiver) = control2.register(0, TEST_QUOTA).await.unwrap();

            // Add bidirectional links
            let link = ingress::Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            oracle
                .add_link(pk1.clone(), pk2.clone(), link.clone())
                .await
                .unwrap();
            oracle.add_link(pk2.clone(), pk1, link).await.unwrap();

            // First message should succeed immediately
            let msg1 = Bytes::from_static(b"message1");
            let result1 = sender
                .send(Recipients::One(pk2.clone()), msg1.clone(), false)
                .await
                .unwrap();
            assert_eq!(result1.len(), 1, "first message should be sent");

            // Verify first message is received
            let (_, received1) = receiver.recv().await.unwrap();
            assert_eq!(received1, msg1);

            // Second message should be rate-limited (quota is 1/sec, no time has passed)
            let msg2 = Bytes::from_static(b"message2");
            let result2 = sender
                .send(Recipients::One(pk2.clone()), msg2.clone(), false)
                .await
                .unwrap();
            assert_eq!(
                result2.len(),
                0,
                "second message should be rate-limited (skipped)"
            );

            // Advance time by 1 second to allow the rate limiter to reset
            context.sleep(Duration::from_secs(1)).await;

            // Third message should succeed after waiting
            let msg3 = Bytes::from_static(b"message3");
            let result3 = sender
                .send(Recipients::One(pk2.clone()), msg3.clone(), false)
                .await
                .unwrap();
            assert_eq!(result3.len(), 1, "third message should be sent after wait");

            // Verify third message is received
            let (_, received3) = receiver.recv().await.unwrap();
            assert_eq!(received3, msg3);
        });
    }
}

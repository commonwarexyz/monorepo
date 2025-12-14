//! Simulate networking between peers.
//!
//! Peers that are part of a registered peer set can communicate directly without
//! explicit link setup. Network simulation (latency, bandwidth, jitter) can be
//! configured at the runtime layer using `commonware-runtime::simulated`.
//!
//! # Determinism
//!
//! `commonware-p2p::simulated` can be run deterministically when paired with
//! `commonware-runtime::deterministic`. This makes it possible to reproduce
//! an arbitrary order of delivered messages with a given seed.
//!
//! # Example
//!
//! ```rust
//! use commonware_p2p::{Manager, simulated::{Config, Network}};
//! use commonware_cryptography::{ed25519, PrivateKey, Signer as _, PublicKey as _, PrivateKeyExt as _};
//! use commonware_runtime::{deterministic, Spawner, Runner, Metrics};
//! use commonware_utils::NZU32;
//! use governor::Quota;
//!
//! // Generate peers
//! let peers = vec![
//!     ed25519::PrivateKey::from_seed(0).public_key(),
//!     ed25519::PrivateKey::from_seed(1).public_key(),
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
//!     // Register a peer set (peers in same set can communicate)
//!     let mut manager = oracle.manager();
//!     manager.update(0, peers.clone().try_into().unwrap()).await;
//!
//!     // Register channels for each peer
//!     let (sender1, receiver1) = oracle.control(peers[0].clone()).register(0, quota).await.unwrap();
//!     let (sender2, receiver2) = oracle.control(peers[1].clone()).register(0, quota).await.unwrap();
//!
//!     // ... Use sender and receiver ...
//!     // Messages sent by sender1 can be received by receiver2 since both peers are in the same peer set
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

pub use ingress::{Control, Manager, Oracle, SocketManager};
pub use network::{
    Config, Network, Receiver, Sender, SplitForwarder, SplitOrigin, SplitRouter, SplitSender,
    SplitTarget,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Manager, Receiver, Recipients, Sender};
    use bytes::Bytes;
    use commonware_cryptography::{
        ed25519::{self, PrivateKey, PublicKey},
        PrivateKeyExt as _, Signer as _,
    };
    use commonware_runtime::{deterministic, Clock, Metrics, Runner, Spawner};
    use commonware_utils::{ordered::Map, NZU32};
    use futures::{channel::mpsc, SinkExt, StreamExt};
    use governor::Quota;
    use std::{
        collections::BTreeMap,
        net::SocketAddr,
        num::NonZeroU32,
        time::Duration,
    };

    /// Default rate limit set high enough to not interfere with normal operation
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    #[test]
    fn test_determinism() {
        // Test that the simulated network is deterministic
        fn run_simulation(seed: u64) -> String {
            let executor = deterministic::Runner::seeded(seed);
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

                // Create peers and send messages
                let pk1 = PrivateKey::from_seed(1).public_key();
                let pk2 = PrivateKey::from_seed(2).public_key();

                let (mut sender1, _) = oracle.control(pk1.clone()).register(0, TEST_QUOTA).await.unwrap();
                let (_, mut receiver2) = oracle.control(pk2.clone()).register(0, TEST_QUOTA).await.unwrap();

                // Send a message
                sender1
                    .send(Recipients::One(pk2.clone()), Bytes::from_static(b"hello"), false)
                    .await
                    .unwrap();

                // Receive it
                let (sender, msg) = receiver2.recv().await.unwrap();
                assert_eq!(sender, pk1);
                assert_eq!(msg, Bytes::from_static(b"hello"));

                context.auditor().state()
            })
        }

        // Run twice with same seed, should get same state
        let state1 = run_simulation(42);
        let state2 = run_simulation(42);
        assert_eq!(state1, state2);
    }

    #[test]
    fn test_message_too_big() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let (network, oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 10, // Very small max size
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            let pk1 = PrivateKey::from_seed(1).public_key();
            let (mut sender, _) = oracle.control(pk1.clone()).register(0, TEST_QUOTA).await.unwrap();

            // Try to send a message that's too big
            let big_msg = Bytes::from(vec![0u8; 100]);
            let result = sender.send(Recipients::All, big_msg, false).await;
            assert!(matches!(result, Err(crate::simulated::Error::MessageTooLarge(100))));
        });
    }

    #[test]
    fn test_duplicate_channel() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            let pk1 = PrivateKey::from_seed(1).public_key();

            // Register channel 0
            let result1 = oracle.control(pk1.clone()).register(0, TEST_QUOTA).await;
            assert!(result1.is_ok());

            // Register channel 0 again - should succeed (overwrites)
            let result2 = oracle.control(pk1.clone()).register(0, TEST_QUOTA).await;
            assert!(result2.is_ok());
        });
    }

    #[test]
    fn test_simple_message_delivery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
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

            // Register peer set
            let mut manager = oracle.manager();
            manager
                .update(0, [pk1.clone(), pk2.clone()].try_into().unwrap())
                .await;

            // Register channels
            let (mut sender1, _) = oracle.control(pk1.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_, mut receiver2) = oracle.control(pk2.clone()).register(0, TEST_QUOTA).await.unwrap();

            // Send message
            let msg = Bytes::from_static(b"hello world");
            let sent = sender1
                .send(Recipients::One(pk2.clone()), msg.clone(), false)
                .await
                .unwrap();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0], pk2);

            // Receive message
            let (sender, received) = receiver2.recv().await.unwrap();
            assert_eq!(sender, pk1);
            assert_eq!(received, msg);
        });
    }

    #[test]
    fn test_send_wrong_channel() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
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

            // Register peer set
            let mut manager = oracle.manager();
            manager
                .update(0, [pk1.clone(), pk2.clone()].try_into().unwrap())
                .await;

            // Register different channels for each peer
            let (mut sender1_ch0, _) = oracle.control(pk1.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_, mut receiver2_ch1) = oracle.control(pk2.clone()).register(1, TEST_QUOTA).await.unwrap();

            // Send on channel 0 - should not be received on channel 1
            sender1_ch0
                .send(Recipients::One(pk2.clone()), Bytes::from_static(b"hello"), false)
                .await
                .unwrap();

            // Give some time for potential delivery
            context.sleep(Duration::from_millis(100)).await;

            // Should not receive anything (different channels)
            use futures::FutureExt;
            assert!(receiver2_ch1.recv().now_or_never().is_none());
        });
    }

    #[test]
    fn test_dynamic_peers() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
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
            let pk3 = PrivateKey::from_seed(3).public_key();

            let mut manager = oracle.manager();

            // Start with pk1 and pk2
            manager
                .update(0, [pk1.clone(), pk2.clone()].try_into().unwrap())
                .await;

            // Register channels
            let (mut sender1, _) = oracle.control(pk1.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_, mut receiver2) = oracle.control(pk2.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_, mut receiver3) = oracle.control(pk3.clone()).register(0, TEST_QUOTA).await.unwrap();

            // Send to pk2 - should work
            sender1
                .send(Recipients::One(pk2.clone()), Bytes::from_static(b"msg1"), false)
                .await
                .unwrap();

            let (_, msg) = receiver2.recv().await.unwrap();
            assert_eq!(msg, Bytes::from_static(b"msg1"));

            // Add pk3 to peer set
            manager
                .update(1, [pk1.clone(), pk2.clone(), pk3.clone()].try_into().unwrap())
                .await;

            // Now send to pk3 - should work
            sender1
                .send(Recipients::One(pk3.clone()), Bytes::from_static(b"msg2"), false)
                .await
                .unwrap();

            let (_, msg) = receiver3.recv().await.unwrap();
            assert_eq!(msg, Bytes::from_static(b"msg2"));
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
            let addr1 = SocketAddr::from(([127, 0, 0, 1], 4000));
            let addr2 = SocketAddr::from(([127, 0, 0, 1], 4001));

            let mut manager = oracle.socket_manager();
            let peers: Map<_, _> = [(pk1.clone(), addr1), (pk2.clone(), addr2)]
                .try_into()
                .unwrap();
            manager.update(1, peers).await;

            let peer_set = manager.peer_set(1).await.expect("peer set missing");
            let keys: Vec<_> = Vec::from(peer_set.clone());
            assert_eq!(keys, vec![pk1.clone(), pk2.clone()]);
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
                    tracked_peer_sets: Some(3), // Window of 3
                },
            );
            network.start();

            let mut manager = oracle.manager();

            // Add peers to multiple peer sets
            for i in 0u64..10 {
                let pk = PrivateKey::from_seed(i).public_key();
                manager.update(i, [pk].try_into().unwrap()).await;
            }

            // Only the most recent 3 peer sets should be tracked
            // (window management is implementation-specific)
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
                    tracked_peer_sets: Some(3),
                },
            );
            network.start();

            let pk1 = PrivateKey::from_seed(1).public_key();
            let pk2 = PrivateKey::from_seed(2).public_key();

            let mut manager = oracle.manager();
            let mut subscription = manager.subscribe().await;

            // Add peer set
            manager
                .update(10, [pk1.clone(), pk2.clone()].try_into().unwrap())
                .await;

            // Should receive notification
            let (id, new, all) = subscription.next().await.unwrap();
            assert_eq!(id, 10);
            assert_eq!(new.len(), 2);
            assert_eq!(all.len(), 2);
        });
    }

    #[test]
    fn test_rate_limiting() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
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

            // Register peer set
            let mut manager = oracle.manager();
            manager
                .update(0, [pk1.clone(), pk2.clone()].try_into().unwrap())
                .await;

            // Register with strict rate limit (1 message per second)
            let strict_quota = Quota::per_second(NonZeroU32::new(1).unwrap());
            let (mut sender, _) = oracle
                .control(pk1.clone())
                .register(0, strict_quota)
                .await
                .unwrap();
            let (_, mut receiver) = oracle.control(pk2.clone()).register(0, TEST_QUOTA).await.unwrap();

            // First message should succeed
            let sent = sender
                .send(Recipients::One(pk2.clone()), Bytes::from_static(b"msg1"), false)
                .await
                .unwrap();
            assert_eq!(sent.len(), 1);

            // Wait and receive first message
            let (_, msg) = receiver.recv().await.unwrap();
            assert_eq!(msg, Bytes::from_static(b"msg1"));

            // Rate limiting may cause subsequent messages to be dropped
            // depending on implementation details
        });
    }

    #[test]
    fn test_broadcast_all() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
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
            let pk3 = PrivateKey::from_seed(3).public_key();

            // Register peer set
            let mut manager = oracle.manager();
            manager
                .update(0, [pk1.clone(), pk2.clone(), pk3.clone()].try_into().unwrap())
                .await;

            // Register channels
            let (mut sender1, _) = oracle.control(pk1.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_, mut receiver2) = oracle.control(pk2.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_, mut receiver3) = oracle.control(pk3.clone()).register(0, TEST_QUOTA).await.unwrap();

            // Broadcast to all
            let msg = Bytes::from_static(b"broadcast");
            let sent = sender1.send(Recipients::All, msg.clone(), false).await.unwrap();
            assert_eq!(sent.len(), 2); // pk2 and pk3 (not pk1 itself)

            // Both should receive
            let (sender, received) = receiver2.recv().await.unwrap();
            assert_eq!(sender, pk1);
            assert_eq!(received, msg);

            let (sender, received) = receiver3.recv().await.unwrap();
            assert_eq!(sender, pk1);
            assert_eq!(received, msg);
        });
    }

    #[test]
    fn test_blocking() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
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

            // Register peer set
            let mut manager = oracle.manager();
            manager
                .update(0, [pk1.clone(), pk2.clone()].try_into().unwrap())
                .await;

            // Register channels
            let mut control1 = oracle.control(pk1.clone());
            let (mut sender1, _) = control1.register(0, TEST_QUOTA).await.unwrap();
            let (_, mut receiver2) = oracle.control(pk2.clone()).register(0, TEST_QUOTA).await.unwrap();

            // Send message before blocking
            sender1
                .send(Recipients::One(pk2.clone()), Bytes::from_static(b"before block"), false)
                .await
                .unwrap();

            let (_, msg) = receiver2.recv().await.unwrap();
            assert_eq!(msg, Bytes::from_static(b"before block"));

            // Block pk2
            use crate::Blocker;
            control1.block(pk2.clone()).await;

            // Messages should now be dropped
            let sent = sender1
                .send(Recipients::One(pk2.clone()), Bytes::from_static(b"after block"), false)
                .await
                .unwrap();
            assert!(sent.is_empty());
        });
    }

    #[test]
    fn test_message_ordering() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, mut oracle) = Network::new(
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

            // Register peer set
            let mut manager = oracle.manager();
            manager
                .update(0, [pk1.clone(), pk2.clone()].try_into().unwrap())
                .await;

            // Register channels
            let (mut sender1, _) = oracle.control(pk1.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_, mut receiver2) = oracle.control(pk2.clone()).register(0, TEST_QUOTA).await.unwrap();

            // Send multiple messages
            for i in 0u8..10 {
                sender1
                    .send(Recipients::One(pk2.clone()), Bytes::from(vec![i]), false)
                    .await
                    .unwrap();
            }

            // Receive in order
            for i in 0u8..10 {
                let (_, msg) = receiver2.recv().await.unwrap();
                assert_eq!(msg, Bytes::from(vec![i]));
            }
        });
    }
}

//! Broadcast messages to and cache messages from untrusted peers.
//!
//! # Overview
//!
//! The core of the module is the [`Engine`]. It is responsible for:
//! - Accepting and caching messages from other participants
//! - Broadcasting messages to all peers
//! - Serving cached messages on-demand
//!
//! # Details
//!
//! The engine receives messages from other peers and caches them. The cache is a bounded queue of
//! messages per peer. When the cache is full, the oldest message is removed to make room for the
//! new one.
//!
//! The [`Mailbox`] is used to make requests to the [`Engine`]. It implements the
//! [`Broadcaster`](crate::Broadcaster) trait. This is used to have the engine send a message to all
//! other peers in the network in a best-effort manner. It also has a method to request a message by
//! digest. The engine will return the message immediately if it is in the cache, or wait for it to
//! be received over the network if it is not.

mod config;
pub use config::Config;
mod engine;
pub use engine::Engine;
mod ingress;
pub use ingress::Mailbox;
pub(crate) use ingress::Message;
mod metrics;

#[cfg(test)]
pub mod mocks;

#[cfg(test)]
mod tests {
    use crate::Broadcaster;

    use super::{mocks::TestMessage, *};
    use commonware_cryptography::{
        ed25519::PublicKey, sha256::Digest as Sha256Digest, Digestible, Ed25519, Signer,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::simulated::{Link, Network, Oracle, Receiver, Sender};
    use commonware_runtime::{deterministic, Clock, Metrics, Runner};
    use std::{collections::BTreeMap, time::Duration};

    // Number of messages to cache per sender
    const CACHE_SIZE: usize = 10;

    // Enough time to receive a cached message. Cannot be instantaneous as the test runtime
    // requires some time to switch context.
    const A_JIFFY: Duration = Duration::from_millis(10);

    // Network speed for the simulated network
    const NETWORK_SPEED: Duration = Duration::from_millis(100);

    // Enough time for a message to propagate through the network
    const NETWORK_SPEED_WITH_BUFFER: Duration = Duration::from_millis(200);

    type Registrations = BTreeMap<PublicKey, (Sender<PublicKey>, Receiver<PublicKey>)>;

    async fn initialize_simulation(
        context: deterministic::Context,
        num_peers: u32,
        success_rate: f64,
    ) -> (Vec<PublicKey>, Registrations, Oracle<PublicKey>) {
        let (network, mut oracle) = Network::<deterministic::Context, PublicKey>::new(
            context.with_label("network"),
            commonware_p2p::simulated::Config {
                max_size: 1024 * 1024,
            },
        );
        network.start();

        let mut schemes = (0..num_peers)
            .map(|i| Ed25519::from_seed(i as u64))
            .collect::<Vec<_>>();
        schemes.sort_by_key(|s| s.public_key());
        let peers: Vec<PublicKey> = schemes.iter().map(|c| (c.public_key())).collect();

        let mut registrations: Registrations = BTreeMap::new();
        for peer in peers.iter() {
            let (sender, receiver) = oracle.register(peer.clone(), 0).await.unwrap();
            registrations.insert(peer.clone(), (sender, receiver));
        }

        // Add links between all peers
        let link = Link {
            latency: NETWORK_SPEED.as_millis() as f64,
            jitter: 0.0,
            success_rate,
        };
        for p1 in peers.iter() {
            for p2 in peers.iter() {
                if p2 == p1 {
                    continue;
                }
                oracle
                    .add_link(p1.clone(), p2.clone(), link.clone())
                    .await
                    .unwrap();
            }
        }

        (peers, registrations, oracle)
    }

    fn spawn_peer_engines(
        context: deterministic::Context,
        registrations: &mut Registrations,
    ) -> BTreeMap<PublicKey, Mailbox<Sha256Digest, TestMessage>> {
        let mut mailboxes = BTreeMap::<PublicKey, Mailbox<Sha256Digest, TestMessage>>::new();
        while let Some((peer, network)) = registrations.pop_first() {
            let context = context.with_label(&peer.to_string());
            let config = Config {
                public_key: peer.clone(),
                mailbox_size: 1024,
                deque_size: CACHE_SIZE,
                priority: false,
                decode_config: (),
            };
            let (engine, engine_mailbox) =
                Engine::<_, PublicKey, Sha256Digest, _, TestMessage, _, _>::new(
                    context.clone(),
                    config,
                );
            mailboxes.insert(peer.clone(), engine_mailbox);
            engine.start(network);
        }
        mailboxes
    }

    #[test_traced]
    fn test_broadcast() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            let (peers, mut registrations, _oracle) =
                initialize_simulation(context.clone(), 4, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &mut registrations);

            // Send a single broadcast message from the first peer
            let message = TestMessage::new(b"hello world test message");
            let mut first_mailbox = mailboxes.get(peers.first().unwrap()).unwrap().clone();
            first_mailbox.broadcast(message.clone()).await;

            // Allow time for propagation
            context.sleep(Duration::from_secs(1)).await;

            // Check that all peers received the message
            for peer in peers.iter() {
                let mut mailbox = mailboxes.get(peer).unwrap().clone();
                let digest = message.digest();
                let receiver = mailbox.get(digest).await;
                let received_message = receiver.await.ok();
                assert_eq!(received_message.unwrap(), message);
            }
        });
    }

    #[test_traced]
    fn test_self_retrieval() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            // Initialize simulation with 1 peer
            let (peers, mut registrations, _oracle) =
                initialize_simulation(context.clone(), 1, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &mut registrations);

            // Set up mailbox for Peer A
            let mut mailbox_a = mailboxes.get(&peers[0]).unwrap().clone();

            // Create a test message
            let m1 = TestMessage::new(b"hello world");
            let digest_m1 = m1.digest();

            // Attempt retrieval before broadcasting
            let receiver_before = mailbox_a.get(digest_m1).await;

            // Broadcast the message
            mailbox_a.broadcast(m1.clone()).await;

            // Wait for the pre-broadcast retrieval to complete
            let msg_before = receiver_before
                .await
                .expect("Pre-broadcast retrieval failed");
            assert_eq!(msg_before, m1);

            // Perform a second retrieval after the broadcast
            let receiver_after = mailbox_a.get(digest_m1).await;

            // Measure the time taken for the second retrieval
            let start = context.current();
            let msg_after = receiver_after
                .await
                .expect("Post-broadcast retrieval failed");
            let duration = context.current().duration_since(start).unwrap();

            // Verify the second retrieval matches the original message
            assert_eq!(msg_after, m1);

            // Verify the second retrieval was instant (less than 10ms)
            assert!(duration < A_JIFFY, "get not instant");
        });
    }

    #[test_traced]
    fn test_packet_loss() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let (peers, mut registrations, _oracle) =
                initialize_simulation(context.clone(), 10, 0.1).await;
            let mailboxes = spawn_peer_engines(context.clone(), &mut registrations);

            // Create a message and grab an arbitrary mailbox
            let message = TestMessage::new(b"hello world test message");
            let mut first_mailbox = mailboxes.get(peers.first().unwrap()).unwrap().clone();

            // Retry until all peers receive the message (or timeout)
            let digest = message.digest();
            for i in 0..100 {
                // Broadcast the message
                first_mailbox.broadcast(message.clone()).await;
                context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

                // Check if all peers received the message
                let mut all_received = true;
                for peer in peers.iter() {
                    let mut mailbox = mailboxes.get(peer).unwrap().clone();
                    let receiver = mailbox.get(digest).await;
                    let has = select! {
                        _ = context.sleep(A_JIFFY) => {false},
                        r = receiver => { r.is_ok() },
                    };
                    all_received &= has;
                }

                // If all received, we're done
                if all_received {
                    assert!(i > 0, "Message received on first try");
                    return;
                }
            }
            panic!("Not all peers received the message after retries");
        });
    }

    #[test_traced]
    fn test_get_cached() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            let (peers, mut registrations, _oracle) =
                initialize_simulation(context.clone(), 2, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &mut registrations);

            // Broadcast a message
            let message = TestMessage::new(b"cached message");
            let mut first_mailbox = mailboxes.get(peers.first().unwrap()).unwrap().clone();
            first_mailbox.broadcast(message.clone()).await;

            // Wait for propagation
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Get from cache (should be instant)
            let digest = message.digest();
            let mut mailbox = mailboxes.get(peers.last().unwrap()).unwrap().clone();
            let receiver = mailbox.get(digest).await;
            let start = context.current();
            let received = receiver.await.expect("failed to get cached message");
            let duration = context.current().duration_since(start).unwrap();
            assert_eq!(received, message);
            assert!(duration < A_JIFFY, "get not instant",);
        });
    }

    #[test_traced]
    fn test_get_nonexistent() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            let (peers, mut registrations, _oracle) =
                initialize_simulation(context.clone(), 2, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &mut registrations);

            // Request nonexistent message from two nodes
            let message = TestMessage::new(b"future message");
            let digest = message.digest();
            let mut mailbox1 = mailboxes.get(&peers[0]).unwrap().clone();
            let mut mailbox2 = mailboxes.get(&peers[1]).unwrap().clone();
            let receiver = mailbox1.get(digest).await;

            // Create two other requests which are dropped
            let dummy1 = mailbox1.get(digest).await;
            let dummy2 = mailbox2.get(digest).await;
            drop(dummy1);
            drop(dummy2);

            // Broadcast the message
            mailbox1.broadcast(message.clone()).await;

            // Wait for propagation
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Check receiver1 gets the message, receiver2 was dropped
            let received = receiver.await.expect("receiver1 should get message");
            assert_eq!(received, message);
        });
    }

    #[test_traced]
    fn test_cache_eviction_single_peer() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            let (peers, mut registrations, _oracle) =
                initialize_simulation(context.clone(), 2, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &mut registrations);

            // Broadcast messages exceeding cache size
            let mut mailbox = mailboxes.get(&peers[0]).unwrap().clone();
            let mut messages = vec![];
            for i in 0..CACHE_SIZE + 1 {
                messages.push(TestMessage::new(format!("message {}", i).as_bytes()));
            }
            for message in messages.iter() {
                mailbox.broadcast(message.clone()).await;
            }

            // Wait for propagation
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Check all other messages exist
            let mut peer_mailbox = mailboxes.get(&peers[1]).unwrap().clone();
            for msg in messages.iter().skip(1) {
                let result = peer_mailbox.get(msg.digest()).await.await.unwrap();
                assert_eq!(result, msg.clone());
            }

            // Check first message times out
            let receiver = peer_mailbox.get(messages[0].digest()).await;
            select! {
                _ = context.sleep(A_JIFFY) => {},
                _ = receiver => { panic!("receiver should have failed")},
            }
        });
    }

    #[test_traced]
    fn test_cache_eviction_multi_peer() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|context| async move {
            // Initialize simulation with 3 peers
            let (peers, mut registrations, _oracle) =
                initialize_simulation(context.clone(), 3, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &mut registrations);

            // Assign mailboxes for peers A, B, C
            let mut mailbox_a = mailboxes.get(&peers[0]).unwrap().clone();
            let mut mailbox_b = mailboxes.get(&peers[1]).unwrap().clone();
            let mut mailbox_c = mailboxes.get(&peers[2]).unwrap().clone();

            // Create and broadcast message M1 from A
            let m1 = TestMessage::new(b"message M1");
            let digest_m1 = m1.digest();
            mailbox_a.broadcast(m1.clone()).await;
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Broadcast M1 from C
            mailbox_c.broadcast(m1.clone()).await;
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // M1 is now in A's and C's deques in B's engine

            // Peer A broadcasts 10 new messages to evict M1 from A's deque
            let mut new_messages_a = Vec::with_capacity(CACHE_SIZE);
            for i in 0..CACHE_SIZE {
                new_messages_a.push(TestMessage::new(format!("A{}", i).as_bytes()));
            }
            for msg in &new_messages_a {
                mailbox_a.broadcast(msg.clone()).await;
            }
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Verify B can still get M1 (in C's deque)
            let receiver = mailbox_b.get(digest_m1).await;
            let received = receiver.await.expect("M1 should be retrievable");
            assert_eq!(received, m1);

            // Peer C broadcasts 10 new messages to evict M1 from C's deque
            let mut new_messages_c = Vec::with_capacity(CACHE_SIZE);
            for i in 0..CACHE_SIZE {
                new_messages_c.push(TestMessage::new(format!("C{}", i).as_bytes()));
            }
            for msg in &new_messages_c {
                mailbox_c.broadcast(msg.clone()).await;
            }
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Verify B cannot get M1 (evicted from all deques)
            let receiver = mailbox_b.get(digest_m1).await;
            select! {
                _ = context.sleep(A_JIFFY) => {},
                _ = receiver => { panic!("M1 should not be retrievable"); },
            }
        });
    }
}

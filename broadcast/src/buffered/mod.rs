//! Best-effort broadcast to a network.
//!
//! # Design
//!
//! The core of the module is the [`Engine`]. It is responsible for:
//! - Serializing and deserializing messages
//! - Performing best-effort broadcast to all participants in the network
//! - Accepting and caching broadcasts from other participants
//! - Notifying other actors of new broadcasts
//! - Serving cached broadcasts on-demand

use commonware_utils::Array;
use std::future::Future;

mod config;
pub use config::Config;
mod engine;
pub use engine::Engine;
mod ingress;
use ingress::{Mailbox, Message};
mod metrics;

#[cfg(test)]
pub mod mocks;

pub trait Digestible<D: Array>: Clone + Send + Sync + 'static {
    fn digest(&self) -> D;
}

pub trait Serializable: Sized + Clone + Send + Sync + 'static {
    fn serialize(&self) -> Vec<u8>;
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
}

#[derive(Debug)]
pub enum Error {
    DeserializationError,
}

#[cfg(test)]
mod tests {
    use super::{mocks::TestMessage, *};
    use commonware_cryptography::{
        ed25519::PublicKey, sha256::Digest as Sha256Digest, Ed25519, Scheme,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::simulated::{Link, Network, Oracle, Receiver, Sender};
    use commonware_runtime::{
        deterministic::{Context, Executor},
        Clock, Metrics, Runner,
    };
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
        context: Context,
        num_peers: u32,
        success_rate: f64,
    ) -> (Vec<PublicKey>, Registrations, Oracle<PublicKey>) {
        let (network, mut oracle) = Network::<Context, PublicKey>::new(
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
        context: Context,
        registrations: &mut Registrations,
    ) -> BTreeMap<PublicKey, Mailbox<Sha256Digest, TestMessage>> {
        let mut mailboxes = BTreeMap::<PublicKey, Mailbox<Sha256Digest, TestMessage>>::new();
        while let Some((peer, network)) = registrations.pop_first() {
            let context = context.with_label(&peer.to_string());
            let config = Config {
                public_key: peer.clone(),
                mailbox_size: 1024,
                per_sender_cache_size: CACHE_SIZE,
                priority: false,
            };
            let (engine, engine_mailbox) =
                Engine::<_, PublicKey, Sha256Digest, TestMessage, _, _>::new(
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
        let (runner, context, _) = Executor::timed(Duration::from_secs(5));
        runner.start(async move {
            let (peers, mut registrations, _oracle) =
                initialize_simulation(context.clone(), 4, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &mut registrations);

            // Send a single broadcast message from the first peer
            let message = TestMessage::new(b"hello world test message");
            let mut first_mailbox = mailboxes.get(peers.first().unwrap()).unwrap().clone();
            first_mailbox.broadcast(message.clone()).await;

            // Allow time for propagation
            context.sleep(Duration::from_secs(1)).await;

            // Check that all peers can retrieve the message
            for peer in peers.iter() {
                let mut mailbox = mailboxes.get(peer).unwrap().clone();
                let digest = message.digest();
                let receiver = mailbox.retrieve(digest).await;
                let retrieved_message = receiver.await.ok();
                assert_eq!(retrieved_message.unwrap(), message);
            }
        });
    }

    #[test_traced]
    fn test_packet_loss() {
        let (runner, context, _) = Executor::timed(Duration::from_secs(30));
        runner.start(async move {
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
                    let receiver = mailbox.retrieve(digest).await;
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
    fn test_retrieve_cached() {
        let (runner, context, _) = Executor::timed(Duration::from_secs(5));
        runner.start(async move {
            let (peers, mut registrations, _oracle) =
                initialize_simulation(context.clone(), 2, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &mut registrations);

            // Broadcast a message
            let message = TestMessage::new(b"cached message");
            let mut first_mailbox = mailboxes.get(peers.first().unwrap()).unwrap().clone();
            first_mailbox.broadcast(message.clone()).await;

            // Wait for propagation
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Retrieve from cache (should be instant)
            let digest = message.digest();
            let mut mailbox = mailboxes.get(peers.last().unwrap()).unwrap().clone();
            let receiver = mailbox.retrieve(digest).await;
            let start = context.current();
            let retrieved = receiver.await.expect("failed to retrieve cached message");
            let duration = context.current().duration_since(start).unwrap();
            assert_eq!(retrieved, message);
            // "Instant" in the testing runtime uses 1ms to switch context
            assert!(duration < Duration::from_millis(10), "retrieve not instant",);
        });
    }

    #[test_traced]
    fn test_retrieve_nonexistent() {
        let (runner, context, _) = Executor::timed(Duration::from_secs(5));
        runner.start(async move {
            let (peers, mut registrations, _oracle) =
                initialize_simulation(context.clone(), 2, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &mut registrations);

            // Request nonexistent message from two nodes
            let message = TestMessage::new(b"future message");
            let digest = message.digest();
            let mut mailbox1 = mailboxes.get(&peers[0]).unwrap().clone();
            let mut mailbox2 = mailboxes.get(&peers[1]).unwrap().clone();
            let receiver = mailbox1.retrieve(digest).await;

            // Create two other requests which are dropped
            let dummy1 = mailbox1.retrieve(digest).await;
            let dummy2 = mailbox2.retrieve(digest).await;
            drop(dummy1);
            drop(dummy2);

            // Broadcast the message
            mailbox1.broadcast(message.clone()).await;

            // Wait for propagation
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Check receiver1 gets the message, receiver2 was dropped
            let retrieved = receiver.await.expect("receiver1 should get message");
            assert_eq!(retrieved, message);
        });
    }

    #[test_traced]
    fn test_cache_eviction() {
        let (runner, context, _) = Executor::timed(Duration::from_secs(5));
        runner.start(async move {
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
                let result = peer_mailbox.retrieve(msg.digest()).await.await.unwrap();
                assert_eq!(result, msg.clone());
            }

            // Check first message times out
            let receiver = peer_mailbox.retrieve(messages[0].digest()).await;
            select! {
                _ = context.sleep(A_JIFFY) => {},
                _ = receiver => { panic!("receiver should have failed")},
            }
        });
    }
}

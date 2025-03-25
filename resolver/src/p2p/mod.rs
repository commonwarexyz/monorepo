//! Resolve data identified by a fixed-length key by using the P2P network.
//!
//! # Overview
//!
//! The `p2p` module enables resolving data by fixed-length keys in a P2P network. Central to the
//! module is the `peer` actor which manages the fetch-request lifecycle. Its mailbox allows
//! initiation and cancellation of fetch requests via the `Resolver` interface.
//!
//! The peer handles an arbitrarily large number of concurrent fetch requests by sending requests
//! to other peers and processing their responses. It uses [commonware_p2p::utils::requester] to
//! select peers based on performance, retrying with another peer if one fails or provides invalid
//! data. Requests persist until canceled or fulfilled, delivering data to the `Consumer` for
//! verification.
//!
//! The `Consumer` checks data integrity and authenticity (critical in an adversarial environment)
//! and returns `true` if valid, completing the fetch, or `false` to retry.
//!
//! The peer also serves data to other peers, forwarding network requests to the `Producer`. The
//! `Producer` provides data asynchronously (e.g., from storage). If it fails, the peer sends an
//! empty response, prompting the requester to retry elsewhere. Each message between peers contains
//! an ID. Each request is sent with a unique ID, and each response includes the ID of the request
//! it responds to.
//!
//! Lastly, the `Coordinator` manages the set of peers that can be used to fetch data.
//!
//! # Performance Considerations
//!
//! The peer supports arbitrarily many concurrent fetch requests, but resource usage generally
//! depends on the rate-limiting configuration of the `Requester` and of the underlying P2P network.

use bytes::Bytes;
use commonware_utils::Array;
use futures::channel::oneshot;
use std::future::Future;

mod config;
pub use config::Config;
mod engine;
pub use engine::Engine;
mod fetcher;
mod ingress;
pub use ingress::Mailbox;
mod metrics;
mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

#[cfg(test)]
pub mod mocks;

/// Serves data requested by the network.
pub trait Producer: Clone + Send + 'static {
    /// Type used to uniquely identify data.
    type Key: Array;

    /// Serve a request received from the network.
    fn produce(&mut self, key: Self::Key) -> impl Future<Output = oneshot::Receiver<Bytes>> + Send;
}

/// Manages the set of peers that can be used to fetch data.
pub trait Coordinator: Clone + Send + Sync + 'static {
    /// Type used to uniquely identify peers.
    type PublicKey: Array;

    /// Returns the current list of peers that can be used to fetch data.
    ///
    /// This is also used to filter requests from peers.
    fn peers(&self) -> &Vec<Self::PublicKey>;

    /// Returns an identifier for the peer set.
    ///
    /// Used as a low-overhead way to check if the list of peers has changed, this value must change
    /// to a novel value whenever the list of peers changes. For example, it could be an
    /// incrementing counter, or an epoch.
    fn peer_set_id(&self) -> u64;
}

#[cfg(test)]
mod tests {
    use super::{
        mocks::{Consumer, Coordinator, CoordinatorMsg, Event, Key, Producer},
        Config, Engine, Mailbox,
    };
    use crate::Resolver;
    use bytes::Bytes;
    use commonware_cryptography::{ed25519::PublicKey, Ed25519, Signer};
    use commonware_macros::{select, test_traced};
    use commonware_p2p::simulated::{Link, Network, Oracle, Receiver, Sender};
    use commonware_runtime::deterministic::{Context, Executor};
    use commonware_runtime::{Clock, Metrics, Runner};
    use futures::{SinkExt, StreamExt};
    use std::time::Duration;

    const MAILBOX_SIZE: usize = 1024;
    const RATE_LIMIT: u32 = 10;
    const INITIAL_DURATION: Duration = Duration::from_millis(100);
    const TIMEOUT: Duration = Duration::from_millis(400);
    const FETCH_RETRY_TIMEOUT: Duration = Duration::from_millis(100);
    const LINK: Link = Link {
        latency: 10.0,
        jitter: 1.0,
        success_rate: 1.0,
    };
    const LINK_UNRELIABLE: Link = Link {
        latency: 10.0,
        jitter: 1.0,
        success_rate: 0.5,
    };

    async fn setup_network_and_peers(
        context: &Context,
        peer_seeds: &[u64],
    ) -> (
        Oracle<PublicKey>,
        Vec<Ed25519>,
        Vec<PublicKey>,
        Vec<(Sender<PublicKey>, Receiver<PublicKey>)>,
    ) {
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            commonware_p2p::simulated::Config {
                max_size: 1024 * 1024,
            },
        );
        network.start();

        let schemes: Vec<Ed25519> = peer_seeds
            .iter()
            .map(|seed| Ed25519::from_seed(*seed))
            .collect();
        let peers: Vec<PublicKey> = schemes.iter().map(|s| s.public_key()).collect();

        let mut connections = Vec::new();
        for peer in &peers {
            let (sender, receiver) = oracle.register(peer.clone(), 0).await.unwrap();
            connections.push((sender, receiver));
        }

        (oracle, schemes, peers, connections)
    }

    async fn add_link(
        oracle: &mut Oracle<PublicKey>,
        link: Link,
        peers: &[PublicKey],
        from: usize,
        to: usize,
    ) {
        oracle
            .add_link(peers[from].clone(), peers[to].clone(), link.clone())
            .await
            .unwrap();
        oracle
            .add_link(peers[to].clone(), peers[from].clone(), link)
            .await
            .unwrap();
    }

    async fn setup_and_spawn_actor(
        context: &Context,
        coordinator: &Coordinator<PublicKey>,
        scheme: Ed25519,
        connection: (Sender<PublicKey>, Receiver<PublicKey>),
        consumer: Consumer<Key, Bytes>,
        producer: Producer<Key, Bytes>,
    ) -> Mailbox<Key> {
        let (engine, mailbox) = Engine::new(
            context.with_label(&format!("actor_{}", scheme.public_key())),
            Config {
                coordinator: coordinator.clone(),
                consumer,
                producer,
                mailbox_size: MAILBOX_SIZE,
                requester_config: commonware_p2p::utils::requester::Config {
                    public_key: scheme.public_key(),
                    rate_limit: governor::Quota::per_second(
                        std::num::NonZeroU32::new(RATE_LIMIT).unwrap(),
                    ),
                    initial: INITIAL_DURATION,
                    timeout: TIMEOUT,
                },
                fetch_retry_timeout: FETCH_RETRY_TIMEOUT,
                priority_requests: false,
                priority_responses: false,
            },
        );
        engine.start(connection);

        mailbox
    }

    /// Tests that fetching a key from another peer succeeds when data is available.
    /// This test sets up two peers, where Peer 1 requests data that Peer 2 has,
    /// and verifies that the data is correctly delivered to Peer 1's consumer.
    #[test_traced]
    fn test_fetch_success() {
        let (executor, context, _) = Executor::timed(Duration::from_secs(10));
        executor.start(async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(2);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 2"));

            let coordinator = Coordinator::new(peers);
            let (cons1, mut cons_out1) = Consumer::new();

            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                &coordinator,
                schemes.remove(0),
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            let _mailbox2 = setup_and_spawn_actor(
                &context,
                &coordinator,
                schemes.remove(0),
                connections.remove(0),
                Consumer::dummy(),
                prod2,
            )
            .await;

            mailbox1.fetch(key.clone()).await;

            let event = cons_out1.next().await.unwrap();
            match event {
                Event::Success(key_actual, value) => {
                    assert_eq!(key_actual, key);
                    assert_eq!(value, Bytes::from("data for key 2"));
                }
                Event::Failed(_) => panic!("Fetch failed unexpectedly"),
            }
        });
    }

    /// Tests that canceling a fetch request results in a failure event.
    /// This test initiates a fetch request and immediately cancels it,
    /// verifying that the consumer receives a failure notification instead of data.
    #[test_traced]
    fn test_cancel_fetch() {
        let (executor, context, _) = Executor::timed(Duration::from_secs(10));
        executor.start(async move {
            let (_oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1]).await;

            let coordinator = Coordinator::new(peers);
            let (cons1, mut cons_out1) = Consumer::new();
            let prod1 = Producer::default();

            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                &coordinator,
                schemes.remove(0),
                connections.remove(0),
                cons1,
                prod1,
            )
            .await;

            let key = Key(3);
            mailbox1.fetch(key.clone()).await;
            mailbox1.cancel(key.clone()).await;

            let event = cons_out1.next().await.unwrap();
            match event {
                Event::Failed(key_actual) => {
                    assert_eq!(key_actual, key);
                }
                Event::Success(_, _) => panic!("Fetch should have been canceled"),
            }
        });
    }

    /// Tests fetching data from a peer when some peers lack the data.
    /// This test sets up three peers, where Peer 1 requests data that only Peer 3 has.
    /// It verifies that the resolver retries with another peer and successfully
    /// delivers the data to Peer 1's consumer.
    #[test_traced]
    fn test_peer_no_data() {
        let (executor, context, _) = Executor::timed(Duration::from_secs(10));
        executor.start(async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;

            let prod1 = Producer::default();
            let prod2 = Producer::default();
            let mut prod3 = Producer::default();
            let key = Key(3);
            prod3.insert(key.clone(), Bytes::from("data for key 3"));

            let coordinator = Coordinator::new(peers);
            let (cons1, mut cons_out1) = Consumer::new();

            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                &coordinator,
                schemes.remove(0),
                connections.remove(0),
                cons1,
                prod1,
            )
            .await;

            let _mailbox2 = setup_and_spawn_actor(
                &context,
                &coordinator,
                schemes.remove(0),
                connections.remove(0),
                Consumer::dummy(),
                prod2,
            )
            .await;

            let _mailbox3 = setup_and_spawn_actor(
                &context,
                &coordinator,
                schemes.remove(0),
                connections.remove(0),
                Consumer::dummy(),
                prod3,
            )
            .await;

            mailbox1.fetch(key.clone()).await;

            let event = cons_out1.next().await.unwrap();
            match event {
                Event::Success(key_actual, value) => {
                    assert_eq!(key_actual, key);
                    assert_eq!(value, Bytes::from("data for key 3"));
                }
                Event::Failed(_) => panic!("Fetch failed unexpectedly"),
            }
        });
    }

    /// Tests fetching when no peers are available.
    /// This test sets up a single peer with an empty coordinator (no peers).
    /// It initiates a fetch, waits beyond the retry timeout, cancels the fetch,
    /// and verifies that the consumer receives a failure notification.
    #[test_traced]
    fn test_no_peers_available() {
        let (executor, context, _) = Executor::timed(Duration::from_secs(10));
        executor.start(async move {
            let (_oracle, mut schemes, _peers, mut connections) =
                setup_network_and_peers(&context, &[1]).await;

            let coordinator = Coordinator::new(vec![]);
            let (cons1, mut cons_out1) = Consumer::new();
            let prod1 = Producer::default();

            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                &coordinator,
                schemes.remove(0),
                connections.remove(0),
                cons1,
                prod1,
            )
            .await;

            let key = Key(4);
            mailbox1.fetch(key.clone()).await;
            context.sleep(Duration::from_secs(5)).await;
            mailbox1.cancel(key.clone()).await;

            let event = cons_out1.next().await.expect("Consumer channel closed");
            match event {
                Event::Failed(key_actual) => {
                    assert_eq!(key_actual, key);
                }
                Event::Success(_, _) => {
                    panic!("Fetch should have failed due to no peers")
                }
            }
        });
    }

    /// Tests that concurrent fetch requests are handled correctly.
    /// Also tests that the peer can recover from having no peers available.
    /// Also tests that the peer can get data from multiple peers that have different sets of data.
    #[test_traced]
    fn test_concurrent_fetch_requests() {
        let (executor, context, _) = Executor::timed(Duration::from_secs(60));
        executor.start(async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3]).await;

            let key2 = Key(2);
            let key3 = Key(3);
            let mut prod2 = Producer::default();
            prod2.insert(key2.clone(), Bytes::from("data for key 2"));
            let mut prod3 = Producer::default();
            prod3.insert(key3.clone(), Bytes::from("data for key 3"));

            let coordinator = Coordinator::new(peers.clone());
            let (cons1, mut cons_out1) = Consumer::new();

            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                &coordinator,
                schemes.remove(0),
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            let _mailbox2 = setup_and_spawn_actor(
                &context,
                &coordinator,
                schemes.remove(0),
                connections.remove(0),
                Consumer::dummy(),
                prod2,
            )
            .await;

            let _mailbox3 = setup_and_spawn_actor(
                &context,
                &coordinator,
                schemes.remove(0),
                connections.remove(0),
                Consumer::dummy(),
                prod3,
            )
            .await;

            // Add choppy links between the requester and the two producers
            add_link(&mut oracle, LINK_UNRELIABLE.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK_UNRELIABLE.clone(), &peers, 0, 2).await;

            // Run the fetches multiple times to ensure that the peer tries both of its peers
            for _ in 0..10 {
                // Initiate concurrent fetch requests
                mailbox1.fetch(key2.clone()).await;
                mailbox1.fetch(key3.clone()).await;

                // Collect both events without assuming order
                let mut events = Vec::new();
                events.push(cons_out1.next().await.expect("Consumer channel closed"));
                events.push(cons_out1.next().await.expect("Consumer channel closed"));

                // Check that both keys were successfully fetched
                let mut found_key2 = false;
                let mut found_key3 = false;
                for event in events {
                    match event {
                        Event::Success(key_actual, value) => {
                            if key_actual == key2 {
                                assert_eq!(value, Bytes::from("data for key 2"));
                                found_key2 = true;
                            } else if key_actual == key3 {
                                assert_eq!(value, Bytes::from("data for key 3"));
                                found_key3 = true;
                            } else {
                                panic!("Unexpected key received");
                            }
                        }
                        Event::Failed(_) => panic!("Fetch failed unexpectedly"),
                    }
                }
                assert!(found_key2 && found_key3,);
            }
        });
    }

    /// Tests that canceling an inactive fetch request has no effect.
    /// Cancels a request before, after, and during the fetch process,
    #[test_traced]
    fn test_cancel() {
        let (executor, context, _) = Executor::timed(Duration::from_secs(10));
        executor.start(async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(6);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 6"));

            let coordinator = Coordinator::new(peers);
            let (cons1, mut cons_out1) = Consumer::new();

            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                &coordinator,
                schemes.remove(0),
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            let _mailbox2 = setup_and_spawn_actor(
                &context,
                &coordinator,
                schemes.remove(0),
                connections.remove(0),
                Consumer::dummy(),
                prod2,
            )
            .await;

            // Cancel before sending the fetch request, expecting no effect
            mailbox1.cancel(key.clone()).await;
            select! {
                _ = cons_out1.next() => { panic!("unexpected event"); },
                _ = context.sleep(Duration::from_millis(100)) => {},
            };

            // Initiate fetch and wait for data to be delivered
            mailbox1.fetch(key.clone()).await;
            let event = cons_out1.next().await.unwrap();
            match event {
                Event::Success(key_actual, value) => {
                    assert_eq!(key_actual, key);
                    assert_eq!(value, Bytes::from("data for key 6"));
                }
                Event::Failed(_) => panic!("Fetch failed unexpectedly"),
            }

            // Attempt to cancel after data has been delivered, expecting no effect
            mailbox1.cancel(key.clone()).await;
            select! {
                _ = cons_out1.next() => { panic!("unexpected event"); },
                _ = context.sleep(Duration::from_millis(100)) => {},
            };

            // Initiate and cancel another fetch request
            let key = Key(7);
            mailbox1.fetch(key.clone()).await;
            mailbox1.cancel(key.clone()).await;

            // Make sure we receive a failure event
            let event = cons_out1.next().await.unwrap();
            match event {
                Event::Failed(key_actual) => {
                    assert_eq!(key_actual, key);
                }
                Event::Success(_, _) => panic!("Fetch should have been canceled"),
            }
        });
    }

    /// Tests that a peer is blocked after delivering invalid data,
    /// preventing further fetches from that peer.
    #[test_traced]
    fn test_blocking_peer() {
        let (executor, context, _) = Executor::timed(Duration::from_secs(10));
        executor.start(async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;
            add_link(&mut oracle, LINK.clone(), &peers, 1, 2).await;

            let key_a = Key(1);
            let key_b = Key(2);
            let invalid_data_a = Bytes::from("invalid for A");
            let valid_data_a = Bytes::from("valid for A");
            let valid_data_b = Bytes::from("valid for B");

            // Set up producers
            let mut prod2 = Producer::default();
            prod2.insert(key_a.clone(), invalid_data_a.clone());
            prod2.insert(key_b.clone(), valid_data_b.clone());

            let mut prod3 = Producer::default();
            prod3.insert(key_a.clone(), valid_data_a.clone());

            // Set up coordinators
            let coordinator1 = Coordinator::new(vec![peers[1].clone(), peers[2].clone()]);
            let coordinator2 = Coordinator::new(vec![peers[0].clone()]);
            let coordinator3 = Coordinator::new(vec![peers[0].clone()]);

            // Set up consumer for Peer1 with expected values
            let (mut cons1, mut cons_out1) = Consumer::new();
            cons1.add_expected(key_a.clone(), valid_data_a.clone());
            cons1.add_expected(key_b.clone(), valid_data_b.clone());

            // Spawn actors
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                &coordinator1,
                schemes.remove(0),
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            let _mailbox2 = setup_and_spawn_actor(
                &context,
                &coordinator2,
                schemes.remove(0),
                connections.remove(0),
                Consumer::dummy(),
                prod2,
            )
            .await;

            let _mailbox3 = setup_and_spawn_actor(
                &context,
                &coordinator3,
                schemes.remove(0),
                connections.remove(0),
                Consumer::dummy(),
                prod3,
            )
            .await;

            // Fetch keyA multiple times to ensure that Peer2 is blocked.
            for _ in 0..10 {
                // Fetch keyA
                mailbox1.fetch(key_a.clone()).await;

                // Wait for success event for keyA
                let event = cons_out1.next().await.unwrap();
                match event {
                    Event::Success(key_actual, value) => {
                        assert_eq!(key_actual, key_a);
                        assert_eq!(value, valid_data_a);
                    }
                    Event::Failed(_) => panic!("Fetch failed unexpectedly"),
                }
            }

            // Fetch keyB
            mailbox1.fetch(key_b.clone()).await;

            // Wait for some time (longer than retry timeout)
            context.sleep(Duration::from_secs(5)).await;

            // Cancel the fetch for keyB
            mailbox1.cancel(key_b.clone()).await;

            // Wait for failure event for keyB
            let event = cons_out1.next().await.unwrap();
            match event {
                Event::Failed(key_actual) => {
                    assert_eq!(key_actual, key_b);
                }
                Event::Success(_, _) => panic!("Fetch should have been canceled"),
            }
        });
    }

    /// Tests that duplicate fetch requests for the same key are handled properly.
    /// The test verifies that when the same key is requested multiple times,
    /// the data is correctly delivered once without errors.
    #[test_traced]
    fn test_duplicate_fetch_request() {
        let (executor, context, _) = Executor::timed(Duration::from_secs(10));
        executor.start(async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(5);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 5"));

            let coordinator = Coordinator::new(peers);
            let (cons1, mut cons_out1) = Consumer::new();

            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                &coordinator,
                schemes.remove(0),
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            let _mailbox2 = setup_and_spawn_actor(
                &context,
                &coordinator,
                schemes.remove(0),
                connections.remove(0),
                Consumer::dummy(),
                prod2,
            )
            .await;

            // Send duplicate fetch requests for the same key
            mailbox1.fetch(key.clone()).await;
            mailbox1.fetch(key.clone()).await;

            // Should receive the data only once
            let event = cons_out1.next().await.unwrap();
            match event {
                Event::Success(key_actual, value) => {
                    assert_eq!(key_actual, key);
                    assert_eq!(value, Bytes::from("data for key 5"));
                }
                Event::Failed(_) => panic!("Fetch failed unexpectedly"),
            }

            // Make sure we don't receive a second event for the duplicate fetch
            select! {
                _ = cons_out1.next() => {
                    panic!("Unexpected second event received for duplicate fetch");
                },
                _ = context.sleep(Duration::from_millis(500)) => {
                    // This is expected - no additional events should be produced
                },
            };
        });
    }

    /// Tests that changing peer sets is handled correctly using the update channel.
    /// This test verifies that when the peer set changes from peer A to peer B,
    /// the resolver correctly adapts and fetches from the new peer.
    #[test_traced]
    fn test_changing_peer_sets() {
        let (executor, context, _) = Executor::timed(Duration::from_secs(10));
        executor.start(async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;

            let key1 = Key(1);
            let key2 = Key(2);

            let mut prod2 = Producer::default();
            prod2.insert(key1.clone(), Bytes::from("data from peer 2"));

            let mut prod3 = Producer::default();
            prod3.insert(key2.clone(), Bytes::from("data from peer 3"));

            // Create a coordinator with initial peer 2
            let coordinator = Coordinator::new(vec![peers[1].clone()]);

            // Create an update channel for the coordinator
            let mut update_sender = coordinator.create_update_channel(context.clone());

            let (cons1, mut cons_out1) = Consumer::new();

            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                &coordinator,
                schemes.remove(0),
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            let _mailbox2 = setup_and_spawn_actor(
                &context,
                &Coordinator::new(vec![peers[0].clone()]),
                schemes.remove(0),
                connections.remove(0),
                Consumer::dummy(),
                prod2,
            )
            .await;

            let _mailbox3 = setup_and_spawn_actor(
                &context,
                &Coordinator::new(vec![peers[0].clone()]),
                schemes.remove(0),
                connections.remove(0),
                Consumer::dummy(),
                prod3,
            )
            .await;

            // Fetch key1 from peer 2
            mailbox1.fetch(key1.clone()).await;

            // Wait for successful fetch
            let event = cons_out1.next().await.unwrap();
            match event {
                Event::Success(key_actual, value) => {
                    assert_eq!(key_actual, key1);
                    assert_eq!(value, Bytes::from("data from peer 2"));
                }
                Event::Failed(_) => panic!("Fetch failed unexpectedly"),
            }

            // Change peer set to only include peer 3 via the update channel
            update_sender
                .send(CoordinatorMsg::UpdatePeers(vec![peers[2].clone()]))
                .await
                .expect("Failed to send update");

            // Need to wait for the peer set change to propagate
            context.sleep(Duration::from_millis(200)).await;

            // Fetch key2 from peer 3
            mailbox1.fetch(key2.clone()).await;

            // Wait for successful fetch
            let event = cons_out1.next().await.unwrap();
            match event {
                Event::Success(key_actual, value) => {
                    assert_eq!(key_actual, key2);
                    assert_eq!(value, Bytes::from("data from peer 3"));
                }
                Event::Failed(_) => panic!("Fetch failed unexpectedly"),
            }
        });
    }
}

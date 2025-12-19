//! Resolve data identified by a fixed-length key by using the P2P network.
//!
//! # Overview
//!
//! The `p2p` module enables resolving data by fixed-length keys in a P2P network. Central to the
//! module is the `peer` actor which manages the fetch-request lifecycle. Its mailbox allows
//! initiation and cancellation of fetch requests via the `Resolver` interface.
//!
//! The peer handles an arbitrarily large number of concurrent fetch requests by sending requests
//! to other peers and processing their responses. It selects peers based on performance, retrying
//! with another peer if one fails or provides invalid data. Requests persist until canceled or
//! fulfilled, delivering data to the `Consumer` for verification.
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
//! # Targeting
//!
//! Callers can restrict fetches to specific target peers using [`Mailbox::fetch_targeted`]. Only
//! target peers are tried, there is no automatic fallback to other peers. Targets persist through
//! transient failures (timeout, "no data" response, send failure) since the peer might be slow or
//! receive the data later.
//!
//! While a fetch is in progress, callers can modify targeting:
//! - [`Mailbox::fetch_targeted`] adds peers to the existing target set
//! - [`Resolver::fetch`](crate::Resolver::fetch) clears all targets, allowing fallback to any peer
//!
//! These modifications only apply to in-progress fetches. Once a fetch completes (success, cancel,
//! or blocked peer), the targets for that key are cleared automatically.
//!
//! # Performance Considerations
//!
//! The peer supports arbitrarily many concurrent fetch requests, but resource usage generally
//! depends on the rate-limiting configuration of the underlying P2P network.

use bytes::Bytes;
use commonware_utils::Span;
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
mod wire;

#[cfg(feature = "mocks")]
pub mod mocks;

/// Serves data requested by the network.
pub trait Producer: Clone + Send + 'static {
    /// Type used to uniquely identify data.
    type Key: Span;

    /// Serve a request received from the network.
    fn produce(&mut self, key: Self::Key) -> impl Future<Output = oneshot::Receiver<Bytes>> + Send;
}

#[cfg(test)]
mod tests {
    use super::{
        mocks::{Consumer, Event, Key, Producer},
        Config, Engine, Mailbox,
    };
    use crate::Resolver;
    use bytes::Bytes;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Signer,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::{
        simulated::{Link, Network, Oracle, Receiver, Sender},
        Blocker, Manager,
    };
    use commonware_runtime::{deterministic, Clock, Metrics, Quota, Runner};
    use commonware_utils::{non_empty_vec, NZU32};
    use futures::StreamExt;
    use std::{collections::HashMap, num::NonZeroU32, time::Duration};

    const MAILBOX_SIZE: usize = 1024;
    const RATE_LIMIT: NonZeroU32 = NZU32!(10);
    const INITIAL_DURATION: Duration = Duration::from_millis(100);
    const TIMEOUT: Duration = Duration::from_millis(400);
    const FETCH_RETRY_TIMEOUT: Duration = Duration::from_millis(100);
    const LINK: Link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };
    const LINK_UNRELIABLE: Link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 0.5,
    };

    async fn setup_network_and_peers(
        context: &deterministic::Context,
        peer_seeds: &[u64],
    ) -> (
        Oracle<PublicKey, deterministic::Context>,
        Vec<PrivateKey>,
        Vec<PublicKey>,
        Vec<(
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        )>,
    ) {
        setup_network_and_peers_with_rate_limit(context, peer_seeds, Quota::per_second(RATE_LIMIT))
            .await
    }

    async fn setup_network_and_peers_with_rate_limit(
        context: &deterministic::Context,
        peer_seeds: &[u64],
        rate_limit: Quota,
    ) -> (
        Oracle<PublicKey, deterministic::Context>,
        Vec<PrivateKey>,
        Vec<PublicKey>,
        Vec<(
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        )>,
    ) {
        let (network, oracle) = Network::new(
            context.with_label("network"),
            commonware_p2p::simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: Some(3),
            },
        );
        network.start();

        let schemes: Vec<PrivateKey> = peer_seeds
            .iter()
            .map(|seed| PrivateKey::from_seed(*seed))
            .collect();
        let peers: Vec<PublicKey> = schemes.iter().map(|s| s.public_key()).collect();
        let mut manager = oracle.manager();
        manager.update(0, peers.clone().try_into().unwrap()).await;

        let mut connections = Vec::new();
        for peer in &peers {
            let (sender, receiver) = oracle
                .control(peer.clone())
                .register(0, rate_limit)
                .await
                .unwrap();
            connections.push((sender, receiver));
        }

        (oracle, schemes, peers, connections)
    }

    async fn add_link(
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
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
        context: &deterministic::Context,
        manager: impl Manager<PublicKey = PublicKey>,
        blocker: impl Blocker<PublicKey = PublicKey>,
        signer: impl Signer<PublicKey = PublicKey>,
        connection: (
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        ),
        consumer: Consumer<Key, Bytes>,
        producer: Producer<Key, Bytes>,
    ) -> Mailbox<Key, PublicKey> {
        let public_key = signer.public_key();
        let (engine, mailbox) = Engine::new(
            context.with_label(&format!("actor_{public_key}")),
            Config {
                manager,
                blocker,
                consumer,
                producer,
                mailbox_size: MAILBOX_SIZE,
                me: Some(public_key),
                initial: INITIAL_DURATION,
                timeout: TIMEOUT,
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
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(2);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 2"));

            let (cons1, mut cons_out1) = Consumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
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
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (oracle, mut schemes, _peers, mut connections) =
                setup_network_and_peers(&context, &[1]).await;

            let (cons1, mut cons_out1) = Consumer::new();
            let prod1 = Producer::default();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
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
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;

            let prod1 = Producer::default();
            let prod2 = Producer::default();
            let mut prod3 = Producer::default();
            let key = Key(3);
            prod3.insert(key.clone(), Bytes::from("data for key 3"));

            let (cons1, mut cons_out1) = Consumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                prod1,
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                prod2,
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
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
    /// This test sets up a single peer with an empty peer provider (no peers).
    /// It initiates a fetch, waits beyond the retry timeout, cancels the fetch,
    /// and verifies that the consumer receives a failure notification.
    #[test_traced]
    fn test_no_peers_available() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (oracle, mut schemes, _peers, mut connections) =
                setup_network_and_peers(&context, &[1]).await;

            let (cons1, mut cons_out1) = Consumer::new();
            let prod1 = Producer::default();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
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
        let executor = deterministic::Runner::timed(Duration::from_secs(60));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3]).await;

            let key2 = Key(2);
            let key3 = Key(3);
            let mut prod2 = Producer::default();
            prod2.insert(key2.clone(), Bytes::from("data for key 2"));
            let mut prod3 = Producer::default();
            prod3.insert(key3.clone(), Bytes::from("data for key 3"));

            let (cons1, mut cons_out1) = Consumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                prod2,
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
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
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(6);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 6"));

            let (cons1, mut cons_out1) = Consumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
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
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
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

            // Set up consumer for Peer1 with expected values
            let (mut cons1, mut cons_out1) = Consumer::new();
            cons1.add_expected(key_a.clone(), valid_data_a.clone());
            cons1.add_expected(key_b.clone(), valid_data_b.clone());

            // Spawn actors
            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                prod2,
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                prod3,
            )
            .await;

            // Fetch keyA multiple times to ensure that Peer2 is blocked.
            for _ in 0..20 {
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

            // Check oracle
            let blocked = oracle.blocked().await.unwrap();
            assert_eq!(blocked.len(), 1);
            assert_eq!(blocked[0].0, peers[0]);
            assert_eq!(blocked[0].1, peers[1]);
        });
    }

    /// Tests that duplicate fetch requests for the same key are handled properly.
    /// The test verifies that when the same key is requested multiple times,
    /// the data is correctly delivered once without errors.
    #[test_traced]
    fn test_duplicate_fetch_request() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(5);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 5"));

            let (cons1, mut cons_out1) = Consumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
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
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
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

            let (cons1, mut cons_out1) = Consumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                prod2,
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

            // Change peer set to include peer 3
            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                prod3,
            )
            .await;

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

    #[test_traced]
    fn test_fetch_targeted() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;

            let key = Key(1);
            let invalid_data = Bytes::from("invalid data");
            let valid_data = Bytes::from("valid data");

            // Peer 2 has invalid data, peer 3 has valid data
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), invalid_data.clone());

            let mut prod3 = Producer::default();
            prod3.insert(key.clone(), valid_data.clone());

            // Consumer expects only valid_data
            let (mut cons1, mut cons_out1) = Consumer::new();
            cons1.add_expected(key.clone(), valid_data.clone());

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                prod2,
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                prod3,
            )
            .await;

            // Wait for peer set to be established
            context.sleep(Duration::from_millis(100)).await;

            // Start fetch with targets for both peer 2 (invalid data) and peer 3 (valid data)
            // When peer 2 returns invalid data, only peer 2 should be removed from targets
            // Peer 3 should still be tried as a target and succeed
            mailbox1
                .fetch_targeted(
                    key.clone(),
                    non_empty_vec![peers[1].clone(), peers[2].clone()],
                )
                .await;

            // Should eventually succeed from peer 3
            let event = cons_out1.next().await.unwrap();
            match event {
                Event::Success(key_actual, value) => {
                    assert_eq!(key_actual, key);
                    assert_eq!(value, valid_data);
                }
                Event::Failed(_) => panic!("Fetch failed unexpectedly"),
            }

            // Verify peer 2 was blocked (sent invalid data)
            let blocked = oracle.blocked().await.unwrap();
            assert_eq!(blocked.len(), 1);
            assert_eq!(blocked[0].0, peers[0]);
            assert_eq!(blocked[0].1, peers[1]);

            // Verify metrics: 1 successful fetch (from peer 3 after peer 2 was blocked)
            let metrics = context.encode();
            assert!(metrics.contains("_fetch_total{status=\"Success\"} 1"));
        });
    }

    #[test_traced]
    fn test_fetch_targeted_no_fallback() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3, 4]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 3).await;

            let key = Key(1);

            // Only peer 4 has the data, peers 2 and 3 don't
            let mut prod4 = Producer::default();
            prod4.insert(key.clone(), Bytes::from("data from peer 4"));

            let (cons1, mut cons_out1) = Consumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                Producer::default(), // no data
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                Producer::default(), // no data
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox4 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                prod4,
            )
            .await;

            // Wait for peer set to be established
            context.sleep(Duration::from_millis(100)).await;

            // Start fetch with targets for peers 2 and 3 (both don't have data)
            // Peer 4 has data but is NOT a target - it should NEVER be tried
            mailbox1
                .fetch_targeted(
                    key.clone(),
                    non_empty_vec![peers[1].clone(), peers[2].clone()],
                )
                .await;

            // Wait enough time for targets to fail and retry multiple times
            // The fetch should not succeed because peer 4 (which has data) is not targeted
            select! {
                event = cons_out1.next() => {
                    panic!("Fetch should not succeed, but got: {event:?}");
                },
                _ = context.sleep(Duration::from_secs(3)) => {
                    // Expected: no success event because peer 4 is not targeted
                },
            };
        });
    }

    #[test_traced]
    fn test_fetch_all_targeted() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3, 4]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 3).await;

            let key1 = Key(1);
            let key2 = Key(2);
            let key3 = Key(3);

            // Peer 2 has key1
            let mut prod2 = Producer::default();
            prod2.insert(key1.clone(), Bytes::from("data for key 1"));

            // Peer 3 has key3
            let mut prod3 = Producer::default();
            prod3.insert(key3.clone(), Bytes::from("data for key 3"));

            // Peer 4 has key2
            let mut prod4 = Producer::default();
            prod4.insert(key2.clone(), Bytes::from("data for key 2"));

            // Consumer expects all three keys
            let (mut cons1, mut cons_out1) = Consumer::new();
            cons1.add_expected(key1.clone(), Bytes::from("data for key 1"));
            cons1.add_expected(key2.clone(), Bytes::from("data for key 2"));
            cons1.add_expected(key3.clone(), Bytes::from("data for key 3"));

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                prod2,
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                prod3,
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox4 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                prod4,
            )
            .await;

            // Wait for peer set to be established
            context.sleep(Duration::from_millis(100)).await;

            // Fetch keys with mixed targeting:
            // - key1 targeted to peer 2 (has data) -> should succeed from target
            // - key2 targeted to peer 4 (has data) -> should succeed from target
            // - key3 no targeting -> fetched from any peer (peer 3 has it)
            mailbox1
                .fetch_all_targeted(vec![
                    (key1.clone(), non_empty_vec![peers[1].clone()]), // peer 2 has key1
                    (key2.clone(), non_empty_vec![peers[3].clone()]), // peer 4 has key2
                ])
                .await;
            mailbox1.fetch(key3.clone()).await; // no targeting for key3

            // Collect all three events
            let mut results = HashMap::new();
            for _ in 0..3 {
                let event = cons_out1.next().await.unwrap();
                match event {
                    Event::Success(key, value) => {
                        results.insert(key, value);
                    }
                    Event::Failed(key) => panic!("Fetch failed for key {key:?}"),
                }
            }

            // Verify all keys received correct data
            assert_eq!(results.len(), 3);
            assert_eq!(results.get(&key1).unwrap(), &Bytes::from("data for key 1"));
            assert_eq!(results.get(&key2).unwrap(), &Bytes::from("data for key 2"));
            assert_eq!(results.get(&key3).unwrap(), &Bytes::from("data for key 3"));

            // Verify metrics: 3 successful fetches
            let metrics = context.encode();
            assert!(metrics.contains("_fetch_total{status=\"Success\"} 3"));
        });
    }

    /// Tests that calling fetch() on an in-progress targeted fetch clears the targets,
    /// allowing the fetch to succeed from any available peer.
    #[test_traced]
    fn test_fetch_clears_targets() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2, 3]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;

            let key = Key(1);
            let valid_data = Bytes::from("valid data");

            // Peer 2 has no data, peer 3 has the data
            let mut prod3 = Producer::default();
            prod3.insert(key.clone(), valid_data.clone());

            let (cons1, mut cons_out1) = Consumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                Producer::default(), // no data
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                prod3,
            )
            .await;

            // Wait for peer set to be established
            context.sleep(Duration::from_millis(100)).await;

            // Start fetch with target for peer 2 only (who doesn't have data)
            mailbox1
                .fetch_targeted(key.clone(), non_empty_vec![peers[1].clone()])
                .await;

            // Wait for the targeted fetch to fail a few times
            context.sleep(Duration::from_millis(500)).await;

            // Call fetch() which should clear the targets and allow fallback to any peer
            mailbox1.fetch(key.clone()).await;

            // Should now succeed from peer 3 (who has data but wasn't originally targeted)
            let event = cons_out1.next().await.unwrap();
            match event {
                Event::Success(key_actual, value) => {
                    assert_eq!(key_actual, key);
                    assert_eq!(value, valid_data);
                }
                Event::Failed(_) => panic!("Fetch failed unexpectedly"),
            }
        });
    }

    #[test_traced]
    fn test_retain() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            let key = Key(5);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 5"));

            let (cons1, mut cons_out1) = Consumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                prod2,
            )
            .await;

            // Retain before fetching should have no effect
            mailbox1.retain(|_| true).await;
            select! {
                _ = cons_out1.next() => { panic!("unexpected event"); },
                _ = context.sleep(Duration::from_millis(100)) => {},
            };

            // Start a fetch (no link, so fetch stays in-flight with timer in fetch timers)
            mailbox1.fetch(key.clone()).await;

            // Retain with predicate that excludes the key
            // This must clean up fetch timers entry for the key
            let key_clone = key.clone();
            mailbox1.retain(move |k| k != &key_clone).await;

            // Consumer should receive failed event
            let event = cons_out1.next().await.unwrap();
            match event {
                Event::Failed(key_actual) => {
                    assert_eq!(key_actual, key);
                }
                Event::Success(_, _) => panic!("Fetch should have been retained out"),
            }

            // Now add link so fetches can complete
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            // Fetch same key again, if fetch timers wasn't cleaned up, this would
            // be treated as a duplicate and silently ignored
            mailbox1.fetch(key.clone()).await;

            // Should succeed
            let event = cons_out1.next().await.unwrap();
            match event {
                Event::Success(key_actual, value) => {
                    assert_eq!(key_actual, key);
                    assert_eq!(value, Bytes::from("data for key 5"));
                }
                Event::Failed(_) => unreachable!(),
            }
        });
    }

    #[test_traced]
    fn test_clear() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            // No link yet - fetch will stay in-flight
            let key = Key(6);
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), Bytes::from("data for key 6"));

            let (cons1, mut cons_out1) = Consumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                prod2,
            )
            .await;

            // Clear before fetching should have no effect
            mailbox1.clear().await;
            select! {
                _ = cons_out1.next() => { panic!("unexpected event"); },
                _ = context.sleep(Duration::from_millis(100)) => {},
            };

            // Start a fetch (no link, so fetch stays in-flight with timer in fetch timers)
            mailbox1.fetch(key.clone()).await;

            // Clear all fetches
            mailbox1.clear().await;

            // Consumer should receive failed event
            let event = cons_out1.next().await.unwrap();
            match event {
                Event::Failed(key_actual) => {
                    assert_eq!(key_actual, key);
                }
                Event::Success(_, _) => panic!("Fetch should have been cleared"),
            }

            // Now add link so fetches can complete
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            // Fetch same key again, if fetch_timers wasn't cleaned up, this would
            // be treated as a duplicate and silently ignored
            mailbox1.fetch(key.clone()).await;

            // Should succeed
            let event = cons_out1.next().await.unwrap();
            match event {
                Event::Success(key_actual, value) => {
                    assert_eq!(key_actual, key);
                    assert_eq!(value, Bytes::from("data for key 6"));
                }
                Event::Failed(_) => unreachable!(),
            }
        });
    }

    /// Tests that when a peer is rate-limited, the fetcher spills over to another peer.
    /// With 2 peers and rate limit of 1/sec each, 2 requests issued simultaneously should
    /// both complete immediately (one to each peer) without waiting for rate limit reset.
    #[test_traced]
    fn test_rate_limit_spillover() {
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|context| async move {
            // Use a very restrictive rate limit: 1 request per second per peer
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers_with_rate_limit(
                    &context,
                    &[1, 2, 3],
                    Quota::per_second(NZU32!(1)),
                )
                .await;

            // Add links between peer 1 and both peer 2 and peer 3
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;

            // Both peer 2 and peer 3 have the same data
            let mut prod2 = Producer::default();
            let mut prod3 = Producer::default();
            prod2.insert(Key(0), Bytes::from("data for key 0"));
            prod2.insert(Key(1), Bytes::from("data for key 1"));
            prod3.insert(Key(0), Bytes::from("data for key 0"));
            prod3.insert(Key(1), Bytes::from("data for key 1"));

            let (cons1, mut cons_out1) = Consumer::new();

            // Set up peer 1 (the requester)
            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            // Set up peer 2 (has data)
            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                prod2,
            )
            .await;

            // Set up peer 3 (also has data)
            let scheme = schemes.remove(0);
            let _mailbox3 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                prod3,
            )
            .await;

            // Wait for peer set to be established
            context.sleep(Duration::from_millis(100)).await;
            let start = context.current();

            // Issue 2 fetch requests rapidly
            // With rate limit of 1/sec per peer and 2 peers, both should complete
            // immediately via spill-over (one request to each peer)
            mailbox1.fetch(Key(0)).await;
            mailbox1.fetch(Key(1)).await;

            // Collect results
            let mut results = HashMap::new();
            for _ in 0..2 {
                let event = cons_out1.next().await.unwrap();
                match event {
                    Event::Success(key, value) => {
                        results.insert(key.clone(), value);
                    }
                    Event::Failed(key) => panic!("Fetch failed for key {key:?}"),
                }
            }

            // Verify both keys were fetched successfully
            assert_eq!(results.len(), 2);
            assert_eq!(
                results.get(&Key(0)).unwrap(),
                &Bytes::from("data for key 0")
            );
            assert_eq!(
                results.get(&Key(1)).unwrap(),
                &Bytes::from("data for key 1")
            );

            // Verify it completed quickly (well under 1 second) - proves spill-over worked
            // Without spill-over, the second request would wait ~1 second for rate limit reset
            let elapsed = context.current().duration_since(start).unwrap();
            assert!(
                elapsed < Duration::from_millis(500),
                "Expected quick completion via spill-over, but took {elapsed:?}"
            );
        });
    }

    /// Tests that rate limiting causes retries to eventually succeed after the rate limit resets.
    /// This test uses a single peer with a restrictive rate limit and verifies that
    /// fetches eventually complete after waiting for the rate limit to reset.
    #[test_traced]
    fn test_rate_limit_retry_after_reset() {
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|context| async move {
            // Use a restrictive rate limit: 1 request per second
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers_with_rate_limit(
                    &context,
                    &[1, 2],
                    Quota::per_second(NZU32!(1)),
                )
                .await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            // Peer 2 has data for multiple keys
            let mut prod2 = Producer::default();
            prod2.insert(Key(1), Bytes::from("data for key 1"));
            prod2.insert(Key(2), Bytes::from("data for key 2"));
            prod2.insert(Key(3), Bytes::from("data for key 3"));

            let (cons1, mut cons_out1) = Consumer::new();

            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                Producer::default(),
            )
            .await;

            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                prod2,
            )
            .await;

            // Wait for peer set to be established
            context.sleep(Duration::from_millis(100)).await;
            let start = context.current();

            // Issue 3 fetch requests to a single peer with rate limit of 1/sec
            // Only 1 can be sent immediately, the others must wait for rate limit reset
            mailbox1.fetch(Key(1)).await;
            mailbox1.fetch(Key(2)).await;
            mailbox1.fetch(Key(3)).await;

            // All 3 should eventually succeed (after rate limit resets)
            let mut results = HashMap::new();
            for _ in 0..3 {
                let event = cons_out1.next().await.unwrap();
                match event {
                    Event::Success(key, value) => {
                        results.insert(key.clone(), value);
                    }
                    Event::Failed(key) => panic!("Fetch failed for key {key:?}"),
                }
            }

            assert_eq!(results.len(), 3);
            for i in 1..=3 {
                assert_eq!(
                    results.get(&Key(i)).unwrap(),
                    &Bytes::from(format!("data for key {}", i))
                );
            }

            // Verify it took significant time due to rate limiting
            // With 3 requests at 1/sec to a single peer, requests 2 and 3 must wait
            // for rate limit resets (~1 second each), so total should be > 2 seconds
            let elapsed = context.current().duration_since(start).unwrap();
            assert!(
                elapsed > Duration::from_secs(2),
                "Expected rate limiting to cause delay > 2s, but took {elapsed:?}"
            );
        });
    }

    /// Tests that the resolver never sends fetch requests to itself (me exclusion).
    /// Even when the local peer has the data in its producer, it should fetch from
    /// another peer instead.
    #[test_traced]
    fn test_self_exclusion() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, mut schemes, peers, mut connections) =
                setup_network_and_peers(&context, &[1, 2]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let key = Key(1);
            let data = Bytes::from("shared data");

            // Both peers have the data - peer 1 (requester) and peer 2
            let mut prod1 = Producer::default();
            prod1.insert(key.clone(), data.clone());
            let mut prod2 = Producer::default();
            prod2.insert(key.clone(), data.clone());

            let (cons1, mut cons_out1) = Consumer::new();

            // Set up peer 1 with `me` set - it has the data but should NOT fetch from itself
            let scheme = schemes.remove(0);
            let mut mailbox1 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                cons1,
                prod1, // peer 1 has the data
            )
            .await;

            // Set up peer 2 - also has the data
            let scheme = schemes.remove(0);
            let _mailbox2 = setup_and_spawn_actor(
                &context,
                oracle.manager(),
                oracle.control(scheme.public_key()),
                scheme,
                connections.remove(0),
                Consumer::dummy(),
                prod2,
            )
            .await;

            // Wait for peer set to be established
            context.sleep(Duration::from_millis(100)).await;

            // Fetch the key - should get it from peer 2, not from self
            mailbox1.fetch(key.clone()).await;

            // Should succeed (from peer 2)
            let event = cons_out1.next().await.unwrap();
            match event {
                Event::Success(key_actual, value) => {
                    assert_eq!(key_actual, key);
                    assert_eq!(value, data);
                }
                Event::Failed(_) => panic!("Fetch failed unexpectedly"),
            }
        });
    }
}

//! Makes and responds to requests using the P2P network.

use bytes::Bytes;
use commonware_utils::Array;
use futures::channel::oneshot;
use std::future::Future;

#[cfg(test)]
pub mod mocks;

pub mod peer;
mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

/// The interface responsible for serving data requested by the network.
pub trait Producer: Clone + Send + 'static {
    /// Type used to uniquely identify data.
    type Key: Array;

    /// Serve a request received from the network.
    fn produce(&mut self, key: Self::Key) -> impl Future<Output = oneshot::Receiver<Bytes>> + Send;
}

/// The interface responsible for managing the list of peers that can be used to fetch data.
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

    /// Returns true if the given public key is a peer.
    fn is_peer(&self, public_key: &Self::PublicKey) -> bool;
}

#[cfg(test)]
mod tests {
    use super::{
        mocks::{Consumer, Coordinator, Event, Key, Producer},
        peer,
    };
    use crate::Resolver;
    use bytes::Bytes;
    use commonware_cryptography::ed25519::PublicKey;
    use commonware_cryptography::{Ed25519, Scheme};
    use commonware_macros::{select, test_traced};
    use commonware_p2p::simulated::{Link, Network, Oracle, Receiver, Sender};
    use commonware_runtime::deterministic::{Context, Executor};
    use commonware_runtime::{Clock, Metrics, Runner};
    use futures::channel::mpsc;
    use futures::StreamExt;
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

    #[allow(clippy::type_complexity)]
    fn setup_consumer() -> (
        Consumer<Key, Bytes, ()>,
        mpsc::Receiver<Event<Key, Bytes, ()>>,
    ) {
        let (sender, receiver) = mpsc::channel(MAILBOX_SIZE);
        let consumer = Consumer::new(sender);
        (consumer, receiver)
    }

    async fn setup_and_spawn_actor(
        context: &Context,
        coordinator: &Coordinator<PublicKey>,
        scheme: Ed25519,
        connection: (Sender<PublicKey>, Receiver<PublicKey>),
        consumer: Consumer<Key, Bytes, ()>,
        producer: Producer<Key, Bytes>,
    ) -> peer::Mailbox<Key> {
        let (actor, mailbox) = peer::Actor::new(
            context.with_label(&format!("actor_{}", scheme.public_key())),
            peer::Config {
                crypto: scheme.clone(),
                coordinator: coordinator.clone(),
                consumer,
                producer,
                mailbox_size: MAILBOX_SIZE,
                requester_config: commonware_p2p::utils::requester::Config {
                    crypto: scheme,
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
        )
        .await;
        actor.start(connection);

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
            let (cons1, mut cons_out1) = setup_consumer();

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
                Event::Failed(_, _) => panic!("Fetch failed unexpectedly"),
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
            let (cons1, mut cons_out1) = setup_consumer();
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
                Event::Failed(key_actual, _failure) => {
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
            let (cons1, mut cons_out1) = setup_consumer();

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
                Event::Failed(_, _) => panic!("Fetch failed unexpectedly"),
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
            let (cons1, mut cons_out1) = setup_consumer();
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
                Event::Failed(key_actual, _failure) => {
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
            let (cons1, mut cons_out1) = setup_consumer();

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
                        Event::Failed(_, _) => panic!("Fetch failed unexpectedly"),
                    }
                }
                assert!(
                    found_key2 && found_key3,
                    "Both keys should have been successfully fetched"
                );
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
            let (cons1, mut cons_out1) = setup_consumer();

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
                Event::Failed(_, _) => panic!("Fetch failed unexpectedly"),
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
                Event::Failed(key_actual, _failure) => {
                    assert_eq!(key_actual, key);
                }
                Event::Success(_, _) => panic!("Fetch should have been canceled"),
            }
        });
    }
}

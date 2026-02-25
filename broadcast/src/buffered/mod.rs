//! Broadcast messages to and cache messages from untrusted peers.
//!
//! # Overview
//!
//! The core of the module is the [Engine]. It is responsible for:
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
//! The [Mailbox] is used to make requests to the [Engine]. It implements the
//! [crate::Broadcaster] trait. This is used to have the engine send a message to all
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
    use super::{mocks::TestMessage, *};
    use crate::Broadcaster;
    use commonware_codec::RangeCfg;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Digestible, Hasher, Sha256, Signer as _,
    };
    use commonware_macros::test_traced;
    use commonware_p2p::{
        simulated::{Link, Network, Oracle, Receiver, Sender},
        Provider, Recipients, Sender as _,
    };
    use commonware_runtime::{
        count_running_tasks, deterministic, Clock, Error, IoBuf, Metrics, Quota, Runner,
    };
    use std::{collections::BTreeMap, num::NonZeroU32, time::Duration};

    // Number of messages to cache per sender
    const CACHE_SIZE: usize = 10;

    // Enough time to receive a cached message. Cannot be instantaneous as the test runtime
    // requires some time to switch context.
    const A_JIFFY: Duration = Duration::from_millis(10);

    // Network speed for the simulated network
    const NETWORK_SPEED: Duration = Duration::from_millis(100);

    // Enough time for a message to propagate through the network
    const NETWORK_SPEED_WITH_BUFFER: Duration = Duration::from_millis(200);

    /// Default rate limit set high enough to not interfere with normal operation
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    type Registrations = BTreeMap<
        PublicKey,
        (
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        ),
    >;

    async fn initialize_simulation(
        context: deterministic::Context,
        num_peers: u32,
        success_rate: f64,
    ) -> (
        Vec<PublicKey>,
        Registrations,
        Oracle<PublicKey, deterministic::Context>,
    ) {
        let (network, oracle) = Network::<deterministic::Context, PublicKey>::new(
            context.with_label("network"),
            commonware_p2p::simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: None,
            },
        );
        network.start();

        let mut schemes = (0..num_peers)
            .map(|i| PrivateKey::from_seed(i as u64))
            .collect::<Vec<_>>();
        schemes.sort_by_key(|s| s.public_key());
        let peers: Vec<PublicKey> = schemes.iter().map(|c| c.public_key()).collect();

        let mut registrations: Registrations = BTreeMap::new();
        for peer in peers.iter() {
            let (sender, receiver) = oracle
                .control(peer.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            registrations.insert(peer.clone(), (sender, receiver));
        }

        // Add links between all peers
        let link = Link {
            latency: NETWORK_SPEED,
            jitter: Duration::ZERO,
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

    async fn spawn_peer_engines(
        context: deterministic::Context,
        oracle: &Oracle<PublicKey, deterministic::Context>,
        registrations: &mut Registrations,
    ) -> BTreeMap<PublicKey, Mailbox<PublicKey, TestMessage>> {
        let mut mailboxes = BTreeMap::new();
        while let Some((peer, network)) = registrations.pop_first() {
            let context = context.with_label(&format!("peer_{}", peer));
            let config = Config {
                public_key: peer.clone(),
                mailbox_size: 1024,
                deque_size: CACHE_SIZE,
                priority: false,
                codec_config: RangeCfg::from(..),
                peer_set_subscription: oracle.manager().subscribe().await,
            };
            let (engine, engine_mailbox) =
                Engine::<_, PublicKey, TestMessage>::new(context.clone(), config);
            mailboxes.insert(peer.clone(), engine_mailbox);
            engine.start(network);
        }
        mailboxes
    }

    #[test_traced]
    fn test_broadcast() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.clone(), 4, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &oracle, &mut registrations).await;

            // Send a single broadcast message from the first peer
            let message = TestMessage::shared(b"hello world test message");
            let first_mailbox = mailboxes.get(peers.first().unwrap()).unwrap().clone();
            let result = first_mailbox
                .broadcast(Recipients::All, message.clone())
                .await;

            // Allow time for propagation
            context.sleep(Duration::from_secs(1)).await;

            // Check that all peers received the message
            for peer in peers.iter() {
                let mailbox = mailboxes.get(peer).unwrap().clone();
                let digest = message.digest();
                let receiver = mailbox.subscribe(digest).await;
                let received_message = receiver.await.ok();
                assert_eq!(received_message.unwrap(), message.clone());
            }
            assert_eq!(result.await.unwrap().len(), peers.len() - 1);

            // Drop broadcast result
            let message = TestMessage::shared(b"hello world again");
            let result = first_mailbox
                .broadcast(Recipients::All, message.clone())
                .await;
            drop(result);

            // Allow time for propagation
            context.sleep(Duration::from_secs(1)).await;

            // Check that all peers received the new message
            let mut found = 0;
            for peer in peers.iter() {
                let mailbox = mailboxes.get(peer).unwrap().clone();
                let digest = message.digest();
                let receiver = mailbox.get(digest).await;
                if let Some(receiver) = receiver {
                    assert_eq!(receiver, message.clone());
                    found += 1;
                }
            }
            assert!(found > 0, "No peers received the message");
        });
    }

    #[test_traced]
    fn test_self_retrieval() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            // Initialize simulation with 1 peer
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.clone(), 1, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &oracle, &mut registrations).await;

            // Set up mailbox for Peer A
            let mailbox_a = mailboxes.get(&peers[0]).unwrap().clone();

            // Create a test message
            let m1 = TestMessage::shared(b"hello world");
            let digest_m1 = m1.digest();

            // Attempt immediate retrieval before broadcasting
            let receiver_before = mailbox_a.get(digest_m1).await;
            assert!(receiver_before.is_none());

            // Attempt retrieval before broadcasting
            let receiver_before = mailbox_a.subscribe(digest_m1).await;

            // Broadcast the message
            let result = mailbox_a.broadcast(Recipients::All, m1.clone()).await;
            assert_eq!(result.await.unwrap().len(), peers.len() - 1);

            // Wait for the pre-broadcast retrieval to complete
            let msg_before = receiver_before
                .await
                .expect("Pre-broadcast retrieval failed");
            assert_eq!(msg_before, m1);

            // Attempt immediate retrieval after broadcasting
            let receiver_after = mailbox_a.get(digest_m1).await;
            assert_eq!(receiver_after, Some(m1.clone()));

            // Perform a second retrieval after the broadcast
            let receiver_after = mailbox_a.subscribe(digest_m1).await;

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
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.clone(), 10, 0.1).await;
            let mailboxes = spawn_peer_engines(context.clone(), &oracle, &mut registrations).await;

            // Create a message and grab an arbitrary mailbox
            let message = TestMessage::shared(b"hello world test message");
            let first_mailbox = mailboxes.get(peers.first().unwrap()).unwrap().clone();

            // Retry until all peers receive the message (or timeout)
            let digest = message.digest();
            for i in 0..100 {
                // Broadcast the message
                let result = first_mailbox
                    .broadcast(Recipients::All, message.clone())
                    .await;
                context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

                // Check if all peers received the message
                let mut all_received = true;
                for peer in peers.iter() {
                    let mailbox = mailboxes.get(peer).unwrap().clone();
                    let receiver = mailbox.subscribe(digest).await;
                    let has = match context.timeout(A_JIFFY, receiver).await {
                        Ok(r) => r.is_ok(),
                        Err(Error::Timeout) => false,
                        Err(e) => panic!("unexpected error: {e:?}"),
                    };
                    all_received &= has;
                }
                assert_eq!(result.await.unwrap().len(), peers.len() - 1);

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
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.clone(), 2, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &oracle, &mut registrations).await;

            // Broadcast a message
            let message = TestMessage::shared(b"cached message");
            let first_mailbox = mailboxes.get(peers.first().unwrap()).unwrap().clone();
            let result = first_mailbox
                .broadcast(Recipients::All, message.clone())
                .await;
            assert_eq!(result.await.unwrap().len(), peers.len() - 1);

            // Wait for propagation
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Get from cache (should be instant)
            let digest = message.digest();
            let mailbox = mailboxes.get(peers.last().unwrap()).unwrap().clone();
            let receiver = mailbox.subscribe(digest).await;
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
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.clone(), 2, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &oracle, &mut registrations).await;

            // Request nonexistent message from two nodes
            let message = TestMessage::shared(b"future message");
            let digest = message.digest();
            let mailbox1 = mailboxes.get(&peers[0]).unwrap().clone();
            let mailbox2 = mailboxes.get(&peers[1]).unwrap().clone();
            let receiver = mailbox1.subscribe(digest).await;

            // Create two other requests which are dropped
            let dummy1 = mailbox1.subscribe(digest).await;
            let dummy2 = mailbox2.subscribe(digest).await;
            drop(dummy1);
            drop(dummy2);

            // Broadcast the message
            let result = mailbox1.broadcast(Recipients::All, message.clone()).await;
            assert_eq!(result.await.unwrap().len(), peers.len() - 1);

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
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.clone(), 2, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &oracle, &mut registrations).await;

            // Broadcast messages exceeding cache size
            let mailbox = mailboxes.get(&peers[0]).unwrap().clone();
            let mut messages = vec![];
            for i in 0..CACHE_SIZE + 1 {
                messages.push(TestMessage::shared(format!("message {i}").as_bytes()));
            }
            for message in messages.iter() {
                let result = mailbox.broadcast(Recipients::All, message.clone()).await;
                assert_eq!(result.await.unwrap().len(), peers.len() - 1);
            }

            // Wait for propagation
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Check all other messages exist
            let peer_mailbox = mailboxes.get(&peers[1]).unwrap().clone();
            for msg in messages.iter().skip(1) {
                let result = peer_mailbox.subscribe(msg.digest()).await.await.unwrap();
                assert_eq!(result, msg.clone());
            }

            // Check first message times out
            let receiver = peer_mailbox.subscribe(messages[0].digest()).await;
            match context.timeout(A_JIFFY, receiver).await {
                Ok(_) => panic!("receiver should have failed"),
                Err(Error::Timeout) => {} // Expected timeout
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        });
    }

    #[test_traced]
    fn test_cache_eviction_multi_peer() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|context| async move {
            // Initialize simulation with 3 peers
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.clone(), 3, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &oracle, &mut registrations).await;

            // Assign mailboxes for peers A, B, C
            let mailbox_a = mailboxes.get(&peers[0]).unwrap().clone();
            let mailbox_b = mailboxes.get(&peers[1]).unwrap().clone();
            let mailbox_c = mailboxes.get(&peers[2]).unwrap().clone();

            // Create and broadcast message M1 from A
            let m1 = TestMessage::shared(b"message M1");
            let digest_m1 = m1.digest();
            let result = mailbox_a.broadcast(Recipients::All, m1.clone()).await;
            assert_eq!(result.await.unwrap().len(), peers.len() - 1);
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Broadcast M1 from C
            let result = mailbox_c.broadcast(Recipients::All, m1.clone()).await;
            assert_eq!(result.await.unwrap().len(), peers.len() - 1);
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // M1 is now in A's and C's deques in B's engine

            // Peer A broadcasts 10 new messages to evict M1 from A's deque
            let mut new_messages_a = Vec::with_capacity(CACHE_SIZE);
            for i in 0..CACHE_SIZE {
                new_messages_a.push(TestMessage::shared(format!("A{i}").as_bytes()));
            }
            for msg in &new_messages_a {
                let result = mailbox_a.broadcast(Recipients::All, msg.clone()).await;
                assert_eq!(result.await.unwrap().len(), peers.len() - 1);
            }
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Verify B can still get M1 (in C's deque)
            let receiver = mailbox_b.subscribe(digest_m1).await;
            let received = receiver.await.expect("M1 should be retrievable");
            assert_eq!(received, m1);

            // Peer C broadcasts 10 new messages to evict M1 from C's deque
            let mut new_messages_c = Vec::with_capacity(CACHE_SIZE);
            for i in 0..CACHE_SIZE {
                new_messages_c.push(TestMessage::shared(format!("C{i}").as_bytes()));
            }
            for msg in &new_messages_c {
                let result = mailbox_c.broadcast(Recipients::All, msg.clone()).await;
                assert_eq!(result.await.unwrap().len(), peers.len() - 1);
            }
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Verify B cannot get M1 (evicted from all deques)
            let receiver = mailbox_b.subscribe(digest_m1).await;
            match context.timeout(A_JIFFY, receiver).await {
                Ok(_) => panic!("M1 should not be retrievable"),
                Err(Error::Timeout) => {} // Expected timeout
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        });
    }

    #[test_traced]
    fn test_selective_recipients() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.clone(), 4, 1.0).await;

            let sender_pk = peers[0].clone();
            let target_peer = peers[1].clone();
            let non_target_peer = peers[2].clone();

            let mailboxes = spawn_peer_engines(context.clone(), &oracle, &mut registrations).await;
            let sender_mb = mailboxes.get(&sender_pk).unwrap().clone();

            let msg = TestMessage::shared(b"selective-broadcast");
            let result = sender_mb
                .broadcast(Recipients::One(target_peer.clone()), msg.clone())
                .await;
            assert_eq!(result.await.unwrap(), vec![target_peer.clone()]);

            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Only target peer should retrieve the message.
            let got_target = mailboxes
                .get(&target_peer)
                .unwrap()
                .clone()
                .get(msg.digest())
                .await;
            assert_eq!(got_target, Some(msg.clone()));

            // Non-target peer should not retrieve the message.
            let got_other = mailboxes
                .get(&non_target_peer)
                .unwrap()
                .clone()
                .get(msg.digest())
                .await;
            assert!(got_other.is_none());
        });
    }

    #[test_traced]
    fn test_ref_count_across_peers() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|context| async move {
            // three peers so we can observe from a third
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.clone(), 3, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &oracle, &mut registrations).await;

            let p0 = peers[0].clone();
            let p1 = peers[1].clone();
            let observer = peers[2].clone();

            let mb0 = mailboxes.get(&p0).unwrap().clone();
            let mb1 = mailboxes.get(&p1).unwrap().clone();
            let obs = mailboxes.get(&observer).unwrap().clone();

            // the message duplicated by p0 and p1
            let dup = TestMessage::shared(b"dup");
            let digest = dup.digest();

            // broadcast from both senders
            mb0.broadcast(Recipients::All, dup.clone())
                .await
                .await
                .unwrap();
            mb1.broadcast(Recipients::All, dup.clone())
                .await
                .await
                .unwrap();
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // observer must get it now
            assert_eq!(obs.get(digest).await, Some(dup.clone()));

            // Evict from p0's deque only
            for i in 0..CACHE_SIZE {
                let spam = TestMessage::shared(format!("p0-{i}").into_bytes());
                mb0.broadcast(Recipients::All, spam).await.await.unwrap();
            }
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;
            assert_eq!(obs.get(digest).await, Some(dup.clone()));

            // Evict from p1's deque as well
            for i in 0..CACHE_SIZE {
                let spam = TestMessage::shared(format!("p1-{i}").into_bytes());
                mb1.broadcast(Recipients::All, spam).await.await.unwrap();
            }
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;
            assert!(obs.get(digest).await.is_none());
        });
    }

    #[test_traced]
    fn test_deterministic_retrieval() {
        let run = |seed: u64| {
            let config = deterministic::Config::new()
                .with_seed(seed)
                .with_timeout(Some(Duration::from_secs(5)));
            let runner = deterministic::Runner::new(config);
            runner.start(|context| async move {
                let (peers, mut registrations, oracle) =
                    initialize_simulation(context.clone(), 1, 1.0).await;
                let mailboxes =
                    spawn_peer_engines(context.clone(), &oracle, &mut registrations).await;

                let sender1 = peers[0].clone();
                let mb1 = mailboxes.get(&sender1).unwrap().clone();

                // Three messages with distinct digests.
                let m1 = TestMessage::shared(b"content-1");
                let m2 = TestMessage::shared(b"content-2");
                let m3 = TestMessage::shared(b"content-3");
                mb1.broadcast(Recipients::All, m1.clone())
                    .await
                    .await
                    .unwrap();
                mb1.broadcast(Recipients::All, m2.clone())
                    .await
                    .await
                    .unwrap();
                mb1.broadcast(Recipients::All, m3.clone())
                    .await
                    .await
                    .unwrap();

                let mut hasher = Sha256::default();
                for msg in [&m1, &m2, &m3] {
                    if let Some(value) = mb1.get(msg.digest()).await {
                        hasher.update(&value.content);
                    }
                }
                hasher.finalize()
            })
        };

        for seed in 0..10 {
            let h1 = run(seed);
            let h2 = run(seed);

            assert_eq!(h1, h2, "Messages returned in different order for {seed}");
        }
    }

    #[test_traced]
    fn test_malformed_network_payload_does_not_break_valid_traffic() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|context| async move {
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.clone(), 3, 1.0).await;

            let attacker = peers[0].clone();
            let honest = peers[1].clone();
            let victim = peers[2].clone();

            let (mut attacker_sender, _) = registrations.remove(&attacker).unwrap();
            let mailboxes = spawn_peer_engines(context.clone(), &oracle, &mut registrations).await;
            let honest_mailbox = mailboxes.get(&honest).unwrap().clone();
            let victim_mailbox = mailboxes.get(&victim).unwrap().clone();

            // Send malformed bytes that cannot decode into `TestMessage`.
            let sent = attacker_sender
                .send(
                    Recipients::One(victim.clone()),
                    IoBuf::from(vec![0xFF]),
                    false,
                )
                .await
                .expect("malformed payload send should not fail at transport level");
            assert_eq!(sent, vec![victim.clone()]);
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // The victim should still process later valid traffic.
            let message = TestMessage::shared(b"valid-after-malformed");
            let result = honest_mailbox
                .broadcast(Recipients::One(victim.clone()), message.clone())
                .await;
            assert_eq!(result.await.unwrap(), vec![victim.clone()]);
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            let received = victim_mailbox
                .subscribe(message.digest())
                .await
                .await
                .expect("victim should receive valid message after malformed payload");
            assert_eq!(received, message);
        });
    }

    #[test_traced]
    fn test_dropped_waiters_for_missing_digest_are_cleaned_up() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|context| async move {
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.clone(), 1, 1.0).await;
            let peer = peers[0].clone();
            let (sender, receiver) = registrations.remove(&peer).unwrap();

            let engine_context = context.with_label("waiter_cleanup");
            let config = Config {
                public_key: peer,
                mailbox_size: 1024,
                deque_size: CACHE_SIZE,
                priority: false,
                codec_config: RangeCfg::from(..),
                peer_set_subscription: oracle.manager().subscribe().await,
            };
            let (engine, mailbox) =
                Engine::<_, PublicKey, TestMessage>::new(engine_context.clone(), config);
            engine.start((sender, receiver));

            let missing = TestMessage::shared(b"never-arrives");
            let missing_digest = missing.digest();
            let rx1 = mailbox.subscribe(missing_digest).await;
            let rx2 = mailbox.subscribe(missing_digest).await;

            // Ensure subscriptions are processed and waiters are reflected in metrics.
            let _ = mailbox
                .get(TestMessage::shared(b"before-cleanup").digest())
                .await;
            context.sleep(A_JIFFY).await;
            let metrics_before = engine_context.encode();
            let waiter_values_before: Vec<f64> = metrics_before
                .lines()
                .filter(|line| {
                    line.starts_with("waiters")
                        || (line.contains("_waiters")
                            && !line.starts_with("# HELP")
                            && !line.starts_with("# TYPE"))
                })
                .filter_map(|line| line.split_whitespace().last())
                .filter_map(|value| value.parse::<f64>().ok())
                .collect();
            assert!(
                !waiter_values_before.is_empty(),
                "waiters metric not found in output:\n{metrics_before}"
            );
            assert!(
                waiter_values_before.iter().any(|value| *value > 0.0),
                "expected positive waiters before cleanup, got:\n{metrics_before}"
            );

            drop(rx1);
            drop(rx2);

            // Trigger another mailbox event and give the run loop time to clean closed waiters.
            let _ = mailbox
                .get(TestMessage::shared(b"after-cleanup").digest())
                .await;
            context.sleep(A_JIFFY).await;

            let metrics_after = engine_context.encode();
            let waiter_values_after: Vec<f64> = metrics_after
                .lines()
                .filter(|line| {
                    line.starts_with("waiters")
                        || (line.contains("_waiters")
                            && !line.starts_with("# HELP")
                            && !line.starts_with("# TYPE"))
                })
                .filter_map(|line| line.split_whitespace().last())
                .filter_map(|value| value.parse::<f64>().ok())
                .collect();
            assert!(
                !waiter_values_after.is_empty(),
                "waiters metric not found in output:\n{metrics_after}"
            );
            assert!(
                waiter_values_after.iter().all(|value| *value == 0.0),
                "expected zero retained waiters, got:\n{metrics_after}"
            );
        });
    }

    #[allow(clippy::type_complexity)]
    async fn spawn_peer_engines_with_handles(
        context: deterministic::Context,
        oracle: &Oracle<PublicKey, deterministic::Context>,
        registrations: &mut Registrations,
    ) -> (
        BTreeMap<PublicKey, Mailbox<PublicKey, TestMessage>>,
        Vec<commonware_runtime::Handle<()>>,
    ) {
        let mut mailboxes = BTreeMap::new();
        let mut handles = Vec::new();
        let engine_context = context.with_label("engine");
        while let Some((peer, network)) = registrations.pop_first() {
            let ctx = engine_context.with_label(&format!("peer_{}", peer));
            let config = Config {
                public_key: peer.clone(),
                mailbox_size: 1024,
                deque_size: CACHE_SIZE,
                priority: false,
                codec_config: RangeCfg::from(..),
                peer_set_subscription: oracle.manager().subscribe().await,
            };
            let (engine, engine_mailbox) =
                Engine::<_, PublicKey, TestMessage>::new(ctx.clone(), config);
            mailboxes.insert(peer.clone(), engine_mailbox);
            handles.push(engine.start(network));
        }
        (mailboxes, handles)
    }

    #[test_traced]
    fn test_operations_after_shutdown_do_not_panic() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.clone(), 2, 1.0).await;
            let (mut mailboxes, handles) =
                spawn_peer_engines_with_handles(context.clone(), &oracle, &mut registrations).await;

            // Broadcast a message to verify network is functional
            let message = TestMessage::shared(b"test message");
            let mailbox = mailboxes.remove(&peers[0]).unwrap();
            let result = mailbox
                .broadcast(Recipients::All, message.clone())
                .await
                .await;
            assert!(result.is_ok(), "broadcast should succeed before shutdown");

            // Abort all engine handles
            for handle in handles {
                handle.abort();
            }
            context.sleep(Duration::from_millis(100)).await;

            // All operations should not panic after shutdown

            // Broadcast should not panic
            let result = mailbox
                .broadcast(Recipients::All, message.clone())
                .await
                .await;
            assert!(
                result.is_err() || result.unwrap().is_empty(),
                "broadcast after shutdown should fail or return empty"
            );

            // Subscribe should not panic (returns Canceled since engine is down)
            let digest = message.digest();
            let receiver = mailbox.subscribe(digest).await;
            let result = receiver.await;
            assert!(
                result.is_err(),
                "subscribe after shutdown should return Canceled"
            );

            // Get should not panic
            let result = mailbox.get(digest).await;
            assert!(result.is_none(), "get after shutdown should return None");
        });
    }

    fn clean_shutdown(seed: u64) {
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30)));
        let runner = deterministic::Runner::new(cfg);
        runner.start(|context| async move {
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.clone(), 2, 1.0).await;

            let (mailboxes, handles) =
                spawn_peer_engines_with_handles(context.clone(), &oracle, &mut registrations).await;

            // Allow tasks to start
            context.sleep(Duration::from_millis(100)).await;

            // Count running tasks under the engine prefix
            let running_before = count_running_tasks(&context, "engine");
            assert!(
                running_before > 0,
                "at least one engine task should be running"
            );

            // Verify network is functional
            let message = TestMessage::shared(b"test message");
            let mailbox = mailboxes.get(&peers[0]).unwrap().clone();
            let result = mailbox
                .broadcast(Recipients::All, message.clone())
                .await
                .await;
            assert!(result.is_ok(), "broadcast should succeed");

            // Wait for propagation
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Verify message received
            let peer_mailbox = mailboxes.get(&peers[1]).unwrap().clone();
            let received = peer_mailbox.get(message.digest()).await;
            assert_eq!(received, Some(message));

            // Abort all engine handles
            for handle in handles {
                handle.abort();
            }
            context.sleep(Duration::from_millis(100)).await;

            // Verify all engine tasks are stopped
            let running_after = count_running_tasks(&context, "engine");
            assert_eq!(
                running_after, 0,
                "all engine tasks should be stopped, but {running_after} still running"
            );
        });
    }

    #[test]
    fn test_clean_shutdown() {
        for seed in 0..25 {
            clean_shutdown(seed);
        }
    }

    #[test_traced]
    fn test_peer_set_update_evicts_disconnected_peer_buffers() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.clone(), 3, 1.0).await;

            let peer_a = peers[0].clone();
            let peer_b = peers[1].clone();
            let peer_c = peers[2].clone();

            let (peer_set_tx, peer_set_rx) = commonware_utils::channel::mpsc::unbounded_channel();

            // Spawn peer B's engine with the peer set subscription.
            let network_b = registrations.remove(&peer_b).unwrap();
            let config_b = Config {
                public_key: peer_b.clone(),
                mailbox_size: 1024,
                deque_size: CACHE_SIZE,
                priority: false,
                codec_config: RangeCfg::from(..),
                peer_set_subscription: peer_set_rx,
            };
            let (engine_b, mailbox_b) =
                Engine::<_, PublicKey, TestMessage>::new(context.with_label("peer_b"), config_b);
            engine_b.start(network_b);

            // Spawn remaining peer engines.
            let mut mailboxes = BTreeMap::new();
            mailboxes.insert(peer_b.clone(), mailbox_b);
            for (peer, network) in registrations {
                let ctx = context.with_label(&format!("peer_{}", peer));
                let config = Config {
                    public_key: peer.clone(),
                    mailbox_size: 1024,
                    deque_size: CACHE_SIZE,
                    priority: false,
                    codec_config: RangeCfg::from(..),
                    peer_set_subscription: oracle.manager().subscribe().await,
                };
                let (engine, mailbox) = Engine::<_, PublicKey, TestMessage>::new(ctx, config);
                mailboxes.insert(peer, mailbox);
                engine.start(network);
            }

            // Peer A broadcasts a message.
            let msg = TestMessage::shared(b"eviction-test");
            let mailbox_a = mailboxes.get(&peer_a).unwrap().clone();
            let result = mailbox_a.broadcast(Recipients::All, msg.clone()).await;
            assert_eq!(result.await.unwrap().len(), 2);
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Peer B should have cached the message (received from A).
            let mailbox_b = mailboxes.get(&peer_b).unwrap().clone();
            assert_eq!(
                mailbox_b.get(msg.digest()).await,
                Some(msg.clone()),
                "peer B should have the message before eviction"
            );

            // Send a peer set update excluding peer A.
            let remaining = commonware_utils::ordered::Set::from_iter_dedup(vec![peer_b, peer_c]);
            peer_set_tx.send((1, remaining.clone(), remaining)).unwrap();
            context.sleep(A_JIFFY).await;

            // Peer A's deque was evicted; the message should be gone.
            assert!(
                mailbox_b.get(msg.digest()).await.is_none(),
                "message should be evicted after peer A left the peer set"
            );
        });
    }

    #[test_traced]
    fn test_peer_set_update_preserves_shared_messages() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.clone(), 3, 1.0).await;

            let peer_a = peers[0].clone();
            let peer_b = peers[1].clone();
            let peer_c = peers[2].clone();

            let (peer_set_tx, peer_set_rx) = commonware_utils::channel::mpsc::unbounded_channel();

            // Spawn peer B with subscription.
            let network_b = registrations.remove(&peer_b).unwrap();
            let config_b = Config {
                public_key: peer_b.clone(),
                mailbox_size: 1024,
                deque_size: CACHE_SIZE,
                priority: false,
                codec_config: RangeCfg::from(..),
                peer_set_subscription: peer_set_rx,
            };
            let (engine_b, mailbox_b) =
                Engine::<_, PublicKey, TestMessage>::new(context.with_label("peer_b"), config_b);
            engine_b.start(network_b);

            // Spawn remaining peer engines.
            let mut mailboxes = BTreeMap::new();
            mailboxes.insert(peer_b.clone(), mailbox_b);
            for (peer, network) in registrations {
                let ctx = context.with_label(&format!("peer_{}", peer));
                let config = Config {
                    public_key: peer.clone(),
                    mailbox_size: 1024,
                    deque_size: CACHE_SIZE,
                    priority: false,
                    codec_config: RangeCfg::from(..),
                    peer_set_subscription: oracle.manager().subscribe().await,
                };
                let (engine, mailbox) = Engine::<_, PublicKey, TestMessage>::new(ctx, config);
                mailboxes.insert(peer, mailbox);
                engine.start(network);
            }

            // Both A and C broadcast the same message.
            let msg = TestMessage::shared(b"shared-msg");
            let mailbox_a = mailboxes.get(&peer_a).unwrap().clone();
            let mailbox_c = mailboxes.get(&peer_c).unwrap().clone();
            mailbox_a.broadcast(Recipients::All, msg.clone()).await;
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;
            mailbox_c.broadcast(Recipients::All, msg.clone()).await;
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // B has the message in both A's and C's deques (ref count = 2).
            let mailbox_b = mailboxes.get(&peer_b).unwrap().clone();
            assert_eq!(mailbox_b.get(msg.digest()).await, Some(msg.clone()));

            // Evict peer A only; C is still tracked.
            let remaining = commonware_utils::ordered::Set::from_iter_dedup(vec![peer_b, peer_c]);
            peer_set_tx.send((1, remaining.clone(), remaining)).unwrap();
            context.sleep(A_JIFFY).await;

            // Message should still be available (C's deque still holds it).
            assert_eq!(
                mailbox_b.get(msg.digest()).await,
                Some(msg.clone()),
                "message should survive when another tracked peer still references it"
            );
        });
    }
}

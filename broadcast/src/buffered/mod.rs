//! Broadcast messages to and cache messages from untrusted peers.
//!
//! # Overview
//!
//! The core of the module is the [Engine]. It is responsible for:
//! - Accepting and caching messages from other participants
//! - Broadcasting messages to all peers
//! - Serving cached messages on-demand
//!
//! # Message Caching
//!
//! The engine receives messages from other peers and caches them. The cache is a bounded queue of
//! messages per peer. When the cache is full, the oldest message is removed to make room for the
//! new one.
//!
//! Messages referenced by multiple senders stay cached until the last per-sender deque that
//! contains them is evicted (meaning redundant messages are only stored once).
//!
//! # Peer Management
//!
//! Only peers in `latest.primary` may buffer messages (see [commonware_p2p::Provider]). When a peer
//! is no longer in `latest.primary`, its buffered messages are evicted unless buffered by any other
//! primary peer.

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
    use commonware_actor::{
        mailbox::{Overflow, Policy},
        Feedback,
    };
    use commonware_codec::RangeCfg;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Digestible, Hasher, Sha256, Signer as _,
    };
    use commonware_macros::test_traced;
    use commonware_p2p::{
        simulated::{Link, Network, Oracle, Receiver, Sender},
        Manager as _, Recipients, Sender as _, TrackedPeers,
    };
    use commonware_runtime::{
        deterministic, telemetry::metrics::count_running_tasks, Clock, Error, IoBuf, Metrics as _,
        Quota, Runner, Supervisor as _,
    };
    use commonware_utils::NZUsize;
    use std::{
        collections::{BTreeMap, VecDeque},
        num::NonZeroU32,
        time::Duration,
    };

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
            context,
            commonware_p2p::simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
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

        // Track all peers so the simulated network allows message delivery.
        let all_peers = commonware_utils::ordered::Set::from_iter_dedup(peers.clone());
        oracle.manager().track(0, all_peers).await;

        (peers, registrations, oracle)
    }

    #[test]
    fn policy_drops_closed_responders() {
        let mut overflow = <Message<PublicKey, TestMessage> as Policy>::Overflow::default();
        let pending_subscribe = TestMessage::shared(b"pending_subscribe");
        let pending_get = TestMessage::shared(b"pending_get");
        let open_subscribe = TestMessage::shared(b"open_subscribe");
        let open_get = TestMessage::shared(b"open_get");
        let current_get = TestMessage::shared(b"current_get");

        let (closed_responder, closed_receiver) = commonware_utils::channel::oneshot::channel();
        <Message<PublicKey, TestMessage> as Policy>::handle(
            &mut overflow,
            Message::Subscribe {
                digest: pending_subscribe.digest(),
                responder: closed_responder,
            },
        );
        drop(closed_receiver);

        let (open_responder, _open_receiver) = commonware_utils::channel::oneshot::channel();
        <Message<PublicKey, TestMessage> as Policy>::handle(
            &mut overflow,
            Message::Subscribe {
                digest: open_subscribe.digest(),
                responder: open_responder,
            },
        );

        let (closed_responder, closed_receiver) = commonware_utils::channel::oneshot::channel();
        <Message<PublicKey, TestMessage> as Policy>::handle(
            &mut overflow,
            Message::Get {
                digest: pending_get.digest(),
                responder: closed_responder,
            },
        );
        drop(closed_receiver);

        let (open_responder, _open_receiver) = commonware_utils::channel::oneshot::channel();
        <Message<PublicKey, TestMessage> as Policy>::handle(
            &mut overflow,
            Message::Get {
                digest: open_get.digest(),
                responder: open_responder,
            },
        );

        let (current_responder, current_receiver) = commonware_utils::channel::oneshot::channel();
        drop(current_receiver);
        <Message<PublicKey, TestMessage> as Policy>::handle(
            &mut overflow,
            Message::Get {
                digest: current_get.digest(),
                responder: current_responder,
            },
        );

        let mut drained = VecDeque::new();
        while !overflow.is_empty() {
            overflow.drain(|message| {
                drained.push_back(message);
                None
            });
        }

        assert_eq!(drained.len(), 2);
        assert!(drained.iter().any(|message| matches!(
            message,
            Message::Subscribe { digest, responder }
                if *digest == open_subscribe.digest() && !responder.is_closed()
        )));
        assert!(drained.iter().any(|message| matches!(
            message,
            Message::Get { digest, responder }
                if *digest == open_get.digest() && !responder.is_closed()
        )));
    }

    #[test]
    fn policy_drain_stops_after_accepting_message() {
        let mut overflow = <Message<PublicKey, TestMessage> as Policy>::Overflow::default();
        let first = TestMessage::shared(b"first");
        let second = TestMessage::shared(b"second");

        let (closed_responder, closed_receiver) = commonware_utils::channel::oneshot::channel();
        <Message<PublicKey, TestMessage> as Policy>::handle(
            &mut overflow,
            Message::Subscribe {
                digest: TestMessage::shared(b"closed").digest(),
                responder: closed_responder,
            },
        );
        drop(closed_receiver);

        let (first_responder, _first_receiver) = commonware_utils::channel::oneshot::channel();
        <Message<PublicKey, TestMessage> as Policy>::handle(
            &mut overflow,
            Message::Get {
                digest: first.digest(),
                responder: first_responder,
            },
        );
        let (second_responder, _second_receiver) = commonware_utils::channel::oneshot::channel();
        <Message<PublicKey, TestMessage> as Policy>::handle(
            &mut overflow,
            Message::Get {
                digest: second.digest(),
                responder: second_responder,
            },
        );

        let mut drained = VecDeque::new();
        overflow.drain(|message| {
            drained.push_back(message);
            None
        });

        assert_eq!(drained.len(), 1);
        assert!(matches!(
            &drained[0],
            Message::Get { digest, responder }
                if *digest == first.digest() && !responder.is_closed()
        ));

        overflow.drain(|message| {
            drained.push_back(message);
            None
        });
        assert_eq!(drained.len(), 2);
        assert!(matches!(
            &drained[1],
            Message::Get { digest, responder }
                if *digest == second.digest() && !responder.is_closed()
        ));
    }

    #[test]
    fn policy_drain_stops_after_returned_message_closes() {
        let mut overflow = <Message<PublicKey, TestMessage> as Policy>::Overflow::default();
        let first = TestMessage::shared(b"first");
        let second = TestMessage::shared(b"second");

        let (first_responder, first_receiver) = commonware_utils::channel::oneshot::channel();
        <Message<PublicKey, TestMessage> as Policy>::handle(
            &mut overflow,
            Message::Get {
                digest: first.digest(),
                responder: first_responder,
            },
        );
        let (second_responder, _second_receiver) = commonware_utils::channel::oneshot::channel();
        <Message<PublicKey, TestMessage> as Policy>::handle(
            &mut overflow,
            Message::Get {
                digest: second.digest(),
                responder: second_responder,
            },
        );

        let mut first_receiver = Some(first_receiver);
        let mut attempts = 0;
        overflow.drain(|message| {
            attempts += 1;
            drop(first_receiver.take());
            Some(message)
        });
        assert_eq!(attempts, 1);

        let mut drained = VecDeque::new();
        while !overflow.is_empty() {
            overflow.drain(|message| {
                drained.push_back(message);
                None
            });
        }
        assert_eq!(drained.len(), 1);
        assert!(matches!(
            &drained[0],
            Message::Get { digest, responder }
                if *digest == second.digest() && !responder.is_closed()
        ));
    }

    async fn spawn_peer_engines(
        context: deterministic::Context,
        oracle: &Oracle<PublicKey, deterministic::Context>,
        registrations: &mut Registrations,
    ) -> BTreeMap<PublicKey, Mailbox<PublicKey, TestMessage>> {
        let mut mailboxes = BTreeMap::new();
        while let Some((peer, network)) = registrations.pop_first() {
            let context = context.child("peer").with_attribute("public_key", &peer);
            let config = Config {
                public_key: peer.clone(),
                mailbox_size: NZUsize!(1024),
                deque_size: CACHE_SIZE,
                priority: false,
                codec_config: RangeCfg::from(..),
                peer_provider: oracle.manager(),
            };
            let (engine, engine_mailbox) =
                Engine::<_, PublicKey, TestMessage, _>::new(context, config);
            mailboxes.insert(peer.clone(), engine_mailbox);
            engine.start(network);
        }

        // Let each engine run until it applies the peer set from `initialize_simulation` so
        // `latest_primary_peers` is populated before any broadcast.
        context.sleep(A_JIFFY).await;
        mailboxes
    }

    #[test_traced]
    fn test_broadcast() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.child("network"), 4, 1.0).await;
            let mailboxes =
                spawn_peer_engines(context.child("peers"), &oracle, &mut registrations).await;

            // Send a single broadcast message from the first peer
            let message = TestMessage::shared(b"hello world test message");
            let first_mailbox = mailboxes.get(peers.first().unwrap()).unwrap().clone();
            assert!(first_mailbox
                .broadcast(Recipients::All, message.clone())
                .accepted());

            // Allow time for propagation
            context.sleep(Duration::from_secs(1)).await;

            // Check that all peers received the message
            for peer in peers.iter() {
                let mailbox = mailboxes.get(peer).unwrap().clone();
                let digest = message.digest();
                let receiver = mailbox.subscribe(digest);
                let received_message = receiver.await.ok();
                assert_eq!(received_message.unwrap(), message.clone());
            }

            // Send another message
            let message = TestMessage::shared(b"hello world again");
            assert!(first_mailbox
                .broadcast(Recipients::All, message.clone())
                .accepted());

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
                initialize_simulation(context.child("network"), 1, 1.0).await;
            let mailboxes =
                spawn_peer_engines(context.child("peers"), &oracle, &mut registrations).await;

            // Set up mailbox for Peer A
            let mailbox_a = mailboxes.get(&peers[0]).unwrap().clone();

            // Create a test message
            let m1 = TestMessage::shared(b"hello world");
            let digest_m1 = m1.digest();

            // Attempt immediate retrieval before broadcasting
            let receiver_before = mailbox_a.get(digest_m1).await;
            assert!(receiver_before.is_none());

            // Attempt retrieval before broadcasting
            let receiver_before = mailbox_a.subscribe(digest_m1);

            // Broadcast the message
            assert!(mailbox_a.broadcast(Recipients::All, m1.clone()).accepted());

            // Wait for the pre-broadcast retrieval to complete
            let msg_before = receiver_before
                .await
                .expect("Pre-broadcast retrieval failed");
            assert_eq!(msg_before, m1);

            // Attempt immediate retrieval after broadcasting
            let receiver_after = mailbox_a.get(digest_m1).await;
            assert_eq!(receiver_after, Some(m1.clone()));

            // Perform a second retrieval after the broadcast
            let receiver_after = mailbox_a.subscribe(digest_m1);

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
                initialize_simulation(context.child("network"), 10, 0.1).await;
            let mailboxes =
                spawn_peer_engines(context.child("peers"), &oracle, &mut registrations).await;

            // Create a message and grab an arbitrary mailbox
            let message = TestMessage::shared(b"hello world test message");
            let first_mailbox = mailboxes.get(peers.first().unwrap()).unwrap().clone();

            // Retry until all peers receive the message (or timeout)
            let digest = message.digest();
            for i in 0..100 {
                // Broadcast the message
                assert!(first_mailbox
                    .broadcast(Recipients::All, message.clone())
                    .accepted());
                context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

                // Check if all peers received the message
                let mut all_received = true;
                for peer in peers.iter() {
                    let mailbox = mailboxes.get(peer).unwrap().clone();
                    let receiver = mailbox.subscribe(digest);
                    let has = match context.timeout(A_JIFFY, receiver).await {
                        Ok(r) => r.is_ok(),
                        Err(Error::Timeout) => false,
                        Err(e) => panic!("unexpected error: {e:?}"),
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
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.child("network"), 2, 1.0).await;
            let mailboxes =
                spawn_peer_engines(context.child("peers"), &oracle, &mut registrations).await;

            // Broadcast a message
            let message = TestMessage::shared(b"cached message");
            let first_mailbox = mailboxes.get(peers.first().unwrap()).unwrap().clone();
            assert!(first_mailbox
                .broadcast(Recipients::All, message.clone())
                .accepted());

            // Wait for propagation
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Get from cache (should be instant)
            let digest = message.digest();
            let mailbox = mailboxes.get(peers.last().unwrap()).unwrap().clone();
            let receiver = mailbox.subscribe(digest);
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
                initialize_simulation(context.child("network"), 2, 1.0).await;
            let mailboxes =
                spawn_peer_engines(context.child("peers"), &oracle, &mut registrations).await;

            // Request nonexistent message from two nodes
            let message = TestMessage::shared(b"future message");
            let digest = message.digest();
            let mailbox1 = mailboxes.get(&peers[0]).unwrap().clone();
            let mailbox2 = mailboxes.get(&peers[1]).unwrap().clone();
            let receiver = mailbox1.subscribe(digest);

            // Create two other requests which are dropped
            let dummy1 = mailbox1.subscribe(digest);
            let dummy2 = mailbox2.subscribe(digest);
            drop(dummy1);
            drop(dummy2);

            // Broadcast the message
            assert!(mailbox1
                .broadcast(Recipients::All, message.clone())
                .accepted());

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
                initialize_simulation(context.child("network"), 2, 1.0).await;
            let mailboxes =
                spawn_peer_engines(context.child("peers"), &oracle, &mut registrations).await;

            // Broadcast messages exceeding cache size
            let mailbox = mailboxes.get(&peers[0]).unwrap().clone();
            let mut messages = vec![];
            for i in 0..CACHE_SIZE + 1 {
                messages.push(TestMessage::shared(format!("message {i}").as_bytes()));
            }
            for message in messages.iter() {
                assert!(mailbox
                    .broadcast(Recipients::All, message.clone())
                    .accepted());
            }

            // Wait for propagation
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Check all other messages exist
            let peer_mailbox = mailboxes.get(&peers[1]).unwrap().clone();
            for msg in messages.iter().skip(1) {
                let result = peer_mailbox.subscribe(msg.digest()).await.unwrap();
                assert_eq!(result, msg.clone());
            }

            // Check first message times out
            let receiver = peer_mailbox.subscribe(messages[0].digest());
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
                initialize_simulation(context.child("network"), 3, 1.0).await;
            let mailboxes =
                spawn_peer_engines(context.child("peers"), &oracle, &mut registrations).await;

            // Assign mailboxes for peers A, B, C
            let mailbox_a = mailboxes.get(&peers[0]).unwrap().clone();
            let mailbox_b = mailboxes.get(&peers[1]).unwrap().clone();
            let mailbox_c = mailboxes.get(&peers[2]).unwrap().clone();

            // Create and broadcast message M1 from A
            let m1 = TestMessage::shared(b"message M1");
            let digest_m1 = m1.digest();
            assert!(mailbox_a.broadcast(Recipients::All, m1.clone()).accepted());
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Broadcast M1 from C
            assert!(mailbox_c.broadcast(Recipients::All, m1.clone()).accepted());
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // M1 is now in A's and C's deques in B's engine

            // Peer A broadcasts 10 new messages to evict M1 from A's deque
            let mut new_messages_a = Vec::with_capacity(CACHE_SIZE);
            for i in 0..CACHE_SIZE {
                new_messages_a.push(TestMessage::shared(format!("A{i}").as_bytes()));
            }
            for msg in &new_messages_a {
                assert!(mailbox_a.broadcast(Recipients::All, msg.clone()).accepted());
            }
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Verify B can still get M1 (in C's deque)
            let receiver = mailbox_b.subscribe(digest_m1);
            let received = receiver.await.expect("M1 should be retrievable");
            assert_eq!(received, m1);

            // Peer C broadcasts 10 new messages to evict M1 from C's deque
            let mut new_messages_c = Vec::with_capacity(CACHE_SIZE);
            for i in 0..CACHE_SIZE {
                new_messages_c.push(TestMessage::shared(format!("C{i}").as_bytes()));
            }
            for msg in &new_messages_c {
                assert!(mailbox_c.broadcast(Recipients::All, msg.clone()).accepted());
            }
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Verify B cannot get M1 (evicted from all deques)
            let receiver = mailbox_b.subscribe(digest_m1);
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
                initialize_simulation(context.child("network"), 4, 1.0).await;

            let sender_pk = peers[0].clone();
            let target_peer = peers[1].clone();
            let non_target_peer = peers[2].clone();

            let mailboxes =
                spawn_peer_engines(context.child("peers"), &oracle, &mut registrations).await;
            let sender_mb = mailboxes.get(&sender_pk).unwrap().clone();

            let msg = TestMessage::shared(b"selective-broadcast");
            assert!(sender_mb
                .broadcast(Recipients::One(target_peer.clone()), msg.clone())
                .accepted());

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
                initialize_simulation(context.child("network"), 3, 1.0).await;
            let mailboxes =
                spawn_peer_engines(context.child("peers"), &oracle, &mut registrations).await;

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
            assert!(mb0.broadcast(Recipients::All, dup.clone()).accepted());
            assert!(mb1.broadcast(Recipients::All, dup.clone()).accepted());
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // observer must get it now
            assert_eq!(obs.get(digest).await, Some(dup.clone()));

            // Evict from p0's deque only
            for i in 0..CACHE_SIZE {
                let spam = TestMessage::shared(format!("p0-{i}").into_bytes());
                assert!(mb0.broadcast(Recipients::All, spam).accepted());
            }
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;
            assert_eq!(obs.get(digest).await, Some(dup.clone()));

            // Evict from p1's deque as well
            for i in 0..CACHE_SIZE {
                let spam = TestMessage::shared(format!("p1-{i}").into_bytes());
                assert!(mb1.broadcast(Recipients::All, spam).accepted());
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
                    initialize_simulation(context.child("network"), 1, 1.0).await;
                let mailboxes =
                    spawn_peer_engines(context.child("peers"), &oracle, &mut registrations).await;

                let sender1 = peers[0].clone();
                let mb1 = mailboxes.get(&sender1).unwrap().clone();

                // Three messages with distinct digests.
                let m1 = TestMessage::shared(b"content-1");
                let m2 = TestMessage::shared(b"content-2");
                let m3 = TestMessage::shared(b"content-3");
                assert!(mb1.broadcast(Recipients::All, m1.clone()).accepted());
                assert!(mb1.broadcast(Recipients::All, m2.clone()).accepted());
                assert!(mb1.broadcast(Recipients::All, m3.clone()).accepted());

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
                initialize_simulation(context.child("network"), 3, 1.0).await;

            let attacker = peers[0].clone();
            let honest = peers[1].clone();
            let victim = peers[2].clone();

            let (mut attacker_sender, _) = registrations.remove(&attacker).unwrap();
            let mailboxes =
                spawn_peer_engines(context.child("peers"), &oracle, &mut registrations).await;
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
            assert!(honest_mailbox
                .broadcast(Recipients::One(victim.clone()), message.clone())
                .accepted());
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            let received = victim_mailbox
                .subscribe(message.digest())
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
                initialize_simulation(context.child("network"), 1, 1.0).await;
            let peer = peers[0].clone();
            let (sender, receiver) = registrations.remove(&peer).unwrap();

            let engine_context = context.child("waiter_cleanup");
            let config = Config {
                public_key: peer,
                mailbox_size: NZUsize!(1024),
                deque_size: CACHE_SIZE,
                priority: false,
                codec_config: RangeCfg::from(..),
                peer_provider: oracle.manager(),
            };
            let (engine, mailbox) =
                Engine::<_, PublicKey, TestMessage, _>::new(engine_context, config);
            engine.start((sender, receiver));

            let missing = TestMessage::shared(b"never-arrives");
            let missing_digest = missing.digest();
            let rx1 = mailbox.subscribe(missing_digest);
            let rx2 = mailbox.subscribe(missing_digest);

            // Ensure subscriptions are processed and waiters are reflected in metrics.
            let _ = mailbox
                .get(TestMessage::shared(b"before-cleanup").digest())
                .await;
            context.sleep(A_JIFFY).await;
            let metrics_before = context.encode();
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

            let metrics_after = context.encode();
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
        while let Some((peer, network)) = registrations.pop_first() {
            let ctx = context.child("peer").with_attribute("public_key", &peer);
            let config = Config {
                public_key: peer.clone(),
                mailbox_size: NZUsize!(1024),
                deque_size: CACHE_SIZE,
                priority: false,
                codec_config: RangeCfg::from(..),
                peer_provider: oracle.manager(),
            };
            let (engine, engine_mailbox) = Engine::<_, PublicKey, TestMessage, _>::new(ctx, config);
            mailboxes.insert(peer.clone(), engine_mailbox);
            handles.push(engine.start(network));
        }

        context.sleep(A_JIFFY).await;
        (mailboxes, handles)
    }

    #[test_traced]
    fn test_operations_after_shutdown_do_not_panic() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.child("network"), 2, 1.0).await;
            let (mut mailboxes, handles) = spawn_peer_engines_with_handles(
                context.child("peers"),
                &oracle,
                &mut registrations,
            )
            .await;

            // Broadcast a message to verify network is functional
            let message = TestMessage::shared(b"test message");
            let mailbox = mailboxes.remove(&peers[0]).unwrap();
            assert!(
                mailbox
                    .broadcast(Recipients::All, message.clone())
                    .accepted(),
                "broadcast should succeed before shutdown"
            );

            // Abort all engine handles
            for handle in handles {
                handle.abort();
            }
            context.sleep(Duration::from_millis(100)).await;

            // All operations should not panic after shutdown

            // Broadcast should not panic
            assert_eq!(
                mailbox.broadcast(Recipients::All, message.clone()),
                Feedback::Closed,
                "broadcast after shutdown should return Closed"
            );

            // Subscribe should not panic (returns Canceled since engine is down)
            let digest = message.digest();
            let receiver = mailbox.subscribe(digest);
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
                initialize_simulation(context.child("network"), 2, 1.0).await;

            let (mailboxes, handles) = spawn_peer_engines_with_handles(
                context.child("peers"),
                &oracle,
                &mut registrations,
            )
            .await;

            // Allow tasks to start
            context.sleep(Duration::from_millis(100)).await;

            // Count running tasks under the peers prefix
            let running_before = count_running_tasks(&context, "peers");
            assert!(
                running_before > 0,
                "at least one peer engine task should be running"
            );

            // Verify network is functional
            let message = TestMessage::shared(b"test message");
            let mailbox = mailboxes.get(&peers[0]).unwrap().clone();
            assert!(
                mailbox
                    .broadcast(Recipients::All, message.clone())
                    .accepted(),
                "broadcast should succeed"
            );

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

            // Verify all peer engine tasks are stopped
            let running_after = count_running_tasks(&context, "peers");
            assert_eq!(
                running_after, 0,
                "all peer engine tasks should be stopped, but {running_after} still running"
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
                initialize_simulation(context.child("network"), 3, 1.0).await;

            let peer_a = peers[0].clone();
            let peer_b = peers[1].clone();
            let peer_c = peers[2].clone();

            // Spawn peer B's engine with its own manager.
            let network_b = registrations.remove(&peer_b).unwrap();
            let config_b = Config {
                public_key: peer_b.clone(),
                mailbox_size: NZUsize!(1024),
                deque_size: CACHE_SIZE,
                priority: false,
                codec_config: RangeCfg::from(..),
                peer_provider: oracle.manager(),
            };
            let (engine_b, mailbox_b) =
                Engine::<_, PublicKey, TestMessage, _>::new(context.child("peer_b"), config_b);
            engine_b.start(network_b);

            // Spawn remaining peer engines.
            let mut mailboxes = BTreeMap::new();
            mailboxes.insert(peer_b.clone(), mailbox_b);
            for (peer, network) in registrations {
                let ctx = context.child("peer").with_attribute("public_key", &peer);
                let config = Config {
                    public_key: peer.clone(),
                    mailbox_size: NZUsize!(1024),
                    deque_size: CACHE_SIZE,
                    priority: false,
                    codec_config: RangeCfg::from(..),
                    peer_provider: oracle.manager(),
                };
                let (engine, mailbox) = Engine::<_, PublicKey, TestMessage, _>::new(ctx, config);
                mailboxes.insert(peer, mailbox);
                engine.start(network);
            }
            context.sleep(A_JIFFY).await;

            // Peer A broadcasts a message.
            let msg = TestMessage::shared(b"eviction-test");
            let mailbox_a = mailboxes.get(&peer_a).unwrap().clone();
            assert!(mailbox_a.broadcast(Recipients::All, msg.clone()).accepted());
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
            oracle.manager().track(1, remaining).await;
            context.sleep(A_JIFFY).await;

            // Peer A's deque was evicted; the message should be gone.
            assert!(
                mailbox_b.get(msg.digest()).await.is_none(),
                "message should be evicted after peer A left the peer set"
            );
        });
    }

    #[test_traced]
    fn test_peer_set_update_evicts_peers_not_in_latest_set_even_if_still_in_overlap() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            // Use tracked_peer_sets=2 so old sets are retained in the window.
            let (network, oracle) = Network::<deterministic::Context, PublicKey>::new(
                context.child("network"),
                commonware_p2p::simulated::Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(2),
                },
            );
            network.start();

            let mut schemes = (0..3)
                .map(|i| PrivateKey::from_seed(i as u64))
                .collect::<Vec<_>>();
            schemes.sort_by_key(|s| s.public_key());
            let peers: Vec<PublicKey> = schemes.iter().map(|c| c.public_key()).collect();
            let peer_a = peers[0].clone();
            let peer_b = peers[1].clone();
            let peer_c = peers[2].clone();

            let mut registrations: Registrations = BTreeMap::new();
            for peer in peers.iter() {
                let (sender, receiver) = oracle
                    .control(peer.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                registrations.insert(peer.clone(), (sender, receiver));
            }
            let link = Link {
                latency: NETWORK_SPEED,
                jitter: Duration::ZERO,
                success_rate: 1.0,
            };
            for p1 in peers.iter() {
                for p2 in peers.iter() {
                    if p2 != p1 {
                        oracle
                            .add_link(p1.clone(), p2.clone(), link.clone())
                            .await
                            .unwrap();
                    }
                }
            }

            // Track all three peers in set 0.
            let all = commonware_utils::ordered::Set::from_iter_dedup(peers.clone());
            oracle.manager().track(0, all).await;

            // Spawn engines for B (with its own manager) and the rest.
            let network_b = registrations.remove(&peer_b).unwrap();
            let config_b = Config {
                public_key: peer_b.clone(),
                mailbox_size: NZUsize!(1024),
                deque_size: CACHE_SIZE,
                priority: false,
                codec_config: RangeCfg::from(..),
                peer_provider: oracle.manager(),
            };
            let (engine_b, mailbox_b) =
                Engine::<_, PublicKey, TestMessage, _>::new(context.child("peer_b"), config_b);
            engine_b.start(network_b);

            let mut mailboxes = BTreeMap::new();
            mailboxes.insert(peer_b.clone(), mailbox_b);
            for (peer, network) in registrations {
                let ctx = context.child("peer").with_attribute("public_key", &peer);
                let config = Config {
                    public_key: peer.clone(),
                    mailbox_size: NZUsize!(1024),
                    deque_size: CACHE_SIZE,
                    priority: false,
                    codec_config: RangeCfg::from(..),
                    peer_provider: oracle.manager(),
                };
                let (engine, mailbox) = Engine::<_, PublicKey, TestMessage, _>::new(ctx, config);
                mailboxes.insert(peer, mailbox);
                engine.start(network);
            }
            context.sleep(A_JIFFY).await;

            // Peer A broadcasts a message. B caches it.
            let msg = TestMessage::shared(b"eviction-latest-test");
            let mailbox_a = mailboxes.get(&peer_a).unwrap().clone();
            assert!(mailbox_a.broadcast(Recipients::All, msg.clone()).accepted());
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            let mailbox_b = mailboxes.get(&peer_b).unwrap().clone();
            assert_eq!(
                mailbox_b.get(msg.digest()).await,
                Some(msg.clone()),
                "peer B should have the message before eviction"
            );

            // Track set 1 with only [B, C]. With tracked_peer_sets=2, both
            // sets 0 and 1 are retained, so A is still in `all.primary`. Buffered caches follow
            // `latest.primary`, though, so A's deque should be evicted immediately.
            let remaining = commonware_utils::ordered::Set::from_iter_dedup(vec![
                peer_b.clone(),
                peer_c.clone(),
            ]);
            oracle.manager().track(1, remaining).await;
            context.sleep(A_JIFFY).await;

            assert!(
                mailbox_b.get(msg.digest()).await.is_none(),
                "message should be evicted: peer A is not in the latest peer set"
            );

            // Peer A is no longer in `latest.primary`, so A does not buffer; send still runs.
            let fresh = TestMessage::shared(b"post-eviction-latest-test");
            assert!(mailbox_a
                .broadcast(Recipients::All, fresh.clone())
                .accepted());
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            assert!(
                mailbox_b.get(fresh.digest()).await.is_none(),
                "message should not be rebuffered after peer A left latest.primary"
            );
        });
    }

    #[test_traced]
    fn test_initial_latest_peer_set_blocks_sender_not_in_latest_primary() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            let (network, oracle) = Network::<deterministic::Context, PublicKey>::new(
                context.child("network"),
                commonware_p2p::simulated::Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let mut schemes = (0..3)
                .map(|i| PrivateKey::from_seed(i as u64))
                .collect::<Vec<_>>();
            schemes.sort_by_key(|s| s.public_key());
            let peers: Vec<PublicKey> = schemes.iter().map(|c| c.public_key()).collect();
            let peer_a = peers[0].clone();
            let peer_b = peers[1].clone();
            let peer_c = peers[2].clone();

            let mut registrations: Registrations = BTreeMap::new();
            for peer in &peers {
                let (sender, receiver) = oracle
                    .control(peer.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                registrations.insert(peer.clone(), (sender, receiver));
            }
            let link = Link {
                latency: NETWORK_SPEED,
                jitter: Duration::ZERO,
                success_rate: 1.0,
            };
            for p1 in &peers {
                for p2 in &peers {
                    if p1 != p2 {
                        oracle
                            .add_link(p1.clone(), p2.clone(), link.clone())
                            .await
                            .unwrap();
                    }
                }
            }

            let latest_primary = commonware_utils::ordered::Set::from_iter_dedup(vec![
                peer_b.clone(),
                peer_c.clone(),
            ]);
            let latest_secondary =
                commonware_utils::ordered::Set::from_iter_dedup(vec![peer_a.clone()]);
            oracle
                .manager()
                .track(0, TrackedPeers::new(latest_primary, latest_secondary))
                .await;

            let mut mailboxes = BTreeMap::new();
            for (peer, network) in registrations {
                let ctx = context.child("peer").with_attribute("public_key", &peer);
                let config = Config {
                    public_key: peer.clone(),
                    mailbox_size: NZUsize!(1024),
                    deque_size: CACHE_SIZE,
                    priority: false,
                    codec_config: RangeCfg::from(..),
                    peer_provider: oracle.manager(),
                };
                let (engine, mailbox) = Engine::<_, PublicKey, TestMessage, _>::new(ctx, config);
                mailboxes.insert(peer, mailbox);
                engine.start(network);
            }
            context.sleep(A_JIFFY).await;

            let mailbox_a = mailboxes.get(&peer_a).unwrap().clone();
            let mailbox_b = mailboxes.get(&peer_b).unwrap().clone();
            let msg = TestMessage::shared(b"startup-latest-primary-only");
            assert!(
                mailbox_a
                    .broadcast(Recipients::All, msg.clone())
                    .accepted(),
                "Recipients::All is accepted locally; cache policy is separate"
            );
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            assert_eq!(
                mailbox_a.get(msg.digest()).await,
                None,
                "sender not in latest.primary should not buffer, including own broadcasts"
            );
            assert!(
                mailbox_b.get(msg.digest()).await.is_none(),
                "peer B should not cache messages from a sender excluded by the initial latest.primary set"
            );
        });
    }

    /// Local `broadcast` queued before the engine run loop starts must still be cached when the
    /// peer is already in `latest.primary` (regression for biased handling of `peer_set_subscription`
    /// vs mailbox).
    #[test_traced]
    fn test_broadcast_queued_before_start_respects_initial_latest_primary() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            // Add a sole peer (self) to the network
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.child("network"), 1, 1.0).await;
            let peer = peers[0].clone();
            let network = registrations.remove(&peer).unwrap();
            let config = Config {
                public_key: peer.clone(),
                mailbox_size: NZUsize!(1024),
                deque_size: CACHE_SIZE,
                priority: false,
                codec_config: RangeCfg::from(..),
                peer_provider: oracle.manager(),
            };
            let (engine, mailbox) =
                Engine::<_, PublicKey, TestMessage, _>::new(context.child("peer"), config);

            // Enqueue a broadcast while the engine task is not running yet (only the mailbox channel)
            let msg = TestMessage::shared(b"queued-before-start");
            assert!(mailbox
                .broadcast(Recipients::All, msg.clone())
                .accepted());

            // Start the engine (now that a message is enqueued)
            engine.start(network);

            assert_eq!(
                mailbox.get(msg.digest()).await,
                Some(msg),
                "sender is already in the initial latest.primary set, so its local broadcast should be cached"
            );
        });
    }

    #[test_traced]
    fn test_engine_starts_before_initial_peer_set_and_delivers_after_tracking() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            let (network, oracle) = Network::<deterministic::Context, PublicKey>::new(
                context.child("network"),
                commonware_p2p::simulated::Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let mut schemes = (0..2)
                .map(|i| PrivateKey::from_seed(i as u64))
                .collect::<Vec<_>>();
            schemes.sort_by_key(|s| s.public_key());
            let peers: Vec<PublicKey> = schemes.iter().map(|c| c.public_key()).collect();
            let peer_a = peers[0].clone();
            let peer_b = peers[1].clone();

            let mut registrations: Registrations = BTreeMap::new();
            for peer in &peers {
                let (sender, receiver) = oracle
                    .control(peer.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                registrations.insert(peer.clone(), (sender, receiver));
            }

            let link = Link {
                latency: NETWORK_SPEED,
                jitter: Duration::ZERO,
                success_rate: 1.0,
            };
            for p1 in &peers {
                for p2 in &peers {
                    if p1 != p2 {
                        oracle
                            .add_link(p1.clone(), p2.clone(), link.clone())
                            .await
                            .unwrap();
                    }
                }
            }

            let mut mailboxes = BTreeMap::new();
            for (peer, network) in registrations {
                let ctx = context.child("peer").with_attribute("public_key", &peer);
                let config = Config {
                    public_key: peer.clone(),
                    mailbox_size: NZUsize!(1024),
                    deque_size: CACHE_SIZE,
                    priority: false,
                    codec_config: RangeCfg::from(..),
                    peer_provider: oracle.manager(),
                };
                let (engine, mailbox) = Engine::<_, PublicKey, TestMessage, _>::new(ctx, config);
                mailboxes.insert(peer, mailbox);
                engine.start(network);
            }

            let mailbox_a = mailboxes.get(&peer_a).unwrap().clone();
            let mailbox_b = mailboxes.get(&peer_b).unwrap().clone();

            let before = TestMessage::shared(b"before-tracking");
            assert!(
                mailbox_a
                    .broadcast(Recipients::All, before.clone())
                    .accepted(),
                "broadcast request should be accepted before a peer set is tracked"
            );
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            assert_eq!(
                mailbox_a.get(before.digest()).await,
                None,
                "without latest.primary, local broadcasts are not buffered"
            );
            assert!(
                mailbox_b.get(before.digest()).await.is_none(),
                "without latest.primary, remote peers do not cache inbound messages"
            );

            oracle
                .manager()
                .track(
                    0,
                    commonware_utils::ordered::Set::from_iter_dedup(peers.clone()),
                )
                .await;
            context.sleep(A_JIFFY).await;

            let after = TestMessage::shared(b"after-tracking");
            assert!(mailbox_a
                .broadcast(Recipients::All, after.clone())
                .accepted());
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            assert_eq!(mailbox_b.get(after.digest()).await, Some(after));
        });
    }

    #[test_traced]
    fn test_peer_set_update_preserves_shared_messages() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            let (peers, mut registrations, oracle) =
                initialize_simulation(context.child("network"), 3, 1.0).await;

            let peer_a = peers[0].clone();
            let peer_b = peers[1].clone();
            let peer_c = peers[2].clone();

            // Spawn peer B with its own manager.
            let network_b = registrations.remove(&peer_b).unwrap();
            let config_b = Config {
                public_key: peer_b.clone(),
                mailbox_size: NZUsize!(1024),
                deque_size: CACHE_SIZE,
                priority: false,
                codec_config: RangeCfg::from(..),
                peer_provider: oracle.manager(),
            };
            let (engine_b, mailbox_b) =
                Engine::<_, PublicKey, TestMessage, _>::new(context.child("peer_b"), config_b);
            engine_b.start(network_b);

            // Spawn remaining peer engines.
            let mut mailboxes = BTreeMap::new();
            mailboxes.insert(peer_b.clone(), mailbox_b);
            for (peer, network) in registrations {
                let ctx = context.child("peer").with_attribute("public_key", &peer);
                let config = Config {
                    public_key: peer.clone(),
                    mailbox_size: NZUsize!(1024),
                    deque_size: CACHE_SIZE,
                    priority: false,
                    codec_config: RangeCfg::from(..),
                    peer_provider: oracle.manager(),
                };
                let (engine, mailbox) = Engine::<_, PublicKey, TestMessage, _>::new(ctx, config);
                mailboxes.insert(peer, mailbox);
                engine.start(network);
            }
            context.sleep(A_JIFFY).await;

            // Both A and C broadcast the same message.
            let msg = TestMessage::shared(b"shared-msg");
            let mailbox_a = mailboxes.get(&peer_a).unwrap().clone();
            let mailbox_c = mailboxes.get(&peer_c).unwrap().clone();
            assert!(mailbox_a.broadcast(Recipients::All, msg.clone()).accepted());
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;
            assert!(mailbox_c.broadcast(Recipients::All, msg.clone()).accepted());
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // B has the message in both A's and C's deques (ref count = 2).
            let mailbox_b = mailboxes.get(&peer_b).unwrap().clone();
            assert_eq!(mailbox_b.get(msg.digest()).await, Some(msg.clone()));

            // Evict peer A only; C is still in the latest primary set.
            let remaining = commonware_utils::ordered::Set::from_iter_dedup(vec![peer_b, peer_c]);
            oracle.manager().track(1, remaining).await;
            context.sleep(A_JIFFY).await;

            // Message should still be available (C's deque still holds it).
            assert_eq!(
                mailbox_b.get(msg.digest()).await,
                Some(msg.clone()),
                "message should survive when another peer in the primary set still references it"
            );
        });
    }
}

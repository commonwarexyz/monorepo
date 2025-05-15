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
    use super::{mocks::TestMessage, *};
    use crate::Broadcaster;
    use commonware_codec::RangeCfg;
    use commonware_cryptography::{
        ed25519::PublicKey, sha256::Digest as Sha256Digest, Committable, Digestible, Ed25519,
        Signer,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::{
        simulated::{Link, Network, Oracle, Receiver, Sender},
        Recipients,
    };
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
    ) -> BTreeMap<PublicKey, Mailbox<PublicKey, Sha256Digest, Sha256Digest, TestMessage>> {
        let mut mailboxes = BTreeMap::new();
        while let Some((peer, network)) = registrations.pop_first() {
            let context = context.with_label(&peer.to_string());
            let config = Config {
                public_key: peer.clone(),
                mailbox_size: 1024,
                deque_size: CACHE_SIZE,
                priority: false,
                codec_config: RangeCfg::from(..),
            };
            let (engine, engine_mailbox) =
                Engine::<_, PublicKey, Sha256Digest, Sha256Digest, TestMessage>::new(
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
            let message = TestMessage::shared(b"hello world test message");
            let mut first_mailbox = mailboxes.get(peers.first().unwrap()).unwrap().clone();
            let result = first_mailbox
                .broadcast(Recipients::All, message.clone())
                .await;

            // Allow time for propagation
            context.sleep(Duration::from_secs(1)).await;

            // Check that all peers received the message
            for peer in peers.iter() {
                let mut mailbox = mailboxes.get(peer).unwrap().clone();
                let commitment = message.commitment();
                let receiver = mailbox.subscribe(None, commitment, None).await;
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
                let mut mailbox = mailboxes.get(peer).unwrap().clone();
                let commitment = message.commitment();
                let receiver = mailbox.get(None, commitment, None).await;
                if !receiver.is_empty() {
                    assert_eq!(receiver, vec![message.clone()]);
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
            let (peers, mut registrations, _oracle) =
                initialize_simulation(context.clone(), 1, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &mut registrations);

            // Set up mailbox for Peer A
            let mut mailbox_a = mailboxes.get(&peers[0]).unwrap().clone();

            // Create a test message
            let m1 = TestMessage::shared(b"hello world");
            let commitment_m1 = m1.commitment();

            // Attempt immediate retrieval before broadcasting
            let receiver_before = mailbox_a.get(None, commitment_m1, None).await;
            assert!(receiver_before.is_empty());

            // Attempt retrieval before broadcasting
            let receiver_before = mailbox_a.subscribe(None, commitment_m1, None).await;

            // Broadcast the message
            let result = mailbox_a.broadcast(Recipients::All, m1.clone()).await;
            assert_eq!(result.await.unwrap().len(), peers.len() - 1);

            // Wait for the pre-broadcast retrieval to complete
            let msg_before = receiver_before
                .await
                .expect("Pre-broadcast retrieval failed");
            assert_eq!(msg_before, m1);

            // Attempt immediate retrieval after broadcasting
            let receiver_after = mailbox_a.get(None, commitment_m1, None).await;
            assert_eq!(receiver_after, vec![m1.clone()]);

            // Perform a second retrieval after the broadcast
            let receiver_after = mailbox_a.subscribe(None, commitment_m1, None).await;

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
            let message = TestMessage::shared(b"hello world test message");
            let mut first_mailbox = mailboxes.get(peers.first().unwrap()).unwrap().clone();

            // Retry until all peers receive the message (or timeout)
            let commitment = message.commitment();
            for i in 0..100 {
                // Broadcast the message
                let result = first_mailbox
                    .broadcast(Recipients::All, message.clone())
                    .await;
                context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

                // Check if all peers received the message
                let mut all_received = true;
                for peer in peers.iter() {
                    let mut mailbox = mailboxes.get(peer).unwrap().clone();
                    let receiver = mailbox.subscribe(None, commitment, None).await;
                    let has = select! {
                        _ = context.sleep(A_JIFFY) => {false},
                        r = receiver => { r.is_ok() },
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
            let (peers, mut registrations, _oracle) =
                initialize_simulation(context.clone(), 2, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &mut registrations);

            // Broadcast a message
            let message = TestMessage::shared(b"cached message");
            let mut first_mailbox = mailboxes.get(peers.first().unwrap()).unwrap().clone();
            let result = first_mailbox
                .broadcast(Recipients::All, message.clone())
                .await;
            assert_eq!(result.await.unwrap().len(), peers.len() - 1);

            // Wait for propagation
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Get from cache (should be instant)
            let commitment = message.commitment();
            let mut mailbox = mailboxes.get(peers.last().unwrap()).unwrap().clone();
            let receiver = mailbox.subscribe(None, commitment, None).await;
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
            let message = TestMessage::shared(b"future message");
            let commitment = message.commitment();
            let mut mailbox1 = mailboxes.get(&peers[0]).unwrap().clone();
            let mut mailbox2 = mailboxes.get(&peers[1]).unwrap().clone();
            let receiver = mailbox1.subscribe(None, commitment, None).await;

            // Create two other requests which are dropped
            let dummy1 = mailbox1.subscribe(None, commitment, None).await;
            let dummy2 = mailbox2.subscribe(None, commitment, None).await;
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
            let (peers, mut registrations, _oracle) =
                initialize_simulation(context.clone(), 2, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &mut registrations);

            // Broadcast messages exceeding cache size
            let mut mailbox = mailboxes.get(&peers[0]).unwrap().clone();
            let mut messages = vec![];
            for i in 0..CACHE_SIZE + 1 {
                messages.push(TestMessage::shared(format!("message {}", i).as_bytes()));
            }
            for message in messages.iter() {
                let result = mailbox.broadcast(Recipients::All, message.clone()).await;
                assert_eq!(result.await.unwrap().len(), peers.len() - 1);
            }

            // Wait for propagation
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Check all other messages exist
            let mut peer_mailbox = mailboxes.get(&peers[1]).unwrap().clone();
            for msg in messages.iter().skip(1) {
                let result = peer_mailbox
                    .subscribe(None, msg.commitment(), None)
                    .await
                    .await
                    .unwrap();
                assert_eq!(result, msg.clone());
            }

            // Check first message times out
            let receiver = peer_mailbox
                .subscribe(None, messages[0].commitment(), None)
                .await;
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
            let m1 = TestMessage::shared(b"message M1");
            let commitment_m1 = m1.commitment();
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
                new_messages_a.push(TestMessage::shared(format!("A{}", i).as_bytes()));
            }
            for msg in &new_messages_a {
                let result = mailbox_a.broadcast(Recipients::All, msg.clone()).await;
                assert_eq!(result.await.unwrap().len(), peers.len() - 1);
            }
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Verify B can still get M1 (in C's deque)
            let receiver = mailbox_b.subscribe(None, commitment_m1, None).await;
            let received = receiver.await.expect("M1 should be retrievable");
            assert_eq!(received, m1);

            // Peer C broadcasts 10 new messages to evict M1 from C's deque
            let mut new_messages_c = Vec::with_capacity(CACHE_SIZE);
            for i in 0..CACHE_SIZE {
                new_messages_c.push(TestMessage::shared(format!("C{}", i).as_bytes()));
            }
            for msg in &new_messages_c {
                let result = mailbox_c.broadcast(Recipients::All, msg.clone()).await;
                assert_eq!(result.await.unwrap().len(), peers.len() - 1);
            }
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // Verify B cannot get M1 (evicted from all deques)
            let receiver = mailbox_b.subscribe(None, commitment_m1, None).await;
            select! {
                _ = context.sleep(A_JIFFY) => {},
                _ = receiver => { panic!("M1 should not be retrievable"); },
            }
        });
    }

    #[test_traced]
    fn test_selective_recipients() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            let (peers, mut registrations, _oracle) =
                initialize_simulation(context.clone(), 4, 1.0).await;

            let sender_pk = peers[0].clone();
            let target_peer = peers[1].clone();
            let non_target_peer = peers[2].clone();

            let mailboxes = spawn_peer_engines(context.clone(), &mut registrations);
            let mut sender_mb = mailboxes.get(&sender_pk).unwrap().clone();

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
                .get(None, msg.commitment(), None)
                .await;
            assert_eq!(got_target, vec![msg.clone()]);

            // Non-target peer should not retrieve the message.
            let got_other = mailboxes
                .get(&non_target_peer)
                .unwrap()
                .clone()
                .get(None, msg.commitment(), None)
                .await;
            assert!(got_other.is_empty());
        });
    }

    #[test_traced]
    fn test_sender_filter_subscribe() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|context| async move {
            let (peers, mut registrations, _oracle) =
                initialize_simulation(context.clone(), 4, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &mut registrations);

            let sender1 = peers[0].clone();
            let sender2 = peers[1].clone();
            let sender3 = peers[2].clone();

            let mut mb1 = mailboxes.get(&sender1).unwrap().clone();
            let mut mb2 = mailboxes.get(&sender2).unwrap().clone();
            let mut mb3 = mailboxes.get(&sender3).unwrap().clone();

            let msg = TestMessage::shared(b"from-one");
            let id = msg.commitment();

            // mb2 waits for `id` but only if it originates from `sender1`.
            let mut recv = mb2.subscribe(Some(sender1.clone()), id, None).await;

            // Broadcast from the wrong sender (should *not* satisfy).
            mb3.broadcast(Recipients::All, msg.clone())
                .await
                .await
                .unwrap();

            // Wait for the broadcast to propagate
            context.sleep(A_JIFFY).await;

            // Check that the receiver is still waiting
            assert!(recv.try_recv().unwrap().is_none());

            // Correct sender broadcasts and subscription fulfills.
            mb1.broadcast(Recipients::All, msg.clone())
                .await
                .await
                .unwrap();
            assert_eq!(recv.await.unwrap(), msg);
        });
    }

    #[test_traced]
    fn test_get_all_for_commitment() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            let (peers, mut registrations, _oracle) =
                initialize_simulation(context.clone(), 4, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &mut registrations);

            let sender1 = peers[0].clone();
            let sender2 = peers[1].clone();

            let mut mb1 = mailboxes.get(&sender1).unwrap().clone();
            let mut mb2 = mailboxes.get(&sender2).unwrap().clone();

            // Two messages share commitment but have distinct digests.
            let m1 = TestMessage::new(b"id", b"content-1");
            let m2 = TestMessage::new(b"id", b"content-2");
            let m3 = TestMessage::new(b"other-id", b"content-3");
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

            // Wait for propagation
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;

            // `get` with digest=None returns both.
            let mut got = mb2.get(None, m1.commitment(), None).await;
            got.sort_by_key(|m| m.content.clone());
            assert_eq!(got, vec![m1.clone(), m2.clone()]);

            // `get` with digest=Some returns only the first.
            let got = mb2.get(None, m1.commitment(), Some(m1.digest())).await;
            assert_eq!(got, vec![m1.clone()]);

            // `get` with digest=None returns only one with a duplicate digest.
            let got = mb2.get(None, m3.commitment(), None).await;
            assert_eq!(got, vec![m3.clone()]);

            // `get` with digest=Some that does not exist returns empty.
            let got = mb2.get(None, m3.commitment(), Some(m2.digest())).await;
            assert!(got.is_empty());

            // `get` with digest=None from a single sender should return all messages.
            let mut got = mb2.get(Some(sender1.clone()), m1.commitment(), None).await;
            got.sort_by_key(|m| m.content.clone());
            assert_eq!(got, vec![m1.clone(), m2.clone()]);
            let got = mb2.get(Some(sender1.clone()), m3.commitment(), None).await;
            assert_eq!(got, vec![m3.clone()]);
        });
    }

    #[test_traced]
    fn test_ref_count_across_peers() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|context| async move {
            // three peers so we can observe from a third
            let (peers, mut registrations, _oracle) =
                initialize_simulation(context.clone(), 3, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &mut registrations);

            let p0 = peers[0].clone();
            let p1 = peers[1].clone();
            let observer = peers[2].clone();

            let mut mb0 = mailboxes.get(&p0).unwrap().clone();
            let mut mb1 = mailboxes.get(&p1).unwrap().clone();
            let mut obs = mailboxes.get(&observer).unwrap().clone();

            // the message duplicated by p0 and p1
            let dup = TestMessage::shared(b"dup");
            let id = dup.commitment();

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
            assert_eq!(obs.get(None, id, None).await, vec![dup.clone()]);

            // Evict from p0’s deque only
            for i in 0..CACHE_SIZE {
                let spam = TestMessage::shared(format!("p0-{i}").into_bytes());
                mb0.broadcast(Recipients::All, spam).await.await.unwrap();
            }
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;
            assert_eq!(obs.get(None, id, None).await, vec![dup.clone()]);

            // Evict from p1’s deque as well
            for i in 0..CACHE_SIZE {
                let spam = TestMessage::shared(format!("p1-{i}").into_bytes());
                mb1.broadcast(Recipients::All, spam).await.await.unwrap();
            }
            context.sleep(NETWORK_SPEED_WITH_BUFFER).await;
            assert!(obs.get(None, id, None).await.is_empty());
        });
    }

    #[test_traced]
    fn test_digest_filtered_waiter() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|context| async move {
            let (peers, mut registrations, _oracle) =
                initialize_simulation(context.clone(), 3, 1.0).await;
            let mailboxes = spawn_peer_engines(context.clone(), &mut registrations);

            let owner = peers[0].clone();
            let spoiler = peers[1].clone();
            let waiter = peers[2].clone();

            let mut mb_owner = mailboxes.get(&owner).unwrap().clone();
            let mut mb_spoiler = mailboxes.get(&spoiler).unwrap().clone();
            let mut mb_waiter = mailboxes.get(&waiter).unwrap().clone();

            // two messages share commitment but differ in digest
            let wanted = TestMessage::new(b"same-id", b"wanted");
            let not_want = TestMessage::new(b"same-id", b"noise");

            // waiter only wants the *wanted* digest and only from `owner`
            let mut recv = mb_waiter
                .subscribe(
                    Some(owner.clone()),
                    wanted.commitment(),
                    Some(wanted.digest()),
                )
                .await;

            // spoiler broadcasts the *wanted* digest
            mb_spoiler
                .broadcast(Recipients::All, wanted.clone())
                .await
                .await
                .unwrap();
            context.sleep(A_JIFFY).await;
            assert!(recv.try_recv().unwrap().is_none());

            // owner broadcasts a *different* digest with same commitment
            mb_owner
                .broadcast(Recipients::All, not_want.clone())
                .await
                .await
                .unwrap();
            context.sleep(A_JIFFY).await;
            assert!(recv.try_recv().unwrap().is_none());

            // owner finally broadcasts the exact match
            mb_owner
                .broadcast(Recipients::All, wanted.clone())
                .await
                .await
                .unwrap();
            assert_eq!(recv.await.unwrap(), wanted);
        });
    }
}

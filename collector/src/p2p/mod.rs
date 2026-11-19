//! Collect responses from peers on a [commonware_p2p] network.
//!
//! # Overview
//!
//! An [Engine] runs on every peer and plays both roles. As an originator it sends the requests
//! enqueued through its [Mailbox] and passes the responses it collects to its
//! [Monitor](crate::Monitor). As a handler it passes each request it receives to its
//! [Handler](crate::Handler) and returns any response to the peer that sent the request.
//!
//! Requests and responses share the p2p channel passed to [Engine::start], and the engine handles
//! them in the order they arrive.
//!
//! ```text
//!                  peer A                                              peer B
//!     application             Engine                       Engine               application
//! (Mailbox, Monitor)       (originator)                   (handler)              (Handler)
//!          |                     |                            |                      |
//!          |--- send ----------->|                            |                      |
//!          |                     |--- request --------------->|                      |
//!          |                     |                            |--- process --------->|
//!          |                     |                            |<-- response ---------|
//!          |                     |<-- response ---------------|                      |
//!          |<-- collected -------|                            |                      |
//! ```
//!
//! # Collections
//!
//! A [collection](crate::Originator) starts when a commitment is sent to at least one peer and
//! lasts until the commitment is cancelled. Sending the commitment again adds the recipients it is
//! sent to. Requests that share a commitment may differ in content, and so may the responses to
//! them.
//!
//! The engine collects the first response for the commitment from each recipient, and its event
//! loop passes each one to [Monitor::collected](crate::Monitor::collected) with the number
//! collected so far. A response from a peer that already responded, from a peer the commitment was
//! not sent to, or for a commitment with no collection is ignored without blocking its sender.
//!
//! ```text
//! commands        send(c: X, Y)           send(c: Z)        cancel(c)   send(c: X)
//!                 |                       |                 |           |
//! collection      +=========================================+           +================
//! response from         X     Y     X           W     Z           Y           X     X
//! count                 1     2     .           .     3           .           1     .
//! ignored as                    duplicate   not asked         cancelled         duplicate
//! ```
//!
//! `send(c: X, Y)` sends a request with commitment `c` to peers X and Y, and each command is drawn
//! where the engine handles it. A number is the count reported with a collected response and `.`
//! is an ignored response.
//!
//! A response is matched by its commitment and its sender, not by the request it answers. A
//! recipient's first response to a collection is collected even when it answers a request sent
//! before the last cancel:
//!
//! ```text
//! commands        send(c: X)              cancel(c)   send(c: X)
//!                 |                       |           |
//! collection      +=======================+           +==================================
//! answer to 1st         X ------------------------------------> 1
//! answer to 2nd                                             X ------------> .
//! ignored as                                                            duplicate
//! ```
//!
//! Each arrow runs from the time X answers a send to the time its response arrives. Two requests
//! to the same peer that each need a response must have distinct commitments.
//!
//! # Delivery
//!
//! The engine attempts each request and each response once. A recipient over its rate limit is
//! skipped and is not added to the collection, and a request sent to no recipient starts no
//! collection. The application is not told which recipients were skipped.
//!
//! The channel's quota applies separately to what the engine sends a peer and to what it receives
//! from that peer, and requests and responses count against it together. A response to a peer over
//! the send limit is dropped. The quota should therefore allow the combined rate and bursts of the
//! requests and the responses that one peer sends another.
//!
//! The engine has no timeouts and no retries. The application retries a request by sending it
//! again, and it must cancel the commitment once it needs no more responses.
//!
//! # Invalid Messages
//!
//! A peer that sends a message the engine cannot decode is blocked through [Config::blocker]. All
//! peers must therefore use the same request and response types, with codec configurations that
//! accept each other's messages.
//!
//! # Serving Requests
//!
//! The engine calls [Handler::process](crate::Handler::process) from its event loop and keeps a
//! request pending until the handler sends its response or drops the sender. Nothing limits how
//! many requests are pending or for how long, so a handler that answers later must bound the
//! requests it holds from each peer.
//!
//! # Backpressure
//!
//! The [Mailbox] never waits for the engine. [Config::mailbox_size] requests and cancellations
//! fit in the engine's inbox. Later ones wait behind it in order and without limit, and
//! enqueueing them returns [Feedback::Backoff](commonware_actor::Feedback::Backoff).
//!
//! A cancellation that waits behind the inbox discards the requests for its commitment that wait
//! with it. A request already in the inbox is still sent, and its responses are collected until
//! the engine handles the cancellation. Here `cancel(c)` is enqueued with a `mailbox_size` of 2:
//!
//! ```text
//!                     inbox                     waiting behind the inbox
//!                     +---------+---------+     +---------+---------+---------+
//! before cancel(c)    | send(c) | send(b) |     | send(c) | send(d) | send(c) |
//!                     +---------+---------+     +---------+---------+---------+
//!
//!                     +---------+---------+     +---------+-----------+
//! after cancel(c)     | send(c) | send(b) |     | send(d) | cancel(c) |
//!                     +---------+---------+     +---------+-----------+
//! ```
//!
//! # Message Sizes
//!
//! ```text
//! Request (tag 0):
//! +---------+------------------------+
//! | tag (1) | request (encoded size) |
//! +---------+------------------------+
//!
//! Response (tag 1):
//! +---------+-------------------------+
//! | tag (1) | response (encoded size) |
//! +---------+-------------------------+
//! ```
//!
//! The tag adds one byte to the encoding of each request and response. [max_message_size] bounds
//! the size of a message given the sizes of the largest encoded request and response. Every
//! message must fit the network's payload limit, less the subchannel prefix on a
//! [Muxer](commonware_p2p::utils::mux::Muxer) subchannel.

mod config;
pub use config::Config;
mod engine;
pub use engine::Engine;
mod ingress;
pub use ingress::Mailbox;
mod wire;
pub use wire::max_message_size;

#[cfg(test)]
mod mocks;

#[cfg(test)]
mod tests {
    use super::{
        Config, Engine, Mailbox,
        mocks::{
            handler::{Deferring as DeferringHandler, Handler as MockHandler},
            monitor::Monitor as MockMonitor,
            sender::{Failing, Recording},
            types::{Request, Response},
        },
        wire,
    };
    use crate::{Handler, Monitor, Originator};
    use commonware_actor::Feedback;
    use commonware_codec::{Encode, FixedSize as _};
    use commonware_cryptography::{
        Committable, Signer,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::{
        Blocker, Manager as _, Receiver as _, Recipients, Sender as _,
        simulated::{Link, Network, Oracle, Receiver, Sender},
        utils::mocks::inert_channel,
    };
    use commonware_runtime::{
        Clock, Metrics as _, Quota, Runner, Spawner as _, Supervisor as _, deterministic,
        telemetry::metrics::{count_running_tasks, status::Status},
    };
    use commonware_utils::{
        NZU32, NZUsize, channel::fallible::OneshotExt as _, ordered::Set, probability,
    };
    use rstest::rstest;
    use std::{collections::HashSet, num::NonZeroUsize, time::Duration};

    /// Default rate limit quota for tests (high enough to not interfere with normal operation)
    const TEST_QUOTA: Quota = Quota::per_second(NZU32!(1_000_000));

    const MAILBOX_SIZE: NonZeroUsize = commonware_utils::NZUsize!(1024);
    const LINK: Link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: probability!(1.0),
    };
    const LINK_SLOW: Link = Link {
        latency: Duration::from_secs(1),
        jitter: Duration::from_millis(1),
        success_rate: probability!(1.0),
    };

    /// The sender and receiver of a peer's channel.
    type Channel = (
        Sender<PublicKey, deterministic::Context>,
        Receiver<PublicKey>,
    );

    /// A message on the channel between test peers.
    type Message = wire::Message<Request, Response>;

    async fn setup_network_and_peers(
        context: &deterministic::Context,
        peer_seeds: &[u64],
    ) -> (
        Oracle<PublicKey, deterministic::Context>,
        Vec<PrivateKey>,
        Vec<PublicKey>,
        Vec<Channel>,
    ) {
        let (network, oracle) = Network::new(
            context.child("network"),
            commonware_p2p::simulated::Config {
                max_size: 1024 * 1024,
                max_peers_per_set: NZUsize!(peer_seeds.len()),
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
        );
        network.start();

        let schemes: Vec<PrivateKey> = peer_seeds
            .iter()
            .map(|seed| PrivateKey::from_seed(*seed))
            .collect();
        let peers: Vec<PublicKey> = schemes.iter().map(|s| s.public_key()).collect();

        let mut connections = Vec::new();
        for peer in &peers {
            let channel = oracle
                .control(peer.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            connections.push(channel);
        }
        oracle
            .manager()
            .track(0, Set::from_iter_dedup(peers.clone()));

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

    /// Reads the metric exported as `name` by the engine labelled with `public_key`.
    fn engine_metric(context: &deterministic::Context, name: &str, public_key: &PublicKey) -> i64 {
        let prefix = format!("engine_{name}{{");
        let label = format!("public_key=\"{public_key}\"");
        let encoded = context.encode();
        let line = encoded
            .lines()
            .find(|line| line.starts_with(&prefix) && line.contains(&label))
            .unwrap_or_else(|| panic!("metric {name} must be exported for {public_key}"));
        line.rsplit(' ').next().unwrap().parse().unwrap()
    }

    /// Reads how often the engine labelled with `public_key` counted `status` in `family`. A
    /// status that was never counted reads as zero.
    fn engine_count(
        context: &deterministic::Context,
        family: &str,
        status: Status,
        public_key: &PublicKey,
    ) -> u64 {
        let prefix = format!("engine_{family}_total{{");
        let peer = format!("public_key=\"{public_key}\"");
        let status = format!("status=\"{status:?}\"");
        context
            .encode()
            .lines()
            .find(|line| {
                line.starts_with(&prefix) && line.contains(&peer) && line.contains(&status)
            })
            .map_or(0, |line| line.rsplit(' ').next().unwrap().parse().unwrap())
    }

    /// Waits until `blocker` has blocked `blocked`.
    async fn wait_for_block(
        context: &deterministic::Context,
        oracle: &Oracle<PublicKey, deterministic::Context>,
        blocker: &PublicKey,
        blocked: &PublicKey,
    ) {
        while !oracle
            .blocked()
            .await
            .unwrap()
            .iter()
            .any(|(from, to)| from == blocker && to == blocked)
        {
            context.sleep(Duration::from_millis(10)).await;
        }
    }

    /// Returns the default test [Config] for `blocker`, `monitor`, and `handler`.
    fn config<B: Blocker, M: Monitor, H: Handler>(
        blocker: B,
        monitor: M,
        handler: H,
    ) -> Config<B, M, H, (), ()> {
        Config {
            blocker,
            monitor,
            handler,
            mailbox_size: MAILBOX_SIZE,
            priority_requests: false,
            request_codec_config: (),
            priority_responses: false,
            response_codec_config: (),
        }
    }

    /// Starts an engine for `signer` on `connection` and returns its mailbox.
    fn setup_and_spawn_engine(
        context: &deterministic::Context,
        blocker: impl Blocker<PublicKey = PublicKey>,
        signer: impl Signer<PublicKey = PublicKey>,
        connection: Channel,
        monitor: impl Monitor<PublicKey = PublicKey, Response = Response>,
        handler: impl Handler<PublicKey = PublicKey, Request = Request, Response = Response>,
    ) -> Mailbox<PublicKey, Request> {
        let public_key = signer.public_key();
        let (engine, mailbox) = Engine::new(
            context
                .child("engine")
                .with_attribute("public_key", &public_key),
            config(blocker, monitor, handler),
        );
        engine.start(connection);

        mailbox
    }

    #[test_traced]
    fn test_send_and_collect_response() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Link the two peers
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            // Setup peer 1
            let scheme = schemes.next().unwrap();
            let (mon, mut mon_out) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                mon,
                MockHandler::dummy(),
            );

            // Setup peer 2
            let scheme = schemes.next().unwrap();
            let (handler, mut handler_out) = MockHandler::new(true);
            let _mailbox = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                MockMonitor::dummy(),
                handler,
            );

            // Send request from peer 1 to peer 2
            let request = Request { id: 1, data: 1 };
            assert_eq!(
                mailbox1.send(Recipients::One(peers[1].clone()), request.clone()),
                Feedback::Ok
            );

            // Verify peer 2 received the request
            let processed = handler_out.recv().await.unwrap();
            assert_eq!(processed.origin, peers[0]);
            assert_eq!(processed.request, request);
            assert!(processed.responded);

            // Verify peer 1's monitor collected the response
            let collected = mon_out.recv().await.unwrap();
            assert_eq!(collected.handler, peers[1]);
            assert_eq!(collected.response.id, 1);
            assert_eq!(collected.response.result, 2);
            assert_eq!(collected.count, 1);
        });
    }

    #[test_traced]
    fn test_cancel_request() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Link the two peers
            add_link(&mut oracle, LINK_SLOW.clone(), &peers, 0, 1).await;

            // Setup peer 1
            let scheme = schemes.next().unwrap();
            let (mon, mut mon_out) = MockMonitor::new();
            let mut mailbox = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                mon,
                MockHandler::dummy(),
            );

            // Setup peer 2
            let scheme = schemes.next().unwrap();
            let (handler, _) = MockHandler::new(true);
            let _mailbox = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                MockMonitor::dummy(),
                handler,
            );

            // Send request from peer 1 to peer 2
            let request = Request { id: 1, data: 1 };
            let commitment = request.commitment();
            assert_eq!(
                mailbox.send(Recipients::One(peers[1].clone()), request.clone()),
                Feedback::Ok
            );

            // Cancel immediately
            assert_eq!(mailbox.cancel(commitment), Feedback::Ok);

            // Wait a bit and verify no response collected
            select! {
                _ = mon_out.recv() => {
                    panic!("Should not receive any monitor events");
                },
                _ = context.sleep(Duration::from_millis(5_000)) => {
                    // Expected: no events
                },
            }
        });
    }

    #[test_traced]
    fn test_broadcast_request() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1, 2]).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Link the peers
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;

            // Setup peer 1
            let scheme1 = schemes.next().unwrap();
            let (mon1, mut mon_out1) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme1.public_key()),
                scheme1,
                connections.next().unwrap(),
                mon1,
                MockHandler::dummy(),
            );

            // Setup peer 2
            let scheme2 = schemes.next().unwrap();
            let (handler2, _) = MockHandler::new(true);
            let _mailbox2 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme2.public_key()),
                scheme2,
                connections.next().unwrap(),
                MockMonitor::dummy(),
                handler2,
            );

            // Setup peer 3
            let scheme3 = schemes.next().unwrap();
            let (handler3, _) = MockHandler::new(true);
            let _mailbox3 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme3.public_key()),
                scheme3,
                connections.next().unwrap(),
                MockMonitor::dummy(),
                handler3,
            );

            // Broadcast request
            let request = Request { id: 3, data: 3 };
            assert_eq!(
                mailbox1.send(Recipients::All, request.clone()),
                Feedback::Ok
            );

            // Collect responses
            let mut responses_collected = 0;
            let mut peer2_responded = false;
            let mut peer3_responded = false;

            for _ in 0..2 {
                let collected = mon_out1.recv().await.unwrap();
                assert_eq!(collected.response.id, 3);
                assert_eq!(collected.response.result, 6);
                responses_collected += 1;
                assert_eq!(collected.count, responses_collected);

                if collected.handler == peers[1] {
                    peer2_responded = true;
                } else if collected.handler == peers[2] {
                    peer3_responded = true;
                }
            }

            assert!(peer2_responded);
            assert!(peer3_responded);
        });
    }

    #[test_traced]
    fn test_duplicate_response_ignored() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Link the peers
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            // Setup peer 1
            let scheme1 = schemes.next().unwrap();
            let (mon1, mut mon_out1) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme1.public_key()),
                scheme1,
                connections.next().unwrap(),
                mon1,
                MockHandler::dummy(),
            );

            // Setup peer 2
            let scheme2 = schemes.next().unwrap();
            let (handler2, _) = MockHandler::new(true);
            let _mailbox2 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme2.public_key()),
                scheme2,
                connections.next().unwrap(),
                MockMonitor::dummy(),
                handler2,
            );

            // Send the same request multiple times
            let request = Request { id: 5, data: 5 };
            for _ in 0..3 {
                assert_eq!(
                    mailbox1.send(Recipients::One(peers[1].clone()), request.clone()),
                    Feedback::Ok
                );
            }

            // Should only receive one response
            let collected = mon_out1.recv().await.unwrap();
            assert_eq!(collected.handler, peers[1]);
            assert_eq!(collected.response.id, 5);
            assert_eq!(collected.count, 1);

            // Wait and verify no more responses
            select! {
                _ = mon_out1.recv() => {
                    panic!("Should not receive duplicate responses");
                },
                _ = context.sleep(Duration::from_millis(5_000)) => {
                    // Expected: no more responses
                },
            }

            // Duplicate responses can be honest, so they do not block their sender.
            assert!(oracle.blocked().await.unwrap().is_empty());

            // The first response is collected and the two duplicates are dropped.
            assert_eq!(
                engine_count(&context, "collect", Status::Success, &peers[0]),
                1
            );
            assert_eq!(
                engine_count(&context, "collect", Status::Dropped, &peers[0]),
                2
            );
        });
    }

    #[test_traced]
    fn test_concurrent_requests() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Link the peers
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            // Setup peer 1
            let scheme1 = schemes.next().unwrap();
            let (mon1, mut mon_out1) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme1.public_key()),
                scheme1,
                connections.next().unwrap(),
                mon1,
                MockHandler::dummy(),
            );

            // Setup peer 2
            let scheme2 = schemes.next().unwrap();
            let (mut handler2, _) = MockHandler::new(false);
            handler2.set_response(10, Response { id: 10, result: 20 });
            handler2.set_response(20, Response { id: 20, result: 40 });
            let _mailbox2 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme2.public_key()),
                scheme2,
                connections.next().unwrap(),
                MockMonitor::dummy(),
                handler2,
            );

            // Send multiple concurrent requests
            let request1 = Request { id: 10, data: 10 };
            let request2 = Request { id: 20, data: 20 };
            assert_eq!(
                mailbox1.send(Recipients::One(peers[1].clone()), request1),
                Feedback::Ok
            );
            assert_eq!(
                mailbox1.send(Recipients::One(peers[1].clone()), request2),
                Feedback::Ok
            );

            // Collect both responses
            let mut response10_received = false;
            let mut response20_received = false;
            for _ in 0..2 {
                let collected = mon_out1.recv().await.unwrap();
                assert_eq!(collected.handler, peers[1]);
                assert_eq!(collected.count, 1);
                match collected.response.id {
                    10 => {
                        assert_eq!(collected.response.result, 20);
                        response10_received = true;
                    }
                    20 => {
                        assert_eq!(collected.response.result, 40);
                        response20_received = true;
                    }
                    _ => panic!("Unexpected response ID"),
                }
            }

            assert!(response10_received);
            assert!(response20_received);
        });
    }

    #[test_traced]
    fn test_handler_no_response() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Link the peers
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            // Setup peer 1
            let scheme1 = schemes.next().unwrap();
            let (mon1, mut mon_out1) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme1.public_key()),
                scheme1,
                connections.next().unwrap(),
                mon1,
                MockHandler::dummy(),
            );

            // Setup peer 2 with handler that doesn't respond
            let scheme2 = schemes.next().unwrap();
            let (handler2, mut handler_out2) = MockHandler::new(false);
            let _mailbox2 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme2.public_key()),
                scheme2,
                connections.next().unwrap(),
                MockMonitor::dummy(),
                handler2,
            );

            // Send request
            let request = Request { id: 100, data: 100 };
            assert_eq!(
                mailbox1.send(Recipients::One(peers[1].clone()), request.clone()),
                Feedback::Ok
            );

            // Verify handler received request but didn't respond
            let processed = handler_out2.recv().await.unwrap();
            assert_eq!(processed.origin, peers[0]);
            assert_eq!(processed.request, request);
            assert!(!processed.responded);

            // Verify no response collected
            select! {
                _ = mon_out1.recv() => {
                    panic!("Should not receive any monitor events");
                },
                _ = context.sleep(Duration::from_millis(1_000)) => {
                    // Expected: no events
                },
            }
        });
    }

    /// A request sent to no peer starts no collection.
    #[rstest]
    // No other peer exists.
    #[case::all(Recipients::All)]
    // No peer is named.
    #[case::none(Recipients::Some(Vec::new()))]
    #[test_traced]
    fn test_empty_recipients(#[case] recipients: Recipients<PublicKey>) {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // A single peer runs an engine with no other peer to send to.
            let (oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0]).await;
            let scheme = schemes.into_iter().next().unwrap();
            let mut mailbox = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.into_iter().next().unwrap(),
                MockMonitor::dummy(),
                MockHandler::dummy(),
            );

            // The request is dropped and starts no collection.
            let request = Request { id: 1, data: 1 };
            assert_eq!(mailbox.send(recipients, request), Feedback::Ok);
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(
                engine_count(&context, "send", Status::Dropped, &peers[0]),
                1
            );
            assert_eq!(engine_metric(&context, "outstanding", &peers[0]), 0);
        });
    }

    #[test_traced]
    fn test_send_closed_does_not_collect() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Link peers 0 and 1.
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            let mut connections = connections.into_iter();

            // Peer 0's sender is closed, and peer 1 is a raw peer.
            let (_sender, receiver) = connections.next().unwrap();
            let (mut raw, _raw_receiver) = connections.next().unwrap();
            let public_key = schemes[0].public_key();
            let (monitor, mut monitor_out) = MockMonitor::new();
            let (engine, mut mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &public_key),
                config(oracle.control(public_key), monitor, MockHandler::dummy()),
            );
            engine.start((Failing::<PublicKey>::new(), receiver));

            // A request sent to no peer starts no collection.
            let request = Request { id: 1, data: 1 };
            assert_eq!(
                mailbox.send(Recipients::One(peers[1].clone()), request),
                Feedback::Ok
            );
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(
                engine_count(&context, "send", Status::Dropped, &peers[0]),
                1
            );
            assert_eq!(engine_metric(&context, "outstanding", &peers[0]), 0);

            // A response from the intended recipient is not collected.
            raw.send(
                Recipients::One(peers[0].clone()),
                Message::Response(Response { id: 1, result: 2 }).encode(),
                false,
            );
            select! {
                _ = monitor_out.recv() => {
                    panic!("a peer the request was not sent to must not be collected");
                },
                _ = context.sleep(Duration::from_secs(1)) => {},
            }
            assert_eq!(
                engine_count(&context, "collect", Status::Dropped, &peers[0]),
                1
            );
        });
    }

    #[test_traced]
    fn test_send_after_shutdown_returns_closed() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Setup peer 1
            let scheme = schemes.next().unwrap();
            let connection = connections.next().unwrap();
            let public_key = scheme.public_key();
            let (engine, mut mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &public_key),
                config(
                    oracle.control(public_key),
                    MockMonitor::dummy(),
                    MockHandler::dummy(),
                ),
            );

            // Start engine
            let handle = engine.start(connection);

            // Stop the engine
            handle.abort();
            handle.await.expect_err("engine should be aborted");

            // Send request
            let request = Request { id: 1, data: 1 };
            assert_eq!(
                mailbox.send(Recipients::One(peers[1].clone()), request),
                Feedback::Closed
            );
        });
    }

    #[test_traced]
    fn test_response_from_unknown_peer() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1, 2]).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Link all peers
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;
            add_link(&mut oracle, LINK.clone(), &peers, 1, 2).await;

            // Setup peer 1 (originator)
            let scheme1 = schemes.next().unwrap();
            let (mon1, mut mon_out1) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme1.public_key()),
                scheme1,
                connections.next().unwrap(),
                mon1,
                MockHandler::dummy(),
            );

            // Setup peer 2 (legitimate responder)
            let scheme2 = schemes.next().unwrap();
            let (handler2, _) = MockHandler::new(true);
            let _mailbox2 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme2.public_key()),
                scheme2,
                connections.next().unwrap(),
                MockMonitor::dummy(),
                handler2,
            );

            // Setup peer 3 (will respond with same commitment as peer 2's request)
            let (mut sender3, _receiver3) = connections.next().unwrap();

            // Send request from peer 1 to peer 2 (collector records the in-flight request)
            let request_to_peer2 = Request { id: 42, data: 42 };
            assert_eq!(
                mailbox1.send(Recipients::One(peers[1].clone()), request_to_peer2.clone()),
                Feedback::Ok
            );

            // Send a response from peer 3 to peer 1
            let response_to_peer1 = Response { id: 42, result: 72 };
            sender3.send(
                Recipients::One(peers[0].clone()),
                Message::Response(response_to_peer1).encode(),
                true,
            );

            // Give some time for messages to be processed
            context.sleep(Duration::from_millis(1_000)).await;

            // Should only receive one response (from peer 2, not peer 3)
            let collected = mon_out1.recv().await.unwrap();
            assert_eq!(collected.handler, peers[1]); // Response from peer 2
            assert_eq!(collected.response.id, 42);
            assert_eq!(collected.response.result, 84); // 42 * 2 (default mock behavior)
            assert_eq!(collected.count, 1);

            // Verify no additional responses (peer 3's response should be ignored)
            select! {
                _ = mon_out1.recv() => {
                    panic!("Should not receive response from unknown peer");
                },
                _ = context.sleep(Duration::from_millis(1_000)) => {
                    // Expected: no more events
                },
            }

            // Unsolicited responses can be honest, so they do not block their sender.
            assert!(oracle.blocked().await.unwrap().is_empty());

            // The recipient's response is collected and the other peer's response is dropped.
            assert_eq!(
                engine_count(&context, "collect", Status::Success, &peers[0]),
                1
            );
            assert_eq!(
                engine_count(&context, "collect", Status::Dropped, &peers[0]),
                1
            );
        });
    }

    /// Starts an engine with a responding mock handler for each scheme and returns their mailboxes
    /// and handles.
    fn spawn_engines_with_handles(
        engine_context: deterministic::Context,
        oracle: &Oracle<PublicKey, deterministic::Context>,
        schemes: Vec<PrivateKey>,
        connections: Vec<Channel>,
    ) -> (
        Vec<Mailbox<PublicKey, Request>>,
        Vec<commonware_runtime::Handle<()>>,
    ) {
        let mut mailboxes = Vec::new();
        let mut handles = Vec::new();

        for (idx, (scheme, conn)) in schemes.into_iter().zip(connections).enumerate() {
            let ctx = engine_context.child("peer").with_attribute("index", idx);
            let (mon, _) = MockMonitor::new();
            let (handler, _) = MockHandler::new(true);
            let (engine, mailbox) = Engine::new(
                ctx,
                config(oracle.control(scheme.public_key()), mon, handler),
            );
            handles.push(engine.start(conn));
            mailboxes.push(mailbox);
        }

        (mailboxes, handles)
    }

    #[test_traced]
    fn test_operations_after_shutdown_do_not_panic() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let (mut mailboxes, handles) =
                spawn_engines_with_handles(context.child("engine"), &oracle, schemes, connections);

            // Abort all engines immediately
            for handle in &handles {
                handle.abort();
            }
            for handle in handles {
                handle.await.expect_err("engine should be aborted");
            }

            // All operations should not panic after shutdown

            // Send should not panic
            let request = Request { id: 1, data: 1 };
            let feedback = mailboxes[0].send(Recipients::One(peers[1].clone()), request.clone());
            assert_eq!(feedback, Feedback::Closed);

            // Cancel should not panic
            assert_eq!(mailboxes[0].cancel(request.commitment()), Feedback::Closed);
        });
    }

    fn clean_shutdown(seed: u64) {
        let cfg = deterministic::Config::default()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|context| async move {
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;

            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;

            let (mut mailboxes, handles) =
                spawn_engines_with_handles(context.child("peers"), &oracle, schemes, connections);

            // Allow tasks to start
            context.sleep(Duration::from_millis(100)).await;

            // Count running tasks under the peers prefix
            let running_before = count_running_tasks(&context, "peers");
            assert!(
                running_before > 0,
                "at least one peer engine task should be running"
            );

            // Verify the network is functional by sending a request and expecting a response
            let request = Request { id: 1, data: 1 };
            assert_eq!(
                mailboxes[0].send(Recipients::One(peers[1].clone()), request.clone()),
                Feedback::Ok
            );

            // Abort all engines
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

    /// Regression test for https://github.com/commonwarexyz/monorepo/pull/5153.
    ///
    /// Every `Mailbox` can be dropped while the engine runs. The engine must then
    /// stop instead of polling its closed mailbox forever.
    #[test_traced]
    fn pr_5153_regression() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (oracle, schemes, _, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            let public_key = schemes[0].public_key();
            let conn = connections.into_iter().next().unwrap();
            let (engine, mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &public_key),
                config(
                    oracle.control(public_key),
                    MockMonitor::dummy(),
                    MockHandler::dummy(),
                ),
            );
            let handle = engine.start(conn);

            drop(mailbox);
            handle
                .await
                .expect("engine should stop once every mailbox is dropped");
        });
    }

    /// The engine blocks a peer that sends a message it cannot decode, counts the message as
    /// invalid, and keeps serving other peers and collecting from them.
    #[rstest]
    // The payload is empty.
    #[case::empty(Vec::new())]
    // The tag marks neither a request nor a response.
    #[case::unknown_tag([&[2][..], &Request { id: 1, data: 1 }.encode()[..]].concat())]
    // A request tag is followed by a body one byte short of a request.
    #[case::malformed_request(
        Message::Request(Request { id: 1, data: 1 }).encode()[..Request::SIZE].to_vec()
    )]
    // A response tag is followed by a body one byte short of a response.
    #[case::malformed_response(
        Message::Response(Response { id: 1, result: 2 }).encode()[..Response::SIZE].to_vec()
    )]
    // A valid request is followed by one extra byte.
    #[case::trailing_byte(
        [&Message::Request(Request { id: 1, data: 1 }).encode()[..], &[0][..]].concat()
    )]
    #[test_traced]
    fn test_invalid_message_blocks_sender_and_engine_keeps_working(#[case] payload: Vec<u8>) {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Link peer 0 to peers 1 and 2.
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1, 2]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Peers 0 and 1 both serve and originate, and peer 2 is a raw peer.
            let scheme = schemes.next().unwrap();
            let (handler, mut handler_out) = MockHandler::new(true);
            let (monitor, mut monitor_out) = MockMonitor::new();
            let mut mailbox0 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                monitor,
                handler,
            );
            let scheme = schemes.next().unwrap();
            let (monitor, mut monitor_out1) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                monitor,
                MockHandler::dummy(),
            );
            let (mut attacker, _attacker_receiver) = connections.next().unwrap();

            // The message blocks peer 2 and is counted as invalid.
            attacker.send(Recipients::One(peers[0].clone()), payload, false);
            wait_for_block(&context, &oracle, &peers[0], &peers[2]).await;
            assert_eq!(oracle.blocked().await.unwrap().len(), 1);
            assert_eq!(engine_metric(&context, "invalid_total", &peers[0]), 1);

            // Peer 0 keeps serving peer 1, and its handler's first request is peer 1's.
            let request = Request { id: 1, data: 1 };
            assert_eq!(
                mailbox1.send(Recipients::One(peers[0].clone()), request.clone()),
                Feedback::Ok
            );
            let processed = handler_out.recv().await.unwrap();
            assert_eq!(processed.origin, peers[1]);
            assert_eq!(processed.request, request);
            let collected = monitor_out1.recv().await.unwrap();
            assert_eq!(collected.handler, peers[0]);
            assert_eq!(collected.count, 1);

            // Peer 0 keeps collecting from peer 1, and its monitor's first response is peer 1's.
            assert_eq!(
                mailbox0.send(
                    Recipients::One(peers[1].clone()),
                    Request { id: 2, data: 2 }
                ),
                Feedback::Ok
            );
            let collected = monitor_out.recv().await.unwrap();
            assert_eq!(collected.handler, peers[1]);
            assert_eq!(collected.response, Response { id: 2, result: 4 });
            assert_eq!(collected.count, 1);

            // Peer 0's handler and monitor saw nothing else.
            assert!(handler_out.try_recv().is_err());
            assert!(monitor_out.try_recv().is_err());
        });
    }

    #[test_traced]
    fn test_dropped_responder_keeps_engine_serving() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Link peers 0 and 1.
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Peer 1's handler drops the responder for request 1 and answers request 2.
            let scheme = schemes.next().unwrap();
            let (monitor, mut monitor_out) = MockMonitor::new();
            let mut mailbox0 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                monitor,
                MockHandler::dummy(),
            );
            let scheme = schemes.next().unwrap();
            let (mut handler, mut handler_out) = MockHandler::new(false);
            handler.set_response(2, Response { id: 2, result: 4 });
            let _mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                MockMonitor::dummy(),
                handler,
            );

            // Peer 1 declines request 1, and its engine handles the dropped responder before
            // request 2 arrives.
            assert_eq!(
                mailbox0.send(
                    Recipients::One(peers[1].clone()),
                    Request { id: 1, data: 1 }
                ),
                Feedback::Ok
            );
            assert!(!handler_out.recv().await.unwrap().responded);
            context.sleep(Duration::from_millis(100)).await;

            // Peer 1 still serves later requests.
            assert_eq!(
                mailbox0.send(
                    Recipients::One(peers[1].clone()),
                    Request { id: 2, data: 2 }
                ),
                Feedback::Ok
            );
            let collected = monitor_out.recv().await.unwrap();
            assert_eq!(collected.handler, peers[1]);
            assert_eq!(collected.response, Response { id: 2, result: 4 });
        });
    }

    #[test_traced]
    fn test_requests_that_share_a_commitment_keep_their_own_contents() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Link peer 0 to peers 1 and 2.
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1, 2]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Peer 0 originates, and peers 1 and 2 report the requests they serve.
            let scheme = schemes.next().unwrap();
            let (monitor, mut monitor_out) = MockMonitor::new();
            let mut mailbox0 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                monitor,
                MockHandler::dummy(),
            );
            let mut served = Vec::new();
            let mut mailboxes = Vec::new();
            for _ in 0..2 {
                let scheme = schemes.next().unwrap();
                let (handler, handler_out) = MockHandler::new(true);
                mailboxes.push(setup_and_spawn_engine(
                    &context,
                    oracle.control(scheme.public_key()),
                    scheme,
                    connections.next().unwrap(),
                    MockMonitor::dummy(),
                    handler,
                ));
                served.push(handler_out);
            }

            // Two requests share a commitment and differ in content, one for each peer.
            let requests = [Request { id: 7, data: 10 }, Request { id: 7, data: 20 }];
            assert_eq!(requests[0].commitment(), requests[1].commitment());
            for (request, peer) in requests.iter().zip(&peers[1..]) {
                assert_eq!(
                    mailbox0.send(Recipients::One(peer.clone()), request.clone()),
                    Feedback::Ok
                );
            }

            // Each peer serves the request that was sent to it.
            for (request, served) in requests.iter().zip(&mut served) {
                let processed = served.recv().await.unwrap();
                assert_eq!(processed.origin, peers[0]);
                assert_eq!(&processed.request, request);
            }

            // One collection collects each peer's response with the content that peer produced.
            let first = monitor_out.recv().await.unwrap();
            let second = monitor_out.recv().await.unwrap();
            assert_eq!((first.count, second.count), (1, 2));
            assert_ne!(first.handler, second.handler);
            for collected in [first, second] {
                let index = peers
                    .iter()
                    .position(|peer| peer == &collected.handler)
                    .unwrap();
                let result = u64::from(requests[index - 1].data.wrapping_mul(2));
                assert_eq!(collected.response, Response { id: 7, result });
            }
        });
    }

    #[test_traced]
    fn test_resend_after_cancel_restarts_collection() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Link peers 0 and 1.
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Peer 0 originates, and peer 1 serves.
            let scheme = schemes.next().unwrap();
            let (monitor, mut monitor_out) = MockMonitor::new();
            let mut mailbox0 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                monitor,
                MockHandler::dummy(),
            );
            let scheme = schemes.next().unwrap();
            let _mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                MockMonitor::dummy(),
                MockHandler::dummy(),
            );

            // Each send after a cancel starts a new collection for the same commitment.
            let request = Request { id: 6, data: 6 };
            for _ in 0..2 {
                assert_eq!(
                    mailbox0.send(Recipients::One(peers[1].clone()), request.clone()),
                    Feedback::Ok
                );
                let collected = monitor_out.recv().await.unwrap();
                assert_eq!(collected.handler, peers[1]);
                assert_eq!(collected.count, 1);
                assert_eq!(mailbox0.cancel(request.commitment()), Feedback::Ok);
            }
        });
    }

    #[test_traced]
    fn test_outstanding_counts_sent_commitments_until_cancelled() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Link peer 0 to peers 1 and 2.
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1, 2]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Peer 0 originates, peer 1 serves, and peer 2 is a raw peer that sends unsolicited
            // responses.
            let scheme = schemes.next().unwrap();
            let (monitor, mut monitor_out) = MockMonitor::new();
            let mut mailbox0 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                monitor,
                MockHandler::dummy(),
            );
            let scheme = schemes.next().unwrap();
            let _mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                MockMonitor::dummy(),
                MockHandler::dummy(),
            );
            let (mut raw, _raw_receiver) = connections.next().unwrap();

            // Unsolicited responses neither start a collection nor block their sender.
            for id in [7, 8, 9] {
                raw.send(
                    Recipients::One(peers[0].clone()),
                    Message::Response(Response { id, result: 0 }).encode(),
                    false,
                );
            }
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(
                engine_count(&context, "collect", Status::Dropped, &peers[0]),
                3
            );
            assert_eq!(engine_metric(&context, "outstanding", &peers[0]), 0);
            assert!(oracle.blocked().await.unwrap().is_empty());

            // Sent commitments are outstanding until cancelled, including one that a peer
            // answered before it was ever sent.
            for id in [7, 2] {
                assert_eq!(
                    mailbox0.send(Recipients::One(peers[1].clone()), Request { id, data: 0 }),
                    Feedback::Ok
                );
            }
            for _ in 0..2 {
                assert_eq!(monitor_out.recv().await.unwrap().handler, peers[1]);
            }
            assert_eq!(engine_metric(&context, "outstanding", &peers[0]), 2);

            // Cancelling an unknown commitment changes nothing, and cancelling a sent one ends its
            // collection.
            let unknown = Request { id: 3, data: 0 }.commitment();
            assert_eq!(mailbox0.cancel(unknown), Feedback::Ok);
            assert_eq!(
                mailbox0.cancel(Request { id: 7, data: 0 }.commitment()),
                Feedback::Ok
            );
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(engine_metric(&context, "outstanding", &peers[0]), 1);
            assert_eq!(
                mailbox0.cancel(Request { id: 2, data: 0 }.commitment()),
                Feedback::Ok
            );
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(engine_metric(&context, "outstanding", &peers[0]), 0);
        });
    }

    #[test_traced]
    fn test_wire_payloads_are_tagged_encodings() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Link peers 0 and 1.
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            let mut connections = connections.into_iter();

            // Peer 0 runs the engine, and peer 1 is a raw peer.
            let scheme = schemes.into_iter().next().unwrap();
            let (monitor, mut monitor_out) = MockMonitor::new();
            let mut mailbox0 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                monitor,
                MockHandler::dummy(),
            );
            let (mut raw, mut raw_receiver) = connections.next().unwrap();

            // A request travels as the byte 0 followed by its encoding.
            let request = Request { id: 9, data: 3 };
            assert_eq!(
                mailbox0.send(Recipients::One(peers[1].clone()), request.clone()),
                Feedback::Ok
            );
            let (origin, bytes) = raw_receiver.recv().await.unwrap();
            assert_eq!(origin, peers[0]);
            assert_eq!(bytes, [&[0][..], &request.encode()[..]].concat().as_slice());

            // The byte 1 followed by a response's encoding is collected.
            let response = Response { id: 9, result: 6 };
            raw.send(
                Recipients::One(peers[0].clone()),
                [&[1][..], &response.encode()[..]].concat(),
                false,
            );
            let collected = monitor_out.recv().await.unwrap();
            assert_eq!(collected.handler, peers[1]);
            assert_eq!(collected.response, response);
            assert_eq!(collected.count, 1);

            // The byte 0 followed by a request's encoding is served, and the response travels as
            // the byte 1 followed by its encoding.
            let request = Request { id: 4, data: 5 };
            raw.send(
                Recipients::One(peers[0].clone()),
                [&[0][..], &request.encode()[..]].concat(),
                false,
            );
            let (origin, bytes) = raw_receiver.recv().await.unwrap();
            assert_eq!(origin, peers[0]);
            let response = Response { id: 4, result: 10 };
            assert_eq!(
                bytes,
                [&[1][..], &response.encode()[..]].concat().as_slice()
            );
        });
    }

    /// An engine sends each request with the request priority and each response with the response
    /// priority, and it sends a response only to the peer that requested it.
    #[rstest]
    // Requests have priority and responses do not.
    #[case::requests(true, false)]
    // Responses have priority and requests do not.
    #[case::responses(false, true)]
    #[test_traced]
    fn test_sends_use_configured_priority_and_answer_only_requester(
        #[case] priority_requests: bool,
        #[case] priority_responses: bool,
    ) {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Link peers 0 and 1.
            let (mut oracle, _, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            let mut connections = connections.into_iter();

            // Peer 0 sends through a recording sender, and peer 1 is a raw peer.
            let (_sender, receiver) = connections.next().unwrap();
            let (mut raw, _raw_receiver) = connections.next().unwrap();
            let (sender, sent) = Recording::<PublicKey>::new();
            let (engine, mut mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &peers[0]),
                Config {
                    priority_requests,
                    priority_responses,
                    ..config(
                        oracle.control(peers[0].clone()),
                        MockMonitor::dummy(),
                        MockHandler::dummy(),
                    )
                },
            );
            engine.start((sender, receiver));

            // A request carries the request priority.
            assert_eq!(
                mailbox.send(
                    Recipients::One(peers[1].clone()),
                    Request { id: 1, data: 1 }
                ),
                Feedback::Ok
            );
            context.sleep(Duration::from_millis(100)).await;
            assert!(matches!(
                sent.lock().as_slice(),
                [(Recipients::One(peer), 0, priority)]
                    if peer == &peers[1] && *priority == priority_requests
            ));

            // A response carries the response priority and goes only to the requester.
            raw.send(
                Recipients::One(peers[0].clone()),
                Message::Request(Request { id: 2, data: 2 }).encode(),
                true,
            );
            context.sleep(Duration::from_millis(100)).await;
            assert!(matches!(
                sent.lock().as_slice(),
                [_, (Recipients::One(peer), 1, priority)]
                    if peer == &peers[1] && *priority == priority_responses
            ));
        });
    }

    #[test_traced]
    fn test_overflow_cancel_prunes_queued_send() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Peer 0 runs the engine, and peer 1 is a raw peer that reads the engine's requests.
            let (mut oracle, _, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            let mut connections = connections.into_iter();
            let connection = connections.next().unwrap();
            let (_raw_sender, mut raw_receiver) = connections.next().unwrap();

            // Give peer 0 a one-slot inbox.
            let (engine, mut mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &peers[0]),
                Config {
                    mailbox_size: NZUsize!(1),
                    ..config(
                        oracle.control(peers[0].clone()),
                        MockMonitor::dummy(),
                        MockHandler::dummy(),
                    )
                },
            );

            // Before the engine starts, fill the inbox and cancel a request that waits behind it.
            let kept = Request { id: 1, data: 1 };
            let cancelled = Request { id: 2, data: 2 };
            assert_eq!(
                mailbox.send(Recipients::One(peers[1].clone()), kept.clone()),
                Feedback::Ok
            );
            assert_eq!(
                mailbox.send(Recipients::One(peers[1].clone()), cancelled.clone()),
                Feedback::Backoff
            );
            assert_eq!(mailbox.cancel(cancelled.commitment()), Feedback::Backoff);
            engine.start(connection);

            // Only the request that was not cancelled is sent, and it starts a collection.
            let (_, bytes) = raw_receiver.recv().await.unwrap();
            assert_eq!(bytes, Message::Request(kept).encode().as_ref());
            select! {
                _ = raw_receiver.recv() => {
                    panic!("a request cancelled while it waits behind the inbox must not be sent");
                },
                _ = context.sleep(Duration::from_secs(1)) => {},
            }
            assert_eq!(engine_metric(&context, "outstanding", &peers[0]), 1);
        });
    }

    #[test_traced]
    fn test_dropped_mailbox_stops_engine_after_enqueued_commands() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Peer 0's engine has a one-slot inbox and a sender that records each send.
            let (oracle, _, peers, _) = setup_network_and_peers(&context, &[0, 1, 2]).await;
            let (engine, mut mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &peers[0]),
                Config {
                    mailbox_size: NZUsize!(1),
                    ..config(
                        oracle.control(peers[0].clone()),
                        MockMonitor::dummy(),
                        MockHandler::dummy(),
                    )
                },
            );
            let (sender, sent) = Recording::<PublicKey>::new();
            let (_, receiver) = inert_channel(&peers);

            // Before the engine starts, enqueue a request for peer 1 into the inbox and a request
            // for peer 2 behind it, then drop the only mailbox.
            let request = Request { id: 1, data: 1 };
            assert_eq!(
                mailbox.send(Recipients::One(peers[1].clone()), request.clone()),
                Feedback::Ok
            );
            assert_eq!(
                mailbox.send(Recipients::One(peers[2].clone()), request),
                Feedback::Backoff
            );
            drop(mailbox);

            // The engine sends both requests in order and then stops.
            engine
                .start((sender, receiver))
                .await
                .expect("an engine must stop once every mailbox is dropped");
            assert!(matches!(
                sent.lock().as_slice(),
                [(Recipients::One(first), 0, _), (Recipients::One(second), 0, _)]
                    if first == &peers[1] && second == &peers[2]
            ));
        });
    }

    /// An engine whose receiver is already closed stops as soon as it starts.
    #[test_traced]
    fn test_closed_network_receiver_stops_engine() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // A single peer with no links.
            let (oracle, _, peers, connections) = setup_network_and_peers(&context, &[0]).await;

            // Registering the channel again closes the receiver the engine starts with.
            let _replacement = oracle
                .control(peers[0].clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();

            // The engine stops as soon as it starts, and its mailbox then reports it closed.
            let (engine, mut mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &peers[0]),
                config(
                    oracle.control(peers[0].clone()),
                    MockMonitor::dummy(),
                    MockHandler::dummy(),
                ),
            );
            let connection = connections.into_iter().next().unwrap();
            engine
                .start(connection)
                .await
                .expect("an engine must stop once its network receiver closes");
            assert_eq!(
                mailbox.cancel(Request { id: 1, data: 1 }.commitment()),
                Feedback::Closed
            );
        });
    }

    #[test_traced]
    fn test_resend_does_not_collect_handler_again() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Link peer 0 to peers 1 and 2.
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1, 2]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Peer 0 originates, and peers 1 and 2 answer every request.
            let scheme = schemes.next().unwrap();
            let (monitor, mut monitor_out) = MockMonitor::new();
            let mut mailbox = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                monitor,
                MockHandler::dummy(),
            );
            let mut mailboxes = Vec::new();
            for _ in 0..2 {
                let scheme = schemes.next().unwrap();
                mailboxes.push(setup_and_spawn_engine(
                    &context,
                    oracle.control(scheme.public_key()),
                    scheme,
                    connections.next().unwrap(),
                    MockMonitor::dummy(),
                    MockHandler::dummy(),
                ));
            }

            // Peer 1 answers the first send.
            let request = Request { id: 9, data: 9 };
            assert_eq!(
                mailbox.send(Recipients::One(peers[1].clone()), request.clone()),
                Feedback::Ok
            );
            let collected = monitor_out.recv().await.unwrap();
            assert_eq!(collected.handler, peers[1]);
            assert_eq!(collected.count, 1);

            // A second send of the same commitment adds peer 2 to the collection, and peer 1's
            // second answer is not collected again.
            assert_eq!(
                mailbox.send(
                    Recipients::Some(vec![peers[1].clone(), peers[2].clone()]),
                    request
                ),
                Feedback::Ok
            );
            let collected = monitor_out.recv().await.unwrap();
            assert_eq!(collected.handler, peers[2]);
            assert_eq!(collected.count, 2);
            select! {
                _ = monitor_out.recv() => {
                    panic!("a handler must be collected at most once per collection");
                },
                _ = context.sleep(Duration::from_secs(2)) => {},
            }
            assert_eq!(
                engine_count(&context, "collect", Status::Dropped, &peers[0]),
                1
            );
        });
    }

    #[test_traced]
    fn test_metrics_count_each_outcome() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Link peer 0 to every other peer.
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1, 2, 3]).await;
            for peer in 1..peers.len() {
                add_link(&mut oracle, LINK.clone(), &peers, 0, peer).await;
            }
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Peer 0 originates, peer 1 answers request 1 and declines the rest, peer 2 cannot
            // send responses, and peer 3 is a raw peer.
            let scheme = schemes.next().unwrap();
            let (monitor, mut monitor_out) = MockMonitor::new();
            let mut mailbox0 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                monitor,
                MockHandler::dummy(),
            );
            let scheme = schemes.next().unwrap();
            let (mut handler, mut handler_out) = MockHandler::new(false);
            handler.set_response(1, Response { id: 1, result: 2 });
            let _mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                MockMonitor::dummy(),
                handler,
            );
            let public_key = schemes.next().unwrap().public_key();
            let (_sender, receiver) = connections.next().unwrap();
            let (handler, mut silenced_out) = MockHandler::new(true);
            let (engine, _mailbox2) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &public_key),
                config(oracle.control(public_key), MockMonitor::dummy(), handler),
            );
            engine.start((Failing::<PublicKey>::new(), receiver));
            let (mut raw, _raw_receiver) = connections.next().unwrap();

            // A request sent to no peer is dropped, and a request that is sent, served, and
            // collected is a success in each of those counts.
            assert_eq!(
                mailbox0.send(Recipients::Some(Vec::new()), Request { id: 9, data: 0 }),
                Feedback::Ok
            );
            assert_eq!(
                mailbox0.send(
                    Recipients::One(peers[1].clone()),
                    Request { id: 1, data: 0 }
                ),
                Feedback::Ok
            );
            assert!(handler_out.recv().await.unwrap().responded);
            assert_eq!(monitor_out.recv().await.unwrap().handler, peers[1]);
            assert_eq!(
                engine_count(&context, "send", Status::Dropped, &peers[0]),
                1
            );
            assert_eq!(
                engine_count(&context, "send", Status::Success, &peers[0]),
                1
            );
            assert_eq!(
                engine_count(&context, "collect", Status::Success, &peers[0]),
                1
            );
            assert_eq!(
                engine_count(&context, "serve", Status::Success, &peers[1]),
                1
            );

            // A request the handler declines is a failure.
            assert_eq!(
                mailbox0.send(
                    Recipients::One(peers[1].clone()),
                    Request { id: 2, data: 0 }
                ),
                Feedback::Ok
            );
            assert!(!handler_out.recv().await.unwrap().responded);
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(
                engine_count(&context, "serve", Status::Failure, &peers[1]),
                1
            );

            // A response that cannot be sent is dropped.
            assert_eq!(
                mailbox0.send(
                    Recipients::One(peers[2].clone()),
                    Request { id: 3, data: 0 }
                ),
                Feedback::Ok
            );
            assert!(silenced_out.recv().await.unwrap().responded);
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(
                engine_count(&context, "serve", Status::Dropped, &peers[2]),
                1
            );
            assert_eq!(
                engine_count(&context, "serve", Status::Success, &peers[2]),
                0
            );

            // A response that matches no collection is dropped.
            raw.send(
                Recipients::One(peers[0].clone()),
                Message::Response(Response { id: 8, result: 0 }).encode(),
                false,
            );
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(
                engine_count(&context, "collect", Status::Dropped, &peers[0]),
                1
            );

            // Bytes that do not decode are invalid.
            raw.send(Recipients::One(peers[0].clone()), vec![0xFF], false);
            wait_for_block(&context, &oracle, &peers[0], &peers[3]).await;
            assert_eq!(engine_metric(&context, "invalid_total", &peers[0]), 1);
        });
    }

    #[test_traced]
    fn test_deferred_response_is_pending_until_answered() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Link peers 0 and 1.
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Peer 0 originates, and peer 1 hands each responder to the test.
            let scheme = schemes.next().unwrap();
            let (monitor, mut monitor_out) = MockMonitor::new();
            let mut mailbox0 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                monitor,
                MockHandler::dummy(),
            );
            let scheme = schemes.next().unwrap();
            let (handler, mut deferred) = DeferringHandler::new();
            let _mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                MockMonitor::dummy(),
                handler,
            );

            // Both requests stay pending while the handler holds their responders.
            for id in [1, 2] {
                assert_eq!(
                    mailbox0.send(Recipients::One(peers[1].clone()), Request { id, data: 0 }),
                    Feedback::Ok
                );
            }
            let (first, first_responder) = deferred.recv().await.unwrap();
            let (second, second_responder) = deferred.recv().await.unwrap();
            assert_eq!((first.id, second.id), (1, 2));
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(engine_metric(&context, "serve_processing", &peers[1]), 2);

            // A response sent later is collected.
            let response = Response { id: 2, result: 7 };
            assert!(second_responder.send_lossy(response.clone()));
            let collected = monitor_out.recv().await.unwrap();
            assert_eq!(collected.handler, peers[1]);
            assert_eq!(collected.response, response);
            assert_eq!(engine_metric(&context, "serve_processing", &peers[1]), 1);

            // A dropped responder releases its request without a response.
            drop(first_responder);
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(engine_metric(&context, "serve_processing", &peers[1]), 0);
            assert_eq!(
                engine_count(&context, "serve", Status::Failure, &peers[1]),
                1
            );
            assert!(monitor_out.try_recv().is_err());
        });
    }

    /// Sends one request to four peers over links that lose half of all messages and sends it
    /// again until every peer has responded. Returns the runtime's final state.
    fn collect_over_lossy_links(seed: u64) -> String {
        let cfg = deterministic::Config::default()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(60)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|context| async move {
            // Link peer 0 to every other peer over links that lose half of all messages.
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1, 2, 3, 4]).await;
            let lossy = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(5),
                success_rate: probability!(0.5),
            };
            for peer in 1..peers.len() {
                add_link(&mut oracle, lossy.clone(), &peers, 0, peer).await;
            }
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Peer 0 originates, and every other peer answers each request it receives.
            let scheme = schemes.next().unwrap();
            let (monitor, mut monitor_out) = MockMonitor::new();
            let mut mailbox = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                monitor,
                MockHandler::dummy(),
            );
            let _servers: Vec<_> = schemes
                .zip(connections)
                .map(|(scheme, connection)| {
                    setup_and_spawn_engine(
                        &context,
                        oracle.control(scheme.public_key()),
                        scheme,
                        connection,
                        MockMonitor::dummy(),
                        MockHandler::dummy(),
                    )
                })
                .collect();

            // An attempt can lose any of its requests and responses. A peer that answers more than
            // one attempt is collected at most once, and the count grows by one with each handler
            // collected.
            let request = Request { id: 1, data: 1 };
            let mut responders = HashSet::new();
            while responders.len() < peers.len() - 1 {
                assert_eq!(mailbox.send(Recipients::All, request.clone()), Feedback::Ok);
                loop {
                    select! {
                        collected = monitor_out.recv() => {
                            let collected = collected.unwrap();
                            assert!(
                                responders.insert(collected.handler),
                                "a handler must be collected at most once per collection"
                            );
                            assert_eq!(collected.count, responders.len());
                        },
                        _ = context.sleep(Duration::from_millis(100)) => break,
                    }
                }
            }

            // The peers collected are exactly the peers other than peer 0.
            assert_eq!(responders, peers[1..].iter().cloned().collect());
            context.auditor().state()
        })
    }

    #[rstest]
    #[test_traced]
    fn test_resend_over_lossy_links_collects_every_peer(#[values(0, 1, 2, 3, 4)] seed: u64) {
        // A run collects every peer, and a replay of its seed ends in the same state.
        assert_eq!(
            collect_over_lossy_links(seed),
            collect_over_lossy_links(seed),
            "runs with seed {seed} must end in the same state"
        );
    }

    #[test_traced]
    fn test_response_to_request_sent_before_cancel_is_collected_after_resend() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Link peers 0 and 1.
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Peer 0 originates, and peer 1 answers every request with twice its data.
            let scheme = schemes.next().unwrap();
            let (monitor, mut monitor_out) = MockMonitor::new();
            let mut mailbox0 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                monitor,
                MockHandler::dummy(),
            );
            let scheme = schemes.next().unwrap();
            let _mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                MockMonitor::dummy(),
                MockHandler::dummy(),
            );

            // Two requests share a commitment, and a cancel separates them.
            let stale = Request { id: 1, data: 10 };
            let fresh = Request { id: 1, data: 20 };
            assert_eq!(
                mailbox0.send(Recipients::One(peers[1].clone()), stale.clone()),
                Feedback::Ok
            );
            assert_eq!(mailbox0.cancel(stale.commitment()), Feedback::Ok);
            assert_eq!(
                mailbox0.send(Recipients::One(peers[1].clone()), fresh),
                Feedback::Ok
            );

            // The answer to the request sent before the cancel arrives first, and the collection
            // started after the cancel collects it.
            let collected = monitor_out.recv().await.unwrap();
            assert_eq!(collected.handler, peers[1]);
            assert_eq!(collected.response, Response { id: 1, result: 20 });
            assert_eq!(collected.count, 1);

            // The answer to the request sent after the cancel is then ignored.
            select! {
                _ = monitor_out.recv() => {
                    panic!("a handler must be collected at most once per collection");
                },
                _ = context.sleep(Duration::from_secs(1)) => {},
            }
            assert_eq!(
                engine_count(&context, "collect", Status::Dropped, &peers[0]),
                1
            );
        });
    }

    #[test_traced]
    fn test_recipient_before_cancel_is_ignored_after_resend_to_another() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Peer 0 runs the engine, and peers 1 and 2 are raw peers that answer when the test
            // decides.
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1, 2]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;
            let mut connections = connections.into_iter();
            let connection = connections.next().unwrap();
            let (mut raw1, mut raw_receiver1) = connections.next().unwrap();
            let (mut raw2, mut raw_receiver2) = connections.next().unwrap();

            // Peer 0 records what its monitor collects.
            let scheme = schemes.into_iter().next().unwrap();
            let (monitor, mut monitor_out) = MockMonitor::new();
            let mut mailbox = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connection,
                monitor,
                MockHandler::dummy(),
            );

            // Peer 0 sends a request to peer 1, and peer 1 receives it.
            let request = Request { id: 1, data: 10 };
            assert_eq!(
                mailbox.send(Recipients::One(peers[1].clone()), request.clone()),
                Feedback::Ok
            );
            raw_receiver1.recv().await.unwrap();

            // Peer 0 cancels the commitment and sends the request to peer 2 alone. Peer 2
            // receives it, so the engine has handled the cancel and the second send.
            assert_eq!(mailbox.cancel(request.commitment()), Feedback::Ok);
            assert_eq!(
                mailbox.send(Recipients::One(peers[2].clone()), request),
                Feedback::Ok
            );
            raw_receiver2.recv().await.unwrap();

            // Peer 1 answers late, and its response is ignored.
            let response = Message::Response(Response { id: 1, result: 20 }).encode();
            raw1.send(Recipients::One(peers[0].clone()), response.clone(), false);
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(
                engine_count(&context, "collect", Status::Dropped, &peers[0]),
                1
            );
            assert!(monitor_out.try_recv().is_err());

            // Peer 2 answers, and its response is collected.
            raw2.send(Recipients::One(peers[0].clone()), response, false);
            let collected = monitor_out.recv().await.unwrap();
            assert_eq!(collected.handler, peers[2]);
            assert_eq!(collected.count, 1);
        });
    }

    #[test_traced]
    fn test_rate_limited_recipient_is_not_collected() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Peer 0 runs the engine, and peers 1 and 2 are raw peers that send responses.
            let (mut oracle, _, peers, connections) =
                setup_network_and_peers(&context, &[0, 1, 2]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;
            let mut connections = connections.into_iter().skip(1);
            let (mut raw1, _raw_receiver1) = connections.next().unwrap();
            let (mut raw2, _raw_receiver2) = connections.next().unwrap();

            // Peer 0 registers the channel again so that its engine may send each peer one
            // message per second.
            let channel = oracle
                .control(peers[0].clone())
                .register(0, Quota::per_second(NZU32!(1)))
                .await
                .unwrap();
            let (monitor, mut monitor_out) = MockMonitor::new();
            let (engine, mut mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &peers[0]),
                config(
                    oracle.control(peers[0].clone()),
                    monitor,
                    MockHandler::dummy(),
                ),
            );
            engine.start(channel);

            // The first request spends peer 1's quota, so the second is sent to peer 2 alone.
            assert_eq!(
                mailbox.send(
                    Recipients::One(peers[1].clone()),
                    Request { id: 1, data: 0 }
                ),
                Feedback::Ok
            );
            assert_eq!(
                mailbox.send(
                    Recipients::Some(vec![peers[1].clone(), peers[2].clone()]),
                    Request { id: 2, data: 0 }
                ),
                Feedback::Ok
            );
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(
                engine_count(&context, "send", Status::Success, &peers[0]),
                2
            );

            // The skipped recipient's response is ignored, and the other recipient's response
            // is collected.
            let response = Message::Response(Response { id: 2, result: 0 }).encode();
            raw1.send(Recipients::One(peers[0].clone()), response.clone(), false);
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(
                engine_count(&context, "collect", Status::Dropped, &peers[0]),
                1
            );
            raw2.send(Recipients::One(peers[0].clone()), response, false);
            let collected = monitor_out.recv().await.unwrap();
            assert_eq!(collected.handler, peers[2]);
            assert_eq!(collected.count, 1);
            assert!(monitor_out.try_recv().is_err());
        });
    }

    /// The requests and responses an engine sends to one peer count against the same send limit.
    #[rstest]
    // A request spends the limit, so the response to that peer's request is dropped.
    #[case::request_first(true)]
    // A response spends the limit, so a request to that peer is skipped and starts no collection.
    #[case::response_first(false)]
    #[test_traced]
    fn test_requests_and_responses_share_send_limit(#[case] request_first: bool) {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Peer 0 runs the engine, and peer 1 is a raw peer.
            let (mut oracle, _, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            let (mut raw, mut raw_receiver) = connections.into_iter().nth(1).unwrap();

            // Peer 0 registers the channel again so that its engine may send each peer one
            // message per second.
            let channel = oracle
                .control(peers[0].clone())
                .register(0, Quota::per_second(NZU32!(1)))
                .await
                .unwrap();
            let (handler, mut handler_out) = MockHandler::new(true);
            let (engine, mut mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &peers[0]),
                config(
                    oracle.control(peers[0].clone()),
                    MockMonitor::dummy(),
                    handler,
                ),
            );
            engine.start(channel);

            // Within one second, peer 0 enqueues a request to peer 1 and its handler answers a
            // request from peer 1, in the order of the case.
            let request = Request { id: 1, data: 1 };
            let asked = Request { id: 2, data: 2 };
            for originate in [request_first, !request_first] {
                if originate {
                    assert_eq!(
                        mailbox.send(Recipients::One(peers[1].clone()), request.clone()),
                        Feedback::Ok
                    );
                } else {
                    raw.send(
                        Recipients::One(peers[0].clone()),
                        Message::Request(asked.clone()).encode(),
                        false,
                    );
                    assert!(handler_out.recv().await.unwrap().responded);
                }
                context.sleep(Duration::from_millis(100)).await;
            }

            // Only the first message reaches peer 1, even once the limit allows another.
            let first = if request_first {
                Message::Request(request)
            } else {
                Message::Response(Response { id: 2, result: 4 })
            };
            let (_, bytes) = raw_receiver.recv().await.unwrap();
            assert_eq!(bytes, first.encode().as_ref());
            select! {
                _ = raw_receiver.recv() => {
                    panic!("a message over the send limit must not be sent");
                },
                _ = context.sleep(Duration::from_secs(2)) => {},
            }

            // The second message is counted as dropped, and a skipped request starts no
            // collection.
            let (sent, answered) = if request_first { (1, 0) } else { (0, 1) };
            assert_eq!(
                engine_count(&context, "send", Status::Success, &peers[0]),
                sent
            );
            assert_eq!(
                engine_count(&context, "send", Status::Dropped, &peers[0]),
                1 - sent
            );
            assert_eq!(
                engine_count(&context, "serve", Status::Success, &peers[0]),
                answered
            );
            assert_eq!(
                engine_count(&context, "serve", Status::Dropped, &peers[0]),
                1 - answered
            );
            assert_eq!(
                engine_metric(&context, "outstanding", &peers[0]),
                i64::from(request_first)
            );
        });
    }

    #[test_traced]
    fn test_stopped_context_stops_engine() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // A single peer starts an engine on a channel that never closes.
            let (oracle, _, peers, _) = setup_network_and_peers(&context, &[0]).await;
            let (engine, mut mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &peers[0]),
                config(
                    oracle.control(peers[0].clone()),
                    MockMonitor::dummy(),
                    MockHandler::dummy(),
                ),
            );
            let handle = engine.start(inert_channel(&peers));

            // The engine stops while it waits for work with its mailbox held and its receiver
            // open, and its mailbox then reports it closed.
            context.sleep(Duration::from_millis(100)).await;
            context.child("stopper").stop(0, None).await.unwrap();
            handle
                .await
                .expect("an engine must stop once its context is stopped");
            assert_eq!(
                mailbox.cancel(Request { id: 1, data: 1 }.commitment()),
                Feedback::Closed
            );
        });
    }
}

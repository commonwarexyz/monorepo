//! Collect responses from peers on a [commonware_p2p] network.
//!
//! # Overview
//!
//! An [Engine] runs on every peer and plays both roles. As an originator it sends the requests
//! enqueued through its [Mailbox] and passes the responses it collects to its
//! [Monitor](crate::Monitor). As a handler it passes each request it admits to its
//! [Handler](crate::Handler) and returns any response to the peer that sent the request. Requests
//! and responses travel on two p2p channels, the requests channel and the responses channel, and
//! both are passed to [Engine::start].
//!
//! ```text
//!                  peer A                                              peer B
//!     application             Engine                       Engine               application
//! (Mailbox, Monitor)       (originator)                   (handler)              (Handler)
//!          |                     |                            |                      |
//!          |--- send ----------->|                            |                      |
//!          |                     |--- request --------------->|                      |
//!          |                     |    (requests channel)      |                      |
//!          |                     |                            |--- process --------->|
//!          |                     |                            |<-- response ---------|
//!          |                     |<-- response ---------------|                      |
//!          |                     |    (responses channel)     |                      |
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
//! The engine collects the first response for the commitment from each recipient. Its event loop
//! passes each collected response to [Monitor::collected](crate::Monitor::collected) with the
//! number of responses collected so far. A response from a peer that already responded, from a
//! peer the commitment was not sent to, or for a commitment with no collection is ignored, and its
//! sender is not blocked.
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
//! A response is lost when the network drops it, for example when the peer that requested it is
//! over its rate limit on the responses channel. The responses channel's quota must therefore be
//! at least as large as the requests channel's.
//!
//! The engine has no timeouts and no retries. The application retries a request by sending it
//! again, and it must cancel the commitment once it needs no more responses.
//!
//! # Invalid Messages
//!
//! A peer that sends a request or response the engine cannot decode is blocked through
//! [Config::blocker]. All peers must therefore use the same request and response types, with
//! codec configurations that accept each other's messages.
//!
//! # Serving Requests
//!
//! The engine keeps at most [Config::max_pending_requests] requests pending across all peers
//! and at most [Config::max_pending_requests_per_peer] from one peer. When either limit is full,
//! the engine drops the decoded request before calling [Handler::process](crate::Handler::process)
//! and increments `serve_limited_global_total` or `serve_limited_per_peer_total`. If both limits
//! are full, it counts the total limit. It does not block the peer or send a response.
//!
//! An admitted request holds its slot until the engine receives the handler's answer or sees
//! that the handler dropped the sender. A peer disconnect does not release the slot. There is
//! no timeout.
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
//! Request, sent on the requests channel:
//! +------------------------+
//! | request (encoded size) |
//! +------------------------+
//!
//! Response, sent on the responses channel:
//! +-------------------------+
//! | response (encoded size) |
//! +-------------------------+
//! ```
//!
//! Each payload the engine sends is the encoding of one request from its [Mailbox] or one response
//! from its [Handler](crate::Handler). The engine adds no framing, so each request and each
//! response must fit the configured `max_message_size` of the network that carries its channel,
//! less the subchannel prefix on a [Muxer](commonware_p2p::utils::mux::Muxer) subchannel.

mod config;
pub use config::Config;
mod engine;
pub use engine::Engine;
mod ingress;
pub use ingress::Mailbox;

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
    };
    use crate::{Handler, Monitor, Originator};
    use commonware_actor::Feedback;
    use commonware_codec::Encode;
    use commonware_cryptography::{
        Committable, Signer,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::{
        Blocker, Manager as _, Receiver as _, Recipients, Sender as _,
        simulated::{Link, Network, Oracle, Receiver, Sender},
    };
    use commonware_runtime::{
        Clock, Metrics as _, Quota, Runner, Spawner as _, Supervisor as _, deterministic,
        telemetry::metrics::{count_running_tasks, status::Status},
    };
    use commonware_utils::{
        NZU32, NZUsize,
        channel::{fallible::OneshotExt as _, mpsc, oneshot},
        ordered::Set,
        probability,
    };
    use rstest::rstest;
    use std::{collections::HashSet, num::NonZeroUsize, time::Duration};

    /// Default rate limit quota for tests (high enough to not interfere with normal operation)
    const TEST_QUOTA: Quota = Quota::per_second(NZU32!(1_000_000));

    const MAILBOX_SIZE: NonZeroUsize = commonware_utils::NZUsize!(1024);
    const MAX_PENDING_REQUESTS: NonZeroUsize = commonware_utils::NZUsize!(1024);
    const MAX_PENDING_REQUESTS_PER_PEER: NonZeroUsize = commonware_utils::NZUsize!(1024);
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

    async fn setup_network_and_peers(
        context: &deterministic::Context,
        peer_seeds: &[u64],
    ) -> (
        Oracle<PublicKey, deterministic::Context>,
        Vec<PrivateKey>,
        Vec<PublicKey>,
        Vec<(
            (
                Sender<PublicKey, deterministic::Context>,
                Receiver<PublicKey>,
            ),
            (
                Sender<PublicKey, deterministic::Context>,
                Receiver<PublicKey>,
            ),
        )>,
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
            let control = oracle.control(peer.clone());
            let (sender1, receiver1) = control.register(0, TEST_QUOTA).await.unwrap();
            let (sender2, receiver2) = control.register(1, TEST_QUOTA).await.unwrap();
            connections.push(((sender1, receiver1), (sender2, receiver2)));
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

    /// Reads gauge `name` exported by the engine labelled with `public_key`.
    fn engine_gauge(context: &deterministic::Context, name: &str, public_key: &PublicKey) -> i64 {
        let prefix = format!("engine_{name}{{");
        let label = format!("public_key=\"{public_key}\"");
        let encoded = context.encode();
        let line = encoded
            .lines()
            .find(|line| line.starts_with(&prefix) && line.contains(&label))
            .unwrap_or_else(|| panic!("gauge {name} must be exported for {public_key}"));
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

    /// Starts an engine for `signer` on `connection` and returns its mailbox.
    #[allow(clippy::type_complexity)]
    fn setup_and_spawn_engine(
        context: &deterministic::Context,
        blocker: impl Blocker<PublicKey = PublicKey>,
        signer: impl Signer<PublicKey = PublicKey>,
        connection: (
            (
                Sender<PublicKey, deterministic::Context>,
                Receiver<PublicKey>,
            ),
            (
                Sender<PublicKey, deterministic::Context>,
                Receiver<PublicKey>,
            ),
        ),
        monitor: impl Monitor<PublicKey = PublicKey, Response = Response>,
        handler: impl Handler<PublicKey = PublicKey, Request = Request, Response = Response>,
    ) -> Mailbox<PublicKey, Request> {
        let public_key = signer.public_key();
        let (engine, mailbox) = Engine::new(
            context
                .child("engine")
                .with_attribute("public_key", &public_key),
            Config {
                blocker,
                monitor,
                handler,
                mailbox_size: MAILBOX_SIZE,
                max_pending_requests: MAX_PENDING_REQUESTS,
                max_pending_requests_per_peer: MAX_PENDING_REQUESTS_PER_PEER,
                priority_requests: false,
                request_codec_config: (),
                priority_responses: false,
                response_codec_config: (),
            },
        );
        engine.start(connection.0, connection.1);

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
            let conn = connections.next().unwrap();
            let req_conn = conn.0;
            let res_conn = conn.1;
            let (mon, mut mon_out) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                (req_conn, res_conn),
                mon,
                MockHandler::dummy(),
            );

            // Setup peer 2
            let scheme = schemes.next().unwrap();
            let conn = connections.next().unwrap();
            let req_conn = conn.0;
            let res_conn = conn.1;
            let (handler, mut handler_out) = MockHandler::new(true);
            let _mailbox = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                (req_conn, res_conn),
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
            let conn = connections.next().unwrap();
            let req_conn = conn.0;
            let res_conn = conn.1;
            let (mon, mut mon_out) = MockMonitor::new();
            let mut mailbox = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                (req_conn, res_conn),
                mon,
                MockHandler::dummy(),
            );

            // Setup peer 2
            let scheme = schemes.next().unwrap();
            let conn = connections.next().unwrap();
            let req_conn = conn.0;
            let res_conn = conn.1;
            let (handler, _) = MockHandler::new(true);
            let _mailbox = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                (req_conn, res_conn),
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
            let conn1 = connections.next().unwrap();
            let req_conn1 = conn1.0;
            let res_conn1 = conn1.1;
            let (mon1, mut mon_out1) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme1.public_key()),
                scheme1,
                (req_conn1, res_conn1),
                mon1,
                MockHandler::dummy(),
            );

            // Setup peer 2
            let scheme2 = schemes.next().unwrap();
            let conn2 = connections.next().unwrap();
            let req_conn2 = conn2.0;
            let res_conn2 = conn2.1;
            let (handler2, _) = MockHandler::new(true);
            let _mailbox2 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme2.public_key()),
                scheme2,
                (req_conn2, res_conn2),
                MockMonitor::dummy(),
                handler2,
            );

            // Setup peer 3
            let scheme3 = schemes.next().unwrap();
            let conn3 = connections.next().unwrap();
            let req_conn3 = conn3.0;
            let res_conn3 = conn3.1;
            let (handler3, _) = MockHandler::new(true);
            let _mailbox3 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme3.public_key()),
                scheme3,
                (req_conn3, res_conn3),
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
            let conn1 = connections.next().unwrap();
            let req_conn1 = conn1.0;
            let res_conn1 = conn1.1;
            let (mon1, mut mon_out1) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme1.public_key()),
                scheme1,
                (req_conn1, res_conn1),
                mon1,
                MockHandler::dummy(),
            );

            // Setup peer 2
            let scheme2 = schemes.next().unwrap();
            let conn2 = connections.next().unwrap();
            let req_conn2 = conn2.0;
            let res_conn2 = conn2.1;
            let (handler2, _) = MockHandler::new(true);
            let _mailbox2 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme2.public_key()),
                scheme2,
                (req_conn2, res_conn2),
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
            let conn1 = connections.next().unwrap();
            let req_conn1 = conn1.0;
            let res_conn1 = conn1.1;
            let (mon1, mut mon_out1) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme1.public_key()),
                scheme1,
                (req_conn1, res_conn1),
                mon1,
                MockHandler::dummy(),
            );

            // Setup peer 2
            let scheme2 = schemes.next().unwrap();
            let conn2 = connections.next().unwrap();
            let req_conn2 = conn2.0;
            let res_conn2 = conn2.1;
            let (mut handler2, _) = MockHandler::new(false);
            handler2.set_response(10, Response { id: 10, result: 20 });
            handler2.set_response(20, Response { id: 20, result: 40 });
            let _mailbox2 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme2.public_key()),
                scheme2,
                (req_conn2, res_conn2),
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
            let conn1 = connections.next().unwrap();
            let req_conn1 = conn1.0;
            let res_conn1 = conn1.1;
            let (mon1, mut mon_out1) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme1.public_key()),
                scheme1,
                (req_conn1, res_conn1),
                mon1,
                MockHandler::dummy(),
            );

            // Setup peer 2 with handler that doesn't respond
            let scheme2 = schemes.next().unwrap();
            let conn2 = connections.next().unwrap();
            let req_conn2 = conn2.0;
            let res_conn2 = conn2.1;
            let (handler2, mut handler_out2) = MockHandler::new(false);
            let _mailbox2 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme2.public_key()),
                scheme2,
                (req_conn2, res_conn2),
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

    #[test_traced]
    fn test_empty_recipients() {
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

            // A request that reaches no peer starts no collection.
            for recipients in [Recipients::All, Recipients::Some(Vec::new())] {
                let request = Request { id: 1, data: 1 };
                assert_eq!(mailbox.send(recipients, request), Feedback::Ok);
            }
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(
                engine_count(&context, "send", Status::Dropped, &peers[0]),
                2
            );
            assert_eq!(engine_gauge(&context, "outstanding", &peers[0]), 0);
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

            // Peer 0's request sender is closed, and peer 1 is a raw peer.
            let ((_request_sender, request_receiver), responses) = connections.next().unwrap();
            let (_raw_requests, (mut raw_responses, _raw_response_receiver)) =
                connections.next().unwrap();
            let public_key = schemes[0].public_key();
            let (monitor, mut monitor_out) = MockMonitor::new();
            let (engine, mut mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &public_key),
                Config {
                    blocker: oracle.control(public_key),
                    monitor,
                    handler: MockHandler::dummy(),
                    mailbox_size: MAILBOX_SIZE,
                    max_pending_requests: MAX_PENDING_REQUESTS,
                    max_pending_requests_per_peer: MAX_PENDING_REQUESTS_PER_PEER,
                    priority_requests: false,
                    request_codec_config: (),
                    priority_responses: false,
                    response_codec_config: (),
                },
            );
            engine.start((Failing::<PublicKey>::new(), request_receiver), responses);

            // A request that reaches no peer starts no collection.
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
            assert_eq!(engine_gauge(&context, "outstanding", &peers[0]), 0);

            // A response from the intended recipient is not collected.
            raw_responses.send(
                Recipients::One(peers[0].clone()),
                Response { id: 1, result: 2 }.encode(),
                false,
            );
            select! {
                _ = monitor_out.recv() => {
                    panic!("a peer the request never reached must not be collected");
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
            let conn = connections.next().unwrap();
            let (sender1, receiver1) = conn.0; // Request channel
            let (sender2, receiver2) = conn.1; // Response channel
            let public_key = scheme.public_key();
            let (engine, mut mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &public_key),
                Config {
                    blocker: oracle.control(public_key),
                    monitor: MockMonitor::dummy(),
                    handler: MockHandler::dummy(),
                    mailbox_size: MAILBOX_SIZE,
                    max_pending_requests: MAX_PENDING_REQUESTS,
                    max_pending_requests_per_peer: MAX_PENDING_REQUESTS_PER_PEER,
                    priority_requests: false,
                    request_codec_config: (),
                    priority_responses: false,
                    response_codec_config: (),
                },
            );

            // Start engine
            let handle = engine.start((sender1, receiver1), (sender2, receiver2));

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
            let conn1 = connections.next().unwrap();
            let req_conn1 = conn1.0;
            let res_conn1 = conn1.1;
            let (mon1, mut mon_out1) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme1.public_key()),
                scheme1,
                (req_conn1, res_conn1),
                mon1,
                MockHandler::dummy(),
            );

            // Setup peer 2 (legitimate responder)
            let scheme2 = schemes.next().unwrap();
            let conn2 = connections.next().unwrap();
            let req_conn2 = conn2.0;
            let res_conn2 = conn2.1;
            let (handler2, _) = MockHandler::new(true);
            let _mailbox2 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme2.public_key()),
                scheme2,
                (req_conn2, res_conn2),
                MockMonitor::dummy(),
                handler2,
            );

            // Setup peer 3 (will respond with same commitment as peer 2's request)
            let conn3 = connections.next().unwrap();
            let mut res_conn3 = conn3.1;

            // Send request from peer 1 to peer 2 (collector records the in-flight request)
            let request_to_peer2 = Request { id: 42, data: 42 };
            assert_eq!(
                mailbox1.send(Recipients::One(peers[1].clone()), request_to_peer2.clone()),
                Feedback::Ok
            );

            // Send a response from peer 3 to peer 1
            let response_to_peer1 = Response { id: 42, result: 72 };
            res_conn3.0.send(
                Recipients::One(peers[0].clone()),
                response_to_peer1.encode(),
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
    #[allow(clippy::type_complexity)]
    fn spawn_engines_with_handles(
        engine_context: deterministic::Context,
        oracle: &Oracle<PublicKey, deterministic::Context>,
        schemes: Vec<PrivateKey>,
        connections: Vec<(
            (
                Sender<PublicKey, deterministic::Context>,
                Receiver<PublicKey>,
            ),
            (
                Sender<PublicKey, deterministic::Context>,
                Receiver<PublicKey>,
            ),
        )>,
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
                Config {
                    blocker: oracle.control(scheme.public_key()),
                    monitor: mon,
                    handler,
                    mailbox_size: MAILBOX_SIZE,
                    max_pending_requests: MAX_PENDING_REQUESTS,
                    max_pending_requests_per_peer: MAX_PENDING_REQUESTS_PER_PEER,
                    priority_requests: false,
                    request_codec_config: (),
                    priority_responses: false,
                    response_codec_config: (),
                },
            );
            handles.push(engine.start(conn.0, conn.1));
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
                Config {
                    blocker: oracle.control(public_key),
                    monitor: MockMonitor::dummy(),
                    handler: MockHandler::dummy(),
                    mailbox_size: MAILBOX_SIZE,
                    max_pending_requests: MAX_PENDING_REQUESTS,
                    max_pending_requests_per_peer: MAX_PENDING_REQUESTS_PER_PEER,
                    priority_requests: false,
                    request_codec_config: (),
                    priority_responses: false,
                    response_codec_config: (),
                },
            );
            let handle = engine.start(conn.0, conn.1);

            drop(mailbox);
            handle
                .await
                .expect("engine should stop once every mailbox is dropped");
        });
    }

    #[test_traced]
    fn test_invalid_request_blocks_sender_and_engine_keeps_serving() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Link peer 0 to peers 1 and 2.
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1, 2]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Peer 0 serves, peer 1 originates, and peer 2 is a raw attacker.
            let scheme = schemes.next().unwrap();
            let (handler, mut handler_out) = MockHandler::new(true);
            let _mailbox0 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                MockMonitor::dummy(),
                handler,
            );
            let scheme = schemes.next().unwrap();
            let (monitor, mut monitor_out) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.control(scheme.public_key()),
                scheme,
                connections.next().unwrap(),
                monitor,
                MockHandler::dummy(),
            );
            let ((mut attacker, _attacker_requests), _attacker_responses) =
                connections.next().unwrap();

            // Bytes that do not decode as a request block the attacker.
            attacker.send(Recipients::One(peers[0].clone()), vec![0xFF], false);
            wait_for_block(&context, &oracle, &peers[0], &peers[2]).await;
            assert_eq!(oracle.blocked().await.unwrap().len(), 1);

            // The engine keeps serving honest peers, and the invalid request never reached the
            // handler.
            let request = Request { id: 1, data: 1 };
            assert_eq!(
                mailbox1.send(Recipients::One(peers[0].clone()), request.clone()),
                Feedback::Ok
            );
            let processed = handler_out.recv().await.unwrap();
            assert_eq!(processed.origin, peers[1]);
            assert_eq!(processed.request, request);
            let collected = monitor_out.recv().await.unwrap();
            assert_eq!(collected.handler, peers[0]);
            assert_eq!(collected.count, 1);
        });
    }

    #[test_traced]
    fn test_invalid_response_blocks_sender_and_engine_keeps_collecting() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Link peer 0 to peers 1 and 2.
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1, 2]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Peer 0 originates, peer 1 serves, and peer 2 is a raw attacker.
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
            let (_attacker_requests, (mut attacker, _attacker_responses)) =
                connections.next().unwrap();

            // Bytes that do not decode as a response block the attacker.
            attacker.send(Recipients::One(peers[0].clone()), vec![0xFF], false);
            wait_for_block(&context, &oracle, &peers[0], &peers[2]).await;
            assert_eq!(oracle.blocked().await.unwrap().len(), 1);

            // The engine keeps collecting from honest peers.
            let request = Request { id: 1, data: 1 };
            assert_eq!(
                mailbox0.send(Recipients::One(peers[1].clone()), request),
                Feedback::Ok
            );
            let collected = monitor_out.recv().await.unwrap();
            assert_eq!(collected.handler, peers[1]);
            assert_eq!(collected.response, Response { id: 1, result: 2 });
            assert_eq!(collected.count, 1);
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
    fn test_resend_adds_recipients_to_collection() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Link peer 0 to peers 1 and 2.
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1, 2]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Peer 0 originates, and peers 1 and 2 serve.
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

            // Both sends are enqueued before either response can arrive.
            let request = Request { id: 4, data: 4 };
            for peer in &peers[1..] {
                assert_eq!(
                    mailbox0.send(Recipients::One(peer.clone()), request.clone()),
                    Feedback::Ok
                );
            }

            // The responders to both sends are collected in one collection.
            let first = monitor_out.recv().await.unwrap();
            let second = monitor_out.recv().await.unwrap();
            assert_eq!((first.count, second.count), (1, 2));
            let mut responders = vec![first.handler, second.handler];
            responders.sort();
            let mut expected = peers[1..].to_vec();
            expected.sort();
            assert_eq!(responders, expected);
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

            // One collection collects both responses, each with the content its peer produced.
            let first = monitor_out.recv().await.unwrap();
            let second = monitor_out.recv().await.unwrap();
            assert_eq!((first.count, second.count), (1, 2));
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

            // Peer 0 originates, peer 1 serves, and peer 2 sends raw unsolicited responses.
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
            let (_raw_requests, (mut raw, _raw_response_receiver)) = connections.next().unwrap();

            // Unsolicited responses neither start a collection nor block their sender.
            for id in [7, 8, 9] {
                raw.send(
                    Recipients::One(peers[0].clone()),
                    Response { id, result: 0 }.encode(),
                    false,
                );
            }
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(
                engine_count(&context, "collect", Status::Dropped, &peers[0]),
                3
            );
            assert_eq!(engine_gauge(&context, "outstanding", &peers[0]), 0);
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
            assert_eq!(engine_gauge(&context, "outstanding", &peers[0]), 2);

            // Cancelling an unknown commitment changes nothing, and cancelling a sent one ends its
            // collection.
            let unknown = Request { id: 3, data: 0 }.commitment();
            assert_eq!(mailbox0.cancel(unknown), Feedback::Ok);
            assert_eq!(
                mailbox0.cancel(Request { id: 7, data: 0 }.commitment()),
                Feedback::Ok
            );
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(engine_gauge(&context, "outstanding", &peers[0]), 1);
            assert_eq!(
                mailbox0.cancel(Request { id: 2, data: 0 }.commitment()),
                Feedback::Ok
            );
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(engine_gauge(&context, "outstanding", &peers[0]), 0);
        });
    }

    #[test_traced]
    fn test_wire_payloads_are_bare_encodings() {
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
            let ((_raw_request_sender, mut raw_requests), (mut raw_responses, _raw_receiver)) =
                connections.next().unwrap();

            // A request travels as its bare encoding.
            let request = Request { id: 9, data: 3 };
            assert_eq!(
                mailbox0.send(Recipients::One(peers[1].clone()), request.clone()),
                Feedback::Ok
            );
            let (origin, bytes) = raw_requests.recv().await.unwrap();
            assert_eq!(origin, peers[0]);
            assert_eq!(bytes, request.encode().as_ref());

            // A bare response encoding is collected.
            let response = Response { id: 9, result: 6 };
            raw_responses.send(Recipients::One(peers[0].clone()), response.encode(), false);
            let collected = monitor_out.recv().await.unwrap();
            assert_eq!(collected.handler, peers[1]);
            assert_eq!(collected.response, response);
            assert_eq!(collected.count, 1);
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

            // Peer 0 sends through recording senders, and peer 1 is a raw peer.
            let ((_request_sender, requests_in), (_response_sender, responses_in)) =
                connections.next().unwrap();
            let ((mut raw_requests, _raw_request_receiver), _raw_responses) =
                connections.next().unwrap();
            let (request_sender, sent_requests) = Recording::<PublicKey>::new();
            let (response_sender, sent_responses) = Recording::<PublicKey>::new();
            let (engine, mut mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &peers[0]),
                Config {
                    blocker: oracle.control(peers[0].clone()),
                    monitor: MockMonitor::dummy(),
                    handler: MockHandler::dummy(),
                    mailbox_size: MAILBOX_SIZE,
                    max_pending_requests: MAX_PENDING_REQUESTS,
                    max_pending_requests_per_peer: MAX_PENDING_REQUESTS_PER_PEER,
                    priority_requests,
                    request_codec_config: (),
                    priority_responses,
                    response_codec_config: (),
                },
            );
            engine.start(
                (request_sender, requests_in),
                (response_sender, responses_in),
            );

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
                sent_requests.lock().as_slice(),
                [(Recipients::One(peer), priority)]
                    if peer == &peers[1] && *priority == priority_requests
            ));

            // A response carries the response priority and goes only to the requester.
            raw_requests.send(
                Recipients::One(peers[0].clone()),
                Request { id: 2, data: 2 }.encode(),
                true,
            );
            context.sleep(Duration::from_millis(100)).await;
            assert!(matches!(
                sent_responses.lock().as_slice(),
                [(Recipients::One(peer), priority)]
                    if peer == &peers[1] && *priority == priority_responses
            ));
        });
    }

    #[test_traced]
    fn test_overflow_cancel_prunes_queued_send() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Peer 0 runs the engine, and peer 1 reads the raw requests it sends.
            let (mut oracle, _, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            let mut connections = connections.into_iter();
            let connection = connections.next().unwrap();
            let ((_raw_request_sender, mut raw_requests), _raw_responses) =
                connections.next().unwrap();

            // Give peer 0 a one-slot inbox.
            let (engine, mut mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &peers[0]),
                Config {
                    blocker: oracle.control(peers[0].clone()),
                    monitor: MockMonitor::dummy(),
                    handler: MockHandler::dummy(),
                    mailbox_size: NZUsize!(1),
                    max_pending_requests: MAX_PENDING_REQUESTS,
                    max_pending_requests_per_peer: MAX_PENDING_REQUESTS_PER_PEER,
                    priority_requests: false,
                    request_codec_config: (),
                    priority_responses: false,
                    response_codec_config: (),
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
            engine.start(connection.0, connection.1);

            // Only the request that was not cancelled reaches the wire and starts a collection.
            let (_, bytes) = raw_requests.recv().await.unwrap();
            assert_eq!(bytes, kept.encode().as_ref());
            select! {
                _ = raw_requests.recv() => {
                    panic!("a request cancelled while it waits behind the inbox must not be sent");
                },
                _ = context.sleep(Duration::from_secs(1)) => {},
            }
            assert_eq!(engine_gauge(&context, "outstanding", &peers[0]), 1);
        });
    }

    /// An engine whose receiver on `channel` is already closed stops as soon as it starts.
    #[rstest]
    // The requests channel is closed.
    #[case::requests(0)]
    // The responses channel is closed.
    #[case::responses(1)]
    #[test_traced]
    fn test_closed_network_receiver_stops_engine(#[case] channel: u64) {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // A single peer with no links.
            let (oracle, _, peers, connections) = setup_network_and_peers(&context, &[0]).await;

            // Registering a channel again closes the receiver the engine starts with.
            let _replacement = oracle
                .control(peers[0].clone())
                .register(channel, TEST_QUOTA)
                .await
                .unwrap();

            // The engine stops as soon as it starts, and its mailbox then reports it closed.
            let (engine, mut mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &peers[0]),
                Config {
                    blocker: oracle.control(peers[0].clone()),
                    monitor: MockMonitor::dummy(),
                    handler: MockHandler::dummy(),
                    mailbox_size: MAILBOX_SIZE,
                    max_pending_requests: MAX_PENDING_REQUESTS,
                    max_pending_requests_per_peer: MAX_PENDING_REQUESTS_PER_PEER,
                    priority_requests: false,
                    request_codec_config: (),
                    priority_responses: false,
                    response_codec_config: (),
                },
            );
            let connection = connections.into_iter().next().unwrap();
            engine
                .start(connection.0, connection.1)
                .await
                .expect("an engine must stop once a network receiver closes");
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
                    panic!("a handler must be collected once per collection");
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
            // Link peer 0 to every other peer, and peer 1 to peer 3.
            let (mut oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1, 2, 3]).await;
            for peer in 1..peers.len() {
                add_link(&mut oracle, LINK.clone(), &peers, 0, peer).await;
            }
            add_link(&mut oracle, LINK.clone(), &peers, 1, 3).await;
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
            let (requests, (_response_sender, response_receiver)) = connections.next().unwrap();
            let (handler, mut silenced_out) = MockHandler::new(true);
            let (engine, _mailbox2) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &public_key),
                Config {
                    blocker: oracle.control(public_key),
                    monitor: MockMonitor::dummy(),
                    handler,
                    mailbox_size: MAILBOX_SIZE,
                    max_pending_requests: MAX_PENDING_REQUESTS,
                    max_pending_requests_per_peer: MAX_PENDING_REQUESTS_PER_PEER,
                    priority_requests: false,
                    request_codec_config: (),
                    priority_responses: false,
                    response_codec_config: (),
                },
            );
            engine.start(requests, (Failing::<PublicKey>::new(), response_receiver));
            let ((mut raw_requests, _), (mut raw_responses, _)) = connections.next().unwrap();

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
            raw_responses.send(
                Recipients::One(peers[0].clone()),
                Response { id: 8, result: 0 }.encode(),
                false,
            );
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(
                engine_count(&context, "collect", Status::Dropped, &peers[0]),
                1
            );

            // Bytes that do not decode are invalid on either channel.
            raw_requests.send(Recipients::One(peers[1].clone()), vec![0xFF], false);
            wait_for_block(&context, &oracle, &peers[1], &peers[3]).await;
            assert_eq!(
                engine_count(&context, "serve", Status::Invalid, &peers[1]),
                1
            );
            raw_responses.send(Recipients::One(peers[0].clone()), vec![0xFF], false);
            wait_for_block(&context, &oracle, &peers[0], &peers[3]).await;
            assert_eq!(
                engine_count(&context, "collect", Status::Invalid, &peers[0]),
                1
            );
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
            assert_eq!(engine_gauge(&context, "serve_processing", &peers[1]), 2);

            // A response sent later is collected.
            let response = Response { id: 2, result: 7 };
            assert!(second_responder.send_lossy(response.clone()));
            let collected = monitor_out.recv().await.unwrap();
            assert_eq!(collected.handler, peers[1]);
            assert_eq!(collected.response, response);
            assert_eq!(engine_gauge(&context, "serve_processing", &peers[1]), 1);

            // A dropped responder releases its request without a response.
            drop(first_responder);
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(engine_gauge(&context, "serve_processing", &peers[1]), 0);
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
            // one attempt is collected once, and the count grows by one with each new responder.
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
                                "a handler must be collected once"
                            );
                            assert_eq!(collected.count, responders.len());
                        },
                        _ = context.sleep(Duration::from_millis(100)) => break,
                    }
                }
            }
            context.auditor().state()
        })
    }

    #[test_traced]
    fn test_resend_over_lossy_links_collects_every_peer() {
        // Every seed collects every peer, and a replay of the seed ends in the same state.
        for seed in 0..5 {
            assert_eq!(
                collect_over_lossy_links(seed),
                collect_over_lossy_links(seed),
                "runs with seed {seed} must end in the same state"
            );
        }
    }

    /// A call the engine made on an [Ordered] mock.
    #[derive(Debug, PartialEq, Eq)]
    enum Call {
        /// The engine called [Handler::process].
        Process,
        /// The engine called [Monitor::collected].
        Collected,
    }

    /// A handler and monitor that log their calls in the order the engine makes them.
    #[derive(Clone)]
    struct Ordered {
        calls: mpsc::UnboundedSender<Call>,
    }

    impl Handler for Ordered {
        type PublicKey = PublicKey;
        type Request = Request;
        type Response = Response;

        fn process(&mut self, _: PublicKey, _: Request) -> oneshot::Receiver<Response> {
            let _ = self.calls.send(Call::Process);
            oneshot::channel().1
        }
    }

    impl Monitor for Ordered {
        type PublicKey = PublicKey;
        type Response = Response;

        fn collected(&mut self, _: PublicKey, _: Response, _: usize) {
            let _ = self.calls.send(Call::Collected);
        }
    }

    #[test_traced]
    fn test_waiting_response_is_handled_before_waiting_request() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Peer 0 runs the engine, and peer 1 is a raw peer.
            let (mut oracle, _, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            let mut connections = connections.into_iter();
            let connection = connections.next().unwrap();
            let ((mut raw_requests, _raw_request_receiver), (mut raw_responses, _raw_receiver)) =
                connections.next().unwrap();

            // Peer 0's handler and monitor log each call its engine makes.
            let (calls, mut observed) = mpsc::unbounded_channel();
            let ordered = Ordered { calls };
            let (engine, mut mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &peers[0]),
                Config {
                    blocker: oracle.control(peers[0].clone()),
                    monitor: ordered.clone(),
                    handler: ordered,
                    mailbox_size: MAILBOX_SIZE,
                    max_pending_requests: MAX_PENDING_REQUESTS,
                    max_pending_requests_per_peer: MAX_PENDING_REQUESTS_PER_PEER,
                    priority_requests: false,
                    request_codec_config: (),
                    priority_responses: false,
                    response_codec_config: (),
                },
            );

            // Peer 0 enqueues a request to peer 1, and a request and a response from peer 1 both
            // wait for peer 0's engine to start.
            assert_eq!(
                mailbox.send(
                    Recipients::One(peers[1].clone()),
                    Request { id: 1, data: 1 }
                ),
                Feedback::Ok
            );
            raw_requests.send(
                Recipients::One(peers[0].clone()),
                Request { id: 2, data: 2 }.encode(),
                false,
            );
            raw_responses.send(
                Recipients::One(peers[0].clone()),
                Response { id: 1, result: 2 }.encode(),
                false,
            );
            context.sleep(Duration::from_millis(100)).await;
            engine.start(connection.0, connection.1);

            // The engine collects the response before it serves the request.
            assert_eq!(observed.recv().await.unwrap(), Call::Collected);
            assert_eq!(observed.recv().await.unwrap(), Call::Process);
        });
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
                    panic!("a handler must be collected once per collection");
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
    fn test_rate_limited_recipient_is_not_collected() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Peer 0 runs the engine, and peers 1 and 2 send raw responses.
            let (mut oracle, _, peers, connections) =
                setup_network_and_peers(&context, &[0, 1, 2]).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 1).await;
            add_link(&mut oracle, LINK.clone(), &peers, 0, 2).await;
            let mut connections = connections.into_iter();
            let (_, responses) = connections.next().unwrap();
            let (_raw_requests1, (mut raw_responses1, _raw_receiver1)) =
                connections.next().unwrap();
            let (_raw_requests2, (mut raw_responses2, _raw_receiver2)) =
                connections.next().unwrap();

            // Peer 0's engine may send each peer one request per second.
            let requests = oracle
                .control(peers[0].clone())
                .register(0, Quota::per_second(NZU32!(1)))
                .await
                .unwrap();
            let (monitor, mut monitor_out) = MockMonitor::new();
            let (engine, mut mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &peers[0]),
                Config {
                    blocker: oracle.control(peers[0].clone()),
                    monitor,
                    handler: MockHandler::dummy(),
                    mailbox_size: MAILBOX_SIZE,
                    max_pending_requests: MAX_PENDING_REQUESTS,
                    max_pending_requests_per_peer: MAX_PENDING_REQUESTS_PER_PEER,
                    priority_requests: false,
                    request_codec_config: (),
                    priority_responses: false,
                    response_codec_config: (),
                },
            );
            engine.start(requests, responses);

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
            let response = Response { id: 2, result: 0 };
            raw_responses1.send(Recipients::One(peers[0].clone()), response.encode(), false);
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(
                engine_count(&context, "collect", Status::Dropped, &peers[0]),
                1
            );
            raw_responses2.send(Recipients::One(peers[0].clone()), response.encode(), false);
            let collected = monitor_out.recv().await.unwrap();
            assert_eq!(collected.handler, peers[2]);
            assert_eq!(collected.count, 1);
            assert!(monitor_out.try_recv().is_err());
        });
    }

    #[test_traced]
    fn test_stopped_context_stops_engine() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // A single peer starts an engine.
            let (oracle, _, peers, connections) = setup_network_and_peers(&context, &[0]).await;
            let (engine, mut mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &peers[0]),
                Config {
                    blocker: oracle.control(peers[0].clone()),
                    monitor: MockMonitor::dummy(),
                    handler: MockHandler::dummy(),
                    mailbox_size: MAILBOX_SIZE,
                    max_pending_requests: MAX_PENDING_REQUESTS,
                    max_pending_requests_per_peer: MAX_PENDING_REQUESTS_PER_PEER,
                    priority_requests: false,
                    request_codec_config: (),
                    priority_responses: false,
                    response_codec_config: (),
                },
            );
            let connection = connections.into_iter().next().unwrap();
            let handle = engine.start(connection.0, connection.1);

            // The engine stops while its mailbox is held and its receivers are open, and its
            // mailbox then reports it closed.
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

    #[test_traced]
    fn test_pending_limits_drop_requests_until_a_slot_frees() {
        /// Sends request `id` from a raw peer to `to` and returns its responder if the handler
        /// received it.
        async fn serve(
            context: &deterministic::Context,
            sender: &mut Sender<PublicKey, deterministic::Context>,
            to: &PublicKey,
            deferred: &mut mpsc::UnboundedReceiver<(Request, oneshot::Sender<Response>)>,
            id: u64,
        ) -> Option<oneshot::Sender<Response>> {
            sender.send(
                Recipients::One(to.clone()),
                Request { id, data: 0 }.encode(),
                false,
            );
            context.sleep(Duration::from_millis(100)).await;
            let (request, responder) = deferred.try_recv().ok()?;
            assert_eq!(request.id, id);
            Some(responder)
        }

        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            // Peer 0 holds at most two requests pending, one per peer, and peers 1 to 3 (A, B,
            // and C) send raw requests.
            let (mut oracle, _, peers, connections) =
                setup_network_and_peers(&context, &[0, 1, 2, 3]).await;
            for peer in 1..peers.len() {
                add_link(&mut oracle, LINK.clone(), &peers, 0, peer).await;
            }
            let mut connections = connections.into_iter();
            let (requests, responses) = connections.next().unwrap();
            let mut raw: Vec<_> = connections
                .map(|((sender, _), (_, receiver))| (sender, receiver))
                .collect();
            let (handler, mut deferred) = DeferringHandler::new();
            let (engine, _mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("limit", "caller")
                    .with_attribute("public_key", &peers[0]),
                Config {
                    blocker: oracle.control(peers[0].clone()),
                    monitor: MockMonitor::dummy(),
                    handler,
                    mailbox_size: MAILBOX_SIZE,
                    max_pending_requests: NZUsize!(2),
                    max_pending_requests_per_peer: NZUsize!(1),
                    priority_requests: false,
                    request_codec_config: (),
                    priority_responses: false,
                    response_codec_config: (),
                },
            );
            engine.start(requests, responses);
            let to = &peers[0];

            // A holds its one slot, B takes the last slot, and the handler never sees A's second
            // request or C's first.
            let a = serve(&context, &mut raw[0].0, to, &mut deferred, 1)
                .await
                .unwrap();
            assert!(
                serve(&context, &mut raw[0].0, to, &mut deferred, 2)
                    .await
                    .is_none()
            );
            let b = serve(&context, &mut raw[1].0, to, &mut deferred, 3)
                .await
                .unwrap();
            assert!(
                serve(&context, &mut raw[2].0, to, &mut deferred, 4)
                    .await
                    .is_none()
            );
            assert_eq!(engine_gauge(&context, "serve_processing", to), 2);
            assert!(oracle.blocked().await.unwrap().is_empty());

            // An answered request frees A's slot.
            let response = Response { id: 1, result: 7 };
            assert!(a.send_lossy(response.clone()));
            let (_, bytes) = raw[0].1.recv().await.unwrap();
            assert_eq!(bytes, response.encode().as_ref());
            let _a = serve(&context, &mut raw[0].0, to, &mut deferred, 5)
                .await
                .unwrap();

            // A declined request frees a slot that C can take.
            drop(b);
            let _c = serve(&context, &mut raw[2].0, to, &mut deferred, 6)
                .await
                .unwrap();

            // Each rejection is counted once and in no serve status.
            let encoded = context.encode();
            for name in ["serve_limited_global_total", "serve_limited_per_peer_total"] {
                let expected = format!("engine_{name}{{limit=\"caller\",public_key=\"{to}\"}} 1");
                assert!(encoded.lines().any(|line| line == expected), "{expected}");
            }
            assert_eq!(engine_count(&context, "serve", Status::Success, to), 1);
            assert_eq!(engine_count(&context, "serve", Status::Failure, to), 1);
            assert_eq!(engine_count(&context, "serve", Status::Dropped, to), 0);
        });
    }
}

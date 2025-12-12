//! Implementation of a [commonware_p2p]-optimized `collector`.

use crate::{Handler, Monitor};

mod engine;
use commonware_p2p::Blocker;
pub use engine::Engine;
mod ingress;
pub use ingress::{Mailbox, Message};

#[cfg(test)]
mod mocks;

/// Configuration for an [Engine].
#[derive(Clone)]
pub struct Config<B: Blocker, M: Monitor, H: Handler, RqC, RsC> {
    /// The [commonware_p2p::Blocker] that will be used to block peers from sending messages.
    pub blocker: B,

    /// The [Monitor] that will be notified when a response is collected.
    pub monitor: M,

    /// The [Handler] that will be used to process requests.
    pub handler: H,

    /// The size of the mailbox for sending and receiving messages.
    pub mailbox_size: usize,

    /// Whether or not to send requests with priority over other network messages.
    pub priority_request: bool,

    /// The [commonware_codec::Codec] configuration for requests.
    pub request_codec: RqC,

    /// Whether or not to send responses with priority over other network messages.
    pub priority_response: bool,

    /// The [commonware_codec::Codec] configuration for responses.
    pub response_codec: RsC,
}

#[cfg(test)]
mod tests {
    use super::{
        mocks::{
            handler::Handler as MockHandler,
            monitor::Monitor as MockMonitor,
            types::{Request, Response},
        },
        Config, Engine, Mailbox,
    };
    use crate::{Error, Handler, Monitor, Originator};
    use commonware_codec::Encode;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Committable, PrivateKeyExt, Signer,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::{
        simulated::{Link, Network, Oracle, Receiver, Sender},
        Blocker, Recipients, Sender as _,
    };
    use commonware_runtime::{deterministic, Clock, Metrics, Runner};
    use commonware_utils::NZU32;
    use futures::StreamExt;
    use governor::Quota;
    use std::time::Duration;

    /// Default rate limit quota for tests (high enough to not interfere with normal operation)
    const TEST_QUOTA: Quota = Quota::per_second(NZU32!(1_000_000));

    const MAILBOX_SIZE: usize = 1024;
    const LINK: Link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };
    const LINK_SLOW: Link = Link {
        latency: Duration::from_secs(1),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };

    async fn setup_network_and_peers(
        context: &deterministic::Context,
        peer_seeds: &[u64],
    ) -> (
        Oracle<PublicKey>,
        Vec<PrivateKey>,
        Vec<PublicKey>,
        Vec<(
            (Sender<PublicKey>, Receiver<PublicKey>),
            (Sender<PublicKey>, Receiver<PublicKey>),
        )>,
    ) {
        let (network, oracle) = Network::new(
            context.with_label("network"),
            commonware_p2p::simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: None,
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
            let mut control = oracle.control(peer.clone());
            let (sender1, receiver1) = control.register(0, TEST_QUOTA).await.unwrap();
            let (sender2, receiver2) = control.register(1, TEST_QUOTA).await.unwrap();
            connections.push(((sender1, receiver1), (sender2, receiver2)));
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
    async fn setup_and_spawn_engine(
        context: &deterministic::Context,
        blocker: impl Blocker<PublicKey = PublicKey>,
        signer: impl Signer<PublicKey = PublicKey>,
        connection: (
            (Sender<PublicKey>, Receiver<PublicKey>),
            (Sender<PublicKey>, Receiver<PublicKey>),
        ),
        monitor: impl Monitor<PublicKey = PublicKey, Response = Response>,
        handler: impl Handler<PublicKey = PublicKey, Request = Request, Response = Response>,
    ) -> Mailbox<PublicKey, Request> {
        let public_key = signer.public_key();
        let (engine, mailbox) = Engine::new(
            context.with_label(&format!("engine_{public_key}")),
            Config {
                blocker,
                monitor,
                handler,
                mailbox_size: MAILBOX_SIZE,
                priority_request: false,
                request_codec: (),
                priority_response: false,
                response_codec: (),
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
            )
            .await;

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
            )
            .await;

            // Send request from peer 1 to peer 2
            let request = Request { id: 1, data: 1 };
            let recipients = mailbox1
                .send(Recipients::One(peers[1].clone()), request.clone())
                .await
                .expect("send failed");
            assert_eq!(recipients, vec![peers[1].clone()]);

            // Verify peer 2 received the request
            let processed = handler_out.next().await.unwrap();
            assert_eq!(processed.origin, peers[0]);
            assert_eq!(processed.request, request);
            assert!(processed.responded);

            // Verify peer 1's monitor collected the response
            let collected = mon_out.next().await.unwrap();
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
            )
            .await;

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
            )
            .await;

            // Send request from peer 1 to peer 2
            let request = Request { id: 1, data: 1 };
            let commitment = request.commitment();
            let recipients = mailbox
                .send(Recipients::One(peers[1].clone()), request.clone())
                .await
                .expect("send failed");
            assert_eq!(recipients, vec![peers[1].clone()]);

            // Cancel immediately
            mailbox.cancel(commitment).await;

            // Wait a bit and verify no response collected
            select! {
                _ = mon_out.next() => {
                    panic!("Should not receive any monitor events");
                },
                _ = context.sleep(Duration::from_millis(5_000)) => {
                    // Expected: no events
                }
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
            )
            .await;

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
            )
            .await;

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
            )
            .await;

            // Broadcast request
            let request = Request { id: 3, data: 3 };
            let recipients = mailbox1
                .send(Recipients::All, request.clone())
                .await
                .expect("send failed");
            assert_eq!(recipients.len(), 2);
            assert!(recipients.contains(&peers[1]));
            assert!(recipients.contains(&peers[2]));

            // Collect responses
            let mut responses_collected = 0;
            let mut peer2_responded = false;
            let mut peer3_responded = false;

            for _ in 0..2 {
                let collected = mon_out1.next().await.unwrap();
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
            )
            .await;

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
            )
            .await;

            // Send the same request multiple times
            let request = Request { id: 5, data: 5 };
            for _ in 0..3 {
                let recipients = mailbox1
                    .send(Recipients::One(peers[1].clone()), request.clone())
                    .await
                    .expect("send failed");
                assert_eq!(recipients, vec![peers[1].clone()]);
            }

            // Should only receive one response
            let collected = mon_out1.next().await.unwrap();
            assert_eq!(collected.handler, peers[1]);
            assert_eq!(collected.response.id, 5);
            assert_eq!(collected.count, 1);

            // Wait and verify no more responses
            select! {
                _ = mon_out1.next() => {
                    panic!("Should not receive duplicate responses");
                },
                _ = context.sleep(Duration::from_millis(5_000)) => {
                    // Expected: no more responses
                }
            }
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
            )
            .await;

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
            )
            .await;

            // Send multiple concurrent requests
            let request1 = Request { id: 10, data: 10 };
            let request2 = Request { id: 20, data: 20 };
            mailbox1
                .send(Recipients::One(peers[1].clone()), request1)
                .await
                .expect("send failed");
            mailbox1
                .send(Recipients::One(peers[1].clone()), request2)
                .await
                .expect("send failed");

            // Collect both responses
            let mut response10_received = false;
            let mut response20_received = false;
            for _ in 0..2 {
                let collected = mon_out1.next().await.unwrap();
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
            )
            .await;

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
            )
            .await;

            // Send request
            let request = Request { id: 100, data: 100 };
            let recipients = mailbox1
                .send(Recipients::One(peers[1].clone()), request.clone())
                .await
                .expect("send failed");
            assert_eq!(recipients, vec![peers[1].clone()]);

            // Verify handler received request but didn't respond
            let processed = handler_out2.next().await.unwrap();
            assert_eq!(processed.origin, peers[0]);
            assert_eq!(processed.request, request);
            assert!(!processed.responded);

            // Verify no response collected
            select! {
                _ = mon_out1.next() => {
                    panic!("Should not receive any monitor events");
                },
                _ = context.sleep(Duration::from_millis(1_000)) => {
                    // Expected: no events
                }
            }
        });
    }

    #[test_traced]
    fn test_empty_recipients() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (oracle, schemes, _, connections) = setup_network_and_peers(&context, &[0]).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

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
            )
            .await;

            // Send request with empty recipients list
            let request = Request { id: 1, data: 1 };
            let recipients = mailbox
                .send(Recipients::All, request.clone())
                .await
                .expect("send failed");
            assert_eq!(recipients, Vec::<PublicKey>::new());

            // Verify no responses collected
            select! {
                _ = mon_out.next() => {
                    panic!("Should not receive any monitor events");
                },
                _ = context.sleep(Duration::from_millis(1_000)) => {
                    // Expected: no events
                }
            }
        });
    }

    #[test_traced]
    fn test_send_fails_with_network_error() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Setup peer 1 with a failing sender
            let scheme = schemes.next().unwrap();
            let conn = connections.next().unwrap();
            let (_, receiver1) = conn.0; // Request channel
            let sender1 = super::mocks::sender::Failing::<PublicKey>::new();
            let (sender2, receiver2) = conn.1; // Response channel
            let (engine, mut mailbox) = Engine::new(
                context.with_label(&format!("engine_{}", scheme.public_key())),
                Config {
                    blocker: oracle.control(scheme.public_key()),
                    monitor: MockMonitor::dummy(),
                    handler: MockHandler::dummy(),
                    mailbox_size: MAILBOX_SIZE,
                    priority_request: false,
                    request_codec: (),
                    priority_response: false,
                    response_codec: (),
                },
            );

            // Start engine
            engine.start((sender1, receiver1), (sender2, receiver2));

            // Send request
            let request = Request { id: 1, data: 1 };
            let err = mailbox
                .send(Recipients::One(peers[1].clone()), request.clone())
                .await
                .unwrap_err();
            assert!(matches!(err, Error::SendFailed(_)));
        });
    }

    #[test_traced]
    fn test_send_fails_with_canceled() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1]).await;
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Setup peer 1 with a failing sender
            let scheme = schemes.next().unwrap();
            let conn = connections.next().unwrap();
            let (sender1, receiver1) = conn.0; // Request channel
            let (sender2, receiver2) = conn.1; // Response channel
            let (engine, mut mailbox) = Engine::new(
                context.with_label(&format!("engine_{}", scheme.public_key())),
                Config {
                    blocker: oracle.control(scheme.public_key()),
                    monitor: MockMonitor::dummy(),
                    handler: MockHandler::dummy(),
                    mailbox_size: MAILBOX_SIZE,
                    priority_request: false,
                    request_codec: (),
                    priority_response: false,
                    response_codec: (),
                },
            );

            // Start engine
            let handle = engine.start((sender1, receiver1), (sender2, receiver2));

            // Stop the engine (which will result in all further requests being canceled)
            handle.abort();

            // Send request (will return Error::Canceled instead of Error::SendFailed)
            let request = Request { id: 1, data: 1 };
            let err = mailbox
                .send(Recipients::One(peers[1].clone()), request.clone())
                .await
                .unwrap_err();
            assert!(matches!(err, Error::Canceled));
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
            )
            .await;

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
            )
            .await;

            // Setup peer 3 (will respond with same commitment as peer 2's request)
            let conn3 = connections.next().unwrap();
            let mut res_conn3 = conn3.1;

            // Send request from peer 1 to peer 2 (this gets tracked)
            let request_to_peer2 = Request { id: 42, data: 42 };
            let recipients = mailbox1
                .send(Recipients::One(peers[1].clone()), request_to_peer2.clone())
                .await
                .expect("send failed");
            assert_eq!(recipients, vec![peers[1].clone()]);

            // Send a response from peer 3 to peer 1
            let response_to_peer1 = Response { id: 42, result: 72 };
            res_conn3
                .0
                .send(
                    Recipients::One(peers[0].clone()),
                    response_to_peer1.encode().into(),
                    true,
                )
                .await
                .unwrap();

            // Give some time for messages to be processed
            context.sleep(Duration::from_millis(1_000)).await;

            // Should only receive one response (from peer 2, not peer 3)
            let collected = mon_out1.next().await.unwrap();
            assert_eq!(collected.handler, peers[1]); // Response from peer 2
            assert_eq!(collected.response.id, 42);
            assert_eq!(collected.response.result, 84); // 42 * 2 (default mock behavior)
            assert_eq!(collected.count, 1);

            // Verify no additional responses (peer 3's response should be ignored)
            select! {
                _ = mon_out1.next() => {
                    panic!("Should not receive response from unknown peer");
                },
                _ = context.sleep(Duration::from_millis(1_000)) => {
                    // Expected: no more events
                }
            }
        });
    }
}

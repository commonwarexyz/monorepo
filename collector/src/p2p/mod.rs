//! Implementation of a [commonware_p2p]-optimized `collector`.

use crate::{Handler, Monitor};

mod engine;
use commonware_p2p::Blocker;
pub use engine::Engine;
use std::num::NonZeroUsize;
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
    pub mailbox_size: NonZeroUsize,

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
        Config, Engine, Mailbox,
        mocks::{
            handler::Handler as MockHandler,
            monitor::Monitor as MockMonitor,
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
        Advertisement, Blocker, Reachability, ReachabilityManager as _, ReachableTrackedPeers,
        Recipients, Sender as _, TrackedPeers, authenticated::lookup,
    };
    use commonware_runtime::{
        Clock, Quota, Runner, Supervisor as _, deterministic,
        deterministic::network::{Endpoint, Link, Oracle as TransportOracle},
        telemetry::metrics::count_running_tasks,
    };
    use commonware_utils::{NZU32, ordered::Map};
    use std::{collections::BTreeMap, num::NonZeroUsize, time::Duration};

    /// Default rate limit quota for tests (high enough to not interfere with normal operation)
    const TEST_QUOTA: Quota = Quota::per_second(NZU32!(1_000_000));

    const MAILBOX_SIZE: NonZeroUsize = commonware_utils::NZUsize!(1024);
    const LINK: Link = Link::new(Duration::from_millis(10)).with_jitter(Duration::from_millis(1));
    const LINK_SLOW: Link = Link::new(Duration::from_secs(1)).with_jitter(Duration::from_millis(1));
    const CONNECTION_WAIT: Duration = Duration::from_secs(2);

    type LookupOracle = lookup::ReachabilityOracle<PublicKey, Endpoint>;
    type Connection = (
        (
            lookup::Sender<PublicKey, deterministic::Context>,
            lookup::Receiver<PublicKey>,
        ),
        (
            lookup::Sender<PublicKey, deterministic::Context>,
            lookup::Receiver<PublicKey>,
        ),
    );

    struct TestNetwork {
        context: deterministic::Context,
        transport: TransportOracle<deterministic::Context>,
        endpoints: BTreeMap<PublicKey, Endpoint>,
        oracles: BTreeMap<PublicKey, LookupOracle>,
    }

    impl TestNetwork {
        fn oracle(&self, peer: &PublicKey) -> LookupOracle {
            self.oracles[peer].clone()
        }

        fn track<T: Into<TrackedPeers<PublicKey>>>(&self, index: u64, peers: T) {
            let peers = peers.into();
            for (local, oracle) in &self.oracles {
                let mut oracle = oracle.clone();
                oracle.track(
                    index,
                    ReachableTrackedPeers::new(
                        self.reachability(local, &peers.primary),
                        self.reachability(local, &peers.secondary),
                    ),
                );
            }
        }

        fn reachability(
            &self,
            local: &PublicKey,
            peers: &commonware_utils::ordered::Set<PublicKey>,
        ) -> Map<PublicKey, Reachability<Endpoint>> {
            Map::from_iter_dedup(peers.iter().cloned().map(|peer| {
                let endpoint = self.endpoints[&peer];
                let advertisement = Advertisement::new(vec![endpoint]).unwrap();
                let reachability = if local < &peer {
                    Reachability::Dialable(advertisement)
                } else {
                    Reachability::OutboundOnly
                };
                (peer, reachability)
            }))
        }
    }

    fn setup_network_and_peers(
        context: &deterministic::Context,
        peer_seeds: &[u64],
    ) -> (
        TestNetwork,
        Vec<PrivateKey>,
        Vec<PublicKey>,
        Vec<Connection>,
    ) {
        let schemes: Vec<PrivateKey> = peer_seeds
            .iter()
            .map(|seed| PrivateKey::from_seed(*seed))
            .collect();
        let peers: Vec<PublicKey> = schemes.iter().map(|s| s.public_key()).collect();
        let transport = TransportOracle::new(Default::default());
        let endpoints = peers
            .iter()
            .enumerate()
            .map(|(index, peer)| (peer.clone(), Endpoint::new(index as u64)))
            .collect::<BTreeMap<_, _>>();

        let mut connections = Vec::new();
        let mut oracles = BTreeMap::new();
        for (scheme, peer) in schemes.iter().cloned().zip(&peers) {
            let (mut network, oracle) = commonware_p2p::utils::mocks::lookup(
                context.child("peer_network").with_attribute("peer", peer),
                &transport,
                scheme,
                endpoints[peer],
                b"_COMMONWARE_COLLECTOR_P2P_TEST",
                1024 * 1024,
            );
            let (sender1, receiver1) = network.register(0, TEST_QUOTA, 1024);
            let (sender2, receiver2) = network.register(1, TEST_QUOTA, 1024);
            connections.push(((sender1, receiver1), (sender2, receiver2)));
            network.start();
            oracles.insert(peer.clone(), oracle);
        }

        let network = TestNetwork {
            context: context.child("connection_wait"),
            transport,
            endpoints,
            oracles,
        };
        let tracked = commonware_utils::ordered::Set::from_iter_dedup(peers.clone());
        network.track(0, tracked);

        (network, schemes, peers, connections)
    }

    async fn add_link(
        network: &TestNetwork,
        link: Link,
        peers: &[PublicKey],
        from: usize,
        to: usize,
    ) {
        // Establish authentication over the normal test link before applying a slow data path.
        // This keeps slow-link tests focused on collector behavior rather than handshake timing.
        network
            .transport
            .set_link(
                network.endpoints[&peers[from]],
                network.endpoints[&peers[to]],
                LINK,
            )
            .unwrap();
        network
            .transport
            .set_link(
                network.endpoints[&peers[to]],
                network.endpoints[&peers[from]],
                LINK,
            )
            .unwrap();
        network.context.sleep(CONNECTION_WAIT).await;
        if link == LINK {
            return;
        }
        network
            .transport
            .set_link(
                network.endpoints[&peers[from]],
                network.endpoints[&peers[to]],
                link,
            )
            .unwrap();
        network
            .transport
            .set_link(
                network.endpoints[&peers[to]],
                network.endpoints[&peers[from]],
                link,
            )
            .unwrap();
    }

    #[allow(clippy::type_complexity)]
    fn setup_and_spawn_engine(
        context: &deterministic::Context,
        blocker: impl Blocker<PublicKey = PublicKey>,
        signer: impl Signer<PublicKey = PublicKey>,
        connection: Connection,
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
            let (oracle, schemes, peers, connections) = setup_network_and_peers(&context, &[0, 1]);
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Link the two peers
            add_link(&oracle, LINK, &peers, 0, 1).await;

            // Setup peer 1
            let scheme = schemes.next().unwrap();
            let conn = connections.next().unwrap();
            let req_conn = conn.0;
            let res_conn = conn.1;
            let (mon, mut mon_out) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.oracle(&scheme.public_key()),
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
                oracle.oracle(&scheme.public_key()),
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
            let (oracle, schemes, peers, connections) = setup_network_and_peers(&context, &[0, 1]);
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Link the two peers
            add_link(&oracle, LINK_SLOW, &peers, 0, 1).await;

            // Setup peer 1
            let scheme = schemes.next().unwrap();
            let conn = connections.next().unwrap();
            let req_conn = conn.0;
            let res_conn = conn.1;
            let (mon, mut mon_out) = MockMonitor::new();
            let mut mailbox = setup_and_spawn_engine(
                &context,
                oracle.oracle(&scheme.public_key()),
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
                oracle.oracle(&scheme.public_key()),
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
            let (oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1, 2]);
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Link the peers
            add_link(&oracle, LINK, &peers, 0, 1).await;
            add_link(&oracle, LINK, &peers, 0, 2).await;

            // Setup peer 1
            let scheme1 = schemes.next().unwrap();
            let conn1 = connections.next().unwrap();
            let req_conn1 = conn1.0;
            let res_conn1 = conn1.1;
            let (mon1, mut mon_out1) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.oracle(&scheme1.public_key()),
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
                oracle.oracle(&scheme2.public_key()),
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
                oracle.oracle(&scheme3.public_key()),
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
            let (oracle, schemes, peers, connections) = setup_network_and_peers(&context, &[0, 1]);
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Link the peers
            add_link(&oracle, LINK, &peers, 0, 1).await;

            // Setup peer 1
            let scheme1 = schemes.next().unwrap();
            let conn1 = connections.next().unwrap();
            let req_conn1 = conn1.0;
            let res_conn1 = conn1.1;
            let (mon1, mut mon_out1) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.oracle(&scheme1.public_key()),
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
                oracle.oracle(&scheme2.public_key()),
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
        });
    }

    #[test_traced]
    fn test_concurrent_requests() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (oracle, schemes, peers, connections) = setup_network_and_peers(&context, &[0, 1]);
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Link the peers
            add_link(&oracle, LINK, &peers, 0, 1).await;

            // Setup peer 1
            let scheme1 = schemes.next().unwrap();
            let conn1 = connections.next().unwrap();
            let req_conn1 = conn1.0;
            let res_conn1 = conn1.1;
            let (mon1, mut mon_out1) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.oracle(&scheme1.public_key()),
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
                oracle.oracle(&scheme2.public_key()),
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
            let (oracle, schemes, peers, connections) = setup_network_and_peers(&context, &[0, 1]);
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Link the peers
            add_link(&oracle, LINK, &peers, 0, 1).await;

            // Setup peer 1
            let scheme1 = schemes.next().unwrap();
            let conn1 = connections.next().unwrap();
            let req_conn1 = conn1.0;
            let res_conn1 = conn1.1;
            let (mon1, mut mon_out1) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.oracle(&scheme1.public_key()),
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
                oracle.oracle(&scheme2.public_key()),
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
            let (oracle, schemes, _, connections) = setup_network_and_peers(&context, &[0]);
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
                oracle.oracle(&scheme.public_key()),
                scheme,
                (req_conn, res_conn),
                mon,
                MockHandler::dummy(),
            );

            // Send request with empty recipients list
            let request = Request { id: 1, data: 1 };
            assert_eq!(mailbox.send(Recipients::All, request.clone()), Feedback::Ok);

            // Verify no responses collected
            select! {
                _ = mon_out.recv() => {
                    panic!("Should not receive any monitor events");
                },
                _ = context.sleep(Duration::from_millis(1_000)) => {
                    // Expected: no events
                },
            }
        });
    }

    #[test_traced]
    fn test_send_closed_does_not_collect() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (oracle, schemes, peers, connections) = setup_network_and_peers(&context, &[0, 1]);
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Setup peer 1 with a failing sender
            let scheme = schemes.next().unwrap();
            let conn = connections.next().unwrap();
            let (_, receiver1) = conn.0; // Request channel
            let sender1 = super::mocks::sender::Failing::<PublicKey>::new();
            let (sender2, receiver2) = conn.1; // Response channel
            let public_key = scheme.public_key();
            let (engine, mut mailbox) = Engine::new(
                context
                    .child("engine")
                    .with_attribute("public_key", &public_key),
                Config {
                    blocker: oracle.oracle(&public_key),
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
            assert_eq!(
                mailbox.send(Recipients::One(peers[1].clone()), request),
                Feedback::Ok
            );
        });
    }

    #[test_traced]
    fn test_send_after_shutdown_returns_closed() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let (oracle, schemes, peers, connections) = setup_network_and_peers(&context, &[0, 1]);
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Setup peer 1 with a failing sender
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
                    blocker: oracle.oracle(&public_key),
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
            let (oracle, schemes, peers, connections) =
                setup_network_and_peers(&context, &[0, 1, 2]);
            let mut schemes = schemes.into_iter();
            let mut connections = connections.into_iter();

            // Link all peers
            add_link(&oracle, LINK, &peers, 0, 1).await;
            add_link(&oracle, LINK, &peers, 0, 2).await;
            add_link(&oracle, LINK, &peers, 1, 2).await;

            // Setup peer 1 (originator)
            let scheme1 = schemes.next().unwrap();
            let conn1 = connections.next().unwrap();
            let req_conn1 = conn1.0;
            let res_conn1 = conn1.1;
            let (mon1, mut mon_out1) = MockMonitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                oracle.oracle(&scheme1.public_key()),
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
                oracle.oracle(&scheme2.public_key()),
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
        });
    }

    #[allow(clippy::type_complexity)]
    fn spawn_engines_with_handles(
        engine_context: deterministic::Context,
        oracle: &TestNetwork,
        schemes: Vec<PrivateKey>,
        connections: Vec<Connection>,
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
                    blocker: oracle.oracle(&scheme.public_key()),
                    monitor: mon,
                    handler,
                    mailbox_size: MAILBOX_SIZE,
                    priority_request: false,
                    request_codec: (),
                    priority_response: false,
                    response_codec: (),
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
            let (oracle, schemes, peers, connections) = setup_network_and_peers(&context, &[0, 1]);

            add_link(&oracle, LINK, &peers, 0, 1).await;

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
            let (oracle, schemes, peers, connections) = setup_network_and_peers(&context, &[0, 1]);

            add_link(&oracle, LINK, &peers, 0, 1).await;

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

            // Verify network is functional - send a request and expect a response
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
}

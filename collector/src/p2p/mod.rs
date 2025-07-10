//! Implementation of the [crate::Originator], [crate::Handler], and [crate::Monitor] traits for [commonware_p2p].

use crate::{Handler, Monitor};

mod engine;
pub use engine::Engine;
mod ingress;
pub use ingress::{Mailbox, Message};

#[cfg(test)]
mod mocks;

/// Configuration for an [Engine].
#[derive(Clone)]
pub struct Config<M: Monitor, H: Handler, RqC, RsC> {
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
            HandlerEvent, MockHandler as Handler, MockMonitor as Monitor, MonitorEvent, Request,
            Response,
        },
        Config, Engine, Mailbox,
    };
    use crate::Originator;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Committable, PrivateKeyExt, Signer,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::{
        simulated::{Link, Network, Oracle, Receiver, Sender},
        Recipients,
    };
    use commonware_runtime::{deterministic, Clock, Metrics, Runner};
    use futures::StreamExt;
    use std::time::Duration;

    const MAILBOX_SIZE: usize = 1024;
    const LINK: Link = Link {
        latency: 10.0,
        jitter: 1.0,
        success_rate: 1.0,
    };
    const LINK_SLOW: Link = Link {
        latency: 1_000.0,
        jitter: 1.0,
        success_rate: 1.0,
    };
    const LINK_UNRELIABLE: Link = Link {
        latency: 10.0,
        jitter: 1.0,
        success_rate: 0.5,
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
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            commonware_p2p::simulated::Config {
                max_size: 1024 * 1024,
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
            let (sender1, receiver1) = oracle.register(peer.clone(), 0).await.unwrap();
            let (sender2, receiver2) = oracle.register(peer.clone(), 1).await.unwrap();
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
        signer: impl Signer<PublicKey = PublicKey>,
        connection: (
            (Sender<PublicKey>, Receiver<PublicKey>),
            (Sender<PublicKey>, Receiver<PublicKey>),
        ),
        monitor: Monitor,
        handler: Handler,
    ) -> Mailbox<PublicKey, Request> {
        let public_key = signer.public_key();
        let (engine, mailbox) = Engine::new(
            context.with_label(&format!("engine_{public_key}")),
            Config {
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
            let (mon, mut mon_out) = Monitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                scheme,
                (req_conn, res_conn),
                mon,
                Handler::dummy(),
            )
            .await;

            // Setup peer 2
            let scheme = schemes.next().unwrap();
            let conn = connections.next().unwrap();
            let req_conn = conn.0;
            let res_conn = conn.1;
            let (handler, mut handler_out) = Handler::new(true);
            let _mailbox = setup_and_spawn_engine(
                &context,
                scheme,
                (req_conn, res_conn),
                Monitor::dummy(),
                handler,
            )
            .await;

            // Send request from peer 1 to peer 2
            let request = Request { id: 1, data: 1 };
            let recipients = mailbox1
                .send(Recipients::One(peers[1].clone()), request.clone())
                .await;
            assert_eq!(recipients, vec![peers[1].clone()]);

            // Verify peer 2 received the request
            let event = handler_out.next().await.unwrap();
            match event {
                HandlerEvent::ReceivedRequest {
                    origin,
                    request: received_request,
                    responded,
                } => {
                    assert_eq!(origin, peers[0]);
                    assert_eq!(received_request, request);
                    assert!(responded);
                }
            }

            // Verify peer 1's monitor collected the response
            let event = mon_out.next().await.unwrap();
            match event {
                MonitorEvent::Collected {
                    handler,
                    response,
                    count,
                } => {
                    assert_eq!(handler, peers[1]);
                    assert_eq!(response.id, 1);
                    assert_eq!(response.result, 2);
                    assert_eq!(count, 1);
                }
            }
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
            let (mon, mut mon_out) = Monitor::new();
            let mut mailbox = setup_and_spawn_engine(
                &context,
                scheme,
                (req_conn, res_conn),
                mon,
                Handler::dummy(),
            )
            .await;

            // Setup peer 2
            let scheme = schemes.next().unwrap();
            let conn = connections.next().unwrap();
            let req_conn = conn.0;
            let res_conn = conn.1;
            let (handler, _) = Handler::new(true);
            let _mailbox = setup_and_spawn_engine(
                &context,
                scheme,
                (req_conn, res_conn),
                Monitor::dummy(),
                handler,
            )
            .await;

            // Send request from peer 1 to peer 2
            let request = Request { id: 1, data: 1 };
            let commitment = request.commitment();
            let recipients = mailbox
                .send(Recipients::One(peers[1].clone()), request.clone())
                .await;
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
            let (mon1, mut mon_out1) = Monitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                scheme1,
                (req_conn1, res_conn1),
                mon1,
                Handler::dummy(),
            )
            .await;

            // Setup peer 2
            let scheme2 = schemes.next().unwrap();
            let conn2 = connections.next().unwrap();
            let req_conn2 = conn2.0;
            let res_conn2 = conn2.1;
            let (handler2, _) = Handler::new(true);
            let _mailbox2 = setup_and_spawn_engine(
                &context,
                scheme2,
                (req_conn2, res_conn2),
                Monitor::dummy(),
                handler2,
            )
            .await;

            // Setup peer 3
            let scheme3 = schemes.next().unwrap();
            let conn3 = connections.next().unwrap();
            let req_conn3 = conn3.0;
            let res_conn3 = conn3.1;
            let (handler3, _) = Handler::new(true);
            let _mailbox3 = setup_and_spawn_engine(
                &context,
                scheme3,
                (req_conn3, res_conn3),
                Monitor::dummy(),
                handler3,
            )
            .await;

            // Broadcast request
            let request = Request { id: 3, data: 3 };
            let recipients = mailbox1.send(Recipients::All, request.clone()).await;
            assert_eq!(recipients.len(), 2);
            assert!(recipients.contains(&peers[1]));
            assert!(recipients.contains(&peers[2]));

            // Collect responses
            let mut responses_collected = 0;
            let mut peer2_responded = false;
            let mut peer3_responded = false;

            for _ in 0..2 {
                let event = mon_out1.next().await.unwrap();
                match event {
                    MonitorEvent::Collected {
                        handler,
                        response,
                        count,
                    } => {
                        assert_eq!(response.id, 3);
                        assert_eq!(response.result, 6);
                        responses_collected += 1;
                        assert_eq!(count, responses_collected);

                        if handler == peers[1] {
                            peer2_responded = true;
                        } else if handler == peers[2] {
                            peer3_responded = true;
                        }
                    }
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
            let (mon1, mut mon_out1) = Monitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                scheme1,
                (req_conn1, res_conn1),
                mon1,
                Handler::dummy(),
            )
            .await;

            // Setup peer 2
            let scheme2 = schemes.next().unwrap();
            let conn2 = connections.next().unwrap();
            let req_conn2 = conn2.0;
            let res_conn2 = conn2.1;
            let (handler2, _) = Handler::new(true);
            let _mailbox2 = setup_and_spawn_engine(
                &context,
                scheme2,
                (req_conn2, res_conn2),
                Monitor::dummy(),
                handler2,
            )
            .await;

            // Send the same request multiple times
            let request = Request { id: 5, data: 5 };
            for _ in 0..3 {
                let recipients = mailbox1
                    .send(Recipients::One(peers[1].clone()), request.clone())
                    .await;
                assert_eq!(recipients, vec![peers[1].clone()]);
            }

            // Should only receive one response
            let event = mon_out1.next().await.unwrap();
            match event {
                MonitorEvent::Collected {
                    handler,
                    response,
                    count,
                } => {
                    assert_eq!(handler, peers[1]);
                    assert_eq!(response.id, 5);
                    assert_eq!(count, 1);
                }
            }

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
            let (mon1, mut mon_out1) = Monitor::new();
            let mut mailbox1 = setup_and_spawn_engine(
                &context,
                scheme1,
                (req_conn1, res_conn1),
                mon1,
                Handler::dummy(),
            )
            .await;

            // Setup peer 2
            let scheme2 = schemes.next().unwrap();
            let conn2 = connections.next().unwrap();
            let req_conn2 = conn2.0;
            let res_conn2 = conn2.1;
            let (mut handler2, _) = Handler::new(false);
            handler2.set_response(10, Response { id: 10, result: 20 });
            handler2.set_response(20, Response { id: 20, result: 40 });
            let _mailbox2 = setup_and_spawn_engine(
                &context,
                scheme2,
                (req_conn2, res_conn2),
                Monitor::dummy(),
                handler2,
            )
            .await;

            // Send multiple concurrent requests
            let request1 = Request { id: 10, data: 10 };
            let request2 = Request { id: 20, data: 20 };
            mailbox1
                .send(Recipients::One(peers[1].clone()), request1)
                .await;
            mailbox1
                .send(Recipients::One(peers[1].clone()), request2)
                .await;

            // Collect both responses
            let mut response10_received = false;
            let mut response20_received = false;
            for _ in 0..2 {
                let event = mon_out1.next().await.unwrap();
                match event {
                    MonitorEvent::Collected {
                        handler,
                        response,
                        count,
                    } => {
                        assert_eq!(handler, peers[1]);
                        assert_eq!(count, 1);
                        match response.id {
                            10 => {
                                assert_eq!(response.result, 20);
                                response10_received = true;
                            }
                            20 => {
                                assert_eq!(response.result, 40);
                                response20_received = true;
                            }
                            _ => panic!("Unexpected response ID"),
                        }
                    }
                }
            }

            assert!(response10_received);
            assert!(response20_received);
        });
    }

    // /// Tests behavior with unreliable network links.
    // /// This test verifies that the system handles network failures gracefully.
    // #[test_traced]
    // fn test_unreliable_network() {
    //     let executor = deterministic::Runner::timed(Duration::from_secs(10));
    //     executor.start(|context| async move {
    //         let (mut oracle, schemes, peers, mut connections) =
    //             setup_network_and_peers(&context, &[1, 2, 3]).await;

    //         let mut schemes_iter = schemes.into_iter();
    //         let mut conns_iter = connections.into_iter();

    //         let scheme1 = schemes_iter.next().unwrap();
    //         let scheme2 = schemes_iter.next().unwrap();
    //         let scheme3 = schemes_iter.next().unwrap();

    //         let conn1 = conns_iter.next().unwrap();
    //         let req_conn1 = conn1.0;
    //         let res_conn1 = conn1.1;
    //         let conn2 = conns_iter.next().unwrap();
    //         let req_conn2 = conn2.0;
    //         let res_conn2 = conn2.1;
    //         let conn3 = conns_iter.next().unwrap();
    //         let req_conn3 = conn3.0;
    //         let res_conn3 = conn3.1;

    //         let (mon1, mut mon_out1) = Monitor::new();
    //         let (handler2, _) = Handler::new(true);
    //         let (handler3, _) = Handler::new(true);

    //         let mut mailbox1 = setup_and_spawn_engine(
    //             &context,
    //             scheme1,
    //             (req_conn1, res_conn1),
    //             mon1,
    //             Handler::dummy(),
    //         )
    //         .await;

    //         let _mailbox2 = setup_and_spawn_engine(
    //             &context,
    //             scheme2,
    //             (req_conn2, res_conn2),
    //             Monitor::dummy(),
    //             handler2,
    //         )
    //         .await;

    //         let _mailbox3 = setup_and_spawn_engine(
    //             &context,
    //             scheme3,
    //             (req_conn3, res_conn3),
    //             Monitor::dummy(),
    //             handler3,
    //         )
    //         .await;

    //         // Send multiple broadcasts and count responses
    //         let mut total_responses = 0;
    //         for i in 0..5 {
    //             let request = Request {
    //                 id: 100 + i as u64,
    //                 data: 100 + i as u32,
    //             };

    //             mailbox1.send(Recipients::All, request).await;

    //             // Collect any responses that arrive
    //             let mut round_responses = 0;
    //             loop {
    //                 select! {
    //                     event = mon_out1.next() => {
    //                         if let Some(MonitorEvent::Collected { .. }) = event {
    //                             round_responses += 1;
    //                             total_responses += 1;
    //                         }
    //                     },
    //                     _ = context.sleep(Duration::from_millis(100)) => {
    //                         break;
    //                     }
    //                 }
    //             }

    //             // Due to unreliable links, we might get 0, 1, or 2 responses
    //             assert!(round_responses <= 2);
    //         }

    //         // We should have received at least some responses
    //         assert!(total_responses > 0);
    //         // But likely not all of them (with 50% success rate)
    //         assert!(total_responses < 10); // Max would be 2 peers * 5 requests
    //     });
    // }

    // /// Tests that responses for canceled requests are ignored.
    // /// This test verifies that if a request is canceled before the response
    // /// arrives, the response is properly discarded.
    // #[test_traced]
    // fn test_response_after_cancel() {
    //     let executor = deterministic::Runner::timed(Duration::from_secs(10));
    //     executor.start(|context| async move {
    //         let (mut oracle, schemes, peers, mut connections) =
    //             setup_network_and_peers(&context, &[1, 2]).await;

    //         let mut schemes_iter = schemes.into_iter();
    //         let mut conns_iter = connections.into_iter();

    //         let scheme1 = schemes_iter.next().unwrap();
    //         let scheme2 = schemes_iter.next().unwrap();

    //         let conn1 = conns_iter.next().unwrap();
    //         let req_conn1 = conn1.0;
    //         let res_conn1 = conn1.1;
    //         let conn2 = conns_iter.next().unwrap();
    //         let req_conn2 = conn2.0;
    //         let res_conn2 = conn2.1;

    //         let (mon1, mut mon_out1) = Monitor::new();
    //         let (handler2, _) = Handler::new(true);

    //         let mut mailbox1 = setup_and_spawn_engine(
    //             &context,
    //             scheme1,
    //             (req_conn1, res_conn1),
    //             mon1,
    //             Handler::dummy(),
    //         )
    //         .await;

    //         let _mailbox2 = setup_and_spawn_engine(
    //             &context,
    //             scheme2,
    //             (req_conn2, res_conn2),
    //             Monitor::dummy(),
    //             handler2,
    //         )
    //         .await;

    //         // Send request
    //         let request = Request { id: 30, data: 30 };
    //         let commitment = request.commitment();

    //         mailbox1
    //             .send(Recipients::One(peers[1].clone()), request)
    //             .await;

    //         // Cancel before response arrives
    //         context.sleep(Duration::from_millis(10)).await;
    //         mailbox1.cancel(commitment).await;

    //         // Wait for response to arrive (but it should be ignored)
    //         context.sleep(Duration::from_millis(200)).await;

    //         // Verify no response was collected
    //         select! {
    //             _ = mon_out1.next() => {
    //                 panic!("Should not collect response for canceled request");
    //             },
    //             _ = context.sleep(Duration::from_millis(100)) => {
    //                 // Expected: no response collected
    //             }
    //         }
    //     });
    // }
}

use commonware_macros::stability_scope;

stability_scope!(BETA, cfg(not(target_arch = "wasm32")) {
    async fn resolve_tcp_endpoint(
        endpoint: &crate::TcpEndpoint,
    ) -> Result<Vec<std::net::SocketAddr>, crate::Error> {
        use commonware_utils::IpAddrExt;
        use rand::seq::SliceRandom as _;

        let (host, port, allow_private_ips) = match endpoint {
            crate::TcpEndpoint::Socket(address) => return Ok(vec![*address]),
            crate::TcpEndpoint::Dns {
                host,
                port,
                allow_private_ips,
            } => (host, port, allow_private_ips),
        };

        let mut addresses: Vec<_> = ::tokio::net::lookup_host((host.as_str(), *port))
            .await
            .map_err(|error| crate::Error::ResolveFailed(error.to_string()))?
            .filter(|address| *allow_private_ips || IpAddrExt::is_global(&address.ip()))
            .collect();
        if addresses.is_empty() {
            return Err(crate::Error::ResolveFailed("no addresses returned".into()));
        }
        addresses.shuffle(&mut commonware_utils::sys_rng());
        Ok(addresses)
    }
});

stability_scope!(ALPHA, cfg(not(target_arch = "wasm32")) {
    pub(crate) mod audited;
    pub(crate) mod deterministic;
});
stability_scope!(BETA, cfg(not(target_arch = "wasm32")) {
    pub(crate) mod metered;
});
stability_scope!(BETA, cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-network"))) {
    pub(crate) mod tokio;
});
stability_scope!(ALPHA, cfg(all(not(target_arch = "wasm32"), feature = "iouring-network")) {
    pub(crate) mod iouring;
});

#[cfg(test)]
mod tests {
    use crate::{
        Acceptor, Connection, Dialer, IoBuf, IoBufs, Listener, Sink, Stream, TcpEndpoint,
        TcpListener,
    };
    use commonware_macros::select;
    use commonware_utils::sync::Barrier;
    use futures::{FutureExt, join};
    use std::{net::SocketAddr, sync::Arc, time::Duration};
    use tokio::{sync::oneshot, task::JoinSet};

    const CLIENT_SEND_DATA: &[u8] = b"client_send_data";
    const SERVER_SEND_DATA: &[u8] = b"server_send_data";

    #[cfg(not(feature = "iouring-network"))]
    fn assert_send<T: Send>(_: &T) {}

    fn assert_send_sync<T: Send + Sync>() {}

    #[cfg(not(feature = "iouring-network"))]
    #[test]
    fn native_network_types_remain_thread_safe() {
        assert_send_sync::<super::tokio::Network>();
        assert_send_sync::<super::tokio::Connection>();
        assert_send_sync::<super::tokio::Sink>();
        assert_send_sync::<super::tokio::Stream>();

        let mut registry = crate::telemetry::metrics::Registry::default();
        let pool = crate::BufferPool::new(crate::BufferPoolConfig::for_network(), &mut registry);
        let network = super::tokio::Network::new(super::tokio::Config::default(), pool);
        let endpoint = TcpEndpoint::Socket(SocketAddr::from(([127, 0, 0, 1], 1)));
        let dial = network.dial(&endpoint);
        assert_send(&dial);

        let address = SocketAddr::from(([127, 0, 0, 1], 0));
        let bind = network.bind(&address);
        assert_send(&bind);
    }

    #[cfg(feature = "iouring-network")]
    #[test]
    fn native_iouring_network_types_remain_thread_safe() {
        assert_send_sync::<super::iouring::Network>();
        assert_send_sync::<super::iouring::Connection>();
        assert_send_sync::<super::iouring::Sink>();
        assert_send_sync::<super::iouring::Stream>();
    }

    pub(super) async fn test_network_trait<N, F>(new_network: F)
    where
        F: Fn() -> N,
        N: Dialer<Endpoint = TcpEndpoint> + Acceptor<Bind = SocketAddr>,
        <N as Acceptor>::Listener: TcpListener,
    {
        test_network_bind_and_dial(new_network()).await;
        test_network_vectored_send(new_network()).await;
        test_network_multiple_clients(new_network()).await;
        test_network_large_data(new_network()).await;
        test_network_connection_errors(new_network()).await;
        test_network_peek(new_network()).await;
        test_network_canceled_recv_poisons_stream(new_network()).await;
        test_network_canceled_send_poisons_sink(new_network()).await;
        test_network_recv_error_poisons_stream(new_network()).await;
        test_network_send_error_poisons_sink(new_network()).await;
    }

    // Basic network connectivity test
    async fn test_network_bind_and_dial<N>(network: N)
    where
        N: Dialer<Endpoint = TcpEndpoint> + Acceptor<Bind = SocketAddr>,
        <N as Acceptor>::Listener: TcpListener,
    {
        // Start a server
        let mut listener = network
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("Failed to bind");

        // Get the local address of the listener
        let listener_addr = listener.local_addr().expect("Failed to get local address");

        // Spawn server. Returning the socket halves keeps them alive until both
        // join handles are awaited below.
        let server = tokio::spawn(async move {
            // Server accepts a client, verifies the payload, and sends a reply.
            let (mut sink, mut stream, _) =
                listener.accept().await.expect("Failed to accept").split();
            let received = stream
                .recv(CLIENT_SEND_DATA.len())
                .await
                .expect("Failed to receive");
            assert_eq!(received.coalesce(), CLIENT_SEND_DATA);
            sink.send(IoBuf::from(SERVER_SEND_DATA))
                .await
                .expect("Failed to send");
            (sink, stream)
        });

        // Spawn client, connect to server, send and receive data over connection.
        // Returning the socket halves keeps them alive until both join handles
        // are awaited below.
        let client = tokio::spawn(async move {
            // Client connects to the server, sends a payload, and reads the reply.
            // Connect to the server
            let (mut sink, mut stream, _) = network
                .dial(&TcpEndpoint::Socket(listener_addr))
                .await
                .expect("Failed to dial server")
                .split();

            sink.send(IoBuf::from(CLIENT_SEND_DATA))
                .await
                .expect("Failed to send data");
            let received = stream
                .recv(SERVER_SEND_DATA.len())
                .await
                .expect("Failed to receive data");
            assert_eq!(received.coalesce(), SERVER_SEND_DATA);
            (sink, stream)
        });

        // Wait for both tasks to complete
        let (server_result, client_result) = join!(server, client);
        server_result.expect("Server task failed");
        client_result.expect("Client task failed");
    }

    // Test sending a multi-buffer payload.
    async fn test_network_vectored_send<N>(network: N)
    where
        N: Dialer<Endpoint = TcpEndpoint> + Acceptor<Bind = SocketAddr>,
        <N as Acceptor>::Listener: TcpListener,
    {
        // Start a server
        let mut listener = network
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("Failed to bind");

        // Get the local address of the listener
        let listener_addr = listener.local_addr().expect("Failed to get local address");

        // Build one logical message from multiple chunks so this test exercises
        // the `IoBufs` send path (instead of the single-buffer fast path).
        let message = IoBufs::from(vec![
            IoBuf::from(b"client_".to_vec()),
            IoBuf::from(b"vectored_".to_vec()),
            IoBuf::from(b"send".to_vec()),
        ]);
        let expected = message.clone().coalesce();

        // Spawn a server and read exactly the logical message size. The receive
        // side should observe the same byte stream regardless of send chunking.
        let server = tokio::spawn(async move {
            // Server receives the vectored payload as one logical byte stream.
            let (sink, mut stream, _) = listener.accept().await.expect("Failed to accept").split();
            let received = stream
                .recv(expected.len())
                .await
                .expect("Failed to receive");
            assert_eq!(received.coalesce(), expected.as_ref());
            (sink, stream)
        });

        // Spawn client
        let client = tokio::spawn(async move {
            // Client connects and sends the pre-built vectored message.
            // Connect to the server
            let (mut sink, stream, _) = network
                .dial(&TcpEndpoint::Socket(listener_addr))
                .await
                .expect("Failed to dial server")
                .split();

            // Send the pre-built vectored message.
            sink.send(message).await.expect("Failed to send data");
            (sink, stream)
        });

        // Wait for both tasks to complete
        let (server_result, client_result) = join!(server, client);
        server_result.expect("Server task failed");
        client_result.expect("Client task failed");
    }

    // Test handling multiple clients
    async fn test_network_multiple_clients<N>(network: N)
    where
        N: Dialer<Endpoint = TcpEndpoint> + Acceptor<Bind = SocketAddr>,
        <N as Acceptor>::Listener: TcpListener,
    {
        const NUM_CLIENTS: usize = 3;

        // Start a server
        let network = Arc::new(network);
        let mut listener = network
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("Failed to bind");
        let listener_addr = listener.local_addr().expect("Failed to get local address");

        // Keep all sockets alive until every participant finishes.
        let barrier = Arc::new(Barrier::new(NUM_CLIENTS * 2));

        // Server task
        let server_barrier = barrier.clone();
        let server = tokio::spawn(async move {
            // Handle multiple clients
            let mut set = JoinSet::new();
            for _ in 0..NUM_CLIENTS {
                let (mut sink, mut stream, _) =
                    listener.accept().await.expect("Failed to accept").split();
                let barrier = server_barrier.clone();
                set.spawn(async move {
                    let received = stream
                        .recv(CLIENT_SEND_DATA.len())
                        .await
                        .expect("Failed to receive");
                    assert_eq!(received.coalesce(), CLIENT_SEND_DATA);
                    sink.send(IoBuf::from(SERVER_SEND_DATA))
                        .await
                        .expect("Failed to send");

                    // Hold the connection open until every peer has finished.
                    barrier.wait().await;
                });
            }
            while let Some(result) = set.join_next().await {
                result.expect("Server connection task failed");
            }
        });

        // Start multiple clients
        let mut set = JoinSet::new();
        for _ in 0..NUM_CLIENTS {
            let network = network.clone();
            let barrier = barrier.clone();
            set.spawn(async move {
                // Connect to the server
                let (mut sink, mut stream, _) = network
                    .dial(&TcpEndpoint::Socket(listener_addr))
                    .await
                    .expect("Failed to dial server")
                    .split();

                // Send a message to the server
                sink.send(IoBuf::from(CLIENT_SEND_DATA))
                    .await
                    .expect("Failed to send data");

                // Receive a message from the server
                let received = stream
                    .recv(SERVER_SEND_DATA.len())
                    .await
                    .expect("Failed to receive data");

                // Verify the received data
                assert_eq!(received.coalesce(), SERVER_SEND_DATA);

                // Hold the connection open until every peer has finished.
                barrier.wait().await;
            });
        }

        // Wait for all servers and clients to complete.
        while let Some(result) = set.join_next().await {
            result.expect("Client task failed");
        }
        server.await.expect("Server task failed");
    }

    // Test large data transfer
    async fn test_network_large_data<N>(network: N)
    where
        N: Dialer<Endpoint = TcpEndpoint> + Acceptor<Bind = SocketAddr>,
        <N as Acceptor>::Listener: TcpListener,
    {
        const NUM_CHUNKS: usize = 1_000;
        const CHUNK_SIZE: usize = 8 * 1024; // 8 KB

        // Start a server
        let mut listener = network
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("Failed to bind");
        let listener_addr = listener.local_addr().expect("Failed to get local address");

        // Spawn server. Returning the socket halves keeps them alive until both
        // join handles are awaited below.
        let server = tokio::spawn(async move {
            let (mut sink, mut stream, _) =
                listener.accept().await.expect("Failed to accept").split();

            // Receive and echo large data in chunks
            for _ in 0..NUM_CHUNKS {
                let received = stream
                    .recv(CHUNK_SIZE)
                    .await
                    .expect("Failed to receive chunk");
                sink.send(received).await.expect("Failed to send chunk");
            }
            (sink, stream)
        });

        // Client task. Returning the socket halves keeps them alive until both
        // join handles are awaited below.
        let client = tokio::spawn(async move {
            // Connect to the server
            let (mut sink, mut stream, _) = network
                .dial(&TcpEndpoint::Socket(listener_addr))
                .await
                .expect("Failed to dial server")
                .split();

            // Create a pattern of data
            let pattern = (0..CHUNK_SIZE).map(|i| (i % 256) as u8).collect::<Vec<_>>();

            // Send and verify data in chunks
            for _ in 0..NUM_CHUNKS {
                sink.send(pattern.clone())
                    .await
                    .expect("Failed to send chunk");
                let received = stream
                    .recv(CHUNK_SIZE)
                    .await
                    .expect("Failed to receive chunk");
                assert_eq!(received.coalesce(), &pattern[..]);
            }
            (sink, stream)
        });

        // Wait for both tasks to complete
        let (server_result, client_result) = join!(server, client);
        server_result.expect("Server task failed");
        client_result.expect("Client task failed");
    }

    // Tests dialing and binding errors
    async fn test_network_connection_errors<N>(network: N)
    where
        N: Dialer<Endpoint = TcpEndpoint> + Acceptor<Bind = SocketAddr>,
        <N as Acceptor>::Listener: TcpListener,
    {
        // Test dialing an invalid address
        let invalid_addr = SocketAddr::from(([127, 0, 0, 1], 1));
        let result = network.dial(&TcpEndpoint::Socket(invalid_addr)).await;
        assert!(matches!(result, Err(crate::Error::ConnectionFailed)));

        // Test binding to an already bound address
        let listener = network
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("Failed to bind");
        let listener_addr = listener.local_addr().expect("Failed to get local address");

        // Try to bind to the same address
        let result = network.bind(&listener_addr).await;
        assert!(matches!(result, Err(crate::Error::BindFailed)));
    }

    // Tests peek functionality
    async fn test_network_peek<N>(network: N)
    where
        N: Dialer<Endpoint = TcpEndpoint> + Acceptor<Bind = SocketAddr>,
        <N as Acceptor>::Listener: TcpListener,
    {
        const DATA: &[u8] = b"hello world - peek test data";

        let mut listener = network
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("Failed to bind");
        let listener_addr = listener.local_addr().expect("Failed to get local address");

        // Server sends data
        let server = tokio::spawn(async move {
            let (mut sink, stream, _) = listener.accept().await.expect("Failed to accept").split();
            sink.send(IoBuf::from(DATA)).await.expect("Failed to send");
            (sink, stream)
        });

        // Client receives and tests peek
        let client = tokio::spawn(async move {
            // Connect to the server
            let (sink, mut stream, _) = network
                .dial(&TcpEndpoint::Socket(listener_addr))
                .await
                .expect("Failed to dial server")
                .split();

            // Receive partial data to fill the buffer
            let first = stream.recv(5).await.expect("Failed to receive");
            assert_eq!(first.coalesce(), b"hello");

            // Peek should show buffered data without consuming it
            let peeked = stream.peek(100);
            assert!(!peeked.is_empty());

            // Peek again should return the same data (non-consuming)
            let peeked_again = stream.peek(100);
            assert_eq!(peeked, peeked_again, "peek should be non-consuming");

            // Peek with smaller max_len should truncate
            if peeked.len() >= 3 {
                let peeked_small = stream.peek(3);
                assert_eq!(peeked_small.len(), 3);
                assert_eq!(peeked_small, &peeked[..3]);
            }

            // Receive the rest
            let rest_len = DATA.len() - 5;
            let rest = stream.recv(rest_len).await.expect("Failed to receive");
            assert_eq!(rest.coalesce(), &DATA[5..]);

            // After consuming all data, peek should return empty
            let final_peek = stream.peek(100);
            assert!(final_peek.is_empty());
            (sink, stream)
        });

        // Wait for both tasks to complete
        let (server_result, client_result) = join!(server, client);
        server_result.expect("Server task failed");
        client_result.expect("Client task failed");
    }

    async fn test_network_canceled_recv_poisons_stream<N>(network: N)
    where
        N: Dialer<Endpoint = TcpEndpoint> + Acceptor<Bind = SocketAddr>,
        <N as Acceptor>::Listener: TcpListener,
    {
        let mut listener = network
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("Failed to bind");
        let listener_addr = listener.local_addr().expect("Failed to get local address");

        let server = tokio::spawn(async move {
            let (mut sink, mut stream, _) =
                listener.accept().await.expect("Failed to accept").split();

            // Cancel a recv mid-flight
            select! {
                v = stream.recv(100) => {
                    panic!("unexpected value: {v:?}");
                },
                _ = tokio::time::sleep(Duration::from_millis(5)) => {},
            };

            // Stream should be poisoned after cancellation
            assert!(matches!(stream.recv(1).await, Err(crate::Error::Closed)));

            // Sink should remain usable
            sink.send(IoBuf::from(b"ok"))
                .await
                .expect("sink should remain usable after stream cancellation");

            (sink, stream)
        });

        let client = tokio::spawn(async move {
            let (sink, mut stream, _) = network
                .dial(&TcpEndpoint::Socket(listener_addr))
                .await
                .expect("Failed to dial server")
                .split();

            let received = stream.recv(2).await.expect("Failed to receive response");
            assert_eq!(received.coalesce(), b"ok");

            (sink, stream)
        });

        // Wait for both tasks to complete
        let (server_result, client_result) = join!(server, client);
        server_result.expect("Server task failed");
        client_result.expect("Client task failed");
    }

    async fn test_network_canceled_send_poisons_sink<N>(network: N)
    where
        N: Dialer<Endpoint = TcpEndpoint> + Acceptor<Bind = SocketAddr>,
        <N as Acceptor>::Listener: TcpListener,
    {
        // Windows IOCP completes TCP writes without yielding, so send
        // cancellation cannot be easily triggered on that platform.
        if cfg!(target_os = "windows") {
            return;
        }

        let mut listener = network
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("Failed to bind");
        let listener_addr = listener.local_addr().expect("Failed to get local address");
        let (canceled_sender, canceled_receiver) = oneshot::channel();

        let server = tokio::spawn(async move {
            let (mut sink, mut stream, _) =
                listener.accept().await.expect("Failed to accept").split();

            // Poll multiple sends until backpressure makes one pending, then
            // drop that pending future to simulate cancellation.
            let mut blocked = false;
            for _ in 0..1024 {
                match sink.send(vec![0u8; 128 * 1024]).now_or_never() {
                    Some(Ok(())) => {}
                    Some(Err(err)) => panic!("send failed before blocking: {err:?}"),
                    None => {
                        blocked = true;
                        break;
                    }
                }
            }
            assert!(blocked, "send should have blocked on backpressure");

            // Sink should be poisoned after cancellation.
            assert!(matches!(
                sink.send(IoBuf::from(b"after")).await,
                Err(crate::Error::Closed)
            ));
            canceled_sender
                .send(())
                .expect("client should wait for send cancellation");

            // Stream should remain usable.
            let received = stream.recv(2).await.expect("stream should remain usable");
            assert_eq!(received.coalesce(), b"ok");

            (sink, stream)
        });

        let client = tokio::spawn(async move {
            let (mut sink, stream, _) = network
                .dial(&TcpEndpoint::Socket(listener_addr))
                .await
                .expect("Failed to dial server")
                .split();

            canceled_receiver
                .await
                .expect("server should cancel the send first");

            sink.send(IoBuf::from(b"ok")).await.expect("Failed to send");

            (sink, stream)
        });

        // Wait for both tasks to complete
        let (server_result, client_result) = join!(server, client);
        server_result.expect("Server task failed");
        client_result.expect("Client task failed");
    }

    async fn test_network_recv_error_poisons_stream<N>(network: N)
    where
        N: Dialer<Endpoint = TcpEndpoint> + Acceptor<Bind = SocketAddr>,
        <N as Acceptor>::Listener: TcpListener,
    {
        let mut listener = network
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("Failed to bind");
        let listener_addr = listener.local_addr().expect("Failed to get local address");

        // Server triggers a recv error after a partial read, then verifies the
        // stream is poisoned while the sink remains usable.
        let server = tokio::spawn(async move {
            let (mut sink, mut stream, _) =
                listener.accept().await.expect("Failed to accept").split();

            let err = stream
                .recv(100)
                .await
                .expect_err("recv should fail after a partial read");
            assert!(matches!(err, crate::Error::RecvFailed));
            assert!(matches!(stream.recv(1).await, Err(crate::Error::Closed)));

            sink.send(IoBuf::from(b"ok"))
                .await
                .expect("sink should remain usable after stream error");

            (sink, stream)
        });

        // Client sends a partial payload, half-closes its write direction, and
        // still receives the server's response on the read half.
        let client = tokio::spawn(async move {
            let (mut sink, mut stream, _) = network
                .dial(&TcpEndpoint::Socket(listener_addr))
                .await
                .expect("Failed to dial server")
                .split();

            sink.send(vec![1u8; 50])
                .await
                .expect("Failed to send partial payload");
            drop(sink);

            let received = stream.recv(2).await.expect("Failed to receive response");
            assert_eq!(received.coalesce(), b"ok");

            stream
        });

        // Wait for both tasks to complete
        let (server_result, client_result) = join!(server, client);
        server_result.expect("Server task failed");
        client_result.expect("Client task failed");
    }

    async fn test_network_send_error_poisons_sink<N>(network: N)
    where
        N: Dialer<Endpoint = TcpEndpoint> + Acceptor<Bind = SocketAddr>,
        <N as Acceptor>::Listener: TcpListener,
    {
        const DATA: &[u8] = b"okay";

        let mut listener = network
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("Failed to bind");
        let listener_addr = listener.local_addr().expect("Failed to get local address");
        let (buffered_sender, buffered_receiver) = oneshot::channel();
        let (closed_sender, closed_receiver) = oneshot::channel();

        // Server sends a response, waits for the client to buffer it, then
        // closes the connection so the client's next send eventually fails.
        let server = tokio::spawn(async move {
            let (mut sink, stream, _) = listener.accept().await.expect("Failed to accept").split();

            sink.send(IoBuf::from(DATA))
                .await
                .expect("stream peer should remain readable after sink error");

            buffered_receiver
                .await
                .expect("client should signal once the response is buffered");

            drop(sink);
            drop(stream);

            closed_sender
                .send(())
                .expect("client should still be waiting for the close");
        });

        // Client confirms the read half remains usable after the server closes,
        // then verifies the sink is poisoned after the first send error.
        let client = tokio::spawn(async move {
            let (mut sink, mut stream, _) = network
                .dial(&TcpEndpoint::Socket(listener_addr))
                .await
                .expect("Failed to dial server")
                .split();

            let prefix = stream.recv(2).await.expect("Failed to receive response");
            assert_eq!(prefix.coalesce(), &DATA[..2]);
            assert_eq!(stream.peek(2), &DATA[2..]);
            buffered_sender
                .send(())
                .expect("server should still be waiting for the client");
            closed_receiver
                .await
                .expect("server should signal after closing the connection");

            let mut err = None;
            for _ in 0..10 {
                // A peer close is not guaranteed to make the next send fail
                // immediately, so retry briefly until the error becomes visible.
                match sink.send(vec![9u8]).await {
                    Ok(()) => tokio::time::sleep(Duration::from_millis(5)).await,
                    Err(send_err) => {
                        err = Some(send_err);
                        break;
                    }
                }
            }
            let err = err.expect("send should fail after the peer closes");
            assert!(matches!(err, crate::Error::SendFailed));
            assert!(matches!(
                sink.send(vec![9u8]).await,
                Err(crate::Error::Closed)
            ));

            let suffix = stream
                .recv(2)
                .await
                .expect("Failed to receive buffered response");
            assert_eq!(suffix.coalesce(), &DATA[2..]);

            (sink, stream)
        });

        // Wait for both tasks to complete
        let (server_result, client_result) = join!(server, client);
        server_result.expect("Server task failed");
        client_result.expect("Client task failed");
    }

    /// Test a network backend's connect timeout against a real TCP connection.
    ///
    /// This is Linux-only because the behavior of a zero-length listen backlog is
    /// platform-specific. Linux permits one connection to occupy the accept queue, and
    /// while that connection remains unaccepted another connection attempt is left
    /// pending rather than completing. Other operating systems may clamp the backlog to a
    /// different value or handle an overflowing accept queue differently.
    #[cfg(target_os = "linux")]
    pub(super) async fn test_network_connect_timeout<N>(network: N, connect_timeout: Duration)
    where
        N: Dialer<Endpoint = TcpEndpoint>,
    {
        // Create a loopback listener with the smallest possible accept queue.
        let socket = tokio::net::TcpSocket::new_v4().expect("Failed to create TCP socket");
        socket
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("Failed to bind TCP socket");
        let listener = socket.listen(0).expect("Failed to listen on TCP socket");
        let listener_addr = listener.local_addr().expect("Failed to get local address");

        // Establish one connection without accepting it. Keeping both the listener
        // and this connection alive fills the accept queue, so the next connection
        // remains pending long enough for the backend's connect timeout to fire.
        let _queued_connection = tokio::net::TcpStream::connect(listener_addr)
            .await
            .expect("Failed to fill listener accept queue");

        let start = std::time::Instant::now();
        let result = tokio::time::timeout(
            connect_timeout * 2,
            network.dial(&TcpEndpoint::Socket(listener_addr)),
        )
        .await
        .expect("Dial did not honor connect timeout");

        assert!(matches!(result, Err(crate::Error::Timeout)));

        // Confirm the dial remained pending for the configured budget.
        assert!(start.elapsed() >= connect_timeout);
    }

    /// Network stress tests
    pub(super) async fn stress_test_network_trait<N, F>(new_network: F)
    where
        F: Fn() -> N,
        N: Dialer<Endpoint = TcpEndpoint> + Acceptor<Bind = SocketAddr>,
        <N as Acceptor>::Listener: TcpListener,
    {
        stress_concurrent_streams(new_network()).await;
    }

    /// Creates a large number of concurrent streams and sends messages
    /// back and forth between them.
    async fn stress_concurrent_streams<N>(network: N)
    where
        N: Dialer<Endpoint = TcpEndpoint> + Acceptor<Bind = SocketAddr>,
        <N as Acceptor>::Listener: TcpListener,
    {
        const NUM_CLIENTS: usize = 96;
        const NUM_MESSAGES: usize = 16_384;
        const MESSAGE_SIZE: usize = 4096;

        let network = Arc::new(network);
        let mut listener = network
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        // Keep every connection alive until both the client and server halves finish.
        let barrier = Arc::new(Barrier::new(NUM_CLIENTS * 2));

        // Spawn a server task that echoes messages from many clients.
        let server_barrier = barrier.clone();
        let server = tokio::spawn(async move {
            let mut set = JoinSet::new();
            for _ in 0..NUM_CLIENTS {
                let (mut sink, mut stream, _) = listener.accept().await.unwrap().split();
                let barrier = server_barrier.clone();
                set.spawn(async move {
                    // Echo every message back to the connected client.
                    for _ in 0..NUM_MESSAGES {
                        let received = stream.recv(MESSAGE_SIZE).await.unwrap();
                        sink.send(received).await.unwrap();
                    }

                    // Hold the connection open until every peer has finished.
                    barrier.wait().await;
                });
            }
            while let Some(result) = set.join_next().await {
                result.unwrap();
            }
        });

        // Spawn all clients.
        let mut set = JoinSet::new();
        for _ in 0..NUM_CLIENTS {
            let network = network.clone();
            let barrier = barrier.clone();
            set.spawn(async move {
                // Dial the server and repeatedly verify the echoed payload.
                let (mut sink, mut stream, _) = network
                    .dial(&TcpEndpoint::Socket(addr))
                    .await
                    .unwrap()
                    .split();
                let payload = vec![42u8; MESSAGE_SIZE];
                for _ in 0..NUM_MESSAGES {
                    sink.send(payload.clone()).await.unwrap();
                    let received = stream.recv(MESSAGE_SIZE).await.unwrap();
                    assert_eq!(received.coalesce(), &payload[..]);
                }

                // Hold the connection open until every peer has finished.
                barrier.wait().await;
            });
        }

        // Wait for all servers and clients to complete.
        while let Some(result) = set.join_next().await {
            result.unwrap();
        }
        server.await.unwrap();
    }
}

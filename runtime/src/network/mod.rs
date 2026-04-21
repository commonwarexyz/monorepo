use commonware_macros::stability_scope;

stability_scope!(ALPHA {
    pub(crate) mod audited;
    pub(crate) mod deterministic;
});
stability_scope!(BETA {
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
    use crate::{IoBuf, IoBufs, Listener, Sink, Stream};
    use commonware_utils::sync::Barrier;
    use futures::join;
    use std::{net::SocketAddr, sync::Arc};
    use tokio::task::JoinSet;

    const CLIENT_SEND_DATA: &[u8] = b"client_send_data";
    const SERVER_SEND_DATA: &[u8] = b"server_send_data";

    pub(super) async fn test_network_trait<N, F>(new_network: F)
    where
        F: Fn() -> N,
        N: crate::Network + Clone,
    {
        test_network_bind_and_dial(new_network()).await;
        test_network_vectored_send(new_network()).await;
        test_network_multiple_clients(new_network()).await;
        test_network_large_data(new_network()).await;
        test_network_connection_errors(new_network()).await;
        test_network_peek(new_network()).await;
    }

    // Basic network connectivity test
    async fn test_network_bind_and_dial<N: crate::Network>(network: N) {
        // Start a server
        let mut listener = network
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("Failed to bind");

        // Get the local address of the listener
        let listener_addr = listener.local_addr().expect("Failed to get local address");

        // Spawn server. Returning the socket halves keeps them alive until both
        // join handles are awaited below.
        let server = tokio::spawn(async move {
            // Server accepts a client, verifies the payload, and sends a reply.
            let (_, mut sink, mut stream) = listener.accept().await.expect("Failed to accept");
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
            let (mut sink, mut stream) = network
                .dial(listener_addr)
                .await
                .expect("Failed to dial server");

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
    async fn test_network_vectored_send<N: crate::Network>(network: N) {
        // Start a server
        let mut listener = network
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
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
            let (_, sink, mut stream) = listener.accept().await.expect("Failed to accept");
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
            let (mut sink, stream) = network
                .dial(listener_addr)
                .await
                .expect("Failed to dial server");

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
    async fn test_network_multiple_clients<N: crate::Network + Clone>(network: N) {
        const NUM_CLIENTS: usize = 3;

        // Start a server
        let mut listener = network
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
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
                let (_, mut sink, mut stream) = listener.accept().await.expect("Failed to accept");
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
                let (mut sink, mut stream) = network
                    .dial(listener_addr)
                    .await
                    .expect("Failed to dial server");

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
    async fn test_network_large_data<N: crate::Network>(network: N) {
        const NUM_CHUNKS: usize = 1_000;
        const CHUNK_SIZE: usize = 8 * 1024; // 8 KB

        // Start a server
        let mut listener = network
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("Failed to bind");
        let listener_addr = listener.local_addr().expect("Failed to get local address");

        // Spawn server. Returning the socket halves keeps them alive until both
        // join handles are awaited below.
        let server = tokio::spawn(async move {
            let (_, mut sink, mut stream) = listener.accept().await.expect("Failed to accept");

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
            let (mut sink, mut stream) = network
                .dial(listener_addr)
                .await
                .expect("Failed to dial server");

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
    async fn test_network_connection_errors<N: crate::Network>(network: N) {
        // Test dialing an invalid address
        let invalid_addr = SocketAddr::from(([127, 0, 0, 1], 1));
        let result = network.dial(invalid_addr).await;
        assert!(matches!(result, Err(crate::Error::ConnectionFailed)));

        // Test binding to an already bound address
        let listener = network
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("Failed to bind");
        let listener_addr = listener.local_addr().expect("Failed to get local address");

        // Try to bind to the same address
        let result = network.bind(listener_addr).await;
        assert!(matches!(result, Err(crate::Error::BindFailed)));
    }

    // Tests peek functionality
    async fn test_network_peek<N: crate::Network>(network: N) {
        const DATA: &[u8] = b"hello world - peek test data";

        let mut listener = network
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("Failed to bind");
        let listener_addr = listener.local_addr().expect("Failed to get local address");

        // Server sends data
        let server = tokio::spawn(async move {
            let (_, mut sink, stream) = listener.accept().await.expect("Failed to accept");
            sink.send(IoBuf::from(DATA)).await.expect("Failed to send");
            (sink, stream)
        });

        // Client receives and tests peek
        let client = tokio::spawn(async move {
            // Connect to the server
            let (sink, mut stream) = network
                .dial(listener_addr)
                .await
                .expect("Failed to dial server");

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

    /// Network stress tests
    pub(super) async fn stress_test_network_trait<N, F>(new_network: F)
    where
        F: Fn() -> N,
        N: crate::Network + Clone,
    {
        stress_concurrent_streams(new_network()).await;
    }

    /// Creates a large number of concurrent streams and sends messages
    /// back and forth between them.
    async fn stress_concurrent_streams<N: crate::Network + Clone>(network: N) {
        const NUM_CLIENTS: usize = 96;
        const NUM_MESSAGES: usize = 16_384;
        const MESSAGE_SIZE: usize = 4096;

        let mut listener = network
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
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
                let (_, mut sink, mut stream) = listener.accept().await.unwrap();
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
                let (mut sink, mut stream) = network.dial(addr).await.unwrap();
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

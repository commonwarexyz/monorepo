use commonware_macros::stability_scope;

stability_scope!(ALPHA {
    pub(crate) mod audited;
    pub(crate) mod deterministic;
});
stability_scope!(ALPHA, cfg(not(target_arch = "wasm32")) {
    pub mod proxy;
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
    use crate::{IoBuf, Listener, Sink, Stream};
    use futures::join;
    use std::net::SocketAddr;

    const CLIENT_SEND_DATA: &[u8] = b"client_send_data";
    const SERVER_SEND_DATA: &[u8] = b"server_send_data";

    pub(super) async fn test_network_trait<N, F>(new_network: F)
    where
        F: Fn() -> N,
        N: crate::Network,
    {
        test_network_bind_and_dial(new_network()).await;
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

        let runtime = tokio::runtime::Handle::current();

        // Spawn server
        let server = runtime.spawn(async move {
            let (_, mut sink, mut stream) = listener.accept().await.expect("Failed to accept");

            let received = stream
                .recv(CLIENT_SEND_DATA.len() as u64)
                .await
                .expect("Failed to receive");
            assert_eq!(received.coalesce(), CLIENT_SEND_DATA);
            sink.send(IoBuf::from(SERVER_SEND_DATA))
                .await
                .expect("Failed to send");
        });

        // Spawn client, connect to server, send and receive data over connection
        let client = runtime.spawn(async move {
            // Connect to the server
            let (mut sink, mut stream) = network
                .dial(listener_addr)
                .await
                .expect("Failed to dial server");

            sink.send(IoBuf::from(CLIENT_SEND_DATA))
                .await
                .expect("Failed to send data");

            let received = stream
                .recv(SERVER_SEND_DATA.len() as u64)
                .await
                .expect("Failed to receive data");
            assert_eq!(received.coalesce(), SERVER_SEND_DATA);
        });

        // Wait for both tasks to complete
        let (server_result, client_result) = join!(server, client);
        assert!(server_result.is_ok());
        assert!(client_result.is_ok());
    }

    // Test handling multiple clients
    async fn test_network_multiple_clients<N: crate::Network>(network: N) {
        let runtime = tokio::runtime::Handle::current();

        // Start a server
        let mut listener = network
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("Failed to bind");
        let listener_addr = listener.local_addr().expect("Failed to get local address");

        // Server task
        let server = runtime.spawn(async move {
            // Handle multiple clients
            for _ in 0..3 {
                let (_, mut sink, mut stream) = listener.accept().await.expect("Failed to accept");

                let received = stream
                    .recv(CLIENT_SEND_DATA.len() as u64)
                    .await
                    .expect("Failed to receive");
                assert_eq!(received.coalesce(), CLIENT_SEND_DATA);

                sink.send(IoBuf::from(SERVER_SEND_DATA))
                    .await
                    .expect("Failed to send");
            }
        });

        // Start multiple clients
        let client = runtime.spawn(async move {
            for _ in 0..3 {
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
                    .recv(SERVER_SEND_DATA.len() as u64)
                    .await
                    .expect("Failed to receive data");
                // Verify the received data
                assert_eq!(received.coalesce(), SERVER_SEND_DATA);
            }
        });

        // Wait for server and all clients
        server.await.expect("Server task failed");
        client.await.expect("Client task failed");
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

        let runtime = tokio::runtime::Handle::current();
        let server = runtime.spawn(async move {
            let (_, mut sink, mut stream) = listener.accept().await.expect("Failed to accept");

            // Receive and echo large data in chunks
            for _ in 0..NUM_CHUNKS {
                let received = stream
                    .recv(CHUNK_SIZE as u64)
                    .await
                    .expect("Failed to receive chunk");
                sink.send(received).await.expect("Failed to send chunk");
            }
        });

        // Client task
        let client = runtime.spawn(async move {
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
                    .recv(CHUNK_SIZE as u64)
                    .await
                    .expect("Failed to receive chunk");
                assert_eq!(received.coalesce(), &pattern[..]);
            }
        });

        // Wait for both tasks to complete
        server.await.expect("Server task failed");
        client.await.expect("Client task failed");
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

        let runtime = tokio::runtime::Handle::current();

        // Server sends data
        let server = runtime.spawn(async move {
            let (_, mut sink, _) = listener.accept().await.expect("Failed to accept");
            sink.send(IoBuf::from(DATA)).await.expect("Failed to send");
        });

        // Client receives and tests peek
        let client = runtime.spawn(async move {
            let (_, mut stream) = network
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
            let rest = stream
                .recv(rest_len as u64)
                .await
                .expect("Failed to receive");
            assert_eq!(rest.coalesce(), &DATA[5..]);

            // After consuming all data, peek should return empty
            let final_peek = stream.peek(100);
            assert!(final_peek.is_empty());
        });

        let (server_result, client_result) = join!(server, client);
        assert!(server_result.is_ok());
        assert!(client_result.is_ok());
    }

    /// Network stress tests
    pub(super) async fn stress_test_network_trait<N, F>(new_network: F)
    where
        F: Fn() -> N,
        N: crate::Network,
    {
        stress_concurrent_streams(new_network()).await;
    }

    /// Creates a large number of concurrent streams and sends messages
    /// back and forth between them.
    async fn stress_concurrent_streams<N: crate::Network>(network: N) {
        const NUM_CLIENTS: usize = 96;
        const NUM_MESSAGES: usize = 16_384;
        const MESSAGE_SIZE: usize = 4096;

        let mut listener = network
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a server task that echoes messages from many clients.
        let server = tokio::spawn(async move {
            for _ in 0..NUM_CLIENTS {
                let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    for _ in 0..NUM_MESSAGES {
                        let received = stream.recv(MESSAGE_SIZE as u64).await.unwrap();
                        sink.send(received).await.unwrap();
                    }
                });
            }
        });

        // Spawn all clients.
        let mut clients = Vec::new();
        for _ in 0..NUM_CLIENTS {
            let network = network.clone();
            clients.push(tokio::spawn(async move {
                let (mut sink, mut stream) = network.dial(addr).await.unwrap();
                let payload = vec![42u8; MESSAGE_SIZE];
                for _ in 0..NUM_MESSAGES {
                    sink.send(payload.clone()).await.unwrap();
                    let received = stream.recv(MESSAGE_SIZE as u64).await.unwrap();
                    assert_eq!(received.coalesce(), &payload[..]);
                }
            }));
        }

        for client in clients {
            client.await.unwrap();
        }
        server.await.unwrap();
    }
}

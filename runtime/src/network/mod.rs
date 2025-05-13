pub(crate) mod audited;
pub(crate) mod deterministic;
pub(crate) mod metered;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod tokio;

#[cfg(test)]
mod tests {
    use crate::{Listener, Sink, Stream};
    use futures::join;
    use std::net::SocketAddr;

    const CLIENT_SEND_DATA: &str = "client_send_data";
    const SERVER_SEND_DATA: &str = "server_send_data";

    pub(super) async fn test_network_trait<N, F>(new_network: F)
    where
        F: Fn() -> N,
        N: crate::Network,
    {
        test_network_bind_and_dial(new_network()).await;
        test_network_multiple_clients(new_network()).await;
        test_network_large_data(new_network()).await;
        test_network_connection_errors(new_network()).await;
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

            let mut buf = [0u8; CLIENT_SEND_DATA.len()];
            stream.recv(&mut buf).await.expect("Failed to receive");
            assert_eq!(&buf, CLIENT_SEND_DATA.as_bytes());
            sink.send(SERVER_SEND_DATA.as_bytes())
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

            sink.send(CLIENT_SEND_DATA.as_bytes())
                .await
                .expect("Failed to send data");

            let mut buf = [0u8; SERVER_SEND_DATA.len()];
            stream.recv(&mut buf).await.expect("Failed to receive data");
            assert_eq!(&buf, SERVER_SEND_DATA.as_bytes());
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

                // runtime.spawn(async move {
                let mut buf = [0u8; CLIENT_SEND_DATA.len()];
                stream.recv(&mut buf).await.expect("Failed to receive");
                assert_eq!(&buf, CLIENT_SEND_DATA.as_bytes());

                sink.send(SERVER_SEND_DATA.as_bytes())
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
                sink.send(CLIENT_SEND_DATA.as_bytes())
                    .await
                    .expect("Failed to send data");

                // Receive a message from the server
                let mut buf = [0u8; SERVER_SEND_DATA.len()];
                stream.recv(&mut buf).await.expect("Failed to receive data");
                // Verify the received data
                assert_eq!(&buf, SERVER_SEND_DATA.as_bytes());
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
            let mut buffer = vec![0u8; CHUNK_SIZE];
            for _ in 0..NUM_CHUNKS {
                stream
                    .recv(&mut buffer)
                    .await
                    .expect("Failed to receive chunk");
                sink.send(&buffer).await.expect("Failed to send chunk");
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
            let mut receive_buffer = vec![0u8; CHUNK_SIZE];

            // Send and verify data in chunks
            for _ in 0..NUM_CHUNKS {
                sink.send(&pattern).await.expect("Failed to send chunk");
                stream
                    .recv(&mut receive_buffer)
                    .await
                    .expect("Failed to receive chunk");
                assert_eq!(&receive_buffer, &pattern);
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
}

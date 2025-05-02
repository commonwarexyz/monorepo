pub(crate) mod metered;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod tokio;

#[cfg(test)]
mod tests {
    use crate::{Listener, Sink, Stream};
    use futures::join;
    use std::net::SocketAddr;

    // TODO danlaine: remove
    const PORT_NUMBER: u16 = 5000;
    const CLIENT_SEND_DATA: &str = "client_send_data";
    const SERVER_SEND_DATA: &str = "server_send_data";

    pub(super) async fn run_network_tests<N, F>(new_network: F)
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
        let listener_addr = SocketAddr::from(([127, 0, 0, 1], PORT_NUMBER));

        // Start a server
        let mut listener = network.bind(listener_addr).await.expect("Failed to bind");

        let runtime = tokio::runtime::Handle::current();

        // Spawn server
        let server = runtime.spawn(async move {
            let (_, mut sink, mut stream) = listener.accept().await.expect("Failed to accept");

            let mut buf = [0u8; CLIENT_SEND_DATA.len()];
            stream.recv(&mut buf).await.expect("Failed to receive");
            assert_eq!(&buf, CLIENT_SEND_DATA.as_bytes());
            sink.send(&buf).await.expect("Failed to send");
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
            assert_eq!(&buf, CLIENT_SEND_DATA.as_bytes());
        });

        // Wait for both tasks to complete
        let (server_result, client_result) = join!(server, client);
        assert!(server_result.is_ok());
        assert!(client_result.is_ok());
    }

    // Test handling multiple clients
    async fn test_network_multiple_clients<N: crate::Network>(network: N) {
        let listener_addr = SocketAddr::from(([127, 0, 0, 1], PORT_NUMBER));

        let runtime = tokio::runtime::Handle::current();

        // Start a server
        let mut listener = network.bind(listener_addr).await.expect("Failed to bind");

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
                // });
            }
        });

        // Create multiple clients
        // let mut client_handles = Vec::new();

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
        // client_handles.push(client);

        // Wait for server and all clients
        server.await.expect("Server task failed");
        // for (i, handle) in client_handles.into_iter().enumerate() {
        //     handle.await.expect(&format!("Client {} failed", i));
        // }
        client.await.expect("Client task failed");
    }

    // Test large data transfer
    async fn test_network_large_data<N: crate::Network>(network: N) {
        let listener_addr = SocketAddr::from(([127, 0, 0, 1], PORT_NUMBER));

        // Start a server
        let mut listener = network.bind(listener_addr).await.expect("Failed to bind");
        let runtime = tokio::runtime::Handle::current();
        let server = runtime.spawn(async move {
            let (_, mut sink, mut stream) = listener.accept().await.expect("Failed to accept");

            // Receive and echo large data in chunks
            let mut total_received = 0;
            let mut buffer = vec![0u8; 8192];

            while total_received < 1_000_000 {
                stream
                    .recv(&mut buffer)
                    .await
                    .expect("Failed to receive chunk");
                sink.send(&buffer).await.expect("Failed to send chunk");
                total_received += buffer.len();
            }

            total_received
        });

        // Client task
        let client = runtime.spawn(async move {
            // Connect to the server
            let (mut sink, mut stream) = network
                .dial(listener_addr)
                .await
                .expect("Failed to dial server");

            // Create a pattern of data
            let pattern = (0..8192).map(|i| (i % 256) as u8).collect::<Vec<_>>();
            let mut total_sent = 0;
            let mut total_received = 0;
            let mut receive_buffer = vec![0u8; 8192];

            // Send and verify data in chunks
            while total_sent < 1_000_000 {
                sink.send(&pattern).await.expect("Failed to send chunk");
                total_sent += pattern.len();

                stream
                    .recv(&mut receive_buffer)
                    .await
                    .expect("Failed to receive chunk");
                assert_eq!(&receive_buffer, &pattern);
                total_received += receive_buffer.len();
            }

            (total_sent, total_received)
        });

        // Wait for both tasks to complete
        let (server_result, client_result) = join!(server, client);
        let server_total = server_result.expect("Server task failed");
        let (client_sent, client_received) = client_result.expect("Client task failed");

        assert_eq!(server_total, 123 * 8192); // Smallest multiple of 8192 greater than 1_000_000
        assert_eq!(client_sent, 123 * 8192);
        assert_eq!(client_received, 123 * 8192);
    }

    // Tests dialing and binding errors
    async fn test_network_connection_errors<N: crate::Network>(network: N) {
        // Test dialing an invalid address
        let invalid_addr = SocketAddr::from(([127, 0, 0, 1], 1));
        let result = network.dial(invalid_addr).await;
        assert!(matches!(result, Err(crate::Error::ConnectionFailed)));

        // Test binding to an already bound address
        let listener_addr = SocketAddr::from(([127, 0, 0, 1], PORT_NUMBER));
        let _listener = network.bind(listener_addr).await.expect("Failed to bind");

        // Try to bind to the same address
        let result = network.bind(listener_addr).await;
        assert!(matches!(result, Err(crate::Error::BindFailed)));
    }

    // // Test timeouts and partial reads/writes
    // fn test_network_timeouts<R: Runner>(runner: R)
    // where
    //     R::Context: crate::Network + Spawner + Clock,
    // {
    //     runner.start(|context| async move {
    //         let socket = SocketAddr::from(([127, 0, 0, 1], 0));

    //         // Start a server that deliberately doesn't respond
    //         let mut listener = context.bind(socket).await.expect("Failed to bind");
    //         let server_addr = listener.local_addr().expect("Failed to get server address");

    //         // Server task that accepts but doesn't respond
    //         let server = context.spawn(move |_| async move {
    //             let (_, _, _) = listener.accept().await.expect("Failed to accept");
    //             // Don't respond, just wait
    //             tokio::time::sleep(Duration::from_secs(2)).await;
    //         });

    //         // Client task with timeout
    //         let client = context.spawn(move |context| async move {
    //             let (mut sink, mut stream) = context
    //                 .dial(server_addr)
    //                 .await
    //                 .expect("Failed to dial server");

    //             // Send data
    //             sink.send(b"Hello").await.expect("Failed to send data");

    //             // Try to receive with a short timeout
    //             let mut buf = [0u8; 10];

    //             // Wrap in a timeout
    //             let result =
    //                 tokio::time::timeout(Duration::from_millis(100), stream.recv(&mut buf)).await;

    //             // Should timeout
    //             assert!(result.is_err());
    //         });

    //         // Wait for client to complete
    //         client.await.expect("Client task failed");

    //         // Don't wait for server to complete, it's deliberately hanging
    //     });
    // }
}

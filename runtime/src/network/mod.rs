pub(crate) mod metered;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod tokio;

// Add this to the tests module
#[cfg(test)]
mod network_tests {
    use futures::join;

    use crate::{
        deterministic, tokio::Runner as TokioRunner, Clock, Network as _, Runner, Spawner,
    };
    use crate::{Listener, Sink, Stream};

    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // Basic network connectivity test
    fn test_network_bind_and_dial<R: Runner>(runner: R)
    where
        R::Context: crate::Network + Spawner + Clock,
    {
        runner.start(|context| async move {
            // Use a dynamic port to avoid conflicts
            let socket = SocketAddr::from(([127, 0, 0, 1], 0));

            // Start a server
            let mut listener = context.bind(socket).await.expect("Failed to bind");
            let server_addr = listener.local_addr().expect("Failed to get server address");

            // Server task
            let server = context.spawn(move |_| async move {
                let (client_addr, mut sink, mut stream) =
                    listener.accept().await.expect("Failed to accept");

                // Echo server
                let mut buf = [0u8; 10];
                stream.recv(&mut buf).await.expect("Failed to receive");
                sink.send(&buf).await.expect("Failed to send");

                client_addr
            });

            // Client task
            let client = context.spawn(move |context| async move {
                // Connect to the server
                let (mut sink, mut stream) = context
                    .dial(server_addr)
                    .await
                    .expect("Failed to dial server");

                // Send and receive data
                let data = b"Hello Test";
                sink.send(data).await.expect("Failed to send data");

                let mut buf = [0u8; 10];
                stream.recv(&mut buf).await.expect("Failed to receive data");

                assert_eq!(&buf, data);
            });

            // Wait for both tasks to complete
            let (server_result, client_result) = join!(server, client);
            assert!(server_result.is_ok());
            assert!(client_result.is_ok());
        });
    }

    // Test handling multiple clients
    fn test_network_multiple_clients<R: Runner>(runner: R)
    where
        R::Context: crate::Network + Spawner + Clock,
    {
        runner.start(|context| async move {
            let socket = SocketAddr::from(([127, 0, 0, 1], 0));

            // Start a server
            let mut listener = context.bind(socket).await.expect("Failed to bind");
            let server_addr = listener.local_addr().expect("Failed to get server address");

            // Connection counter
            let connection_count = Arc::new(AtomicUsize::new(0));

            // Server task
            let server_conn_count = connection_count.clone();
            let server = context.spawn(move |context| async move {
                // Handle multiple clients
                for _ in 0..3 {
                    let (_, mut sink, mut stream) =
                        listener.accept().await.expect("Failed to accept");
                    let count = server_conn_count.clone();

                    context.spawn(move |_| async move {
                        let mut buf = [0u8; 10];
                        stream.recv(&mut buf).await.expect("Failed to receive");
                        sink.send(&buf).await.expect("Failed to send");
                        count.fetch_add(1, Ordering::SeqCst);
                    });
                }
            });

            // Create multiple clients
            let mut client_handles = Vec::new();
            for i in 0..3 {
                let client_ctx = context.with_label(&format!("client_{}", i));
                let client = client_ctx.spawn(move |context| async move {
                    // Connect to the server
                    let (mut sink, mut stream) = context
                        .dial(server_addr)
                        .await
                        .expect("Failed to dial server");

                    // Send unique data for each client
                    let data = [i as u8; 10];
                    sink.send(&data).await.expect("Failed to send data");

                    let mut buf = [0u8; 10];
                    stream.recv(&mut buf).await.expect("Failed to receive data");

                    assert_eq!(&buf, &data);
                });
                client_handles.push(client);
            }

            // Wait for server and all clients
            server.await.expect("Server task failed");
            for (i, handle) in client_handles.into_iter().enumerate() {
                handle.await.expect(&format!("Client {} failed", i));
            }

            // Verify all connections were processed
            assert_eq!(connection_count.load(Ordering::SeqCst), 3);
        });
    }

    // Test large data transfer
    fn test_network_large_data<R: Runner>(runner: R)
    where
        R::Context: crate::Network + Spawner,
    {
        runner.start(|context| async move {
            let socket = SocketAddr::from(([127, 0, 0, 1], 0));

            // Start a server
            let mut listener = context.bind(socket).await.expect("Failed to bind");
            let server_addr = listener.local_addr().expect("Failed to get server address");

            // Server task
            let server = context.spawn(move |_| async move {
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
            let client = context.spawn(move |context| async move {
                let (mut sink, mut stream) = context
                    .dial(server_addr)
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

            // Wait for tasks to complete
            let (server_total, client_results) = join!(server, client);
            let (client_sent, client_received) = client_results.unwrap();

            assert!(server_total.is_ok());
            assert_eq!(client_sent, 1_048_576); // 128 * 8192
            assert_eq!(client_received, 1_048_576);
        });
    }

    // Test connection errors
    fn test_network_connection_errors<R: Runner>(runner: R)
    where
        R::Context: crate::Network + Spawner,
    {
        runner.start(|context| async move {
            // Test dialing an invalid address
            let invalid_addr = SocketAddr::from(([127, 0, 0, 1], 1));
            let result = context.dial(invalid_addr).await;
            assert!(matches!(result, Err(Error::ConnectionFailed)));

            // Test binding to an already bound address
            let socket = SocketAddr::from(([127, 0, 0, 1], 0));
            let listener1 = context.bind(socket).await.expect("Failed to bind");
            let bound_addr = listener1
                .local_addr()
                .expect("Failed to get server address");

            // Try to bind to the same address
            let result = context.bind(bound_addr).await;
            assert!(matches!(result, Err(Error::BindFailed)));
        });
    }

    // Test timeouts and partial reads/writes
    fn test_network_timeouts<R: Runner>(runner: R)
    where
        R::Context: crate::Network + Spawner + Clock,
    {
        runner.start(|context| async move {
            let socket = SocketAddr::from(([127, 0, 0, 1], 0));

            // Start a server that deliberately doesn't respond
            let mut listener = context.bind(socket).await.expect("Failed to bind");
            let server_addr = listener.local_addr().expect("Failed to get server address");

            // Server task that accepts but doesn't respond
            let server = context.spawn(move |_| async move {
                let (_, _, _) = listener.accept().await.expect("Failed to accept");
                // Don't respond, just wait
                tokio::time::sleep(Duration::from_secs(2)).await;
            });

            // Client task with timeout
            let client = context.spawn(move |context| async move {
                let (mut sink, mut stream) = context
                    .dial(server_addr)
                    .await
                    .expect("Failed to dial server");

                // Send data
                sink.send(b"Hello").await.expect("Failed to send data");

                // Try to receive with a short timeout
                let mut buf = [0u8; 10];

                // Wrap in a timeout
                let result =
                    tokio::time::timeout(Duration::from_millis(100), stream.recv(&mut buf)).await;

                // Should timeout
                assert!(result.is_err());
            });

            // Wait for client to complete
            client.await.expect("Client task failed");

            // Don't wait for server to complete, it's deliberately hanging
        });
    }

    // Run the tests for each runtime implementation

    #[test]
    fn test_deterministic_network_bind_and_dial() {
        let executor = deterministic::Runner::default();
        test_network_bind_and_dial(executor);
    }

    #[test]
    fn test_deterministic_network_multiple_clients() {
        let executor = deterministic::Runner::default();
        test_network_multiple_clients(executor);
    }

    #[test]
    fn test_deterministic_network_large_data() {
        let executor = deterministic::Runner::default();
        test_network_large_data(executor);
    }

    #[test]
    fn test_deterministic_network_connection_errors() {
        let executor = deterministic::Runner::default();
        test_network_connection_errors(executor);
    }

    #[test]
    fn test_deterministic_network_timeouts() {
        let executor = deterministic::Runner::default();
        test_network_timeouts(executor);
    }

    #[test]
    fn test_tokio_network_bind_and_dial() {
        let executor = TokioRunner::default();
        test_network_bind_and_dial(executor);
    }

    #[test]
    fn test_tokio_network_multiple_clients() {
        let executor = TokioRunner::default();
        test_network_multiple_clients(executor);
    }

    #[test]
    fn test_tokio_network_large_data() {
        let executor = TokioRunner::default();
        test_network_large_data(executor);
    }

    #[test]
    fn test_tokio_network_connection_errors() {
        let executor = TokioRunner::default();
        test_network_connection_errors(executor);
    }

    #[test]
    fn test_tokio_network_timeouts() {
        let executor = TokioRunner::default();
        test_network_timeouts(executor);
    }
}

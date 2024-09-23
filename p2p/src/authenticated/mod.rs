mod actors;
mod channels;
mod config;
mod connection;
mod ip;
mod metrics;
mod network;
mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("message too large: {0}")]
    MessageTooLarge(usize),
    #[error("compression failed")]
    CompressionFailed,
    #[error("decompression failed")]
    DecompressionFailed,
    #[error("network closed")]
    NetworkClosed,
}

pub use actors::tracker::Oracle;
pub use channels::{Receiver, Sender};
pub use config::{Bootstrapper, Config};
pub use network::Network;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Receiver, Recipients, Sender};
    use bytes::Bytes;
    use commonware_cryptography::{Ed25519, Scheme};
    use commonware_runtime::{
        deterministic, tokio, Clock, Listener, Network as RNetwork, Runner, Sink, Spawner, Stream,
    };
    use governor::{clock::ReasonablyRealtime, Quota};
    use prometheus_client::registry::Registry;
    use rand::{CryptoRng, Rng};
    use std::collections::HashSet;
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        num::NonZeroU32,
        sync::{Arc, Mutex},
        time::Duration,
    };

    #[derive(Copy, Clone)]
    enum Mode {
        All,
        Some,
        One,
    }

    /// Test connectivity between `n` peers.
    ///
    /// We set a unique `base_port` for each test to avoid "address already in use"
    /// errors when tests are run immediately after each other.
    async fn run_network<Si: Sink, St: Stream, L: Listener<Si, St>>(
        runtime: impl Spawner + Clock + ReasonablyRealtime + Rng + CryptoRng + RNetwork<L, Si, St>,
        max_message_size: usize,
        base_port: u16,
        n: usize,
        mode: Mode,
    ) {
        // Create peers
        let mut peers = Vec::new();
        for i in 0..n {
            peers.push(Ed25519::from_seed(i as u64));
        }
        let addresses = peers.iter().map(|p| p.public_key()).collect::<Vec<_>>();

        // Create networks
        let mut waiters = Vec::new();
        for (i, peer) in peers.iter().enumerate() {
            // Derive port
            let port = base_port + i as u16;

            // Create bootstrappers
            let mut bootstrappers = Vec::new();
            if i > 0 {
                bootstrappers.push((
                    addresses[0].clone(),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port),
                ));
            }

            // Create network
            let signer = peer.clone();
            let registry = Arc::new(Mutex::new(Registry::with_prefix("p2p")));
            let config = Config::test(
                signer.clone(),
                registry,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                bootstrappers,
                max_message_size,
            );
            let (mut network, mut oracle) = Network::new(runtime.clone(), config);

            // Register peers
            oracle.register(0, addresses.clone()).await;

            // Register basic application
            let (mut sender, mut receiver) = network.register(
                0,
                Quota::per_second(NonZeroU32::new(1).unwrap()), // Ensure we hit the rate limit
                1_024,
                128,
                None,
            );

            // Wait to connect to all peers, and then send messages to everyone
            runtime.spawn(network.run());

            // Send/Recieve messages
            let handler = runtime.spawn({
                let addresses = addresses.clone();
                let runtime = runtime.clone();
                async move {
                    // Wait for all peers to send their identity
                    let acker = runtime.spawn(async move {
                        let mut received = HashSet::new();
                        while received.len() < n - 1 {
                            // Ensure message equals sender identity
                            let (sender, message) = receiver.recv().await.unwrap();
                            assert_eq!(sender, message);

                            // Add to received set
                            received.insert(sender);
                        }
                    });

                    // Send identity to all peers
                    let msg = signer.public_key();
                    match mode {
                        Mode::One => {
                            for (j, recipient) in addresses.iter().enumerate() {
                                // Don't send message to self
                                if i == j {
                                    continue;
                                }

                                // Loop until success
                                loop {
                                    let sent = sender
                                        .send(Recipients::One(recipient.clone()), msg.clone(), true)
                                        .await
                                        .unwrap();
                                    if sent.len() != 1 {
                                        runtime.sleep(Duration::from_millis(100)).await;
                                        continue;
                                    }
                                    assert_eq!(sent[0], recipient);
                                    break;
                                }
                            }
                        }
                        Mode::Some => {
                            // Get all peers not including self
                            let mut recipients = addresses.clone();
                            recipients.remove(i);
                            recipients.sort();

                            // Loop until all peer sends successful
                            loop {
                                let mut sent = sender
                                    .send(Recipients::Some(recipients.clone()), msg.clone(), true)
                                    .await
                                    .unwrap();
                                if sent.len() != n - 1 {
                                    runtime.sleep(Duration::from_millis(100)).await;
                                    continue;
                                }

                                // Compare to expected
                                sent.sort();
                                assert_eq!(sent, recipients);
                                break;
                            }
                        }
                        Mode::All => {
                            // Get all peers not including self
                            let mut recipients = addresses.clone();
                            recipients.remove(i);
                            recipients.sort();

                            // Loop until all peer sends successful
                            loop {
                                let mut sent = sender
                                    .send(Recipients::All, msg.clone(), true)
                                    .await
                                    .unwrap();
                                if sent.len() != n - 1 {
                                    runtime.sleep(Duration::from_millis(100)).await;
                                    continue;
                                }

                                // Compare to expected
                                sent.sort();
                                assert_eq!(sent, recipients);
                                break;
                            }
                        }
                    };

                    // Wait for all peers to send their identity
                    acker.await.unwrap();
                }
            });

            // Add to waiters
            waiters.push(handler);
        }

        // Wait for all peers to finish
        for waiter in waiters {
            waiter.await.unwrap();
        }
    }

    fn run_deterministic_test(mode: Mode) {
        let max_message_size = 1_024 * 1_024; // 1MB
        let (executor, runtime, auditor) =
            deterministic::Executor::init(0, Duration::from_millis(1));
        executor.start(async move {
            run_network(runtime, max_message_size, 3000, 10, mode).await;
        });
        let state = auditor.state();
        let (executor, runtime, auditor) =
            deterministic::Executor::init(0, Duration::from_millis(1));
        executor.start(async move {
            run_network(runtime, max_message_size, 3000, 10, mode).await;
        });
        assert_eq!(state, auditor.state());
    }

    #[test]
    fn test_determinism_one() {
        run_deterministic_test(Mode::One);
    }

    #[test]
    fn test_determinism_some() {
        run_deterministic_test(Mode::Some);
    }

    #[test]
    fn test_determinism_all() {
        run_deterministic_test(Mode::All);
    }

    #[test]
    fn test_deterministic_connectivity() {
        let max_message_size = 1_024 * 1_024; // 1MB
        let (executor, runtime, _) = deterministic::Executor::init(1, Duration::from_millis(1));
        executor.start(async move {
            run_network(runtime, max_message_size, 3000, 10, Mode::One).await;
        });
    }

    #[test]
    fn test_tokio_connectivity() {
        let cfg = tokio::Config::default();
        let (executor, runtime) = tokio::Executor::init(cfg);
        executor.start(async move {
            run_network(runtime, cfg.max_message_size, 3000, 10, Mode::One).await;
        });
    }

    #[test]
    fn test_multi_index_oracle() {
        // Configure test
        let base_port = 3000;
        let n: usize = 100;

        // Initialize runtime
        let (executor, runtime, _) = deterministic::Executor::init(0, Duration::from_millis(1));
        executor.start(async move {
            // Create peers
            let mut peers = Vec::new();
            for i in 0..n {
                peers.push(Ed25519::from_seed(i as u64));
            }
            let addresses = peers.iter().map(|p| p.public_key()).collect::<Vec<_>>();

            // Create networks
            let mut waiters = Vec::new();
            for (i, peer) in peers.iter().enumerate() {
                // Derive port
                let port = base_port + i as u16;

                // Create bootstrappers
                let mut bootstrappers = Vec::new();
                if i > 0 {
                    bootstrappers.push((
                        addresses[0].clone(),
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port),
                    ));
                }

                // Create network
                let signer = peer.clone();
                let registry = Arc::new(Mutex::new(Registry::with_prefix("p2p")));
                let config = Config::test(
                    signer.clone(),
                    registry,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                    bootstrappers,
                    1_024 * 1_024, // 1MB
                );
                let (mut network, mut oracle) = Network::new(runtime.clone(), config);

                // Register peers at separate indices
                oracle.register(0, vec![addresses[0].clone()]).await;
                oracle
                    .register(1, vec![addresses[1].clone(), addresses[2].clone()])
                    .await;
                oracle
                    .register(2, addresses.iter().skip(2).cloned().collect())
                    .await;

                // Register basic application
                let (mut sender, mut receiver) = network.register(
                    0,
                    Quota::per_second(NonZeroU32::new(10).unwrap()),
                    1_024 * 1_024, // 1MB
                    128,
                    None,
                );

                // Wait to connect to all peers, and then send messages to everyone
                runtime.spawn(network.run());

                // Send/Recieve messages
                let handler = runtime.spawn({
                    let runtime = runtime.clone();
                    async move {
                        if i == 0 {
                            // Loop until success
                            let msg = signer.public_key();
                            loop {
                                if sender
                                    .send(Recipients::All, msg.clone(), true)
                                    .await
                                    .unwrap()
                                    .len()
                                    == n - 1
                                {
                                    break;
                                }

                                // Sleep and try again (avoid busy loop)
                                runtime.sleep(Duration::from_millis(100)).await;
                            }
                        } else {
                            // Ensure message equals sender identity
                            let (sender, message) = receiver.recv().await.unwrap();
                            assert_eq!(sender, message);
                        }
                    }
                });

                // Add to waiters
                waiters.push(handler);
            }

            // Wait for waiters to finish (receiver before sender)
            for waiter in waiters.into_iter().rev() {
                waiter.await.unwrap();
            }
        });
    }

    fn test_chunking(compression: Option<u8>) {
        // Configure test
        let base_port = 3000;
        let n: usize = 2;

        // Initialize runtime
        let (executor, mut runtime, _) = deterministic::Executor::init(0, Duration::from_millis(1));
        executor.start(async move {
            // Create peers
            let mut peers = Vec::new();
            for i in 0..n {
                peers.push(Ed25519::from_seed(i as u64));
            }
            let addresses = peers.iter().map(|p| p.public_key()).collect::<Vec<_>>();

            // Create random message
            let mut msg = vec![0u8; 2 * 1024 * 1024]; // 2MB (greater than frame capacity)
            runtime.fill(&mut msg[..]);

            // Create networks
            let mut waiters = Vec::new();
            for (i, peer) in peers.iter().enumerate() {
                // Derive port
                let port = base_port + i as u16;

                // Create bootstrappers
                let mut bootstrappers = Vec::new();
                if i > 0 {
                    bootstrappers.push((
                        addresses[0].clone(),
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port),
                    ));
                }

                // Create network
                let signer = peer.clone();
                let registry = Arc::new(Mutex::new(Registry::with_prefix("p2p")));
                let config = Config::test(
                    signer.clone(),
                    registry,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                    1_024 * 1_024, // 1MB
                );
                let (mut network, mut oracle) = Network::new(runtime.clone(), config);

                // Register peers
                oracle.register(0, addresses.clone()).await;

                // Register basic application
                let (mut sender, mut receiver) = network.register(
                    0,
                    Quota::per_second(NonZeroU32::new(10).unwrap()),
                    5 * 1_024 * 1_024, // 5MB
                    128,
                    compression,
                );

                // Wait to connect to all peers, and then send messages to everyone
                runtime.spawn(network.run());

                // Send/Recieve messages
                let msg = Bytes::from(msg.clone());
                let msg_sender = addresses[0].clone();
                let msg_recipient = addresses[1].clone();
                let peer_handler = runtime.spawn({
                    let runtime = runtime.clone();
                    async move {
                        if i == 0 {
                            // Loop until success
                            let recipient = Recipients::One(msg_recipient);
                            loop {
                                if sender
                                    .send(recipient.clone(), msg.clone(), true)
                                    .await
                                    .unwrap()
                                    .len()
                                    == 1
                                {
                                    break;
                                }

                                // Sleep and try again (avoid busy loop)
                                runtime.sleep(Duration::from_millis(100)).await;
                            }
                        } else {
                            // Ensure message equals sender identity
                            let (sender, message) = receiver.recv().await.unwrap();
                            assert_eq!(sender, msg_sender);

                            // Ensure message equals sent message
                            assert_eq!(message.len(), msg.len());
                            for (i, (&byte1, &byte2)) in message.iter().zip(msg.iter()).enumerate()
                            {
                                assert_eq!(byte1, byte2, "byte {} mismatch", i);
                            }
                        }
                    }
                });

                // Add to waiters
                waiters.push(peer_handler);
            }

            // Wait for waiters to finish (receiver before sender)
            for waiter in waiters.into_iter().rev() {
                waiter.await.unwrap();
            }
        });
    }

    #[test]
    fn test_chunking_no_compression() {
        test_chunking(None);
    }

    #[test]
    fn test_chunking_compression() {
        test_chunking(Some(3));
    }

    fn test_message_too_large(compression: Option<u8>) {
        // Configure test
        let base_port = 3000;
        let n: usize = 2;

        // Initialize runtime
        let (executor, mut runtime, _) = deterministic::Executor::init(0, Duration::from_millis(1));
        executor.start(async move {
            // Create peers
            let mut peers = Vec::Vec::new();
            for i in 0..n {
                peers.push(Ed25519::from_seed(i as u64));
            }
            let addresses = peers.iter().map(|p| p.public_key()).collect::<Vec<_>>();

            // Create network
            let signer = peers[0].clone();
            let registry = Arc::new(Mutex::new(Registry::with_prefix("p2p")));
            let config = Config::test(
                signer.clone(),
                registry,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port),
                Vec::new(),
                1_024 * 1_024, // 1MB
            );
            let (mut network, mut oracle) = Network::new(runtime.clone(), config);

            // Register peers
            oracle.register(0, addresses.clone()).await;

            // Register basic application
            let (mut sender, _) = network.register(
                0,
                Quota::per_second(NonZeroU32::new(10).unwrap()),
                1_024 * 1_024, // 1MB
                128,
                compression,
            );

            // Wait to connect to all peers, and then send messages to everyone
            runtime.spawn(network.run());

            // Crate random message
            let mut msg = vec![0u8; 10 * 1024 * 1024]; // 10MB (greater than frame capacity)
            runtime.fill(&mut msg[..]);

            // Send message
            let recipient = Recipients::One(addresses[1].clone());
            let result = sender.send(recipient, msg.into(), true).await;
            assert!(matches!(result, Err(Error::MessageTooLarge(_))));
        });
    }

    #[test]
    fn test_message_too_large_no_compression() {
        test_message_too_large(None);
    }

    #[test]
    fn test_message_too_large_compression() {
        test_message_too_large(Some(3));
    }

    #[test]
    fn test_register_channel() {
        let cfg = tokio::Config::default();
        let (executor, runtime) = tokio::Executor::init(cfg);
        executor.start(async move {
            // Create peers
            let peer = Ed25519::from_seed(0);
            let addresses = vec![peer.public_key()];

            // Create network
            let registry = Arc::new(Mutex::new(Registry::with_prefix("p2p")));
            let config = Config::test(
                peer.clone(),
                registry,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000),
                Vec::new(),
                1_024 * 1_024, // 1MB
            );
            let (mut network, mut oracle) = Network::new(runtime.clone(), config);

            // Register peers
            oracle.register(0, addresses.clone()).await;

            // Register basic application
            let (sender, receiver) = network.register(
                0,
                Quota::per_second(NonZeroU32::new(10).unwrap()),
                1_024 * 1_024, // 1MB
                128,
                None,
            );

            // Ensure sender and receiver are not None
            assert!(sender.is_some());
            assert!(receiver.is_some());
        });
    }

    #[test]
    fn test_network_shutdown() {
        let cfg = tokio::Config::default();
        let (executor, runtime) = tokio::Executor::init(cfg);
        executor.start(async move {
            // Create peers
            let peer = Ed25519::from_seed(0);
            let addresses = vec![peer.public_key()];

            // Create network
            let registry = Arc::new(Mutex::new(Registry::with_prefix("p2p")));
            let config = Config::test(
                peer.clone(),
                registry,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000),
                Vec::new(),
                1_024 * 1_024, // 1MB
            );
            let (mut network, mut oracle) = Network::new(runtime.clone(), config);

            // Register peers
            oracle.register(0, addresses.clone()).await;

            // Register basic application
            let (sender, receiver) = network.register(
                0,
                Quota::per_second(NonZeroU32::new(10).unwrap()),
                1_024 * 1_024, // 1MB
                128,
                None,
            );

            // Run network
            let network_handler = runtime.spawn(network.run());

            // Shutdown network
            network_handler.abort();

            // Ensure network is shutdown
            assert!(network_handler.is_aborted());
        });
    }

    #[test]
    fn test_compression() {
        let message = b"hello world";
        let compressed = compress(message, 3).unwrap();
        let buf = decompress(&compressed, message.len()).unwrap();
        assert_eq!(message, buf.as_slice());
    }

    #[tokio::test]
    async fn test_sender_send() {
        let (messenger_sender, mut messenger_receiver) = mpsc::channel(1);
        let messenger = Messenger::new(messenger_sender);
        let mut sender = Sender::new(1, 1024, None, messenger);

        let recipients = Recipients::All;
        let message = Bytes::from("test message");
        let result = sender.send(recipients, message.clone(), false).await;

        assert!(result.is_ok());
        let sent_message = messenger_receiver.next().await.unwrap();
        assert_eq!(sent_message.2, message);
    }

    #[tokio::test]
    async fn test_receiver_recv() {
        let (sender, receiver) = mpsc::channel(1);
        let mut receiver = Receiver::new(1024, false, receiver);

        let message = Bytes::from("test message");
        let sender_key = PublicKey::from([0u8; 32]);
        sender.send((sender_key.clone(), message.clone())).await.unwrap();

        let received_message = receiver.recv().await.unwrap();
        assert_eq!(received_message.0, sender_key);
        assert_eq!(received_message.1, message);
    }

    #[tokio::test]
    async fn test_sender_send_with_compression() {
        let (messenger_sender, mut messenger_receiver) = mpsc::channel(1);
        let messenger = Messenger::new(messenger_sender);
        let mut sender = Sender::new(1, 1024, Some(3), messenger);

        let recipients = Recipients::All;
        let message = Bytes::from("test message");
        let result = sender.send(recipients, message.clone(), false).await;

        assert!(result.is_ok());
        let sent_message = messenger_receiver.next().await.unwrap();
        let decompressed_message = decompress(&sent_message.2, 1024).unwrap();
        assert_eq!(decompressed_message, message);
    }

    #[tokio::test]
    async fn test_receiver_recv_with_compression() {
        let (sender, receiver) = mpsc::channel(1);
        let mut receiver = Receiver::new(1024, true, receiver);

        let message = Bytes::from("test message");
        let compressed_message = compress(&message, 3).unwrap();
        let sender_key = PublicKey::from([0u8; 32]);
        sender.send((sender_key.clone(), compressed_message.into())).await.unwrap();

        let received_message = receiver.recv().await.unwrap();
        assert_eq!(received_message.0, sender_key);
        assert_eq!(received_message.1, message);
    }
}

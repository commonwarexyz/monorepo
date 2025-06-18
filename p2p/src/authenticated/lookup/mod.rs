//! Communicate with a fixed set of authenticated peers with known addresses over encrypted connections.
//!
//! `lookup` provides multiplexed communication between fully-connected peers
//! identified by a developer-specified cryptographic identity (i.e. BLS, ed25519, etc.).
//! Unlike `discovery`, peers in `lookup` don't use a discovery mechanism to find each other;
//! each peer's address is supplied by the application layer.
//!
//! # Features
//!
//! - Configurable Cryptography Scheme for Peer Identities (BLS, ed25519, etc.)
//! - Multiplexing With Configurable Rate Limiting Per Channel and Send Prioritization
//! - Optional Message Compression (using `zstd`)
//!
//! # Design
//!
//! ## Discovery
//!
//! This module operates under the assumption that all peers are aware of and synchronized on
//! the composition of peer sets at specific, user-provided indices (`u64`). Each index maps to a
//! list of peer `PublicKey`/`SocketAddr` pairs (`(u64, Vec<(PublicKey, SocketAddr)>)`).
//!
//! On startup, the application supplies the initial set of peers. The `Oracle` actor allows
//! the application to update peer --> address mappings so that peers can find each other.
//!
//! ## Messages
//!
//! Application-level data is exchanged using the `Data` message type. This structure contains:
//! - `channel`: A `u32` identifier used to route the message to the correct application handler.
//! - `message`: The arbitrary application payload as `Bytes`.
//!
//! The size of the `message` bytes (after potential compression) must not exceed the configured
//! `max_message_size`. If it does, the sending operation will fail with
//! [Error::MessageTooLarge]. Messages can be sent with `priority`, allowing certain
//! communications to potentially bypass lower-priority messages waiting in send queues across all
//! channels. Each registered channel ([Sender], [Receiver]) handles its own message queuing,
//! rate limiting, and optional `zstd` compression/decompression.
//!
//! # Example
//!
//! ```rust
//! use commonware_p2p::{authenticated::lookup::{self, Network}, Sender, Recipients};
//! use commonware_cryptography::{ed25519, Signer, PrivateKey as _, PublicKey as _, PrivateKeyExt as _};
//! use commonware_runtime::{tokio, Spawner, Runner, Metrics};
//! use commonware_utils::NZU32;
//! use governor::Quota;
//! use std::net::{IpAddr, Ipv4Addr, SocketAddr};
//!
//! // Configure context
//! let runtime_cfg = tokio::Config::default();
//! let runner = tokio::Runner::new(runtime_cfg.clone());
//!
//! // Generate identity
//! //
//! // In production, the signer should be generated from a secure source of entropy.
//! let my_sk = ed25519::PrivateKey::from_seed(0);
//! let my_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000);
//!
//! // Generate peers
//! //
//! // In production, peer identities will be provided by some external source of truth
//! // (like the staking set of a blockchain).
//! let peer1 = ed25519::PrivateKey::from_seed(1).public_key();
//! let peer1_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3001);
//! let peer2 = ed25519::PrivateKey::from_seed(2).public_key();
//! let peer2_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3002);
//! let peer3 = ed25519::PrivateKey::from_seed(3).public_key();
//! let peer3_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3003);
//!
//! // Configure namespace
//! //
//! // In production, use a unique application namespace to prevent cryptographic replay attacks.
//! let application_namespace = b"my-app-namespace";
//!
//! // Configure network
//! //
//! // In production, use a more conservative configuration like `Config::recommended`.
//! const MAX_MESSAGE_SIZE: usize = 1_024; // 1KB
//! let p2p_cfg = lookup::Config::aggressive(
//!     my_sk.clone(),
//!     application_namespace,
//!     my_addr,
//!     my_addr,
//!     MAX_MESSAGE_SIZE,
//! );
//!
//! // Start context
//! runner.start(|context| async move {
//!     // Initialize network
//!     let (mut network, mut oracle) = Network::new(context.with_label("network"), p2p_cfg);
//!
//!     // Register authorized peers
//!     //
//!     // In production, this would be updated as new peer sets are created (like when
//!     // the composition of a validator set changes).
//!     oracle.register(0, vec![(my_sk.public_key(), my_addr), (peer1, peer1_addr), (peer2, peer2_addr), (peer3, peer3_addr)]).await;
//!
//!     // Register some channel
//!     const MAX_MESSAGE_BACKLOG: usize = 128;
//!     const COMPRESSION_LEVEL: Option<i32> = Some(3);
//!     let (mut sender, receiver) = network.register(
//!         0,
//!         Quota::per_second(NZU32!(1)),
//!         MAX_MESSAGE_BACKLOG,
//!         COMPRESSION_LEVEL,
//!     );
//!
//!     // Run network
//!     let network_handler = network.start();
//!
//!     // Example: Use sender
//!     let _ = sender.send(Recipients::All, bytes::Bytes::from_static(b"hello"), false).await;
//!
//!     // Shutdown network
//!     network_handler.abort();
//! });
//! ```

mod actors;
mod channels;
mod config;
mod metrics;
mod network;
mod types;

use thiserror::Error;

/// Errors that can occur when interacting with the network.
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
pub use config::Config;
pub use network::Network;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Receiver, Recipients, Sender};
    use commonware_cryptography::{ed25519, PrivateKeyExt as _, Signer as _};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic, tokio, Clock, Metrics, Network as RNetwork, Runner, Spawner,
    };
    use commonware_utils::NZU32;
    use governor::{clock::ReasonablyRealtime, Quota};
    use rand::{CryptoRng, Rng};
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    #[derive(Copy, Clone)]
    enum Mode {
        All,
        Some,
        One,
    }

    const DEFAULT_MESSAGE_BACKLOG: usize = 128;

    /// Test connectivity between `n` peers.
    ///
    /// We set a unique `base_port` for each test to avoid "address already in use"
    /// errors when tests are run immediately after each other.
    async fn run_network(
        context: impl Spawner + Clock + ReasonablyRealtime + Rng + CryptoRng + RNetwork + Metrics,
        max_message_size: usize,
        base_port: u16,
        n: usize,
        mode: Mode,
    ) {
        // Create peers
        let mut peers_and_sks = Vec::new();
        for i in 0..n {
            let private_key = ed25519::PrivateKey::from_seed(i as u64);
            let public_key = private_key.public_key();
            let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port + i as u16);
            peers_and_sks.push((private_key, public_key, address));
        }
        let peers = peers_and_sks
            .iter()
            .map(|(_, pub_key, addr)| (pub_key.clone(), *addr))
            .collect::<Vec<_>>();

        // Create networks
        let mut waiters = Vec::new();
        let mut oracles = Vec::new();
        for (i, (private_key, public_key, address)) in peers_and_sks.iter().enumerate() {
            let public_key = public_key.clone();

            // Create peer context
            let context = context.with_label(&format!("peer-{}", i));

            // Create network
            let config = Config::test(private_key.clone(), *address, max_message_size);
            let (mut network, mut oracle) = Network::new(context.with_label("network"), config);

            // Register peers
            oracle.register(0, peers.clone()).await;
            oracles.push(oracle);

            // Register basic application
            let (mut sender, mut receiver) = network.register(
                0,
                Quota::per_second(NZU32!(5)), // Ensure we hit the rate limit
                DEFAULT_MESSAGE_BACKLOG,
                None,
            );

            // Wait to connect to all peers, and then send messages to everyone
            network.start();

            // Send/Receive messages
            let peers = peers.clone();
            // All public keys (except self) sorted
            let mut public_keys = peers
                .iter()
                .filter_map(|(pk, _)| {
                    if pk != &public_key {
                        Some(pk.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            public_keys.sort();
            let handler = context.with_label("agent").spawn({
                move |context| async move {
                    // Wait for all peers to send their identity
                    let acker = context.with_label("receiver").spawn(move |_| async move {
                        let mut received = HashSet::new();
                        while received.len() < n - 1 {
                            // Ensure message equals sender identity
                            let (sender, message) = receiver.recv().await.unwrap();
                            assert_eq!(sender.as_ref(), message.as_ref());

                            // Add to received set
                            received.insert(sender);
                        }
                    });

                    // Send identity to all peers
                    match mode {
                        Mode::One => {
                            for (j, (pub_key, _)) in peers.iter().enumerate() {
                                // Don't send message to self
                                if i == j {
                                    continue;
                                }

                                // Loop until success
                                loop {
                                    let sent = sender
                                        .send(
                                            Recipients::One(pub_key.clone()),
                                            public_key.to_vec().into(),
                                            true,
                                        )
                                        .await
                                        .unwrap();
                                    if sent.len() != 1 {
                                        context.sleep(Duration::from_millis(100)).await;
                                        continue;
                                    }
                                    assert_eq!(&sent[0], pub_key);
                                    break;
                                }
                            }
                        }
                        Mode::Some => {
                            // Get all peers not including self
                            let mut recipients = peers.clone();
                            recipients.remove(i);
                            recipients.sort();

                            // Loop until all peer sends successful
                            loop {
                                let mut sent = sender
                                    .send(
                                        Recipients::Some(public_keys.clone()),
                                        public_key.to_vec().into(),
                                        true,
                                    )
                                    .await
                                    .unwrap();
                                if sent.len() != n - 1 {
                                    context.sleep(Duration::from_millis(100)).await;
                                    continue;
                                }

                                // Compare to expected
                                sent.sort();
                                assert_eq!(sent, public_keys);
                                break;
                            }
                        }
                        Mode::All => {
                            // Get all peers not including self
                            let mut recipients = peers.clone();
                            recipients.remove(i);
                            recipients.sort();

                            // Loop until all peer sends successful
                            loop {
                                let mut sent = sender
                                    .send(Recipients::All, public_key.to_vec().into(), true)
                                    .await
                                    .unwrap();
                                if sent.len() != n - 1 {
                                    context.sleep(Duration::from_millis(100)).await;
                                    continue;
                                }

                                // Compare to expected
                                sent.sort();
                                assert_eq!(sent, public_keys);
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

    fn run_deterministic_test(seed: u64, mode: Mode) {
        // Configure test
        const MAX_MESSAGE_SIZE: usize = 1_024 * 1_024; // 1MB
        const NUM_PEERS: usize = 25;
        const BASE_PORT: u16 = 3000;

        // Run first instance
        let executor = deterministic::Runner::seeded(seed);
        let state = executor.start(|context| async move {
            run_network(
                context.clone(),
                MAX_MESSAGE_SIZE,
                BASE_PORT,
                NUM_PEERS,
                mode,
            )
            .await;
            context.auditor().state()
        });

        // Compare result to second instance
        let executor = deterministic::Runner::seeded(seed);
        let state2 = executor.start(|context| async move {
            run_network(
                context.clone(),
                MAX_MESSAGE_SIZE,
                BASE_PORT,
                NUM_PEERS,
                mode,
            )
            .await;
            context.auditor().state()
        });
        assert_eq!(state, state2);
    }

    #[test_traced]
    #[ignore]
    fn test_determinism_one() {
        for i in 0..10 {
            run_deterministic_test(i, Mode::One);
        }
    }

    #[test_traced]
    #[ignore]
    fn test_determinism_some() {
        for i in 0..10 {
            run_deterministic_test(i, Mode::Some);
        }
    }

    #[test_traced]
    #[ignore]
    fn test_determinism_all() {
        for i in 0..10 {
            run_deterministic_test(i, Mode::All);
        }
    }

    #[test_traced]
    fn test_tokio_connectivity() {
        let cfg = tokio::Config::default();
        let executor = tokio::Runner::new(cfg.clone());
        executor.start(|context| async move {
            const MAX_MESSAGE_SIZE: usize = 1_024 * 1_024; // 1MB
            let base_port = 4000;
            let n = 10;
            run_network(context, MAX_MESSAGE_SIZE, base_port, n, Mode::One).await;
        });
    }

    #[test_traced]
    fn test_multi_index_oracle() {
        // Configure test
        let base_port = 3000;
        let n: usize = 10;

        // Initialize context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create peers
            let mut peers_and_sks = Vec::new();
            for i in 0..n {
                let sk = ed25519::PrivateKey::from_seed(i as u64);
                let pk = sk.public_key();
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port + i as u16);
                peers_and_sks.push((sk, pk, addr));
            }
            let peers = peers_and_sks
                .iter()
                .map(|(_, pk, addr)| (pk.clone(), *addr))
                .collect::<Vec<_>>();

            // Create networks
            let mut waiters = Vec::new();
            for (i, (peer_sk, peer_pk, peer_addr)) in peers_and_sks.iter().enumerate() {
                // Create peer context
                let context = context.with_label(&format!("peer-{}", i));

                // Create network
                let config = Config::test(
                    peer_sk.clone(),
                    *peer_addr,
                    1_024 * 1_024, // 1MB
                );
                let (mut network, mut oracle) = Network::new(context.with_label("network"), config);

                // Register peers at separate indices
                oracle.register(0, vec![peers[0].clone()]).await;
                oracle
                    .register(1, vec![peers[1].clone(), peers[2].clone()])
                    .await;
                oracle
                    .register(2, peers.iter().skip(2).cloned().collect())
                    .await;

                // Register basic application
                let (mut sender, mut receiver) = network.register(
                    0,
                    Quota::per_second(NZU32!(10)),
                    DEFAULT_MESSAGE_BACKLOG,
                    None,
                );

                // Wait to connect to all peers, and then send messages to everyone
                network.start();

                // Send/Receive messages
                let msg = peer_pk.clone();
                let handler = context
                    .with_label("agent")
                    .spawn(move |context| async move {
                        if i == 0 {
                            // Loop until success
                            loop {
                                if sender
                                    .send(Recipients::All, msg.to_vec().into(), true)
                                    .await
                                    .unwrap()
                                    .len()
                                    == n - 1
                                {
                                    break;
                                }

                                // Sleep and try again (avoid busy loop)
                                context.sleep(Duration::from_millis(100)).await;
                            }
                        } else {
                            // Ensure message equals sender identity
                            let (sender, message) = receiver.recv().await.unwrap();
                            assert_eq!(sender.as_ref(), message.as_ref());
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

    fn test_message_too_large(compression: Option<i32>) {
        // Configure test
        let base_port = 3000;
        let n: usize = 2;

        // Initialize context
        let executor = deterministic::Runner::seeded(0);
        executor.start(|mut context| async move {
            // Create peers
            let mut peers_and_sks = Vec::new();
            for i in 0..n {
                let peer_sk = ed25519::PrivateKey::from_seed(i as u64);
                let peer_pk = peer_sk.public_key();
                let peer_addr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port + i as u16);
                peers_and_sks.push((peer_sk, peer_pk, peer_addr));
            }
            let peers = peers_and_sks
                .iter()
                .map(|(_, pk, addr)| (pk.clone(), *addr))
                .collect::<Vec<_>>();

            // Create network
            let (sk, _, addr) = peers_and_sks[0].clone();
            let config = Config::test(
                sk,
                addr,
                1_024 * 1_024, // 1MB
            );
            let (mut network, mut oracle) = Network::new(context.with_label("network"), config);

            // Register peers
            oracle.register(0, peers.clone()).await;

            // Register basic application
            let (mut sender, _) = network.register(
                0,
                Quota::per_second(NZU32!(10)),
                DEFAULT_MESSAGE_BACKLOG,
                compression,
            );

            // Wait to connect to all peers, and then send messages to everyone
            network.start();

            // Crate random message
            let mut msg = vec![0u8; 10 * 1024 * 1024]; // 10MB (greater than frame capacity)
            context.fill(&mut msg[..]);

            // Send message
            let recipient = Recipients::One(peers[1].0.clone());
            let result = sender.send(recipient, msg.into(), true).await;
            assert!(matches!(result, Err(Error::MessageTooLarge(_))));
        });
    }

    #[test_traced]
    fn test_message_too_large_no_compression() {
        test_message_too_large(None);
    }

    #[test_traced]
    fn test_message_too_large_compression() {
        test_message_too_large(Some(3));
    }
}

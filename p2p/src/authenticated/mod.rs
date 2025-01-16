//! Communicate with a fixed set of authenticated peers over encrypted connections.
//!
//! `authenticated` provides multiplexed communication between fully-connected peers
//! identified by a developer-specified cryptographic identity (i.e. BLS, ed25519, etc.).
//! Peer discovery occurs automatically using ordered bit vectors (sorted by authorized
//! cryptographic identities) to efficiently communicate knowledge of dialable peers.
//!
//! # Features
//!
//! * Configurable Cryptography Scheme for Peer Identities (BLS, ed25519, etc.)
//! * Automatic Peer Discovery Using Bit Vectors (Used as Ping/Pongs)
//! * Multiplexing With Configurable Rate Limiting Per Channel and Send Prioritization
//! * Optional Message Compression (using `zstd`)
//!
//! # Design
//!
//! ## Discovery
//!
//! Peer discovery relies heavily on the assumption that all peers are known and synchronized at each index (a user-provided tuple of
//! `(u64, Vec<PublicKey>)`). Using this assumption, we can construct a sorted bit vector that represents our knowledge
//! of peer IPs (where 1 == we know, 0 == we don't know). This means we can represent our knowledge of 1000 peers in only 125 bytes!
//!
//! _If peers at a given index are not synchronized, peers may signal their knowledge of peer IPs that another peer may
//! incorrectly respond to (associating a given index with a different peer) or fail to respond to (if the bit vector representation
//! of the set is smaller/larger than expected). It is up to the application to ensure sets are synchronized._
//!
//! Because this representation is so efficient/small, peers send bit vectors to each other periodically as a "ping" to keep
//! the connection alive. Because it may be useful to be connected to multiple indexes of peers at a given time (i.e. to
//! perform a DKG with a new set of peers), it is possible to configure this crate to maintain connections to multiple
//! indexes (and pings are a random index we are trying to connect to).
//!
//! ```protobuf
//! message BitVec {
//!     uint64 index = 1;
//!     bytes bits = 2;
//! }
//! ```
//!
//! Upon receiving a bit vector, a peer will select a random collection of peers (under a configured max) that it knows about that the
//! sender does not. If the sender knows about all peers that we know about, the receiver does nothing (and relies on its bit vector
//! to serve as a pong to keep the connection alive).
//!
//! ```protobuf
//! message Peers {
//!     repeated Peer peers = 1;
//! }
//! ```
//!
//! If a peer learns about an updated address for a peer, it will update the record it has stored (for itself and for future gossip).
//! This record is created during instantiation and is sent immediately after a connection is established (right after the handshake).
//! This means that a peer that learned about an outdated record for a peer will update it immediately upon being dialed.
//!
//! ```protobuf
//! message Peer {
//!     bytes socket = 1;
//!     uint64 timestamp = 2;
//!     Signature signature = 3;
//! }
//! ```
//!
//! To get all of this started, a peer must first be bootstrapped with a list of known peers/addresses. The peer will dial these
//! other peers, send its own record, send a bit vector (with all 0's except its own position in the sorted list), and then
//! wait for the other peer to respond with some set of unknown peers. Different peers do not need to agree on who this list of
//! bootstrapping peers is (this list is configurable). Knowledge of bootstrappers and connections to them are never dropped,
//! even if the bootstrapper is not in any known peer set.
//!
//! _If a peer is not in any registered peer set (to its knowledge) but is dialed by a peer that is, it will accept the connection.
//! This allows peers that have a more up-to-date version of the peer set to connect, exchange application-level information, and for
//! the said peer to potentially learn of an updated peer set (of which it is part)._
//!
//! ## Messages
//!
//! Messages are sent using the Data message type. This message type is used to send arbitrary bytes to a given channel.
//! The message must be smaller (in bytes) than the configured maximum message size. If the message is larger, an error will be returned.
//! It is possible for a sender to prioritize messages over others.
//!
//! ```protobuf
//! message Data {
//!     uint32 channel = 1;
//!     bytes message = 2;
//! }
//! ```
//!
//! # Example
//!
//! ```rust
//! use commonware_p2p::authenticated::{self, Network};
//! use commonware_cryptography::{Ed25519, Scheme};
//! use commonware_runtime::{tokio::{self, Executor}, Spawner, Runner};
//! use governor::Quota;
//! use prometheus_client::registry::Registry;
//! use std::net::{IpAddr, Ipv4Addr, SocketAddr};
//! use std::num::NonZeroU32;
//! use std::sync::{Arc, Mutex};
//!
//! // Configure runtime
//! let runtime_cfg = tokio::Config::default();
//! let (executor, runtime) = Executor::init(runtime_cfg.clone());
//!
//! // Configure prometheus registry
//! let registry = Arc::new(Mutex::new(Registry::with_prefix("p2p")));
//!
//! // Generate identity
//! //
//! // In production, the signer should be generated from a secure source of entropy.
//! let signer = Ed25519::from_seed(0);
//!
//! // Generate peers
//! //
//! // In production, peer identities will be provided by some external source of truth
//! // (like the staking set of a blockchain).
//! let peer1 = Ed25519::from_seed(1).public_key();
//! let peer2 = Ed25519::from_seed(2).public_key();
//! let peer3 = Ed25519::from_seed(3).public_key();
//!
//! // Configure bootstrappers
//! //
//! // In production, it is likely that the address of bootstrappers will be some public address.
//! let bootstrappers = vec![(peer1.clone(), SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3001))];
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
//! let p2p_cfg = authenticated::Config::aggressive(
//!     signer.clone(),
//!     application_namespace,
//!     registry,
//!     SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000),
//!     bootstrappers,
//!     MAX_MESSAGE_SIZE,
//! );
//!
//! // Start runtime
//! executor.start(async move {
//!     // Initialize network
//!     let (mut network, mut oracle) = Network::new(runtime.clone(), p2p_cfg);
//!
//!     // Register authorized peers
//!     //
//!     // In production, this would be updated as new peer sets are created (like when
//!     // the composition of a validator set changes).
//!     oracle.register(0, vec![signer.public_key(), peer1, peer2, peer3]);
//!
//!     // Register some channel
//!     const MAX_MESSAGE_BACKLOG: usize = 128;
//!     const COMPRESSION_LEVEL: Option<i32> = Some(3);
//!     let (sender, receiver) = network.register(
//!         0,
//!         Quota::per_second(NonZeroU32::new(1).unwrap()),
//!         MAX_MESSAGE_BACKLOG,
//!         COMPRESSION_LEVEL,
//!     );
//!
//!     // Run network
//!     let network_handler = runtime.spawn("network", network.run());
//!
//!     // ... Use sender and receiver ...
//!
//!     // Shutdown network
//!     network_handler.abort();
//! });
//! ```

mod actors;
mod channels;
mod config;
mod ip;
mod metrics;
mod network;
mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

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
pub use config::{Bootstrapper, Config};
pub use network::Network;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Receiver, Recipients, Sender};
    use commonware_cryptography::{Ed25519, Scheme};
    use commonware_macros::test_traced;
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

    const DEFAULT_MESSAGE_BACKLOG: usize = 128;

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
                Quota::per_second(NonZeroU32::new(5).unwrap()), // Ensure we hit the rate limit
                DEFAULT_MESSAGE_BACKLOG,
                None,
            );

            // Wait to connect to all peers, and then send messages to everyone
            runtime.spawn("network", network.run());

            // Send/Receive messages
            let handler = runtime.spawn("agent", {
                let addresses = addresses.clone();
                let runtime = runtime.clone();
                async move {
                    // Wait for all peers to send their identity
                    let acker = runtime.spawn("receiver", async move {
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

    fn run_deterministic_test(seed: u64, mode: Mode) {
        // Configure test
        const MAX_MESSAGE_SIZE: usize = 1_024 * 1_024; // 1MB
        const NUM_PEERS: usize = 25;
        const BASE_PORT: u16 = 3000;

        // Run first instance
        let (executor, runtime, auditor) = deterministic::Executor::seeded(seed);
        executor.start(async move {
            run_network(runtime, MAX_MESSAGE_SIZE, BASE_PORT, NUM_PEERS, mode).await;
        });
        let state = auditor.state();

        // Compare result to second instance
        let (executor, runtime, auditor) = deterministic::Executor::seeded(seed);
        executor.start(async move {
            run_network(runtime, MAX_MESSAGE_SIZE, BASE_PORT, NUM_PEERS, mode).await;
        });
        assert_eq!(state, auditor.state());
    }

    #[test_traced]
    fn test_determinism_one() {
        for i in 0..10 {
            run_deterministic_test(i, Mode::One);
        }
    }

    #[test_traced]
    fn test_determinism_some() {
        for i in 0..10 {
            run_deterministic_test(i, Mode::Some);
        }
    }

    #[test_traced]
    fn test_determinism_all() {
        for i in 0..10 {
            run_deterministic_test(i, Mode::All);
        }
    }

    #[test_traced]
    fn test_tokio_connectivity() {
        let cfg = tokio::Config::default();
        let (executor, runtime) = tokio::Executor::init(cfg.clone());
        executor.start(async move {
            const MAX_MESSAGE_SIZE: usize = 1_024 * 1_024; // 1MB
            let base_port = 3000;
            let n = 10;
            run_network(runtime, MAX_MESSAGE_SIZE, base_port, n, Mode::One).await;
        });
    }

    #[test_traced]
    fn test_multi_index_oracle() {
        // Configure test
        let base_port = 3000;
        let n: usize = 100;

        // Initialize runtime
        let (executor, runtime, _) = deterministic::Executor::default();
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
                    DEFAULT_MESSAGE_BACKLOG,
                    None,
                );

                // Wait to connect to all peers, and then send messages to everyone
                runtime.spawn("network", network.run());

                // Send/Receive messages
                let handler = runtime.spawn("agent", {
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

    fn test_message_too_large(compression: Option<i32>) {
        // Configure test
        let base_port = 3000;
        let n: usize = 2;

        // Initialize runtime
        let (executor, mut runtime, _) = deterministic::Executor::seeded(0);
        executor.start(async move {
            // Create peers
            let mut peers = Vec::new();
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
                DEFAULT_MESSAGE_BACKLOG,
                compression,
            );

            // Wait to connect to all peers, and then send messages to everyone
            runtime.spawn("network", network.run());

            // Crate random message
            let mut msg = vec![0u8; 10 * 1024 * 1024]; // 10MB (greater than frame capacity)
            runtime.fill(&mut msg[..]);

            // Send message
            let recipient = Recipients::One(addresses[1].clone());
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

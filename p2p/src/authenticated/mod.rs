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
//! * Automatic Peer Discovery Using Bit Vectors (Also Used as Ping Messages)
//! * Multiplexing With Configurable Rate Limiting Per Channel and Send Prioritization
//! * Optional Message Compression (using `zstd`)
//!
//! # Design
//!
//! ## Discovery
//!
//! Peer discovery operates under the assumption that all peers are aware of and synchronized on the
//! composition of peer sets at specific, user-provided indices (`u64`). Each index maps to a list
//! of authorized `PublicKey`s (`(u64, Vec<PublicKey>)`). Based on this shared knowledge, each peer
//! can construct a sorted bit vector ([`BitVec`](types::BitVec)) representing its knowledge of the
//! dialable addresses [`SocketAddr`](std::net::SocketAddr) for the peers in that set. A '1' at a
//! position in the bit vector signifies that the sending peer knows the address of the peer
//! corresponding to that position in the sorted list, while a '0' means it does not.
//!
//! _Warning: If peers are not synchronized on the peer set composition at a given index, discovery
//! messages can be misinterpreted. A peer might associate a bit vector index with the wrong peer or
//! fail to parse the vector if its length doesn't match the expected set size. The application
//! layer is responsible for ensuring peer set synchronization._
//!
//! Due to their small size, these `BitVec` messages are exchanged periodically
//! (configured by `gossip_bit_vec_frequency` in the [`Config`]) between connected peers. This
//! serves as both a peer discovery mechanism and a keep-alive "ping" message to maintain the
//! underlying connection, especially during periods of low application-level traffic. The protocol
//! supports tracking multiple peer sets concurrently (up to `tracked_peer_sets`), each identified
//! by its `index`. This is useful, for instance, during transitions like distributed key generation
//! (DKG) where connections to both old and new peer sets are needed simultaneously. The relevant
//! `index` is included in each `BitVec` message.
//!
//! Upon receiving a `BitVec` message, a peer compares it against its own knowledge for the same index.
//! If the receiving peer knows addresses that the sender marked as '0' (unknown), it selects a random
//! subset of these known [`PeerInfo`](types::PeerInfo) structures (up to `peer_gossip_max_count`)
//! and sends them back in a [`Peers`](types::Payload::Peers) message . Each `PeerInfo` contains the
//! peer's `SocketAddr`, `PublicKey`, a `timestamp`, and a `signature` over the socket and
//! timestamp, verifying the address claim. If the receiver doesn't know any addresses the sender is
//! unaware of, it sends no `Peers` response; the received `BitVec` implicitly acts as a "pong".
//!
//! If a peer receives a `PeerInfo` message (either directly or through gossip) containing a more
//! recent timestamp for a known peer's address, it updates its local record `Record`. This
//! updated `PeerInfo` is also used in future gossip messages. Each peer generates its own signed
//! `PeerInfo` upon startup and sends it immediately after establishing a connection (following the
//! cryptographic handshake). This ensures that if a peer connects using an outdated address record,
//! the record will be corrected promptly by the peer being dialed.
//!
//! To initiate the discovery process, a peer needs a list of `bootstrappers` - known peer public
//! keys and their corresponding socket addresses. The peer attempts to dial these bootstrappers,
//! performs the handshake, sends its own `PeerInfo`, and then sends a `BitVec` for the relevant
//! peer set(s) (initially only knowing its own address, marked as '1'). It then waits for
//! responses, learning about other peers through the `Peers` messages received. Bootstrapper
//! information is persisted, and connections to them are maintained even if they aren't part of any
//! currently tracked peer sets. Different peers can have different bootstrapper lists.
//!
//! _Note: If a peer (listener) receives a connection request from another peer (dialer) that
//! belongs to a registered peer set, the listener will accept the connection, even if the listener
//! itself hasn't yet learned about that specific peer set (or has an older version). The core
//! requirement is that the listener recognizes the *dialer's public key* as belonging to *some*
//! authorized set it tracks (`actors::tracker::Actor::allowed`). This mechanism allows peers with
//! more up-to-date peer set information to connect and propagate that information, enabling the
//! listener to potentially learn about newer sets it is part of._
//!
//! ## Messages
//!
//! Application-level data is exchanged using the [`Data`](types::Payload::Data) message type.
//! This type encapsulates arbitrary `Bytes` intended for a specific `channel` (a `u32` identifier).
//! The size of the `message` (after potential compression) must not exceed the configured
//! `max_message_size`. If it does, the sending operation will fail with [`Error::MessageTooLarge`].
//! Messages can be sent with `priority`, allowing certain communications to potentially bypass
//! lower-priority messages waiting in send queues across all channels. Each registered channel
//! handles its own message queuing, rate limiting, and optional `zstd` compression/decompression.
//!
//! # Example
//!
//! ```rust
//! use commonware_p2p::{authenticated::{self, Network}, Recipients};
//! use commonware_cryptography::{Ed25519, Signer, Verifier};
//! use commonware_runtime::{tokio::{self, Executor}, Spawner, Runner, Metrics};
//! use governor::Quota;
//! use std::net::{IpAddr, Ipv4Addr, SocketAddr};
//! use std::num::NonZeroU32;
//!
//! // Configure context
//! let runtime_cfg = tokio::Config::default();
//! let (executor, context) = Executor::init(runtime_cfg.clone());
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
//!     SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 3000),
//!     SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000), // Use a specific dialable addr
//!     bootstrappers,
//!     MAX_MESSAGE_SIZE,
//! );
//!
//! // Start context
//! executor.start(async move {
//!     // Initialize network
//!     let (mut network, mut oracle) = Network::new(context.with_label("network"), p2p_cfg);
//!
//!     // Register authorized peers
//!     //
//!     // In production, this would be updated as new peer sets are created (like when
//!     // the composition of a validator set changes).
//!     oracle.register(0, vec![signer.public_key(), peer1, peer2, peer3]).await;
//!
//!     // Register some channel
//!     const MAX_MESSAGE_BACKLOG: usize = 128;
//!     const COMPRESSION_LEVEL: Option<i32> = Some(3);
//!     let (mut sender, receiver) = network.register(
//!         0,
//!         Quota::per_second(NonZeroU32::new(1).unwrap()),
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
mod ip;
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
pub use config::{Bootstrapper, Config};
pub use network::Network;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Receiver, Recipients, Sender};
    use commonware_cryptography::{Ed25519, Signer};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic, tokio, Clock, Listener, Metrics, Network as RNetwork, Runner, Sink, Spawner,
        Stream,
    };
    use governor::{clock::ReasonablyRealtime, Quota};
    use rand::{CryptoRng, Rng};
    use std::collections::HashSet;
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        num::NonZeroU32,
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
        context: impl Spawner
            + Clock
            + ReasonablyRealtime
            + Rng
            + CryptoRng
            + RNetwork<L, Si, St>
            + Metrics,
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
            // Create peer context
            let context = context.with_label(&format!("peer-{}", i));

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
            let config = Config::test(
                signer.clone(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                bootstrappers,
                max_message_size,
            );
            let (mut network, mut oracle) = Network::new(context.with_label("network"), config);

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
            network.start();

            // Send/Receive messages
            let handler = context.with_label("agent").spawn({
                let addresses = addresses.clone();
                move |context| async move {
                    // Wait for all peers to send their identity
                    let acker = context
                        .clone()
                        .with_label("receiver")
                        .spawn(move |_| async move {
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
                                        .send(
                                            Recipients::One(recipient.clone()),
                                            msg.to_vec().into(),
                                            true,
                                        )
                                        .await
                                        .unwrap();
                                    if sent.len() != 1 {
                                        context.sleep(Duration::from_millis(100)).await;
                                        continue;
                                    }
                                    assert_eq!(&sent[0], recipient);
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
                                    .send(
                                        Recipients::Some(recipients.clone()),
                                        msg.to_vec().into(),
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
                                    .send(Recipients::All, msg.to_vec().into(), true)
                                    .await
                                    .unwrap();
                                if sent.len() != n - 1 {
                                    context.sleep(Duration::from_millis(100)).await;
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
        let (executor, context, auditor) = deterministic::Executor::seeded(seed);
        executor.start(async move {
            run_network(context, MAX_MESSAGE_SIZE, BASE_PORT, NUM_PEERS, mode).await;
        });
        let state = auditor.state();

        // Compare result to second instance
        let (executor, context, auditor) = deterministic::Executor::seeded(seed);
        executor.start(async move {
            run_network(context, MAX_MESSAGE_SIZE, BASE_PORT, NUM_PEERS, mode).await;
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
        let (executor, context) = tokio::Executor::init(cfg.clone());
        executor.start(async move {
            const MAX_MESSAGE_SIZE: usize = 1_024 * 1_024; // 1MB
            let base_port = 3000;
            let n = 10;
            run_network(context, MAX_MESSAGE_SIZE, base_port, n, Mode::One).await;
        });
    }

    #[test_traced]
    fn test_multi_index_oracle() {
        // Configure test
        let base_port = 3000;
        let n: usize = 100;

        // Initialize context
        let (executor, context, _) = deterministic::Executor::default();
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
                // Create peer context
                let context = context.with_label(&format!("peer-{}", i));

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
                let config = Config::test(
                    signer.clone(),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                    bootstrappers,
                    1_024 * 1_024, // 1MB
                );
                let (mut network, mut oracle) = Network::new(context.with_label("network"), config);

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
                network.start();

                // Send/Receive messages
                let handler = context
                    .with_label("agent")
                    .spawn(move |context| async move {
                        if i == 0 {
                            // Loop until success
                            let msg = signer.public_key();
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
        let (executor, mut context, _) = deterministic::Executor::seeded(0);
        executor.start(async move {
            // Create peers
            let mut peers = Vec::new();
            for i in 0..n {
                peers.push(Ed25519::from_seed(i as u64));
            }
            let addresses = peers.iter().map(|p| p.public_key()).collect::<Vec<_>>();

            // Create network
            let signer = peers[0].clone();
            let config = Config::test(
                signer.clone(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port),
                Vec::new(),
                1_024 * 1_024, // 1MB
            );
            let (mut network, mut oracle) = Network::new(context.with_label("network"), config);

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
            network.start();

            // Crate random message
            let mut msg = vec![0u8; 10 * 1024 * 1024]; // 10MB (greater than frame capacity)
            context.fill(&mut msg[..]);

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

//! Communicate with a fixed set of authenticated peers over encrypted connections.
//!
//! `authenticated` provides encrypted, multiplexed communication between fully-connected peers
//! identified by a developer-specified cryptographic identity (i.e. BLS, ed25519, etc.). Unlike
//! most p2p crates, `authenticated` implements its own encrypted transport layer (no TLS) that
//! exclusively uses said cryptographic identities to authenticate incoming connections (dropping
//! any that aren't explicitly authorized). Peer discovery occurs automatically using ordered bit
//! vectors (sorted by authorized cryptographic identities) to efficiently communicate knowledge
//! of dialable peers.
//!
//! # Features
//!
//! * Simple Handshakes (No TLS, No X.509 Certificates, No Protocol Negotiation)
//! * ChaCha20-Poly1305 Stream Encryption
//! * Configurable Cryptography Scheme for Peer Identities (BLS, ed25519, etc.)
//! * Automatic Peer Discovery Using Bit Vectors (Used as Ping/Pongs)
//! * Multiplexing With Configurable Rate Limiting Per Channel and Send Prioritization
//! * Optional Message Compression (using `zstd`)
//! * Emebdded Message Chunking
//!
//! # Design
//!
//! ## Handshake
//!
//! When establishing a connection with a peer, a simple handshake is performed between
//! peers to authenticate each other and to establish a shared secret for connection encryption (explained below).
//! This simple handshake is done in lieu of using TLS, Noise, WireGuard, etc. because it supports
//! the usage of arbitrary cryptographic schemes, there is no protocol negotation (only one way to connect),
//! because it only takes a few hundred lines of code to implement (not having any features is a feature
//! in safety-critical code), and because it can be simulated deterministically.
//!
//! In any handshake, the dialer is the party that attempts to connect to some known address/identity (public key)
//! and the recipient of this connection is the dialee. Upon forming a TCP connection, the dialer sends a signed
//! handshake message to the dialee.
//!
//! ```protobuf
//! message Handshake {
//!     bytes recipient_public_key = 1;
//!     bytes ephemeral_public_key = 2;
//!     uint64 timestamp = 3;
//!     Signature signature = 4;
//! }
//! ```
//!
//! The dialee verifies the public keys are well-formatted, the timestamp is valid (not too old/not too far in the future),
//! and that the signature is valid. If all these checks pass, the dialee checks to see if it is already connected or dialing
//! this peer. If it is, it drops the connection. If it isn't, it sends back its own signed handshake message (same as above)
//! and considers the connection established.
//!
//! Upon receiving the dialee's handshake message, the dialer verifies the same data as the dialee and additionally verifies
//! that the public key returned matches what they expected at the address. If all these checks pass, the dialer considers the
//! connection established. If not, the dialer drops the connection.
//!
//! To better protect against malicious peers that create and/or accept connections but do not participate in handshakes,
//! a configurable deadline is enforced for any handshake to be completed. This allows for the underlying runtime to maintain
//! a standard read/write timeout for connections without making it easier for malicious peers to keep useless connections open.
//!
//! ## Encryption
//!
//! During the handshake (described above), a shared x25519 secret is established using a Diffie-Hellman Key Exchange. This
//! x25519 secret is then used to create a ChaCha20-Poly1305 cipher for encrypting all messages exchanged between
//! any two peers (including peer discovery messages).
//!
//! ChaCha20-Poly1305 nonces (12 bytes) are constructed such that the first bit indicates whether the sender is a dialer (1) or
//! dialee (0). The rest of the first byte (next 7 bits) and next byte (all 8 bits) are unused (set to 0). The next 2 bytes
//! are a `u16` iterator and the final 8 bytes are a `u64` sequence number. When the sequence reaches `u64::MAX`, the iterator
//! is incremented and the sequence is reset to 0. This technique provides each sender with a channel duration of `2^80` frames
//! (and automatically terminates when this number of frames has been sent). In the blockchain context, validators often maintain
//! long-lived connections with each other and avoiding connection re-establishment (to reset iterator/sequence with a new cipher)
//! is desirable.
//!
//! ```text
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |10 |11 |
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! | D | U |It(u16)|         Sequence(u64)         |
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//!
//! D = Dialer/Dialee, U = Unused, It = Iterator
//! ```
//!
//! _We use a combination of `u64` (sequence) and `u16` (iterator) instead of implementing `u80/u88` because
//! CPUs provide native support for `u64` operations (which will always be faster than an implementation of a
//! "wrapping add" over arbitrary bytes). With this technique, almost all operations (other than iterator
//! increments every `2^64` frames) are just a basic `u64` increment._
//!
//! This simple coordination prevents nonce reuse (which would allow for messages to be decrypted) and saves a small amount of
//! bandwidth (no need to send the nonce alongside the encrypted message). This "pedantic" construction of the nonce
//! also avoids accidentally reusing a nonce over long-lived connections when setting it to be a small hash (as in XChaCha-Poly1305).
//!
//! ## Discovery
//!
//! Peer discovery relies heavily on the assumption that all peers are known at each index (a user-provided tuple of
//! `(u64, Vec<PublicKey>)`). Using this assumption, we can construct a sorted bit vector that represents our knowledge
//! of peer IPs (where 1 == we know, 0 == we don't know). This means we can represent our knowledge of 1000 peers in only 125 bytes!
//!
//! Because this representation is so efficient/small, peers send bit vectors to each other periodically as a "ping" to keep
//! the connection alive. Because it may be useful to be connected to multiple indexes of peers at a given time (i.e. to perform a DKG
//! with a new set of peers), it is possible to configure this crate to maintain connections to multiple indexes (and pings are a
//! random index we are trying to connect to).
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
//! bootstrapping peers is (this list is configurable).
//!
//! ## Chunking
//!
//! To support arbitarily large messages (while maintaing a small frame size), this crate automatically chunks messages
//! that exceed the frame size (the frame size is configurable). A connection will be blocked until all chunks of a given
//! message are sent. It is possible for a sender to prioritize messages over others but not to be interleaved with an
//! ongoing multi-chunk message.
//!
//! ```protobuf
//! message Chunk {
//!     uint32 channel = 1;
//!     uint32 part = 2;
//!     uint32 total_parts = 3;
//!     bytes content = 4;
//! }  
//! ```
//!
//! To minimize the number of chunks sent and to ensure each chunk is full (otherwise someone could send us a million chunks
//! each 1 byte), content is compressed (if enabled) before chunking rather than after. As a result, the configuration
//! chosen for frame size has no impact on compression efficiency.
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
//! // Configure network
//! //
//! // In production, use a more conservative configuration like `Config::recommended`.
//! let registry = Arc::new(Mutex::new(Registry::with_prefix("p2p")));
//! let p2p_cfg = authenticated::Config::aggressive(
//!     signer.clone(),
//!     registry,
//!     SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000),
//!     bootstrappers,
//!     runtime_cfg.max_message_size,
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
//!     let (sender, receiver) = network.register(
//!         0,
//!         Quota::per_second(NonZeroU32::new(1).unwrap()),
//!         1024, // max message size
//!         128, // max backlog
//!         Some(3), // compression level
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
                Quota::per_second(NonZeroU32::new(5).unwrap()), // Ensure we hit the rate limit
                1_024,
                128,
                None,
            );

            // Wait to connect to all peers, and then send messages to everyone
            runtime.spawn("network", network.run());

            // Send/Recieve messages
            let handler = runtime.spawn("agent", {
                let addresses = addresses.clone();
                let runtime = runtime.clone_with_prefix("agent");
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
        let max_message_size = 1_024 * 1_024; // 1MB
        let n = 25;
        let base_port = 3000;

        // Run first instance
        let cfg = deterministic::Config {
            seed,
            ..deterministic::Config::default()
        };
        let (executor, runtime, auditor) = deterministic::Executor::init(cfg);
        executor.start(async move {
            run_network(runtime, max_message_size, base_port, n, mode).await;
        });
        let state = auditor.state();

        // Compare result to second instance
        let cfg = deterministic::Config {
            seed,
            ..deterministic::Config::default()
        };
        let (executor, runtime, auditor) = deterministic::Executor::init(cfg);
        executor.start(async move {
            run_network(runtime, max_message_size, base_port, n, mode).await;
        });
        assert_eq!(state, auditor.state());
    }

    #[test]
    fn test_determinism_one() {
        for i in 0..10 {
            run_deterministic_test(i, Mode::One);
        }
    }

    #[test]
    fn test_determinism_some() {
        for i in 0..10 {
            run_deterministic_test(i, Mode::Some);
        }
    }

    #[test]
    fn test_determinism_all() {
        for i in 0..10 {
            run_deterministic_test(i, Mode::All);
        }
    }

    #[test]
    fn test_tokio_connectivity() {
        let cfg = tokio::Config::default();
        let (executor, runtime) = tokio::Executor::init(cfg.clone());
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
        let cfg = deterministic::Config::default();
        let (executor, runtime, _) = deterministic::Executor::init(cfg);
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
                runtime.spawn("network", network.run());

                // Send/Recieve messages
                let handler = runtime.spawn("agent", {
                    let runtime = runtime.clone_with_prefix("agent");
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
        let cfg = deterministic::Config::default();
        let (executor, mut runtime, _) = deterministic::Executor::init(cfg);
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
                    bootstrappers,
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
                runtime.spawn("network", network.run());

                // Send/Recieve messages
                let msg = Bytes::from(msg.clone());
                let msg_sender = addresses[0].clone();
                let msg_recipient = addresses[1].clone();
                let peer_handler = runtime.spawn("agent", {
                    let runtime = runtime.clone_with_prefix("agent");
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
        let cfg = deterministic::Config::default();
        let (executor, mut runtime, _) = deterministic::Executor::init(cfg);
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
                1_024 * 1_024, // 1MB
                128,
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

    #[test]
    fn test_message_too_large_no_compression() {
        test_message_too_large(None);
    }

    #[test]
    fn test_message_too_large_compression() {
        test_message_too_large(Some(3));
    }
}

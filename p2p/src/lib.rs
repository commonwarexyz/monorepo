//! Communicate with authenticated peers over encrypted connections.
//!
//! commonware-p2p provides encrypted, multiplexed communication between fully-connected peers
//! identified by a developer-specified cryptographic identity (i.e. BLS, ed25519, etc.). Unlike
//! most p2p crates, commonware-p2p implements its own encrypted transport layer (no TLS) that
//! exclusively uses said cryptographic identities to authenticate incoming connections (dropping
//! any that aren't explicitly authorized). Peer discovery occurs automatically using ordered bit
//! vectors (sorted by authorized cryptographic identities) to efficiently communicate knowledge
//! of dialable peers.
//!
//! # Status
//!
//! `commonware-p2p` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.
//!
//! # Features
//!
//! * No TLS, No X.509 Certificates, No Protocol Negotiation
//! * ChaCha20-Poly1305 Stream Encryption
//! * Arbitrary Cryptographic Peer Identities
//! * Automatic Peer Discovery Using Bit Vectors (Used as Ping/Pongs)
//! * Multiplexing With Configurable Rate Limiting Per Channel and Send Prioritization
//! * Emebdded Message Chunking
//! * Metrics via Prometheus
//!
//! # TODO
//!
//! ## Handshake
//!
//! When establishing a connection with a peer, a simple handshake is performed between
//! peers to authenticate each other and to establish a shared secret for connection encryption.
//! This is done in lieu of using TLS, Noise, WireGuard, etc. because it supports the usage of
//! arbitrary cryptographic schemes, there is no protocol negotation (only one way to connect), and
//! because it takes a few hundred lines of code to implement (not having any features is a feature).
//!
//! The dialer starts this process by sending a message that contains `{recipient_public_key,
//! ephemeral_public_key, timestamp, signature}.`
//!
//! ## Encryption
//!
//! ## Discovery
//!
//! # Example
//!
//! ```rust
//! use commonware_p2p::{Config, Network};
//! use commonware_cryptography::{ed25519, Scheme};
//! use governor::Quota;
//! use prometheus_client::registry::Registry;
//! use std::net::{IpAddr, Ipv4Addr, SocketAddr};
//! use std::num::NonZeroU32;
//! use std::sync::{Arc, Mutex};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Generate identity
//!     //
//!     // In production, the signer should be generated from a secure source of entropy.
//!     let signer = ed25519::insecure_signer(0);
//!
//!     // Generate peers
//!     //
//!     // In production, peer identities will be provided by some external source of truth
//!     // (like the staking set of a blockchain).
//!     let peer1 = ed25519::insecure_signer(1).me();
//!     let peer2 = ed25519::insecure_signer(2).me();
//!     let peer3 = ed25519::insecure_signer(3).me();
//!
//!     // Configure bootstrappers
//!     //
//!     // In production, it is likely that the address of bootstrappers will be some public address.
//!     let bootstrappers = vec![(peer1.clone(), SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3001))];
//!
//!     // Configure network
//!     //
//!     // In production, use a more conservative configuration like `Config::recommended`.
//!     let registry = Arc::new(Mutex::new(Registry::with_prefix("p2p")));
//!     let config = Config::aggressive(
//!         signer.clone(),
//!         registry,
//!         SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000),
//!         bootstrappers,
//!     );
//!     let (mut network, oracle) = Network::new(config);
//!
//!     // Register authorized peers
//!     //
//!     // In production, this would be updated as new peer sets are created (like when
//!     // the composition of a validator set changes).
//!     oracle.register(0, vec![signer.me(), peer1, peer2, peer3]);
//!
//!     // Register some channel
//!     let (sender, receiver) = network.register(0, Quota::per_second(NonZeroU32::new(1).unwrap()), 1024, 128);
//!
//!     // Run network
//!     let network_handler = tokio::spawn(network.run());
//!
//!     // ... Use sender and receiver ...
//!
//!     // Shutdown network
//!     network_handler.abort();
//! }
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

pub use actors::tracker::Oracle;
pub use channels::{Message, Receiver, Sender};
pub use config::{Bootstrapper, Config};
pub use network::Network;

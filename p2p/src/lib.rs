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
//! ### Step 0: Dialer Opens Connection and Sends Handshake
//!
//! The dialer starts the handshake by sending the following message:
//! ```protobuf
//! syntax = "proto3";
//!
//! message Handshake {
//!     bytes recipient_public_key = 1;
//!     bytes ephemeral_public_key = 2;
//!     uint64 timestamp = 3;
//!     Signature signature = 4;
//! }
//! ```
//!
//! The timestamp....
//!
//! // TODO: prevent signatures in the future (both handshake and peer discovery) -> change to max_age_drift
//!
//! ### Step 1: Dialee Verified Handshake and Sends Response
//!
//! The dialee verifies the handshake and sends back its own version of the same message:
//! ```protobuf
//! syntax = "proto3";
//!
//! message Handshake {
//!     bytes recipient_public_key = 1;
//!     bytes ephemeral_public_key = 2;
//!     uint64 timestamp = 3;
//!     Signature signature = 4;
//! }
//! ```
//!
//! At this point, the dialee considers the connection established.
//!
//! ### Step 3: Dialer Verifies Response
//!
//! The dialer verifies the response and considers the connection established.
//!
//! ## Encryption
//!
//! During the handshake, a shared x25519 secret is established between the peers using a Diffie-Hellman Key Exchange.
//!
//! This x25519 secret is then used to create a ChaCha20-Poly1305 cipher for encrypting all messages exchanged between
//! any two peers (including peer discovery messages)
//!
//! Nonces (12 bytes) are orchestrated such that each message sent by the dialer sets the first bit of the first byte and
//! then sets the last 8 bytes (of the 12) with a counter (in big-endian u64) of the messages sent. The dialee uses a similar strategy byt does not set the
//! first bit of the first byte. This simple coordination prevents nonce reuse (which would allow for messages
//! to be decrypted), avoids sending the nonce alongside the message (saves bandwidth), and avoids the use of a small hash
//! as a nonce (common in XChaCha-Poly1305), which may accidentally be reused when sending many messages over a long-lived connection (which is common in blockchain applications).
//!
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |10 |11 |
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! | F |  Unused   |     Sequence Number (u64)     |
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//!
//! ## Discovery
//!
//! ### Step X: Send Signed IP
//!
//! After establishing a connection, a peer will send a signed message that
//! indicates how to dial to it (using IP:Port):
//! ```protobuf
//! syntax = "proto3";
//!
//! message Peer {
//!     bytes socket = 1;
//!     uint64 timestamp = 2;
//!     Signature signature = 3;
//! }
//! ```
//!
//! ```protobuf
//! syntax = "proto3";
//!
//! message BitVec {
//!     uint64 index = 1;
//!     bytes bits = 2;
//! }
//! ```
//!
//! ```protobuf
//! syntax = "proto3";
//!
//! message Peers {
//!     repeated Peer peers = 1;
//! }
//! ```
//!
//! If a peer receives a signed message that is newer than the last message it received,
//! it will update its knowledge of the peer. Unlike handshakes, these update messages
//! do not have a recency requirement.
//!
//! ## Message Chunking
//!
//! ```protobuf
//! syntax = "proto3";
//!
//! message Chunk {
//!     uint32 channel = 1;
//!     uint32 part = 2;
//!     uint32 total_parts = 3;
//!     bytes content = 4;
//! }  
//! ```
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

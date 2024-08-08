//! Fully-connected ...
//!
//! TODO: Add more documentation here
//!
//! ```rust
//! use chat::{
//!     crypto::{Crypto, ed25519},
//!     Config, Network,
//! };
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
//!     // In production use, the signer should be generated from a secure source of entropy.
//!     let signer = ed25519::insecure_signer(0);
//!
//!     // Generate peers
//!     //
//!     // In production use, peer identities will be provided by some external source of truth
//!     // (like the staking set of a blockchain).
//!     let peer1 = ed25519::insecure_signer(1).me();
//!     let peer2 = ed25519::insecure_signer(2).me();
//!     let peer3 = ed25519::insecure_signer(3).me();
//!
//!     // Configure bootstrappers
//!     //
//!     // In production use, it is likely that the address of bootstrappers will be some public address.
//!     let bootstrappers = vec![(peer1.clone(), SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3001))];
//!
//!     // Configure network
//!     //
//!     // In production use, it is not recommended to allow private IPs.
//!     let registry = Arc::new(Mutex::new(Registry::with_prefix("p2p")));
//!     let config = Config::default(
//!         signer.clone(),
//!         registry,
//!         SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000),
//!         bootstrappers,
//!         true,
//!     );
//!     let (mut network, oracle) = Network::new(config);
//!
//!     // Register authorized peers
//!     //
//!     // In production use, this would be updated as new peer sets are created (like when
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

pub mod crypto;
pub use actors::tracker::Oracle;
pub use channels::{Message, Receiver, Sender};
pub use config::{Bootstrapper, Config};
pub use network::Network;

mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

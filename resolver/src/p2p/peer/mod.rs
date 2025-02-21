//! TODO

pub mod actor;
mod config;
pub mod ingress;

/// Type of data resolved by the p2p network.
/// This is a blob of bytes that is opaque to the resolver.
pub type Value = Vec<u8>;

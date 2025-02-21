//! Makes and responds to requests using the P2P network.

#[cfg(test)]
pub mod mocks;

pub mod peer;
mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

/// Type of data resolved by the p2p network.
/// This is a blob of bytes that is opaque to the resolver.
pub type Value = Vec<u8>;

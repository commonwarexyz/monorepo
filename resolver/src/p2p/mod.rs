//! Makes and responds to requests using the P2P network.

#[cfg(test)]
pub mod mocks;

pub mod peer;
mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

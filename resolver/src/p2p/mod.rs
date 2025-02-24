//! Makes and responds to requests using the P2P network.

use std::future::Future;

use commonware_utils::Array;
use futures::channel::oneshot;

#[cfg(test)]
pub mod mocks;

pub mod peer;
mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

/// Type of data resolved by the p2p network.
/// This is a blob of bytes that is opaque to the resolver.
pub type Value = Vec<u8>;

/// The interface responsible for serving data requested by the network.
pub trait Producer: Clone + Send + 'static {
    /// Type used to uniquely identify data.
    type Key: Array;

    /// Type of data returned by the producer.
    type Value;

    /// Serve a request received from the network.
    fn produce(
        &mut self,
        key: Self::Key,
    ) -> impl Future<Output = oneshot::Receiver<Self::Value>> + Send;
}

/// The interface responsible for managing the list of peers that can be used to fetch data.
pub trait Director: Clone + Send + 'static {
    /// Type used to uniquely identify peers.
    type PublicKey: Array;

    /// Returns the current list of peers that can be used to fetch data.
    ///
    /// This is also used to filter requests from peers.
    fn peers(&self) -> &Vec<Self::PublicKey>;

    /// Returns true if the given public key is a peer.
    fn is_peer(&self, public_key: &Self::PublicKey) -> bool;
}

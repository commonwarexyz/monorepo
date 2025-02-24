//! Makes and responds to requests using the P2P network.

use bytes::Bytes;
use commonware_utils::Array;
use futures::channel::oneshot;
use std::future::Future;

#[cfg(test)]
pub mod mocks;

pub mod peer;
mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

/// The interface responsible for serving data requested by the network.
pub trait Producer: Clone + Send + 'static {
    /// Type used to uniquely identify data.
    type Key: Array;

    /// Serve a request received from the network.
    fn produce(&mut self, key: Self::Key) -> impl Future<Output = oneshot::Receiver<Bytes>> + Send;
}

/// The interface responsible for managing the list of peers that can be used to fetch data.
pub trait Director: Clone + Send + 'static {
    /// Type used to uniquely identify peers.
    type PublicKey: Array;

    /// Returns the current list of peers that can be used to fetch data.
    ///
    /// This is also used to filter requests from peers.
    fn peers(&self) -> &Vec<Self::PublicKey>;

    /// Returns an identifier for the peer set.
    ///
    /// Used as a low-overhead way to check if the list of peers has changed,
    /// this value should increment whenever the list of peers changes.
    fn peer_set_id(&self) -> u64;

    /// Returns true if the given public key is a peer.
    fn is_peer(&self, public_key: &Self::PublicKey) -> bool;
}

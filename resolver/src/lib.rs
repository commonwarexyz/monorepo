//! TODO

use commonware_cryptography::Array;
use futures::channel::oneshot;
use std::future::Future;

pub mod p2p;

/// The interface that gets notified when data is available.
pub trait Consumer: Clone + Send + 'static {
    /// Type used to uniquely identify data.
    type Key: Array;

    /// Type of data to retrieve.
    type Value;

    /// Type used to indicate why data is not available.
    type FailureCode;

    /// Deliver data to the consumer.
    fn deliver(&mut self, key: Self::Key, value: Self::Value) -> impl Future<Output = ()> + Send;

    /// Let the consumer know that the data is not available.
    fn failed(
        &mut self,
        key: Self::Key,
        reason: Self::FailureCode,
    ) -> impl Future<Output = ()> + Send;
}

/// The interface responsible for fetching data from the network.
pub trait Resolver: Clone + Send + 'static {
    /// Type used to uniquely identify data.
    type Key: Array;

    /// Fetch data from the network.
    fn fetch(&mut self, key: Self::Key) -> impl Future<Output = ()> + Send;

    /// Cancel a fetch request.
    fn cancel(&mut self, key: Self::Key) -> impl Future<Output = ()> + Send;
}

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
    fn peers(&self) -> Vec<Self::PublicKey>;

    /// Returns true if the given public key is a peer.
    fn is_peer(&self, public_key: &Self::PublicKey) -> bool;
}

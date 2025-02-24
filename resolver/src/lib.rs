//! TODO

use commonware_cryptography::Array;
use std::future::Future;

pub mod p2p;

/// The interface that gets notified when data is available.
pub trait Consumer: Clone + Send + 'static {
    /// Type used to uniquely identify data.
    type Key: Array;

    /// Type of data to retrieve.
    type Value;

    /// Type used to indicate why data is not available.
    type Failure;

    /// Deliver data to the consumer.
    fn deliver(&mut self, key: Self::Key, value: Self::Value) -> impl Future<Output = ()> + Send;

    /// Let the consumer know that the data is not available.
    fn failed(&mut self, key: Self::Key, failure: Self::Failure)
        -> impl Future<Output = ()> + Send;
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

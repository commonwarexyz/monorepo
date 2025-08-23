//! Resolve data identified by a fixed-length key.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use commonware_utils::Span;
use std::future::Future;

pub mod p2p;

/// Notified when data is available, and must validate it.
pub trait Consumer: Clone + Send + 'static {
    /// Type used to uniquely identify data.
    type Key: Span;

    /// Type of data to retrieve.
    type Value;

    /// Type used to indicate why data is not available.
    type Failure;

    /// Deliver data to the consumer.
    ///
    /// Returns `true` if the data is valid.
    fn deliver(&mut self, key: Self::Key, value: Self::Value) -> impl Future<Output = bool> + Send;

    /// Let the consumer know that the data is not being fetched anymore.
    ///
    /// The failure is used to indicate why.
    fn failed(&mut self, key: Self::Key, failure: Self::Failure)
        -> impl Future<Output = ()> + Send;
}

/// Responsible for fetching data and notifying a `Consumer`.
pub trait Resolver: Clone + Send + 'static {
    /// Type used to uniquely identify data.
    type Key: Span;

    /// Initiate a fetch request.
    fn fetch(&mut self, key: Self::Key) -> impl Future<Output = ()> + Send;

    /// Cancel a fetch request.
    fn cancel(&mut self, key: Self::Key) -> impl Future<Output = ()> + Send;

    /// Cancel all fetch requests.
    fn clear(&mut self) -> impl Future<Output = ()> + Send;

    /// Retain only the fetch requests that satisfy the predicate.
    fn retain(
        &mut self,
        predicate: impl Fn(&Self::Key) -> bool + Send + 'static,
    ) -> impl Future<Output = ()> + Send;
}

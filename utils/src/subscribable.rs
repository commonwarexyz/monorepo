//! A trait for subscribing to values by key.

use crate::Span;
use futures::channel::oneshot;
use std::future::Future;

/// Interface for subscribing to values by key.
///
/// Implementations allow getting values that may or may not be available yet,
/// and subscribing to receive values when they become available.
pub trait Subscribable: Clone + Send + 'static {
    /// The key type used to look up values.
    type Key: Span;

    /// The type of value that can be retrieved.
    type Value: Clone + Send + 'static;

    /// Get a value by key, if available.
    fn get(&mut self, key: Self::Key) -> impl Future<Output = Option<Self::Value>> + Send;

    /// Subscribe to receive a value by key.
    ///
    /// The receiver will be sent the value when available; either
    /// instantly (if already present) or when it arrives.
    fn subscribe(
        &mut self,
        key: Self::Key,
    ) -> impl Future<Output = oneshot::Receiver<Self::Value>> + Send;
}

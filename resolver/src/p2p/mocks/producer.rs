use crate::Span;
use bytes::Bytes;
use futures::channel::oneshot;
use std::collections::HashMap;

/// A producer that can be used for testing
#[derive(Clone, Default)]
pub struct Producer<K: Span, V> {
    /// The data that the producer produces upon request
    data: HashMap<K, V>,
}

impl<K: Span, V> Producer<K, V> {
    /// Adds a key-value pair to the producer
    pub fn insert(&mut self, key: K, value: V) {
        self.data.insert(key, value);
    }
}

impl<K: Span, V: Into<Bytes> + Clone + Send + 'static> crate::p2p::Producer for Producer<K, V> {
    type Key = K;

    /// Produce a value for the given key.
    ///
    /// If the key is not found, the returned receiver will resolve with an error since the sender
    /// is dropped.
    async fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (sender, receiver) = oneshot::channel();
        if let Some(value) = self.data.get(&key) {
            let _ = sender.send(value.clone().into());
        }
        receiver
    }
}

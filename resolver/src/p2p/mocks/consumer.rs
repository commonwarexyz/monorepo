use crate::Array;
use futures::channel::mpsc;
use futures::SinkExt;
use std::collections::HashMap;

pub enum Event<K, V> {
    Success(K, V),
    Failed(K),
}

/// A consumer that can be used for testing
#[derive(Clone)]
pub struct Consumer<K: Array, V> {
    /// The sender to send events to
    sender: mpsc::Sender<Event<K, V>>,

    /// The expected values for each key
    ///
    /// If there is no expected value for a key, it will be considered valid
    expected: HashMap<K, V>,
}

impl<K: Array, V: Clone + PartialEq> Consumer<K, V> {
    /// Create a new consumer
    pub fn new(sender: mpsc::Sender<Event<K, V>>) -> Self {
        Self {
            sender,
            expected: HashMap::new(),
        }
    }

    /// Create a dummy consumer that is not expected to be used
    pub fn dummy() -> Self {
        let (sender, _) = mpsc::channel(0);
        Self {
            sender,
            expected: HashMap::new(),
        }
    }

    /// Add an expected value for a key
    pub fn add_expected(&mut self, k: K, v: V) {
        self.expected.insert(k, v);
    }

    /// Remove the expected value for a key
    pub fn pop_expected(&mut self, k: &K) -> Option<V> {
        self.expected.remove(k)
    }
}

impl<K: Array, V: Clone + PartialEq + Send + 'static> crate::Consumer for Consumer<K, V> {
    type Key = K;
    type Value = V;
    type Failure = ();

    /// Deliver data to the consumer.
    ///
    /// Returns `true` if the value is expected for the key or if there is no expected value.
    async fn deliver(&mut self, key: Self::Key, value: Self::Value) -> bool {
        let valid = self.expected.get(&key).map_or(true, |v| v == &value);
        if valid {
            let _ = self.sender.send(Event::Success(key, value)).await;
        }
        valid
    }

    /// Let the consumer know that the data is not being fetched anymore.
    async fn failed(&mut self, key: Self::Key, _failure: ()) {
        let _ = self.sender.send(Event::Failed(key)).await;
    }
}

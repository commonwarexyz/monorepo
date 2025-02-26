use crate::Array;
use futures::channel::mpsc;
use futures::SinkExt;
use std::collections::HashMap;

/// An event that indicates the messages that were sent to the consumer
#[derive(Debug)]
pub enum Event<K, V> {
    /// The consumer received a value for a key and considered it valid
    Success(K, V),

    /// The consumer failed to fetch a value for a key
    Failed(K),
}

/// A consumer that can be used for testing
#[derive(Clone)]
pub struct Consumer<K: Array, V> {
    /// The sender to send events to
    sender: mpsc::UnboundedSender<Event<K, V>>,

    /// The expected values for each key
    ///
    /// If there is no expected value for a key, it will be considered valid
    expected: HashMap<K, V>,
}

impl<K: Array, V: Clone + PartialEq> Consumer<K, V> {
    /// Create a new consumer
    ///
    /// Returns the consumer and a receiver that can be used to get the events
    pub fn new() -> (Self, mpsc::UnboundedReceiver<Event<K, V>>) {
        let (sender, receiver) = mpsc::unbounded();
        (
            Self {
                sender,
                expected: HashMap::new(),
            },
            receiver,
        )
    }

    /// Create a dummy consumer that is not expected to be used
    pub fn dummy() -> Self {
        let (sender, _) = mpsc::unbounded();
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
        let valid = self.expected.get(&key).is_none_or(|v| v == &value);
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

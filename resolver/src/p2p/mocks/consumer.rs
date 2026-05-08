use crate::{Dependencies, Span};
use commonware_utils::channel::{fallible::FallibleExt, mpsc};
use std::collections::HashMap;

/// A consumer that can be used for testing
#[derive(Clone)]
pub struct Consumer<K: Span, V> {
    /// The sender to send delivered (key, value) pairs to
    sender: mpsc::UnboundedSender<(K, V)>,

    /// The expected values for each key
    ///
    /// If there is no expected value for a key, it will be considered valid
    expected: HashMap<K, V>,
}

impl<K: Span, V: Clone + PartialEq> Consumer<K, V> {
    /// Create a new consumer
    ///
    /// Returns the consumer and a receiver that can be used to get delivered (key, value) pairs
    pub fn new() -> (Self, mpsc::UnboundedReceiver<(K, V)>) {
        let (sender, receiver) = mpsc::unbounded_channel();
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
        let (sender, _) = mpsc::unbounded_channel();
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

impl<K: Span, V: Clone + PartialEq + Send + 'static> crate::Consumer for Consumer<K, V> {
    type Key = K;
    type Dependency = K;
    type Value = V;

    /// Deliver data to the consumer.
    ///
    /// Returns `true` if the value is expected for the key or if there is no expected value.
    async fn deliver(
        &mut self,
        dependencies: Dependencies<Self::Key, Self::Dependency>,
        value: Self::Value,
    ) -> bool {
        let key = dependencies.request;
        let valid = self.expected.get(&key).is_none_or(|v| v == &value);
        if valid {
            self.sender.send_lossy((key, value));
        }
        valid
    }
}

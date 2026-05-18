use crate::{Delivery, Span};
use commonware_utils::channel::{fallible::FallibleExt, mpsc, oneshot};
use std::{collections::HashMap, marker::PhantomData};

/// A consumer that can be used for testing
#[derive(Clone)]
pub struct Consumer<R: Span, V, S = ()> {
    /// The sender to send delivered (key, value) pairs to
    sender: mpsc::UnboundedSender<(R, V)>,

    /// The expected values for each key
    ///
    /// If there is no expected value for a key, it will be considered valid
    expected: HashMap<R, V>,
    _subscriber: PhantomData<S>,
}

impl<R: Span, V: Clone + PartialEq, S> Consumer<R, V, S> {
    /// Create a new consumer
    ///
    /// Returns the consumer and a receiver that can be used to get delivered (key, value) pairs
    pub fn new() -> (Self, mpsc::UnboundedReceiver<(R, V)>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (
            Self {
                sender,
                expected: HashMap::new(),
                _subscriber: PhantomData,
            },
            receiver,
        )
    }

    /// Add an expected value for a key
    pub fn add_expected(&mut self, k: R, v: V) {
        self.expected.insert(k, v);
    }

    /// Remove the expected value for a key
    pub fn pop_expected(&mut self, k: &R) -> Option<V> {
        self.expected.remove(k)
    }
}

impl<R: Span, V: Clone + PartialEq> Consumer<R, V, ()> {
    /// Create a dummy consumer that is not expected to be used
    pub fn dummy() -> Self {
        let (sender, _) = mpsc::unbounded_channel();
        Self {
            sender,
            expected: HashMap::new(),
            _subscriber: PhantomData,
        }
    }
}

impl<R, V, S> crate::Consumer for Consumer<R, V, S>
where
    R: Span,
    V: Clone + PartialEq + Send + 'static,
    S: Clone + Eq + Send + 'static,
{
    type Request = R;
    type Subscriber = S;
    type Value = V;

    /// Deliver data to the consumer.
    ///
    /// Returns `true` if the value is expected for the key or if there is no expected value.
    fn deliver(
        &mut self,
        delivery: Delivery<Self::Request, Self::Subscriber>,
        value: Self::Value,
    ) -> oneshot::Receiver<bool> {
        let request = delivery.request;
        let (sender, receiver) = oneshot::channel();
        let valid = self.expected.get(&request).is_none_or(|v| v == &value);
        if valid {
            self.sender.send_lossy((request, value));
        }
        let _ = sender.send(valid);
        receiver
    }
}

use crate::Resolver;
use commonware_utils::Span;
use futures::{channel::mpsc, SinkExt};

type Predicate<K> = Box<dyn Fn(&K) -> bool + Send>;

/// Messages that can be sent to the peer actor.
pub enum Message<K> {
    /// Initiate a fetch request by key.
    Fetch { key: K },

    /// Cancel a fetch request by key.
    Cancel { key: K },

    /// Cancel all fetch requests.
    Clear,

    /// Cancel all fetch requests that do not satisfy the predicate.
    Retain { predicate: Predicate<K> },
}

/// A way to send messages to the peer actor.
#[derive(Clone)]
pub struct Mailbox<K> {
    /// The channel that delivers messages to the peer actor.
    sender: mpsc::Sender<Message<K>>,
}

impl<K> Mailbox<K> {
    /// Create a new mailbox.
    pub(super) fn new(sender: mpsc::Sender<Message<K>>) -> Self {
        Self { sender }
    }
}

impl<K: Span> Resolver for Mailbox<K> {
    type Key = K;

    /// Send a fetch request to the peer actor.
    ///
    /// Panics if the send fails.
    async fn fetch(&mut self, key: Self::Key) {
        self.sender
            .send(Message::Fetch { key })
            .await
            .expect("Failed to send fetch");
    }

    /// Send a cancel request to the peer actor.
    ///
    /// Panics if the send fails.
    async fn cancel(&mut self, key: Self::Key) {
        self.sender
            .send(Message::Cancel { key })
            .await
            .expect("Failed to send cancel_fetch");
    }

    /// Send a cancel all request to the peer actor.
    ///
    /// Panics if the send fails.
    async fn retain(&mut self, predicate: impl Fn(&Self::Key) -> bool + Send + 'static) {
        self.sender
            .send(Message::Retain {
                predicate: Box::new(predicate),
            })
            .await
            .expect("Failed to send retain");
    }

    /// Send a clear request to the peer actor.
    ///
    /// Panics if the send fails.
    async fn clear(&mut self) {
        self.sender
            .send(Message::Clear)
            .await
            .expect("Failed to send cancel_all");
    }
}

use crate::Resolver;
use commonware_cryptography::PublicKey;
use commonware_utils::Span;
use futures::{channel::mpsc, SinkExt};

type Predicate<K> = Box<dyn Fn(&K) -> bool + Send>;

/// Messages that can be sent to the peer actor.
pub enum Message<K, P> {
    /// Initiate a fetch request by key.
    Fetch { keys: Vec<K> },

    /// Cancel a fetch request by key.
    Cancel { key: K },

    /// Cancel all fetch requests.
    Clear,

    /// Cancel all fetch requests that do not satisfy the predicate.
    Retain { predicate: Predicate<K> },

    /// Add a hint peer for a key.
    Hint { key: K, peer: P },
}

/// A way to send messages to the peer actor.
#[derive(Clone)]
pub struct Mailbox<K, P> {
    /// The channel that delivers messages to the peer actor.
    sender: mpsc::Sender<Message<K, P>>,
}

impl<K, P> Mailbox<K, P> {
    /// Create a new mailbox.
    pub(super) const fn new(sender: mpsc::Sender<Message<K, P>>) -> Self {
        Self { sender }
    }
}

impl<K: Span, P: PublicKey> Resolver for Mailbox<K, P> {
    type Key = K;

    /// Send a fetch request to the peer actor.
    ///
    /// Panics if the send fails.
    async fn fetch(&mut self, key: Self::Key) {
        self.sender
            .send(Message::Fetch { keys: vec![key] })
            .await
            .expect("Failed to send fetch");
    }

    /// Send a fetch request to the peer actor for a batch of keys.
    ///
    /// Panics if the send fails.
    async fn fetch_all(&mut self, keys: Vec<Self::Key>) {
        self.sender
            .send(Message::Fetch { keys })
            .await
            .expect("Failed to send fetch_all");
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

impl<K: Span, P: PublicKey> Mailbox<K, P> {
    /// Register a peer as likely having data for a key.
    ///
    /// When fetching this key, hinted peers are tried first. If a hinted peer
    /// fails (timeout, error response, or send failure), only that peer is
    /// removed from hints. As hints deplete through failures, the resolver
    /// naturally falls back to trying all peers.
    ///
    /// Multiple hints can be registered for the same key. Hints can be added
    /// before or after calling `fetch()` - new hints will be used on retry.
    ///
    /// Hints are automatically cleared when:
    /// - The fetch succeeds (data received)
    /// - The fetch is canceled
    /// - All hinted peers fail (empty hints trigger fallback to all peers)
    ///
    /// Panics if the send fails.
    pub async fn hint(&mut self, key: K, peer: P) {
        self.sender
            .send(Message::Hint { key, peer })
            .await
            .expect("Failed to send hint");
    }
}

use crate::Resolver;
use commonware_cryptography::PublicKey;
use commonware_utils::{vec::NonEmptyVec, Span};
use futures::{channel::mpsc, SinkExt};

type Predicate<K> = Box<dyn Fn(&K) -> bool + Send>;

/// A request to fetch data for a key, optionally with target peers.
pub struct FetchRequest<K, P> {
    /// The key to fetch.
    pub key: K,
    /// Target peers to restrict the fetch to.
    ///
    /// - `None`: No targeting (or clear existing targeting), try any available peer
    /// - `Some(peers)`: Only try the specified peers
    pub targets: Option<NonEmptyVec<P>>,
}

/// Messages that can be sent to the peer actor.
pub enum Message<K, P> {
    /// Initiate fetch requests.
    Fetch(Vec<FetchRequest<K, P>>),

    /// Cancel a fetch request by key.
    Cancel { key: K },

    /// Cancel all fetch requests.
    Clear,

    /// Cancel all fetch requests that do not satisfy the predicate.
    Retain { predicate: Predicate<K> },
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
    /// If a fetch is already in progress for this key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// Panics if the send fails.
    async fn fetch(&mut self, key: Self::Key) {
        self.sender
            .send(Message::Fetch(vec![FetchRequest { key, targets: None }]))
            .await
            .expect("Failed to send fetch");
    }

    /// Send a fetch request to the peer actor for a batch of keys.
    ///
    /// If a fetch is already in progress for any key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// Panics if the send fails.
    async fn fetch_all(&mut self, keys: Vec<Self::Key>) {
        self.sender
            .send(Message::Fetch(
                keys.into_iter()
                    .map(|key| FetchRequest { key, targets: None })
                    .collect(),
            ))
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
    /// Send a fetch request restricted to specific target peers.
    ///
    /// Only target peers are tried, there is no fallback to other peers. Targets
    /// persist through transient failures (timeout, "no data" response, send failure)
    /// since the peer might be slow or might receive the data later.
    ///
    /// If a fetch is already in progress for this key, the new targets are added
    /// to the existing target set. To clear targeting and fall back to any peer,
    /// call [`fetch`](Self::fetch) instead.
    ///
    /// Targets are automatically cleared when the fetch succeeds or is canceled.
    /// When a peer is blocked (sent invalid data), only that peer is removed
    /// from the target set.
    pub async fn fetch_targeted(&mut self, key: K, targets: NonEmptyVec<P>) {
        self.sender
            .send(Message::Fetch(vec![FetchRequest {
                key,
                targets: Some(targets),
            }]))
            .await
            .expect("Failed to send fetch_targeted");
    }

    /// Send fetch requests for multiple keys, each with their own targets.
    ///
    /// See [`fetch_targeted`](Self::fetch_targeted) for details on target behavior.
    pub async fn fetch_all_targeted(&mut self, requests: Vec<(K, NonEmptyVec<P>)>) {
        self.sender
            .send(Message::Fetch(
                requests
                    .into_iter()
                    .map(|(key, targets)| FetchRequest {
                        key,
                        targets: Some(targets),
                    })
                    .collect(),
            ))
            .await
            .expect("Failed to send fetch_all_targeted");
    }
}

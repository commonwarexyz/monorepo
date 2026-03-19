use crate::Resolver;
use commonware_cryptography::PublicKey;
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, mpsc},
    vec::NonEmptyVec,
    Span,
};

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
    type PublicKey = P;

    /// Send a fetch request to the peer actor.
    ///
    /// If a fetch is already in progress for this key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// If the engine has shut down, this is a no-op.
    async fn fetch(&mut self, key: Self::Key) {
        self.sender
            .send_lossy(Message::Fetch(vec![FetchRequest { key, targets: None }]))
            .await;
    }

    /// Send a fetch request to the peer actor for a batch of keys.
    ///
    /// If a fetch is already in progress for any key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// If the engine has shut down, this is a no-op.
    async fn fetch_all(&mut self, keys: Vec<Self::Key>) {
        self.sender
            .send_lossy(Message::Fetch(
                keys.into_iter()
                    .map(|key| FetchRequest { key, targets: None })
                    .collect(),
            ))
            .await;
    }

    /// Send a targeted fetch request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    async fn fetch_targeted(&mut self, key: Self::Key, targets: NonEmptyVec<Self::PublicKey>) {
        self.sender
            .send_lossy(Message::Fetch(vec![FetchRequest {
                key,
                targets: Some(targets),
            }]))
            .await;
    }

    /// Send targeted fetch requests to the peer actor for a batch of keys.
    ///
    /// If the engine has shut down, this is a no-op.
    async fn fetch_all_targeted(
        &mut self,
        requests: Vec<(Self::Key, NonEmptyVec<Self::PublicKey>)>,
    ) {
        self.sender
            .send_lossy(Message::Fetch(
                requests
                    .into_iter()
                    .map(|(key, targets)| FetchRequest {
                        key,
                        targets: Some(targets),
                    })
                    .collect(),
            ))
            .await;
    }

    /// Send a cancel request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    async fn cancel(&mut self, key: Self::Key) {
        self.sender.send_lossy(Message::Cancel { key }).await;
    }

    /// Send a retain request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    async fn retain(&mut self, predicate: impl Fn(&Self::Key) -> bool + Send + 'static) {
        self.sender
            .send_lossy(Message::Retain {
                predicate: Box::new(predicate),
            })
            .await;
    }

    /// Send a clear request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    async fn clear(&mut self) {
        self.sender.send_lossy(Message::Clear).await;
    }
}

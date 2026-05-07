use crate::Resolver;
use commonware_cryptography::PublicKey;
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, mpsc},
    vec::NonEmptyVec,
    Span,
};

type Predicate<R> = Box<dyn Fn(&R) -> bool + Send>;

/// A request to fetch data for a key, optionally with target peers.
pub struct FetchRequest<K, P, R> {
    /// The key to fetch.
    pub key: K,
    /// The key used to decide whether the fetch should be retained.
    pub retain_key: R,
    /// Target peers to restrict the fetch to.
    ///
    /// - `None`: No targeting (or clear existing targeting), try any available peer
    /// - `Some(peers)`: Only try the specified peers
    pub targets: Option<NonEmptyVec<P>>,
}

/// Messages that can be sent to the peer actor.
pub enum Message<K, P, R> {
    /// Initiate fetch requests.
    Fetch(Vec<FetchRequest<K, P, R>>),

    /// Cancel a fetch request by key.
    Cancel { key: K },

    /// Cancel all fetch requests.
    Clear,

    /// Cancel all fetch requests without a retain key that satisfies the predicate.
    Retain { predicate: Predicate<R> },
}

/// A way to send messages to the peer actor.
#[derive(Clone)]
pub struct Mailbox<K, P, R = K> {
    /// The channel that delivers messages to the peer actor.
    sender: mpsc::Sender<Message<K, P, R>>,
}

impl<K, P, R> Mailbox<K, P, R> {
    /// Create a new mailbox.
    pub(super) const fn new(sender: mpsc::Sender<Message<K, P, R>>) -> Self {
        Self { sender }
    }
}

impl<K, P, R> Resolver for Mailbox<K, P, R>
where
    K: Span,
    P: PublicKey,
    R: Clone + From<K> + Send + 'static,
{
    type Key = K;
    type RetainKey = R;
    type PublicKey = P;

    /// Send a fetch request to the peer actor.
    ///
    /// If a fetch is already in progress for this key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// If the engine has shut down, this is a no-op.
    async fn fetch(&mut self, key: Self::Key) {
        self.sender
            .send_lossy(Message::Fetch(vec![FetchRequest {
                retain_key: R::from(key.clone()),
                key,
                targets: None,
            }]))
            .await;
    }

    /// Send a fetch request to the peer actor with a separate retain key.
    ///
    /// If the engine has shut down, this is a no-op.
    async fn fetch_with_retain_key(&mut self, key: Self::Key, retain_key: Self::RetainKey) {
        self.sender
            .send_lossy(Message::Fetch(vec![FetchRequest {
                key,
                retain_key,
                targets: None,
            }]))
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
                    .map(|key| FetchRequest {
                        retain_key: R::from(key.clone()),
                        key,
                        targets: None,
                    })
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
                retain_key: R::from(key.clone()),
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
                        retain_key: R::from(key.clone()),
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
    async fn retain(&mut self, predicate: impl Fn(&Self::RetainKey) -> bool + Send + 'static) {
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

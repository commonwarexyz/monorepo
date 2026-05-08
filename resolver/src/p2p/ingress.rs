use crate::{Dependencies, FetchDependency, Resolver};
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
    /// The dependencies used to decide whether the fetch should be retained.
    pub dependencies: Vec<FetchDependency<R>>,
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

    /// Cancel all fetch requests without a dependency that satisfies the predicate.
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
    R: Clone + Send + 'static,
{
    type Key = K;
    type Dependency = R;
    type PublicKey = P;

    /// Send a fetch request to the peer actor.
    ///
    /// If a fetch is already in progress for this key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// If the engine has shut down, this is a no-op.
    async fn fetch<D>(&mut self, request: D)
    where
        D: Into<Dependencies<Self::Key, Self::Dependency>> + Send,
    {
        let request = request.into();
        self.sender
            .send_lossy(Message::Fetch(vec![FetchRequest {
                key: request.request,
                dependencies: request.dependencies,
                targets: None,
            }]))
            .await;
    }

    /// Send a fetch request to the peer actor for a batch of requests.
    ///
    /// If a fetch is already in progress for any key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// If the engine has shut down, this is a no-op.
    async fn fetch_all<D>(&mut self, requests: Vec<D>)
    where
        D: Into<Dependencies<Self::Key, Self::Dependency>> + Send,
    {
        self.sender
            .send_lossy(Message::Fetch(
                requests
                    .into_iter()
                    .map(|request| {
                        let request = request.into();
                        FetchRequest {
                            key: request.request,
                            dependencies: request.dependencies,
                            targets: None,
                        }
                    })
                    .collect(),
            ))
            .await;
    }

    /// Send a targeted fetch request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    async fn fetch_targeted(
        &mut self,
        request: impl Into<Dependencies<Self::Key, Self::Dependency>> + Send,
        targets: NonEmptyVec<Self::PublicKey>,
    ) {
        let request = request.into();
        self.sender
            .send_lossy(Message::Fetch(vec![FetchRequest {
                key: request.request,
                dependencies: request.dependencies,
                targets: Some(targets),
            }]))
            .await;
    }

    /// Send targeted fetch requests to the peer actor for a batch of keys.
    ///
    /// If the engine has shut down, this is a no-op.
    async fn fetch_all_targeted<D>(&mut self, requests: Vec<(D, NonEmptyVec<Self::PublicKey>)>)
    where
        D: Into<Dependencies<Self::Key, Self::Dependency>> + Send,
    {
        self.sender
            .send_lossy(Message::Fetch(
                requests
                    .into_iter()
                    .map(|(request, targets)| {
                        let request = request.into();
                        FetchRequest {
                            key: request.request,
                            dependencies: request.dependencies,
                            targets: Some(targets),
                        }
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
    async fn retain(&mut self, predicate: impl Fn(&Self::Dependency) -> bool + Send + 'static) {
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

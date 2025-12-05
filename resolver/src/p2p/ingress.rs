use crate::Resolver;
use commonware_cryptography::PublicKey;
use commonware_utils::Span;
use futures::{channel::mpsc, SinkExt};

type Predicate<K> = Box<dyn Fn(&K) -> bool + Send>;

/// A request to fetch data for a key, optionally with target peers.
pub struct FetchRequest<K, P> {
    /// The key to fetch.
    pub key: K,
    /// Target peers to restrict the fetch to.
    pub targets: Vec<P>,
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

    /// Add target peers for a key (only effective if key is being fetched).
    Target { key: K, peers: Vec<P> },

    /// Replace all targets for a key (only effective if key is being fetched).
    Retarget { key: K, peers: Vec<P> },

    /// Clear targeting for a key (only effective if key is being fetched).
    Untarget { key: K },
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
            .send(Message::Fetch(vec![FetchRequest {
                key,
                targets: Vec::new(),
            }]))
            .await
            .expect("Failed to send fetch");
    }

    /// Send a fetch request to the peer actor for a batch of keys.
    ///
    /// Panics if the send fails.
    async fn fetch_all(&mut self, keys: Vec<Self::Key>) {
        self.sender
            .send(Message::Fetch(
                keys.into_iter()
                    .map(|key| FetchRequest {
                        key,
                        targets: Vec::new(),
                    })
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
    /// Only target peers are tried - there is no fallback to other peers. Targets
    /// persist through transient failures (timeout, "no data" response, send failure)
    /// since the peer might be slow or might receive the data later.
    ///
    /// To clear targeting and fall back to any peer, use [`untarget`](Self::untarget).
    /// To replace targets, use [`retarget`](Self::retarget).
    /// To add more targets, use [`target`](Self::target).
    ///
    /// Targets are automatically cleared when:
    /// - The fetch succeeds (data received)
    /// - The fetch is canceled
    /// - A peer is blocked (sent invalid data)
    ///
    /// Panics if the send fails.
    pub async fn fetch_targeted(&mut self, key: K, targets: Vec<P>) {
        self.sender
            .send(Message::Fetch(vec![FetchRequest { key, targets }]))
            .await
            .expect("Failed to send fetch_targeted");
    }

    /// Send fetch requests for multiple keys, each with their own targets.
    ///
    /// See [`fetch_targeted`](Self::fetch_targeted) for details on target behavior.
    ///
    /// Panics if the send fails.
    pub async fn fetch_all_targeted(&mut self, requests: Vec<(K, Vec<P>)>) {
        self.sender
            .send(Message::Fetch(
                requests
                    .into_iter()
                    .map(|(key, targets)| FetchRequest { key, targets })
                    .collect(),
            ))
            .await
            .expect("Failed to send fetch_all_targeted");
    }

    /// Add target peers for an **ongoing** fetch.
    ///
    /// This only has an effect if a fetch is already in progress for this key.
    /// To provide targets when starting a fetch, use [`fetch_targeted`](Self::fetch_targeted)
    /// or [`fetch_all_targeted`](Self::fetch_all_targeted) instead.
    ///
    /// Only target peers are tried - there is no fallback to other peers. Targets
    /// persist through transient failures (timeout, "no data" response, send failure).
    ///
    /// Multiple calls add to the existing target set. Use [`retarget`](Self::retarget)
    /// to replace targets, or [`untarget`](Self::untarget) to clear targeting.
    ///
    /// Targets are automatically cleared when:
    /// - The fetch succeeds (data received)
    /// - The fetch is canceled
    /// - A peer is blocked (sent invalid data)
    ///
    /// Panics if the send fails.
    pub async fn target(&mut self, key: K, peers: Vec<P>) {
        self.sender
            .send(Message::Target { key, peers })
            .await
            .expect("Failed to send target");
    }

    /// Replace all targets for an **ongoing** fetch.
    ///
    /// Atomically replaces the target set. Use this when you want to change
    /// which peers are tried without adding to the existing set.
    ///
    /// If `peers` is empty, the fetch will wait until targets are added via
    /// [`target`](Self::target). To clear targeting and try any peer, use
    /// [`untarget`](Self::untarget) instead.
    ///
    /// Panics if the send fails.
    pub async fn retarget(&mut self, key: K, peers: Vec<P>) {
        self.sender
            .send(Message::Retarget { key, peers })
            .await
            .expect("Failed to send retarget");
    }

    /// Clear targeting for an **ongoing** fetch.
    ///
    /// After this call, the fetch will try any available peer instead of
    /// being restricted to targets. Use this to fall back to any peer after
    /// targets have been exhausted or timed out.
    ///
    /// Panics if the send fails.
    pub async fn untarget(&mut self, key: K) {
        self.sender
            .send(Message::Untarget { key })
            .await
            .expect("Failed to send untarget");
    }
}

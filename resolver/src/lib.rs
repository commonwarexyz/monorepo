//! Resolve data identified by a fixed-length key.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

commonware_macros::stability_scope!(BETA {
    use commonware_actor::Feedback;
    use commonware_cryptography::PublicKey;
    use commonware_utils::{channel::oneshot, vec::NonEmptyVec, Span};

    pub mod p2p;

    /// A key to fetch data for a subscriber.
    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct Fetch<K, S = ()> {
        /// The peer-visible key.
        pub key: K,
        /// Subscriber attached to the key.
        pub subscriber: S,
    }

    impl<K, S> Fetch<K, S> {
        /// Create a fetch for a key and subscriber.
        pub const fn new(key: K, subscriber: S) -> Self {
            Self { key, subscriber }
        }

        /// Consume the fetch into its key and subscriber.
        pub fn into_parts(self) -> (K, S) {
            (self.key, self.subscriber)
        }
    }

    impl<K, S> From<(K, S)> for Fetch<K, S> {
        fn from((key, subscriber): (K, S)) -> Self {
            Self::new(key, subscriber)
        }
    }

    impl<K, S: Default> From<K> for Fetch<K, S> {
        fn from(key: K) -> Self {
            Self::new(key, S::default())
        }
    }

    /// Data delivered for a resolved fetch.
    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct Delivery<K, S> {
        /// The peer-visible key used to validate the response.
        pub key: K,
        /// Subscribers that were still retained when the response arrived.
        pub subscribers: NonEmptyVec<S>,
    }

    /// Notified when data is available, and must validate it.
    pub trait Consumer: Clone + Send + 'static {
        /// Type used to key data requested from peers.
        type Key: Span;

        /// Type used to track subscribers on fetch keys.
        type Subscriber: Clone + Eq + Send + 'static;

        /// Type of data to retrieve.
        type Value;

        /// Deliver data to the consumer.
        ///
        /// Returns a receiver that resolves to `true` if the data is valid for the key.
        ///
        /// The returned receiver may be dropped before completion if the application
        /// cancels the fetch via [`Resolver::retain`]. When this happens, the
        /// resolver discards the validation result.
        ///
        /// Implementations of [`Resolver`] must only invoke `deliver` for keys that were
        /// previously requested via [`Resolver::fetch`] (or its variants).
        ///
        /// `delivery` contains the peer-visible key and the retained subscribers
        /// for the fetch. Subscribers decide who should observe a valid response;
        /// they do not define peer validity.
        fn deliver(
            &mut self,
            delivery: Delivery<Self::Key, Self::Subscriber>,
            value: Self::Value,
        ) -> oneshot::Receiver<bool>;
    }

    /// Responsible for fetching data and notifying a `Consumer`.
    pub trait Resolver: Clone + Send + 'static {
        /// Type used to key data requested from peers.
        type Key: Span;

        /// Type used to track subscribers on fetch keys.
        ///
        /// Implementations that also own the [`Consumer`] should supply subscribers to
        /// [`Consumer::deliver`] when a fetch resolves.
        type Subscriber: Clone + Eq + Send + 'static;

        /// Type used to identify peers for targeted fetches.
        type PublicKey: PublicKey;

        /// Initiate a fetch.
        ///
        /// The resolver fetches and delivers the key. The subscriber is
        /// retained and supplied to [`Consumer::deliver`] when the fetch resolves.
        /// If multiple subscribers are attached to the same key,
        /// the fetch is retained as long as at least one subscriber satisfies the
        /// latest [`retain`](Self::retain) predicate.
        ///
        /// Passing a bare key is supported when `Subscriber: Default`.
        fn fetch<F>(
            &mut self,
            key: F,
        ) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send;

        /// Initiate fetches for a batch of keys.
        fn fetch_all<F>(&mut self, keys: Vec<F>) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send;

        /// Initiate a fetch restricted to specific target peers.
        ///
        /// Only target peers are tried, there is no fallback to other peers. Targets
        /// persist through transient failures (timeout, "no data" response, send failure)
        /// since the peer might be slow or might receive the data later.
        ///
        /// If a fetch is already in progress for this key:
        /// - If the existing fetch has targets, the new targets are added to the set
        /// - If the existing fetch has no targets (can try any peer), it remains
        ///   unrestricted (this call is ignored)
        ///
        /// To clear targeting and fall back to any peer, call [`fetch`](Self::fetch).
        ///
        /// Targets are automatically cleared when the fetch succeeds or is canceled.
        /// When a peer is blocked (sent invalid data), only that peer is removed
        /// from the target set.
        fn fetch_targeted(
            &mut self,
            key: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
            targets: NonEmptyVec<Self::PublicKey>,
        ) -> Feedback;

        /// Initiate fetches for multiple keys, each with their own targets.
        ///
        /// See [`fetch_targeted`](Self::fetch_targeted) for details on target behavior.
        fn fetch_all_targeted<F>(
            &mut self,
            keys: Vec<(F, NonEmptyVec<Self::PublicKey>)>,
        ) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send;

        /// Retain only fetch subscribers satisfying the predicate.
        ///
        /// The predicate receives the peer-visible key and subscriber.
        ///
        /// Fetches not retained are canceled. If response validation is in
        /// progress, cancellation may drop the [`Consumer::deliver`] future
        /// before it reports whether the data was valid.
        fn retain(
            &mut self,
            predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
        ) -> Feedback;
    }
});

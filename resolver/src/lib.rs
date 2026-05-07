//! Resolve data identified by a fixed-length key.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

commonware_macros::stability_scope!(BETA {
    use commonware_cryptography::PublicKey;
    use commonware_utils::{vec::NonEmptyVec, Span};
    use std::future::Future;

    pub mod p2p;

    /// A local reason retaining a fetch.
    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub enum RetentionKey<R> {
        /// The fetch is retained by the request key itself.
        Request,
        /// A separate local key that retained the fetch.
        Retain(R),
    }

    /// A resolved fetch and the local reasons that kept it alive.
    pub struct Delivery<K, R> {
        /// The peer-visible request key.
        pub key: K,
        /// The local reasons currently retaining the fetch.
        pub retainers: Vec<RetentionKey<R>>,
    }

    /// Notified when data is available, and must validate it.
    pub trait Consumer: Clone + Send + 'static {
        /// Type used to uniquely identify data.
        type Key: Span;

        /// Type used to retain or prune fetch requests.
        type RetainKey: Clone + Send + 'static;

        /// Type of data to retrieve.
        type Value;

        /// Deliver data to the consumer.
        ///
        /// Returns `true` if the data is valid.
        ///
        /// The returned future may be dropped before completion if the
        /// application cancels the fetch via [`Resolver::cancel`],
        /// [`Resolver::clear`], or [`Resolver::retain`]. When this happens,
        /// the resolver discards the validation result.
        ///
        /// Implementations of [`Resolver`] must only invoke `deliver` for keys that were
        /// previously requested via [`Resolver::fetch`] (or its variants).
        ///
        /// `delivery` contains the peer-visible request key and the currently retained
        /// local reasons for the fetch. Ordinary fetches use [`RetentionKey::Request`],
        /// avoiding a duplicate retain key when the request key itself retains the fetch.
        fn deliver(
            &mut self,
            delivery: Delivery<Self::Key, Self::RetainKey>,
            value: Self::Value,
        ) -> impl Future<Output = bool> + Send;
    }

    /// Responsible for fetching data and notifying a `Consumer`.
    pub trait Resolver: Clone + Send + 'static {
        /// Type used to uniquely identify data.
        type Key: Span;

        /// Type used to retain or prune fetch requests.
        ///
        /// Implementations that also own the [`Consumer`] should supply the retained keys to
        /// [`Consumer::deliver`] when a fetch resolves.
        type RetainKey: Clone + Send + 'static;

        /// Type used to identify peers for targeted fetches.
        type PublicKey: PublicKey;

        /// Initiate a fetch request for a single key.
        fn fetch(&mut self, key: Self::Key) -> impl Future<Output = ()> + Send;

        /// Initiate a fetch request with a separate key used by [`retain`](Self::retain).
        ///
        /// The resolver still fetches and delivers `key`. `retain_key` controls
        /// whether the request is retained by [`retain`](Self::retain) and is also
        /// supplied to [`Consumer::deliver`] when the fetch resolves. If multiple
        /// retain keys are attached to the same fetch key, the fetch is retained as
        /// long as at least one retain key satisfies the predicate.
        ///
        /// [`cancel`](Self::cancel) still cancels by fetch key.
        fn fetch_with_retain_key(
            &mut self,
            key: Self::Key,
            retain_key: Self::RetainKey,
        ) -> impl Future<Output = ()> + Send;

        /// Initiate a fetch request for a batch of keys.
        fn fetch_all(&mut self, keys: Vec<Self::Key>) -> impl Future<Output = ()> + Send;

        /// Initiate a fetch request restricted to specific target peers.
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
            key: Self::Key,
            targets: NonEmptyVec<Self::PublicKey>,
        ) -> impl Future<Output = ()> + Send;

        /// Initiate fetch requests for multiple keys, each with their own targets.
        ///
        /// See [`fetch_targeted`](Self::fetch_targeted) for details on target behavior.
        fn fetch_all_targeted(
            &mut self,
            requests: Vec<(Self::Key, NonEmptyVec<Self::PublicKey>)>,
        ) -> impl Future<Output = ()> + Send;

        /// Cancel a fetch request.
        ///
        /// If response validation is in progress, cancellation may drop the
        /// [`Consumer::deliver`] future before it reports whether the data was
        /// valid.
        fn cancel(&mut self, key: Self::Key) -> impl Future<Output = ()> + Send;

        /// Cancel all fetch requests.
        ///
        /// See [`cancel`](Self::cancel) for how cancellation affects
        /// in-progress response validation.
        fn clear(&mut self) -> impl Future<Output = ()> + Send;

        /// Retain only the fetch requests with at least one retain key satisfying the predicate.
        ///
        /// Fetches not retained are canceled. See [`cancel`](Self::cancel) for
        /// how cancellation affects in-progress response validation.
        fn retain(
            &mut self,
            predicate: impl Fn(&Self::RetainKey) -> bool + Send + 'static,
        ) -> impl Future<Output = ()> + Send;
    }
});

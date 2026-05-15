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

    /// Subscribers attached to a resolved fetch.
    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct Subscribers<K, L> {
        /// The peer-visible request key.
        pub request: K,
        /// Subscribers that kept the fetch active.
        pub subscribers: Vec<L>,
    }

    impl<K: Clone, L: From<K>> Subscribers<K, L> {
        /// Create subscribers for an ordinary fetch.
        pub fn new(request: K) -> Self {
            Self {
                subscribers: vec![L::from(request.clone())],
                request,
            }
        }
    }

    impl<K: Clone, L: From<K>> From<K> for Subscribers<K, L> {
        fn from(request: K) -> Self {
            Self::new(request)
        }
    }

    /// Notified when data is available, and must validate it.
    pub trait Consumer: Clone + Send + 'static {
        /// Type used to uniquely identify data.
        type Key: Span;

        /// Type used to track local subscribers on fetch requests.
        type Subscriber: Clone + Send + 'static;

        /// Type of data to retrieve.
        type Value;

        /// Deliver data to the consumer.
        ///
        /// Returns a receiver that resolves to `true` if the data is valid for the request.
        ///
        /// The returned receiver may be dropped before completion if the application
        /// cancels the fetch via [`Resolver::cancel`], [`Resolver::clear`], or
        /// [`Resolver::retain`]. When this happens, the resolver discards the
        /// validation result.
        ///
        /// Implementations of [`Resolver`] must only invoke `deliver` for keys that were
        /// previously requested via [`Resolver::fetch`] (or its variants).
        ///
        /// `subscribers` contains the peer-visible request key and the currently
        /// retained subscribers for the fetch. Subscribers are local metadata for
        /// deciding who should observe a valid response; they do not define peer
        /// validity. Ordinary fetches include `Subscriber::from(request)`.
        fn deliver(
            &mut self,
            subscribers: Subscribers<Self::Key, Self::Subscriber>,
            value: Self::Value,
        ) -> oneshot::Receiver<bool>;
    }

    /// Responsible for fetching data and notifying a `Consumer`.
    pub trait Resolver: Clone + Send + 'static {
        /// Type used to uniquely identify data.
        type Key: Span;

        /// Type used to track local subscribers on fetch requests.
        ///
        /// Implementations that also own the [`Consumer`] should supply subscribers to
        /// [`Consumer::deliver`] when a fetch resolves.
        type Subscriber: Clone + From<Self::Key> + Send + 'static;

        /// Type used to identify peers for targeted fetches.
        type PublicKey: PublicKey;

        /// Initiate a fetch request.
        ///
        /// The resolver fetches and delivers the request key. Subscribers control
        /// whether the request is retained by [`retain`](Self::retain) and are also
        /// supplied to [`Consumer::deliver`] when the fetch resolves. If multiple
        /// subscribers are attached to the same request key, the fetch is retained
        /// as long as at least one subscriber satisfies the predicate.
        ///
        /// Passing a bare key is equivalent to [`Subscribers::new`]. [`cancel`](Self::cancel)
        /// still cancels by request key.
        fn fetch<R>(
            &mut self,
            request: R,
        ) -> Feedback
        where
            R: Into<Subscribers<Self::Key, Self::Subscriber>> + Send;

        /// Initiate a fetch request for a batch of requests.
        fn fetch_all<R>(&mut self, requests: Vec<R>) -> Feedback
        where
            R: Into<Subscribers<Self::Key, Self::Subscriber>> + Send;

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
            request: impl Into<Subscribers<Self::Key, Self::Subscriber>> + Send,
            targets: NonEmptyVec<Self::PublicKey>,
        ) -> Feedback;

        /// Initiate fetch requests for multiple requests, each with their own targets.
        ///
        /// See [`fetch_targeted`](Self::fetch_targeted) for details on target behavior.
        fn fetch_all_targeted<R>(
            &mut self,
            requests: Vec<(R, NonEmptyVec<Self::PublicKey>)>,
        ) -> Feedback
        where
            R: Into<Subscribers<Self::Key, Self::Subscriber>> + Send;

        /// Cancel a fetch request.
        ///
        /// If response validation is in progress, cancellation may drop the
        /// [`Consumer::deliver`] future before it reports whether the data was
        /// valid.
        fn cancel(&mut self, key: Self::Key) -> Feedback;

        /// Cancel all fetch requests.
        ///
        /// See [`cancel`](Self::cancel) for how cancellation affects
        /// in-progress response validation.
        fn clear(&mut self) -> Feedback;

        /// Retain only the fetch requests with at least one subscriber satisfying the predicate.
        ///
        /// Fetches not retained are canceled. See [`cancel`](Self::cancel) for
        /// how cancellation affects in-progress response validation.
        fn retain(
            &mut self,
            predicate: impl Fn(&Self::Subscriber) -> bool + Send + 'static,
        ) -> Feedback;
    }
});

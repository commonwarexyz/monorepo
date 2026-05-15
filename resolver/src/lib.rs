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

    /// Local reason considered by [`Resolver::retain`].
    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub enum Interest<'a, K, S> {
        /// A bare request key submitted with [`Resolver::fetch`] or one of its variants.
        Request(&'a K),
        /// Local subscriber metadata attached to a request.
        Subscriber(&'a S),
    }

    /// A request to fetch data, optionally with local subscribers.
    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct Fetch<K, S> {
        /// The peer-visible request key.
        pub request: K,
        requested: bool,
        /// Local subscribers attached to the request.
        pub subscribers: Vec<S>,
    }

    impl<K, S> Fetch<K, S> {
        /// Create an ordinary fetch request with no local subscribers.
        pub const fn new(request: K) -> Self {
            Self {
                request,
                requested: true,
                subscribers: Vec::new(),
            }
        }

        /// Create a fetch request with local subscribers and no bare request interest.
        ///
        /// If `subscribers` is empty, the fetch has no retained interest. Use
        /// [`Fetch::new`] for an ordinary bare request.
        pub const fn with_subscribers(request: K, subscribers: Vec<S>) -> Self {
            Self {
                request,
                requested: false,
                subscribers,
            }
        }

        /// Create an ordinary fetch request that also carries local subscribers.
        pub const fn with_request_and_subscribers(request: K, subscribers: Vec<S>) -> Self {
            Self {
                request,
                requested: true,
                subscribers,
            }
        }

        /// Returns true if this fetch includes a bare request interest.
        pub const fn requested(&self) -> bool {
            self.requested
        }

        /// Consume the fetch into its request key, request marker, and subscribers.
        pub fn into_parts(self) -> (K, bool, Vec<S>) {
            (self.request, self.requested, self.subscribers)
        }
    }

    impl<K, S> From<K> for Fetch<K, S> {
        fn from(request: K) -> Self {
            Self::new(request)
        }
    }

    /// Data delivered for a resolved fetch.
    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct Delivery<K, S> {
        /// The peer-visible request key used to validate the response.
        pub request: K,
        /// Whether a bare request key was still retained when the response arrived.
        pub requested: bool,
        /// Local subscribers that were still retained when the response arrived.
        pub subscribers: Vec<S>,
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
        /// `delivery` contains the peer-visible request key and the retained
        /// local interests for the fetch. Subscribers are local metadata for
        /// deciding who should observe a valid response; they do not define peer
        /// validity.
        fn deliver(
            &mut self,
            delivery: Delivery<Self::Key, Self::Subscriber>,
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
        type Subscriber: Clone + Send + 'static;

        /// Type used to identify peers for targeted fetches.
        type PublicKey: PublicKey;

        /// Initiate a fetch request.
        ///
        /// The resolver fetches and delivers the request key. A bare key is
        /// retained as an [`Interest::Request`]. Subscribers are retained as
        /// [`Interest::Subscriber`] and are supplied to [`Consumer::deliver`]
        /// when the fetch resolves. If multiple interests are attached to the same
        /// request key, the fetch is retained as long as at least one interest
        /// satisfies the predicate.
        ///
        /// Passing a bare key is equivalent to [`Fetch::new`]. [`cancel`](Self::cancel)
        /// cancels by request key.
        fn fetch<R>(
            &mut self,
            request: R,
        ) -> Feedback
        where
            R: Into<Fetch<Self::Key, Self::Subscriber>> + Send;

        /// Initiate a fetch request for a batch of requests.
        fn fetch_all<R>(&mut self, requests: Vec<R>) -> Feedback
        where
            R: Into<Fetch<Self::Key, Self::Subscriber>> + Send;

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
            request: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
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
            R: Into<Fetch<Self::Key, Self::Subscriber>> + Send;

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

        /// Retain only fetches with at least one interest satisfying the predicate.
        ///
        /// Fetches not retained are canceled. See [`cancel`](Self::cancel) for
        /// how cancellation affects in-progress response validation.
        fn retain(
            &mut self,
            predicate: impl for<'a> Fn(Interest<'a, Self::Key, Self::Subscriber>) -> bool
                + Send
                + 'static,
        ) -> Feedback;
    }
});

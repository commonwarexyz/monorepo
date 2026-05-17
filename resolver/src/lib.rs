//! Resolve data identified by a fixed-length request.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

commonware_macros::stability_scope!(BETA {
    use commonware_actor::Feedback;
    use commonware_cryptography::PublicKey;
    use commonware_utils::{channel::oneshot, vec::NonEmptyVec, Span};

    pub mod p2p;

    /// A request to fetch data for a local subscriber.
    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct Fetch<R, S> {
        /// The peer-visible request.
        pub request: R,
        /// Local subscriber attached to the request.
        pub subscriber: S,
    }

    impl<R, S> Fetch<R, S> {
        /// Create a fetch request for a local subscriber.
        pub const fn new(request: R, subscriber: S) -> Self {
            Self { request, subscriber }
        }

        /// Consume the fetch into its request and subscriber.
        pub fn into_parts(self) -> (R, S) {
            (self.request, self.subscriber)
        }
    }

    impl<R, S> From<(R, S)> for Fetch<R, S> {
        fn from((request, subscriber): (R, S)) -> Self {
            Self::new(request, subscriber)
        }
    }

    /// Data delivered for a resolved fetch.
    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct Delivery<R, S> {
        /// The peer-visible request used to validate the response.
        pub request: R,
        /// Local subscribers that were still retained when the response arrived.
        pub subscribers: Vec<S>,
    }

    /// Notified when data is available, and must validate it.
    pub trait Consumer: Clone + Send + 'static {
        /// Type used to request data from peers.
        type Request: Span;

        /// Type used to track local subscribers on fetch requests.
        type Subscriber: Clone + Eq + Send + 'static;

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
        /// Implementations of [`Resolver`] must only invoke `deliver` for requests that were
        /// previously requested via [`Resolver::fetch`] (or its variants).
        ///
        /// `delivery` contains the peer-visible request and the retained local
        /// subscribers for the fetch. Subscribers are local metadata for deciding
        /// who should observe a valid response; they do not define peer validity.
        fn deliver(
            &mut self,
            delivery: Delivery<Self::Request, Self::Subscriber>,
            value: Self::Value,
        ) -> oneshot::Receiver<bool>;
    }

    /// Responsible for fetching data and notifying a `Consumer`.
    pub trait Resolver: Clone + Send + 'static {
        /// Type used to request data from peers.
        type Request: Span;

        /// Type used to track local subscribers on fetch requests.
        ///
        /// Implementations that also own the [`Consumer`] should supply subscribers to
        /// [`Consumer::deliver`] when a fetch resolves.
        type Subscriber: Clone + Eq + Send + 'static;

        /// Type used to identify peers for targeted fetches.
        type PublicKey: PublicKey;

        /// Initiate a fetch request.
        ///
        /// The resolver fetches and delivers the request. The provided subscriber
        /// is retained locally and supplied to [`Consumer::deliver`] when the
        /// fetch resolves. If multiple subscribers are attached to the same
        /// request, the fetch is retained as long as at least one subscriber
        /// satisfies the latest [`retain`](Self::retain) predicate.
        ///
        /// [`cancel`](Self::cancel) cancels by subscriber.
        fn fetch<F>(
            &mut self,
            request: F,
        ) -> Feedback
        where
            F: Into<Fetch<Self::Request, Self::Subscriber>> + Send;

        /// Initiate a fetch request for a batch of requests.
        fn fetch_all<F>(&mut self, requests: Vec<F>) -> Feedback
        where
            F: Into<Fetch<Self::Request, Self::Subscriber>> + Send;

        /// Initiate a fetch request restricted to specific target peers.
        ///
        /// Only target peers are tried, there is no fallback to other peers. Targets
        /// persist through transient failures (timeout, "no data" response, send failure)
        /// since the peer might be slow or might receive the data later.
        ///
        /// If a fetch is already in progress for this request:
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
            request: impl Into<Fetch<Self::Request, Self::Subscriber>> + Send,
            targets: NonEmptyVec<Self::PublicKey>,
        ) -> Feedback;

        /// Initiate fetch requests for multiple requests, each with their own targets.
        ///
        /// See [`fetch_targeted`](Self::fetch_targeted) for details on target behavior.
        fn fetch_all_targeted<F>(
            &mut self,
            requests: Vec<(F, NonEmptyVec<Self::PublicKey>)>,
        ) -> Feedback
        where
            F: Into<Fetch<Self::Request, Self::Subscriber>> + Send;

        /// Cancel a subscriber's outstanding fetch interest.
        ///
        /// If this removes the last subscriber for a request and response
        /// validation is in progress, cancellation may drop the
        /// [`Consumer::deliver`] future before it reports whether the data was valid.
        fn cancel(&mut self, subscriber: Self::Subscriber) -> Feedback;

        /// Cancel all fetch requests.
        ///
        /// See [`cancel`](Self::cancel) for how cancellation affects
        /// in-progress response validation.
        fn clear(&mut self) -> Feedback;

        /// Retain only fetches with at least one subscriber satisfying the predicate.
        ///
        /// Fetches not retained are canceled. See [`cancel`](Self::cancel) for
        /// how cancellation affects in-progress response validation.
        fn retain(
            &mut self,
            predicate: impl Fn(&Self::Subscriber) -> bool + Send + 'static,
        ) -> Feedback;
    }
});

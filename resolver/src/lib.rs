//! Resolve data identified by a fixed-length key.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

commonware_macros::stability_scope!(BETA {
    use commonware_actor::Feedback;
    use commonware_cryptography::PublicKey;
    use commonware_utils::{vec::NonEmptyVec, Span};
    use std::future::Future;

    pub mod p2p;

    /// Notified when data is available, and must validate it.
    pub trait Consumer: Clone + Send + 'static {
        /// Type used to uniquely identify data.
        type Key: Span;

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
        fn deliver(
            &mut self,
            key: Self::Key,
            value: Self::Value,
        ) -> impl Future<Output = bool> + Send;
    }

    /// Responsible for fetching data and notifying a `Consumer`.
    pub trait Resolver: Clone + Send + 'static {
        /// Type used to uniquely identify data.
        type Key: Span;

        /// Type used to identify peers for targeted fetches.
        type PublicKey: PublicKey;

        /// Initiate a fetch request for a single key.
        fn fetch(&mut self, key: Self::Key) -> Feedback;

        /// Initiate a fetch request for a batch of keys.
        fn fetch_all(&mut self, keys: Vec<Self::Key>) -> Feedback;

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
        ) -> Feedback;

        /// Initiate fetch requests for multiple keys, each with their own targets.
        ///
        /// See [`fetch_targeted`](Self::fetch_targeted) for details on target behavior.
        fn fetch_all_targeted(
            &mut self,
            requests: Vec<(Self::Key, NonEmptyVec<Self::PublicKey>)>,
        ) -> Feedback;

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

        /// Retain only the fetch requests that satisfy the predicate.
        ///
        /// Fetches not retained are canceled. See [`cancel`](Self::cancel) for
        /// how cancellation affects in-progress response validation.
        fn retain(
            &mut self,
            predicate: impl Fn(&Self::Key) -> bool + Send + 'static,
        ) -> Feedback;
    }
});

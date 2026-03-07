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

    /// Controls how aggressively the resolver fans out fetch requests.
    ///
    /// A [`Regular`](RequestType::Regular) request tries the single best-performing
    /// peer and retries on failure. An [`Urgent`](RequestType::Urgent) request fans
    /// out the same request to every eligible peer simultaneously, maximizing the
    /// chance of a fast response at the cost of extra ingress.
    ///
    /// Urgency is tracked per key inside the resolver. A key can be upgraded from
    /// regular to urgent while in flight (the resolver will immediately re-dispatch
    /// to all peers), but is never downgraded. A key's urgent flag is cleared when
    /// that key's fetch completes or is canceled.
    ///
    /// Higher-level callers may need to remember which logical items are urgent
    /// independently, because a fetch that is "satisfied" by a related-but-different
    /// response (e.g. a higher-view notarization) will clear urgency in the resolver
    /// even though the original item may still be needed urgently if that response is
    /// later invalidated.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum RequestType {
        /// Try the best peer first and fall back through retries.
        Regular,
        /// Fan out immediately to every eligible peer and keep retrying urgently.
        Urgent,
    }

    /// Notified when data is available, and must validate it.
    pub trait Consumer: Clone + Send + 'static {
        /// Type used to uniquely identify data.
        type Key: Span;

        /// Type of data to retrieve.
        type Value;

        /// Type used to indicate why data is not available.
        type Failure;

        /// Deliver data to the consumer.
        ///
        /// Returns `true` if the data is valid.
        fn deliver(
            &mut self,
            key: Self::Key,
            value: Self::Value,
        ) -> impl Future<Output = bool> + Send;

        /// Let the consumer know that the data is not being fetched anymore.
        ///
        /// The failure is used to indicate why.
        fn failed(
            &mut self,
            key: Self::Key,
            failure: Self::Failure,
        ) -> impl Future<Output = ()> + Send;
    }

    /// Responsible for fetching data and notifying a `Consumer`.
    pub trait Resolver: Clone + Send + 'static {
        /// Type used to uniquely identify data.
        type Key: Span;

        /// Type used to identify peers for targeted fetches.
        type PublicKey: PublicKey;

        /// Initiate a regular fetch request for a single key.
        ///
        /// This is equivalent to calling [`fetch_with_type`](Self::fetch_with_type)
        /// with [`RequestType::Regular`].
        fn fetch(&mut self, key: Self::Key) -> impl Future<Output = ()> + Send {
            self.fetch_with_type(key, RequestType::Regular)
        }

        /// Initiate regular fetch requests for a batch of keys.
        ///
        /// This is equivalent to calling [`fetch_all_with_type`](Self::fetch_all_with_type)
        /// with [`RequestType::Regular`].
        fn fetch_all(&mut self, keys: Vec<Self::Key>) -> impl Future<Output = ()> + Send {
            self.fetch_all_with_type(keys, RequestType::Regular)
        }

        /// Initiate a fetch request with a specific request type.
        ///
        /// Requests can be upgraded from [`RequestType::Regular`] to [`RequestType::Urgent`]
        /// while in flight. Urgent requests are never downgraded until they resolve or
        /// are canceled.
        fn fetch_with_type(
            &mut self,
            key: Self::Key,
            request_type: RequestType,
        ) -> impl Future<Output = ()> + Send;

        /// Initiate a batch of fetch requests with the same request type.
        fn fetch_all_with_type(
            &mut self,
            keys: Vec<Self::Key>,
            request_type: RequestType,
        ) -> impl Future<Output = ()> + Send;

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
        fn cancel(&mut self, key: Self::Key) -> impl Future<Output = ()> + Send;

        /// Cancel all fetch requests.
        fn clear(&mut self) -> impl Future<Output = ()> + Send;

        /// Retain only the fetch requests that satisfy the predicate.
        fn retain(
            &mut self,
            predicate: impl Fn(&Self::Key) -> bool + Send + 'static,
        ) -> impl Future<Output = ()> + Send;
    }
});

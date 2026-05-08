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

    /// A dependency that kept a fetch active.
    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub enum FetchDependency<L> {
        /// The peer-visible request key itself kept the fetch active.
        Request,
        /// A separate local dependency kept the fetch active.
        Local(L),
    }

    impl<L> FetchDependency<L> {
        /// Return true if this is the peer-visible request dependency.
        pub const fn is_request(&self) -> bool {
            matches!(self, Self::Request)
        }

        /// Return the local dependency, if this is one.
        pub const fn local(&self) -> Option<&L> {
            match self {
                Self::Request => None,
                Self::Local(local) => Some(local),
            }
        }
    }

    /// Dependencies attached to a resolved fetch.
    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct Dependencies<K, L> {
        /// The peer-visible request key.
        pub request: K,
        /// Dependencies that kept the fetch active.
        pub dependencies: Vec<FetchDependency<L>>,
    }

    impl<K, L> Dependencies<K, L> {
        /// Create dependencies for an ordinary fetch.
        pub fn new(request: K) -> Self {
            Self {
                request,
                dependencies: vec![FetchDependency::Request],
            }
        }

        /// Create dependencies for a fetch with explicit dependencies.
        pub const fn with_dependencies(request: K, dependencies: Vec<FetchDependency<L>>) -> Self {
            Self {
                request,
                dependencies,
            }
        }

        /// Create dependencies for a fetch with local dependencies only.
        pub fn with_locals(request: K, locals: Vec<L>) -> Self {
            Self {
                request,
                dependencies: locals.into_iter().map(FetchDependency::Local).collect(),
            }
        }

        /// Create dependencies for a fetch with one local dependency.
        pub fn with_dependency(request: K, dependency: L) -> Self {
            Self::with_locals(request, vec![dependency])
        }

        /// Split into the peer-visible request and dependencies.
        pub fn into_parts(self) -> (K, Vec<FetchDependency<L>>) {
            (self.request, self.dependencies)
        }

        /// Return true if the request key itself kept the fetch active.
        pub fn has_request(&self) -> bool {
            self.dependencies.iter().any(FetchDependency::is_request)
        }

        /// Return the local dependencies.
        pub fn locals(&self) -> impl Iterator<Item = &L> {
            self.dependencies.iter().filter_map(FetchDependency::local)
        }

        /// Return the peer-visible request key.
        pub const fn request(&self) -> &K {
            &self.request
        }
    }

    impl<K, L> From<K> for Dependencies<K, L> {
        fn from(request: K) -> Self {
            Self::new(request)
        }
    }

    /// Notified when data is available, and must validate it.
    pub trait Consumer: Clone + Send + 'static {
        /// Type used to uniquely identify data.
        type Key: Span;

        /// Type used to track local dependencies on fetch requests.
        type Dependency: Clone + Send + 'static;

        /// Type of data to retrieve.
        type Value;

        /// Deliver data to the consumer.
        ///
        /// Returns `true` if the data is valid for the request and all of its
        /// dependencies.
        ///
        /// The returned future may be dropped before completion if the
        /// application cancels the fetch via [`Resolver::cancel`],
        /// [`Resolver::clear`], or [`Resolver::retain`]. When this happens,
        /// the resolver discards the validation result.
        ///
        /// Implementations of [`Resolver`] must only invoke `deliver` for keys that were
        /// previously requested via [`Resolver::fetch`] (or its variants).
        ///
        /// `dependencies` contains the peer-visible request key and the currently
        /// retained dependencies for the fetch. Ordinary fetches include a
        /// zero-payload [`FetchDependency::Request`] marker, avoiding a duplicate local
        /// key when the request key itself keeps the fetch active.
        fn deliver(
            &mut self,
            dependencies: Dependencies<Self::Key, Self::Dependency>,
            value: Self::Value,
        ) -> impl Future<Output = bool> + Send;
    }

    /// Responsible for fetching data and notifying a `Consumer`.
    pub trait Resolver: Clone + Send + 'static {
        /// Type used to uniquely identify data.
        type Key: Span;

        /// Type used to track local dependencies on fetch requests.
        ///
        /// Implementations that also own the [`Consumer`] should supply dependencies to
        /// [`Consumer::deliver`] when a fetch resolves.
        type Dependency: Clone + Send + 'static;

        /// Type used to identify peers for targeted fetches.
        type PublicKey: PublicKey;

        /// Initiate a fetch request.
        ///
        /// The resolver fetches and delivers the request key. Dependencies control
        /// whether the request is retained by [`retain`](Self::retain) and are also
        /// supplied to [`Consumer::deliver`] when the fetch resolves. If multiple
        /// dependencies are attached to the same request key, the fetch is retained
        /// as long as at least one dependency satisfies the predicate.
        ///
        /// Passing a bare key is equivalent to [`Dependencies::new`]. [`cancel`](Self::cancel)
        /// still cancels by request key.
        fn fetch<R>(
            &mut self,
            request: R,
        ) -> impl Future<Output = ()> + Send
        where
            R: Into<Dependencies<Self::Key, Self::Dependency>> + Send;

        /// Initiate a fetch request for a batch of requests.
        fn fetch_all<R>(&mut self, requests: Vec<R>) -> impl Future<Output = ()> + Send
        where
            R: Into<Dependencies<Self::Key, Self::Dependency>> + Send;

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
            request: impl Into<Dependencies<Self::Key, Self::Dependency>> + Send,
            targets: NonEmptyVec<Self::PublicKey>,
        ) -> impl Future<Output = ()> + Send;

        /// Initiate fetch requests for multiple requests, each with their own targets.
        ///
        /// See [`fetch_targeted`](Self::fetch_targeted) for details on target behavior.
        fn fetch_all_targeted<R>(
            &mut self,
            requests: Vec<(R, NonEmptyVec<Self::PublicKey>)>,
        ) -> impl Future<Output = ()> + Send
        where
            R: Into<Dependencies<Self::Key, Self::Dependency>> + Send;

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

        /// Retain only the fetch requests with at least one dependency satisfying the predicate.
        ///
        /// Fetches not retained are canceled. See [`cancel`](Self::cancel) for
        /// how cancellation affects in-progress response validation.
        fn retain(
            &mut self,
            predicate: impl Fn(&Self::Dependency) -> bool + Send + 'static,
        ) -> impl Future<Output = ()> + Send;
    }
});

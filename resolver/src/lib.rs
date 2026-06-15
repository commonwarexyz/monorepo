//! Resolve data identified by a fixed-length key.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

commonware_macros::stability_scope!(BETA {
    use commonware_actor::Feedback;
    use commonware_cryptography::PublicKey;
    use commonware_utils::{channel::oneshot, vec::NonEmptyVec, Span};

    pub mod delivery;
    mod ingress;
    pub mod opaque;
    pub mod p2p;
    mod subscribers;

    /// A key to fetch data for a subscriber.
    #[derive(Clone, Debug)]
    pub struct Fetch<K, S = ()> {
        /// The peer-visible key.
        pub key: K,
        /// Subscriber attached to the key.
        pub subscriber: S,
        /// Trace span carried from issuance to delivery.
        ///
        /// The resolver retains this span with the subscriber and re-attaches it
        /// to that subscriber in [`Delivery`] when the fetch resolves, so consumer
        /// work nests under the span that requested it.
        pub span: tracing::Span,
    }

    impl<K, S: Default> From<K> for Fetch<K, S> {
        fn from(key: K) -> Self {
            Self {
                key,
                subscriber: S::default(),
                span: tracing::Span::none(),
            }
        }
    }

    /// Data delivered for a resolved fetch.
    #[derive(Clone, Debug)]
    pub struct Delivery<K, S> {
        /// The peer-visible key used to validate the response.
        pub key: K,
        /// Subscribers that were still retained when the response arrived, each
        /// paired with the trace span of the fetch that requested it.
        ///
        /// Consumer work for a subscriber nests under that subscriber's span, so
        /// every requester observes the resolution of its own fetch.
        pub subscribers: NonEmptyVec<(S, tracing::Span)>,
    }

    impl<K: PartialEq, S: PartialEq> PartialEq for Delivery<K, S> {
        fn eq(&self, other: &Self) -> bool {
            self.key == other.key
                && self.subscribers.len() == other.subscribers.len()
                && self
                    .subscribers
                    .iter()
                    .zip(other.subscribers.iter())
                    .all(|((a, _), (b, _))| a == b)
        }
    }

    impl<K: Eq, S: Eq> Eq for Delivery<K, S> {}

    /// Notified when data is available, and must validate it.
    pub trait Consumer: Clone + Send + 'static {
        /// Type used to key data requested from peers.
        type Key: Span;

        /// Type of data to retrieve.
        type Value;

        /// Type used to track subscribers on fetch keys.
        type Subscriber: Clone + Eq + Send + 'static;

        /// Deliver data to the consumer.
        ///
        /// Returns a receiver that resolves to `true` if the data is valid for the key.
        ///
        /// The returned receiver may be dropped before completion if the application
        /// cancels the fetch via [`Resolver::retain`]. When this happens, the
        /// resolver discards the validation result.
        ///
        /// Implementations of [`Resolver`] must only invoke `deliver` for keys that were
        /// previously requested via [`Resolver::fetch`] (or [`TargetedResolver`] variants).
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

    /// Extension for resolvers that accept target peer hints.
    pub trait TargetedResolver: Resolver {
        /// Type used to identify peers for targeted fetch hints.
        type PublicKey: PublicKey;

        /// Initiate a fetch with target peer hints.
        ///
        /// Implementations define whether target hints persist through retries,
        /// merge with existing in-progress fetches, or are discarded.
        fn fetch_targeted(
            &mut self,
            fetch: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
            targets: NonEmptyVec<Self::PublicKey>,
        ) -> Feedback;

        /// Initiate fetches for multiple keys, each with their own target hints.
        ///
        /// See [`fetch_targeted`](Self::fetch_targeted) for details on target behavior.
        fn fetch_all_targeted<F>(
            &mut self,
            keys: Vec<(F, NonEmptyVec<Self::PublicKey>)>,
        ) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send;
    }
});

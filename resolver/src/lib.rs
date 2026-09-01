//! Resolve data identified by a fixed-length key.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

commonware_macros::stability_scope!(BETA {
    use commonware_actor::Feedback;
    use commonware_cryptography::PublicKey;
    use commonware_utils::{Span, channel::oneshot, vec::NonEmptyVec};
    use core::cmp::Ordering;

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
        pub span: tracing::Span,
    }

    impl<K: PartialEq, S: PartialEq> PartialEq for Fetch<K, S> {
        fn eq(&self, other: &Self) -> bool {
            self.key == other.key && self.subscriber == other.subscriber
        }
    }

    impl<K: Eq, S: Eq> Eq for Fetch<K, S> {}

    impl<K: PartialOrd, S: PartialOrd> PartialOrd for Fetch<K, S> {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            match self.key.partial_cmp(&other.key)? {
                Ordering::Equal => self.subscriber.partial_cmp(&other.subscriber),
                ordering => Some(ordering),
            }
        }
    }

    impl<K: Ord, S: Ord> Ord for Fetch<K, S> {
        fn cmp(&self, other: &Self) -> Ordering {
            self.key
                .cmp(&other.key)
                .then_with(|| self.subscriber.cmp(&other.subscriber))
        }
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

    impl<K: PartialOrd, S: PartialOrd> PartialOrd for Delivery<K, S> {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            match self.key.partial_cmp(&other.key)? {
                Ordering::Equal => self
                    .subscribers
                    .iter()
                    .map(|(subscriber, _)| subscriber)
                    .partial_cmp(other.subscribers.iter().map(|(subscriber, _)| subscriber)),
                ordering => Some(ordering),
            }
        }
    }

    impl<K: Ord, S: Ord> Ord for Delivery<K, S> {
        fn cmp(&self, other: &Self) -> Ordering {
            self.key.cmp(&other.key).then_with(|| {
                self.subscribers
                    .iter()
                    .map(|(subscriber, _)| subscriber)
                    .cmp(other.subscribers.iter().map(|(subscriber, _)| subscriber))
            })
        }
    }

    /// Consumer disposition for a delivered response.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Outcome {
        /// The response is invalid for the peer-visible key.
        ///
        /// Network resolvers may penalize the serving peer before retrying, and
        /// retire a fetch left with no peer that could serve it.
        Invalid,

        /// The response is valid and satisfies every delivered subscriber.
        Complete,

        /// The peer-visible key admits multiple valid responses, and this response does not
        /// satisfy every delivered subscriber.
        ///
        /// The resolver retries the key without penalizing the serving peer so another response
        /// can be tried.
        Ambiguous,

        /// The consumer no longer needs the key, so the response does not need to be validated.
        ///
        /// The resolver retires the key and all of its subscribers without retrying or
        /// attributing the response to its source.
        Ignored,
    }

    impl From<bool> for Outcome {
        fn from(valid: bool) -> Self {
            if valid { Self::Complete } else { Self::Invalid }
        }
    }

    /// Determines the disposition of data returned for a fetch.
    pub trait Consumer: Clone + Send + 'static {
        /// Type used to key data requested from peers.
        type Key: Span;

        /// Type of data to retrieve.
        type Value;

        /// Type used to track subscribers on fetch keys.
        type Subscriber: Clone + Eq + Send + 'static;

        /// Delivery disposition returned after validation.
        ///
        /// Consumers that only distinguish valid and invalid data may use
        /// `bool`, which maps to [`crate::Outcome::Complete`] and
        /// [`crate::Outcome::Invalid`].
        type Outcome: Into<crate::Outcome> + Send + 'static;

        /// Deliver data to the consumer.
        ///
        /// Returns a receiver that reports whether the response completes the
        /// delivery, is invalid, is valid but leaves subscribers unresolved, or
        /// can be ignored because the key is no longer needed.
        ///
        /// The returned receiver may be dropped before completion if the application
        /// cancels the fetch via [`Resolver::retain`]. When this happens, the
        /// resolver discards the validation result.
        ///
        /// If the consumer drops the sender without reporting a verdict, the
        /// response is handed to any subscribers that joined after this delivery
        /// was snapshotted, and the key is retired without penalizing its source
        /// once no subscribers remain. The subscribers in the dropped delivery are
        /// not retried.
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
        ) -> oneshot::Receiver<Self::Outcome>;
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
        fn fetch<F>(&mut self, key: F) -> Feedback
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

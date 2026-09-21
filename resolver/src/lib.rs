//! Resolve data identified by a fixed-length key.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

commonware_macros::stability_scope!(BETA {
    use commonware_actor::Feedback;
    use commonware_cryptography::PublicKey;
    use commonware_utils::{Span, channel::mpsc, vec::NonEmptyVec};
    use std::{fmt, future::Future, time::Duration};

    pub mod delivery;
    mod ingress;
    pub mod opaque;
    pub mod p2p;
    mod subscribers;
    mod response;

    pub use response::{ChannelConsumer, Response};

    // Idle sources and consumers need not produce another event after callers leave.
    pub(crate) const RECLAIM_INTERVAL: Duration = Duration::from_secs(1);

    /// A fetch whose demand lasts while its response receiver remains open.
    pub struct Fetch<K, S, R> {
        /// The peer-visible key.
        pub key: K,
        /// Local metadata describing the demand.
        pub subscriber: S,
        /// Channel through which the consumer responds to this demand.
        pub response: mpsc::Sender<R>,
        /// Trace span carried from issuance to delivery.
        pub span: tracing::Span,
    }

    impl<K: Clone, S: Clone, R> Clone for Fetch<K, S, R> {
        fn clone(&self) -> Self {
            Self {
                key: self.key.clone(),
                subscriber: self.subscriber.clone(),
                response: self.response.clone(),
                span: self.span.clone(),
            }
        }
    }

    impl<K: fmt::Debug, S: fmt::Debug, R> fmt::Debug for Fetch<K, S, R> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Fetch")
                .field("key", &self.key)
                .field("subscriber", &self.subscriber)
                .field("response", &self.response)
                .finish_non_exhaustive()
        }
    }

    impl<K: PartialEq, S: PartialEq, R> PartialEq for Fetch<K, S, R> {
        fn eq(&self, other: &Self) -> bool {
            self.key == other.key
                && self.subscriber == other.subscriber
                && self.response.same_channel(&other.response)
        }
    }
    impl<K: Eq, S: Eq, R> Eq for Fetch<K, S, R> {}

    /// A response route and its local demand metadata.
    ///
    /// Equal metadata on different channels identifies independent callers.
    pub struct Subscriber<S, R> {
        /// Local metadata describing the demand.
        pub subscriber: S,
        /// Channel through which the consumer responds.
        pub response: mpsc::Sender<R>,
        /// Trace span of the fetch that introduced this demand.
        pub span: tracing::Span,
    }

    impl<S: Clone, R> Clone for Subscriber<S, R> {
        fn clone(&self) -> Self {
            Self {
                subscriber: self.subscriber.clone(),
                response: self.response.clone(),
                span: self.span.clone(),
            }
        }
    }
    impl<S: fmt::Debug, R> fmt::Debug for Subscriber<S, R> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Subscriber")
                .field("subscriber", &self.subscriber)
                .field("response", &self.response)
                .finish_non_exhaustive()
        }
    }
    impl<S: PartialEq, R> PartialEq for Subscriber<S, R> {
        fn eq(&self, other: &Self) -> bool {
            self.subscriber == other.subscriber && self.response.same_channel(&other.response)
        }
    }
    impl<S: Eq, R> Eq for Subscriber<S, R> {}

    /// The exact response routes included in one consumer delivery.
    pub struct Delivery<K, S, R> {
        /// The peer-visible key used to validate the response.
        pub key: K,
        /// Demand that was open when this delivery began.
        pub subscribers: NonEmptyVec<Subscriber<S, R>>,
    }
    impl<K: Clone, S: Clone, R> Clone for Delivery<K, S, R> {
        fn clone(&self) -> Self {
            Self {
                key: self.key.clone(),
                subscribers: self.subscribers.clone(),
            }
        }
    }
    impl<K: fmt::Debug, S: fmt::Debug, R> fmt::Debug for Delivery<K, S, R> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Delivery")
                .field("key", &self.key)
                .field("subscribers", &self.subscribers)
                .finish()
        }
    }
    impl<K: PartialEq, S: PartialEq, R> PartialEq for Delivery<K, S, R> {
        fn eq(&self, other: &Self) -> bool {
            self.key == other.key && self.subscribers == other.subscribers
        }
    }
    impl<K: Eq, S: Eq, R> Eq for Delivery<K, S, R> {}

    /// Consumer disposition for a delivered response.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Outcome {
        /// The response is invalid for the peer-visible key.
        ///
        /// Network resolvers may penalize the serving peer before retrying.
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

        /// Response sent to the caller.
        type Response: Send + 'static;

        /// Delivery disposition returned after validation.
        ///
        /// Consumers that only distinguish valid and invalid data may use
        /// `bool`, which maps to [`crate::Outcome::Complete`] and
        /// [`crate::Outcome::Invalid`].
        type Outcome: Into<crate::Outcome> + Send + 'static;

        /// Deliver one response for the supplied demand snapshot.
        ///
        /// The resolver may drop the returned future when all delivered receivers
        /// close. A surviving later caller can receive the cached value in a new
        /// delivery. Returning `None` leaves this response unjudged and retires
        /// only the supplied snapshot, without penalizing its source.
        ///
        /// Only previously requested keys may be delivered. Subscribers describe
        /// local demand. Validity is determined by the peer-visible key.
        fn deliver(
            &mut self,
            delivery: Delivery<Self::Key, Self::Subscriber, Self::Response>,
            value: Self::Value,
        ) -> impl Future<Output = Option<Self::Outcome>> + Send + 'static;
    }

    /// Fetches data while the caller keeps its response receiver open.
    ///
    /// Closing a receiver cancels only its request. Cancellation is asynchronous,
    /// so a fetch attempt may already be in progress when it takes effect.
    pub trait Resolver: Clone + Send + 'static {
        /// Type used to key data requested from peers.
        type Key: Span;
        /// Local demand metadata.
        type Subscriber: Clone + Eq + Send + 'static;
        /// Response produced by the consumer.
        type Response: Send + 'static;

        /// Initiate a fetch. Reusing the same channel and metadata updates existing demand.
        ///
        /// Keep the receiver open through rejected candidates until the request is
        /// satisfied or no longer needed. The feedback reports mailbox admission.
        fn fetch<F>(&mut self, fetch: F) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber, Self::Response>> + Send;

        /// Initiate a batch of fetches.
        fn fetch_all<F>(&mut self, fetches: Vec<F>) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber, Self::Response>> + Send;
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
            fetch: impl Into<Fetch<Self::Key, Self::Subscriber, Self::Response>> + Send,
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
            F: Into<Fetch<Self::Key, Self::Subscriber, Self::Response>> + Send;
    }
});

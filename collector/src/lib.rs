//! Collect responses to [Committable] requests.
//!
//! # Status
//!
//! Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

commonware_macros::stability_scope!(BETA {
    use commonware_actor::Feedback;
    use commonware_codec::Codec;
    use commonware_cryptography::{Committable, PublicKey};
    use commonware_p2p::Recipients;
    use commonware_utils::channel::oneshot;

    pub mod p2p;

    /// An [Originator] sends requests to a set of [Handler]s.
    ///
    /// Requests with the same commitment join one collection, and a [Monitor] receives the
    /// responses collected for it.
    pub trait Originator: Clone + Send + 'static {
        /// The [PublicKey] of a recipient.
        type PublicKey: PublicKey;

        /// The type of request to send.
        type Request: Committable + Codec;

        /// Enqueues `request` for a set of [Recipients]. Each recipient the request is sent to
        /// joins the collection for its commitment. [Feedback] indicates whether the request was
        /// accepted for processing, not whether any recipient received it.
        fn send(
            &mut self,
            recipients: Recipients<Self::PublicKey>,
            request: Self::Request,
        ) -> Feedback;

        /// Enqueues cancellation of the collection for `commitment`.
        ///
        /// A collection lasts until it is cancelled. Responses for `commitment` are then ignored
        /// until it is sent again, and sending it again starts a new collection.
        fn cancel(&mut self, commitment: <Self::Request as Committable>::Commitment) -> Feedback;
    }

    /// A [Handler] receives requests and may send responses.
    pub trait Handler: Clone + Send + 'static {
        /// The [PublicKey] of the [Originator].
        type PublicKey: PublicKey;

        /// The type of request received.
        type Request: Committable + Codec;

        /// The type of response to send.
        ///
        /// A response must have the commitment of the request it answers.
        type Response: Committable<Commitment = <Self::Request as Committable>::Commitment> + Codec;

        /// Processes a `request` from an [Originator] and returns the receiver of its response.
        ///
        /// `process` must return promptly. A handler that cannot answer yet sends the response
        /// later, and a handler that declines the request drops the sender.
        fn process(
            &mut self,
            origin: Self::PublicKey,
            request: Self::Request,
        ) -> oneshot::Receiver<Self::Response>;
    }

    /// A [Monitor] receives the responses collected from [Handler]s.
    pub trait Monitor: Clone + Send + 'static {
        /// The [PublicKey] of the [Handler].
        type PublicKey: PublicKey;

        /// The type of response collected.
        type Response: Committable + Codec;

        /// Receives a `response` collected from `handler`. A collection yields at most one response
        /// per `handler`, and `count` is the number of handlers that have responded in the
        /// collection, whether or not their responses are valid. `collected` must return promptly.
        fn collected(&mut self, handler: Self::PublicKey, response: Self::Response, count: usize);
    }
});

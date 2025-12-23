//! Collect responses to [Committable] requests.
//!
//! # Status
//!
//! `commonware-collector` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use commonware_codec::Codec;
use commonware_cryptography::{Committable, Digestible, PublicKey};
use commonware_p2p::Recipients;
use futures::channel::oneshot;
use std::future::Future;
use thiserror::Error;

pub mod p2p;

/// Errors that can occur when interacting with a [Originator].
#[derive(Error, Debug)]
pub enum Error {
    #[error("send failed: {0}")]
    SendFailed(anyhow::Error),
    #[error("canceled")]
    Canceled,
}

/// An [Originator] sends requests out to a set of [Handler]s and collects replies.
pub trait Originator: Clone + Send + 'static {
    /// The [PublicKey] of a recipient.
    type PublicKey: PublicKey;

    /// The type of request to send.
    type Request: Committable + Digestible + Codec;

    /// Sends a `Request` to a set of [Recipients], returning the list of handlers that we
    /// tried to send to.
    fn send(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
        request: Self::Request,
    ) -> impl Future<Output = Result<Vec<Self::PublicKey>, Error>> + Send;

    /// Cancel a request by `commitment`, ignoring any future responses.
    ///
    /// Tracked commitments are not removed until explicitly cancelled.
    fn cancel(
        &mut self,
        commitment: <Self::Request as Committable>::Commitment,
    ) -> impl Future<Output = ()> + Send;
}

/// A [Handler] receives requests and (optionally) sends replies.
pub trait Handler: Clone + Send + 'static {
    /// The [PublicKey] of the [Originator].
    type PublicKey: PublicKey;

    /// The type of request received.
    type Request: Committable + Digestible + Codec;

    /// The type of response to send.
    type Response: Committable<Commitment = <Self::Request as Committable>::Commitment>
        + Digestible<Digest = <Self::Request as Digestible>::Digest>
        + Codec;

    /// Processes a `request` from an [Originator] and (optionally) send a response.
    ///
    /// If no response is needed, the `responder` should be dropped.
    fn process(
        &mut self,
        origin: Self::PublicKey,
        request: Self::Request,
        response: oneshot::Sender<Self::Response>,
    ) -> impl Future<Output = ()> + Send;
}

/// A [Monitor] collects responses from [Handler]s.
pub trait Monitor: Clone + Send + 'static {
    /// The [PublicKey] of the [Handler].
    type PublicKey: PublicKey;

    /// The type of response collected.
    type Response: Committable + Digestible + Codec;

    /// Called for each response collected with the number of responses collected so far for
    /// the same commitment.
    ///
    /// [Monitor::collected] is only called once per `handler`.
    fn collected(
        &mut self,
        handler: Self::PublicKey,
        response: Self::Response,
        count: usize,
    ) -> impl Future<Output = ()> + Send;
}

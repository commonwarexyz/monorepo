//! An [Originator] sends requests out to a set of [Endpoint]s and collects responses.
//!
//! The originator's [Collector] is used to distribute and collect responses.
//! The endpoint's [Collector] is used to receive and respond to requests.

use commonware_cryptography::{Committable, Digestible, PublicKey};
use commonware_p2p::Recipients;
use futures::channel::oneshot;
use std::{fmt::Debug, future::Future};

pub mod actor;

/// Interface for actor that will disperse requests and collect responses.
pub trait Originator: Clone + Send + 'static {
    type Request: Committable + Digestible + Debug + Send + 'static;
    type Response: Committable<Commitment = <Self::Request as Committable>::Commitment>
        + Digestible<Digest = <Self::Request as Digestible>::Digest>
        + Debug
        + Send
        + 'static;
    type PublicKey: PublicKey;

    /// Sends a `request` to a set of `recipients`, returning the list of recipients that were
    /// successfully sent to.
    ///
    /// Once a quorum of responses have been collected, the [Originator] will be notified.
    fn send(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
        request: Self::Request,
    ) -> impl Future<Output = Vec<Self::PublicKey>> + Send;

    /// Cancels a request by `digest`, dropping all existing and future responses.
    fn cancel(
        &mut self,
        commitment: <Self::Request as Committable>::Commitment,
    ) -> impl Future<Output = ()> + Send;
}

/// Interface for the application that receives requests from an origin and sends responses.
pub trait Handler: Clone + Send + 'static {
    type Request: Committable + Digestible + Debug + Send + 'static;
    type Response: Committable<Commitment = <Self::Request as Committable>::Commitment>
        + Digestible<Digest = <Self::Request as Digestible>::Digest>
        + Debug
        + Send
        + 'static;
    type PublicKey: PublicKey;

    /// Processes a `request` from `origin` and (optionally) sends a response.
    ///
    /// If no response is needed, the `responder` should be dropped.
    fn process(
        &mut self,
        origin: Self::PublicKey,
        request: Self::Request,
        response: oneshot::Sender<Self::Response>,
    ) -> impl Future<Output = ()> + Send;
}

/// Interface for the application that originates requests.
pub trait Monitor: Clone + Send + 'static {
    type Response: Committable + Digestible + Debug + Send + 'static;
    type PublicKey: PublicKey;

    /// Called for each response once `minimum` responses have been collected for a commitment.
    fn collected(
        &mut self,
        origin: Self::PublicKey,
        response: Self::Response,
        count: usize,
    ) -> impl Future<Output = ()> + Send;
}

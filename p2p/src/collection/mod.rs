//! An [Originator] sends requests out to a set of [Endpoint]s and collects responses.
//!
//! The originator's [Collector] is used to distribute and collect responses.
//! The endpoint's [Collector] is used to receive and respond to requests.

use crate::Recipients;
use commonware_cryptography::{Committable, Digest, Digestible, PublicKey};
use futures::channel::oneshot;
use std::{collections::HashMap, fmt::Debug, future::Future};

pub mod actor;

/// Interface for actor that will disperse requests and collect responses.
pub trait Collector<D: Digest>: Clone + Send + 'static {
    type Request: Committable + Digestible<Digest = D> + Debug + Send + 'static;
    type Response: Digestible<Digest = D> + Debug + Send + 'static;
    type PublicKey: PublicKey;

    /// Sends a `request` to a set of `recipients`, returning the list of recipients that were
    /// successfully sent to.
    ///
    /// Once a quorum of responses have been collected, the [Originator] will be notified.
    fn send(
        &mut self,
        request: Self::Request,
        recipients: Recipients<Self::PublicKey>,
    ) -> impl Future<Output = Vec<Self::PublicKey>> + Send;

    /// Peek at the collected responses for a given `digest`.
    ///
    /// Returns [None] if the request is not being collected.
    fn peek(
        &mut self,
        digest: D,
    ) -> impl Future<Output = Option<HashMap<Self::PublicKey, Self::Response>>> + Send;

    /// Cancels a request by `digest`, dropping all existing and future responses.
    fn cancel(&mut self, digest: D) -> impl Future<Output = ()> + Send;
}

/// Interface for the application that originates requests.
pub trait Originator<D: Digest>: Clone + Send + 'static {
    type PublicKey: PublicKey;
    type Response: Digestible<Digest = D> + Debug + Send + 'static;

    /// Called once a quorum of `responses` have been collected for a request.
    fn collected(
        &mut self,
        id: D,
        responses: HashMap<Self::PublicKey, Self::Response>,
    ) -> impl Future<Output = ()> + Send;
}

/// Interface for the application that receives requests from an origin and sends responses.
pub trait Endpoint<D: Digest>: Clone + Send + 'static {
    type Request: Committable + Digestible<Digest = D> + Debug + Send + 'static;
    type Response: Digestible<Digest = D> + Debug + Send + 'static;
    type PublicKey: PublicKey;

    /// Processes a `request` from `origin` and (optionally) sends a response.
    ///
    /// If no response is needed, the `responder` should be dropped.
    fn process(
        &mut self,
        origin: Self::PublicKey,
        request: Self::Request,
        responder: oneshot::Sender<Self::Response>,
    ) -> impl Future<Output = ()> + Send;
}

//! An [Originator] sends messages out to a set of [Endpoint]s and collects responses.
//!
//! The originator's [Collector] is used to distribute and collect responses.
//! The endpoint's [Collector] is used to receive and respond to messages.

use bytes::Bytes;
use commonware_cryptography::PublicKey;
use futures::channel::oneshot;
use std::{collections::HashMap, fmt::Debug, future::Future};

pub mod actor;

/// Trait for an item that has an associated, unique ID.
pub trait Idable: Clone + Send + 'static {
    type ID: Debug + Send + 'static;

    /// Returns the unique ID of the item.
    fn id(&self) -> Self::ID;
}

/// Interface for actor that will disperse messages and collect responses.
pub trait Collector: Clone + Send + 'static {
    type Message: Idable + Debug + Send + 'static;
    type PublicKey: PublicKey;

    /// Sends a message to recipients.
    ///
    /// Once a quorum of responses have been collected, the [Originator] will be notified.
    fn send(
        &mut self,
        message: Self::Message,
        transformer: fn(Self::Message, Self::PublicKey) -> Bytes,
    ) -> impl Future<Output = ()> + Send;

    /// Peek at the collected responses for a given ID.
    fn peek(
        &mut self,
        id: <Self::Message as Idable>::ID,
    ) -> impl Future<Output = oneshot::Receiver<HashMap<Self::PublicKey, Bytes>>> + Send;

    /// Cancels a message, dropping all existing and future responses.
    fn cancel(&mut self, id: <Self::Message as Idable>::ID) -> impl Future<Output = ()> + Send;
}

/// Interface for the application that originates messages.
pub trait Originator: Clone + Send + 'static {
    type PublicKey: PublicKey;
    type ID: Debug + Send + 'static;

    /// Called once a sufficient amount of responses have been collected for a message.
    fn collected(
        &mut self,
        id: Self::ID,
        responses: HashMap<Self::PublicKey, Bytes>,
    ) -> impl Future<Output = ()> + Send;
}

/// Interface for the application that receives messages from an origin.
pub trait Endpoint: Clone + Send + 'static {
    type Message: Idable + Debug + Send + 'static;

    /// Processes a message and (optionally) sends a response.
    ///
    /// If no response is needed, the response sender should be dropped.
    fn process(
        &mut self,
        message: Self::Message,
        response: oneshot::Sender<Bytes>,
    ) -> impl Future<Output = ()> + Send;
}

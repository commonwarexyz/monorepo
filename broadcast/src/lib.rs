//! Replication of messages across a network.

use std::future::Future;

use bytes::Bytes;
use commonware_cryptography::Digest;
use futures::channel::oneshot;
use thiserror::Error;

pub mod linked;

/// Errors that can occur when interacting with a stream.
#[derive(Error, Debug)]
pub enum Error {
    #[error("Protobuf decode error")]
    UnableToDecode,
    #[error("Duplicate ack")]
    DuplicateAck,
    #[error("Conflicting ack")]
    ConflictingAck,
    #[error("Unable to create threshold signature")]
    ThresholdSignature,
    #[error("Unknown signer")]
    UnknownSigner,
    #[error("Mailbox error")]
    MailboxError,
}

/// A trait for reliable replication of messages across a network.
pub trait Broadcaster {
    type Context;

    /// Broadcast a message to the network.
    fn broadcast(&mut self, payload: Bytes)
        -> impl Future<Output = oneshot::Receiver<bool>> + Send;
}

/// Application is the interface responsible for processing messages received from the network.
pub trait Application: Clone + Send + 'static {
    /// Context is metadata provided by the broadcast engine to associated with a given payload.
    /// This includes things like the sequencer, height, parent, etc.
    type Context;

    // Proof is the proof of broadcast.
    // This may be something like a threshold signature.
    type Proof;

    /// Verify and store (long-term storage) a proposed payload received from the network.
    ///
    /// If it is possible to verify the payload, a boolean should be returned indicating whether
    /// the payload is valid. If it is not possible to verify the payload, the channel can be dropped.
    fn verify(
        &mut self,
        context: Self::Context,
        payload: Digest,
    ) -> impl Future<Output = oneshot::Receiver<bool>> + Send;

    /// Event that a payload has been successfully broadcasted to a threshold of signers in the network.
    fn broadcasted(
        &mut self,
        context: Self::Context,
        payload: Digest,
        proof: Self::Proof,
    ) -> impl Future<Output = ()> + Send;
}

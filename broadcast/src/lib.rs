//! Replication of messages across a network.

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
}

/// A trait for reliable replication of messages across a network.
pub trait Broadcast {
    // TODO
}

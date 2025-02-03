//! Replication of messages across a network.

use std::future::Future;

use bytes::Bytes;
use commonware_cryptography::PublicKey;
use futures::channel::oneshot;
use thiserror::Error;

pub mod linked;

pub type Proof = Bytes;

/// Errors that can occur when interacting with a stream.
#[derive(Error, Debug)]
pub enum Error {
    #[error("Duplicate ack")]
    DuplicateAck,
    #[error("Unable to create threshold signature")]
    ThresholdSignature,
    #[error("Unknown signer")]
    UnknownSigner,
    #[error("Chunk height {0} lower than tip height {1}")]
    HeightTooLow(u64, u64),

    // Application Verify Errors
    #[error("Application verify dropped")]
    ApplicationVerifyDropped,
    #[error("Application verify failed")]
    ApplicationVerifyFailed,

    // Application Verified Errors
    #[error("Application verified no tip")]
    AppVerifiedNoTip,
    #[error("Application verified height mismatch")]
    AppVerifiedHeightMismatch,
    #[error("Application verified payload mismatch")]
    AppVerifiedPayloadMismatch,

    // P2P Errors
    #[error("Unable to send message")]
    UnableToSendMessage,

    // Broadcast errors
    #[error("I am not a sequencer in epoch {0}")]
    IAmNotASequencer(u64),
    #[error("Nothing to rebroadcast")]
    NothingToRebroadcast,
    #[error("Broadcast failed")]
    BroadcastFailed,
    #[error("No threshold for tip")]
    NoThresholdForTip(u64),

    // Proto Malformed Errors
    #[error("Protobuf decode error")]
    UnableToDecode,
    #[error("Missing chunk")]
    MissingChunk,
    #[error("Genesis chunk must not have a parent")]
    GenesisChunkMustNotHaveParent,
    #[error("Link missing parent")]
    LinkMissingParent,
    #[error("Invalid digest")]
    InvalidDigest,

    // Epoch Errors
    #[error("Unknown identity at epoch {0}")]
    UnknownIdentity(u64),
    #[error("Unknown signers at epoch {0}")]
    UnknownSigners(u64),
    #[error("Unknown signer index {0} at epoch {1}")]
    UnknownSignerIndex(u32, u64),
    #[error("Epoch {0} has no sequencer {1:?}")]
    UnknownSequencer(u64, Bytes),
    #[error("Unknown share at epoch {0}")]
    UnknownShare(u64),

    // Peer Errors
    #[error("Peer mismatch")]
    PeerMismatch,

    // Signature Errors
    #[error("Unable to deserialize threshold signature")]
    UnableToDeserializeThresholdSignature,
    #[error("Unable to deserialize partial signature")]
    UnableToDeserializePartialSignature,
    #[error("Invalid threshold signature")]
    InvalidThresholdSignature,
    #[error("Invalid partial signature")]
    InvalidPartialSignature,
    #[error("Invalid link signature")]
    InvalidLinkSignature,

    // Ignorable Message Errors
    #[error("Invalid ack epoch {0} outside bounds {1} - {2}")]
    AckEpochOutsideBounds(u64, u64, u64),
    #[error("Invalid ack height {0} outside bounds {1} - {2}")]
    AckHeightOutsideBounds(u64, u64, u64),
    #[error("Threshold already exists")]
    ThresholdAlreadyExists,
    #[error("Partial already exists")]
    PartialAlreadyExists,

    // Slashable Errors
    #[error("Chunk mismatch from sender {0:?} with height {1}")]
    ChunkMismatch(Bytes, u64),
}

/// A trait for reliable replication of messages across a network.
pub trait Broadcaster {
    type Context;
    type Digest;

    /// Broadcast a message to the network.
    fn broadcast(
        &mut self,
        payload: Self::Digest,
    ) -> impl Future<Output = oneshot::Receiver<bool>> + Send;

    /// Receive notice that a payload is valid.
    fn verified(
        &mut self,
        context: Self::Context,
        payload_digest: Self::Digest,
    ) -> impl Future<Output = ()> + Send;
}

/// Application is the interface responsible for processing messages received from the network.
pub trait Application: Send + 'static {
    /// Context is metadata provided by the broadcast engine to associated with a given payload.
    /// This includes things like the sequencer, height, parent, etc.
    type Context;

    type Digest;

    /// Verify and store (long-term storage) a proposed payload received from the network.
    ///
    /// If it is possible to verify the payload, a boolean should be returned indicating whether
    /// the payload is valid. If it is not possible to verify the payload, the channel can be dropped.
    fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> impl Future<Output = ()> + Send;
}

pub trait Collector: Send + 'static {
    type Context;
    type Digest;

    /// Event that a payload has been successfully broadcasted to a threshold of signers in the network.
    fn acknowledged(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
        proof: Proof,
    ) -> impl Future<Output = ()> + Send;
}

pub trait Coordinator: Clone + Send + Sync + 'static {
    type Index;

    /// Return the current index of the coordinator.
    fn index(&self) -> Self::Index;

    fn sequencers(&self, index: Self::Index) -> Option<&Vec<PublicKey>>;
    fn is_sequencer(&self, index: Self::Index, candidate: &PublicKey) -> Option<u32>;

    fn signers(&self, index: Self::Index) -> Option<&Vec<PublicKey>>;
    fn is_signer(&self, index: Self::Index, candidate: &PublicKey) -> Option<u32>;
}

pub trait ThresholdCoordinator: Coordinator {
    type Identity;
    type Share;

    /// Return the polynomial of the given index.
    fn identity(&self, index: Self::Index) -> Option<&Self::Identity>;

    /// Return my share of the polynomial of the given index.
    fn share(&self, index: Self::Index) -> Option<&Self::Share>;
}

//! Disseminate data over a wide-area network.

use bytes::Bytes;
use commonware_cryptography::Digest;
use commonware_utils::Array;
use futures::channel::oneshot;
use std::future::Future;

/// Proof is a blob that attests to some data.
pub type Proof = Bytes;

/// Broadcaster is the interface responsible for replication of messages across a network.
pub trait Broadcaster: Clone + Send + 'static {
    /// Digest is an arbitrary hash digest.
    type Digest: Digest;

    /// Attempt to broadcast a digest to the network.
    ///
    /// Returns a future that resolves to a boolean indicating success.
    /// The broadcast may fail for a variety of reasons such-as networking errors, the node not
    /// being a valid sequencer, or the Broadcaster not being ready to broadcast a new payload.
    fn broadcast(
        &mut self,
        payload: Self::Digest,
    ) -> impl Future<Output = oneshot::Receiver<bool>> + Send;
}

/// Application is the interface responsible for processing messages received from the network.
pub trait Application: Clone + Send + 'static {
    /// Context is metadata provided by the broadcast engine to associated with a given payload.
    /// This could include things like the public key of the sequencer.
    type Context;

    /// Digest is an arbitrary hash digest.
    type Digest: Array;

    /// Verify a proposed payload received from the network.
    ///
    /// Returns a future that resolves to a boolean indicating success.
    /// Part of verification requires ensuring that the data is made available.
    /// For example, by storing it in a database.
    fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> impl Future<Output = oneshot::Receiver<bool>> + Send;
}

/// Collector is the interface responsible for handling notifications of broadcasted payloads.
pub trait Collector: Clone + Send + 'static {
    /// Digest is an arbitrary hash digest.
    type Digest: Digest;

    /// Emit that a payload has been successfully broadcasted.
    /// This is used to acknowledge that the payload has been "received" by the network,
    /// for example that it has been successfully gossiped to a threshold of validators.
    fn acknowledged(
        &mut self,
        proof: Proof,
        payload: Self::Digest,
    ) -> impl Future<Output = ()> + Send;
}

/// Coordinator is the interface responsible for managing the active set of sequencers and signers.
///
/// It is up to the user to ensure changes in this list are synchronized across nodes in the network
/// at a given `Index`. Otherwise, "acknowledgement" of a payload by the network may be delayed or never occur.
pub trait Coordinator: Clone + Send + Sync + 'static {
    /// Index is the type used to identify a particular set of sequencers and signers.
    type Index;

    /// PublicKey is the type used to identify a sequencer or signer.
    type PublicKey: Array;

    /// Returns the current index of the coordinator.
    fn index(&self) -> Self::Index;

    /// Get the **sorted** sequencers for the given `Index`.
    fn sequencers(&self, index: Self::Index) -> Option<&Vec<Self::PublicKey>>;

    /// Returns the index of the sequencer (in the list of sorted sequencers) if the candidate is a sequencer at the given `Index`.
    fn is_sequencer(&self, index: Self::Index, candidate: &Self::PublicKey) -> Option<u32>;

    /// Get the **sorted** signers for the given `Index`.
    fn signers(&self, index: Self::Index) -> Option<&Vec<Self::PublicKey>>;

    /// Returns the index of the signer (in the list of sorted signers) if the candidate is a signer at the given `Index`.
    fn is_signer(&self, index: Self::Index, candidate: &Self::PublicKey) -> Option<u32>;
}

/// ThresholdCoordinator is the interface responsible for managing which `identity` (typically a group polynomial with
/// a fixed constant factor) and `share` for a signer is active at a given time.
pub trait ThresholdCoordinator: Coordinator {
    /// Identity is the type against which partial signatures are verified.
    type Identity;

    /// Share is the type used to generate a partial signature that can be verified
    /// against `Identity`.
    type Share;

    /// Returns the identity (typically a group polynomial with a fixed constant factor)
    /// at the given index. This is used to verify partial signatures from participants
    /// enumerated in `Coordinator::signers`.
    fn identity(&self, index: Self::Index) -> Option<&Self::Identity>;

    /// Returns share to sign with at a given index. After resharing, the share
    /// may change (and old shares may be deleted).
    fn share(&self, index: Self::Index) -> Option<&Self::Share>;
}

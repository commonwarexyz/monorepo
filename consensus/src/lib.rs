//! TBD

pub mod authority;

use bytes::Bytes;
use commonware_cryptography::{Digest, PublicKey};
use std::future::Future;

/// Byte array representing the externally-provided payload of a container.
pub type Payload = Bytes;

/// Automaton is the interface for the consensus engine to inform of progress.
///
/// While an automaton may be logically instantiated as a single entity, it may be
/// cloned by multiple sub-components of a consensus engine to, among other things,
/// parse payloads concurrently.
pub trait Automaton: Clone + Send + 'static {
    type Context;

    /// Initialize the application with the genesis container at view=0, height=0.
    fn genesis(&mut self) -> (Payload, Digest);

    /// Generate a new payload for the given parent digest.
    ///
    /// If state is not yet ready, this will return None.
    fn propose(&mut self, context: Self::Context) -> impl Future<Output = Option<Payload>> + Send;

    /// Parse the payload and return the digest of the payload. We don't just digest
    /// the payload because it may be more efficient to prove against a digest
    /// that is specifically formatted (like a trie root).
    ///
    /// Parse is a stateless operation and may be called out-of-order.
    fn parse(&mut self, payload: Payload) -> impl Future<Output = Option<Digest>> + Send;

    /// Verify the payload is valid.
    ///
    /// Verify is a stateful operation and must be called in-order. Automatons should
    /// maintain a mapping of containers to payloads to handle invocations from the
    /// `Finalizer`.
    fn verify(
        &mut self,
        context: Self::Context,
        payload: Payload,
        container: Digest,
    ) -> impl Future<Output = bool> + Send;
}

/// Faults are specified by the underlying primitive and can be interpreted if desired (not
/// interpreting just means all faults would be treated equally).
///
/// Various consensus implementations may want to reward participation in different ways. For example,
/// validators could be required to send multiple types of messages (i.e. vote and finalize) and rewarding
/// both equally may better align incentives with desired behavior.
pub type Activity = u8;
pub type Proof = Bytes;

pub trait Supervisor: Clone + Send + 'static {
    type Index;

    /// Get the **sorted** participants for the given view. This is called when entering a new view before
    /// listening for proposals or votes. If nothing is returned, the view will not be entered.
    ///
    /// It is up to the developer to ensure changes to this list are synchronized across nodes in the network
    /// at a given view. If care is not taken to do this, the chain could fork/halt. If using an underlying
    /// consensus implementation that does not require finalization of a height before producing a container
    /// at the next height (asynchronous finalization), a synchrony bound should be enforced around
    /// changes to the set (i.e. participant joining in view 10 should only become active in view 20, where
    /// we assume all other participants have finalized view 10).
    fn participants(&self, index: Self::Index) -> Option<&Vec<PublicKey>>;

    // Indicate whether a PublicKey is a participant at the given view.
    fn is_participant(&self, index: Self::Index, candidate: &PublicKey) -> Option<bool>;

    /// Report a contribution to the application that can be externally proven.
    ///
    /// To get more information about the contribution, the proof can be decoded.
    ///
    /// The consensus instance may report a duplicate contribution.
    fn report(&mut self, activity: Activity, proof: Proof) -> impl Future<Output = ()> + Send;
}

pub trait Finalizer: Clone + Send + 'static {
    /// Event that the container has been prepared.
    ///
    /// No guarantee will send notarized event for all heights.
    fn prepared(&mut self, container: Digest) -> impl Future<Output = ()> + Send;

    /// Event that the container has been finalized.
    fn finalized(&mut self, container: Digest) -> impl Future<Output = ()> + Send;
}

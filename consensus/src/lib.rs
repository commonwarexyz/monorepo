//! TBD
//!
//! Focused on linear consensus protocols that can support concurrent proposals via `broadcast`.

use bytes::Bytes;
use commonware_cryptography::{Digest, PublicKey};
use std::future::Future;

/// Header contains information specific to consensus that can be used, among other things,
/// to verify that a given container was signed by some participant at some height.
type Header = Bytes;

/// Automaton is the interface for the consensus engine to inform of progress.
///
/// While an automaton may be logically instantiated as a single entity, it may be
/// cloned by multiple sub-components of a consensus engine to, among other things,
/// parse payloads concurrently.
pub trait Automaton: Clone + Send + 'static {
    type Context;

    /// Initialize the application with the genesis container.
    fn genesis(&mut self) -> Digest;

    /// Generate a new payload for the given context.
    ///
    /// If it is possible to generate a payload, the `Automaton` should call `Mailbox::proposed`.
    fn propose(&mut self, context: Self::Context) -> impl Future<Output = ()> + Send;

    /// Called once consensus locks on a proposal. At this point the application can
    /// broadcast the raw contents to the network with the given consensus header.
    ///
    /// It is up to the developer to efficiently handle broadcast to the rest of the network.
    fn broadcast(
        &mut self,
        context: Self::Context,
        header: Header,
        payload: Digest,
    ) -> impl Future<Output = ()> + Send;

    /// Verify the payload is valid.
    ///
    /// If `Mailbox::verified` is called with this payload, the consensus will vote to support
    /// the payload. If the payload has not been received or describes an invalid payload, the consensus
    /// instance should not be notified using `Mailbox::verified`.
    fn verify(
        &mut self,
        context: Self::Context,
        payload: Digest,
    ) -> impl Future<Output = ()> + Send;
}

/// Mailbox is implemented by the consensus engine to receive messages from the Automaton.
pub trait Mailbox: Clone + Send + 'static {
    type Context;

    /// Proposed is called after a payload is constructed.
    ///
    /// If the `Context` is no longer active/relevant, this will be dropped.
    fn proposed(
        &mut self,
        context: Self::Context,
        payload: Digest,
    ) -> impl Future<Output = ()> + Send;

    /// Verified is called after a payload is verified.
    fn verified(
        &mut self,
        context: Self::Context,
        payload: Digest,
    ) -> impl Future<Output = ()> + Send;
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
    type Seed;

    /// Get the leader at a given index for the provided seed.
    fn leader(&self, index: Self::Index, seed: Self::Seed) -> Option<PublicKey>;

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
    type Context;

    /// Event that the container has been prepared.
    ///
    /// No guarantee will send notarized event for all heights.
    fn prepared(
        &mut self,
        context: Self::Context,
        payload: Digest,
    ) -> impl Future<Output = ()> + Send;

    /// Event that the container has been finalized.
    fn finalized(
        &mut self,
        context: Self::Context,
        payload: Digest,
    ) -> impl Future<Output = ()> + Send;
}

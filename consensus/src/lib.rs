//! TBD
//!
//! Focused on linear consensus protocols that can support concurrent proposals via `broadcast`.

pub mod authority;

use bytes::Bytes;
use commonware_cryptography::{Digest, PublicKey};
use std::future::Future;

/// Automaton is the interface for the consensus engine to inform of progress.
///
/// While an automaton may be logically instantiated as a single entity, it may be
/// cloned by multiple sub-components of a consensus engine to, among other things,
/// broadcast and verify payloads.
pub trait Automaton: Send + 'static {
    type Context;

    /// Initialize the application with the genesis container.
    fn genesis(&mut self) -> Digest;

    /// Generate a new payload for the given context.
    ///
    /// If it is possible to generate a payload, the `Automaton` should call `Mailbox::proposed`.
    ///
    /// Payload should stand alone and not require any additional context to be verified from the wire.
    ///
    /// TODO: if parent payload digest is provided in propose, we no longer need to actually have
    /// the parent to build on it (useful if already notarized). This is really nice for chains
    /// that store the "tip" of some subprocess in the block rather than the chain content itself. It is
    /// ultimately still up to the "Automaton" to decide how to handle this (the linking to parent digests
    /// could be some sort of tree that requires much more prior knowledge).
    fn propose(&mut self, context: Self::Context) -> impl Future<Output = Digest> + Send;

    /// Verify the payload is valid.
    ///
    /// If `Mailbox::verified` is called with this payload, the consensus will vote to support
    /// the payload.
    ///
    /// If the payload has not been received or describes an invalid payload, the consensus
    /// instance should not be notified using `Mailbox::verified`.
    ///
    /// TODO: if we really want to go crazy, we should not verify and just try to agree here and just
    /// ask for hashes that can be reconciled later? Output of threshold signature for a given agreement
    /// is then useless? TL;DR my job is to agree on a single digest at a given view, nothing else.
    /// -> Can do lagging threshold signatures over verified state at a given height?
    ///
    /// "Stop doing so much, don't be a hero."
    ///
    /// This approach would allow you to just "push what you know" into a log and then handle any issues
    /// with it after the fact.
    ///
    /// Can concurrently sync from multiple heights by using multiple notarizations (historical)
    fn verify(
        &mut self,
        context: Self::Context,
        payload: Digest,
    ) -> impl Future<Output = bool> + Send;
}

/// Indication that a digest should be disseminated to other participants.
pub trait Relay: Send + 'static {
    /// Called once consensus locks on a proposal. At this point the application can
    /// broadcast the raw contents to the network with the given consensus header (which
    /// references the payload).
    ///
    /// It is up to the developer to efficiently handle broadcast/backfill to/from the rest of the network.
    ///
    /// TODO: how to know what digests might be useful? If it is just opaque bytes, its difficult
    /// to optimistically cache when listening to messages from peers. Could just keep latest proposal digest
    /// per peer sent to us (and answer any verification requests with that digest...how would we do more complex
    /// broadcast).
    fn broadcast(&mut self, payload: Digest) -> impl Future<Output = ()> + Send;
}

pub trait Finalizer: Send + 'static {
    /// Event that the container has been notarized (seen by `2f+1` participants).
    ///
    /// No guarantee will send notarized event for all heights.
    fn notarized(&mut self, payload: Digest) -> impl Future<Output = ()> + Send;

    /// Event that the container has been finalized.
    fn finalized(&mut self, payload: Digest) -> impl Future<Output = ()> + Send;
}

/// Faults are specified by the underlying primitive and can be interpreted if desired (not
/// interpreting just means all faults would be treated equally).
///
/// Various consensus implementations may want to reward participation in different ways. For example,
/// validators could be required to send multiple types of messages (i.e. vote and finalize) and rewarding
/// both equally may better align incentives with desired behavior.
pub type Activity = u8;
pub type Proof = Bytes;

// TODO: should supervisor be managed by consensus? Other than PoA, the consensus usually keeps track of (and updates)
// who is participating, not some external service. If we did this, we could also remove clone from Application?
//
// Rationale not to: application needs to interpret the "reporting" of activity in some way to determine uptime/penalties
// and it isn't clear how this could be sent back to the consensus application?
pub trait Supervisor: Clone + Send + 'static {
    type Index;
    type Seed;

    /// Get the leader at a given index for the provided seed (sourced from consensus).
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
    fn report(&self, activity: Activity, proof: Proof) -> impl Future<Output = ()> + Send;
}

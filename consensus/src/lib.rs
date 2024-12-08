//! Order opaque messages in a Byzantine environment.
//!
//! # Status
//!
//! `commonware-consensus` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

use bytes::Bytes;
use commonware_cryptography::{Digest, PublicKey};
use futures::channel::oneshot;
use std::future::Future;

pub mod authority;

/// Automaton is the interface responsible for driving the consensus forward by proposing new payloads
/// and verifying payloads proposed by other participants.
pub trait Automaton: Clone + Send + 'static {
    /// Context is metadata provided by the consensus engine to associated with a given payload.
    ///
    /// This often includes things like the proposer, view number, the height, or the epoch.
    type Context;

    /// Payload used to initialize the consensus engine.
    fn genesis(&mut self) -> impl Future<Output = Digest> + Send;

    /// Generate a new payload for the given context.
    ///
    /// If it is possible to generate a payload, the Digest should be returned over the provided
    /// channel. If it is not possible to generate a payload, the channel can be dropped.
    ///
    /// If construction takes too long, the consensus engine may drop the provided proposal.
    fn propose(
        &mut self,
        context: Self::Context,
    ) -> impl Future<Output = oneshot::Receiver<Digest>> + Send;

    /// Verify the payload is valid.
    ///
    /// If it is possible to verify the payload, a boolean should be returned indicating whether
    /// the payload is valid. If it is not possible to verify the payload, the channel can be dropped.
    fn verify(
        &mut self,
        context: Self::Context,
        payload: Digest,
    ) -> impl Future<Output = oneshot::Receiver<bool>> + Send;
}

/// Relay is the interface responsible for broadcasting payloads to the network.
///
/// The consensus engine is only aware of a payload's digest, not its contents. It is up
/// to the relay to efficiently broadcast the full payload to other participants.
pub trait Relay: Clone + Send + 'static {
    /// Called once consensus begins working towards a proposal provided by `Automaton` (i.e.
    /// it isn't dropped).
    ///
    /// Other participants may not begin voting on a proposal until they have the full contents,
    /// so timely delivery often yields better performance.
    fn broadcast(&mut self, payload: Digest) -> impl Future<Output = ()> + Send;
}

/// Proof is a blob that attests to some data.
pub type Proof = Bytes;

/// Committer is the interface responsible for handling notifications of payload status.
pub trait Committer: Clone + Send + 'static {
    /// Event that the container has been prepared (indicating some progress towards finalization
    /// but not guaranteeing it will occur).
    ///
    /// No guarantee will send prepared event for all heights.
    fn prepared(&mut self, proof: Proof, payload: Digest) -> impl Future<Output = ()> + Send;

    /// Event that the container has been finalized.
    fn finalized(&mut self, proof: Proof, payload: Digest) -> impl Future<Output = ()> + Send;
}

/// Faults are specified by the underlying primitive and can be interpreted if desired (not
/// interpreting just means all faults would be treated equally).
///
/// Various consensus implementations may want to reward participation in different ways. For example,
/// validators could be required to send multiple types of messages (i.e. vote and finalize) and rewarding
/// both equally may better align incentives with desired behavior.
pub type Activity = u8;

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
    fn is_participant(&self, index: Self::Index, candidate: &PublicKey) -> Option<u32>;

    /// Report a contribution to the application that can be externally proven.
    ///
    /// To get more information about the contribution, the proof can be decoded.
    ///
    /// The consensus instance may report a duplicate contribution.
    fn report(&self, activity: Activity, proof: Proof) -> impl Future<Output = ()> + Send;
}

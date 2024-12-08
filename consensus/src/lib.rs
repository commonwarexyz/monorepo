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

pub mod simplex;

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
    /// channel. If it is not possible to generate a payload, the channel can be dropped. If construction
    /// takes too long, the consensus engine may drop the provided proposal.
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
    /// Event that a payload has made some progress towards finalization but is not yet finalized.
    ///
    /// This is often used to provide an early ("best guess") confirmation to users.
    fn prepared(&mut self, proof: Proof, payload: Digest) -> impl Future<Output = ()> + Send;

    /// Event indicating the container has been finalized.
    fn finalized(&mut self, proof: Proof, payload: Digest) -> impl Future<Output = ()> + Send;
}

/// Activity is specified by the underlying consensus implementation and can be interpreted if desired.
///
/// Examples of activity would be "vote", "finalize", or "fault". Various consensus implementations may
/// want to reward (or penalize) participation in different ways and in different places. For example,
/// validators could be required to send multiple types of messages (i.e. vote and finalize) and rewarding
/// both equally may better align incentives with desired behavior.
pub type Activity = u8;

/// Supervisor is the interface responsible for managing which participants are active at a given time.
pub trait Supervisor: Clone + Send + 'static {
    /// Index is the type used to indicate the in-progress consensus decision.
    type Index;

    /// Seed is a consensus artifact to use as randomness for leader selection.
    type Seed;

    /// Return the leader at a given index for the provided seed.
    fn leader(&self, index: Self::Index, seed: Self::Seed) -> Option<PublicKey>;

    /// Get the **sorted** participants for the given view. This is called when entering a new view before
    /// listening for proposals or votes. If nothing is returned, the view will not be entered.
    ///
    /// It is up to the user to ensure changes in this list are synchronized across nodes in the network
    /// at a given `Index`. If care is not taken to do this, consensus could halt (as different participants
    /// may have a different view of who is active at a given time). The simplest way to avoid this complexity
    /// is to use a consensus implementation that reaches finalization on application data before transitioning
    /// to a new `Index` (i.e. [Tendermint](https://arxiv.org/abs/1807.04938)). Implementations that do not work
    /// this way (like `simplex`) must introduce some synchrony bound for changes (where it is assumed all participants
    /// have finalized some previous set change by some point) or "sync points" (i.e. epochs) where participants
    /// agree that some finalization occurred at some point in the past.
    fn participants(&self, index: Self::Index) -> Option<&Vec<PublicKey>>;

    // Indicate whether some candidate is a participant at the given view.
    fn is_participant(&self, index: Self::Index, candidate: &PublicKey) -> Option<u32>;

    /// Report some activity observed by the consensus implementation.
    fn report(&self, activity: Activity, proof: Proof) -> impl Future<Output = ()> + Send;
}

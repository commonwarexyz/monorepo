//! Order opaque messages in a Byzantine environment.
//!
//! # Status
//!
//! `commonware-consensus` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use commonware_codec::Codec;
use commonware_cryptography::{Committable, Digestible};

pub mod aggregation;
pub mod ordered_broadcast;
pub mod simplex;
pub mod threshold_simplex;

/// Viewable is a trait that provides access to the view (round) number.
/// Any consensus message or object that is associated with a specific view should implement this.
pub trait Viewable {
    /// View is the type used to indicate the in-progress consensus decision.
    type View;

    /// Returns the view associated with this object.
    fn view(&self) -> Self::View;
}

/// Block is the interface for a block in the blockchain.
///
/// Blocks are used to track the progress of the consensus engine.
pub trait Block: Codec + Digestible + Committable + Send + Sync + 'static {
    /// Get the height of the block.
    fn height(&self) -> u64;

    /// Get the parent block's digest.
    fn parent(&self) -> Self::Commitment;
}

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        use commonware_cryptography::{Digest, PublicKey};
        use futures::channel::{oneshot, mpsc};
        use std::future::Future;

        pub mod marshal;
        mod reporter;
        pub use reporter::*;

        /// Histogram buckets for measuring consensus latency.
        const LATENCY: [f64; 36] = [
            0.05, 0.1, 0.125, 0.15, 0.16, 0.17, 0.18, 0.19, 0.2, 0.21, 0.22, 0.23, 0.24, 0.25, 0.26, 0.27, 0.28, 0.29, 0.3, 0.31, 0.32, 0.33, 0.34, 0.35,
            0.36, 0.37, 0.38, 0.39, 0.4, 0.45, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
        ];

        /// Automaton is the interface responsible for driving the consensus forward by proposing new payloads
        /// and verifying payloads proposed by other participants.
        pub trait Automaton: Clone + Send + 'static {
            /// Context is metadata provided by the consensus engine associated with a given payload.
            ///
            /// This often includes things like the proposer, view number, the height, or the epoch.
            type Context;

            /// Hash of an arbitrary payload.
            type Digest: Digest;

            /// Payload used to initialize the consensus engine.
            fn genesis(&mut self) -> impl Future<Output = Self::Digest> + Send;

            /// Generate a new payload for the given context.
            ///
            /// If it is possible to generate a payload, the Digest should be returned over the provided
            /// channel. If it is not possible to generate a payload, the channel can be dropped. If construction
            /// takes too long, the consensus engine may drop the provided proposal.
            fn propose(
                &mut self,
                context: Self::Context,
            ) -> impl Future<Output = oneshot::Receiver<Self::Digest>> + Send;

            /// Verify the payload is valid.
            ///
            /// If it is possible to verify the payload, a boolean should be returned indicating whether
            /// the payload is valid. If it is not possible to verify the payload, the channel can be dropped.
            fn verify(
                &mut self,
                context: Self::Context,
                payload: Self::Digest,
            ) -> impl Future<Output = oneshot::Receiver<bool>> + Send;
        }

        /// Relay is the interface responsible for broadcasting payloads to the network.
        ///
        /// The consensus engine is only aware of a payload's digest, not its contents. It is up
        /// to the relay to efficiently broadcast the full payload to other participants.
        pub trait Relay: Clone + Send + 'static {
            /// Hash of an arbitrary payload.
            type Digest: Digest;

            /// Called once consensus begins working towards a proposal provided by `Automaton` (i.e.
            /// it isn't dropped).
            ///
            /// Other participants may not begin voting on a proposal until they have the full contents,
            /// so timely delivery often yields better performance.
            fn broadcast(&mut self, payload: Self::Digest) -> impl Future<Output = ()> + Send;
        }

        /// Reporter is the interface responsible for reporting activity to some external actor.
        pub trait Reporter: Clone + Send + 'static {
            /// Activity is specified by the underlying consensus implementation and can be interpreted if desired.
            ///
            /// Examples of activity would be "vote", "finalize", or "fault". Various consensus implementations may
            /// want to reward (or penalize) participation in different ways and in different places. For example,
            /// validators could be required to send multiple types of messages (i.e. vote and finalize) and rewarding
            /// both equally may better align incentives with desired behavior.
            type Activity;

            /// Report some activity observed by the consensus implementation.
            fn report(&mut self, activity: Self::Activity) -> impl Future<Output = ()> + Send;
        }

        /// Supervisor is the interface responsible for managing which participants are active at a given time.
        ///
        /// ## Synchronization
        ///
        /// It is up to the user to ensure changes in this list are synchronized across nodes in the network
        /// at a given `Index`. If care is not taken to do this, consensus could halt (as different participants
        /// may have a different view of who is active at a given time).
        ///
        /// The simplest way to avoid this complexity is to use a consensus implementation that reaches finalization
        /// on application data before transitioning to a new `Index` (i.e. [Tendermint](https://arxiv.org/abs/1807.04938)).
        ///
        /// Implementations that do not work this way (like `simplex`) must introduce some synchrony bound for changes
        /// (where it is assumed all participants have finalized some previous set change by some point) or "sync points"
        /// (i.e. epochs) where participants agree that some finalization occurred at some point in the past.
        pub trait Supervisor: Clone + Send + Sync + 'static {
            /// Index is the type used to indicate the in-progress consensus decision.
            type Index;

            /// Public key used to identify participants.
            type PublicKey: PublicKey;

            /// Return the leader at a given index for the provided seed.
            fn leader(&self, index: Self::Index) -> Option<Self::PublicKey>;

            /// Get the **sorted** participants for the given view. This is called when entering a new view before
            /// listening for proposals or votes. If nothing is returned, the view will not be entered.
            fn participants(&self, index: Self::Index) -> Option<&Vec<Self::PublicKey>>;

            // Indicate whether some candidate is a participant at the given view.
            fn is_participant(&self, index: Self::Index, candidate: &Self::PublicKey) -> Option<u32>;
        }

        /// ThresholdSupervisor is the interface responsible for managing which `polynomial` (typically a polynomial with
        /// a fixed constant `identity`) and `share` for a participant is active at a given time.
        ///
        /// ## Synchronization
        ///
        /// The same considerations for [crate::Supervisor] apply here.
        pub trait ThresholdSupervisor: Supervisor {
            /// Identity is the type against which threshold signatures are verified.
            type Identity;

            /// Seed is some random value used to bias the leader selection process.
            type Seed;

            /// Polynomial is the group polynomial over which partial signatures are verified.
            type Polynomial;

            /// Share is the type used to generate a partial signature that can be verified
            /// against `Identity`.
            type Share;

            /// Returns the static identity of the shared secret (typically the constant term
            /// of a polynomial).
            fn identity(&self) -> &Self::Identity;

            /// Return the leader at a given index over the provided seed.
            fn leader(&self, index: Self::Index, seed: Self::Seed) -> Option<Self::PublicKey>;

            /// Returns the polynomial over which partial signatures are verified at a given index.
            fn polynomial(&self, index: Self::Index) -> Option<&Self::Polynomial>;

            /// Returns share to sign with at a given index. After resharing, the share
            /// may change (and old shares may be deleted).
            ///
            /// This can be used to generate a partial signature that can be verified
            /// against `polynomial`.
            fn share(&self, index: Self::Index) -> Option<&Self::Share>;
        }

        /// Monitor is the interface an external actor can use to observe the progress of a consensus implementation.
        ///
        /// Monitor is used to implement mechanisms that share the same set of active participants as consensus and/or
        /// perform some activity that requires some synchronization with the progress of consensus.
        ///
        /// Monitor can be implemented using [crate::Reporter] to avoid introducing complexity
        /// into any particular consensus implementation.
        pub trait Monitor: Clone + Send + 'static {
            /// Index is the type used to indicate the in-progress consensus decision.
            type Index;

            /// Create a channel that will receive updates when the latest index (also provided) changes.
            fn subscribe(&mut self) -> impl Future<Output = (Self::Index, mpsc::Receiver<Self::Index>)> + Send;
        }
    }
}

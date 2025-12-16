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
pub mod types;
pub mod utils;

use types::{Epoch, View};

/// Epochable is a trait that provides access to the epoch number.
/// Any consensus message or object that is associated with a specific epoch should implement this.
pub trait Epochable {
    /// Returns the epoch associated with this object.
    fn epoch(&self) -> Epoch;
}

/// Viewable is a trait that provides access to the view (round) number.
/// Any consensus message or object that is associated with a specific view should implement this.
pub trait Viewable {
    /// Returns the view associated with this object.
    fn view(&self) -> View;
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
        use commonware_cryptography::Digest;
        use futures::channel::{oneshot, mpsc};
        use std::future::Future;
        use commonware_runtime::{Spawner, Metrics, Clock};
        use rand::Rng;
        use crate::marshal::ingress::mailbox::AncestorStream;
        use commonware_cryptography::certificate::Scheme;

        pub mod application;
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
            fn genesis(&mut self, epoch: Epoch) -> impl Future<Output = Self::Digest> + Send;

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

        /// Application is a minimal interface for standard implementations that operate over a stream
        /// of epoched blocks.
        pub trait Application<E>: Clone + Send + 'static
        where
            E: Rng + Spawner + Metrics + Clock
        {
            /// The signing scheme used by the application.
            type SigningScheme: Scheme;

            /// Context is metadata provided by the consensus engine associated with a given payload.
            ///
            /// This often includes things like the proposer, view number, the height, or the epoch.
            type Context: Epochable;

            /// The block type produced by the application's builder.
            type Block: Block;

            /// Payload used to initialize the consensus engine in the first epoch.
            fn genesis(&mut self) -> impl Future<Output = Self::Block> + Send;

            /// Build a new block on top of the provided parent ancestry. If the build job fails,
            /// the implementor should return [None].
            fn propose(
                &mut self,
                context: (E, Self::Context),
                ancestry: AncestorStream<Self::SigningScheme, Self::Block>,
            ) -> impl Future<Output = Option<Self::Block>> + Send;
        }

        /// An extension of [Application] that provides the ability to implementations to verify blocks.
        ///
        /// Some [Application]s may not require this functionality. When employing
        /// erasure coding, for example, verification only serves to verify the integrity of the
        /// received shard relative to the consensus commitment, and can therefore be
        /// hidden from the application.
        pub trait VerifyingApplication<E>: Application<E>
        where
            E: Rng + Spawner + Metrics + Clock
        {
            /// Verify a block produced by the application's proposer, relative to its ancestry.
            fn verify(
                &mut self,
                context: (E, Self::Context),
                ancestry: AncestorStream<Self::SigningScheme, Self::Block>,
            ) -> impl Future<Output = bool> + Send;
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

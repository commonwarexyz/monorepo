//! Execute a finalized stream of inputs into a chain of blocks.
//!
//! A consensus engine's marshal delivers finalized blocks, the inputs, in order, each at the next
//! index of its stream. The [`Executor`] runs an [`Execute`] application over that stream and
//! produces exactly one block per input: the block at height `i` executes the input at index `i`.
//! An input that fails in context still yields a block, one that records why and leaves state
//! unchanged. The executed chain is therefore the finalized stream itself, and a block's height is
//! its input's index.
//!
//! Consumers of the executed chain, such as [`stateful`](crate::stateful), receive each block as a
//! [`Finalized`] item and read the chain through the engine-neutral [`Ledger`] and [`Linear`]
//! traits the executor's [`Mailbox`] implements. Nothing downstream names the engine.
//!
//! # Durability
//!
//! For each input, in order, the executor:
//!
//! 1. executes it on top of the executed chain and checks the block's height, parent, and input;
//! 2. archives the block and delivers it to the consumer;
//! 3. once the consumer acknowledges the block, makes the archive and its applied cursor durable,
//!    and only then acknowledges the input to marshal.
//!
//! Marshal redelivers every input above the applied cursor after a crash, because it was never
//! acknowledged. The executor executes each again, checks that the block equals the archived one,
//! and delivers it again, so a consumer sees every block at least once, in order, and always after
//! the executor produced it in the current process. A mismatch means execution is not
//! deterministic and halts the executor.
//!
//! Execution runs ahead of acknowledgement, bounded by marshal's acknowledgement window. Inputs
//! are handed to the application as they arrive and are never stored; the executor stores only
//! the executed chain and its applied cursor.
//!
//! # Checkpoints
//!
//! [`Checkpoints`] connects the executed chain to [`aggregation`], which certifies the digest of
//! every `interval`-th block with the validators' signatures. A certificate lets a node that
//! state-syncs trust a block, and the state it commits to, without executing the chain below it.
//! The executor keeps the newest certified block, and the inputs after it, from being pruned, and
//! halts once honest validators certify a block it did not execute. It prunes nothing before a
//! checkpoint is certified, so a node must run aggregation over its executed chain to bound its
//! storage and to serve peers that state-sync.
//!
//! [`aggregation`]: commonware_consensus::aggregation
//! [`Finalized`]: commonware_consensus::marshal::Finalized
//! [`Ledger`]: commonware_consensus::marshal::Ledger
//! [`Linear`]: commonware_consensus::marshal::Linear

use commonware_consensus::{
    Block,
    ancestry::Ancestry,
    types::{Epoch, Height},
};
use commonware_cryptography::{Digest, Digestible};
use commonware_runtime::{Clock, Metrics, Spawner};
use rand_core::Rng;
use std::{future::Future, sync::Arc};

mod actor;
pub use actor::{Config, Executor};
mod checkpoints;
pub use checkpoints::Checkpoints;
mod mailbox;
pub use mailbox::{Inbox, Mailbox};
mod store;
pub use store::StoreConfig;

#[cfg(test)]
mod tests;

/// Where an input sits in the finalized stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context<D: Digest> {
    /// The epoch the input was finalized in.
    pub epoch: Epoch,
    /// The height the executed block must have: the input's index in the finalized stream.
    pub height: Height,
    /// The input's digest.
    pub input: D,
}

/// A block produced by executing an input.
///
/// A block's digest must commit to its height, its parent, and its input, so that a certificate
/// over the digest covers the whole executed chain below it.
pub trait Executed<D: Digest>: Block {
    /// Returns the digest of the input this block executed, or `None` for the genesis block.
    fn input(&self) -> Option<D>;
}

/// Deterministic execution of a finalized stream of inputs into a chain of blocks.
pub trait Execute<E>: Clone + Send + 'static
where
    E: Rng + Spawner + Metrics + Clock,
{
    /// The finalized block the consensus engine ordered.
    ///
    /// Its height is its height in its own chain, which is not its place in the stream on every
    /// engine; [`Context::height`] is.
    type Input: Block;

    /// The block execution produces.
    type Block: Executed<<Self::Input as Digestible>::Digest>;

    /// Returns the block at height zero, which precedes every input.
    fn genesis(&mut self) -> impl Future<Output = Self::Block> + Send;

    /// Called once, before the first execution, with the block execution resumes from: the
    /// newest block the consumer applied, or the genesis block of an empty chain.
    ///
    /// Every later execution builds on this block or one of its descendants.
    fn resume(&mut self, _tip: Arc<Self::Block>) {}

    /// Executes `input` on top of `ancestry`, the executed chain newest first starting at the
    /// block at `context.height - 1`, and returns the block at `context.height`.
    ///
    /// The result is final: every honest node returns the same block for the same ancestry and
    /// input, and an input that is invalid in this context yields a block that records the
    /// rejection and leaves state unchanged. The result may depend only on the ancestry, the
    /// input, and state they determine, never on clocks, local configuration, or data that could
    /// differ between nodes. The future may stay pending only for data guaranteed to arrive,
    /// because a finalized input cannot be skipped. The executor may ask again after a crash, and
    /// halts if the answer differs.
    fn execute(
        &mut self,
        context: (E, Context<<Self::Input as Digestible>::Digest>),
        ancestry: impl Ancestry<Self::Block>,
        input: Arc<Self::Input>,
    ) -> impl Future<Output = Self::Block> + Send;
}

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
//! After a crash, marshal redelivers inputs from its own acknowledgement floor, which is at or
//! below the applied cursor. The executor acknowledges each input at or below the cursor once it
//! checks the input against the archived block, and executes each input above it again, checks
//! that the block equals the archived one, and delivers it again. A consumer therefore sees every
//! block at least once, in order, and always after the executor produced it in the current
//! process. A mismatch means execution is not deterministic and halts the executor.
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
//! halts once a checkpoint certifies a block it did not execute, or once more validators than can
//! be faulty sign one. It prunes nothing before a checkpoint is certified, so a node must run
//! aggregation over its executed chain to bound its storage and to serve peers that state-sync.
//!
//! # State Sync
//!
//! An executor configured with [`Start::Checkpoint`] and an empty chain executes nothing until it
//! has a base. It waits for a block a checkpoint certifies, offered through [`Mailbox::sync_to`],
//! durably persists it as its target, and has the application sync its state to it through
//! [`Execute::sync`]. Newer offers move the target forward while the sync runs. The block the sync
//! reaches becomes the base: the executor archives it as applied, acknowledges every input at or
//! below it without executing them, and executes the inputs after it.
//!
//! [`probe`] finds the newest certified block, and floors to resume marshal from, among the
//! validators, and [`probe::join`] installs a floor and keeps offering newer blocks while the sync
//! runs. Marshal must resume the stream at or below the first target so that no input after the
//! base is missing: install marshal's floor before offering the first target, and not again, even
//! after a restart that resumes the sync. Marshal's jump to the installed floor may reach the
//! executor after the first target; the inputs held from the earlier floor are then acknowledged
//! and dropped.
//!
//! Inputs keep arriving while the sync runs. Those at or below the first target, or at or below an
//! update the application [recorded](Update::recorded), are acknowledged at once, because the base
//! is at or above them. The rest are held unacknowledged until the base is known, which stops
//! marshal once its acknowledgement window fills. An application that records updates as they
//! arrive therefore lets marshal follow the newest checkpoint for as long as the sync runs. A
//! crash during the sync resumes it toward the newest persisted target.
//!
//! [`aggregation`]: commonware_consensus::aggregation
//! [`Finalized`]: commonware_consensus::marshal::Finalized
//! [`Ledger`]: commonware_consensus::marshal::Ledger
//! [`Linear`]: commonware_consensus::marshal::Linear

use commonware_consensus::{Block, ancestry::Ancestry, types::Height};
use commonware_cryptography::{Digest, Digestible};
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::channel::{oneshot, ring};
use rand_core::Rng;
use std::{future::Future, sync::Arc};

mod actor;
pub use actor::{Config, Executor, Halt, Start};
mod checkpoints;
pub use checkpoints::Checkpoints;
mod mailbox;
pub use mailbox::{Inbox, Mailbox, Stopped};
pub mod probe;
mod store;
pub use store::StoreConfig;

#[cfg(test)]
mod tests;

/// Where an input sits in the finalized stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context<D: Digest> {
    /// The height the executed block must have: the input's index in the finalized stream.
    pub height: Height,
    /// The input's digest.
    pub input: D,
}

/// A newer target for a running [state sync](Execute::sync).
pub struct Update<B> {
    /// A block a checkpoint certifies, above every earlier target.
    pub block: Arc<B>,
    /// Signaled once the sync is certain to reach `block` or a later update. The executor then
    /// acknowledges the inputs up to `block`. Updates arrive in increasing height, so a sync may
    /// also signal one it ignores as below the block it already targets.
    pub recorded: oneshot::Sender<()>,
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
    /// newest block the consumer applied, the genesis block of an empty chain, or the block a
    /// [`sync`](Self::sync) reached.
    ///
    /// Every later execution builds on this block or one of its descendants.
    fn resume(&mut self, _tip: Arc<Self::Block>) {}

    /// Called when a checkpoint certifies `block`, an executed block, so the application can keep
    /// what a peer needs to sync to it.
    ///
    /// Calls follow increasing heights within one run of the executor, and may repeat heights
    /// after a restart. The block a [`sync`](Self::sync) reached counts as certified.
    fn certified(&mut self, _block: Arc<Self::Block>) {}

    /// Brings the application's state to the state `target` commits to, or to that of a later
    /// block from `updates`, and returns the block it reached.
    ///
    /// `target` and every update are blocks a checkpoint certifies, offered in increasing height
    /// order. Execution resumes after the returned block, which must be `target` or one of the
    /// updates, and at or above every update whose [`recorded`](Update::recorded) the application
    /// signaled. Until an update is recorded, the inputs above the newest recorded target are held
    /// unacknowledged, which stops marshal once its acknowledgement window fills. The executor may
    /// ask again after a crash, starting from the newest target it persisted.
    ///
    /// An application without state of its own can resume from any certified block, which the
    /// default implementation does by returning `target`.
    fn sync(
        &mut self,
        target: Arc<Self::Block>,
        _updates: ring::Receiver<Update<Self::Block>>,
    ) -> impl Future<Output = Arc<Self::Block>> + Send {
        async move { target }
    }

    /// Executes `input` on top of `ancestry`, the executed chain newest first starting at the
    /// block at `context.height - 1`, and returns the block at `context.height`.
    ///
    /// The result is final: every honest node returns the same block for the same parent and
    /// input, and an input that is invalid in this context yields a block that records the
    /// rejection and leaves state unchanged. The result may depend only on the parent, the input,
    /// and state they determine, never on clocks, local configuration, or data that could differ
    /// between nodes. `ancestry` always yields the parent, but may end at any block below it,
    /// since nodes retain different amounts of the executed chain, so how far it reaches must not
    /// affect the result. The future may stay pending only for data guaranteed to arrive, because
    /// a finalized input cannot be skipped. The executor may ask again after a crash, and halts if
    /// the answer differs.
    ///
    /// The executor calls this on its own clone of the application for each input, so changes to
    /// `self` are not kept. The future runs on the executor's task, so an application whose
    /// execution is CPU-heavy should run it on a task of its own, such as a
    /// [`shared`](commonware_runtime::Spawner::shared) one.
    fn execute(
        self,
        context: (E, Context<<Self::Input as Digestible>::Digest>),
        ancestry: impl Ancestry<Self::Block>,
        input: Arc<Self::Input>,
    ) -> impl Future<Output = Self::Block> + Send;
}

//! Run a stateful application over an executed chain.
//!
//! In ordered mode, consensus only orders inputs. The [`executor`](crate::executor) turns each
//! finalized input into one block of a linear chain, and [`Stateful`] manages the databases that
//! chain commits to. It is both halves of the executor's application: its [`Mailbox`] is the
//! executor's [`Execute`](crate::executor::Execute) implementation and the consumer of the blocks
//! the executor delivers.
//!
//! Nothing here names a consensus engine, so one application runs on any engine whose marshal
//! feeds an executor.
//!
//! # Wiring
//!
//! 1. [`Stateful::init`] returns the actor and its [`Mailbox`].
//! 2. [`Executor::init`](crate::executor::Executor::init) takes clones of the mailbox as both its
//!    `execute` and its `consumer`.
//! 3. [`Stateful::start`] takes the executor's [`Mailbox`](crate::executor::Mailbox). The two
//!    start in either order.
//!
//! # Pending State
//!
//! Execution runs ahead of durable application, so [`Stateful`] keeps the merkleized batches of
//! executed blocks it has not applied yet. Every block extends the one before it, so these form a
//! single line rather than the speculative mode's tree of forks: each input executes against
//! batches forked from its parent's pending state, or from the applied databases once the parent
//! is applied, and a forked batch stays valid while its ancestors are applied. The line is
//! bounded by marshal's acknowledgement window.
//!
//! # Durability
//!
//! For each block the executor delivers, [`Stateful`] captures, applies, and observes its batches
//! through [`Application::capture`], [`DatabaseSet::apply`], and [`Application::finalized`], then
//! acknowledges the block once a database barrier covering it completes. The executor
//! acknowledges the input to marshal only after that.
//!
//! On restart, the executor resumes from the newest block it recorded as applied, and
//! [`Stateful`] opens the databases at that block's sync targets, discarding any state a crash
//! left beyond it. The executor then executes and delivers every later input again, so a block's
//! batches may be captured, applied, and observed more than once.
//!
//! # State Sync
//!
//! An executor that starts from a checkpoint asks [`Stateful`] to sync its databases to the
//! checkpointed blocks it is offered, through [`Execute::sync`](crate::executor::Execute::sync).
//! Stateful fetches operations from peers through its resolvers, verifies them against the sync
//! targets of the newest offered block, and returns the block it converged on, which the executor
//! resumes from. Each newer block is recorded once the sync engines retarget to it, which lets the
//! executor acknowledge the inputs up to it, so marshal follows the newest checkpoint while the
//! sync runs, as it follows the newest finalized block in the speculative mode. Once the databases
//! are open, by either path, the resolvers serve them to peers.
//!
//! # Pruning
//!
//! With a [`PruneConfig`](super::PruneConfig), [`Stateful`] prunes the databases and the executed
//! chain behind the applied tip, as the speculative mode does behind marshal. Neither is pruned
//! past the newest certified checkpoint, which peers sync to, nor before one is certified, so the
//! ordered mode relies on [`aggregation`] certifying the executed chain through
//! [`Checkpoints`](crate::executor::Checkpoints).
//!
//! [`aggregation`]: commonware_consensus::aggregation
//!
//! [`DatabaseSet::apply`]: super::db::DatabaseSet::apply

pub use super::actor::ordered::{Config, Mailbox, Stateful};
use crate::{
    executor::{Context, Executed},
    stateful::db::DatabaseSet,
};
use commonware_consensus::{Block, ancestry::Ancestry};
use commonware_cryptography::Digestible;
use commonware_runtime::{Clock, Metrics, Spawner};
use rand_core::Rng;
use std::{future::Future, sync::Arc};

/// The digest of an application's inputs.
type InputDigest<A, E> = <<A as Application<E>>::Input as Digestible>::Digest;

/// The result of executing an input.
pub enum Execution<A, E>
where
    A: Application<E>,
    E: Rng + Spawner + Metrics + Clock,
{
    /// The input changed state.
    Changed {
        /// The executed block, which commits to `merkleized`.
        block: A::Block,
        /// The batches the input produced.
        merkleized: <A::Databases as DatabaseSet<E>>::Merkleized,
    },

    /// The input left state unchanged, as an input that is invalid in context does.
    ///
    /// Nothing is applied for the block, which commits to its parent's state.
    Unchanged {
        /// The executed block, which records why the input changed nothing.
        block: A::Block,
    },
}

/// A stateful application whose inputs are ordered by consensus and executed afterward.
///
/// [`Stateful`] may clone the application and call it concurrently: execution of one input may
/// overlap application of an earlier block. Treat the application as a deterministic state
/// machine whose state lives in the database batches it is given.
pub trait Application<E>: Clone + Send + 'static
where
    E: Rng + Spawner + Metrics + Clock,
{
    /// The finalized block consensus ordered.
    type Input: Block;

    /// The block execution produces, which commits to the state after its input.
    type Block: Executed<InputDigest<Self, E>>;

    /// The databases managed on behalf of this application.
    type Databases: DatabaseSet<E>;

    /// Owned data captured from a block's batches before they are applied.
    ///
    /// Applications with nothing to capture use `()`.
    type Captured: Send;

    /// Returns the per-database sync targets `block` commits to.
    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets;

    /// Returns the block at height zero, which commits to the databases' initial state.
    fn genesis(&mut self) -> impl Future<Output = Self::Block> + Send;

    /// Executes `input` against `batches` and returns the block at `context.height`.
    ///
    /// `batches` hold the state after the block at `context.height - 1`, which `ancestry` yields
    /// first. The same determinism rules as [`Execute::execute`] apply: the result may depend
    /// only on the ancestry, the input, and the state they determine, and an input that is
    /// invalid in context yields [`Execution::Unchanged`] instead of failing.
    ///
    /// [`Stateful`] checks that a changed block commits to its batches, and that an unchanged
    /// block commits to its parent's state, and panics otherwise. Applications using
    /// [`qmdb::current`](commonware_storage::qmdb::current) must still commit to the batches'
    /// canonical root, which that check does not cover.
    ///
    /// [`Execute::execute`]: crate::executor::Execute::execute
    fn execute(
        &mut self,
        context: (E, Context<InputDigest<Self, E>>),
        ancestry: impl Ancestry<Self::Block>,
        input: Arc<Self::Input>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> impl Future<Output = Execution<Self, E>> + Send;

    /// Captures data from a block's batches immediately before they are applied.
    ///
    /// Only reads completed through `readers` during this call are guaranteed to observe the
    /// state before `batches`. The returned value is passed to [`finalized`](Self::finalized)
    /// once the batches are applied. Blocks that left state unchanged invoke neither hook.
    ///
    /// # Panics
    ///
    /// Implementations should panic if capturing pre-apply state fails.
    fn capture(
        &mut self,
        context: E,
        block: &Self::Block,
        batches: &<Self::Databases as DatabaseSet<E>>::Merkleized,
        readers: <Self::Databases as DatabaseSet<E>>::Readers,
    ) -> impl Future<Output = Self::Captured> + Send;

    /// Observes a block after its batches are applied.
    ///
    /// The block's state is readable through `readers`, but may not be durable yet. [`Stateful`]
    /// acknowledges the block only after this future resolves and a database barrier covering
    /// the block completes. Result-affecting mutations must be made through execution, not from
    /// this observer.
    ///
    /// # Panics
    ///
    /// Implementations should panic if observing applied state fails.
    fn finalized(
        &mut self,
        context: E,
        block: &Self::Block,
        captured: Self::Captured,
        readers: <Self::Databases as DatabaseSet<E>>::Readers,
    ) -> impl Future<Output = ()> + Send;
}

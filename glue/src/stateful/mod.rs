//! Speculative and finalized QMDB state for applications built on consensus.
//!
//! An [`Application`] executes blocks against database batches. [`Stateful`] keeps speculative
//! state in memory, persists finalized state, and supports bootstrapping through peer state sync.
//! Its [`Mailbox`] implements the consensus [`Application`](commonware_consensus::Application)
//! and receives finalized blocks from marshal as a [`Reporter`](commonware_consensus::Reporter).
//!
//! # Overview
//!
//! Upon `prepare`, `propose`, or `verify` of a block with parent `p`:
//!
//! * Fork batches from the pending state of `p`, or from the databases if `p` is the applied tip.
//!   Recover missing parent state through [lazy recovery](#lazy-recovery).
//! * Call [`Application::prepare`] or [`Application::propose`] with those batches, or verify the
//!   block by processing it on them with [`Application::process`].
//! * Keep the result as pending state if it matches the block's
//!   [`sync_targets`](Application::sync_targets). A mismatched proposal panics. A verification
//!   votes `false` if [`Application::process`] rejects the block or its result does not match.
//!
//! Requests that need the same block's state share one call to [`Application::process`], so a
//! build on an uncertified parent and the parent's own verification process the parent once. The
//! call runs while any of those requests remains. A pending state answers every later verification
//! of its block.
//!
//! Batches are forked, and missing parent state recovered, before [`Application::prepare`] is
//! called, even when it keeps its default decline.
//!
//! Upon finalization of block `b`:
//!
//! * Wait for processing of `b` and of competing blocks to finish, and reject requests on
//!   competing branches. Processing of descendants of `b` continues.
//! * Take the pending state of `b`, or reconstruct it with [`Application::process`] as a
//!   [`Finality::Finalized`] block.
//! * Discard pending state that does not descend from `b`.
//! * Call [`Application::capture`], apply the state to the databases, and call
//!   [`Application::finalized`]. Acknowledge `b` once the hook resolves and the state is durable.
//!
//! The [`db`] traits group one or more databases into a [`db::DatabaseSet`]. [`db::p2p`] fetches
//! and serves state sync operations, and [`probe`] discovers a recent finalization to sync from.
//!
//! # Startup
//!
//! 1. Load a [`SyncPlan`] with [`SyncPlan::init`].
//! 2. If [`SyncPlan::should_sync`] returns `true`, select a finalized floor and persist it with
//!    [`SyncPlan::set_floor`].
//! 3. Start marshal from [`SyncPlan::marshal_start`] and pass the same plan to [`Stateful`] as
//!    [`Config::plan`].
//!
//! With a persisted floor, [`Stateful`] runs [state sync](#state-sync). Otherwise, it opens the
//! databases at the later of the recorded completion block and the block backing marshal's
//! processed position (genesis on a new node), rewinding databases that are ahead.
//!
//! Completion is recorded after state sync or recovery. Subsequent starts recover the databases
//! without peer state sync.
//!
//! # State Sync
//!
//! State sync verifies untrusted peer data against the targets committed by a finalized block.
//! It starts from the persisted floor, or from the block backing marshal's processed position if
//! marshal has passed that floor. While syncing, [`Stateful`] rejects proposals and defers
//! verifications.
//!
//! Upon finalization of block `b` while syncing:
//!
//! * Retain `b` with its marshal acknowledgement.
//! * When marshal's pending acknowledgement window fills, record the newest retained block as
//!   the sync target and acknowledge the retained blocks.
//!
//! Upon convergence at anchor `a`:
//!
//! * Acknowledge retained blocks at or below `a` without running application hooks.
//! * Apply retained blocks above `a` in height order and acknowledge them once durable.
//! * Record completion after all applied state is durable, then attach the databases to the
//!   resolvers and start serving requests.
//!
//! The persisted floor lets an interrupted sync resume after a crash, even when state sync is
//! not requested on restart. A newer selection may advance the floor but cannot move it backward.
//!
//! # Persistence
//!
//! Pending state is held only in memory. Database state and state sync metadata are persisted.
//! Outside state sync, marshal acknowledgements never advance beyond durable database
//! state. Recovery replays blocks above the recovery point, so application hooks may run again
//! (see [`Application::finalized`]). An interrupted database barrier leaves its blocks unacknowledged.
//!
//! Marshal must deliver every finalized block above the applied tip in height order. Redelivered
//! blocks are acknowledged without repeating their effects. Blocks above the tip must have the
//! next height and name the tip as their parent, or [`Stateful`] panics. A conflicting block at
//! the tip's height also panics. Only the startup floor may skip heights, so advancing a live
//! marshal floor must not skip unapplied blocks.
//!
//! # Lazy Recovery
//!
//! When a parent has no pending or applied state, [`Stateful`] walks its ancestry through a
//! [`BlockProvider`](commonware_consensus::marshal::ancestry::BlockProvider) to the nearest known
//! state, then processes the missing blocks forward with [`Application::process`] as
//! [`Finality::Candidate`] blocks. Each recovered state is retained even if the request is
//! cancelled, and it answers the block's own verification.
//!
//! Recovery runs alongside other requests and processes one block at a time. Finalization can
//! proceed while a request waits for ancestry, and the request then continues from the finalized
//! state. Processing of the block and of competing blocks finishes before a finalization applies
//! the block, and processing of its descendants continues across it. Pruning waits for every
//! active processing call before removing history.
//!
//! Once its parent's state is ready, a proposal forks batches from it and builds. Finalization
//! waits until the build finishes or is cancelled.
//!
//! An ancestor may not yet be certified, so recovery must tolerate invalid blocks.
//!
//! # Failures
//!
//! [`Stateful`] panics on invalid proposal state, on a finalized block that cannot be processed
//! or reproduced, on skipped heights, on a successor whose parent is not the applied tip, or on
//! a conflicting block at the tip's height. It also panics on state sync, storage, or metadata
//! failures, or if marshal cannot return a block needed for startup. See [database
//! failures](db#failures) for the storage contract.
//!
//! # Compatibility
//!
//! [`Stateful`] supports [`Deferred`] and [`coding::Marshaled`]. [`Inline`] is incompatible
//! because it does not verify the embedded context within the [`CertifiableBlock`].
//!
//! [`Deferred`]: commonware_consensus::marshal::standard::Deferred
//! [`Inline`]: commonware_consensus::marshal::standard::Inline
//! [`coding::Marshaled`]: commonware_consensus::marshal::coding::Marshaled

use commonware_consensus::{
    CertifiableBlock, Epochable, Handoff, Viewable, marshal::ancestry::Ancestry,
};
use commonware_cryptography::certificate::Scheme;
use db::DatabaseSet;
use std::future::Future;

mod actor;
pub use actor::{Config, Mailbox, PruneConfig, Stateful, SyncPlan};

pub mod db;
pub mod probe;

#[cfg(test)]
mod tests;

/// The output of a successful [`Application::prepare`] or [`Application::propose`] call.
pub struct Proposed<A: Application<E>, E> {
    /// The block built by the application.
    pub block: A::Block,

    /// The merkleized database batches produced during execution.
    pub merkleized: <A::Databases as DatabaseSet<E>>::Merkleized,
}

/// Whether [`Application::process`] may rely on the block's finalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Finality {
    /// The block is not yet finalized and must pass every validity check.
    Candidate,
    /// The network finalized the block, so honest voters already accepted it as a candidate.
    Finalized,
}

/// Per-proposal input passed to [`Application::prepare`] and [`Application::propose`].
pub struct Input<Upstream, Provider> {
    /// Input passed to [`Stateful`] by its caller.
    pub upstream: Upstream,

    /// A clone of [`Config::provider`].
    pub provider: Provider,
}

/// A deterministic state machine whose storage is managed by [`Stateful`].
///
/// Implementors execute blocks against [`DatabaseSet::Unmerkleized`] batches and return
/// [`DatabaseSet::Merkleized`] batches (see the [module docs](crate::stateful)).
///
/// Methods may run concurrently on different clones. Given the same inputs and database state,
/// every clone must produce the same state transition. Mutable state that affects execution
/// must live in the supplied database batches.
pub trait Application<E>: Clone + Send + 'static {
    /// The signing scheme used by the application and by the marshal supplied through
    /// [`Config::marshal`](crate::stateful::Config::marshal).
    type SigningScheme: Scheme;

    /// Consensus metadata for a block (for example its proposer, epoch, and view).
    type Context: Clone + Epochable + Viewable + Send;

    /// The block type produced by the application.
    type Block: CertifiableBlock<Context = Self::Context>;

    /// The set of databases managed on behalf of this application.
    type Databases: DatabaseSet<E>;

    /// Owned data captured from a finalized block's state before it is applied.
    ///
    /// Applications with nothing to capture use `()`.
    type Captured: Send;

    /// The provider supplied through [`Config::provider`](crate::stateful::Config::provider).
    ///
    /// Supplies data for proposals, such as transactions from a mempool. Must be cheap to clone.
    type Provider: Send + Clone;

    /// Per-proposal input from the caller of [`Stateful`], passed to [`prepare`](Self::prepare)
    /// and [`propose`](Self::propose) with the [`Provider`](Self::Provider) as an [`Input`].
    ///
    /// Use `()` when callers supply no input.
    type Input: Send;

    /// Returns the per-database sync targets that `block` commits to.
    ///
    /// These targets bind execution, recovery, and state sync to the block's committed state.
    /// State sync trusts the targets and verifies untrusted peer data against them.
    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets;

    /// Returns the block used to initialize the consensus engine in the first epoch.
    fn genesis(&mut self) -> impl Future<Output = Self::Block> + Send;

    /// Builds a block on top of the provided parent ancestry before the parent certifies, or
    /// declines with [`Handoff::Wait`].
    ///
    /// Like [`propose`](Self::propose), including its requirements on the merkleized state and
    /// on cancellation. With [`Handoff::Vote`] or [`Handoff::Stage`], the block's state is cached
    /// and the block reaches consensus under that decision. See
    /// [`commonware_consensus::Application::prepare`] for the contract, including the trust an
    /// early vote places in the outgoing leader. The default declines.
    fn prepare(
        &mut self,
        _context: (E, Self::Context),
        _ancestry: impl Ancestry<Self::Block>,
        _batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        _input: Input<Self::Input, Self::Provider>,
    ) -> impl Future<Output = Handoff<Proposed<Self, E>>> + Send {
        async { Handoff::Wait }
    }

    /// Builds a block on top of the provided parent ancestry.
    ///
    /// Returns the block and its merkleized state, or [`None`] if no block is built.
    ///
    /// The merkleized state must match [`sync_targets`](Self::sync_targets) for the returned block:
    /// [`Stateful`] panics otherwise. Applications using
    /// [`qmdb::current`](commonware_storage::qmdb::current) must also ensure the block commits to
    /// the merkleized batch's canonical root, because the sync targets cover only the ops root and
    /// operation range.
    ///
    /// The caller may cancel this future before it completes, so implementations must be
    /// cancellation-safe. A dropped call must leave the application's own state consistent.
    fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        input: Input<Self::Input, Self::Provider>,
    ) -> impl Future<Output = Option<Proposed<Self, E>>> + Send;

    /// Processes an existing block on its parent's state and returns the merkleized result, or
    /// [`None`] if the block is invalid.
    ///
    /// [`Stateful`] calls this to verify a peer's block, to build on an uncertified parent, to
    /// recover missing ancestry, and to finalize a block without pending state. Concurrent
    /// requests for the same block share one call, and a pending state answers every later
    /// verification of its block. `ancestry` starts with the block, followed by its parent and
    /// earlier ancestors fetched on demand, and [`Ancestry::peek`] returns the block without
    /// fetching its parent. `context` carries the block's consensus context.
    ///
    /// For a [`Finality::Candidate`], check every rule a vote depends on: signatures, the
    /// context, the ancestry, and the parent's state. Return [`None`] only for permanent
    /// invalidity under the supplied context, ancestry, and batches. [`Stateful`] then rejects
    /// the block and every block built on it. Later finalization of a competing branch does not
    /// change a completed result.
    ///
    /// A rule fixed by the block and its ancestry, such as a timestamp bound relative to the
    /// parent, can establish permanent invalidity. A rule that depends on the local clock or on
    /// local readiness cannot, so such a condition may only delay the result. Builds and recovery
    /// wait for the full result.
    ///
    /// For a [`Finality::Finalized`] block, honest voters already accepted the block as a
    /// candidate, so checks that do not affect the resulting state may be skipped. The block must
    /// still produce its state, and [`None`] or mismatched sync targets make [`Stateful`] panic.
    ///
    /// Processing must finish without waiting for a later finalization, including through
    /// further ancestry reads, and may await other asynchronous I/O. Data needed to produce
    /// finalized state must survive pruning and state sync.
    ///
    /// [`Stateful`] checks only [`sync_targets`](Self::sync_targets), so implementations must
    /// check any other block commitments, such as the canonical root of
    /// [`qmdb::current`](commonware_storage::qmdb::current).
    ///
    /// The caller or [`Stateful`] may cancel this future before it completes, so implementations
    /// must be cancellation-safe. A dropped call must leave the application's own state consistent.
    ///
    /// Processing may overlap finalization. Read through the provided batches without holding
    /// database locks (see [`db::Shared::read`]).
    fn process(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        finality: Finality,
    ) -> impl Future<Output = Option<<Self::Databases as DatabaseSet<E>>::Merkleized>> + Send;

    /// Captures data from a finalized block's state before it is applied.
    ///
    /// [`Stateful`] calls this immediately before applying each finalized block's state. Blocks
    /// already reflected in the databases skip this hook and [`finalized`](Self::finalized): the
    /// genesis block on a new node, blocks reconciled at startup, and blocks covered by state sync.
    ///
    /// Only reads completed through `readers` during this call are guaranteed to observe
    /// pre-apply state. Capture owned values for [`finalized`](Self::finalized), which receives
    /// the returned value after the batches are applied.
    ///
    /// [`Stateful`] handles no other message while this future or [`finalized`](Self::finalized) is
    /// pending (speculative processing already running continues). Keep this capture cheap, and
    /// spawn expensive follow-on work from [`finalized`](Self::finalized) instead of awaiting it.
    ///
    /// # Panics
    ///
    /// Implementations should panic if capturing pre-apply state fails.
    fn capture(
        &mut self,
        context: (E, Self::Context),
        block: &Self::Block,
        batches: &<Self::Databases as DatabaseSet<E>>::Merkleized,
        readers: <Self::Databases as DatabaseSet<E>>::Readers,
    ) -> impl Future<Output = Self::Captured> + Send;

    /// Observes a finalized block after its state is applied.
    ///
    /// Called in application order with the value returned by [`capture`](Self::capture).
    /// The block's state is readable but may not yet be durable. A database barrier may run
    /// concurrently. Marshal receives an acknowledgement only after this hook resolves and a
    /// barrier covering the block completes.
    ///
    /// Blocks already reflected in the databases skip this hook (see [`capture`](Self::capture)),
    /// so consecutive calls may skip heights after state sync.
    ///
    /// The read-only handles may be used concurrently with descendant processing. Mutations
    /// that affect execution results must go through normal block execution.
    ///
    /// Capture, application, and this hook may repeat after a crash until both the block's state
    /// and marshal's processed position are durable.
    ///
    /// # Panics
    ///
    /// Implementations should panic if observing finalized state fails.
    fn finalized(
        &mut self,
        context: (E, Self::Context),
        block: &Self::Block,
        captured: Self::Captured,
        readers: <Self::Databases as DatabaseSet<E>>::Readers,
    ) -> impl Future<Output = ()> + Send;
}

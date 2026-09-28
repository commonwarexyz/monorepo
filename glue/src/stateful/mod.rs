//! Speculative and finalized QMDB state for applications built on consensus.
//!
//! An [`Application`] executes blocks against database batches. [`Stateful`] keeps speculative
//! state in memory, persists finalized state, and supports bootstrapping through peer state sync.
//! Its [`Mailbox`] implements the consensus [`Application`](commonware_consensus::Application)
//! and receives finalized blocks from marshal as a [`Reporter`](commonware_consensus::Reporter).
//!
//! # Overview
//!
//! Upon `propose` or `verify` of a block with parent `p`:
//!
//! * Fork batches from the pending state of `p`, or from the databases if `p` is the applied tip.
//!   Recover missing parent state through [lazy recovery](#lazy-recovery).
//! * Call [`Application::propose`] or [`Application::verify`] with those batches.
//! * Keep the result as pending state if it matches the block's
//!   [`sync_targets`](Application::sync_targets). A mismatched proposal panics, and a mismatched
//!   verification votes `false`.
//!
//! Upon finalization of block `b`:
//!
//! * Reject verifications on competing branches and restart those that cannot continue across
//!   the finalization.
//! * Take the pending state of `b`, or reconstruct it with [`Application::apply`].
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
//! blocks are acknowledged without repeating their effects. Blocks above the tip must extend it
//! by one height or [`Stateful`] panics. Only the startup floor may skip heights, so advancing a
//! live marshal floor must not skip unapplied blocks.
//!
//! # Lazy Recovery
//!
//! When a parent has no pending or applied state, [`Stateful`] walks its ancestry through a
//! [`BlockProvider`](commonware_consensus::marshal::ancestry::BlockProvider) to the nearest known
//! state, then replays forward with [`Application::apply`]. Each rebuilt state is retained even
//! if the request is cancelled.
//!
//! An ancestor may not yet be certified, so replay must tolerate invalid blocks. Replayed state
//! can serve as parent state but never as a verification verdict: verifying the block still
//! calls [`Application::verify`].
//!
//! # Failures
//!
//! [`Stateful`] panics on invalid proposal state, on a finalized block that cannot be executed
//! or reproduced, on noncontiguous marshal delivery, and on state sync, storage, or metadata
//! failures. A block needed for startup must be available from marshal. See [database
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

use commonware_consensus::{CertifiableBlock, Epochable, Viewable, marshal::ancestry::Ancestry};
use commonware_cryptography::certificate::Scheme;
use commonware_runtime::{Clock, Metrics, Spawner};
use db::DatabaseSet;
use rand_core::Rng;
use std::future::Future;

mod actor;
pub use actor::{Config, Mailbox, PruneConfig, Stateful, SyncPlan};

pub mod db;
pub mod probe;

#[cfg(test)]
mod tests;

/// The output of a successful [`Application::propose`] call.
pub struct Proposed<A: Application<E>, E: Rng + Spawner + Metrics + Clock> {
    /// The block built by the application.
    pub block: A::Block,

    /// The merkleized database batches produced during execution.
    pub merkleized: <A::Databases as DatabaseSet<E>>::Merkleized,
}

/// Per-proposal input passed to [`Application::propose`].
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
pub trait Application<E>: Clone + Send + 'static
where
    E: Rng + Spawner + Metrics + Clock,
{
    /// The signing scheme used by the application.
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

    /// Per-proposal input from the caller of [`Stateful`], passed to [`propose`](Self::propose)
    /// with the [`Provider`](Self::Provider) as an [`Input`].
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
    /// The caller may cancel this future. Cancellation and retry must preserve invariants and
    /// durable progress.
    fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        input: Input<Self::Input, Self::Provider>,
    ) -> impl Future<Output = Option<Proposed<Self, E>>> + Send;

    /// Verifies a block received from a peer against its ancestry.
    ///
    /// Called before this node votes to finalize the block (its notarize vote may already have
    /// been cast). The implementation should execute the block against `batches` and return the
    /// merkleized result.
    ///
    /// Return [`None`] only for permanent invalidity under the supplied context, ancestry, and
    /// batches. To abstain, keep the future pending until validity is decided or the request is
    /// cancelled. Later finalization of a competing branch does not change a completed verdict.
    ///
    /// Reject execution results that differ from the block's commitments. [`Stateful`] checks
    /// [`sync_targets`](Self::sync_targets), so implementations need not repeat that check.
    /// Applications using [`qmdb::current`](commonware_storage::qmdb::current) must reject blocks whose
    /// committed canonical root differs from the merkleized batch root, because the sync targets
    /// cover only the ops root and operation range.
    ///
    /// The caller or [`Stateful`] may cancel this future. Cancellation and retry must preserve
    /// invariants and durable progress.
    ///
    /// Verification may overlap finalization while its batches remain valid. Batches can read
    /// through to the live database and remain valid only while applied state advances along
    /// their branch. [`Stateful`] retries or rejects requests that cannot continue. Read through
    /// the provided batches without holding database locks (see [`db::Shared::read`]).
    fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> impl Future<Output = Option<<Self::Databases as DatabaseSet<E>>::Merkleized>> + Send;

    /// Re-executes `block` to reconstruct its merkleized state.
    ///
    /// Used for [lazy recovery](crate::stateful#lazy-recovery) and for finalized blocks without
    /// pending state.
    ///
    /// The returned state must match what [`verify`](Self::verify) accepts for `block`.
    /// It may become parent state or be committed at finalization, but never substitutes for
    /// [`verify`](Self::verify). [`Stateful`] checks only [`sync_targets`](Self::sync_targets),
    /// so implementations must check any other block commitments.
    ///
    /// A replayed ancestor may be invalid. Return [`None`] if it cannot be executed, rejecting
    /// ancestry that depends on it. For a finalized block, [`None`] or mismatched sync targets
    /// cause [`Stateful`] to panic.
    ///
    /// The caller or [`Stateful`] may cancel this future. Cancellation and retry must preserve
    /// invariants and durable progress.
    ///
    /// # Panics
    ///
    /// Implementations should panic if executing a valid block fails.
    fn apply(
        &mut self,
        context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
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
    /// pending (verifications already running continue). Keep this capture cheap, and spawn
    /// expensive follow-on work from [`finalized`](Self::finalized) instead of awaiting it.
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
    /// The read-only handles may be used concurrently with descendant verification. Mutations
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

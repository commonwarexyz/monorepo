//! Manage QMDB database instances on behalf of a stateful application.
//!
//! A stateful application built on consensus must maintain speculative state for
//! every pending chain built on top of the finalized tip. This module provides
//! the [`Application`] trait and a [`Stateful`] actor that automates that
//! bookkeeping:
//!
//! 1. Before each `propose` or `verify`, the actor forks unmerkleized batches
//!    from the parent block's pending state (or from applied database state
//!    if the parent has been finalized).
//! 2. The application executes against those batches and returns merkleized
//!    results, which the actor stores as a new pending tip keyed by the
//!    block's digest.
//! 3. On finalization, the actor applies the winning tip's changesets to the
//!    underlying databases and prunes pending entries from dead forks.
//!
//! # Database Layer
//!
//! The [`db`] module defines batch lifecycle traits ([`db::Unmerkleized`],
//! [`db::Merkleized`], [`db::ManagedDb`]) and a [`db::DatabaseSet`] trait that
//! groups one or more databases into a single unit.
//!
//! The [`db::p2p`] submodule provides a P2P resolver actor
//! (implementing [`commonware_storage::qmdb::sync::Source`]) over
//! [`commonware-resolver`](commonware_resolver), enabling databases to fetch
//! and serve sync operations from peers.
//!
//! # Syncing
//!
//! State sync operates against a single trusted target at a time. The peers serving operations and
//! proofs remain untrusted, and their responses are verified against that target. Selecting the
//! target before the storage boundary lets the sync engines follow strictly advancing updates
//! instead of reconciling competing targets.
//!
//! Applications load a [`SyncPlan`] before constructing marshal and [`Stateful`].
//! The plan reads the durable state sync state and keeps that metadata handle
//! until [`Stateful`] consumes it, avoiding multiple opens of the same metadata
//! partition during startup. Callers use [`SyncPlan::should_state_sync`] to
//! decide whether to discover and attach a finalized floor via
//! [`SyncPlan::with_floor`]. The same plan then drives marshal (via
//! [`SyncPlan::marshal_start`]) and stateful (via [`Config::plan`]), so both
//! actors are guaranteed to agree on the startup decision. Once the durable
//! complete height is set, the node never performs peer state sync again and
//! must recover from the later of the stored height and marshal's processed
//! height on future startups.
//!
//! The actor supports two sync paths:
//!
//! - **Marshal sync** (no floor attached): [`Stateful::start`] prepares the
//!   databases before the actor is spawned. New nodes initialize from
//!   genesis; restarted nodes reconcile the database set against the later of
//!   marshal's processed anchor and the stored state sync height, rewinding if
//!   needed. If marshal is behind that stored height, the actor acknowledges old
//!   finalized blocks without applying them again until marshal catches up. The
//!   actor then starts directly in normal processing mode while marshal continues
//!   backfilling blocks from the network.
//!
//! - **State sync** (floor attached): Run a one-time QMDB state sync from
//!   marshal's configured floor block, populating each database via
//!   [`db::StateSyncSet::sync`]. The actor retains finalized blocks and their
//!   acknowledgements until marshal's pending-ack window fills, waits for the live
//!   sync coordinator to record the newest block's target, and releases the batch.
//!   If state sync completes before the window fills, the pending blocks are handled
//!   during the transition to normal processing. Durable metadata records the selected
//!   floor before database mutation and is marked complete only after the converged state
//!   and any required handoff blocks are durable. A crash before completion restarts from
//!   that floor. The storage target is advanced to the block backing marshal's durable
//!   processed position when necessary, because marshal cannot redeliver acknowledged blocks
//!   below that position. Journal state that has pruned the resulting range start is discarded
//!   and rebuilt. State extending beyond the target is rewound to the target end so its retained
//!   prefix can be reused. A lagging floor sampled during restart cannot move the floor backward.
//!   Subsequent restarts after completion take the marshal sync path to ensure a contiguous stream.
//!
//! # Lazy Recovery
//!
//! Pending state is kept entirely in memory to avoid disk writes on the
//! consensus hot path. After a restart the map is empty, but the actor
//! recovers lazily: when `propose` or `verify` encounters a parent whose
//! state is missing, the actor walks back through the block DAG (via a
//! [`BlockProvider`](commonware_consensus::marshal::ancestry::BlockProvider))
//! to the nearest known ancestor or the finalized tip,
//! then replays forward via [`Application::apply`] to fill the gap. Each
//! replayed block is inserted into the pending map immediately so that
//! partial progress survives timeouts.
//!
//! # Compatibility
//!
//! The [`Stateful`] application may be used with [`Deferred`] and [`coding::Marshaled`],
//! but not with [`Inline`]. This is because [`Inline`] does not verify the correctness
//! of the embedded context within the [`CertifiableBlock`].
//!
//! [`Deferred`]: commonware_consensus::marshal::standard::Deferred
//! [`Inline`]: commonware_consensus::marshal::standard::Inline
//! [`coding::Marshaled`]: commonware_consensus::marshal::coding::Marshaled

use commonware_consensus::{CertifiableBlock, Epochable, Viewable, marshal::ancestry::Ancestry};
use commonware_cryptography::certificate::Scheme;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_storage::{merkle::Family, qmdb};
use db::{DatabaseSet, MerkleizedOf, ReadersOf, UnmerkleizedOf};
use rand_core::Rng;
use std::future::Future;
use thiserror::Error;

mod actor;
pub use actor::{Config, Mailbox, PruneConfig, Stateful, SyncPlan};

pub mod db;
pub mod probe;

#[cfg(test)]
mod tests;

/// Why a block execution failed.
#[derive(Debug, Error)]
pub enum ExecutionError {
    /// A competing finalization invalidated the batch's reads mid-execution.
    #[error("stale execution: a competing block was finalized")]
    Stale,
    /// Any other storage failure.
    #[error("storage failure: {0}")]
    Fatal(String),
}

impl<F: Family> From<qmdb::Error<F>> for ExecutionError {
    fn from(err: qmdb::Error<F>) -> Self {
        match err {
            qmdb::Error::StaleRead => Self::Stale,
            err => Self::Fatal(err.to_string()),
        }
    }
}

/// The output of a successful [`Application::propose`] call.
pub struct Proposed<A: Application<E>, E: Rng + Spawner + Metrics + Clock> {
    /// The block built by the application.
    pub block: A::Block,

    /// The merkleized database batches produced during execution.
    pub merkleized: <A::Databases as DatabaseSet<E>>::Merkleized,
}

/// Aggregated per-proposal input a [`Stateful`] application hands its inner
/// application.
///
/// `upstream` is the input [`Stateful`] received as a
/// [`commonware_consensus::Application`] (from whatever wraps it);
/// `provider` is the stateful-owned handle from [`Config::provider`]. Being
/// generic over the upstream input, it lets an outer application (for example a
/// reshare wrapper) stack its own input on top of the stateful-owned provider
/// without either layer knowing the other.
pub struct Input<Upstream, Provider> {
    /// Input forwarded from the application wrapping [`Stateful`].
    pub upstream: Upstream,

    /// Provider owned by the stateful actor, from its [`Config::provider`].
    pub provider: Provider,
}

/// A stateful application whose storage is managed by a [`DatabaseSet`].
///
/// Implementors receive [`DatabaseSet::Unmerkleized`] batches and
/// return [`DatabaseSet::Merkleized`] batches after execution. The surrounding
/// wrapper handles persistence: storing merkleized batches as pending tips on
/// the block tree and applying changesets to the underlying databases on
/// finalization. Every execution method reads through `batches`, which is the
/// only database access an implementor is given. A batch overlays speculative
/// ancestor state and falls back to applied state for anything it does not
/// cover, so it is always the complete view for its branch.
///
/// [`Stateful`] may freely clone the application and invoke its methods
/// concurrently. Implementors should treat `Application` as a stateless,
/// deterministic state machine. Given the same method inputs and database
/// state, every clone must produce the same state-transition result.
/// Mutable state that affects those results must live in the database batches
/// provided to proposal, verification, and replay methods.
pub trait Application<E>: Clone + Send + 'static
where
    E: Rng + Spawner + Metrics + Clock,
{
    /// The signing scheme used by the application.
    type SigningScheme: Scheme;

    /// Metadata provided by the consensus engine for a given block.
    ///
    /// This often includes things like the proposer, view number, height, or
    /// epoch. Must be [`Epochable`] and [`Viewable`] so the wrapper can
    /// construct a [`Round`](commonware_consensus::types::Round) for
    /// pending-state pruning.
    type Context: Clone + Epochable + Viewable + Send;

    /// The block type produced by the application.
    ///
    /// Must implement [`CertifiableBlock`] so the wrapper can extract
    /// the consensus context during lazy recovery (see
    /// [`apply`](Self::apply)).
    type Block: CertifiableBlock<Context = Self::Context>;

    /// The set of databases managed on behalf of this application.
    type Databases: DatabaseSet<E>;

    /// The stateful-owned provider, supplied through
    /// [`Config::provider`](crate::stateful::Config::provider).
    ///
    /// This may be a mempool that serves transactions, a stream of
    /// certificates, or any other handle to data that drives state
    /// transitions. The stateful actor owns it and clones it for each proposal,
    /// so it must be cheap to clone (e.g. `()` or a handle).
    type Provider: Send + Clone;

    /// Per-proposal input forwarded from the application wrapping
    /// [`Stateful`], aggregated with [`Provider`](Self::Provider) into the
    /// [`Input`] handed to [`propose`](Self::propose). Set this to `()`
    /// when nothing wraps the stateful actor with its own input.
    type Input: Send;

    /// Extract per-database sync targets from a finalized block.
    ///
    /// Called by the wrapper for finalized blocks received during state sync.
    ///
    /// Target selection occurs before this boundary, so state sync trusts the returned targets
    /// and only verifies that peer data matches them.
    ///
    /// The returned targets are handed to the state sync coordinator so the
    /// sync engines can track the latest finalized state root and range.
    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets;

    /// Block used to initialize the consensus engine in the first epoch.
    fn genesis(&mut self) -> impl Future<Output = Self::Block> + Send;

    /// Build a new block on top of the provided parent ancestry.
    ///
    /// Returns [`None`] if the build fails.
    ///
    /// The wrapper checks that the returned merkleized state matches
    /// [`sync_targets`](Self::sync_targets) for the returned block before the
    /// result is cached as pending state. If the implementor produces a
    /// block with mismatched targets, this function will panic.
    ///
    /// Applications using [`qmdb::current`] must still ensure the proposed
    /// block commits to the merkleized batch's canonical root. The wrapper's
    /// sync-target check only verifies the ops root and operation range used
    /// by replay sync.
    ///
    /// This future may be cancelled by consensus if the caller drops its
    /// response receiver. Implementations should be cancellation-safe: dropping
    /// and retrying must not violate invariants or lose durable progress.
    ///
    /// Storage errors from batch operations are propagated as [`ExecutionError`],
    /// never interpreted. The wrapper declines the proposal on `Ok(None)` and
    /// [`Stale`](ExecutionError::Stale), and panics on
    /// [`Fatal`](ExecutionError::Fatal).
    fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: UnmerkleizedOf<Self::Databases, E>,
        input: Input<Self::Input, Self::Provider>,
    ) -> impl Future<Output = Result<Option<Proposed<Self, E>>, ExecutionError>> + Send;

    /// Verify a block received from a peer, relative to its ancestry.
    ///
    /// Called before voting. The implementation should execute the block
    /// against the provided batches and merkleize them.
    ///
    /// This future should not resolve until the implementation can produce a
    /// stable verdict. Return [`None`] only when the block is permanently
    /// invalid for the supplied context, ancestry, and batches. If validity may
    /// still change as additional information becomes available, continue
    /// waiting instead of returning [`None`].
    ///
    /// Validity is relative to those inputs: finalizing a competing branch
    /// later does not retroactively change a completed verdict. The wrapper may
    /// discard the verified state instead of caching it, but the answer is
    /// unchanged.
    ///
    /// In other words, to abstain from voting, do not resolve this future yet.
    /// Keep it pending until the implementation can either prove the block
    /// valid, prove it invalid, or the consensus engine cancels the request.
    /// Abstaining is not represented by a special return value.
    ///
    /// Verification must reject any block whose execution result does not
    /// match the block's committed state (for example, a state root mismatch).
    /// Implementations do not need to re-check [`sync_targets`](Self::sync_targets)
    /// against the produced batches themselves: the wrapper enforces
    /// this by checking that any returned merkleized state matches the block
    /// before it is cached as pending state.
    ///
    /// Applications using [`qmdb::current`] must still reject blocks whose
    /// committed canonical root differs from the merkleized batch root. The
    /// wrapper's sync-target check only verifies the ops root and operation
    /// range used by replay sync.
    ///
    /// This future is scoped to its caller. Dropping the response cancels only
    /// this request. The wrapper never cancels it while the actor runs, so a
    /// batch operation running when a finalized block is applied waits for that
    /// apply and then continues. Actor shutdown drops it with everything else.
    ///
    /// Once a block from a competing branch is finalized, every batch
    /// operation refuses with [`ExecutionError::Stale`]. The wrapper then
    /// re-checks the block against the new canonical state and retries or
    /// answers from it.
    fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: UnmerkleizedOf<Self::Databases, E>,
    ) -> impl Future<Output = Result<Option<MerkleizedOf<Self::Databases, E>>, ExecutionError>> + Send;

    /// Apply a previously certified block to reconstruct its merkleized state.
    ///
    /// Called by the wrapper during lazy recovery when pending state for
    /// an ancestor block is missing (e.g. after a restart). The block is
    /// known-good (it was previously certified), so the implementation
    /// should unconditionally execute the block's state transitions.
    ///
    /// The returned merkleized state must match what
    /// [`verify`](Self::verify) accepted for `block`. The wrapper commits this
    /// replay result during finalization and cannot re-check block-specific
    /// commitments generically.
    ///
    /// This future may be cancelled if its originating request is dropped or
    /// the actor shuts down; the wrapper never cancels it while the actor runs.
    /// Cancellation must not violate invariants or lose durable progress.
    ///
    /// Storage errors from batch operations are propagated as [`ExecutionError`],
    /// never interpreted (see [`verify`](Self::verify)). The wrapper re-checks
    /// canonical state when a verification replay goes stale and panics when the
    /// failure is impossible on a correct node (the finalize path).
    fn apply(
        &mut self,
        context: (E, Self::Context),
        block: &Self::Block,
        batches: UnmerkleizedOf<Self::Databases, E>,
    ) -> impl Future<Output = Result<MerkleizedOf<Self::Databases, E>, ExecutionError>> + Send;

    /// Observe a finalized block after it is reflected in the database set.
    ///
    /// Once the database set is ready, the wrapper calls this for every
    /// finalized block it receives from marshal before releasing that block's
    /// marshal acknowledgement. Blocks applied through normal processing are
    /// reported after [`DatabaseSet::apply`] succeeds: the block's state is
    /// readable from the databases, but durability through that block may still
    /// be pending. When an earlier database sync is active, the sync covering
    /// this block may not have started yet. Blocks already reflected by startup
    /// reconciliation or completed state sync are reported without reapplying
    /// them.
    ///
    /// During peer state sync, a finalized block may be absorbed into a recorded sync target and
    /// acknowledged without invoking this hook. Blocks still pending when sync completes are
    /// reported or applied during handoff. Applications must derive synchronized state from the
    /// database set rather than rely on receiving every peer-state-sync finalization here.
    ///
    /// `readers` are readers over the database set.
    ///
    /// For blocks that are reported, this is an at-least-once notification inherited from
    /// marshal's reporter stream: a crash after this hook runs but before a database sync covering
    /// the block and marshal's processed position are durable may cause the same block to be
    /// reported again.
    ///
    /// # Panics
    ///
    /// Implementations should panic if observing finalized state fails.
    fn finalized(
        &mut self,
        _context: (E, Self::Context),
        _block: &Self::Block,
        _readers: ReadersOf<Self::Databases, E>,
    ) -> impl Future<Output = ()> + Send {
        async {}
    }
}

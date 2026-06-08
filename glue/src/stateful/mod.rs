//! Manage QMDB database instances on behalf of a stateful application.
//!
//! A stateful application built on consensus must maintain speculative state for
//! every pending chain built on top of the finalized tip. This module provides
//! the [`Application`] trait and a [`Stateful`] actor that automates that
//! bookkeeping:
//!
//! 1. Before each `propose` or `verify`, the actor forks unmerkleized batches
//!    from the parent block's pending state (or from committed database state
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
//! The [`db::p2p`] submodule provides P2P resolver actors (a
//! [`db::p2p::standard`] resolver implementing
//! [`commonware_storage::qmdb::sync::resolver::Resolver`] and a
//! [`db::p2p::compact`] resolver implementing
//! [`commonware_storage::qmdb::sync::compact::Resolver`]) over
//! [`commonware-resolver`](commonware_resolver), enabling databases to fetch
//! and serve sync operations from peers.
//!
//! # Syncing
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
//!   [`db::StateSyncSet::sync`]. For each finalized block while state sync
//!   is live, the actor synchronously asks the syncer to observe that block's
//!   sync targets. If the live session accepts the block, the actor
//!   acknowledges it immediately. Once the syncer freezes databases at
//!   `database_anchor`, the actor enters normal processing. If a finalized block
//!   above `database_anchor` arrives first, the actor processes it during handoff.
//!   Durable metadata is marked in-progress before any database mutation and is
//!   marked complete at the converged anchor before handoff acknowledgement. A
//!   crash before completion restarts through the state-sync path, reopening
//!   the existing sync journals. Subsequent restarts after completion take the
//!   marshal sync path to ensure a contiguous stream.
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

use commonware_consensus::{CertifiableBlock, Epochable, Viewable};
use commonware_cryptography::certificate::Scheme;
use commonware_runtime::{Clock, Metrics, Spawner};
use db::DatabaseSet;
use futures::Stream;
use rand::Rng;
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

/// A stateful application whose storage is managed by a [`DatabaseSet`].
///
/// Implementors receive [`DatabaseSet::Unmerkleized`] batches and
/// return [`DatabaseSet::Merkleized`] batches after execution. The surrounding
/// wrapper handles persistence: storing merkleized batches as pending tips on
/// the block tree and applying changesets to the underlying databases on
/// finalization.
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
    type Context: Epochable + Viewable + Send;

    /// The block type produced by the application.
    ///
    /// Must implement [`CertifiableBlock`] so the wrapper can extract
    /// the consensus context during lazy recovery (see
    /// [`apply`](Self::apply)).
    type Block: CertifiableBlock<Context = Self::Context>;

    /// The set of databases managed on behalf of this application.
    type Databases: DatabaseSet<E>;

    /// A provider of input to the application.
    ///
    /// This may be a mempool that serves transactions, a stream of
    /// certificates, or any other source of input that drives state
    /// transitions.
    type InputProvider: Send;

    /// Extract per-database sync targets from a finalized block.
    ///
    /// Called by the wrapper for finalized blocks received during state sync.
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
    /// Applications using [`qmdb::current`](commonware_storage::qmdb::current)
    /// must still ensure the proposed block commits to the merkleized batch's
    /// canonical root. The wrapper's sync-target check only verifies the ops
    /// root and operation range used by replay sync.
    ///
    /// This future may be cancelled by consensus if the caller drops its
    /// response receiver. Implementations should be cancellation-safe: dropping
    /// and retrying must not violate invariants or lose durable progress.
    fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Stream<Item = Self::Block> + Send,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        input: &mut Self::InputProvider,
    ) -> impl Future<Output = Option<Proposed<Self, E>>> + Send;

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
    /// Applications using [`qmdb::current`](commonware_storage::qmdb::current)
    /// must still reject blocks whose committed canonical root differs from the
    /// merkleized batch root. The wrapper's sync-target check only verifies the
    /// ops root and operation range used by replay sync.
    ///
    /// This future may be cancelled by consensus if the caller drops its
    /// response receiver. Implementations should be cancellation-safe: dropping
    /// and retrying must not violate invariants or lose durable progress.
    fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Stream<Item = Self::Block> + Send,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> impl Future<Output = Option<<Self::Databases as DatabaseSet<E>>::Merkleized>> + Send;

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
    /// This future may be cancelled if the originating propose/verify request
    /// is dropped. Implementations should be cancellation-safe: dropping and
    /// retrying must not violate invariants or lose durable progress.
    ///
    /// # Panics
    ///
    /// Implementations should panic if execution fails, as this indicates
    /// data corruption or non-determinism.
    fn apply(
        &mut self,
        context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> impl Future<Output = <Self::Databases as DatabaseSet<E>>::Merkleized> + Send;

    /// Observe a finalized block after it is reflected in durable state.
    ///
    /// Once the database set is ready, the wrapper calls this for every
    /// finalized block it receives from marshal before releasing that block's
    /// marshal acknowledgement. Blocks applied through normal processing are
    /// reported after [`DatabaseSet::finalize`] succeeds. Blocks already
    /// reflected by startup reconciliation or completed state sync are reported
    /// without reapplying them.
    ///
    /// During peer state sync, finalized blocks observed before sync completes
    /// are used to update the sync target and are not reported here.
    ///
    /// Inherited from marshal's reporter stream, this is an at-least-once notification:
    /// a crash after this hook runs but before the marshal acknowledgement is
    /// durable may cause the same block to be reported again after restart.
    ///
    /// # Panics
    ///
    /// Implementations should panic if post-finalization maintenance fails.
    fn finalized(
        &mut self,
        _context: (E, Self::Context),
        _block: &Self::Block,
        _databases: &Self::Databases,
    ) -> impl Future<Output = ()> + Send {
        async {}
    }
}

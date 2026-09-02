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

/// Describes whether a finalized notification applied winning batches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finalized<T> {
    /// The block's winning batches were captured and applied.
    Applied(T),

    /// The block was already reflected without winning batches to capture.
    ///
    /// This includes startup anchors, recovery alignment, and completed state
    /// sync. It does not identify which path reflected the block.
    Synchronized,
}

/// A stateful application whose storage is managed by a [`DatabaseSet`].
///
/// Implementors receive [`DatabaseSet::Unmerkleized`] batches and
/// return [`DatabaseSet::Merkleized`] batches after execution. The surrounding
/// wrapper handles persistence: storing merkleized batches as pending tips on
/// the block tree and applying changesets to the underlying databases on
/// finalization.
///
/// [`Stateful`] may freely clone the application and invoke its methods
/// concurrently. Implementors should treat `Application` as a stateless,
/// deterministic state machine: given the same method inputs and database
/// state, every clone must produce the same state-transition result. Mutable
/// state that affects those results must live in the database batches provided
/// to proposal, verification, and replay methods.
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

    /// Owned data captured from winning batches before they are applied.
    ///
    /// Applications with nothing to capture use `()`.
    type FinalizedArtifact: Send + 'static;

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
        ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        input: Input<Self::Input, Self::Provider>,
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
    /// Validity is relative to those inputs: finalizing a competing branch
    /// later does not retroactively change a completed verdict.
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
    /// This future is scoped to its caller. Stateful may also cancel and retry
    /// it before finalization or pruning. Cancellation and retry must not
    /// violate invariants or lose durable progress.
    ///
    /// Verification may overlap finalization while its batches remain valid.
    /// Stateful retries or rejects requests that cannot safely overlap it.
    /// Read through the provided batches without holding the database set's
    /// locks. Batches may be branch-scoped views rather than historical
    /// snapshots: retained ancestor overlays preserve same-branch state, while
    /// unresolved reads may fall through to the live applied database. Such
    /// batches remain valid only while applied state advances along their branch
    /// (see [`db::Shared::read`] for guard discipline).
    fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
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
    /// This future may be cancelled if its originating request is dropped, or
    /// cancelled and retried before finalization or pruning. Cancellation and
    /// retry must not violate invariants or lose durable progress.
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

    /// Capture data from winning batches before they are applied.
    ///
    /// Only reads completed through `readers` during this call are guaranteed
    /// to observe database state before `batches`. Retain owned values instead
    /// of reader handles when the pre-apply state is required later. The
    /// returned artifact is passed unchanged to [`finalized`](Self::finalized)
    /// after the batches are applied.
    ///
    /// Finalization of this block and every later block waits for this future.
    /// Keep it to cheap reads and defer expensive work behind the durable
    /// handoff. Applications with nothing to capture return `()`.
    fn capture_finalized(
        &mut self,
        context: (E, Self::Context),
        block: &Self::Block,
        batches: &<Self::Databases as DatabaseSet<E>>::Merkleized,
        readers: <Self::Databases as DatabaseSet<E>>::Readers,
    ) -> impl Future<Output = Self::FinalizedArtifact> + Send;

    /// Observe a finalized block after it is reflected in the database set.
    ///
    /// Once the database set is ready, the wrapper calls this for every
    /// finalized block it receives from marshal before releasing that block's
    /// marshal acknowledgement. Blocks applied through normal processing are
    /// reported after [`DatabaseSet::apply`] succeeds. The block's state is
    /// readable from the databases, but durability through that block may still
    /// be pending. A database barrier may run concurrently with this future.
    /// The wrapper releases the block's marshal acknowledgement only after this
    /// future resolves and a barrier covering the block completes.
    ///
    /// [`Finalized::Applied`] carries the artifact captured from the exact
    /// batches applied for this notification. [`Finalized::Synchronized`]
    /// means the block was already reflected and no winning batches were
    /// available. This can occur for the startup anchor on a fresh boot, after
    /// recovery alignment, or following completed state sync.
    ///
    /// During peer state sync, a finalized block may be absorbed into a recorded sync target and
    /// acknowledged without invoking this hook. Blocks still pending when sync completes are
    /// reported or applied during handoff. Applications must derive synchronized state from the
    /// database set rather than rely on receiving every peer-state-sync finalization here.
    ///
    /// This hook receives read-only database handles and may overlap verification
    /// of blocks built on the newly finalized block or one of its retained
    /// descendants. Result-affecting mutations must be made through normal block
    /// execution, not from this observer.
    ///
    /// For blocks that are reported, this is an at-least-once notification
    /// inherited from marshal's reporter stream. A crash after this hook runs
    /// but before a database sync covering the block and marshal's processed
    /// position are durable may cause the same block to be reported again.
    ///
    /// # Panics
    ///
    /// Implementations should panic if observing finalized state fails.
    fn finalized(
        &mut self,
        _context: (E, Self::Context),
        _block: &Self::Block,
        _provenance: Finalized<Self::FinalizedArtifact>,
        _readers: <Self::Databases as DatabaseSet<E>>::Readers,
    ) -> impl Future<Output = ()> + Send {
        async {}
    }
}

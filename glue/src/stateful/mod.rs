//! Speculative and finalized QMDB state for applications built on consensus.
//!
//! `stateful` lets an [`Application`] execute blocks against QMDB databases while the [`Stateful`]
//! actor manages storage. [`Stateful`] maintains state for every pending block built on the
//! finalized tip, applies finalized blocks to the databases, and can bootstrap a new node from
//! peers with QMDB state sync. Its [`Mailbox`] implements the consensus
//! [`Application`](commonware_consensus::Application) and receives finalized blocks from marshal as
//! a [`Reporter`](commonware_consensus::Reporter).
//!
//! # Overview
//!
//! The _application_ executes a block against unmerkleized database batches and returns the
//! merkleized result. [`Stateful`] holds each accepted result in memory as the _pending state_ of
//! its block.
//!
//! Upon `propose` or `verify` of a block with parent `p`:
//!
//! * Fork batches from the pending state of `p`, or from the databases if `p` is the last applied
//!   block. If neither exists, recover the state of `p` first (see
//!   [Lazy Recovery](#lazy-recovery)).
//! * Call [`Application::propose`] or [`Application::verify`] with those batches.
//! * Keep the result as the pending state of the block if it matches the block's
//!   [`sync_targets`](Application::sync_targets). A mismatched proposal panics, and a mismatched
//!   verification votes `false`.
//!
//! Upon finalization of block `b` (marshal delivers finalized blocks in height order):
//!
//! * Answer `false` to verifications of blocks that cannot descend from `b`, and restart those
//!   that cannot continue across the finalization.
//! * Take the pending state of `b`, or re-execute `b` with [`Application::apply`] if it has none.
//! * Discard pending state that does not descend from `b`.
//! * Call [`Application::capture`], apply the state of `b` to the databases, then call
//!   [`Application::finalized`].
//! * Acknowledge `b` to marshal once `finalized` resolves and `b` is durable (see
//!   [Persistence](#persistence)).
//!
//! # Architecture
//!
//! [`Stateful`] runs in one of two modes. While state sync runs, it rejects proposals, defers
//! verifications, and uses finalized blocks to advance the sync target. Once its databases are
//! ready, it serves proposals, verifications, and finalizations as described above.
//!
//! The [`db`] module defines the batch lifecycle traits ([`db::Unmerkleized`], [`db::Merkleized`],
//! [`db::ManagedDb`]) and the [`db::DatabaseSet`] trait that groups one or more databases into a
//! single unit. The [`db::p2p`] module provides a resolver over
//! [`commonware-resolver`](commonware_resolver) that fetches sync operations from peers and serves
//! local operations to them. Its [`Mailbox`](db::p2p::Mailbox) implements
//! [`commonware_storage::qmdb::sync::Source`]. The [`probe`] module gathers a recent finalization
//! to sync from.
//!
//! # Startup
//!
//! 1. Load a [`SyncPlan`] with [`SyncPlan::init`].
//! 2. If [`SyncPlan::should_sync`] returns `true`, select a finalized floor and persist it with
//!    [`SyncPlan::set_floor`].
//! 3. Start marshal from [`SyncPlan::marshal_start`] and pass the same plan to [`Stateful`] as
//!    [`Config::plan`].
//!
//! With a persisted floor, [`Stateful`] runs [state sync](#state-sync). Without one, it _recovers_:
//! before handling any message, it opens the databases at the later of marshal's processed height
//! and the recorded completion height (genesis on a new node).
//!
//! _Completion_ is recorded when state sync converges and on every recovery. Once it is recorded,
//! peer state sync never runs on the node again.
//!
//! # State Sync
//!
//! State sync follows a single trusted target at a time: the targets committed by a finalized
//! block. The peers serving operations and proofs remain untrusted, and their responses are
//! verified against that target.
//!
//! Upon startup with persisted floor `f`:
//!
//! * Sync the databases toward the targets of `f`, or toward those of the block backing marshal's
//!   processed height if marshal has already passed `f` (marshal does not redeliver blocks at or
//!   below its processed height).
//!
//! Upon finalization of block `b` while syncing:
//!
//! * Retain `b` with its marshal acknowledgement.
//! * Once marshal's pending acknowledgement window is full, record the newest retained block as the
//!   sync target and acknowledge every retained block.
//!
//! Upon convergence at anchor `a`:
//!
//! * Acknowledge retained blocks at or below `a` without running application hooks.
//! * Apply retained blocks above `a` in height order, as for any finalization, and acknowledge them
//!   once they are durable.
//! * Record completion, attach the databases to the resolvers, and start serving requests.
//!
//! # Persistence
//!
//! Pending state is held only in memory. The databases and the state sync metadata are durable.
//!
//! * Once the databases are ready, a finalized block is acknowledged to marshal only when database
//!   state through it is durable, so marshal's processed height does not pass durable database
//!   state. After a crash, recovery opens every database at the recovery height (rewinding any
//!   that are ahead), and the blocks above it are delivered and applied again.
//! * Once the databases are ready, the _applied tip_ is the latest block they reflect. [`Stateful`]
//!   requires marshal to deliver every finalized block above its applied tip in height order. It
//!   acknowledges a redelivered block at or below the tip without repeating its effects and panics
//!   on a block that skips heights. The startup floor is the only permitted jump, so a live marshal
//!   floor must not leave an unapplied height below it.
//! * During state sync, retained blocks are acknowledged before the databases reach them.
//!   Following [Startup](#startup), the floor is durable before marshal starts from it, so a crash
//!   before completion resumes [state sync](#state-sync) from that floor or from a newer
//!   selection, whether or not state sync is requested. A lagging selection cannot move the floor
//!   backward.
//! * Completion is recorded only after the converged state and every applied handoff block are
//!   durable, and before the databases are pruned or exposed.
//!
//! [`Application::finalized`] describes which hooks may run again after a crash.
//!
//! # Lazy Recovery
//!
//! After a restart no pending state exists. When `propose` or `verify` needs the state of a parent
//! that is neither pending nor the last applied block, [`Stateful`] walks back through the block
//! DAG (via a [`BlockProvider`](commonware_consensus::marshal::ancestry::BlockProvider)) to the
//! nearest pending or applied block, then replays forward with [`Application::apply`]. Each
//! replayed block becomes pending state as soon as it is rebuilt, so a cancelled request does not
//! discard completed replay.
//!
//! Consensus may build on a block before it is certified (for example, with stable leaders), so a
//! replayed ancestor is not guaranteed to be valid. Replayed state is reusable as parent state but
//! is never a verification verdict: verifying a replayed block still runs [`Application::verify`].
//!
//! # Failures
//!
//! [`Stateful`] panics if a proposal does not match its sync targets, if [`Application::apply`]
//! cannot execute or reproduce a finalized block, if marshal delivers a finalized block that skips
//! heights above the applied tip (see [Persistence](#persistence)), if state sync fails, if a
//! database operation fails (see [Failures](db#failures)), if a state sync metadata write fails, or
//! if marshal cannot return a block needed at startup. If shutdown interrupts a database barrier,
//! [`Stateful`] stops without acknowledging the blocks that barrier covers.
//!
//! # Compatibility
//!
//! The [`Stateful`] application may be used with [`Deferred`] and [`coding::Marshaled`], but not
//! with [`Inline`]: [`Inline`] does not verify the correctness of the embedded context within the
//! [`CertifiableBlock`].
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
///
/// Pairs the input [`Stateful`] receives from its caller with the provider from
/// [`Config::provider`], so an outer application can supply its own input independently of the
/// provider.
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
/// [`Stateful`] may freely clone the application and invoke its methods concurrently. Implementors
/// should treat `Application` as a stateless, deterministic state machine: given the same method
/// inputs and database state, every clone must produce the same state-transition result. Mutable
/// state that affects those results must live in the database batches provided to proposal,
/// verification, and replay methods.
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
    /// This may be a mempool that serves transactions, a stream of certificates, or any other
    /// handle to data that drives state transitions. [`Stateful`] clones it into each proposal, so
    /// it must be cheap to clone (e.g. `()` or a handle).
    type Provider: Send + Clone;

    /// Per-proposal input from the caller of [`Stateful`], passed to [`propose`](Self::propose)
    /// with the [`Provider`](Self::Provider) as an [`Input`].
    ///
    /// Use `()` when callers supply no input.
    type Input: Send;

    /// Returns the per-database sync targets that `block` commits to.
    ///
    /// [`Stateful`] treats these targets as the block's state commitment: proposed, verified, and
    /// replayed results are checked against them, recovery opens the databases at them, and state
    /// sync trusts them and verifies peer data against them.
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
    /// This future may be cancelled by consensus if the caller drops its response receiver.
    /// Implementations should be cancellation-safe: dropping and retrying must not violate
    /// invariants or lose durable progress.
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
    /// Returns [`None`] only if the block is permanently invalid for the supplied context,
    /// ancestry, and batches. While validity may still change, the future should stay pending:
    /// there is no abstain value, so abstaining means not resolving until validity is decided or
    /// the request is cancelled. A verdict is relative to its inputs. Finalizing a competing branch
    /// later does not change a completed verdict.
    ///
    /// Verification must reject any block whose execution result does not match the block's
    /// committed state (for example, a state root mismatch). [`Stateful`] votes `false` on any
    /// returned state that does not match [`sync_targets`](Self::sync_targets), so implementations
    /// need not re-check those. Applications using
    /// [`qmdb::current`](commonware_storage::qmdb::current) must still reject blocks whose
    /// committed canonical root differs from the merkleized batch root, because the sync targets
    /// cover only the ops root and operation range.
    ///
    /// This future is scoped to its caller. [`Stateful`] may also cancel and retry it before
    /// finalization or pruning. Cancellation and retry must not violate invariants or lose durable
    /// progress.
    ///
    /// Verification may overlap finalization while its batches remain valid, and [`Stateful`]
    /// retries or rejects requests that cannot. Batches may be branch-scoped views rather than
    /// historical snapshots: retained ancestor overlays preserve same-branch state, while
    /// unresolved reads may fall through to the live applied database, so batches remain valid only
    /// while applied state advances along their branch. Read through the provided batches without
    /// holding the database set's locks (see [`db::Shared::read`] for guard discipline).
    fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> impl Future<Output = Option<<Self::Databases as DatabaseSet<E>>::Merkleized>> + Send;

    /// Re-executes `block` to reconstruct its merkleized state.
    ///
    /// [`Stateful`] calls this when it lacks the state of `block`: during lazy recovery of a
    /// missing ancestor (e.g. after a restart), and during finalization of a block with no pending
    /// state.
    ///
    /// The returned state must match what [`verify`](Self::verify) accepts for `block`.
    /// [`Stateful`] checks it against [`sync_targets`](Self::sync_targets) and reuses it as parent
    /// state, but never as a verdict: a request to verify the replayed block still runs
    /// [`verify`](Self::verify). A replayed result may be committed at finalization, and
    /// [`Stateful`] cannot check block-specific commitments beyond the sync targets.
    ///
    /// Returns [`None`] if the block cannot be executed, and [`Stateful`] then rejects the ancestry
    /// that depends on it: a replayed ancestor is not guaranteed to have passed
    /// [`verify`](Self::verify) anywhere (see [Lazy Recovery](crate::stateful#lazy-recovery)).
    /// [`Stateful`] panics if this returns [`None`], or state that does not match the sync targets,
    /// for a finalized block.
    ///
    /// This future may be cancelled if its originating request is dropped, or cancelled and
    /// retried before finalization or pruning. Cancellation and retry must not violate invariants
    /// or lose durable progress.
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
    /// Only reads completed through `readers` during this call are guaranteed to observe database
    /// state before `batches`. Retain owned values instead of reader handles when the pre-apply
    /// state is required later. The returned value is passed unchanged to
    /// [`finalized`](Self::finalized) after the batches are applied.
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
    /// [`Stateful`] calls this after every [`DatabaseSet::apply`], in application order. `captured`
    /// is the value [`capture`](Self::capture) returned for the same batches. The block's state is
    /// readable from the databases but may not be durable yet, and a database barrier may run
    /// concurrently with this future. [`Stateful`] acknowledges the block to marshal only after
    /// this future resolves and a barrier covering the block completes.
    ///
    /// Blocks already reflected in the databases skip this hook (see [`capture`](Self::capture)),
    /// so consecutive calls may skip heights after state sync.
    ///
    /// This hook receives read-only database handles and may overlap verification of blocks built
    /// on the newly finalized block or one of its retained descendants. Result-affecting mutations
    /// must be made through normal block execution, not from this observer.
    ///
    /// A crash after this hook runs but before a database sync covering the block and marshal's
    /// processed position are durable may cause the block's batches to be captured, applied, and
    /// observed again after restart.
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

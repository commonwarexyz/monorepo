//! Manage QMDB database instances on behalf of a stateful application.
//!
//! A stateful application built on consensus must maintain speculative state for
//! every pending chain built on top of the finalized tip. This module provides
//! the [`Application`] trait and a [`wrapper::Stateful`] wrapper that automate
//! that bookkeeping:
//!
//! 1. Before each `propose` or `verify` call, the wrapper forks
//!    unmerkleized batches from the parent block's pending state (or from the
//!    committed database state if the parent has already been finalized).
//! 2. The application executes against those batches and returns merkleized
//!    results, which the wrapper stores as a new pending tip keyed by the
//!    block's digest.
//! 3. On finalization, the wrapper applies the winning tip's changesets to the
//!    underlying databases and prunes pending entries from dead forks.
//!
//! The [`db`] module defines the batch lifecycle traits ([`db::Unmerkleized`],
//! [`db::Merkleized`], [`db::ManagedDb`]) and a [`db::DatabaseSet`] trait that
//! extends this to tuples of databases, so applications can work with multiple
//! QMDB instances without manual plumbing.
//!
//! # Lazy Recovery
//!
//! Pending state is kept entirely in memory to avoid disk writes on the
//! consensus hot path. After a restart the map is empty, but the wrapper
//! recovers lazily: when `propose` or `verify` encounters a parent whose
//! state is missing, the wrapper walks back through the block DAG (via a
//! [`BlockProvider`]) to the nearest known ancestor or the finalized tip,
//! then replays forward via [`Application::replay`] to fill the gap. Each
//! replayed block is inserted into the pending map immediately so that
//! partial progress survives timeouts.
//!
//! # TODO
//!
//! - Implement the [`db`] traits across `commonware-storage`'s QMDBs. This
//!   requires two changes to the QMDB API:
//!   1. Remove the `'a` lifetime from batch types. Today, `MerkleizedBatch`
//!      and `UnmerkleizedBatch` borrow the database (`&'a Db`), which prevents
//!      storing them as owned values in the `pending` map. Batches must become
//!      owned (`Send + 'static`) types.
//!   2. Type-erase the parent parameter `P`. QMDB batch types are generic
//!      over their parent (`P`), and the concrete type changes at every chain
//!      depth: a DB-rooted batch has `P = Mmr<...>`, a chained batch has
//!      `P = MerkleizedBatch<..., Mmr<...>>`, a grandchild nests further, etc.
//!      This means `db.new_batch()` and `merkleized.new_batch()` return
//!      different concrete types, violating the
//!      [`Merkleized<Unmerkleized = Self::Unmerkleized>`](db::Merkleized)
//!      constraint on [`ManagedDb`](db::ManagedDb). The fix
//!      is to erase `P` behind a trait object or enum so that all chain depths
//!      share one concrete batch type. The cost is one dynamic dispatch per
//!      `get()` that falls through to a parent -- negligible compared to
//!      storage I/O.
//! - Manage state sync on startup. The wrapper must passively track
//!   finalizations while syncing each database in parallel, then replay
//!   unfinalized blocks to rebuild the pending map before joining consensus.
//!   See `glue/STATE_SYNC.md` for the full design.

use commonware_consensus::{
    marshal::ancestry::{AncestorStream, BlockProvider},
    CertifiableBlock, Epochable, Viewable,
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_runtime::{Clock, Metrics, Spawner};
use db::DatabaseSet;
use rand::Rng;
use std::future::Future;

pub mod db;
pub mod wrapper;

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

    /// Metadata provided by the consensus engine for a given payload.
    ///
    /// This often includes things like the proposer, view number, height, or
    /// epoch. Must be [`Epochable`] and [`Viewable`] so the wrapper can
    /// construct a [`Round`](commonware_consensus::types::Round) for
    /// pending-state pruning.
    type Context: Epochable + Viewable + Send;

    /// The digest type used as the payload in consensus.
    type Payload: Digest;

    /// The block type produced by the application.
    ///
    /// Must implement [`CertifiableBlock`] so the wrapper can extract
    /// the consensus context during lazy recovery (see
    /// [`replay`](Self::replay)).
    type Block: CertifiableBlock<Context = Self::Context>;

    /// The set of databases managed on behalf of this application.
    type Databases: DatabaseSet;

    /// A provider of input to the application.
    ///
    /// This may be a mempool that serves transactions, a stream of
    /// certificates, or any other source of input that drives state
    /// transitions.
    type InputProvider: Clone + Send;

    /// Derive the consensus payload identifier from a block.
    fn payload(block: &Self::Block) -> Self::Payload;

    /// Derive the parent's payload identifier from a block.
    fn parent_payload(block: &Self::Block) -> Self::Payload;

    /// Payload used to initialize the consensus engine in the first epoch.
    fn genesis(&mut self) -> impl Future<Output = Self::Block> + Send;

    /// Build a new block on top of the provided parent ancestry.
    ///
    /// Returns [`None`] if the build fails.
    fn propose<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        context: (E, Self::Context),
        ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet>::Unmerkleized,
        input: &mut Self::InputProvider,
    ) -> impl Future<Output = Option<(Self::Block, <Self::Databases as DatabaseSet>::Merkleized)>> + Send;

    /// Verify a block received from a peer, relative to its ancestry.
    ///
    /// Called before voting. The implementation should execute the block
    /// against the provided batches and merkleize them. Returns [`None`]
    /// only when the block is permanently invalid; if validity may still
    /// change as additional information arrives, continue waiting.
    fn verify<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        context: (E, Self::Context),
        ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet>::Unmerkleized,
    ) -> impl Future<Output = Option<<Self::Databases as DatabaseSet>::Merkleized>> + Send;

    /// Re-execute a previously certified block to reconstruct its
    /// merkleized state.
    ///
    /// Called by the wrapper during lazy recovery when pending state for
    /// an ancestor block is missing (e.g. after a restart). The block is
    /// known-good (it was previously certified), so the implementation
    /// should unconditionally execute the block's state transitions.
    ///
    /// # Panics
    ///
    /// Implementations should panic if execution fails, as this indicates
    /// data corruption or non-determinism.
    fn replay(
        &mut self,
        context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet>::Unmerkleized,
    ) -> impl Future<Output = <Self::Databases as DatabaseSet>::Merkleized> + Send;
}

//! Shared compact QMDB helpers.
//!
//! # What compact dbs store
//!
//! A compact db's only persistent state is its witness journal ([`witness`]), whose entries
//! each snapshot one committed state as the commit operation, the committed leaf count, and
//! the pinned nodes one operation below it. The in-memory compact Merkle
//! ([`crate::merkle::compact`]) is rebuilt from the journal tip on reopen. Without the
//! witness, a compact db could recover its root and continue appending, but it could not
//! serve compact sync to another node.
//!
//! # When compact state changes
//!
//! The servable compact state advances only when a commit is persisted. A db-local commit
//! appends one witness entry during `commit`, `sync`, or `start_sync`. An entry appended by
//! `start_sync` is servable when the call returns and is proven durable only when its handle
//! completes. `rewind` restores the witness from the target journal entry. Unpersisted
//! in-memory mutations are therefore intentionally not servable. `target()` and served
//! responses lag behind `apply_batch()` until the db's next persist.

pub(crate) mod batch;
pub(crate) mod witness;

use crate::{
    Context,
    journal::contiguous::variable,
    merkle::{Family, Location},
    qmdb::{Error, sync::journal::Memory},
};
use commonware_cryptography::Digest;
use commonware_parallel::Strategy;
use commonware_utils::range::NonEmptyRange;

/// Configuration for a compact authenticated db.
#[derive(Clone)]
pub struct Config<C, S: Strategy> {
    /// Strategy used to parallelize merkleization.
    pub strategy: S,

    /// Configuration for the journal that persists the witness.
    pub witness: variable::Config<()>,

    /// Codec config used to decode the persisted last commit operation on reopen.
    pub commit_codec_config: C,
}

/// Build a compact db from state fetched by the sync engine.
///
/// A compact db retains exactly its final commit, so the sync journal must hold the single
/// operation at `range.start()`; anything else is
/// [`Error::UnexpectedData`]. Opens the witness journal and hands the pieces to `init`, the
/// db's `init_from_sync`.
pub(crate) async fn from_sync_result<E, F, D, C, S, Op, DB>(
    context: E,
    config: Config<C, S>,
    log: Memory<F, E, Op>,
    pinned_nodes: Option<Vec<D>>,
    range: NonEmptyRange<Location<F>>,
    init: impl FnOnce(S, witness::Journal<E, F, D>, C, Location<F>, Vec<D>, Op) -> Result<DB, Error<F>>,
) -> Result<DB, Error<F>>
where
    E: Context,
    F: Family,
    D: Digest,
    S: Strategy,
{
    let last_commit_loc = range.start();
    let (start, ops) = log.into_parts();
    let (Ok([op]), true) = (<[Op; 1]>::try_from(ops), start == last_commit_loc) else {
        return Err(Error::UnexpectedData(last_commit_loc));
    };

    let journal = variable::Journal::init(context.child("witness"), config.witness).await?;
    init(
        config.strategy,
        journal,
        config.commit_codec_config,
        last_commit_loc,
        // None only happens at the genesis boundary, where nothing is pinned.
        pinned_nodes.unwrap_or_default(),
        op,
    )
}

//! A collection of authenticated databases inspired by QMDB (Quick Merkle Database).
//!
//! # Terminology
//!
//! A database's state is derived from an append-only log of state-changing _operations_.
//!
//! In a _keyed_ database, a _key_ either has a _value_ or it doesn't, and different types of
//! operations modify the state of a specific key. A key that has a value can change to one without
//! a value through the _delete_ operation. The _update_ operation gives a key a specific value. We
//! sometimes call an update for a key that doesn't already have a value a _create_ operation, but
//! its representation in the log is the same.
//!
//! Keys with values are called _active_. An operation is called _active_ if (1) its key is active,
//! (2) it is an update operation, and (3) it is the most recent operation for that key.
//!
//! # Database Lifecycle
//!
//! All authenticated variants are modified through a batch API that follows a common pattern:
//! 1. Create a batch from the database.
//! 2. Stage mutations on the batch.
//! 3. Merkleize the batch. This resolves mutations against the current state and computes
//!    the Merkle root that would result from applying them.
//! 4. Inspect the root or create child batches.
//! 5. Apply the batch to the database (unapplied ancestors are applied automatically).
//!
//! [any] and [current] advance the inactivity floor with a [`floor::Policy`] when merkleizing.
//! `merkleize` uses [`floor::Proportional`], which keeps the share of inactive operations in the
//! log bounded, and `merkleize_with` takes a caller-owned policy. [store] takes the policy when
//! applying a batch. [immutable] and [keyless], including their compact variants, start each batch
//! at the database or parent batch's floor, and `with_inactivity_floor` sets a different one. That
//! default holds the floor, so their logs grow until the application advances it.
//!
//! A batch records no commit metadata unless `with_metadata` sets it ([store] takes metadata in
//! `finalize` instead). Metadata belongs to one batch. Child batches start without it, and [any]
//! and [current] keep it through `stage` and `expand`.
//!
//! The specific mutation methods vary by variant.
//! See each variant's module documentation for the concrete API and usage examples.
//!
//! # Batch validity
//!
//! A batch's chain has a set of states: its recorded database boundary, each ancestor's tip, and
//! the batch's own tip. While the database is at one of them, value reads through the batch are
//! exact, because the batch retains the writes of every ancestor the database has not applied. At
//! any other state, for example after a sibling or a descendant of the batch is applied, reads
//! return [`Error::StaleRead`], and merkleize and apply return [`Error::StaleBatch`]. Merkleize
//! also returns [`Error::StaleBatch`] once an unapplied ancestor has been dropped, because it
//! reads ancestor operations through the weak parent links, so every unapplied ancestor must be
//! held until its descendant is merkleized. See [`chain`] for the details.
//!
//! # Variable-size writes
//!
//! Callers must ensure that the journal's [`codec_config`] can decode the keys, values, and commit
//! metadata they write to the operation log. For example, if byte values are limited to 4096 bytes,
//! check the length of the final value before adding it to a batch. A commit can succeed with an
//! out-of-bounds value. Reads, proofs, and recovery can then fail when they decode it.
//! [Compact databases](compact) apply the same requirement to commit metadata in their witnesses.
//!
//! [`codec_config`]: crate::journal::contiguous::variable::Config#structfield.codec_config
//!
//! # Durability
//!
//! `commit()` makes applied state durable. `start_sync()` is its pipelined form, which also
//! tries to advance the recovery watermark to bound startup recovery. `sync()` makes applied state
//! durable and advances the operation journal's recovery watermark. Full databases rebuild their
//! Merkle digests from retained operations at every startup.
//!
//! # Initialization bounds
//!
//! With `Some(max_size)`, `init` opens the latest retained commit with at most `max_size`
//! operations, counting commit records and pruned operations. `None` opens the latest retained
//! state. Zero is invalid, and a bound above the stored size does not grow the database.
//! If pruning leaves no commit at or below the bound, initialization returns
//! [`Error::NoRetainedCommit`]. Initialization also fails if pruning removed history needed
//! to rebuild the selected commit.
//!
//! Initialization durably removes later history before returning successfully. The bound does not
//! limit future appends. To require an exact checkpoint, also check the recovered root and range.
//!
//! # Ownership
//!
//! Mutating methods take the database by value and return it on success. If a mutating
//! method returns an error, or its future is dropped before it finishes, the database is
//! gone: state that was not yet durable is discarded, but everything already on disk stays
//! recoverable. This applies to validation errors too (e.g. rejecting a stale batch);
//! use each database's `validate_batch` to pre-check a batch without risking the handle.
//!
//! # Traits
//!
//! The `test-traits` feature compiles `any::traits`, whose `DbAny` and `Provable` traits give the
//! crate's tests and benchmarks one interface over the keyed mutable variants ([any] and
//! [current]). Outside unit-test builds, this shared interface requires the `test-traits` feature.
//!
//! # Acknowledgments
//!
//! The following resources were used as references when implementing this crate:
//!
//! * [QMDB: Quick Merkle Database](https://arxiv.org/abs/2501.05262)
//! * [Merkle Mountain
//!   Ranges](https://github.com/opentimestamps/opentimestamps-server/blob/master/doc/merkle-mountain-range.md)

use crate::{
    Context,
    index::{Cursor, Unordered as Index},
    journal::{
        Error as JournalError,
        authenticated::{self, Backing, Config as MerkleConfig, Journal, Recovery},
        contiguous::Contiguous,
    },
    merkle::{
        Bagging, Family, Location,
        hasher::{Hasher as MerkleHasher, Standard as StandardHasher},
    },
    qmdb::operation::Committable,
};
use commonware_codec::{Encode, EncodeShared};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use thiserror::Error;

pub mod any;
pub(crate) mod bitmap;
mod cache;
pub mod chain;
pub mod compact;
#[cfg(test)]
mod conformance;
pub mod current;
pub mod floor;
pub mod immutable;
pub mod keyless;
mod metrics;
pub mod operation;
mod snapshot;
pub mod store;
pub mod sync;
pub mod value;
pub mod verify;

pub use snapshot::SnapshotBuild;
pub(super) use snapshot::build_snapshot_from_log;
pub use verify::ProofExt;

/// Reject a bound that cannot retain the bootstrap commit.
pub(crate) fn validate_initialization_bound<F: Family>(
    bound: Option<Location<F>>,
) -> Result<(), Error<F>> {
    if bound.is_some_and(|size| size == 0) {
        return Err(Error::InvalidInitializationBound);
    }
    Ok(())
}

/// Classify pruning while selecting a commit for a bounded open.
fn selection_error<F: Family>(error: JournalError, max_size: Option<Location<F>>) -> Error<F> {
    match (error, max_size) {
        (JournalError::ItemPruned(_), Some(cap)) => Error::NoRetainedCommit(cap),
        (error, _) => error.into(),
    }
}

/// Validate a selected commit against its retained history and return its floor.
fn validate_initialization_commit<F: Family>(
    start: u64,
    size: u64,
    fresh: bool,
    commit: Option<&impl Committable<F>>,
    replay_from_floor: bool,
) -> Result<Option<Location<F>>, Error<F>> {
    if size == 0 {
        return if fresh {
            Ok(None)
        } else {
            Err(Error::DataCorrupted("no retained commit"))
        };
    }
    let floor = commit
        .and_then(Committable::inactivity_floor)
        .ok_or(Error::DataCorrupted(
            "selected operation has no commit floor",
        ))?;
    if *floor >= size {
        return Err(Error::DataCorrupted(
            "inactivity floor exceeds commit location",
        ));
    }
    if replay_from_floor && *floor < start {
        return Err(Error::HistoricalFloorPruned(Location::new(size)));
    }
    Ok(Some(floor))
}

/// Check the selected commit before recovery discards history. Rebuilding a snapshot from its floor
/// additionally requires retaining that floor. Keyless only restores commit fields.
pub(crate) async fn validate_initialization<F, E, C, H, S>(
    pending: &Recovery<F, E, C, H, S>,
    replay_from_floor: bool,
) -> Result<Option<Location<F>>, Error<F>>
where
    F: Family,
    E: Context,
    C: Backing<E, Item: Committable<F> + EncodeShared>,
    H: Hasher,
    S: Strategy,
{
    let bounds = pending.bounds();
    let commit = if bounds.end == 0 {
        None
    } else {
        Some(pending.read(bounds.end - 1).await?)
    };
    validate_initialization_commit(
        bounds.start,
        bounds.end,
        pending.is_fresh(),
        commit.as_ref(),
        replay_from_floor,
    )
}

/// Select a QMDB commit before validating variant-specific reconstruction state.
pub(crate) async fn prepare_initialization<F, E, C, H, S>(
    context: E,
    merkle: MerkleConfig<S>,
    journal: C::Config,
    max_size: Option<Location<F>>,
) -> Result<Recovery<F, E, C, H, S>, Error<F>>
where
    F: Family,
    E: Context,
    C: Backing<E, Item: Committable<F> + EncodeShared>,
    H: Hasher,
    S: Strategy,
{
    validate_initialization_bound(max_size)?;
    Journal::prepare(
        context,
        merkle,
        journal,
        max_size.map(|size| *size),
        |op: &C::Item| op.inactivity_floor().is_some(),
        ROOT_BAGGING,
    )
    .await
    // Every pruning error from this step means the selection found no usable commit.
    .map_err(|err| match err {
        authenticated::Error::Journal(err) => selection_error(err, max_size),
        err => err.into(),
    })
}

/// Merkle peak bagging policy used by QMDB operation roots.
pub(crate) const ROOT_BAGGING: Bagging = Bagging::BackwardFold;

/// Return the Merkle hasher configuration used by QMDB operation roots and proofs.
pub const fn hasher<H: Hasher>() -> StandardHasher<H> {
    StandardHasher::new(ROOT_BAGGING)
}

/// Return the root of an operation log containing only `operation`.
///
/// This lets database variants derive their initial root from the bootstrap commit without
/// opening a database.
fn single_operation_root<F: Family, H: Hasher>(operation: &impl Encode) -> H::Digest {
    let hasher = hasher::<H>();
    let leaf = MerkleHasher::<F>::leaf_digest(
        &hasher,
        F::location_to_position(Location::new(0)),
        &operation.encode(),
    );
    MerkleHasher::<F>::root(&hasher, Location::new(1), 0, [&leaf])
        .expect("a single-leaf Merkle root is always valid")
}

/// Look up the inactivity floor declared by the commit at `size - 1`. Returns `None` for
/// size zero or when the retained operation at `size - 1` is not a commit.
///
/// # Errors
///
/// - [`JournalError::ItemPruned`] if `size - 1` precedes the oldest retained location.
/// - [`Error::DataCorrupted`] if the commit declares a floor past its own location.
pub(crate) async fn commit_floor_at<F, R>(
    reader: &R,
    size: Location<F>,
) -> Result<Option<Location<F>>, Error<F>>
where
    F: Family,
    R: Contiguous<Item: Committable<F>>,
{
    let Some(last_op) = size.checked_sub(1) else {
        return Ok(None);
    };
    let last_op = *last_op;
    let bounds = reader.bounds();
    if last_op < bounds.start {
        return Err(JournalError::ItemPruned(last_op).into());
    }

    let op = reader.read(last_op).await?;
    let Some(floor) = op.inactivity_floor() else {
        return Ok(None);
    };
    if floor > Location::new(last_op) {
        return Err(Error::DataCorrupted(
            "inactivity floor exceeds commit location",
        ));
    }
    Ok(Some(floor))
}

/// Look up the inactivity floor at the commit boundary required by recovery or sync.
///
/// # Errors
///
/// - [`Error::HistoricalFloorPruned`] if `size` is zero or the retained operation at
///   `size - 1` has no commit floor.
/// - [`JournalError::ItemPruned`] if `size - 1` precedes the oldest retained location.
/// - [`Error::DataCorrupted`] if the commit declares a floor past its own location.
pub(crate) async fn find_inactivity_floor_at<F, R>(
    reader: &R,
    size: Location<F>,
) -> Result<Location<F>, Error<F>>
where
    F: Family,
    R: Contiguous<Item: Committable<F>>,
{
    commit_floor_at(reader, size)
        .await?
        .ok_or(Error::HistoricalFloorPruned(size))
}

/// Compute the inactive peak count for a proof at the requested commit boundary.
pub(crate) async fn inactive_peaks_at<F, R>(
    reader: &R,
    size: Location<F>,
) -> Result<usize, Error<F>>
where
    F: Family,
    R: Contiguous<Item: Committable<F>>,
{
    let floor = commit_floor_at(reader, size)
        .await?
        .ok_or(Error::NotCommitBoundary(size))?;
    Ok(F::inactive_peaks(size, floor))
}

/// Errors that can occur when interacting with an authenticated database.
#[derive(Error, Debug)]
pub enum Error<F: Family> {
    /// A QMDB initialization bound cannot exclude its initial commit.
    #[error("initialization bound must allow at least one operation")]
    InvalidInitializationBound,

    /// No retained commit is at or below the requested initialization bound.
    #[error("no retained commit at or below size: {0}")]
    NoRetainedCommit(Location<F>),

    /// Database state failed a consistency check. The payload names the check.
    #[error("data corrupted: {0}")]
    DataCorrupted(&'static str),

    /// An error from an underlying Merkle structure.
    #[error("merkle error: {0}")]
    Merkle(#[from] crate::merkle::Error<F>),

    /// An error from a metadata store.
    #[error("metadata error: {0}")]
    Metadata(#[from] crate::metadata::Error),

    /// An error from an underlying journal.
    #[error("journal error: {0}")]
    Journal(#[from] JournalError),

    /// An error from the runtime.
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),

    /// The operation at the location, or the bitmap chunk covering it, has been pruned.
    #[error("operation pruned: {0}")]
    OperationPruned(Location<F>),

    /// The requested key was not found in the snapshot.
    #[error("key not found")]
    KeyNotFound,

    /// The key exists in the db, so we cannot prove its exclusion.
    #[error("key exists")]
    KeyExists,

    /// A compact sync result is not exactly one commit at the expected location. The payload is
    /// that location.
    #[error("unexpected data at location: {0}")]
    UnexpectedData(Location<F>),

    /// A requested location is at or past the size of the database or batch being read. The
    /// payloads are the location and that size.
    #[error("location out of bounds: {0} >= {1}")]
    LocationOutOfBounds(Location<F>, Location<F>),

    /// A batched read's locations were out of order.
    #[error("location {1} out of order after {0}")]
    LocationOutOfOrder(Location<F>, Location<F>),

    /// A prune location exceeds the furthest location pruning may reach: the inactivity floor,
    /// or the sync boundary for [current]. The payloads are the requested location and that
    /// bound.
    #[error("prune location {0} beyond minimum required location {1}")]
    PruneBeyondMinRequired(Location<F>, Location<F>),

    /// The batch cannot be merkleized or applied against the database's state.
    ///
    /// This happens when:
    /// - The database is at neither the batch's recorded database boundary nor an ancestor's tip.
    ///   Reads then return [`Error::StaleRead`], except at the batch's own tip, where an applied
    ///   batch still reads but cannot be applied again.
    /// - Merkleize only: an unapplied ancestor was dropped, so merkleize cannot read its
    ///   operations. Value reads are unaffected, because merkleized batches retain their
    ///   ancestors' writes.
    /// - Current merkleize only: the batch was built against another database instance.
    ///
    /// See [`chain`] for more details on staleness detection, and
    /// [batch validity](self#batch-validity) for the states at which a batch stays usable.
    #[error("stale batch: current database state does not match the batch")]
    StaleBatch,

    /// A read through a batch found the database at no state of the batch's chain (see [`chain`]),
    /// for example after a sibling or a descendant of the batch was applied, or after the database
    /// was reinitialized at another state. Build a new batch from the database to read its state.
    #[error("stale read: database is at no state of the batch's chain")]
    StaleRead,

    /// A read by location asked for a location below the inactivity floor: the database's, or for
    /// a batch read the batch's (for an unmerkleized batch, the floor it builds on).
    ///
    /// Whether the journal still retains such a location depends on local pruning, so reads
    /// reject it on every database at the same commitment.
    #[error("location below inactivity floor: {0}")]
    BelowInactivityFloor(Location<F>),

    /// The batch's inactivity floor is lower than the floor it builds on: its parent's, or the
    /// database's for a batch with no parent. The payloads are the batch's floor and that earlier
    /// floor.
    #[error("floor regressed: batch floor {0} < prior floor {1}")]
    FloorRegressed(Location<F>, Location<F>),

    /// A commit's inactivity floor exceeds the commit operation's own location. The floor must
    /// not sit past the commit, since a subsequent `prune(floor)` would then remove the last
    /// readable commit from the journal. The payloads are the requested floor and the commit
    /// operation's location.
    #[error("floor beyond commit location: floor {0} > commit loc {1}")]
    FloorBeyondCommit(Location<F>, Location<F>),

    /// The requested operation count is zero or its final operation is a retained non-commit.
    #[error("size {0} is not a commit boundary")]
    NotCommitBoundary(Location<F>),

    /// The commit at the given operation count cannot be reconstructed from retained history.
    /// The payload is the requested or selected operation count, not its inactivity floor.
    #[error("historical floor pruned for size: {0}")]
    HistoricalFloorPruned(Location<F>),
}

impl<F: Family> From<authenticated::Error<F>> for Error<F> {
    fn from(e: authenticated::Error<F>) -> Self {
        match e {
            authenticated::Error::Journal(j) => Self::Journal(j),
            authenticated::Error::Merkle(m) => Self::Merkle(m),
        }
    }
}

/// For the given `key` which is known to exist in the snapshot with location `old_loc`, update
/// its location to `new_loc`.
///
/// # Panics
///
/// Panics if `key` is not found in the snapshot or if `old_loc` is not found in the cursor.
fn update_known_loc<F: Family, I: Index<Value = Location<F>>>(
    snapshot: &mut I,
    key: &[u8],
    old_loc: Location<F>,
    new_loc: Location<F>,
) {
    let mut cursor = snapshot.get_mut(key).expect("key should be known to exist");
    assert!(
        cursor.find(|&loc| *loc == old_loc),
        "known key with given old_loc should have been found"
    );
    cursor.update(new_loc);
}

/// For the given `key` which is known to exist in the snapshot with location `old_loc`, delete
/// it from the snapshot.
///
/// # Panics
///
/// Panics if `key` is not found in the snapshot or if `old_loc` is not found in the cursor.
fn delete_known_loc<F: Family, I: Index<Value = Location<F>>>(
    snapshot: &mut I,
    key: &[u8],
    old_loc: Location<F>,
) {
    let mut cursor = snapshot.get_mut(key).expect("key should be known to exist");
    assert!(
        cursor.find(|&loc| *loc == old_loc),
        "known key with given old_loc should have been found"
    );
    cursor.delete();
}

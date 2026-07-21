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
//! All variants are modified through a batch API that follows a common pattern:
//! 1. Create a batch from the database.
//! 2. Stage mutations on the batch.
//! 3. Merkleize the batch -- this resolves mutations against the current state and computes
//!    the Merkle root that would result from applying them.
//! 4. Inspect the root or create child batches.
//! 5. Apply the batch to the database (uncommitted ancestors are applied automatically).
//!
//! The specific mutation methods vary by variant.
//! See each variant's module documentation for the concrete API and usage examples.
//!
//! Persistence and cleanup are managed directly on the database: `sync()`, `prune()`,
//! and `destroy()`.
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
//! Keyed mutable variants ([any] and [current]) implement `any::traits::DbAny`.
//!
//! # Acknowledgments
//!
//! The following resources were used as references when implementing this crate:
//!
//! * [QMDB: Quick Merkle Database](https://arxiv.org/abs/2501.05262)
//! * [Merkle Mountain
//!   Ranges](https://github.com/opentimestamps/opentimestamps-server/blob/master/doc/merkle-mountain-range.md)

use crate::{
    index::{
        Cursor, Unordered as Index,
        partitioned::{PartitionRange, Partitioned},
    },
    journal::{
        Error as JournalError,
        contiguous::{Contiguous, Mutable},
    },
    merkle::{
        Bagging, Family, Location,
        hasher::{Hasher as MerkleHasher, Standard as StandardHasher},
    },
    qmdb::operation::Operation,
    translator::Translator,
};
use commonware_codec::Encode;
use commonware_cryptography::Hasher;
use commonware_runtime::Spawner;
use commonware_utils::{
    bitmap::{Atomic, BitMap},
    cache::Clock,
    channel::mpsc,
};
use core::{num::NonZeroUsize, ops::Range};
use futures::{StreamExt as _, future::join_all, pin_mut};
use std::sync::Arc;
use thiserror::Error;

pub mod any;
pub mod batch_chain;
pub(crate) mod bitmap;
pub(crate) mod compact;
#[cfg(test)]
mod conformance;
pub mod current;
pub mod immutable;
pub mod keyless;
mod metrics;
pub mod operation;
pub mod store;
pub mod sync;
pub mod verify;

pub use verify::{
    create_multi_proof, create_proof_store, verify_multi_proof, verify_proof,
    verify_proof_and_extract_digests, verify_proof_and_pinned_nodes,
};

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

/// Look up the inactivity floor declared at the commit immediately preceding `op_count`.
///
/// `op_count` must be a non-zero commit-boundary historical size: the operation at `op_count - 1`
/// must itself be a commit op (one for which `floor_of` returns `Some`).
///
/// # Errors
///
/// - [`Error::HistoricalFloorPruned`] if `op_count` is zero (no preceding commit exists), or if
///   `op_count - 1` is retained but is not a commit op (either because the caller passed a
///   non-commit-boundary size, or because pruning removed the commit that would have governed this
///   size).
/// - [`JournalError::ItemPruned`] if `op_count - 1` precedes the oldest retained location.
pub(crate) async fn find_inactivity_floor_at<F, R>(
    reader: &R,
    op_count: Location<F>,
    floor_of: impl Fn(&R::Item) -> Option<Location<F>>,
) -> Result<Location<F>, Error<F>>
where
    F: Family,
    R: Contiguous,
{
    let Some(last_op) = op_count.checked_sub(1) else {
        return Err(Error::HistoricalFloorPruned(op_count));
    };
    let last_op = *last_op;
    let bounds = reader.bounds();
    if last_op < bounds.start {
        return Err(JournalError::ItemPruned(last_op).into());
    }

    let op = reader.read(last_op).await?;
    let floor = floor_of(&op).ok_or(Error::HistoricalFloorPruned(op_count))?;
    if floor > Location::new(last_op) {
        return Err(Error::DataCorrupted(
            "inactivity floor exceeds commit location",
        ));
    }
    Ok(floor)
}

/// Compute the inactive peak count for a historical operation count.
pub(crate) async fn inactive_peaks_at<F, R>(
    reader: &R,
    op_count: Location<F>,
    floor_of: impl Fn(&R::Item) -> Option<Location<F>>,
) -> Result<usize, Error<F>>
where
    F: Family,
    R: Contiguous,
{
    if op_count == Location::new(0) {
        return Ok(0);
    }

    let floor = find_inactivity_floor_at::<F, _>(reader, op_count, floor_of).await?;
    Ok(F::inactive_peaks(F::location_to_position(op_count), floor))
}

/// Errors that can occur when interacting with an authenticated database.
#[derive(Error, Debug)]
pub enum Error<F: Family> {
    #[error("data corrupted: {0}")]
    DataCorrupted(&'static str),

    #[error("merkle error: {0}")]
    Merkle(#[from] crate::merkle::Error<F>),

    #[error("metadata error: {0}")]
    Metadata(#[from] crate::metadata::Error),

    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),

    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),

    #[error("operation pruned: {0}")]
    OperationPruned(Location<F>),

    /// The requested key was not found in the snapshot.
    #[error("key not found")]
    KeyNotFound,

    /// The key exists in the db, so we cannot prove its exclusion.
    #[error("key exists")]
    KeyExists,

    #[error("unexpected data at location: {0}")]
    UnexpectedData(Location<F>),

    #[error("location out of bounds: {0} >= {1}")]
    LocationOutOfBounds(Location<F>, Location<F>),

    #[error("prune location {0} beyond minimum required location {1}")]
    PruneBeyondMinRequired(Location<F>, Location<F>),

    /// The batch was created from a different database state than the current one.
    ///
    /// See [`batch_chain`] for more details on staleness detection.
    #[error(
        "stale batch: db has {db_size} ops, batch requires {batch_db_size}, {batch_base_size}, or an ancestor boundary"
    )]
    StaleBatch {
        db_size: u64,
        batch_db_size: u64,
        batch_base_size: u64,
    },

    /// The batch's inactivity floor is lower than the database's current floor.
    #[error("floor regressed: batch floor {0} < current floor {1}")]
    FloorRegressed(Location<F>, Location<F>),

    /// The batch's inactivity floor exceeds its own commit operation's location. The floor
    /// must not sit past the commit, since a subsequent `prune(floor)` would then remove the
    /// last readable commit from the journal.
    #[error("floor beyond commit location: floor {0} > commit loc {1}")]
    FloorBeyondSize(Location<F>, Location<F>),

    /// The inactivity floor that governed the requested `historical_size` is not retrievable from
    /// the journal, so the wrapper cannot derive the `inactive_peaks` count needed to construct a
    /// proof matching the historical root.
    ///
    /// Historical proofs require `historical_size` to be a commit-boundary: the operation at
    /// `historical_size - 1` must itself be a commit op declaring the governing floor. This error
    /// fires when the caller passes a non-commit-boundary size, or when pruning has removed the
    /// commit that would have governed the size.
    #[error("historical floor pruned for size: {0}")]
    HistoricalFloorPruned(Location<F>),
}

impl<F: Family> From<crate::journal::authenticated::Error<F>> for Error<F> {
    fn from(e: crate::journal::authenticated::Error<F>) -> Self {
        match e {
            crate::journal::authenticated::Error::Journal(j) => Self::Journal(j),
            crate::journal::authenticated::Error::Merkle(m) => Self::Merkle(m),
        }
    }
}

/// Builds the database's snapshot by replaying the log starting at the inactivity floor. Assumes
/// the log is not pruned beyond the inactivity floor. The callback is invoked for each replayed
/// operation, indicating activity status updates. The first argument of the callback is the
/// activity status of the operation, and the second argument is the location of the operation it
/// inactivates (if any). Returns the number of active keys in the db.
///
/// `init_buffer` sizes the replay read buffer (in bytes). `cache_size` bounds a
/// `(location -> key)` cache that lets collision resolution resolve candidates from memory
/// instead of re-reading the log; `None` disables it.
pub(super) async fn build_snapshot_from_log<F, C, I, Fn>(
    inactivity_floor_loc: crate::merkle::Location<F>,
    reader: &C,
    snapshot: &mut I,
    init_buffer: NonZeroUsize,
    cache_size: Option<NonZeroUsize>,
    mut callback: Fn,
) -> Result<usize, Error<F>>
where
    F: crate::merkle::Family,
    C: Contiguous<Item: Operation<F>>,
    I: Index<Value = crate::merkle::Location<F>>,
    Fn: FnMut(bool, Option<crate::merkle::Location<F>>),
{
    let bounds = reader.bounds();
    let stream = reader.replay(*inactivity_floor_loc, init_buffer).await?;
    pin_mut!(stream);
    let last_commit_loc = bounds.end.saturating_sub(1);

    // Memoize `(location -> key)` for replayed update ops so collision resolution in
    // `find_update_op` resolves candidates from memory instead of re-reading (and re-decoding) the
    // log.
    let mut cache = cache_size.map(Clock::<u64, <C::Item as Operation<F>>::Key>::new);

    let mut active_keys: usize = 0;
    while let Some(result) = stream.next().await {
        let (loc, op) = result?;
        if let Some(key) = op.key() {
            if op.is_delete() {
                let old_loc = delete_key(snapshot, reader, key, cache.as_mut()).await?;
                callback(false, old_loc);
                if old_loc.is_some() {
                    active_keys -= 1;
                }
            } else if op.is_update() {
                let new_loc = crate::merkle::Location::new(loc);
                let old_loc = update_key(snapshot, reader, key, new_loc, cache.as_mut()).await?;
                callback(true, old_loc);
                if old_loc.is_none() {
                    active_keys += 1;
                }

                // This update op is now a `find_update_op` candidate for later ops of its key.
                if let Some(cache) = cache.as_mut() {
                    cache.put(loc, key.clone());
                }
            }
        } else if op.has_floor().is_some() {
            callback(loc == last_commit_loc, None);
        }
    }

    Ok(active_keys)
}

/// Delete `key` from the snapshot if it exists, using a stable log reader, and return the
/// previously associated location.
async fn delete_key<F, I, R>(
    snapshot: &mut I,
    reader: &R,
    key: &<R::Item as Operation<F>>::Key,
    cache: Option<&mut Clock<u64, <R::Item as Operation<F>>::Key>>,
) -> Result<Option<Location<F>>, Error<F>>
where
    F: Family,
    I: Index<Value = Location<F>>,
    R: Contiguous,
    R::Item: Operation<F>,
{
    // If the translated key is in the snapshot, get a cursor to look for the key.
    let Some(cursor) = snapshot.get_mut(key) else {
        return Ok(None);
    };
    delete_at_cursor::<F, _, _>(cursor, reader, key, cache).await
}

/// Delete `key` at `cursor` (obtained from a `get_mut` lookup of `key`), returning its location if
/// it was present among the cursor's conflicts.
async fn delete_at_cursor<F, C, R>(
    mut cursor: C,
    reader: &R,
    key: &<R::Item as Operation<F>>::Key,
    cache: Option<&mut Clock<u64, <R::Item as Operation<F>>::Key>>,
) -> Result<Option<Location<F>>, Error<F>>
where
    F: Family,
    C: Cursor<Value = Location<F>>,
    R: Contiguous,
    R::Item: Operation<F>,
{
    // Find the matching key among all conflicts, then delete it.
    let Some(loc) = find_update_op::<F, _>(reader, &mut cursor, key, cache).await? else {
        return Ok(None);
    };
    cursor.delete();

    Ok(Some(loc))
}

/// Update `key` in the snapshot using a stable log reader, returning its old location if present.
async fn update_key<F, I, R>(
    snapshot: &mut I,
    reader: &R,
    key: &<R::Item as Operation<F>>::Key,
    new_loc: Location<F>,
    cache: Option<&mut Clock<u64, <R::Item as Operation<F>>::Key>>,
) -> Result<Option<Location<F>>, Error<F>>
where
    F: Family,
    I: Index<Value = Location<F>>,
    R: Contiguous,
    R::Item: Operation<F>,
{
    // If the translated key is not in the snapshot, insert the new location. Otherwise, get a
    // cursor to look for the key.
    let Some(cursor) = snapshot.get_mut_or_insert(key, new_loc) else {
        return Ok(None);
    };
    update_at_cursor::<F, _, _>(cursor, reader, key, new_loc, cache).await
}

/// Update `key` to `new_loc` at `cursor` (obtained from a `get_mut_or_insert` lookup of `key`),
/// returning its old location if it was present among the cursor's conflicts; otherwise `new_loc`
/// is inserted at the cursor.
async fn update_at_cursor<F, C, R>(
    mut cursor: C,
    reader: &R,
    key: &<R::Item as Operation<F>>::Key,
    new_loc: Location<F>,
    cache: Option<&mut Clock<u64, <R::Item as Operation<F>>::Key>>,
) -> Result<Option<Location<F>>, Error<F>>
where
    F: Family,
    C: Cursor<Value = Location<F>>,
    R: Contiguous,
    R::Item: Operation<F>,
{
    // Find the matching key among all conflicts, then update its location.
    if let Some(loc) = find_update_op::<F, _>(reader, &mut cursor, key, cache).await? {
        assert!(new_loc > loc);
        cursor.update(new_loc);
        return Ok(Some(loc));
    }

    // The key wasn't in the snapshot, so add it to the cursor.
    cursor.insert(new_loc);

    Ok(None)
}

/// Find and return the location of the update operation for `key`, if it exists. The cursor is
/// positioned at the matching location, and can be used to update or delete the key.
async fn find_update_op<F, R>(
    reader: &R,
    cursor: &mut impl Cursor<Value = Location<F>>,
    key: &<R::Item as Operation<F>>::Key,
    mut cache: Option<&mut Clock<u64, <R::Item as Operation<F>>::Key>>,
) -> Result<Option<Location<F>>, Error<F>>
where
    F: Family,
    R: Contiguous,
    R::Item: Operation<F>,
{
    while let Some(&loc) = cursor.next() {
        // Consult the cache first; on a miss, read the log and populate.
        let matches = if let Some(k) = cache.as_deref().and_then(|c| c.get(&*loc)) {
            *k == *key
        } else {
            let op = reader.read(*loc).await?;
            let k = op.key().expect("operation without key");
            let matches = *k == *key;
            if let Some(cache) = cache.as_deref_mut() {
                cache.put(*loc, k.clone());
            }
            matches
        };
        if matches {
            return Ok(Some(loc));
        }
    }

    Ok(None)
}

/// Number of operations the snapshot replay batches per worker-channel send during a parallel build.
const SNAPSHOT_ROUTE_BATCH: usize = 4096;

/// Bounded depth (in batches) of each per-worker channel during a parallel build. Backpressure keeps
/// the replay from running arbitrarily far ahead of a slow worker.
const SNAPSHOT_CHANNEL_DEPTH: usize = 4;

/// A batch of keyed operations routed to a snapshot-build worker: each entry is the op's key, its
/// location, and whether it is a delete.
type RoutedBatch<K> = Vec<(K, u64, bool)>;

/// Build one parallel-init worker's partial snapshot: apply the routed operations (streamed in log
/// order over `rx`) to `index`, resolving translated-key collisions with the worker's own log
/// `reader` and `(location -> key)` cache. Sets the bits of the range's active locations in the
/// shared `active` bitmap (indexed over `activity`, the replayed region) and returns the populated
/// worker index along with the range's active-key count.
async fn build_snapshot_worker<F, C, R>(
    log: Arc<C>,
    mut rx: mpsc::Receiver<RoutedBatch<<C::Item as Operation<F>>::Key>>,
    mut index: R,
    activity: Range<u64>,
    active: Arc<Atomic>,
    cache_size: Option<NonZeroUsize>,
) -> Result<(R, usize), Error<F>>
where
    F: Family,
    C: Contiguous<Item: Operation<F>>,
    R: PartitionRange<Value = Location<F>>,
{
    let mut cache = cache_size.map(Clock::<u64, <C::Item as Operation<F>>::Key>::new);
    while let Some(batch) = rx.recv().await {
        for (key, loc, is_delete) in batch {
            if is_delete {
                if let Some(cursor) = index.get_mut(&key) {
                    delete_at_cursor::<F, _, _>(cursor, &*log, &key, cache.as_mut()).await?;
                }
            } else {
                let new_loc = Location::new(loc);
                if let Some(cursor) = index.get_mut_or_insert(&key, new_loc) {
                    update_at_cursor::<F, _, _>(cursor, &*log, &key, new_loc, cache.as_mut())
                        .await?;
                }

                // This update op is now a `find_update_op` candidate for later ops of its key.
                // `key` is owned by this batch and unused after the update, so move it in.
                if let Some(cache) = cache.as_mut() {
                    cache.put(loc, key);
                }
            }
        }
    }

    // Reconstruct this range's share of the activity bitmap (in parallel with the other workers)
    // and count the active keys. Locations are partitioned across workers, so every bit has a
    // single writer.
    let mut active_keys = 0;
    index.for_each_value(|loc| {
        active.set(**loc - activity.start);
        active_keys += 1;
    });
    Ok((index, active_keys))
}

/// Build a snapshot serially on the calling task via [build_snapshot_from_log], collecting each
/// replayed location's activity status into a [BitMap]. Returns the number of active keys and the
/// activity bitmap (see [SnapshotBuild::build_snapshot]).
async fn build_snapshot_serial<F, C, I>(
    inactivity_floor_loc: Location<F>,
    reader: &C,
    snapshot: &mut I,
    init_buffer: NonZeroUsize,
    cache_size: Option<NonZeroUsize>,
) -> Result<(usize, BitMap), Error<F>>
where
    F: Family,
    C: Contiguous<Item: Operation<F>>,
    I: Index<Value = Location<F>>,
{
    // Track per-op transitions locally: push each op's status and clear the bit of any location it
    // supersedes. The state after the last op is each location's final status.
    let mut activity = BitMap::new();
    let floor = *inactivity_floor_loc;
    let active_keys = build_snapshot_from_log(
        inactivity_floor_loc,
        reader,
        snapshot,
        init_buffer,
        cache_size,
        |is_active, old_loc| {
            activity.push(is_active);
            if let Some(loc) = old_loc {
                activity.set(*loc - floor, false);
            }
        },
    )
    .await?;
    Ok((active_keys, activity))
}

/// Build a snapshot by splitting the log replay across parallel workers, each owning a contiguous
/// range of the index's partitions (see [Partitioned]). Returns the number of active keys and
/// the activity bitmap (see [SnapshotBuild::build_snapshot]).
async fn build_snapshot_parallel<F, E, C, I>(
    snapshot: &mut I,
    context: E,
    inactivity_floor_loc: Location<F>,
    log: &Arc<C>,
    init_concurrency: NonZeroUsize,
    init_buffer: NonZeroUsize,
    cache_size: Option<NonZeroUsize>,
) -> Result<(usize, BitMap), Error<F>>
where
    F: Family,
    E: Spawner,
    C: Contiguous<Item: Operation<F>> + 'static,
    I: Partitioned + Index<Value = Location<F>>,
{
    let count = snapshot.partition_count();
    let workers = (init_concurrency.get() - 1).min(count);

    // No workers: build on this task.
    if workers == 0 {
        return build_snapshot_serial(
            inactivity_floor_loc,
            &**log,
            snapshot,
            init_buffer,
            cache_size,
        )
        .await;
    }

    let floor = *inactivity_floor_loc;
    let range_size = count.div_ceil(workers);

    // `range_size` rounds up, so `range_size * workers` can exceed `count`, leaving trailing
    // ranges empty (and a naive `count - lo` would underflow). Reduce to the number of
    // non-empty ranges so routing (`p / range_size`) stays in `[0, workers)`.
    let workers = count.div_ceil(range_size);
    let per_worker_cache = cache_size.and_then(|n| NonZeroUsize::new(n.get() / workers));
    let end = log.bounds().end;

    // All workers share one atomic bitmap to track the activity bits.
    let active = Arc::new(Atomic::zeroes(end - floor));

    // Spawn one worker per contiguous partition range, each owning its own reader and cache.
    let mut senders = Vec::with_capacity(workers);
    let mut handles = Vec::with_capacity(workers);
    for w in 0..workers {
        let (tx, rx) = mpsc::channel(SNAPSHOT_CHANNEL_DEPTH);
        senders.push(tx);
        let log = log.clone();

        // This worker owns the contiguous partition range [lo, lo + range_len). It allocates
        // only that many slots, so per-worker memory is the range, not the full partition set.
        let lo = w * range_size;
        let range_len = range_size.min(count - lo);
        let worker_index = snapshot.new_range(lo, range_len);
        let active = active.clone();
        let handle = context
            .child("snapshot_worker")
            .with_attribute("worker", w)
            .dedicated()
            .spawn(move |_| {
                build_snapshot_worker::<F, C, I::Range>(
                    log,
                    rx,
                    worker_index,
                    floor..end,
                    active,
                    per_worker_cache,
                )
            });
        handles.push(handle);
    }

    // Replay the log once and route each keyed op to the worker owning its partition.
    // Routing runs in an inner future so any replay failure is captured rather than
    // returned immediately: returning while the worker handles are merely dropped would
    // leave the workers running detached, retaining the log and their range allocations
    // after init has already failed. The stream is also released before the join.
    let routing_result: Result<(), Error<F>> = async {
        let stream = log.replay(floor, init_buffer).await?;
        pin_mut!(stream);
        let mut batches: Vec<RoutedBatch<_>> = (0..workers)
            .map(|_| Vec::with_capacity(SNAPSHOT_ROUTE_BATCH))
            .collect();

        // A closed channel means a worker terminated early (e.g. returned an `Error<F>`
        // while resolving a collision). Stop routing on the first such send failure and
        // let the join below surface that worker's error, rather than panicking on the
        // send.
        while let Some(result) = stream.next().await {
            let (loc, op) = result?;
            let is_delete = op.is_delete();
            let Some(key) = op.into_key() else { continue };
            let w = I::partition_of(key.as_ref()) / range_size;
            batches[w].push((key, loc, is_delete));
            if batches[w].len() >= SNAPSHOT_ROUTE_BATCH {
                let batch =
                    std::mem::replace(&mut batches[w], Vec::with_capacity(SNAPSHOT_ROUTE_BATCH));
                if senders[w].send(batch).await.is_err() {
                    return Ok(());
                }
            }
        }

        // Flush remaining batches before the channels close.
        for (w, batch) in batches.into_iter().enumerate() {
            if !batch.is_empty() && senders[w].send(batch).await.is_err() {
                break;
            }
        }
        Ok(())
    }
    .await;

    // Close the channels so each worker's stream terminates and it returns its index.
    drop(senders);

    // Join workers before surfacing any replay failure, so none outlive a failed init.
    let joined = join_all(handles).await;
    routing_result?;

    // Install each worker's partition range into the snapshot and fold its active-key count in.
    let mut total_items = 0;
    for handle in joined {
        let (worker_index, worker_keys) = handle??;
        snapshot.install_range(worker_index);
        total_items += worker_keys;
    }

    // The join reclaimed exclusive ownership of the shared bitmap, so it can be read back.
    let mut active = Arc::into_inner(active)
        .expect("workers were joined")
        .into_bitmap();

    // The last operation is the final commit (a log always ends with one), which stays active.
    // An empty log has none.
    if let Some(last_commit) = end.checked_sub(1)
        && last_commit >= floor
    {
        active.set(last_commit - floor, true);
    }

    Ok((total_items, active))
}

/// Builds a database's snapshot index from the operations log.
///
/// Generic over the `Index` type so each index controls how it builds: serially with the default
/// method body, or split across parallel workers with an override.
///
/// Sealed: only in-crate index types implement this, so internal invariants (e.g. builds must
/// drop every clone of the shared log before returning) are enforced by the implementations
/// rather than the public contract.
pub trait SnapshotBuild<F: Family>:
    sealed::SnapshotBuildSealed + Index<Value = Location<F>> + Sized + 'static
{
    /// The concurrency configuration the build consumes. Index types that always build serially
    /// declare `()`, so a setting they cannot use is unrepresentable.
    type Concurrency: Copy + Send + 'static;

    /// Replay `log` from `inactivity_floor_loc`, populating `self`. Returns the number of active
    /// keys and the activity status of every replayed location, in location order: a location's
    /// bit is set iff it holds the current operation of an active key or is the last commit.
    ///
    /// `init_buffer` sizes the replay read buffer (in bytes), and `cache_size` bounds each
    /// build's `(location -> key)` cache (`None` disables it).
    // In-crate callers await this future at concrete index types, so the flexibility an explicit
    // `Send` bound on the returned future would add is unused.
    #[allow(async_fn_in_trait)]
    async fn build_snapshot<E, C>(
        &mut self,
        _context: E,
        inactivity_floor_loc: Location<F>,
        log: &Arc<C>,
        _init_concurrency: Self::Concurrency,
        init_buffer: NonZeroUsize,
        cache_size: Option<NonZeroUsize>,
    ) -> Result<(usize, BitMap), Error<F>>
    where
        E: Spawner,
        C: Contiguous<Item: Operation<F>> + 'static,
    {
        build_snapshot_serial(inactivity_floor_loc, &**log, self, init_buffer, cache_size).await
    }
}

mod sealed {
    use crate::translator::Translator;

    pub trait SnapshotBuildSealed {}
    impl<T: Translator, V: Send + Sync> SnapshotBuildSealed for crate::index::unordered::Index<T, V> {}
    impl<T: Translator, V: Send + Sync> SnapshotBuildSealed for crate::index::ordered::Index<T, V> {}
    impl<T: Translator, V: Send + Sync, const P: usize> SnapshotBuildSealed
        for crate::index::partitioned::unordered::Index<T, V, P>
    {
    }
    impl<T: Translator, V: Send + Sync, const P: usize> SnapshotBuildSealed
        for crate::index::partitioned::ordered::Index<T, V, P>
    {
    }
}

impl<F: Family, T: Translator> SnapshotBuild<F> for crate::index::unordered::Index<T, Location<F>> {
    type Concurrency = ();
}
impl<F: Family, T: Translator> SnapshotBuild<F> for crate::index::ordered::Index<T, Location<F>> {
    type Concurrency = ();
}

impl<F: Family, T: Translator, const P: usize> SnapshotBuild<F>
    for crate::index::partitioned::unordered::Index<T, Location<F>, P>
{
    type Concurrency = NonZeroUsize;

    async fn build_snapshot<E, C>(
        &mut self,
        context: E,
        inactivity_floor_loc: Location<F>,
        log: &Arc<C>,
        init_concurrency: NonZeroUsize,
        init_buffer: NonZeroUsize,
        cache_size: Option<NonZeroUsize>,
    ) -> Result<(usize, BitMap), Error<F>>
    where
        E: Spawner,
        C: Contiguous<Item: Operation<F>> + 'static,
    {
        build_snapshot_parallel(
            self,
            context,
            inactivity_floor_loc,
            log,
            init_concurrency,
            init_buffer,
            cache_size,
        )
        .await
    }
}

impl<F: Family, T: Translator, const P: usize> SnapshotBuild<F>
    for crate::index::partitioned::ordered::Index<T, Location<F>, P>
{
    type Concurrency = NonZeroUsize;

    async fn build_snapshot<E, C>(
        &mut self,
        context: E,
        inactivity_floor_loc: Location<F>,
        log: &Arc<C>,
        init_concurrency: NonZeroUsize,
        init_buffer: NonZeroUsize,
        cache_size: Option<NonZeroUsize>,
    ) -> Result<(usize, BitMap), Error<F>>
    where
        E: Spawner,
        C: Contiguous<Item: Operation<F>> + 'static,
    {
        build_snapshot_parallel(
            self,
            context,
            inactivity_floor_loc,
            log,
            init_concurrency,
            init_buffer,
            cache_size,
        )
        .await
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

/// A wrapper of DB state required for implementing inactivity floor management.
pub(crate) struct FloorHelper<
    'a,
    F: Family,
    I: Index<Value = Location<F>>,
    C: Mutable<Item: Operation<F>>,
> {
    pub snapshot: &'a mut I,
    pub log: C,
}

impl<F, I, C> FloorHelper<'_, F, I, C>
where
    F: Family,
    I: Index<Value = Location<F>>,
    C: Mutable<Item: Operation<F>>,
{
    /// Moves the given operation to the tip of the log if it is active, rendering its old location
    /// inactive. If the operation was not active, then this is a no-op. Returns the helper and
    /// whether the operation was moved.
    async fn move_op_if_active(
        mut self,
        op: C::Item,
        old_loc: Location<F>,
    ) -> Result<(Self, bool), Error<F>> {
        let Some(key) = op.key() else {
            return Ok((self, false)); // operations without keys cannot be active
        };

        // If we find a snapshot entry corresponding to the operation, we know it's active.
        let active = {
            let Some(mut cursor) = self.snapshot.get_mut(key) else {
                return Ok((self, false));
            };
            if cursor.find(|&loc| loc == old_loc) {
                // Update the operation's snapshot location to point to tip.
                cursor.update(Location::<F>::new(self.log.bounds().end));
                true
            } else {
                false
            }
        };
        if !active {
            return Ok((self, false));
        }

        // Apply the operation at tip.
        (self.log, _) = self.log.append(&op).await?;

        Ok((self, true))
    }

    /// Raise the inactivity floor by taking one _step_, which involves searching for the first
    /// active operation above the inactivity floor, moving it to tip, and then setting the
    /// inactivity floor to the location following the moved operation. This method is therefore
    /// guaranteed to raise the floor by at least one. Returns the helper and the new inactivity
    /// floor location.
    ///
    /// # Panics
    ///
    /// Expects there is at least one active operation above the inactivity floor, and panics
    /// otherwise.
    async fn raise_floor(
        mut self,
        mut inactivity_floor_loc: Location<F>,
    ) -> Result<(Self, Location<F>), Error<F>> {
        let tip_loc: Location<F> = Location::new(self.log.bounds().end);
        loop {
            assert!(
                *inactivity_floor_loc < tip_loc,
                "no active operations above the inactivity floor"
            );
            let old_loc = inactivity_floor_loc;
            inactivity_floor_loc += 1;
            let op = self.log.read(*old_loc).await?;
            let moved;
            (self, moved) = self.move_op_if_active(op, old_loc).await?;
            if moved {
                return Ok((self, inactivity_floor_loc));
            }
        }
    }
}

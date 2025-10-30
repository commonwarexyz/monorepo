//! An _Any_ authenticated database (ADB) provides succinct proofs of _any_ value ever associated
//! with a key. Its implementation is based on an [Mmr] over a log of state-change operations backed
//! by a [Journal].
//!
//! In an Any db, it is not possible to prove whether the value of a key is the currently active
//! one, only that it was associated with the key at some point in the past. This type of
//! authenticated database is most useful for applications involving keys that are given values once
//! and cannot be updated after.

use crate::{
    adb::{operation::fixed::FixedOperation, Error},
    index::{Cursor, Index},
    journal::contiguous::fixed::{Config as JConfig, Journal},
    mmr::{
        bitmap::BitMap,
        journaled::{Config as MmrConfig, Mmr},
        Location, Position, Proof, StandardHasher as Standard,
    },
    translator::Translator,
};
use commonware_codec::Encode as _;
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage, ThreadPool};
use futures::{
    future::{try_join_all, TryFutureExt as _},
    try_join,
};
use std::num::{NonZeroU64, NonZeroUsize};
use tracing::{debug, warn};

pub mod ordered;
pub mod sync;
pub mod unordered;

/// The size of the read buffer to use for replaying the operations log when rebuilding the
/// snapshot.
const SNAPSHOT_READ_BUFFER_SIZE: usize = 1 << 16;

/// Configuration for an `Any` authenticated db.
#[derive(Clone)]
pub struct Config<T: Translator> {
    /// The name of the [Storage] partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the [Storage] partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the [Storage] partition used to persist the (pruned) log of operations.
    pub log_journal_partition: String,

    /// The items per blob configuration value used by the log journal.
    pub log_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

/// Initialize and return the mmr and log from the given config, correcting any inconsistencies
/// between them. Any uncommitted operations in the log will be rolled back and the state of the
/// db will be as of the last committed operation.
pub(crate) async fn init_mmr_and_log<
    E: Storage + Clock + Metrics,
    O: FixedOperation,
    H: CHasher,
    T: Translator,
>(
    context: E,
    cfg: Config<T>,
    hasher: &mut Standard<H>,
) -> Result<(Location, Mmr<E, H>, Journal<E, O>), Error> {
    let mut mmr = Mmr::init(
        context.with_label("mmr"),
        hasher,
        MmrConfig {
            journal_partition: cfg.mmr_journal_partition,
            metadata_partition: cfg.mmr_metadata_partition,
            items_per_blob: cfg.mmr_items_per_blob,
            write_buffer: cfg.mmr_write_buffer,
            thread_pool: cfg.thread_pool,
            buffer_pool: cfg.buffer_pool.clone(),
        },
    )
    .await?;

    let mut log: Journal<E, O> = Journal::init(
        context.with_label("log"),
        JConfig {
            partition: cfg.log_journal_partition,
            items_per_blob: cfg.log_items_per_blob,
            write_buffer: cfg.log_write_buffer,
            buffer_pool: cfg.buffer_pool,
        },
    )
    .await?;

    // Back up over / discard any uncommitted operations in the log.
    let mut log_size: Location = log.size().await.into();
    let mut rewind_leaf_num = log_size;
    let mut inactivity_floor_loc = Location::new_unchecked(0);
    while rewind_leaf_num > 0 {
        let op = log.read(rewind_leaf_num.as_u64() - 1).await?;
        if let Some(loc) = op.commit_floor() {
            inactivity_floor_loc = loc;
            break;
        }
        rewind_leaf_num -= 1;
    }
    if rewind_leaf_num != log_size {
        let op_count = log_size - rewind_leaf_num;
        warn!(
            ?log_size,
            ?op_count,
            "rewinding over uncommitted log operations"
        );
        log.rewind(rewind_leaf_num.as_u64()).await?;
        log.sync().await?;
        log_size = rewind_leaf_num;
    }

    // Pop any MMR elements that are ahead of the last log commit point.
    let mut next_mmr_leaf_num = mmr.leaves();
    if next_mmr_leaf_num > log_size {
        let op_count = next_mmr_leaf_num - log_size;
        warn!(?log_size, ?op_count, "popping uncommitted MMR operations");
        mmr.pop(op_count.as_u64() as usize).await?;
        next_mmr_leaf_num = log_size;
    }

    // If the MMR is behind, replay log operations to catch up.
    if next_mmr_leaf_num < log_size {
        let op_count = log_size - next_mmr_leaf_num;
        warn!(
            ?log_size,
            ?op_count,
            "MMR lags behind log, replaying log to catch up"
        );
        while next_mmr_leaf_num < log_size {
            let op = log.read(next_mmr_leaf_num.as_u64()).await?;
            mmr.add_batched(hasher, &op.encode()).await?;
            next_mmr_leaf_num += 1;
        }
        mmr.sync(hasher).await.map_err(Error::Mmr)?;
    }

    // At this point the MMR and log should be consistent.
    assert_eq!(log.size().await, mmr.leaves());

    Ok((inactivity_floor_loc, mmr, log))
}

/// Common implementation for pruning an Any database.
///
/// # Errors
///
/// - Returns [crate::mmr::Error::LocationOverflow] if `target_prune_loc` >
///   [crate::mmr::MAX_LOCATION].
/// - Returns [crate::mmr::Error::RangeOutOfBounds] if `target_prune_loc` is greater than the
///   inactivity floor.
async fn prune_db<E, O, H>(
    mmr: &mut Mmr<E, H>,
    log: &mut Journal<E, O>,
    hasher: &mut Standard<H>,
    target_prune_loc: Location,
    inactivity_floor_loc: Location,
    op_count: Location,
) -> Result<(), Error>
where
    E: Storage + Clock + Metrics,
    O: FixedOperation,
    H: CHasher,
{
    if target_prune_loc > inactivity_floor_loc {
        return Err(crate::mmr::Error::RangeOutOfBounds(target_prune_loc).into());
    }
    let target_prune_pos = Position::try_from(target_prune_loc)?;

    if mmr.size() == 0 {
        // DB is empty, nothing to prune.
        return Ok(());
    };

    // Sync the mmr before pruning the log, otherwise the MMR tip could end up behind the log's
    // pruning boundary on restart from an unclean shutdown, and there would be no way to replay
    // the operations between the MMR tip and the log pruning boundary.
    mmr.sync(hasher).await?;

    if !log.prune(target_prune_loc.as_u64()).await? {
        return Ok(());
    }

    debug!(
        log_size = op_count.as_u64(),
        ?target_prune_loc,
        "pruned inactive ops"
    );

    mmr.prune_to_pos(hasher, target_prune_pos).await?;

    Ok(())
}

/// Common implementation for historical_proof.
///
/// Generates a proof with respect to the state of the MMR when it had `op_count` operations.
///
/// # Errors
///
/// - Returns [crate::mmr::Error::LocationOverflow] if `op_count` or `start_loc` >
///   [crate::mmr::MAX_LOCATION].
/// - Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= `op_count` or `op_count` >
///   number of operations in the log.
/// - Returns [`Error::OperationPruned`] if `start_loc` has been pruned.
async fn historical_proof<E, O, H>(
    mmr: &Mmr<E, H>,
    log: &Journal<E, O>,
    op_count: Location,
    start_loc: Location,
    max_ops: NonZeroU64,
) -> Result<(Proof<H::Digest>, Vec<O>), Error>
where
    E: Storage + Clock + Metrics,
    O: FixedOperation,
    H: CHasher,
{
    let size = Location::new_unchecked(log.size().await);
    if op_count > size {
        return Err(crate::mmr::Error::RangeOutOfBounds(size).into());
    }
    if start_loc >= op_count {
        return Err(crate::mmr::Error::RangeOutOfBounds(start_loc).into());
    }
    let end_loc = std::cmp::min(op_count, start_loc.saturating_add(max_ops.get()));

    let mmr_size = Position::try_from(op_count)?;
    let proof = mmr
        .historical_range_proof(mmr_size, start_loc..end_loc)
        .await?;

    let mut ops = Vec::with_capacity((end_loc.as_u64() - start_loc.as_u64()) as usize);
    let futures = (start_loc.as_u64()..end_loc.as_u64())
        .map(|i| log.read(i))
        .collect::<Vec<_>>();
    try_join_all(futures)
        .await?
        .into_iter()
        .for_each(|op| ops.push(op));

    Ok((proof, ops))
}

/// Update the location of `key` to `new_loc` in the snapshot and return its old location, or insert
/// it if the key isn't already present.
async fn update_loc<E, I: Index<Value = Location>, O>(
    snapshot: &mut I,
    log: &Journal<E, O>,
    key: &<O as FixedOperation>::Key,
    new_loc: Location,
) -> Result<Option<Location>, Error>
where
    E: Storage + Clock + Metrics,
    O: FixedOperation,
{
    // If the translated key is not in the snapshot, insert the new location. Otherwise, get a
    // cursor to look for the key.
    let Some(mut cursor) = snapshot.get_mut_or_insert(key, new_loc) else {
        return Ok(None);
    };

    // Find the matching key among all conflicts, then update its location.
    if let Some(loc) = find_update_op(log, &mut cursor, key).await? {
        assert!(new_loc > loc);
        cursor.update(new_loc);
        return Ok(Some(loc));
    }

    // The key wasn't in the snapshot, so add it to the cursor.
    cursor.insert(new_loc);

    Ok(None)
}

/// Delete `key` from the snapshot if it exists, returning the location that was previously
/// associated with it.
async fn delete_key<E, I, O>(
    snapshot: &mut I,
    log: &Journal<E, O>,
    key: &O::Key,
) -> Result<Option<Location>, Error>
where
    E: Storage + Clock + Metrics,
    I: Index<Value = Location>,
    O: FixedOperation,
{
    // If the translated key is in the snapshot, get a cursor to look for the key.
    let Some(mut cursor) = snapshot.get_mut(key) else {
        return Ok(None);
    };

    // Find the matching key among all conflicts, then delete it.
    let Some(loc) = find_update_op(log, &mut cursor, key).await? else {
        return Ok(None);
    };
    cursor.delete();

    Ok(Some(loc))
}

/// Find and return the location of the update operation for `key`, if it exists. The cursor is
/// positioned at the matching location, and can be used to update or delete the key.
async fn find_update_op<E, C, O>(
    log: &Journal<E, O>,
    cursor: &mut C,
    key: &<O as FixedOperation>::Key,
) -> Result<Option<Location>, Error>
where
    E: Storage + Clock + Metrics,
    C: Cursor<Value = Location>,
    O: FixedOperation,
{
    while let Some(&loc) = cursor.next() {
        let op = log.read(*loc).await?;
        let k = op.key().expect("operation without key");
        if *k == *key {
            return Ok(Some(loc));
        }
    }

    Ok(None)
}

/// A wrapper of DB state required for invoking operations shared across variants.
pub(crate) struct Shared<
    'a,
    E: Storage + Clock + Metrics,
    I: Index<Value = Location>,
    O: FixedOperation,
    H: CHasher,
> {
    pub snapshot: &'a mut I,
    pub mmr: &'a mut Mmr<E, H>,
    pub log: &'a mut Journal<E, O>,
    pub hasher: &'a mut Standard<H>,
}

impl<E, I, O, H> Shared<'_, E, I, O, H>
where
    E: Storage + Clock + Metrics,
    I: Index<Value = Location>,
    O: FixedOperation,
    H: CHasher,
{
    /// Append `op` to the log and add it to the MMR. The operation will be subject to rollback
    /// until the next successful `commit`.
    pub(crate) async fn apply_op(&mut self, op: O) -> Result<(), Error> {
        let encoded_op = op.encode();

        // Append operation to the log and update the MMR in parallel.
        try_join!(
            self.mmr
                .add_batched(self.hasher, &encoded_op)
                .map_err(Error::Mmr),
            self.log.append(op).map_err(Error::Journal)
        )?;

        Ok(())
    }

    /// Moves the given operation to the tip of the log if it is active, rendering its old location
    /// inactive. If the operation was not active, then this is a no-op. Returns the old location of
    /// the operation if it was active.
    pub(crate) async fn move_op_if_active(
        &mut self,
        op: O,
        old_loc: Location,
    ) -> Result<Option<Location>, Error> {
        // If the translated key is not in the snapshot, get a cursor to look for the key.
        let Some(key) = op.key() else {
            return Ok(None); // operations without keys cannot be active
        };
        let Some(mut cursor) = self.snapshot.get_mut(key) else {
            return Ok(None);
        };

        // Find the snapshot entry corresponding to the operation.
        if cursor.find(|&loc| *loc == old_loc) {
            // Update the operation's snapshot location to point to tip.
            let tip_loc = Location::new_unchecked(self.log.size().await);
            cursor.update(tip_loc);
            drop(cursor);

            // Apply the operation at tip.
            self.apply_op(op).await?;
            return Ok(Some(old_loc));
        }

        // The operation is not active, so this is a no-op.
        Ok(None)
    }

    /// Raise the inactivity floor by taking one _step_, which involves searching for the first
    /// active operation above the inactivity floor, moving it to tip, and then setting the
    /// inactivity floor to the location following the moved operation. This method is therefore
    /// guaranteed to raise the floor by at least one. Returns the new inactivity floor location.
    ///
    /// # Panics
    ///
    /// Expects there is at least one active operation above the inactivity floor, and panics otherwise.
    async fn raise_floor(&mut self, mut inactivity_floor_loc: Location) -> Result<Location, Error>
    where
        E: Storage + Clock + Metrics,
        I: Index<Value = Location>,
        H: CHasher,
        O: FixedOperation,
    {
        // Search for the first active operation above the inactivity floor and move it to tip.
        //
        // TODO(https://github.com/commonwarexyz/monorepo/issues/1829): optimize this w/ a bitmap.
        loop {
            let tip_loc = Location::new_unchecked(self.log.size().await);
            assert!(
                *inactivity_floor_loc < tip_loc,
                "no active operations above the inactivity floor"
            );
            let old_loc = inactivity_floor_loc;
            inactivity_floor_loc += 1;
            let op = self.log.read(*old_loc).await?;
            if self.move_op_if_active(op, old_loc).await?.is_some() {
                return Ok(inactivity_floor_loc);
            }
        }
    }

    /// Same as `raise_floor` but uses the status bitmap to more efficiently find the first active
    /// operation above the inactivity floor.
    ///
    /// # Panics
    ///
    /// Panics if there is not at least one active operation above the inactivity floor.
    pub(crate) async fn raise_floor_with_bitmap<const N: usize>(
        &mut self,
        status: &mut BitMap<H, N>,
        mut inactivity_floor_loc: Location,
    ) -> Result<Location, Error>
    where
        E: Storage + Clock + Metrics,
        I: Index<Value = Location>,
        O: FixedOperation,
        H: CHasher,
    {
        // Use the status bitmap to find the first active operation above the inactivity floor.
        while !status.get_bit(*inactivity_floor_loc) {
            inactivity_floor_loc += 1;
        }

        // Move the active operation to tip.
        let op = self.log.read(*inactivity_floor_loc).await?;
        let loc = self
            .move_op_if_active(op, inactivity_floor_loc)
            .await?
            .expect("op should be active based on status bitmap");
        status.set_bit(*loc, false);
        status.push(true);

        // Advance inactivity floor above the moved operation since we know it's inactive.
        inactivity_floor_loc += 1;

        Ok(inactivity_floor_loc)
    }

    /// Sync the log and process the updates to the MMR in parallel.
    async fn sync_and_process_updates(&mut self) -> Result<(), Error> {
        let mmr_fut = async {
            self.mmr.merkleize(self.hasher);
            Ok::<(), Error>(())
        };
        try_join!(self.log.sync().map_err(Error::Journal), mmr_fut)?;

        Ok(())
    }

    /// Sync the log and the MMR to disk.
    async fn sync(&mut self) -> Result<(), Error> {
        try_join!(
            self.log.sync().map_err(Error::Journal),
            self.mmr.sync(self.hasher).map_err(Error::Mmr)
        )?;

        Ok(())
    }
}

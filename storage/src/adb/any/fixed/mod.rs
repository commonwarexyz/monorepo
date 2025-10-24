//! An _Any_ authenticated database (ADB) provides succinct proofs of _any_ value ever associated
//! with a key. Its implementation is based on an [Mmr] over a log of state-change operations backed
//! by a [Journal].
//!
//! In an Any db, it is not possible to prove whether the value of a key is the currently active
//! one, only that it was associated with the key at some point in the past. This type of
//! authenticated database is most useful for applications involving keys that are given values once
//! and cannot be updated after.

use crate::{
    adb::{operation::FixedOperation as OperationTrait, Error},
    journal::fixed::{Config as JConfig, Journal},
    mmr::{
        journaled::{Config as MmrConfig, Mmr},
        Location, Position, Proof, StandardHasher as Standard,
    },
    translator::Translator,
};
use commonware_codec::Encode as _;
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage, ThreadPool};
use futures::future::try_join_all;
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
    O: OperationTrait,
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
    let mut log_size: Location = log.size().await?.into();
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
    assert_eq!(log.size().await?, mmr.leaves());

    Ok((inactivity_floor_loc, mmr, log))
}

/// Common implementation for pruning an Any database.
///
/// # Errors
///
/// Returns [crate::mmr::Error::LocationOverflow] if `target_prune_loc` > [crate::mmr::MAX_LOCATION].
///
/// # Panic
///
/// Panics if `target_prune_loc` is greater than the inactivity floor.
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
    O: OperationTrait,
    H: CHasher,
{
    let target_prune_pos = Position::try_from(target_prune_loc)?;

    assert!(target_prune_loc <= inactivity_floor_loc);
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
    O: OperationTrait,
    H: CHasher,
{
    let size = Location::new_unchecked(log.size().await?);
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

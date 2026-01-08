//! Shared helper functions for fixed journal synchronization.

use crate::{journal::contiguous::fixed, qmdb};
use commonware_codec::CodecFixed;
use commonware_runtime::{
    buffer::pool::Append, telemetry::metrics::status::GaugeExt, Blob, Metrics, Storage,
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::{collections::BTreeMap, marker::PhantomData, ops::Range};
use tracing::debug;

/// Initialize a [fixed::Journal] for synchronization, reusing existing data if possible.
///
/// Handles three sync scenarios based on existing journal data vs. the given sync boundaries.
///
/// 1. **Fresh Start**: existing_size ≤ range.start
///    - Deletes existing data (if any)
///    - Creates new [fixed::Journal] pruned to `range.start` and size `range.start`
///
/// 2. **Prune and Reuse**: range.start < existing_size ≤ range.end
///    - Prunes the journal to `range.start`
///    - Reuses existing journal data overlapping with the sync range
///
/// 3. **Unexpected Data**: existing_size > range.end
///    - Returns [qmdb::Error::UnexpectedData]
///
/// # Invariants
///
/// The returned [fixed::Journal] has size in the given range.
pub(crate) async fn init_journal<E: Storage + Metrics, A: CodecFixed<Cfg = ()>>(
    context: E,
    cfg: fixed::Config,
    range: Range<u64>,
) -> Result<fixed::Journal<E, A>, qmdb::Error> {
    assert!(!range.is_empty(), "range must not be empty");

    let mut journal =
        fixed::Journal::<E, A>::init(context.with_label("journal"), cfg.clone()).await?;
    let journal_size = journal.size();
    let journal = if journal_size <= range.start {
        debug!(
            journal_size,
            range.start, "Existing journal data is stale, re-initializing in pruned state"
        );
        journal.destroy().await?;
        init_journal_at_size(context, cfg, range.start).await?
    } else if journal_size <= range.end {
        debug!(
            journal_size,
            range.start,
            range.end,
            "Existing journal data within sync range, pruning to lower bound"
        );
        journal.prune(range.start).await?;
        journal
    } else {
        return Err(qmdb::Error::UnexpectedData(
            crate::mmr::Location::new_unchecked(journal_size),
        ));
    };
    let journal_size = journal.size();
    assert!(journal_size <= range.end);
    assert!(journal_size >= range.start);
    Ok(journal)
}

/// Initialize a new [fixed::Journal] instance in a pruned state at a given size.
///
/// # Arguments
/// * `context` - The storage context
/// * `cfg` - Configuration for the journal
/// * `size` - The number of operations that have been pruned.
///
/// # Behavior
/// - Creates only the tail blob at the index that would contain the operation at `size`
/// - Sets the tail blob size to represent the "leftover" operations within that blob.
/// - The [fixed::Journal] is not `sync`ed before being returned.
///
/// # Invariants
/// - The directory given by `cfg.partition` is empty.
///
/// For example, if `items_per_blob = 10` and `size = 25`:
/// - Tail blob index would be 25 / 10 = 2 (third blob, 0-indexed)
/// - Tail blob size would be (25 % 10) * CHUNK_SIZE = 5 * CHUNK_SIZE
/// - Tail blob is filled with dummy data up to its size -- this shouldn't be read.
/// - No blobs are created for indices 0 and 1 (the pruned range)
/// - Reading from positions 0-19 will return `ItemPruned` since those blobs don't exist
/// - This represents a journal that had operations 0-24, with operations 0-19 pruned,
///   leaving operations 20-24 in tail blob 2.
pub(crate) async fn init_journal_at_size<E: Storage + Metrics, A: CodecFixed<Cfg = ()>>(
    context: E,
    cfg: fixed::Config,
    size: u64,
) -> Result<fixed::Journal<E, A>, crate::journal::Error> {
    // Calculate the tail blob index and number of items in the tail
    let tail_index = size / cfg.items_per_blob;
    let tail_items = size % cfg.items_per_blob;
    let tail_size = tail_items * fixed::Journal::<E, A>::CHUNK_SIZE_U64;

    debug!(
        size,
        tail_index, tail_items, tail_size, "Initializing fresh journal at size"
    );

    // Create the tail blob with the correct size to reflect the position
    let (tail_blob, tail_actual_size) = context
        .open(&cfg.partition, &tail_index.to_be_bytes())
        .await?;
    assert_eq!(
        tail_actual_size, 0,
        "Expected empty blob for fresh initialization"
    );

    let tail = Append::new(
        tail_blob,
        0,
        cfg.write_buffer.into(),
        cfg.buffer_pool.clone(),
    )
    .await?;
    if tail_items > 0 {
        tail.resize(tail_size).await?;
    }
    let pruning_boundary = size - (size % cfg.items_per_blob);

    // Initialize metrics
    let tracked = Gauge::default();
    let _ = tracked.try_set(tail_index + 1);
    let synced = Counter::default();
    let pruned = Counter::default();
    context.register("tracked", "Number of blobs", tracked.clone());
    context.register("synced", "Number of syncs", synced.clone());
    context.register("pruned", "Number of blobs pruned", pruned.clone());

    Ok(fixed::Journal::<E, A> {
        context,
        cfg,
        blobs: BTreeMap::new(),
        tail,
        tail_index,
        tracked,
        synced,
        pruned,
        size,
        pruning_boundary,
        _array: PhantomData,
    })
}

//! Generic test suite for [Contiguous] trait implementations.

use super::{Batch, Contiguous, Many, fixed, variable};
use crate::journal::{Error, contiguous::Mutable};
use commonware_macros::boxed;
use commonware_runtime::{
    Blob as _, ReadOptions, Runner as _, Spawner as _, Storage as _, Supervisor as _, WriteOptions,
    buffer::paged::CacheRef,
    deterministic,
    mocks::{DelayedSyncContext, PendingSyncs, RecordingContext},
    reschedule,
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use futures::{FutureExt as _, Stream, StreamExt, future::BoxFuture, stream};
use std::{
    fmt::Debug,
    future::Future,
    num::NonZeroUsize,
    ops::Range,
    sync::atomic::{AtomicUsize, Ordering},
};

/// Replay `range` of `journal` and flatten the batches into one `(position, item)` entry per item,
/// for tests that check items one at a time.
pub(crate) async fn replay_items<J: Contiguous>(
    journal: &J,
    range: Range<u64>,
    buffer: NonZeroUsize,
    read_options: ReadOptions,
) -> Result<impl Stream<Item = Result<(u64, J::Item), Error>> + Send, Error> {
    let batches = journal.replay(range, buffer, read_options).await?;
    Ok(batches.flat_map(|batch: Result<Batch<J::Item>, Error>| {
        let entries: Vec<_> = match batch {
            Ok(batch) => batch.into_iter().map(Ok).collect(),
            Err(err) => vec![Err(err)],
        };
        stream::iter(entries)
    }))
}

/// Zero one byte of the physical page `page` in the blob at `name`, `offset` bytes into its
/// logical contents, which must lie beyond the page's last durable length. Models the crash image
/// of a torn page rewrite, where an unsynced flush that extended a durable partial page lost one
/// of its new bytes and left the zero padding the durable page carried there, so only the page's
/// shorter durable checksum slot still validates while the pages written after it survive.
pub(crate) async fn tear_page_rewrite(
    context: &deterministic::Context,
    partition: &str,
    name: &[u8],
    page: u64,
    offset: u64,
    logical_page_size: u64,
) {
    let physical_page_size = logical_page_size + commonware_runtime::buffer::paged::CHECKSUM_SIZE;
    let position = page * physical_page_size + offset;
    let (blob, _) = context.open(partition, name).await.unwrap();
    let byte = blob
        .read_at(position, 1, ReadOptions::default())
        .await
        .unwrap()
        .coalesce();
    assert_ne!(
        byte.as_ref()[0],
        0,
        "the rewrite must have changed the byte"
    );
    blob.write_at(position, vec![0u8], WriteOptions::default())
        .await
        .unwrap();
    blob.sync().await.unwrap();
}

/// Run the full suite of generic tests on a [Contiguous] implementation.
///
/// The factory receives a test identifier, a unique invocation index, and an optional cap.
/// Use the identifier for partitions and the index for contexts to avoid duplicate metrics
/// when reopening a journal.
///
/// # Assumptions
///
/// These tests assume the journal is configured with **`items_per_blob = 10`**.
/// Some tests rely on this value for blob-boundary calculations and pruning behavior.
#[boxed]
pub(super) async fn run_contiguous_tests<F, J>(factory: F)
where
    F: Fn(String, usize, Option<u64>) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let counter = AtomicUsize::new(0);
    let bounded_factory = |name: String, cap: Option<u64>| {
        let idx = counter.fetch_add(1, Ordering::SeqCst);
        factory(name, idx, cap)
    };
    let indexed_factory = |name: String| bounded_factory(name, None);

    test_empty_journal_bounds(&indexed_factory).await;
    test_bounds_with_items(&indexed_factory).await;
    test_bounds_after_prune(&indexed_factory).await;
    test_append_and_size(&indexed_factory).await;
    test_sequential_appends(&indexed_factory).await;
    test_replay_from_start(&indexed_factory).await;
    test_replay_from_middle(&indexed_factory).await;
    test_replay_from_unsealed_tail(&indexed_factory).await;
    test_replay_with_small_buffer(&indexed_factory).await;
    test_replay_batches(&indexed_factory).await;
    test_prune_retains_size(&indexed_factory).await;
    test_through_trait(&indexed_factory).await;
    test_replay_after_prune(&indexed_factory).await;
    test_prune_then_append(&indexed_factory).await;
    test_position_stability(&indexed_factory).await;
    test_sync_behavior(&indexed_factory).await;
    test_replay_on_empty(&indexed_factory).await;
    test_replay_at_exact_size(&indexed_factory).await;
    test_multiple_prunes(&indexed_factory).await;
    test_prune_beyond_size(&indexed_factory).await;
    test_persistence_basic(&indexed_factory).await;
    test_persistence_after_prune(&indexed_factory).await;
    test_read_by_position(&indexed_factory).await;
    test_read_many(&indexed_factory).await;
    test_read_out_of_range(&indexed_factory).await;
    test_read_after_prune(&indexed_factory).await;
    test_bounded_initialization_to_middle(&bounded_factory).await;
    test_bounded_initialization_to_zero(&bounded_factory).await;
    test_bounded_initialization_at_current_size(&bounded_factory).await;
    test_initialization_cap_above_end(&bounded_factory).await;
    test_bounded_initialization_below_retained_start(&bounded_factory).await;
    test_bounded_initialization_then_append(&bounded_factory).await;
    test_bounded_initialization_zero_then_append(&bounded_factory).await;
    test_bounded_initialization_after_prune(&bounded_factory).await;
    test_section_boundary_behavior(&bounded_factory).await;
    test_destroy_and_reinit(&indexed_factory).await;
    test_append_many_empty(&indexed_factory).await;
    test_append_many_basic(&indexed_factory).await;
    test_append_many_across_sections(&indexed_factory).await;
    test_append_many_then_append(&indexed_factory).await;
    test_append_many_single_item(&indexed_factory).await;
}

/// Test that an empty journal has empty bounds (start == end == 0).
async fn test_empty_journal_bounds<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let journal = factory("empty".into()).await.unwrap();
    let bounds = journal.bounds();
    assert_eq!(bounds.start, 0);
    assert_eq!(bounds.end, 0);
    assert!(bounds.is_empty());
    journal.destroy().await.unwrap();
}

/// Test that bounds returns 0..size for journal with items.
async fn test_bounds_with_items<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("bounds-with-items".into()).await.unwrap();

    // Append some items
    for i in 0..10 {
        (journal, _) = journal.append(&(i * 100)).await.unwrap();
    }

    let bounds = journal.bounds();
    assert_eq!(bounds.start, 0);
    assert_eq!(bounds.end, 10);
    assert!(!bounds.is_empty());
    journal.destroy().await.unwrap();
}

/// Test that bounds updates after pruning.
///
/// This test assumes items_per_blob = 10.
async fn test_bounds_after_prune<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("bounds-after-prune".into()).await.unwrap();

    // Append items across multiple sections
    for i in 0..30 {
        (journal, _) = journal.append(&(i * 100)).await.unwrap();
    }

    // Initially bounds should be 0..30
    let bounds = journal.bounds();
    assert_eq!(bounds.start, 0);
    assert_eq!(bounds.end, 30);

    // Prune the first section.
    (journal, _) = journal.prune(10).await.unwrap();

    let bounds = journal.bounds();
    assert_eq!(bounds.start, 10);
    assert_eq!(bounds.end, 30);

    // Before the prune, the third section reads back through both the async and sync paths.
    let below: Vec<u64> = (20..25).collect();
    let values: Vec<u64> = below.iter().map(|pos| pos * 100).collect();
    assert_eq!(journal.read_many(&below).await.unwrap(), values);
    let cached: Vec<_> = below
        .iter()
        .map(|&pos| journal.try_read_sync(pos))
        .collect();
    assert_eq!(cached, values.iter().copied().map(Some).collect::<Vec<_>>());

    // Pruning inside the third section moves the boundary to the position itself.
    (journal, _) = journal.prune(25).await.unwrap();
    let bounds = journal.bounds();
    assert_eq!(bounds.start, 25);
    assert_eq!(bounds.end, 30);

    // The third section still holds 20 through 24, but every read path reports them pruned.
    for &pos in &below {
        assert!(matches!(journal.read(pos).await, Err(Error::ItemPruned(p)) if p == pos));
        assert_eq!(journal.try_read_sync(pos), None);
    }
    assert!(matches!(
        journal.read_many(&below).await,
        Err(Error::ItemPruned(20))
    ));
    assert!(
        journal
            .try_read_many_sync(&below)
            .iter()
            .all(Option::is_none)
    );
    assert_eq!(
        journal.try_read_many_sync(&[24, 25]),
        vec![None, Some(2500)]
    );
    assert!(matches!(
        journal
            .replay(20..30, NZUsize!(1024), ReadOptions::default())
            .await,
        Err(Error::ItemPruned(20))
    ));

    // Prune all
    (journal, _) = journal.prune(30).await.unwrap();
    let bounds = journal.bounds();
    assert_eq!(bounds.start, 30);
    assert_eq!(bounds.end, 30);
    assert!(bounds.is_empty());

    // Drop and reopen
    journal.sync().await.unwrap();
    let journal = factory("bounds-after-prune".into()).await.unwrap();
    let bounds = journal.bounds();
    assert!(bounds.is_empty());
    journal.destroy().await.unwrap();
}

/// Runs [test_bounds_after_prune] on the fixed journal.
#[test]
fn test_fixed_bounds_after_prune() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let opened = AtomicUsize::new(0);
        test_bounds_after_prune(&|name: String| {
            let cfg = fixed::Config {
                partition: format!("fixed-{name}"),
                items_per_blob: NZU64!(10),
                page_cache: CacheRef::new(NZU16!(1024), NZUsize!(10)),
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            };
            let context = context
                .child("journal")
                .with_attribute("index", opened.fetch_add(1, Ordering::SeqCst));
            fixed::Journal::<_, u64>::init(context, cfg).boxed()
        })
        .await;
    });
}

/// Test that append returns sequential positions and size increments.
async fn test_append_and_size<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("append-and-size".into()).await.unwrap();

    let pos1;
    (journal, pos1) = journal.append(&100).await.unwrap();
    let pos2;
    (journal, pos2) = journal.append(&200).await.unwrap();
    let pos3;
    (journal, pos3) = journal.append(&300).await.unwrap();

    assert_eq!(pos1, 0);
    assert_eq!(pos2, 1);
    assert_eq!(pos3, 2);
    assert_eq!(journal.bounds().end, 3);

    // Verify values can be read back
    assert_eq!(journal.read(0).await.unwrap(), 100);
    assert_eq!(journal.read(1).await.unwrap(), 200);
    assert_eq!(journal.read(2).await.unwrap(), 300);

    journal.destroy().await.unwrap();
}

/// Test appending many items across section boundaries.
async fn test_sequential_appends<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("sequential-appends".into()).await.unwrap();

    for i in 0..25u64 {
        let pos;
        (journal, pos) = journal.append(&(i * 10)).await.unwrap();
        assert_eq!(pos, i);
    }

    assert_eq!(journal.bounds().end, 25);

    for i in 0..25u64 {
        assert_eq!(journal.read(i).await.unwrap(), i * 10);
    }

    journal.destroy().await.unwrap();
}

/// Test replay from the start of the journal.
async fn test_replay_from_start<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("replay-from-start".into()).await.unwrap();

    for i in 0..10u64 {
        (journal, _) = journal.append(&(i * 10)).await.unwrap();
    }

    {
        let stream = replay_items(
            &journal,
            0..journal.bounds().end,
            NZUsize!(1024),
            ReadOptions::default(),
        )
        .await
        .unwrap();
        futures::pin_mut!(stream);

        let mut items = Vec::new();
        while let Some(result) = stream.next().await {
            items.push(result.unwrap());
        }

        assert_eq!(items.len(), 10);
        for (i, (pos, value)) in items.iter().enumerate() {
            assert_eq!(*pos, i as u64);
            assert_eq!(*value, (i as u64) * 10);
        }
    }

    journal.destroy().await.unwrap();
}

/// Test replay from the middle of the journal.
async fn test_replay_from_middle<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("replay-from-middle".into()).await.unwrap();

    for i in 0..15u64 {
        (journal, _) = journal.append(&(i * 10)).await.unwrap();
    }

    {
        let stream = replay_items(
            &journal,
            7..journal.bounds().end,
            NZUsize!(1024),
            ReadOptions::default(),
        )
        .await
        .unwrap();
        futures::pin_mut!(stream);

        let mut items = Vec::new();
        while let Some(result) = stream.next().await {
            items.push(result.unwrap());
        }

        assert_eq!(items.len(), 8);
        for (i, (pos, value)) in items.iter().enumerate() {
            assert_eq!(*pos, (i + 7) as u64);
            assert_eq!(*value, ((i + 7) as u64) * 10);
        }
    }

    journal.destroy().await.unwrap();
}

/// Test replay starting in the writable tail.
async fn test_replay_from_unsealed_tail<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("replay-from-unsealed-tail".into()).await.unwrap();

    for i in 0..17u64 {
        (journal, _) = journal.append(&(i * 10)).await.unwrap();
    }

    {
        let stream = replay_items(
            &journal,
            13..journal.bounds().end,
            NZUsize!(1024),
            ReadOptions::default(),
        )
        .await
        .unwrap();
        futures::pin_mut!(stream);

        let mut items = Vec::new();
        while let Some(result) = stream.next().await {
            items.push(result.unwrap());
        }

        assert_eq!(items.len(), 4);
        for (i, (pos, value)) in items.iter().enumerate() {
            let expected_pos = (i + 13) as u64;
            assert_eq!(*pos, expected_pos);
            assert_eq!(*value, expected_pos * 10);
        }
    }

    journal.destroy().await.unwrap();
}

/// Test replay with a small buffer.
async fn test_replay_with_small_buffer<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("replay-with-small-buffer".into()).await.unwrap();

    for i in 0..25u64 {
        (journal, _) = journal.append(&(i * 10)).await.unwrap();
    }

    {
        let stream = replay_items(
            &journal,
            0..journal.bounds().end,
            NZUsize!(9),
            ReadOptions::default(),
        )
        .await
        .unwrap();
        futures::pin_mut!(stream);

        let mut items = Vec::new();
        while let Some(result) = stream.next().await {
            items.push(result.unwrap());
        }

        assert_eq!(items.len(), 25);
        for (i, (pos, value)) in items.iter().enumerate() {
            assert_eq!(*pos, i as u64);
            assert_eq!(*value, (i as u64) * 10);
        }
    }

    journal.destroy().await.unwrap();
}

/// Drain `journal.replay(range)` with `buffer`, checking that the batches tile `range` in
/// position order, hold `expected(position)`, never cross a boundary between blobs of
/// `items_per_blob` items, and exceed `buffer` by less than one item of `item_len` stored bytes.
pub(super) async fn check_replay_batches<J>(
    journal: &J,
    range: Range<u64>,
    buffer: usize,
    items_per_blob: u64,
    item_len: usize,
    expected: impl Fn(u64) -> J::Item,
) where
    J: Contiguous<Item: PartialEq + Debug>,
{
    let stream = journal
        .replay(range.clone(), NZUsize!(buffer), ReadOptions::default())
        .await
        .unwrap();
    futures::pin_mut!(stream);

    let mut next = range.start;
    while let Some(batch) = stream.next().await {
        let Batch { start, items } = batch.unwrap();
        assert_eq!(start, next, "range {range:?} buffer {buffer}");
        assert!(!items.is_empty(), "range {range:?} buffer {buffer}");
        assert!(
            (items.len() - 1) * item_len < buffer,
            "batch of {} items exceeds buffer {buffer} by an item or more",
            items.len()
        );
        let end = start + items.len() as u64;
        assert!(end <= range.end, "range {range:?} buffer {buffer}");
        assert_eq!(
            start / items_per_blob,
            (end - 1) / items_per_blob,
            "batch {start}..{end} crossed a blob boundary"
        );
        for (i, item) in items.into_iter().enumerate() {
            assert_eq!(item, expected(start + i as u64));
        }
        next = end;
    }
    assert_eq!(next, range.end, "range {range:?} buffer {buffer}");
}

/// Test that replay tiles a range contiguously, stops at blob boundaries, and rejects ranges
/// outside the bounds.
async fn test_replay_batches<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("replay-batches".into()).await.unwrap();

    // Three sealed blobs and a partial tail.
    for i in 0..37u64 {
        (journal, _) = journal.append(&(i * 10)).await.unwrap();
    }

    // Each u64 is stored as a nine-byte frame, so the budgets are one item, less than one blob,
    // and more than the whole journal.
    for buffer in [9usize, 40, 4096] {
        for range in [0..37u64, 7..25, 13..14, 20..20, 30..37] {
            check_replay_batches(&journal, range, buffer, 10, 9, |pos| pos * 10).await;
        }
    }

    // Ranges outside the bounds are rejected.
    let res = journal
        .replay(0..38, NZUsize!(40), ReadOptions::default())
        .await
        .map(|_| ());
    assert!(matches!(res, Err(Error::ItemOutOfRange(38))));
    #[allow(clippy::reversed_empty_ranges)]
    let res = journal
        .replay(10..5, NZUsize!(40), ReadOptions::default())
        .await
        .map(|_| ());
    assert!(matches!(res, Err(Error::ItemOutOfRange(10))));

    // After pruning, batches start at the retained boundary and a pruned start is rejected.
    let (journal, _) = journal.prune(10).await.unwrap();
    check_replay_batches(&journal, 10..37, 40, 10, 9, |pos| pos * 10).await;
    let res = journal
        .replay(5..20, NZUsize!(40), ReadOptions::default())
        .await
        .map(|_| ());
    assert!(matches!(res, Err(Error::ItemPruned(5))));

    journal.destroy().await.unwrap();
}

/// Test that size is unchanged after pruning.
async fn test_prune_retains_size<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("prune-retains-size".into()).await.unwrap();

    for i in 0..20u64 {
        (journal, _) = journal.append(&i).await.unwrap();
    }

    let size_before = journal.bounds().end;
    (journal, _) = journal.prune(10).await.unwrap();
    let size_after = journal.bounds().end;

    assert_eq!(size_before, size_after);
    assert_eq!(size_after, 20);

    (journal, _) = journal.prune(20).await.unwrap();
    let size_after_all = journal.bounds().end;
    assert_eq!(size_after, size_after_all);

    journal.sync().await.unwrap();

    let journal = factory("prune-retains-size".into()).await.unwrap();
    let size_after_close = journal.bounds().end;
    assert_eq!(size_after_close, size_after_all);

    journal.destroy().await.unwrap();
}

/// Test using journal through [Contiguous] trait methods.
async fn test_through_trait<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let journal = factory("through-trait".into()).await.unwrap();

    let (journal, pos1) = Mutable::append(journal, &42).await.unwrap();
    let (journal, pos2) = Mutable::append(journal, &100).await.unwrap();

    assert_eq!(pos1, 0);
    assert_eq!(pos2, 1);

    let size = Contiguous::bounds(&journal).end;
    assert_eq!(size, 2);

    journal.destroy().await.unwrap();
}

/// Test replay after pruning items.
async fn test_replay_after_prune<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("replay-after-prune".into()).await.unwrap();

    for i in 0..20u64 {
        (journal, _) = journal.append(&(i * 10)).await.unwrap();
    }

    let (journal, _) = journal.prune(10).await.unwrap();

    {
        // Replay from the pruning boundary at position 10
        let stream = replay_items(
            &journal,
            10..journal.bounds().end,
            NZUsize!(1024),
            ReadOptions::default(),
        )
        .await
        .unwrap();
        futures::pin_mut!(stream);

        let mut items = Vec::new();
        while let Some(result) = stream.next().await {
            items.push(result.unwrap());
        }

        assert_eq!(items.len(), 10);
        for (i, (pos, value)) in items.iter().enumerate() {
            assert_eq!(*pos, (i + 10) as u64);
            assert_eq!(*value, ((i + 10) as u64) * 10);
        }
    }

    journal.destroy().await.unwrap();
}

/// Test pruning all items then appending new ones.
///
/// Verifies that positions continue consecutively increasing even after
/// pruning all retained items. Assumes items_per_blob = 10.
async fn test_prune_then_append<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("prune-then-append".into()).await.unwrap();

    // Append exactly one section (10 items)
    for i in 0..10u64 {
        (journal, _) = journal.append(&i).await.unwrap();
    }

    // Prune all items at a blob boundary.
    (journal, _) = journal.prune(10).await.unwrap();
    assert!(journal.bounds().is_empty());

    // Append new items after pruning. The position continues from 10.
    let pos;
    (journal, pos) = journal.append(&999).await.unwrap();
    assert_eq!(pos, 10);

    assert_eq!(journal.bounds().end, 11);

    journal.destroy().await.unwrap();
}

/// Test that positions remain stable after pruning and further appends.
async fn test_position_stability<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("position-stability".into()).await.unwrap();

    // Append initial items
    for i in 0..20u64 {
        (journal, _) = journal.append(&(i * 100)).await.unwrap();
    }

    // Prune first 10
    (journal, _) = journal.prune(10).await.unwrap();

    // Append more items
    for i in 20..25u64 {
        let pos;
        (journal, pos) = journal.append(&(i * 100)).await.unwrap();
        assert_eq!(pos, i);
    }

    // Verify reads work for retained items after pruning
    assert_eq!(journal.read(10).await.unwrap(), 1000);
    assert_eq!(journal.read(15).await.unwrap(), 1500);
    assert_eq!(journal.read(20).await.unwrap(), 2000);
    assert_eq!(journal.read(24).await.unwrap(), 2400);

    {
        // Replay from position 10 and verify positions
        let stream = replay_items(
            &journal,
            10..journal.bounds().end,
            NZUsize!(1024),
            ReadOptions::default(),
        )
        .await
        .unwrap();
        futures::pin_mut!(stream);

        let mut items = Vec::new();
        while let Some(result) = stream.next().await {
            items.push(result.unwrap());
        }

        assert_eq!(items.len(), 15);
        for (i, (pos, value)) in items.iter().enumerate() {
            let expected_pos = (i + 10) as u64;
            assert_eq!(*pos, expected_pos);
            assert_eq!(*value, expected_pos * 100);
        }
    }

    journal.destroy().await.unwrap();
}

/// Test sync behavior.
async fn test_sync_behavior<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("sync-behavior".into()).await.unwrap();

    for i in 0..5u64 {
        (journal, _) = journal.append(&i).await.unwrap();
    }

    journal = journal.sync().await.unwrap();

    // Verify operations work after sync
    assert_eq!(journal.read(0).await.unwrap(), 0);
    let pos;
    (journal, pos) = journal.append(&100).await.unwrap();
    assert_eq!(pos, 5);
    assert_eq!(journal.read(5).await.unwrap(), 100);

    assert_eq!(journal.bounds().end, 6);

    journal.destroy().await.unwrap();
}

/// Test replay on an empty journal.
async fn test_replay_on_empty<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let journal = factory("replay-on-empty".into()).await.unwrap();

    {
        let stream = replay_items(
            &journal,
            0..journal.bounds().end,
            NZUsize!(1024),
            ReadOptions::default(),
        )
        .await
        .unwrap();
        futures::pin_mut!(stream);

        let mut items = Vec::new();
        while let Some(result) = stream.next().await {
            items.push(result.unwrap());
        }

        assert_eq!(items.len(), 0);
    }

    journal.destroy().await.unwrap();
}

/// Test replay at exact size position.
async fn test_replay_at_exact_size<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("replay-at-exact-size".into()).await.unwrap();

    for i in 0..10u64 {
        (journal, _) = journal.append(&i).await.unwrap();
    }

    let bounds = journal.bounds();

    {
        let stream = replay_items(
            &journal,
            bounds.end..journal.bounds().end,
            NZUsize!(1024),
            ReadOptions::default(),
        )
        .await
        .unwrap();
        futures::pin_mut!(stream);

        let mut items = Vec::new();
        while let Some(result) = stream.next().await {
            items.push(result.unwrap());
        }

        assert_eq!(items.len(), 0);
    }

    journal.destroy().await.unwrap();
}

/// Test multiple prunes with same min_position for idempotency.
async fn test_multiple_prunes<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("multiple-prunes".into()).await.unwrap();

    for i in 0..20u64 {
        (journal, _) = journal.append(&i).await.unwrap();
    }

    let pruned1;
    (journal, pruned1) = journal.prune(10).await.unwrap();
    let pruned2;
    (journal, pruned2) = journal.prune(10).await.unwrap();

    assert!(pruned1);
    assert!(!pruned2); // Second prune should return false (nothing to prune)

    assert_eq!(journal.bounds().end, 20);
    assert_eq!(journal.read(10).await.unwrap(), 10);
    assert_eq!(journal.read(19).await.unwrap(), 19);

    journal.destroy().await.unwrap();
}

/// Test pruning beyond the current size.
async fn test_prune_beyond_size<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("prune-beyond-size".into()).await.unwrap();

    for i in 0..10u64 {
        (journal, _) = journal.append(&i).await.unwrap();
    }

    // Prune with min_position > size should be safe
    (journal, _) = journal.prune(100).await.unwrap();

    // Verify journal still works
    assert_eq!(journal.bounds().end, 10);

    let pos;
    (journal, pos) = journal.append(&999).await.unwrap();
    assert_eq!(pos, 10);
    assert_eq!(journal.read(10).await.unwrap(), 999);

    journal.destroy().await.unwrap();
}

/// Test basic persistence: append items, close, re-open, verify state.
async fn test_persistence_basic<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let test_name = "persistence-basic".to_string();

    // Create journal and append items
    {
        let mut journal = factory(test_name.clone()).await.unwrap();

        for i in 0..15u64 {
            let pos;
            (journal, pos) = journal.append(&(i * 10)).await.unwrap();
            assert_eq!(pos, i);
        }

        assert_eq!(journal.bounds().end, 15);

        journal.sync().await.unwrap();
    }

    // Re-open and verify state persists
    {
        let journal = factory(test_name.clone()).await.unwrap();

        assert_eq!(journal.bounds().end, 15);

        // Verify reads work after persistence
        for i in 0..15u64 {
            assert_eq!(journal.read(i).await.unwrap(), i * 10);
        }

        // Replay and verify all items
        {
            let stream = replay_items(
                &journal,
                0..journal.bounds().end,
                NZUsize!(1024),
                ReadOptions::default(),
            )
            .await
            .unwrap();
            futures::pin_mut!(stream);

            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                items.push(result.unwrap());
            }

            assert_eq!(items.len(), 15);
            for (i, (pos, value)) in items.iter().enumerate() {
                assert_eq!(*pos, i as u64);
                assert_eq!(*value, (i as u64) * 10);
            }
        }

        journal.destroy().await.unwrap();
    }
}

/// Test persistence after pruning: append, prune, close, re-open, verify pruned state.
async fn test_persistence_after_prune<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let test_name = "persistence-after-prune".to_string();

    // Create journal, append items, and prune
    {
        let mut journal = factory(test_name.clone()).await.unwrap();

        for i in 0..25u64 {
            (journal, _) = journal.append(&(i * 100)).await.unwrap();
        }

        // Prune first 10 items
        let pruned;
        (journal, pruned) = journal.prune(10).await.unwrap();
        assert!(pruned);

        assert_eq!(journal.bounds().end, 25);

        journal.sync().await.unwrap();
    }

    // Re-open and verify pruned state persists
    {
        let mut journal = factory(test_name.clone()).await.unwrap();

        // size should still be 25
        assert_eq!(journal.bounds().end, 25);

        // Verify pruned positions cannot be read
        for i in 0..10u64 {
            assert!(matches!(journal.read(i).await, Err(Error::ItemPruned(_))));
        }

        // Verify non-pruned positions can be read
        for i in 10..25u64 {
            assert_eq!(journal.read(i).await.unwrap(), i * 100);
        }

        // Replay from position 10 (first non-pruned position)
        {
            let stream = replay_items(
                &journal,
                10..journal.bounds().end,
                NZUsize!(1024),
                ReadOptions::default(),
            )
            .await
            .unwrap();
            futures::pin_mut!(stream);

            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                items.push(result.unwrap());
            }

            assert_eq!(items.len(), 15);
            for (i, (pos, value)) in items.iter().enumerate() {
                let expected_pos = (i + 10) as u64;
                assert_eq!(*pos, expected_pos);
                assert_eq!(*value, expected_pos * 100);
            }
        }

        // Append more items after re-opening
        let pos;
        (journal, pos) = journal.append(&999).await.unwrap();
        assert_eq!(pos, 25);

        // Verify the newly appended item can be read
        assert_eq!(journal.read(25).await.unwrap(), 999);

        journal.destroy().await.unwrap();
    }
}

/// Test reading items by position.
pub(super) async fn test_read_by_position<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("read-by-position".into()).await.unwrap();

    for i in 0..1000u64 {
        (journal, _) = journal.append(&(i * 100)).await.unwrap();
        assert_eq!(journal.read(i).await.unwrap(), i * 100);
    }

    // Verify we can still read all items
    for i in 0..1000u64 {
        assert_eq!(journal.read(i).await.unwrap(), i * 100);
    }

    journal.destroy().await.unwrap();
}

/// Test reading multiple items by position.
pub(super) async fn test_read_many<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("read-many".into()).await.unwrap();

    for i in 0..15u64 {
        (journal, _) = journal.append(&(i * 100)).await.unwrap();
    }

    let items = journal.read_many(&[1, 4, 12]).await.unwrap();
    assert_eq!(items, vec![100, 400, 1200]);

    journal.destroy().await.unwrap();
}

/// Test read errors for out-of-range positions.
pub(super) async fn test_read_out_of_range<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("read-out-of-range".into()).await.unwrap();

    (journal, _) = journal.append(&42).await.unwrap();

    // Try to read beyond size
    let result = journal.read(10).await;
    assert!(matches!(result, Err(Error::ItemOutOfRange(_))));

    journal.destroy().await.unwrap();
}

/// Test read after pruning.
pub(super) async fn test_read_after_prune<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("read-after-prune".into()).await.unwrap();

    for i in 0..20u64 {
        (journal, _) = journal.append(&i).await.unwrap();
    }

    let (journal, _) = journal.prune(10).await.unwrap();

    let bounds = journal.bounds();
    let result = journal.read(bounds.start - 1).await;
    assert!(matches!(result, Err(Error::ItemPruned(_))));

    journal.destroy().await.unwrap();
}

/// Bounded initialization selects a prefix within the journal.
async fn test_bounded_initialization_to_middle<F, J>(factory: &F)
where
    F: Fn(String, Option<u64>) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("rewind-to-middle".into(), None).await.unwrap();

    // Append 20 items
    for i in 0..20u64 {
        (journal, _) = journal.append(&(i * 100)).await.unwrap();
    }

    // Reopen with a bound of 12 items.
    _ = journal.sync().await.unwrap();
    journal = factory("rewind-to-middle".into(), Some(12)).await.unwrap();

    assert_eq!(journal.bounds().end, 12);

    // Verify first 12 items are still readable
    for i in 0..12u64 {
        assert_eq!(journal.read(i).await.unwrap(), i * 100);
    }

    // Verify items 12-19 are gone
    for i in 12..20u64 {
        assert!(matches!(
            journal.read(i).await,
            Err(Error::ItemOutOfRange(_))
        ));
    }

    // Next append should get position 12
    let pos;
    (journal, pos) = journal.append(&999).await.unwrap();
    assert_eq!(pos, 12);
    assert_eq!(journal.read(12).await.unwrap(), 999);

    journal.destroy().await.unwrap();
}

/// A zero initialization bound selects an empty journal.
async fn test_bounded_initialization_to_zero<F, J>(factory: &F)
where
    F: Fn(String, Option<u64>) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("rewind-to-zero".into(), None).await.unwrap();

    for i in 0..10u64 {
        (journal, _) = journal.append(&i).await.unwrap();
    }

    _ = journal.sync().await.unwrap();
    journal = factory("rewind-to-zero".into(), Some(0)).await.unwrap();

    let bounds = journal.bounds();
    assert_eq!(bounds.end, 0);
    assert!(bounds.is_empty());

    // Next append should get position 0
    let pos;
    (journal, pos) = journal.append(&42).await.unwrap();
    assert_eq!(pos, 0);

    journal.destroy().await.unwrap();
}

/// An initialization bound at the current size preserves all items.
async fn test_bounded_initialization_at_current_size<F, J>(factory: &F)
where
    F: Fn(String, Option<u64>) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("rewind-current-size".into(), None).await.unwrap();

    for i in 0..10u64 {
        (journal, _) = journal.append(&i).await.unwrap();
    }

    // Reopen with a bound equal to the stored end.
    _ = journal.sync().await.unwrap();
    let journal = factory("rewind-current-size".into(), Some(10))
        .await
        .unwrap();
    assert_eq!(journal.bounds().end, 10);

    journal.destroy().await.unwrap();
}

/// An initialization bound above the stored end does not grow the journal.
async fn test_initialization_cap_above_end<F, J>(factory: &F)
where
    F: Fn(String, Option<u64>) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("rewind-invalid-forward".into(), None)
        .await
        .unwrap();

    for i in 0..10u64 {
        (journal, _) = journal.append(&i).await.unwrap();
    }

    // An above-end initialization bound preserves the stored end.
    _ = journal.sync().await.unwrap();
    let result = factory("rewind-invalid-forward".into(), Some(20)).await;
    let journal = result.unwrap();
    assert_eq!(journal.bounds().end, 10);
    drop(journal);

    let journal = factory("rewind-invalid-forward".into(), None)
        .await
        .unwrap();
    journal.destroy().await.unwrap();
}

/// Initialization rejects a bound below the retained start.
async fn test_bounded_initialization_below_retained_start<F, J>(factory: &F)
where
    F: Fn(String, Option<u64>) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("rewind-invalid-pruned".into(), None).await.unwrap();

    for i in 0..20u64 {
        (journal, _) = journal.append(&i).await.unwrap();
    }

    // Prune first 10 items
    let (journal, _) = journal.prune(10).await.unwrap();

    // Reopen with a bound below the retained start.
    _ = journal.sync().await.unwrap();
    let result = factory("rewind-invalid-pruned".into(), Some(5)).await;
    assert!(matches!(result, Err(Error::ItemPruned(5))));

    let journal = factory("rewind-invalid-pruned".into(), None).await.unwrap();
    journal.destroy().await.unwrap();
}

/// Appends continue from the end selected during initialization.
/// Assumes items_per_blob = 10.
async fn test_bounded_initialization_then_append<F, J>(factory: &F)
where
    F: Fn(String, Option<u64>) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("rewind-then-append".into(), None).await.unwrap();

    // Append across a blob boundary (15 items = 1.5 blobs).
    for i in 0..15u64 {
        (journal, _) = journal.append(&i).await.unwrap();
    }

    // Reopen with a bound inside the first section.
    _ = journal.sync().await.unwrap();
    journal = factory("rewind-then-append".into(), Some(8)).await.unwrap();

    // Append should continue from position 8
    let pos1;
    (journal, pos1) = journal.append(&888).await.unwrap();
    let pos2;
    (journal, pos2) = journal.append(&999).await.unwrap();

    assert_eq!(pos1, 8);
    assert_eq!(pos2, 9);
    assert_eq!(journal.read(8).await.unwrap(), 888);
    assert_eq!(journal.read(9).await.unwrap(), 999);

    journal.destroy().await.unwrap();
}

/// Appends start at zero after initialization selects an empty prefix.
async fn test_bounded_initialization_zero_then_append<F, J>(factory: &F)
where
    F: Fn(String, Option<u64>) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("rewind-zero-then-append".into(), None)
        .await
        .unwrap();

    // Append some items
    for i in 0..10u64 {
        (journal, _) = journal.append(&(i * 100)).await.unwrap();
    }

    // Reopen with a zero bound.
    _ = journal.sync().await.unwrap();
    journal = factory("rewind-zero-then-append".into(), Some(0))
        .await
        .unwrap();

    // Verify journal is empty
    let bounds = journal.bounds();
    assert_eq!(bounds.end, 0);
    assert!(bounds.is_empty());

    // Append should work
    let pos;
    (journal, pos) = journal.append(&42).await.unwrap();
    assert_eq!(pos, 0);
    assert_eq!(journal.bounds().end, 1);
    assert_eq!(journal.read(0).await.unwrap(), 42);

    journal.destroy().await.unwrap();
}

/// Bounded initialization preserves the pruning boundary.
/// Assumes items_per_blob = 10.
async fn test_bounded_initialization_after_prune<F, J>(factory: &F)
where
    F: Fn(String, Option<u64>) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("rewind-after-prune".into(), None).await.unwrap();

    // Append items across 3 blobs (30 items, assuming items_per_blob = 10).
    for i in 0..30u64 {
        (journal, _) = journal.append(&(i * 100)).await.unwrap();
    }

    // Prune first section (items 0-9)
    (journal, _) = journal.prune(10).await.unwrap();
    let bounds = journal.bounds();
    assert_eq!(bounds.start, 10);

    // Reopen with a bound of 20, within the retained range.
    _ = journal.sync().await.unwrap();
    journal = factory("rewind-after-prune".into(), Some(20))
        .await
        .unwrap();
    let bounds = journal.bounds();
    assert_eq!(bounds.end, 20);
    assert_eq!(bounds.start, 10);

    // Verify items in range [bounds.start, 20) are still readable
    for i in bounds.start..20 {
        assert_eq!(journal.read(i).await.unwrap(), i * 100);
    }

    // Append should continue from position 20
    let pos;
    (journal, pos) = journal.append(&999).await.unwrap();
    assert_eq!(pos, 20);
    assert_eq!(journal.read(20).await.unwrap(), 999);
    assert_eq!(journal.bounds().start, 10);

    // A bound below the retained start must fail.
    _ = journal.sync().await.unwrap();
    let result = factory("rewind-after-prune".into(), Some(5)).await;
    assert!(matches!(result, Err(Error::ItemPruned(5))));

    let journal = factory("rewind-after-prune".into(), None).await.unwrap();
    journal.destroy().await.unwrap();
}

/// Test behavior at section boundaries.
/// Assumes items_per_blob = 10.
async fn test_section_boundary_behavior<F, J>(factory: &F)
where
    F: Fn(String, Option<u64>) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("section-boundary".into(), None).await.unwrap();

    // Append exactly one section worth of items (10 items)
    for i in 0..10u64 {
        let pos;
        (journal, pos) = journal.append(&(i * 100)).await.unwrap();
        assert_eq!(pos, i);
    }

    // Verify we're at a blob boundary.
    assert_eq!(journal.bounds().end, 10);

    // Append one more item to cross the boundary
    let pos;
    (journal, pos) = journal.append(&999).await.unwrap();
    assert_eq!(pos, 10);
    assert_eq!(journal.bounds().end, 11);

    // Prune exactly at the blob boundary.
    (journal, _) = journal.prune(10).await.unwrap();
    assert_eq!(journal.bounds().start, 10);

    // Verify only the item after the boundary is readable
    assert!(matches!(journal.read(9).await, Err(Error::ItemPruned(_))));
    assert_eq!(journal.read(10).await.unwrap(), 999);

    // Append another item to move past the boundary
    let pos;
    (journal, pos) = journal.append(&888).await.unwrap();
    assert_eq!(pos, 11);
    assert_eq!(journal.bounds().end, 12);

    // Truncate to exactly the blob boundary (position 10).
    // This leaves bounds.end=10, bounds.start=10, making the journal fully pruned
    _ = journal.sync().await.unwrap();
    journal = factory("section-boundary".into(), Some(10)).await.unwrap();
    let bounds = journal.bounds();
    assert_eq!(bounds.end, 10);
    assert!(bounds.is_empty());

    // Append after truncating to boundary should continue from position 10
    let pos;
    (journal, pos) = journal.append(&777).await.unwrap();
    assert_eq!(pos, 10);
    assert_eq!(journal.bounds().end, 11);
    assert_eq!(journal.read(10).await.unwrap(), 777);
    assert_eq!(journal.bounds().start, 10);

    journal.destroy().await.unwrap();
}

/// Test that destroy properly cleans up storage and re-init starts fresh.
///
/// Verifies that after destroying a journal, a new journal with the same
/// partition name starts from a clean state.
async fn test_destroy_and_reinit<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let test_name = "destroy-and-reinit".to_string();

    // Create journal and add data
    {
        let mut journal = factory(test_name.clone()).await.unwrap();

        for i in 0..20u64 {
            (journal, _) = journal.append(&(i * 100)).await.unwrap();
        }

        let (journal, _) = journal.prune(10).await.unwrap();
        assert_eq!(journal.bounds().end, 20);
        assert!(!journal.bounds().is_empty());

        // Explicitly destroy the journal
        journal.destroy().await.unwrap();
    }

    // Re-initialize with the same partition name
    {
        let journal = factory(test_name.clone()).await.unwrap();

        // Journal should be completely empty, not contain previous data
        let bounds = journal.bounds();
        assert_eq!(bounds.end, 0);
        assert!(bounds.is_empty());

        // Replay should yield no items
        {
            let stream = replay_items(
                &journal,
                0..journal.bounds().end,
                NZUsize!(1024),
                ReadOptions::default(),
            )
            .await
            .unwrap();
            futures::pin_mut!(stream);

            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                items.push(result.unwrap());
            }
            assert!(items.is_empty());
        }

        journal.destroy().await.unwrap();
    }
}

/// Test append_many with empty slice returns an error.
async fn test_append_many_empty<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("append-many-empty".into()).await.unwrap();

    // Append some items first.
    (journal, _) = journal.append(&10).await.unwrap();
    (journal, _) = journal.append(&20).await.unwrap();

    assert_eq!(journal.bounds().end, 2);

    // append_many with empty slice should return an error.
    assert!(matches!(
        journal.append_many(Many::Flat(&[])).await,
        Err(Error::EmptyAppend)
    ));

    let journal = factory("append-many-empty".into()).await.unwrap();
    journal.destroy().await.unwrap();
}

/// Test append_many with multiple items.
async fn test_append_many_basic<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("append-many-basic".into()).await.unwrap();

    let pos;
    (journal, pos) = journal
        .append_many(Many::Flat(&[100, 200, 300]))
        .await
        .unwrap();
    assert_eq!(pos, 2);
    assert_eq!(journal.bounds().end, 3);

    assert_eq!(journal.read(0).await.unwrap(), 100);
    assert_eq!(journal.read(1).await.unwrap(), 200);
    assert_eq!(journal.read(2).await.unwrap(), 300);

    journal.destroy().await.unwrap();
}

/// Test append_many across blob boundaries (items_per_blob = 10).
async fn test_append_many_across_sections<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("append-many-sections".into()).await.unwrap();

    // Append 25 items in one call, crossing section boundaries at 10 and 20.
    let items: Vec<u64> = (0..25).map(|i| i * 10).collect();
    let pos;
    (journal, pos) = journal.append_many(Many::Flat(&items)).await.unwrap();
    assert_eq!(pos, 24);
    assert_eq!(journal.bounds().end, 25);

    for i in 0..25u64 {
        assert_eq!(journal.read(i).await.unwrap(), i * 10);
    }

    journal.destroy().await.unwrap();
}

/// Test append_many followed by single appends.
async fn test_append_many_then_append<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("append-many-then-single".into()).await.unwrap();

    (journal, _) = journal
        .append_many(Many::Flat(&[10, 20, 30]))
        .await
        .unwrap();
    let pos;
    (journal, pos) = journal.append(&40).await.unwrap();
    assert_eq!(pos, 3);

    assert_eq!(journal.read(0).await.unwrap(), 10);
    assert_eq!(journal.read(1).await.unwrap(), 20);
    assert_eq!(journal.read(2).await.unwrap(), 30);
    assert_eq!(journal.read(3).await.unwrap(), 40);

    journal.destroy().await.unwrap();
}

/// Test append_many with a single item behaves like append.
async fn test_append_many_single_item<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("append-many-single".into()).await.unwrap();

    let pos;
    (journal, pos) = journal.append_many(Many::Flat(&[42])).await.unwrap();
    assert_eq!(pos, 0);
    assert_eq!(journal.read(0).await.unwrap(), 42);

    journal.destroy().await.unwrap();
}

#[boxed]
async fn test_start_sync_durability<F, Fut, J>(factory: F)
where
    F: Fn(&'static str) -> Fut,
    Fut: Future<Output = Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("a").await.unwrap();
    for i in 0..7u64 {
        (journal, _) = journal.append(&(i * 10)).await.unwrap();
    }
    let handle;
    (journal, handle) = journal.start_sync().await.unwrap();
    handle.await.unwrap();
    let size = journal.bounds().end;
    drop(journal);

    let journal = factory("b").await.unwrap();
    assert_eq!(journal.bounds().end, size);
    for i in 0..7u64 {
        assert_eq!(journal.read(i).await.unwrap(), i * 10);
    }
    journal.destroy().await.unwrap();
}

#[test]
fn test_fixed_start_sync_durability() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = fixed::Config {
            partition: "fixed-start-sync".into(),
            items_per_blob: NZU64!(3),
            page_cache: CacheRef::new(NZU16!(44), NZUsize!(8)),
            write_buffer: NZUsize!(2048),
            replay_buffer: NZUsize!(2048),
        };
        test_start_sync_durability(|label| {
            let cfg = cfg.clone();
            fixed::Journal::<_, u64>::init(context.child(label), cfg)
        })
        .await;
    });
}

#[test]
fn test_variable_start_sync_durability() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = variable::Config {
            partition: "variable-start-sync".into(),
            items_per_section: NZU64!(3),
            compression: None,
            codec_config: (),
            page_cache: CacheRef::new(NZU16!(44), NZUsize!(8)),
            write_buffer: NZUsize!(2048),
            replay_buffer: NZUsize!(2048),
        };
        test_start_sync_durability(|label| {
            let cfg = cfg.clone();
            variable::Journal::<_, u64>::init(context.child(label), cfg)
        })
        .await;
    });
}

/// A sync handle must not block journal use while backend sync is pending.
#[boxed]
async fn test_start_sync_overlaps_work<F, Fut, J>(
    context: deterministic::Context,
    pending: PendingSyncs,
    make: F,
) where
    F: Fn(DelayedSyncContext<deterministic::Context>) -> Fut,
    Fut: Future<Output = Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = make(DelayedSyncContext {
        inner: context.child("a"),
        pending: pending.clone(),
    })
    .await
    .unwrap();
    for i in 0..4u64 {
        (journal, _) = journal.append(&i).await.unwrap();
    }

    let handle;
    (journal, handle) = journal.start_sync().await.unwrap();
    assert!(pending.starts() >= 1);
    assert_eq!(pending.completions(), 0);

    // Observe the sync while the journal keeps working.
    let waiter = context
        .child("await_sync")
        .spawn(|_| async move { handle.await.unwrap() });
    while pending.entered() == 0 {
        reschedule().await;
    }

    // Append/read complete before sync.
    (journal, _) = journal.append(&999).await.unwrap();
    assert_eq!(journal.read(0).await.unwrap(), 0);
    assert_eq!(
        pending.completions(),
        0,
        "the journal made progress while the sync was still in flight"
    );

    pending.unblock();
    waiter.await.unwrap();
    assert!(pending.completions() >= 1);

    // Mid-sync append is durable after the next sync.
    let handle;
    (journal, handle) = journal.start_sync().await.unwrap();
    handle.await.unwrap();
    drop(journal);

    let journal = make(DelayedSyncContext {
        inner: context.child("b"),
        pending: pending.clone(),
    })
    .await
    .unwrap();
    assert_eq!(journal.bounds().end, 5);
    for i in 0..4u64 {
        assert_eq!(journal.read(i).await.unwrap(), i);
    }
    assert_eq!(journal.read(4).await.unwrap(), 999);
    journal.destroy().await.unwrap();
}

/// A new sync waits for the prior sync before starting: the second start_sync call itself
/// (not its returned handle) stays pending, and no second backend sync starts, until the
/// prior sync completes.
#[boxed]
async fn test_start_sync_waits_for_prior<F, Fut, J>(
    context: deterministic::Context,
    pending: PendingSyncs,
    make: F,
) where
    F: Fn(DelayedSyncContext<deterministic::Context>) -> Fut,
    Fut: Future<Output = Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = make(DelayedSyncContext {
        inner: context.child("a"),
        pending: pending.clone(),
    })
    .await
    .unwrap();
    for i in 0..4u64 {
        (journal, _) = journal.append(&i).await.unwrap();
    }

    let first;
    (journal, first) = journal.start_sync().await.unwrap();
    let starts_before = pending.starts();
    (journal, _) = journal.append(&999).await.unwrap();

    let (journal, second) = {
        let mut call = std::pin::pin!(journal.start_sync());
        assert!(
            call.as_mut().now_or_never().is_none(),
            "start_sync proceeded while the prior sync was pending"
        );
        assert_eq!(
            pending.starts(),
            starts_before,
            "a second backend sync started while the prior sync was pending"
        );
        pending.unblock();
        call.await.unwrap()
    };
    first.await.unwrap();
    second.await.unwrap();
    journal.destroy().await.unwrap();
}

/// A sync handle completes only once both the tail sync and the predecessor's rollover sync
/// are durable.
#[boxed]
async fn test_start_sync_overlaps_predecessor_and_tail<F, Fut, J>(
    context: deterministic::Context,
    pending: PendingSyncs,
    make: F,
) where
    F: FnOnce(DelayedSyncContext<deterministic::Context>) -> Fut,
    Fut: Future<Output = Result<J, Error>>,
    J: Mutable<Item = u64> + 'static,
{
    let mut journal = make(DelayedSyncContext {
        inner: context.child("a"),
        pending: pending.clone(),
    })
    .await
    .unwrap();
    for i in 0..4u64 {
        (journal, _) = journal.append(&i).await.unwrap();
    }
    let starts_before = pending.starts();
    assert!(starts_before > 0);

    let handle;
    (journal, handle) = journal.start_sync().await.unwrap();
    assert!(
        pending.starts() > starts_before,
        "tail sync was not started while predecessor was in flight"
    );

    // The tail sync parked last. Releasing it alone must not complete the handle: the handle
    // also joins the predecessor's rollover sync.
    let tail = {
        let mut parked = pending.lock();
        assert!(
            parked.len() >= 2,
            "expected predecessor and tail syncs parked"
        );
        parked.pop().unwrap()
    };
    tail.release.send(Ok(())).unwrap();
    futures::pin_mut!(handle);
    assert!(
        handle.as_mut().now_or_never().is_none(),
        "sync handle completed without the predecessor sync"
    );

    // Releasing the predecessor completes the handle.
    pending.unblock();
    handle.await.unwrap();
    journal.destroy().await.unwrap();
}

/// A sync begun by `start_sync` that fails in flight surfaces the error through both the
/// returned handle and the next durability operation.
#[boxed]
async fn test_start_sync_failure_propagates<F, Fut, J>(
    context: deterministic::Context,
    pending: PendingSyncs,
    make: F,
) where
    F: FnOnce(DelayedSyncContext<deterministic::Context>) -> Fut,
    Fut: Future<Output = Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = make(DelayedSyncContext {
        inner: context.child("a"),
        pending: pending.clone(),
    })
    .await
    .unwrap();
    for i in 0..4u64 {
        (journal, _) = journal.append(&i).await.unwrap();
    }

    // Arm the in-flight sync to fail, and unblock it so it resolves to an error.
    pending.arm_fail();
    pending.unblock();

    let handle;
    (journal, handle) = journal.start_sync().await.unwrap();
    assert!(
        handle.await.is_err(),
        "the sync handle surfaces the failure"
    );
    let starts_before = pending.starts();
    // A failed mutable method consumes the journal per the failures-are-fatal contract.
    assert!(
        matches!(journal.commit().await, Err(Error::Runtime(_))),
        "the next durability op surfaces the failed in-flight sync"
    );
    assert_eq!(
        pending.starts(),
        starts_before,
        "the surfaced error is the retained failure, not a fresh sync's"
    );
}

fn fixed_overlap_cfg(partition: &str) -> fixed::Config {
    fixed::Config {
        partition: partition.into(),
        items_per_blob: NZU64!(10),
        page_cache: CacheRef::new(NZU16!(44), NZUsize!(8)),
        write_buffer: NZUsize!(2048),
        replay_buffer: NZUsize!(2048),
    }
}

fn variable_overlap_cfg(partition: &str) -> variable::Config<()> {
    variable::Config {
        partition: partition.into(),
        items_per_section: NZU64!(10),
        compression: None,
        codec_config: (),
        page_cache: CacheRef::new(NZU16!(44), NZUsize!(8)),
        write_buffer: NZUsize!(2048),
        replay_buffer: NZUsize!(2048),
    }
}

#[test]
fn test_fixed_start_sync_overlaps_predecessor_and_tail() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let pending = PendingSyncs::default();
        let cfg = fixed::Config {
            partition: "fixed-start-sync-predecessor".into(),
            items_per_blob: NZU64!(3),
            page_cache: CacheRef::new(NZU16!(44), NZUsize!(8)),
            write_buffer: NZUsize!(2048),
            replay_buffer: NZUsize!(2048),
        };
        test_start_sync_overlaps_predecessor_and_tail(context, pending, move |ctx| {
            fixed::Journal::<_, u64>::init(ctx, cfg)
        })
        .await;
    });
}

#[test]
fn test_variable_start_sync_overlaps_predecessor_and_tail() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let pending = PendingSyncs::default();
        let cfg = variable::Config {
            partition: "variable-start-sync-predecessor".into(),
            items_per_section: NZU64!(3),
            compression: None,
            codec_config: (),
            page_cache: CacheRef::new(NZU16!(44), NZUsize!(8)),
            write_buffer: NZUsize!(2048),
            replay_buffer: NZUsize!(2048),
        };
        test_start_sync_overlaps_predecessor_and_tail(context, pending, move |ctx| {
            variable::Journal::<_, u64>::init(ctx, cfg)
        })
        .await;
    });
}

#[test]
fn test_fixed_start_sync_overlaps_work() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let pending = PendingSyncs::default();
        let cfg = fixed_overlap_cfg("fixed-start-sync-overlap");
        test_start_sync_overlaps_work(context, pending, move |ctx| {
            let cfg = cfg.clone();
            fixed::Journal::<_, u64>::init(ctx, cfg)
        })
        .await;
    });
}

#[test]
fn test_variable_start_sync_overlaps_work() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let pending = PendingSyncs::default();
        let cfg = variable_overlap_cfg("variable-start-sync-overlap");
        test_start_sync_overlaps_work(context, pending, move |ctx| {
            let cfg = cfg.clone();
            variable::Journal::<_, u64>::init(ctx, cfg)
        })
        .await;
    });
}

#[test]
fn test_fixed_start_sync_waits_for_prior() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let pending = PendingSyncs::default();
        let cfg = fixed_overlap_cfg("fixed-start-sync-waits");
        test_start_sync_waits_for_prior(context, pending, move |ctx| {
            let cfg = cfg.clone();
            fixed::Journal::<_, u64>::init(ctx, cfg)
        })
        .await;
    });
}

#[test]
fn test_variable_start_sync_waits_for_prior() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let pending = PendingSyncs::default();
        let cfg = variable_overlap_cfg("variable-start-sync-waits");
        test_start_sync_waits_for_prior(context, pending, move |ctx| {
            let cfg = cfg.clone();
            variable::Journal::<_, u64>::init(ctx, cfg)
        })
        .await;
    });
}

#[test]
fn test_fixed_start_sync_failure_propagates() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let pending = PendingSyncs::default();
        let cfg = fixed_overlap_cfg("fixed-start-sync-fail");
        test_start_sync_failure_propagates(context, pending, move |ctx| {
            fixed::Journal::<_, u64>::init(ctx, cfg)
        })
        .await;
    });
}

#[test]
fn test_variable_start_sync_failure_propagates() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let pending = PendingSyncs::default();
        let cfg = variable_overlap_cfg("variable-start-sync-fail");
        test_start_sync_failure_propagates(context, pending, move |ctx| {
            variable::Journal::<_, u64>::init(ctx, cfg)
        })
        .await;
    });
}

/// Destructive operations drain the in-flight rollover sync before mutating storage.
#[boxed]
async fn test_prune_waits_for_pending_sync<F, Fut, J>(
    context: deterministic::Context,
    pending: PendingSyncs,
    make: F,
) where
    F: FnOnce(DelayedSyncContext<deterministic::Context>) -> Fut,
    Fut: Future<Output = Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = make(DelayedSyncContext {
        inner: context.child("a"),
        pending: pending.clone(),
    })
    .await
    .unwrap();
    for i in 0..4u64 {
        (journal, _) = journal.append(&i).await.unwrap();
    }
    assert!(pending.starts() > 0);

    let prune = journal.prune(3);
    futures::pin_mut!(prune);
    assert!(
        prune.as_mut().now_or_never().is_none(),
        "prune proceeded while the rollover sync was pending"
    );
    pending.unblock();
    let (journal, _) = prune.await.unwrap();
    assert_eq!(journal.bounds(), 3..4);
    journal.destroy().await.unwrap();
}

/// Destructive operations surface a failed in-flight sync instead of proceeding.
#[boxed]
async fn test_prune_surfaces_failed_sync<F, Fut, J>(
    context: deterministic::Context,
    pending: PendingSyncs,
    make: F,
) where
    F: FnOnce(DelayedSyncContext<deterministic::Context>) -> Fut,
    Fut: Future<Output = Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = make(DelayedSyncContext {
        inner: context.child("a"),
        pending: pending.clone(),
    })
    .await
    .unwrap();
    for i in 0..4u64 {
        (journal, _) = journal.append(&i).await.unwrap();
    }
    assert!(pending.starts() > 0);

    // Fail the parked rollover sync. The drain in prune must surface it. A failed mutable method
    // consumes the journal per the failures-are-fatal contract.
    pending.arm_fail();
    pending.unblock();
    assert!(
        matches!(journal.prune(3).await, Err(Error::Runtime(_))),
        "prune must surface the failed rollover sync"
    );
}

#[test]
fn test_fixed_prune_waits_for_pending_sync() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let pending = PendingSyncs::default();
        let cfg = fixed::Config {
            partition: "fixed-prune-pending".into(),
            items_per_blob: NZU64!(3),
            page_cache: CacheRef::new(NZU16!(44), NZUsize!(8)),
            write_buffer: NZUsize!(2048),
            replay_buffer: NZUsize!(2048),
        };
        test_prune_waits_for_pending_sync(context, pending, move |ctx| {
            fixed::Journal::<_, u64>::init(ctx, cfg)
        })
        .await;
    });
}

#[test]
fn test_variable_prune_waits_for_pending_sync() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let pending = PendingSyncs::default();
        let cfg = variable::Config {
            partition: "variable-prune-pending".into(),
            items_per_section: NZU64!(3),
            compression: None,
            codec_config: (),
            page_cache: CacheRef::new(NZU16!(44), NZUsize!(8)),
            write_buffer: NZUsize!(2048),
            replay_buffer: NZUsize!(2048),
        };
        test_prune_waits_for_pending_sync(context, pending, move |ctx| {
            variable::Journal::<_, u64>::init(ctx, cfg)
        })
        .await;
    });
}

#[test]
fn test_fixed_prune_surfaces_failed_sync() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let pending = PendingSyncs::default();
        let cfg = fixed::Config {
            partition: "fixed-prune-fail".into(),
            items_per_blob: NZU64!(3),
            page_cache: CacheRef::new(NZU16!(44), NZUsize!(8)),
            write_buffer: NZUsize!(2048),
            replay_buffer: NZUsize!(2048),
        };
        test_prune_surfaces_failed_sync(context, pending, move |ctx| {
            fixed::Journal::<_, u64>::init(ctx, cfg)
        })
        .await;
    });
}

#[test]
fn test_variable_prune_surfaces_failed_sync() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let pending = PendingSyncs::default();
        let cfg = variable::Config {
            partition: "variable-prune-fail".into(),
            items_per_section: NZU64!(3),
            compression: None,
            codec_config: (),
            page_cache: CacheRef::new(NZU16!(44), NZUsize!(8)),
            write_buffer: NZUsize!(2048),
            replay_buffer: NZUsize!(2048),
        };
        test_prune_surfaces_failed_sync(context, pending, move |ctx| {
            variable::Journal::<_, u64>::init(ctx, cfg)
        })
        .await;
    });
}

#[test]
fn test_fresh_sync_avoids_reset_writes() {
    deterministic::Runner::default().start(|context| async move {
        let cache = CacheRef::new(NZU16!(64), NZUsize!(4));
        let fixed_cfg = |partition: &str| fixed::Config {
            partition: partition.into(),
            items_per_blob: NZU64!(5),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            page_cache: cache.clone(),
        };
        let (ordinary, ordinary_io) = RecordingContext::new(context.child("fixed_ordinary"));
        drop(
            fixed::Journal::<_, u64>::init(ordinary, fixed_cfg("fixed-ordinary"))
                .await
                .unwrap(),
        );
        let (sync, sync_io) = RecordingContext::new(context.child("fixed_sync"));
        let journal = crate::journal::authenticated::init_sync::<_, fixed::Journal<_, u64>>(
            sync.child("journal"),
            fixed_cfg("fixed-sync"),
            0..10,
        )
        .await
        .unwrap();
        assert_eq!(journal.bounds(), 0..0);
        assert_eq!(
            sync_io.snapshot().writes.len(),
            ordinary_io.snapshot().writes.len()
        );
        let variable_cfg = |partition: &str| variable::Config {
            partition: partition.into(),
            items_per_section: NZU64!(5),
            compression: None,
            codec_config: (),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            page_cache: cache.clone(),
        };
        let (ordinary, ordinary_io) = RecordingContext::new(context.child("variable_ordinary"));
        drop(
            variable::Journal::<_, u64>::init(ordinary, variable_cfg("variable-ordinary"))
                .await
                .unwrap(),
        );
        let (sync, sync_io) = RecordingContext::new(context.child("variable_sync"));
        let journal = crate::journal::authenticated::init_sync::<_, variable::Journal<_, u64>>(
            sync.child("journal"),
            variable_cfg("variable-sync"),
            0..10,
        )
        .await
        .unwrap();
        assert_eq!(journal.bounds(), 0..0);
        assert_eq!(
            sync_io.snapshot().writes.len(),
            ordinary_io.snapshot().writes.len()
        );
    });
}

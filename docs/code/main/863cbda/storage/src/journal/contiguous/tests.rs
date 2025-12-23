//! Generic test suite for [Contiguous] trait implementations.

use super::Contiguous;
use crate::journal::{
    contiguous::{MutableContiguous, PersistableContiguous},
    Error,
};
use commonware_utils::NZUsize;
use futures::{future::BoxFuture, StreamExt};

/// Run the full suite of generic tests on a [Contiguous] implementation.
///
/// The factory function receives a test identifier string that should be used
/// to create unique partitions for each test to avoid conflicts.
///
/// # Assumptions
///
/// These tests assume the journal is configured with **`items_per_section = 10`**
/// (or `items_per_blob = 10` for fixed journals). Some tests rely on this value
/// for section boundary calculations and pruning behavior.
pub(super) async fn run_contiguous_tests<F, J>(factory: F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    test_empty_journal_size(&factory).await;
    test_empty_journal_oldest_retained_pos(&factory).await;
    test_oldest_retained_pos_with_items(&factory).await;
    test_oldest_retained_pos_after_prune(&factory).await;
    test_pruning_boundary(&factory).await;
    test_append_and_size(&factory).await;
    test_sequential_appends(&factory).await;
    test_replay_from_start(&factory).await;
    test_replay_from_middle(&factory).await;
    test_prune_retains_size(&factory).await;
    test_through_trait(&factory).await;
    test_replay_after_prune(&factory).await;
    test_prune_then_append(&factory).await;
    test_position_stability(&factory).await;
    test_sync_behavior(&factory).await;
    test_replay_on_empty(&factory).await;
    test_replay_at_exact_size(&factory).await;
    test_multiple_prunes(&factory).await;
    test_prune_beyond_size(&factory).await;
    test_persistence_basic(&factory).await;
    test_persistence_after_prune(&factory).await;
    test_read_by_position(&factory).await;
    test_read_out_of_range(&factory).await;
    test_read_after_prune(&factory).await;
    test_rewind_to_middle(&factory).await;
    test_rewind_to_zero(&factory).await;
    test_rewind_current_size(&factory).await;
    test_rewind_invalid_forward(&factory).await;
    test_rewind_invalid_pruned(&factory).await;
    test_rewind_then_append(&factory).await;
    test_rewind_zero_then_append(&factory).await;
    test_rewind_after_prune(&factory).await;
    test_section_boundary_behavior(&factory).await;
    test_destroy_and_reinit(&factory).await;
}

/// Test that an empty journal has size 0.
async fn test_empty_journal_size<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let journal = factory("empty".to_string()).await.unwrap();
    assert_eq!(journal.size(), 0);
    journal.destroy().await.unwrap();
}

/// Test that oldest_retained_pos returns None for empty journal.
async fn test_empty_journal_oldest_retained_pos<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let journal = factory("oldest_empty".to_string()).await.unwrap();
    assert_eq!(journal.oldest_retained_pos(), None);
    journal.destroy().await.unwrap();
}

/// Test that oldest_retained_pos returns Some(0) for journal with items.
async fn test_oldest_retained_pos_with_items<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("oldest_with_items".to_string()).await.unwrap();

    // Append some items
    for i in 0..10 {
        journal.append(i * 100).await.unwrap();
    }

    // Should return 0 (first position)
    assert_eq!(journal.oldest_retained_pos(), Some(0));
    journal.destroy().await.unwrap();
}

/// Test that oldest_retained_pos updates after pruning.
///
/// This test assumes items_per_section = 10.
async fn test_oldest_retained_pos_after_prune<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("oldest_after_prune".to_string()).await.unwrap();

    // Append items across multiple sections
    for i in 0..30 {
        journal.append(i * 100).await.unwrap();
    }

    // Oldest should be 0
    assert_eq!(journal.oldest_retained_pos(), Some(0));

    // Prune first section - trait only guarantees section-aligned pruning
    journal.prune(10).await.unwrap();

    // Assumed section-aligned pruning and items_per_section = 10
    let oldest = journal.oldest_retained_pos().unwrap();
    assert_eq!(oldest, 10);

    // Prune more
    let prev_oldest = oldest;
    journal.prune(25).await.unwrap();

    // Oldest should have advanced and be at most 25
    let oldest = journal.oldest_retained_pos().unwrap();
    assert!(oldest > prev_oldest);
    assert_eq!(oldest, 20);

    // Prune all
    journal.prune(30).await.unwrap();
    assert!(journal.oldest_retained_pos().is_none());

    // Close and reopen
    journal.close().await.unwrap();
    let journal = factory("oldest_after_prune".to_string()).await.unwrap();
    assert!(journal.oldest_retained_pos().is_none());

    journal.destroy().await.unwrap();
}

/// Test that pruning_boundary returns the correct value in various states.
///
/// This test assumes items_per_section = 10.
async fn test_pruning_boundary<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    // Test empty journal: should return size (0)
    let journal = factory("pruning_boundary_empty".to_string()).await.unwrap();
    assert_eq!(journal.pruning_boundary(), 0);
    journal.destroy().await.unwrap();

    // Test journal with items: should return oldest_retained_pos
    let mut journal = factory("pruning_boundary_with_items".to_string())
        .await
        .unwrap();
    for i in 0..10 {
        journal.append(i * 100).await.unwrap();
    }
    assert_eq!(journal.pruning_boundary(), 0);
    journal.destroy().await.unwrap();

    // Test partially pruned journal: should return oldest_retained_pos
    let mut journal = factory("pruning_boundary_partial_prune".to_string())
        .await
        .unwrap();
    for i in 0..30 {
        journal.append(i * 100).await.unwrap();
    }
    journal.prune(10).await.unwrap();
    let oldest = journal.oldest_retained_pos().unwrap();
    assert_eq!(journal.pruning_boundary(), oldest);
    journal.destroy().await.unwrap();

    // Test fully pruned journal: should return size
    let mut journal = factory("pruning_boundary_full_prune".to_string())
        .await
        .unwrap();
    for i in 0..30 {
        journal.append(i * 100).await.unwrap();
    }
    journal.prune(30).await.unwrap();
    let size = journal.size();
    assert_eq!(journal.pruning_boundary(), size);
    assert_eq!(journal.oldest_retained_pos(), None);
    journal.destroy().await.unwrap();
}

/// Test that append returns sequential positions and size increments.
async fn test_append_and_size<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("append_and_size".to_string()).await.unwrap();

    let pos1 = journal.append(100).await.unwrap();
    let pos2 = journal.append(200).await.unwrap();
    let pos3 = journal.append(300).await.unwrap();

    assert_eq!(pos1, 0);
    assert_eq!(pos2, 1);
    assert_eq!(pos3, 2);
    assert_eq!(journal.size(), 3);

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
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("sequential_appends".to_string()).await.unwrap();

    for i in 0..25u64 {
        let pos = journal.append(i * 10).await.unwrap();
        assert_eq!(pos, i);
    }

    assert_eq!(journal.size(), 25);

    for i in 0..25u64 {
        assert_eq!(journal.read(i).await.unwrap(), i * 10);
    }

    journal.destroy().await.unwrap();
}

/// Test replay from the start of the journal.
async fn test_replay_from_start<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("replay_from_start".to_string()).await.unwrap();

    for i in 0..10u64 {
        journal.append(i * 10).await.unwrap();
    }

    {
        let stream = journal.replay(0, NZUsize!(1024)).await.unwrap();
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
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("replay_from_middle".to_string()).await.unwrap();

    for i in 0..15u64 {
        journal.append(i * 10).await.unwrap();
    }

    {
        let stream = journal.replay(7, NZUsize!(1024)).await.unwrap();
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

/// Test that size is unchanged after pruning.
async fn test_prune_retains_size<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("prune_retains_size".to_string()).await.unwrap();

    for i in 0..20u64 {
        journal.append(i).await.unwrap();
    }

    let size_before = journal.size();
    journal.prune(10).await.unwrap();
    let size_after = journal.size();

    assert_eq!(size_before, size_after);
    assert_eq!(size_after, 20);

    journal.prune(20).await.unwrap();
    let size_after_all = journal.size();
    assert_eq!(size_after, size_after_all);

    journal.close().await.unwrap();

    let journal = factory("prune_retains_size".to_string()).await.unwrap();
    let size_after_close = journal.size();
    assert_eq!(size_after_close, size_after_all);

    journal.destroy().await.unwrap();
}

/// Test using journal through [Contiguous] trait methods.
async fn test_through_trait<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("through_trait".to_string()).await.unwrap();

    let pos1 = MutableContiguous::append(&mut journal, 42).await.unwrap();
    let pos2 = MutableContiguous::append(&mut journal, 100).await.unwrap();

    assert_eq!(pos1, 0);
    assert_eq!(pos2, 1);

    let size = Contiguous::size(&journal);
    assert_eq!(size, 2);

    journal.destroy().await.unwrap();
}

/// Test replay after pruning items.
async fn test_replay_after_prune<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("replay_after_prune".to_string()).await.unwrap();

    for i in 0..20u64 {
        journal.append(i * 10).await.unwrap();
    }

    journal.prune(10).await.unwrap();

    {
        // Replay from a position that may or may not be pruned (section-aligned)
        // We replay from position 10 which should be safe
        let stream = journal.replay(10, NZUsize!(1024)).await.unwrap();
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
/// pruning all retained items. Assumes items_per_section = 10.
async fn test_prune_then_append<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("prune_then_append".to_string()).await.unwrap();

    // Append exactly one section (10 items)
    for i in 0..10u64 {
        journal.append(i).await.unwrap();
    }

    // Prune all items (prune at section boundary)
    journal.prune(10).await.unwrap();
    assert!(journal.oldest_retained_pos().is_none());

    // Append new items after pruning - position should continue from 10
    let pos = journal.append(999).await.unwrap();
    assert_eq!(pos, 10);

    let size = journal.size();
    assert_eq!(size, 11);

    journal.destroy().await.unwrap();
}

/// Test that positions remain stable after pruning and further appends.
async fn test_position_stability<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("position_stability".to_string()).await.unwrap();

    // Append initial items
    for i in 0..20u64 {
        journal.append(i * 100).await.unwrap();
    }

    // Prune first 10
    journal.prune(10).await.unwrap();

    // Append more items
    for i in 20..25u64 {
        let pos = journal.append(i * 100).await.unwrap();
        assert_eq!(pos, i);
    }

    // Verify reads work for retained items after pruning
    assert_eq!(journal.read(10).await.unwrap(), 1000);
    assert_eq!(journal.read(15).await.unwrap(), 1500);
    assert_eq!(journal.read(20).await.unwrap(), 2000);
    assert_eq!(journal.read(24).await.unwrap(), 2400);

    {
        // Replay from position 10 and verify positions
        let stream = journal.replay(10, NZUsize!(1024)).await.unwrap();
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
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("sync_behavior".to_string()).await.unwrap();

    for i in 0..5u64 {
        journal.append(i).await.unwrap();
    }

    journal.sync().await.unwrap();

    // Verify operations work after sync
    assert_eq!(journal.read(0).await.unwrap(), 0);
    let pos = journal.append(100).await.unwrap();
    assert_eq!(pos, 5);
    assert_eq!(journal.read(5).await.unwrap(), 100);

    let size = journal.size();
    assert_eq!(size, 6);

    journal.destroy().await.unwrap();
}

/// Test replay on an empty journal.
async fn test_replay_on_empty<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let journal = factory("replay_on_empty".to_string()).await.unwrap();

    {
        let stream = journal.replay(0, NZUsize!(1024)).await.unwrap();
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
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("replay_at_exact_size".to_string()).await.unwrap();

    for i in 0..10u64 {
        journal.append(i).await.unwrap();
    }

    let size = journal.size();

    {
        let stream = journal.replay(size, NZUsize!(1024)).await.unwrap();
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
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("multiple_prunes".to_string()).await.unwrap();

    for i in 0..20u64 {
        journal.append(i).await.unwrap();
    }

    let pruned1 = journal.prune(10).await.unwrap();
    let pruned2 = journal.prune(10).await.unwrap();

    assert!(pruned1);
    assert!(!pruned2); // Second prune should return false (nothing to prune)

    let size = journal.size();
    assert_eq!(size, 20);
    assert_eq!(journal.read(10).await.unwrap(), 10);
    assert_eq!(journal.read(19).await.unwrap(), 19);

    journal.destroy().await.unwrap();
}

/// Test pruning beyond the current size.
async fn test_prune_beyond_size<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("prune_beyond_size".to_string()).await.unwrap();

    for i in 0..10u64 {
        journal.append(i).await.unwrap();
    }

    // Prune with min_position > size should be safe
    journal.prune(100).await.unwrap();

    // Verify journal still works
    let size = journal.size();
    assert_eq!(size, 10);

    let pos = journal.append(999).await.unwrap();
    assert_eq!(pos, 10);
    assert_eq!(journal.read(10).await.unwrap(), 999);

    journal.destroy().await.unwrap();
}

/// Test basic persistence: append items, close, re-open, verify state.
async fn test_persistence_basic<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let test_name = "persistence_basic".to_string();

    // Create journal and append items
    {
        let mut journal = factory(test_name.clone()).await.unwrap();

        for i in 0..15u64 {
            let pos = journal.append(i * 10).await.unwrap();
            assert_eq!(pos, i);
        }

        let size = journal.size();
        assert_eq!(size, 15);

        journal.close().await.unwrap();
    }

    // Re-open and verify state persists
    {
        let journal = factory(test_name.clone()).await.unwrap();

        let size = journal.size();
        assert_eq!(size, 15);

        // Verify reads work after persistence
        for i in 0..15u64 {
            assert_eq!(journal.read(i).await.unwrap(), i * 10);
        }

        // Replay and verify all items
        {
            let stream = journal.replay(0, NZUsize!(1024)).await.unwrap();
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
    J: PersistableContiguous<Item = u64>,
{
    let test_name = "persistence_after_prune".to_string();

    // Create journal, append items, and prune
    {
        let mut journal = factory(test_name.clone()).await.unwrap();

        for i in 0..25u64 {
            journal.append(i * 100).await.unwrap();
        }

        // Prune first 10 items
        let pruned = journal.prune(10).await.unwrap();
        assert!(pruned);

        let size = journal.size();
        assert_eq!(size, 25);

        journal.close().await.unwrap();
    }

    // Re-open and verify pruned state persists
    {
        let mut journal = factory(test_name.clone()).await.unwrap();

        // Size should still be 25
        let size = journal.size();
        assert_eq!(size, 25);

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
            let stream = journal.replay(10, NZUsize!(1024)).await.unwrap();
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
        let pos = journal.append(999).await.unwrap();
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
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("read_by_position".to_string()).await.unwrap();

    for i in 0..1000u64 {
        journal.append(i * 100).await.unwrap();
        assert_eq!(journal.read(i).await.unwrap(), i * 100);
    }

    // Verify we can still read all items
    for i in 0..1000u64 {
        assert_eq!(journal.read(i).await.unwrap(), i * 100);
    }

    journal.destroy().await.unwrap();
}

/// Test read errors for out-of-range positions.
pub(super) async fn test_read_out_of_range<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("read_out_of_range".to_string()).await.unwrap();

    journal.append(42).await.unwrap();

    // Try to read beyond size
    let result = journal.read(10).await;
    assert!(matches!(result, Err(Error::ItemOutOfRange(_))));

    journal.destroy().await.unwrap();
}

/// Test read after pruning.
pub(super) async fn test_read_after_prune<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("read_after_prune".to_string()).await.unwrap();

    for i in 0..20u64 {
        journal.append(i).await.unwrap();
    }

    journal.prune(10).await.unwrap();

    let oldest_retained_pos = journal.oldest_retained_pos().unwrap();
    let result = journal.read(oldest_retained_pos - 1).await;
    assert!(matches!(result, Err(Error::ItemPruned(_))));

    journal.destroy().await.unwrap();
}

/// Test rewinding to the middle of the journal
async fn test_rewind_to_middle<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("rewind_to_middle".to_string()).await.unwrap();

    // Append 20 items
    for i in 0..20u64 {
        journal.append(i * 100).await.unwrap();
    }

    // Rewind to 12 items
    journal.rewind(12).await.unwrap();

    assert_eq!(journal.size(), 12);

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
    let pos = journal.append(999).await.unwrap();
    assert_eq!(pos, 12);
    assert_eq!(journal.read(12).await.unwrap(), 999);

    journal.destroy().await.unwrap();
}

/// Test rewinding to empty journal
async fn test_rewind_to_zero<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("rewind_to_zero".to_string()).await.unwrap();

    for i in 0..10u64 {
        journal.append(i).await.unwrap();
    }

    journal.rewind(0).await.unwrap();

    assert_eq!(journal.size(), 0);
    assert_eq!(journal.oldest_retained_pos(), None);

    // Next append should get position 0
    let pos = journal.append(42).await.unwrap();
    assert_eq!(pos, 0);

    journal.destroy().await.unwrap();
}

/// Test rewind to current size is no-op
async fn test_rewind_current_size<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("rewind_current_size".to_string()).await.unwrap();

    for i in 0..10u64 {
        journal.append(i).await.unwrap();
    }

    // Rewind to current size should be no-op
    journal.rewind(10).await.unwrap();
    assert_eq!(journal.size(), 10);

    journal.destroy().await.unwrap();
}

/// Test rewind with invalid forward size
async fn test_rewind_invalid_forward<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("rewind_invalid_forward".to_string()).await.unwrap();

    for i in 0..10u64 {
        journal.append(i).await.unwrap();
    }

    // Try to rewind forward (invalid)
    let result = journal.rewind(20).await;
    assert!(matches!(result, Err(Error::InvalidRewind(20))));

    journal.destroy().await.unwrap();
}

/// Test rewind to pruned position
async fn test_rewind_invalid_pruned<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("rewind_invalid_pruned".to_string()).await.unwrap();

    for i in 0..20u64 {
        journal.append(i).await.unwrap();
    }

    // Prune first 10 items
    journal.prune(10).await.unwrap();

    // Try to rewind to pruned position (invalid)
    let result = journal.rewind(5).await;
    assert!(matches!(result, Err(Error::ItemPruned(5))));

    journal.destroy().await.unwrap();
}

/// Test rewind then append maintains position continuity.
/// Assumes items_per_section = 10.
async fn test_rewind_then_append<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("rewind_then_append".to_string()).await.unwrap();

    // Append across section boundary (15 items = 1.5 sections)
    for i in 0..15u64 {
        journal.append(i).await.unwrap();
    }

    // Rewind to position 8 (within first section, not at boundary)
    journal.rewind(8).await.unwrap();

    // Append should continue from position 8
    let pos1 = journal.append(888).await.unwrap();
    let pos2 = journal.append(999).await.unwrap();

    assert_eq!(pos1, 8);
    assert_eq!(pos2, 9);
    assert_eq!(journal.read(8).await.unwrap(), 888);
    assert_eq!(journal.read(9).await.unwrap(), 999);

    journal.destroy().await.unwrap();
}

/// Test that rewinding to zero and then appending works
async fn test_rewind_zero_then_append<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("rewind_zero_then_append".to_string())
        .await
        .unwrap();

    // Append some items
    for i in 0..10u64 {
        journal.append(i * 100).await.unwrap();
    }

    // Rewind to 0 (empty journal)
    journal.rewind(0).await.unwrap();

    // Verify journal is empty
    assert_eq!(journal.size(), 0);
    assert_eq!(journal.oldest_retained_pos(), None);

    // Append should work
    let pos = journal.append(42).await.unwrap();
    assert_eq!(pos, 0);
    assert_eq!(journal.size(), 1);
    assert_eq!(journal.read(0).await.unwrap(), 42);

    journal.destroy().await.unwrap();
}

/// Test rewinding after pruning to verify correct interaction between operations.
/// Assumes items_per_section = 10.
async fn test_rewind_after_prune<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("rewind_after_prune".to_string()).await.unwrap();

    // Append items across 3 sections (30 items, assuming items_per_section = 10)
    for i in 0..30u64 {
        journal.append(i * 100).await.unwrap();
    }

    // Prune first section (items 0-9)
    journal.prune(10).await.unwrap();
    let oldest = journal.oldest_retained_pos().unwrap();
    assert_eq!(oldest, 10);

    // Rewind to position 20 (still in retained range)
    journal.rewind(20).await.unwrap();
    assert_eq!(journal.size(), 20);
    assert_eq!(journal.oldest_retained_pos(), Some(10));

    // Verify items in range [oldest, 20) are still readable
    for i in oldest..20 {
        assert_eq!(journal.read(i).await.unwrap(), i * 100);
    }

    // Attempt to rewind to a pruned position should fail
    let result = journal.rewind(5).await;
    assert!(matches!(result, Err(Error::ItemPruned(5))));

    // Verify journal state is unchanged after failed rewind
    assert_eq!(journal.size(), 20);
    assert_eq!(journal.oldest_retained_pos(), Some(10));

    // Append should continue from position 20
    let pos = journal.append(999).await.unwrap();
    assert_eq!(pos, 20);
    assert_eq!(journal.read(20).await.unwrap(), 999);
    assert_eq!(journal.oldest_retained_pos(), Some(10));

    journal.destroy().await.unwrap();
}

/// Test behavior at section boundaries.
/// Assumes items_per_section = 10.
async fn test_section_boundary_behavior<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let mut journal = factory("section_boundary".to_string()).await.unwrap();

    // Append exactly one section worth of items (10 items)
    for i in 0..10u64 {
        let pos = journal.append(i * 100).await.unwrap();
        assert_eq!(pos, i);
    }

    // Verify we're at a section boundary
    assert_eq!(journal.size(), 10);

    // Append one more item to cross the boundary
    let pos = journal.append(999).await.unwrap();
    assert_eq!(pos, 10);
    assert_eq!(journal.size(), 11);

    // Prune exactly at the section boundary
    journal.prune(10).await.unwrap();
    let oldest = journal.oldest_retained_pos().unwrap();
    assert_eq!(oldest, 10);

    // Verify only the item after the boundary is readable
    assert!(matches!(journal.read(9).await, Err(Error::ItemPruned(_))));
    assert_eq!(journal.read(10).await.unwrap(), 999);

    // Append another item to move past the boundary
    let pos = journal.append(888).await.unwrap();
    assert_eq!(pos, 11);
    assert_eq!(journal.size(), 12);

    // Rewind to exactly the section boundary (position 10)
    // This leaves size=10, oldest=10, making the journal fully pruned
    journal.rewind(10).await.unwrap();
    assert_eq!(journal.size(), 10);
    assert!(journal.oldest_retained_pos().is_none());

    // Append after rewinding to boundary should continue from position 10
    let pos = journal.append(777).await.unwrap();
    assert_eq!(pos, 10);
    assert_eq!(journal.size(), 11);
    assert_eq!(journal.read(10).await.unwrap(), 777);
    assert_eq!(journal.oldest_retained_pos(), Some(10));

    journal.destroy().await.unwrap();
}

/// Test that destroy properly cleans up storage and re-init starts fresh.
///
/// Verifies that after destroying a journal, a new journal with the same
/// partition name starts from a clean state.
async fn test_destroy_and_reinit<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: PersistableContiguous<Item = u64>,
{
    let test_name = "destroy_and_reinit".to_string();

    // Create journal and add data
    {
        let mut journal = factory(test_name.clone()).await.unwrap();

        for i in 0..20u64 {
            journal.append(i * 100).await.unwrap();
        }

        journal.prune(10).await.unwrap();
        assert_eq!(journal.size(), 20);
        let oldest = journal.oldest_retained_pos();
        assert!(oldest.is_some());

        // Explicitly destroy the journal
        journal.destroy().await.unwrap();
    }

    // Re-initialize with the same partition name
    {
        let journal = factory(test_name.clone()).await.unwrap();

        // Journal should be completely empty, not contain previous data
        assert_eq!(journal.size(), 0);
        assert_eq!(journal.oldest_retained_pos(), None);

        // Replay should yield no items
        {
            let stream = journal.replay(0, NZUsize!(1024)).await.unwrap();
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

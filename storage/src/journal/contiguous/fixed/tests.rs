use super::*;
use crate::metadata::Config as MetadataConfig;
use commonware_codec::FixedSize;
use commonware_cryptography::{sha256::Digest, Hasher as _, Sha256};
use commonware_macros::test_traced;
use commonware_runtime::{
    buffer::paged::AppendWriter,
    deterministic::{self, Context},
    Blob, BufferPooler, Error as RuntimeError, Metrics as _, Runner, Spawner as _, Storage,
    Supervisor as _,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use futures::{pin_mut, StreamExt};
use std::num::NonZeroU16;

const PAGE_SIZE: NonZeroU16 = NZU16!(44);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(3);

/// Generate a SHA-256 digest for the given value.
fn test_digest(value: u64) -> Digest {
    Sha256::hash(&value.to_be_bytes())
}

fn test_cfg(pooler: &impl BufferPooler, items_per_blob: NonZeroU64) -> Config {
    Config {
        partition: "test-partition".into(),
        items_per_blob,
        page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        write_buffer: NZUsize!(2048),
    }
}

fn blob_partition(cfg: &Config) -> String {
    format!("{}-blobs", cfg.partition)
}

#[test_traced]
fn test_fixed_init_marks_suffix_past_recovery_watermark_dirty() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let mut cfg = test_cfg(&context, NZU64!(10));
        cfg.partition = "init-adopted-fixed".into();

        let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
            .await
            .unwrap();
        journal.append(&1).await.unwrap();
        journal.append(&2).await.unwrap();
        journal.sync().await.unwrap();
        // Simulate the state left by a crash after item 2 became visible to recovery, but
        // before the persisted recovery watermark advanced past item 1.
        journal.test_set_recovery_watermark(1).await.unwrap();
        drop(journal);

        let mut journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
            .await
            .unwrap();
        assert_eq!(journal.size(), 2);

        // Regression: init used to recover size 2 while marking no data blobs dirty.
        // commit() would then skip blob syncs and succeed even though the recovered suffix
        // had not been durably adopted. With the fix, item 2's blob is dirty, so the forced
        // sync failure below must surface.
        *context.storage_fault_config().write() = deterministic::FaultConfig {
            sync_rate: Some(1.0),
            ..Default::default()
        };
        assert!(
            journal.commit().await.is_err(),
            "commit() must sync recovered data beyond the persisted recovery watermark"
        );
    });
}

async fn scan_partition(context: &Context, partition: &str) -> Vec<Vec<u8>> {
    match context.scan(partition).await {
        Ok(blobs) => blobs,
        Err(RuntimeError::PartitionMissing(_)) => Vec::new(),
        Err(err) => panic!("Failed to scan partition {partition}: {err}"),
    }
}

#[test_traced]
fn test_fixed_journal_init_conflicting_partitions() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(2));
        let legacy_partition = cfg.partition.clone();
        let blobs_partition = blob_partition(&cfg);

        let (legacy_blob, _) = context
            .open(&legacy_partition, &0u64.to_be_bytes())
            .await
            .expect("Failed to open legacy blob");
        legacy_blob
            .write_at_sync(0, vec![0u8; 1])
            .await
            .expect("Failed to write legacy blob");

        let (new_blob, _) = context
            .open(&blobs_partition, &0u64.to_be_bytes())
            .await
            .expect("Failed to open new blob");
        new_blob
            .write_at_sync(0, vec![0u8; 1])
            .await
            .expect("Failed to write new blob");

        let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
        assert!(matches!(result, Err(Error::Corruption(_))));
    });
}

#[test_traced]
fn test_fixed_journal_init_prefers_legacy_partition() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(2));
        let legacy_partition = cfg.partition.clone();
        let blobs_partition = blob_partition(&cfg);

        // Seed legacy partition so it is selected.
        let (legacy_blob, _) = context
            .open(&legacy_partition, &0u64.to_be_bytes())
            .await
            .expect("Failed to open legacy blob");
        legacy_blob
            .write_at_sync(0, vec![0u8; 1])
            .await
            .expect("Failed to write legacy blob");

        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .expect("failed to initialize journal");
        journal.append(&test_digest(1)).await.unwrap();
        journal.sync().await.unwrap();
        drop(journal);

        let legacy_blobs = scan_partition(&context, &legacy_partition).await;
        let new_blobs = scan_partition(&context, &blobs_partition).await;
        assert!(!legacy_blobs.is_empty());
        assert!(new_blobs.is_empty());
    });
}

#[test_traced]
fn test_fixed_journal_init_defaults_to_blobs_partition() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(2));
        let legacy_partition = cfg.partition.clone();
        let blobs_partition = blob_partition(&cfg);

        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .expect("failed to initialize journal");
        journal.append(&test_digest(1)).await.unwrap();
        journal.sync().await.unwrap();
        drop(journal);

        let legacy_blobs = scan_partition(&context, &legacy_partition).await;
        let new_blobs = scan_partition(&context, &blobs_partition).await;
        assert!(legacy_blobs.is_empty());
        assert!(!new_blobs.is_empty());
    });
}

#[test_traced]
fn test_fixed_journal_append_and_prune() {
    // Initialize the deterministic context
    let executor = deterministic::Runner::default();

    // Start the test within the executor
    executor.start(|context| async move {
        // Initialize the journal, allowing a max of 2 items per blob.
        let cfg = test_cfg(&context, NZU64!(2));
        let mut journal = Journal::init(context.child("first"), cfg.clone())
            .await
            .expect("failed to initialize journal");

        // Append an item to the journal
        let mut pos = journal
            .append(&test_digest(0))
            .await
            .expect("failed to append data 0");
        assert_eq!(pos, 0);

        // Drop the journal and re-initialize it to simulate a restart
        journal.sync().await.expect("Failed to sync journal");
        drop(journal);

        let cfg = test_cfg(&context, NZU64!(2));
        let mut journal = Journal::init(context.child("second"), cfg.clone())
            .await
            .expect("failed to re-initialize journal");
        assert_eq!(journal.size(), 1);

        // Append two more items to the journal to trigger a new blob creation
        pos = journal
            .append(&test_digest(1))
            .await
            .expect("failed to append data 1");
        assert_eq!(pos, 1);
        pos = journal
            .append(&test_digest(2))
            .await
            .expect("failed to append data 2");
        assert_eq!(pos, 2);

        // Read the items back
        let item0 = journal.read(0).await.expect("failed to read data 0");
        assert_eq!(item0, test_digest(0));
        let item1 = journal.read(1).await.expect("failed to read data 1");
        assert_eq!(item1, test_digest(1));
        let item2 = journal.read(2).await.expect("failed to read data 2");
        assert_eq!(item2, test_digest(2));
        let err = journal.read(3).await.expect_err("expected read to fail");
        assert!(matches!(err, Error::ItemOutOfRange(3)));

        // Sync the journal
        journal.sync().await.expect("failed to sync journal");

        // Pruning to 1 should be a no-op because there's no blob with only older items.
        journal.prune(1).await.expect("failed to prune journal 1");

        // Pruning to 2 should allow the first blob to be pruned.
        journal.prune(2).await.expect("failed to prune journal 2");
        assert_eq!(journal.bounds().start, 2);

        // Reading from the first blob should fail since it's now pruned
        let result0 = journal.read(0).await;
        assert!(matches!(result0, Err(Error::ItemPruned(0))));
        let result1 = journal.read(1).await;
        assert!(matches!(result1, Err(Error::ItemPruned(1))));

        // Third item should still be readable
        let result2 = journal.read(2).await.unwrap();
        assert_eq!(result2, test_digest(2));

        // Should be able to continue to append items
        for i in 3..10 {
            let pos = journal
                .append(&test_digest(i))
                .await
                .expect("failed to append data");
            assert_eq!(pos, i);
        }

        // Check no-op pruning
        journal.prune(0).await.expect("no-op pruning failed");
        assert_eq!(journal.test_oldest_blob(), Some(1));
        assert_eq!(journal.test_newest_blob(), Some(5));
        assert_eq!(journal.bounds().start, 2);

        // Prune first 3 blobs (6 items)
        journal
            .prune(3 * cfg.items_per_blob.get())
            .await
            .expect("failed to prune journal 2");
        assert_eq!(journal.test_oldest_blob(), Some(3));
        assert_eq!(journal.test_newest_blob(), Some(5));
        assert_eq!(journal.bounds().start, 6);

        // Try pruning (more than) everything in the journal.
        journal
            .prune(10000)
            .await
            .expect("failed to max-prune journal");
        let size = journal.size();
        assert_eq!(size, 10);
        assert_eq!(journal.test_oldest_blob(), Some(5));
        assert_eq!(journal.test_newest_blob(), Some(5));
        // Since the size of the journal is currently a multiple of items_per_blob, the newest blob
        // will be empty, and there will be no retained items.
        let bounds = journal.bounds();
        assert!(bounds.is_empty());
        // bounds.start should equal bounds.end when empty.
        assert_eq!(bounds.start, size);

        // Replaying from 0 should fail since all items before bounds.start are pruned
        {
            let reader = journal.reader();
            let result = reader.replay(NZUsize!(1024), 0).await;
            assert!(matches!(result, Err(Error::ItemPruned(0))));
        }

        // Replaying from pruning_boundary should return empty stream
        {
            let reader = journal.reader();
            let res = reader.replay(NZUsize!(1024), 0).await;
            assert!(matches!(res, Err(Error::ItemPruned(_))));

            let reader = journal.reader();
            let stream = reader
                .replay(NZUsize!(1024), journal.bounds().start)
                .await
                .expect("failed to replay journal from pruning boundary");
            pin_mut!(stream);
            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                match result {
                    Ok((pos, item)) => {
                        assert_eq!(test_digest(pos), item);
                        items.push(pos);
                    }
                    Err(err) => panic!("Failed to read item: {err}"),
                }
            }
            assert_eq!(items, Vec::<u64>::new());
        }

        journal.destroy().await.unwrap();
    });
}

/// Append a lot of data to make sure we exercise page cache paging boundaries.
#[test_traced]
fn test_fixed_journal_append_a_lot_of_data() {
    // Initialize the deterministic context
    let executor = deterministic::Runner::default();
    const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(10000);
    executor.start(|context| async move {
        let cfg = test_cfg(&context, ITEMS_PER_BLOB);
        let mut journal = Journal::init(context.child("first"), cfg.clone())
            .await
            .expect("failed to initialize journal");
        // Append 2 blobs worth of items.
        for i in 0u64..ITEMS_PER_BLOB.get() * 2 - 1 {
            journal
                .append(&test_digest(i))
                .await
                .expect("failed to append data");
        }
        // Sync, reopen, then read back.
        journal.sync().await.expect("failed to sync journal");
        drop(journal);
        let journal = Journal::init(context.child("second"), cfg.clone())
            .await
            .expect("failed to re-initialize journal");
        for i in 0u64..10000 {
            let item: Digest = journal.read(i).await.expect("failed to read data");
            assert_eq!(item, test_digest(i));
        }
        journal.destroy().await.expect("failed to destroy journal");
    });
}

#[test_traced]
fn test_fixed_journal_replay() {
    const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(7);
    // Initialize the deterministic context
    let executor = deterministic::Runner::default();

    // Start the test within the executor
    executor.start(|context| async move {
        // Initialize the journal, allowing a max of 7 items per blob.
        let cfg = test_cfg(&context, ITEMS_PER_BLOB);
        let mut journal = Journal::init(context.child("first"), cfg.clone())
            .await
            .expect("failed to initialize journal");

        // Append many items, filling 100 blobs and part of the 101st
        for i in 0u64..(ITEMS_PER_BLOB.get() * 100 + ITEMS_PER_BLOB.get() / 2) {
            let pos = journal
                .append(&test_digest(i))
                .await
                .expect("failed to append data");
            assert_eq!(pos, i);
        }

        // Read them back the usual way.
        for i in 0u64..(ITEMS_PER_BLOB.get() * 100 + ITEMS_PER_BLOB.get() / 2) {
            let item: Digest = journal.read(i).await.expect("failed to read data");
            assert_eq!(item, test_digest(i), "i={i}");
        }

        // Replay should return all items
        {
            let reader = journal.reader();
            let stream = reader
                .replay(NZUsize!(1024), 0)
                .await
                .expect("failed to replay journal");
            let mut items = Vec::new();
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                match result {
                    Ok((pos, item)) => {
                        assert_eq!(test_digest(pos), item, "pos={pos}, item={item:?}");
                        items.push(pos);
                    }
                    Err(err) => panic!("Failed to read item: {err}"),
                }
            }

            // Make sure all items were replayed
            assert_eq!(
                items.len(),
                ITEMS_PER_BLOB.get() as usize * 100 + ITEMS_PER_BLOB.get() as usize / 2
            );
            items.sort();
            for (i, pos) in items.iter().enumerate() {
                assert_eq!(i as u64, *pos);
            }
        }

        journal.sync().await.expect("Failed to sync journal");
        drop(journal);

        // Corrupt one of the bytes and make sure it's detected.
        let (blob, _) = context
            .open(&blob_partition(&cfg), &40u64.to_be_bytes())
            .await
            .expect("Failed to open blob");
        // Write junk bytes.
        let bad_bytes = 123456789u32;
        blob.write_at_sync(1, bad_bytes.to_be_bytes().to_vec())
            .await
            .expect("Failed to write bad bytes");

        // Re-initialize the journal to simulate a restart
        let journal = Journal::init(context.child("second"), cfg.clone())
            .await
            .expect("Failed to re-initialize journal");

        // Make sure reading an item that resides in the corrupted page fails.
        let err = journal
            .read(40 * ITEMS_PER_BLOB.get() + 1)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Runtime(_)));

        // Replay all items.
        {
            let mut error_found = false;
            let reader = journal.reader();
            let stream = reader
                .replay(NZUsize!(1024), 0)
                .await
                .expect("failed to replay journal");
            let mut items = Vec::new();
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                match result {
                    Ok((pos, item)) => {
                        assert_eq!(test_digest(pos), item);
                        items.push(pos);
                    }
                    Err(err) => {
                        error_found = true;
                        assert!(matches!(err, Error::Runtime(_)));
                        break;
                    }
                }
            }
            assert!(error_found); // error should abort replay
        }
    });
}

#[test_traced]
fn test_fixed_journal_replay_with_missing_historical_blob() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(2));
        let mut journal = Journal::init(context.child("first"), cfg.clone())
            .await
            .unwrap();
        for i in 0u64..5 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.sync().await.unwrap();
        drop(journal);

        // Delete a middle blob (external corruption). The watermark (5) now exceeds the
        // recoverable contiguous prefix, which is corruption.
        context
            .remove(&blob_partition(&cfg), Some(&1u64.to_be_bytes()))
            .await
            .unwrap();

        let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
        assert!(matches!(result, Err(Error::Corruption(_))));
    });
}

#[test_traced]
fn test_fixed_journal_partial_replay() {
    const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(7);
    // 53 % 7 = 4, which will trigger a non-trivial seek in the starting blob to reach the
    // starting position.
    const START_POS: u64 = 53;

    // Initialize the deterministic context
    let executor = deterministic::Runner::default();
    // Start the test within the executor
    executor.start(|context| async move {
        // Initialize the journal, allowing a max of 7 items per blob.
        let cfg = test_cfg(&context, ITEMS_PER_BLOB);
        let mut journal = Journal::init(context.child("storage"), cfg.clone())
            .await
            .expect("failed to initialize journal");

        // Append many items, filling 100 blobs and part of the 101st
        for i in 0u64..(ITEMS_PER_BLOB.get() * 100 + ITEMS_PER_BLOB.get() / 2) {
            let pos = journal
                .append(&test_digest(i))
                .await
                .expect("failed to append data");
            assert_eq!(pos, i);
        }

        // Replay should return all items except the first `START_POS`.
        {
            let reader = journal.reader();
            let stream = reader
                .replay(NZUsize!(1024), START_POS)
                .await
                .expect("failed to replay journal");
            let mut items = Vec::new();
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                match result {
                    Ok((pos, item)) => {
                        assert!(pos >= START_POS, "pos={pos}, expected >= {START_POS}");
                        assert_eq!(
                            test_digest(pos),
                            item,
                            "Item at position {pos} did not match expected digest"
                        );
                        items.push(pos);
                    }
                    Err(err) => panic!("Failed to read item: {err}"),
                }
            }

            // Make sure all items were replayed
            assert_eq!(
                items.len(),
                ITEMS_PER_BLOB.get() as usize * 100 + ITEMS_PER_BLOB.get() as usize / 2
                    - START_POS as usize
            );
            items.sort();
            for (i, pos) in items.iter().enumerate() {
                assert_eq!(i as u64, *pos - START_POS);
            }
        }

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_rejects_corrupted_tail_blob() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(3));
        let mut journal = Journal::init(context.child("first"), cfg.clone())
            .await
            .unwrap();
        for i in 0..5 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.sync().await.unwrap();
        drop(journal);

        // Truncate the tail blob by 1 byte (external corruption). The watermark (5) now
        // exceeds the recoverable size, which is corruption.
        let (blob, size) = context
            .open(&blob_partition(&cfg), &1u64.to_be_bytes())
            .await
            .unwrap();
        blob.resize(size - 1).await.unwrap();
        blob.sync().await.unwrap();

        let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
        assert!(matches!(result, Err(Error::Corruption(_))));
    });
}

/// Simulate a crash after recovery persists metadata but before the rewind repair completes.
/// The stale blobs beyond the repair point still exist. The next init must succeed: it
/// re-derives the same size from blob lengths, and the persisted watermark is still within
/// the recovered size.
#[test_traced]
fn test_fixed_journal_crash_during_recovery_repair() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .unwrap();

        // Fill 3 blobs (0..15), sync everything.
        for i in 0..15u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.sync().await.unwrap();
        assert_eq!(journal.recovery_watermark(), 15);

        // Persist the recovered metadata (watermark=9) as init_with_metadata does before
        // applying the rewind repair. This simulates a crash after metadata sync but before
        // the repair removes stale blobs.
        {
            Journal::<_, Digest>::stage_metadata_entries(
                &mut journal.metadata,
                cfg.items_per_blob.get(),
                0,
                9,
            );
            journal.metadata.sync().await.unwrap();
        }
        drop(journal);

        // Shorten blob 1 to simulate a short non-tail blob. Recovery will compute
        // size=9 (blob 0 full + 4 items in blob 1) and generate a repair.
        {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
            let (blob, blob_size) = context
                .open(&blob_partition(&cfg), &1u64.to_be_bytes())
                .await
                .expect("failed to open blob 1");
            let append = AppendWriter::new(blob, blob_size, 2048, cache_ref)
                .await
                .expect("failed to wrap blob 1");
            append
                .resize(4 * Digest::SIZE as u64)
                .await
                .expect("failed to shorten blob 1");
            append
                .sync()
                .await
                .expect("failed to sync shortened blob 1");
        }

        // Blobs 2 (and the empty tail at 3) still exist. Init must succeed and the
        // rewind must remove the stale blobs.
        let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .expect("init should succeed after crash during recovery repair");
        assert_eq!(journal.bounds(), 0..9);
        assert_eq!(journal.recovery_watermark(), 9);
        assert_eq!(journal.read(8).await.unwrap(), test_digest(8));
        assert!(matches!(
            journal.read(9).await,
            Err(Error::ItemOutOfRange(9))
        ));
        assert_eq!(
            journal.test_newest_blob(),
            Some(1),
            "stale blobs beyond the repair point should be removed"
        );

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_recover_accepts_clean_short_tail() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));

        // Set up via the public API: 5 items in blob 0 (full) + 2 items in blob 1
        // (partial), then sync and drop.
        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .unwrap();
        for i in 0..7 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.sync().await.unwrap();
        drop(journal);

        // Reopen and verify the size is exactly 7 with no repair (a clean short tail).
        let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .unwrap();
        assert_eq!(journal.size(), 7);
        // Blobs 0 and 1 exist and we can read every position.
        for i in 0..7u64 {
            assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
        }
        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_recover_accepts_clean_empty_tail() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));

        // Set up via the public API: 5 items in blob 0 (full); rolling over implicitly
        // creates an empty blob 1 as the tail. Sync and drop.
        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .unwrap();
        for i in 0..5 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.sync().await.unwrap();
        drop(journal);

        // Reopen: blob 0 is full, blob 1 is the empty tail. Size = 5, no repair.
        let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .unwrap();
        assert_eq!(journal.size(), 5);
        for i in 0..5u64 {
            assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
        }
        assert_eq!(journal.test_newest_blob(), Some(1));
        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_recover_sparse_blob_ids_repairs_at_gap() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(1));
        let blob_partition = blob_partition(&cfg);

        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .unwrap();
        journal.append(&test_digest(0)).await.unwrap();
        journal.sync().await.unwrap();
        drop(journal);

        // Add a far-future blob directly. Recovery should inspect actual blob ids and
        // repair at the first missing boundary instead of walking the entire numeric range.
        let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let (blob, blob_size) = context
            .open(&blob_partition, &u64::MAX.to_be_bytes())
            .await
            .unwrap();
        let append = AppendWriter::new(blob, blob_size, 2048, cache_ref)
            .await
            .unwrap();
        let extra = test_digest(999);
        append.append(extra.as_ref()).await.unwrap();
        append.sync().await.unwrap();
        drop(append);

        let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .unwrap();
        assert_eq!(journal.bounds(), 0..1);
        assert_eq!(journal.read(0).await.unwrap(), test_digest(0));
        assert!(matches!(
            journal.read(1).await,
            Err(Error::ItemOutOfRange(1))
        ));
        assert_eq!(journal.test_newest_blob(), Some(1));

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_recover_fallback_truncates_after_short_oldest_blob() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                .await
                .expect("failed to initialize journal at size");

        for i in 0..8u64 {
            journal
                .append(&test_digest(100 + i))
                .await
                .expect("failed to append data");
        }
        journal.sync().await.expect("failed to sync journal");
        assert_eq!(journal.bounds(), 7..15);

        {
            journal.metadata.put(RECOVERY_WATERMARK_KEY, 6u64.into());
            journal
                .metadata
                .sync()
                .await
                .expect("failed to sync lower recovery watermark");
        }
        drop(journal);

        let (blob, size) = context
            .open(&blob_partition(&cfg), &1u64.to_be_bytes())
            .await
            .expect("failed to open oldest blob");
        blob.resize(size - 1).await.expect("failed to corrupt blob");
        blob.sync().await.expect("failed to sync blob");

        let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .expect("failed to recover journal");
        assert_eq!(journal.bounds(), 7..9);
        assert_eq!(journal.read(7).await.unwrap(), test_digest(100));
        assert_eq!(journal.read(8).await.unwrap(), test_digest(101));
        assert!(matches!(
            journal.read(9).await,
            Err(Error::ItemOutOfRange(9))
        ));
        assert_eq!(journal.test_oldest_blob(), Some(1));
        assert_eq!(journal.test_newest_blob(), Some(1));

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_stale_pruning_metadata_preserves_watermark() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                .await
                .expect("failed to initialize journal at size");

        for i in 0..10u64 {
            journal
                .append(&test_digest(i))
                .await
                .expect("failed to append data");
        }
        journal.sync().await.expect("failed to sync journal");
        assert_eq!(journal.bounds(), 7..17);

        // Stage the stale forward-looking watermark while the journal is alive (so we go
        // through the public metadata path), then drop and corrupt the underlying blob.
        {
            journal.metadata.put(RECOVERY_WATERMARK_KEY, 12u64.into());
            journal
                .metadata
                .sync()
                .await
                .expect("failed to sync recovery watermark");
        }
        drop(journal);

        // Shorten blob 2 to two items via Append::resize so the on-disk logical view
        // matches the staged watermark of 12.
        {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
            let (blob, blob_size) = context
                .open(&blob_partition(&cfg), &2u64.to_be_bytes())
                .await
                .expect("failed to open blob 2");
            let append = AppendWriter::new(blob, blob_size, 2048, cache_ref)
                .await
                .expect("failed to wrap blob 2");
            append
                .resize(2 * Digest::SIZE as u64)
                .await
                .expect("failed to shorten anchored blob");
            append.sync().await.expect("failed to sync blob 2");
        }

        // Remove the metadata's oldest blob so PRUNING_BOUNDARY_KEY=7 is stale. The
        // watermark is preserved because length-based recovery ends at the same point.
        context
            .remove(&blob_partition(&cfg), Some(&1u64.to_be_bytes()))
            .await
            .expect("failed to remove stale oldest blob");

        let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .expect("failed to recover journal");
        assert_eq!(journal.bounds(), 10..12);
        assert_eq!(journal.recovery_watermark(), 12);
        assert_eq!(journal.read(10).await.unwrap(), test_digest(3));
        assert_eq!(journal.read(11).await.unwrap(), test_digest(4));
        assert!(matches!(
            journal.read(12).await,
            Err(Error::ItemOutOfRange(12))
        ));

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_stale_pruning_metadata_without_watermark_walks_lengths() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                .await
                .expect("failed to initialize journal at size");

        for i in 0..10u64 {
            journal
                .append(&test_digest(i))
                .await
                .expect("failed to append data");
        }
        journal.sync().await.expect("failed to sync journal");
        assert_eq!(journal.bounds(), 7..17);

        {
            journal.metadata.remove(&RECOVERY_WATERMARK_KEY);
            journal
                .metadata
                .sync()
                .await
                .expect("failed to remove recovery watermark");
        }
        drop(journal);

        // Remove the metadata's oldest blob so PRUNING_BOUNDARY_KEY=7 is stale. Without a
        // recovery watermark, recovery must still walk lengths from the recovered blob boundary.
        context
            .remove(&blob_partition(&cfg), Some(&1u64.to_be_bytes()))
            .await
            .expect("failed to remove stale oldest blob");

        let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .expect("failed to recover journal");
        assert_eq!(journal.bounds(), 10..17);
        // No watermark: watermark at the tail blob start, not size.
        assert_eq!(journal.recovery_watermark(), 15);
        assert_eq!(journal.read(10).await.unwrap(), test_digest(3));
        assert_eq!(journal.read(16).await.unwrap(), test_digest(9));

        // After sync, watermark advances to the full recovered size.
        journal.sync().await.expect("failed to sync");
        assert_eq!(journal.recovery_watermark(), 17);

        journal.destroy().await.unwrap();
    });
}

/// Pruning metadata ahead of the oldest blob is not a reachable crash state: prune removes
/// blobs before sync persists metadata, and clear_to_size uses CLEAR_TARGET_KEY for atomicity.
/// Verify it is rejected as corruption.
#[test_traced]
fn test_fixed_journal_pruning_metadata_ahead_of_blobs_is_corruption() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 3)
                .await
                .unwrap();

        // Append 12 items (positions 3..15) spanning blobs 0, 1, 2.
        for i in 0..12u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.sync().await.unwrap();
        assert_eq!(journal.bounds(), 3..15);

        // Set PRUNING_BOUNDARY_KEY to 8 (blob 1) and lower the watermark so it won't
        // independently trigger the watermark > size corruption check. Then remove blob 1's
        // blob so blob 0 is the oldest. The pruning metadata now references a blob ahead
        // of the oldest blob, which is the corruption we're testing.
        {
            journal.metadata.put(PRUNING_BOUNDARY_KEY, 8u64.into());
            journal.metadata.put(RECOVERY_WATERMARK_KEY, 3u64.into());
            journal.metadata.sync().await.unwrap();
        }
        drop(journal);

        context
            .remove(&blob_partition(&cfg), Some(&1u64.to_be_bytes()))
            .await
            .unwrap();

        let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
        assert!(matches!(result, Err(Error::Corruption(_))));
    });
}

/// Mid-blob pruning metadata with no blobs is not a reachable crash state (see comment in
/// `recover_bounds`). Verify it is rejected as corruption rather than silently recovering empty.
#[test_traced]
fn test_fixed_journal_pruning_metadata_with_no_blobs_is_corruption() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                .await
                .unwrap();

        for i in 0..3u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.sync().await.unwrap();
        drop(journal);

        // Remove all blobs but leave metadata (with PRUNING_BOUNDARY_KEY=7) intact.
        for name in scan_partition(&context, &blob_partition(&cfg)).await {
            context
                .remove(&blob_partition(&cfg), Some(&name))
                .await
                .unwrap();
        }

        let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
        assert!(matches!(result, Err(Error::Corruption(_))));
    });
}

#[test_traced]
fn test_fixed_journal_legacy_recovery_installs_watermark() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .expect("failed to initialize journal");

        for i in 0..12u64 {
            journal
                .append(&test_digest(i))
                .await
                .expect("failed to append data");
        }
        journal.sync().await.expect("failed to sync journal");

        {
            journal.metadata.remove(&RECOVERY_WATERMARK_KEY);
            journal
                .metadata
                .sync()
                .await
                .expect("failed to remove recovery watermark");
        }
        drop(journal);

        // Legacy recovery sets watermark to the tail blob start, not size, so the tail
        // is marked dirty and fsynced before the watermark advances.
        let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .expect("failed to recover legacy journal");
        assert_eq!(journal.bounds(), 0..12);
        assert_eq!(journal.recovery_watermark(), 10);

        // After sync, the watermark advances to the full size.
        journal
            .sync()
            .await
            .expect("failed to sync after legacy recovery");
        assert_eq!(journal.recovery_watermark(), 12);

        journal.destroy().await.unwrap();
    });
}

/// Regression: legacy upgrade (no RECOVERY_WATERMARK_KEY) must mark all recovered blobs
/// dirty so they are fsynced before the watermark advances. Without this, init could install
/// a durable watermark for data that was only in the OS page cache.
#[test_traced]
fn test_fixed_journal_legacy_upgrade_marks_recovered_blobs_dirty() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .unwrap();

        for i in 0..7u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.sync().await.unwrap();

        // Remove the watermark to simulate a legacy journal.
        {
            journal.metadata.remove(&RECOVERY_WATERMARK_KEY);
            journal.metadata.sync().await.unwrap();
        }
        drop(journal);

        let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .unwrap();
        assert_eq!(journal.size(), 7);
        // Watermark at tail blob start (blob 1 = position 5).
        assert_eq!(journal.recovery_watermark(), 5);

        // Inject sync faults. If recovered blobs were not marked dirty, commit would
        // skip the data sync and succeed despite the fault.
        *context.storage_fault_config().write() = deterministic::FaultConfig {
            sync_rate: Some(1.0),
            ..Default::default()
        };
        assert!(
            journal.commit().await.is_err(),
            "commit must sync recovered data before the watermark can advance"
        );
    });
}

#[test_traced]
fn test_fixed_journal_update_metadata_watermark_before_clear_lowers_only() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let meta_cfg = MetadataConfig {
            partition: format!("{}-metadata", cfg.partition),
            codec_config: (),
        };
        let mut metadata =
            Metadata::<_, u64, VecU64>::init(context.child("metadata"), meta_cfg)
                .await
                .expect("failed to initialize metadata");
        metadata.put(RECOVERY_WATERMARK_KEY, 7u64.into());

        let changed =
            Journal::<_, Digest>::update_metadata_watermark_before_clear(&mut metadata, 9);
        assert!(!changed);
        let persisted_watermark = metadata
            .get(&RECOVERY_WATERMARK_KEY)
            .copied()
            .map(u64::from)
            .expect("missing recovery watermark");
        assert_eq!(persisted_watermark, 7);

        let changed =
            Journal::<_, Digest>::update_metadata_watermark_before_clear(&mut metadata, 5);
        assert!(changed);
        let persisted_watermark = metadata
            .get(&RECOVERY_WATERMARK_KEY)
            .copied()
            .map(u64::from)
            .expect("missing recovery watermark");
        assert_eq!(persisted_watermark, 5);
    });
}

#[test_traced]
fn test_fixed_journal_commit_does_not_advance_recovery_watermark() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal = Journal::<_, Digest>::init(context.child("journal"), cfg.clone())
            .await
            .unwrap();

        journal.append(&test_digest(0)).await.unwrap();
        journal.sync().await.unwrap();
        assert_eq!(journal.recovery_watermark(), 1);

        journal.append(&test_digest(1)).await.unwrap();
        journal.commit().await.unwrap();
        assert_eq!(
            journal.recovery_watermark(),
            1,
            "commit must make dirty blobs durable without advancing the recovery watermark",
        );

        journal.sync().await.unwrap();
        assert_eq!(journal.recovery_watermark(), 2);
        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_prune_to_blob_boundary_removes_pruning_metadata() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                .await
                .expect("failed to initialize journal at size");

        for i in 0..8u64 {
            journal
                .append(&test_digest(i))
                .await
                .expect("failed to append data");
        }
        journal.sync().await.expect("failed to sync journal");
        assert_eq!(journal.bounds(), 7..15);

        journal.prune(10).await.expect("failed to prune journal");
        journal.sync().await.expect("failed to sync pruned journal");
        assert_eq!(journal.bounds(), 10..15);
        drop(journal);

        let meta_cfg = MetadataConfig {
            partition: format!("{}-metadata", cfg.partition),
            codec_config: (),
        };
        let metadata = Metadata::<_, u64, VecU64>::init(context.child("metadata"), meta_cfg)
            .await
            .expect("failed to reopen metadata");
        assert!(metadata.get(&PRUNING_BOUNDARY_KEY).is_none());
        drop(metadata);

        let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .expect("failed to reopen journal");
        assert_eq!(journal.bounds(), 10..15);
        assert_eq!(journal.read(10).await.unwrap(), test_digest(3));
        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_recover_rejects_overlong_blob() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .expect("failed to initialize journal");

        for i in 0..5u64 {
            journal
                .append(&test_digest(i))
                .await
                .expect("failed to append data");
        }
        journal.sync().await.expect("failed to sync journal");
        drop(journal);

        // Inject an extra item into blob 0 at the blob level so its length exceeds
        // items_per_blob -- this is what `recover_bounds` validates and rejects as Corruption.
        {
            let extra = test_digest(99);
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
            let (blob, blob_size) = context
                .open(&blob_partition(&cfg), &0u64.to_be_bytes())
                .await
                .expect("failed to open blob 0");
            let append = AppendWriter::new(blob, blob_size, 2048, cache_ref)
                .await
                .expect("failed to wrap blob 0");
            append
                .append(extra.as_ref())
                .await
                .expect("failed to append extra item");
            append.sync().await.expect("failed to sync corrupted blob");
        }

        let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
        assert!(matches!(result, Err(Error::Corruption(_))));
    });
}

#[test_traced("DEBUG")]
fn test_fixed_journal_recover_from_unwritten_data() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        // Initialize the journal, allowing a max of 10 items per blob.
        let cfg = test_cfg(&context, NZU64!(10));
        let mut journal = Journal::init(context.child("first"), cfg.clone())
            .await
            .expect("failed to initialize journal");

        // Add only a single item
        journal
            .append(&test_digest(0))
            .await
            .expect("failed to append data");
        assert_eq!(journal.size(), 1);
        journal.sync().await.expect("Failed to sync journal");
        drop(journal);

        // Manually extend the blob to simulate a failure where the file was extended, but no
        // bytes were written due to failure.
        let (blob, size) = context
            .open(&blob_partition(&cfg), &0u64.to_be_bytes())
            .await
            .expect("Failed to open blob");
        blob.write_at_sync(size, vec![0u8; PAGE_SIZE.get() as usize * 3])
            .await
            .expect("Failed to extend blob");

        // Re-initialize the journal to simulate a restart
        let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .expect("Failed to re-initialize journal");

        // The zero-filled pages are detected as invalid (bad checksum) and truncated.
        // No items should be lost since we called sync before the corruption.
        assert_eq!(journal.size(), 1);

        // Make sure journal still works for appending.
        journal
            .append(&test_digest(1))
            .await
            .expect("failed to append data");

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_rewinding() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        // Initialize the journal, allowing a max of 2 items per blob.
        let cfg = test_cfg(&context, NZU64!(2));
        let mut journal = Journal::init(context.child("first"), cfg.clone())
            .await
            .expect("failed to initialize journal");
        assert!(matches!(journal.rewind(0).await, Ok(())));
        assert!(matches!(
            journal.rewind(1).await,
            Err(Error::InvalidRewind(1))
        ));

        // Append an item to the journal
        journal
            .append(&test_digest(0))
            .await
            .expect("failed to append data 0");
        assert_eq!(journal.size(), 1);
        assert!(matches!(journal.rewind(1).await, Ok(()))); // should be no-op
        assert!(matches!(journal.rewind(0).await, Ok(())));
        assert_eq!(journal.size(), 0);

        // append 7 items
        for i in 0..7 {
            let pos = journal
                .append(&test_digest(i))
                .await
                .expect("failed to append data");
            assert_eq!(pos, i);
        }
        assert_eq!(journal.size(), 7);

        // rewind back to item #4, which should prune 2 blobs
        assert!(matches!(journal.rewind(4).await, Ok(())));
        assert_eq!(journal.size(), 4);

        // rewind back to empty and ensure all blobs are rewound over
        assert!(matches!(journal.rewind(0).await, Ok(())));
        assert_eq!(journal.size(), 0);

        // stress test: add 100 items, rewind 49, repeat x10.
        for _ in 0..10 {
            for i in 0..100 {
                journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            journal.rewind(journal.size() - 49).await.unwrap();
        }
        const ITEMS_REMAINING: u64 = 10 * (100 - 49);
        assert_eq!(journal.size(), ITEMS_REMAINING);

        journal.sync().await.expect("Failed to sync journal");
        drop(journal);

        // Repeat with a different blob size (3 items per blob)
        let mut cfg = test_cfg(&context, NZU64!(3));
        cfg.partition = "test-partition-2".into();
        let mut journal = Journal::init(context.child("second"), cfg.clone())
            .await
            .expect("failed to initialize journal");
        for _ in 0..10 {
            for i in 0..100 {
                journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            journal.rewind(journal.size() - 49).await.unwrap();
        }
        assert_eq!(journal.size(), ITEMS_REMAINING);

        journal.sync().await.expect("Failed to sync journal");
        drop(journal);

        // Make sure re-opened journal is as expected
        let mut journal: Journal<_, Digest> =
            Journal::init(context.child("third"), cfg.clone())
                .await
                .expect("failed to re-initialize journal");
        assert_eq!(journal.size(), 10 * (100 - 49));

        // Make sure rewinding works after pruning
        journal.prune(300).await.expect("pruning failed");
        assert_eq!(journal.size(), ITEMS_REMAINING);
        // Rewinding prior to our prune point should fail.
        assert!(matches!(
            journal.rewind(299).await,
            Err(Error::InvalidRewind(299))
        ));
        // Rewinding to the prune point should work.
        // always remain in the journal.
        assert!(matches!(journal.rewind(300).await, Ok(())));
        let bounds = journal.bounds();
        assert_eq!(bounds.end, 300);
        assert!(bounds.is_empty());

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_rewind_commit_reopen() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .expect("failed to initialize journal");

        for i in 0..12u64 {
            journal
                .append(&test_digest(i))
                .await
                .expect("failed to append data");
        }
        journal.sync().await.expect("failed to sync journal");

        journal.rewind(7).await.expect("failed to rewind journal");
        journal.commit().await.expect("failed to commit journal");
        drop(journal);

        let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .expect("failed to re-initialize journal");
        assert_eq!(journal.bounds(), 0..7);
        for i in 0..7u64 {
            assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
        }
        assert!(matches!(
            journal.read(7).await,
            Err(Error::ItemOutOfRange(7))
        ));

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_rewind_persists_lower_watermark() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .expect("failed to initialize journal");

        for i in 0..12u64 {
            journal
                .append(&test_digest(i))
                .await
                .expect("failed to append data");
        }
        journal.sync().await.expect("failed to sync journal");
        journal.rewind(7).await.expect("failed to rewind journal");
        drop(journal);

        let meta_cfg = MetadataConfig {
            partition: format!("{}-metadata", cfg.partition),
            codec_config: (),
        };
        let metadata = Metadata::<_, u64, VecU64>::init(context.child("metadata"), meta_cfg)
            .await
            .expect("failed to reopen metadata");
        let persisted_watermark = metadata
            .get(&RECOVERY_WATERMARK_KEY)
            .copied()
            .map(u64::from)
            .expect("missing recovery watermark after rewind");
        assert_eq!(persisted_watermark, 7);
        drop(metadata);

        let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .expect("failed to re-initialize journal");
        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_recover_after_watermark_lowered_before_rewind() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .expect("failed to initialize journal");

        for i in 0..12u64 {
            journal
                .append(&test_digest(i))
                .await
                .expect("failed to append data");
        }
        journal.sync().await.expect("failed to sync journal");

        {
            journal.metadata.put(RECOVERY_WATERMARK_KEY, 7u64.into());
            journal
                .metadata
                .sync()
                .await
                .expect("failed to lower recovery watermark");
        }
        drop(journal);

        let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .expect("failed to recover journal");
        assert_eq!(journal.bounds(), 0..12);
        assert_eq!(journal.recovery_watermark(), 7);
        assert_eq!(journal.read(11).await.unwrap(), test_digest(11));
        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_rewind_append_commit_reopen() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .expect("failed to initialize journal");

        for i in 0..12u64 {
            journal
                .append(&test_digest(i))
                .await
                .expect("failed to append data");
        }
        journal.sync().await.expect("failed to sync journal");

        journal.rewind(7).await.expect("failed to rewind journal");
        for i in 0..3u64 {
            journal
                .append(&test_digest(100 + i))
                .await
                .expect("failed to append data");
        }
        journal.commit().await.expect("failed to commit journal");
        drop(journal);

        let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .expect("failed to re-initialize journal");
        assert_eq!(journal.bounds(), 0..10);
        assert_eq!(journal.recovery_watermark(), 7);
        for i in 0..7u64 {
            assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
        }
        for i in 0..3u64 {
            assert_eq!(journal.read(7 + i).await.unwrap(), test_digest(100 + i));
        }
        assert!(matches!(
            journal.read(10).await,
            Err(Error::ItemOutOfRange(10))
        ));

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_recovery_handles_multiple_empty_data_tail_blobs() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(1));
        let mut journal = Journal::<_, Digest>::init(context.child("journal"), cfg.clone())
            .await
            .unwrap();

        // Persist a prefix, then append across multiple blob boundaries without syncing. The
        // unsynced item bytes are lost on drop, but their blobs remain visible.
        assert_eq!(journal.append(&test_digest(10)).await.unwrap(), 0);
        journal.sync().await.unwrap();
        assert_eq!(journal.append(&test_digest(20)).await.unwrap(), 1);
        assert_eq!(journal.append(&test_digest(30)).await.unwrap(), 2);
        drop(journal);

        let blobs = scan_partition(&context, &blob_partition(&cfg)).await;
        assert!(
            blobs.len() > 2,
            "expected multiple empty trailing blobs, got {}",
            blobs.len()
        );

        let journal = Journal::<_, Digest>::init(context.child("recovered"), cfg.clone())
            .await
            .unwrap();
        assert_eq!(journal.bounds(), 0..1);
        assert_eq!(journal.read(0).await.unwrap(), test_digest(10));
        drop(journal);

        // Recovery should remove the empty trailing blobs, leaving only the durable prefix's
        // blob and the recreated tail.
        let blobs = scan_partition(&context, &blob_partition(&cfg)).await;
        assert_eq!(blobs.len(), 2);

        let mut journal = Journal::<_, Digest>::init(context.child("recovered"), cfg.clone())
            .await
            .unwrap();
        assert_eq!(journal.append(&test_digest(42)).await.unwrap(), 1);
        assert_eq!(journal.read(1).await.unwrap(), test_digest(42));
        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_recovery_handles_empty_data_with_no_durable_items() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(1));
        let mut journal = Journal::<_, Digest>::init(context.child("journal"), cfg.clone())
            .await
            .unwrap();

        // Append across multiple blob boundaries without ever syncing. No item bytes become
        // durable, so recovery sees multiple empty blobs and no durable data.
        assert_eq!(journal.append(&test_digest(10)).await.unwrap(), 0);
        assert_eq!(journal.append(&test_digest(20)).await.unwrap(), 1);
        drop(journal);

        let blobs = scan_partition(&context, &blob_partition(&cfg)).await;
        assert!(
            blobs.len() > 1,
            "expected multiple empty blobs, got {}",
            blobs.len()
        );

        let journal = Journal::<_, Digest>::init(context.child("recovered"), cfg.clone())
            .await
            .unwrap();
        assert_eq!(journal.bounds(), 0..0);
        drop(journal);

        // Recovery should remove the extra empty blobs, leaving only the recreated tail.
        let blobs = scan_partition(&context, &blob_partition(&cfg)).await;
        assert_eq!(blobs.len(), 1);

        let mut journal = Journal::<_, Digest>::init(context.child("recovered"), cfg.clone())
            .await
            .unwrap();
        assert_eq!(journal.append(&test_digest(42)).await.unwrap(), 0);
        assert_eq!(journal.read(0).await.unwrap(), test_digest(42));
        journal.destroy().await.unwrap();
    });
}

/// Test that a crash partway through a multi-blob sync leaves a contiguous durable prefix
/// that recovery preserves.
///
/// `flush_dirty_blobs` syncs dirty blobs, and all mutating operations serialize on
/// `op_lock` so no concurrent sync can interleave. This reproduces a crash after blobs 0 and
/// 1 were synced but before blob 2, then asserts recovery keeps exactly the contiguous
/// prefix 0..20.
#[test_traced]
fn test_fixed_recovery_partial_sync_loop_keeps_contiguous_prefix() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(10));
        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .unwrap();

        // Fill blobs 0 and 1 and partially fill blob 2 (positions 20..25). Nothing is
        // synced yet, so only the created blobs are durable, all still empty.
        for i in 0..25u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }

        // Sync blobs 0 and 1 but not blob 2, simulating a crash after part of a
        // multi-blob sync became durable.
        {
            journal.test_sync_blob(0).await.unwrap();
            journal.test_sync_blob(1).await.unwrap();
        }
        drop(journal);

        // The durable data is exactly the contiguous prefix: blobs 0 and 1 hold items and
        // blob 2 is an empty trailing blob.
        let names = scan_partition(&context, &blob_partition(&cfg)).await;
        assert_eq!(names.len(), 3);
        for (blob, name) in names.iter().enumerate() {
            let (_blob, size) = context.open(&blob_partition(&cfg), name).await.unwrap();
            if blob < 2 {
                assert!(size > 0, "blob {blob} should be durable");
            } else {
                assert_eq!(size, 0, "blob {blob} should be empty");
            }
        }

        // Recovery preserves exactly the contiguous prefix 0..20.
        let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .unwrap();
        assert_eq!(journal.bounds(), 0..20);
        for i in 0..20u64 {
            assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
        }
        assert!(matches!(
            journal.read(20).await,
            Err(Error::ItemOutOfRange(20))
        ));

        // Appends resume cleanly from the recovered boundary.
        assert_eq!(journal.append(&test_digest(999)).await.unwrap(), 20);
        assert_eq!(journal.read(20).await.unwrap(), test_digest(999));

        journal.destroy().await.unwrap();
    });
}

/// Test that a durable blob above the sync watermark, sitting beyond an empty intermediate
/// blob, is rolled back to the contiguous boundary during recovery.
///
/// Since #3790 removed the append-time sync when crossing blob boundaries, a process crash can
/// leave a later blob incidentally durable while an earlier blob stayed buffered and was
/// lost, producing a physical gap. Length-based recovery walks blobs from oldest and
/// truncates at the first short non-tail blob, so the post-gap blob is discarded and only
/// the synced prefix survives.
#[test_traced]
fn test_fixed_recovery_rolls_back_durable_blob_after_gap() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(10));
        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .unwrap();

        // Durably commit blob 0 (positions 0..10), advancing the recovery watermark to 10.
        for i in 0..10u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.sync().await.unwrap();

        // Append blob 1 and part of blob 2 without committing. Manually sync only blob
        // 2 to mimic its writes surviving a crash, while blob 1 stays buffered and is lost.
        for i in 10..28u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        {
            journal.test_sync_blob(2).await.unwrap();
        }
        drop(journal);

        // Durable state: blob 0 (10 items), blob 1 (empty gap), blob 2 (8 items).
        let names = scan_partition(&context, &blob_partition(&cfg)).await;
        assert_eq!(names.len(), 3);
        let mut sizes = Vec::new();
        for name in &names {
            let (_blob, size) = context.open(&blob_partition(&cfg), name).await.unwrap();
            sizes.push(size);
        }
        assert!(sizes[0] > 0, "blob 0 should be durable");
        assert_eq!(sizes[1], 0, "blob 1 should be the gap");
        assert!(sizes[2] > 0, "blob 2 should be incidentally durable");

        // Recovery rolls back to the watermark boundary: only the synced prefix survives and the
        // gapped blob 2 is truncated away.
        let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .unwrap();
        assert_eq!(journal.bounds(), 0..10);
        for i in 0..10u64 {
            assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
        }
        assert!(matches!(
            journal.read(10).await,
            Err(Error::ItemOutOfRange(10))
        ));

        // The orphaned blob 2 is gone; the truncated blob 1 remains as the recovered tail.
        let names = scan_partition(&context, &blob_partition(&cfg)).await;
        assert_eq!(names.len(), 2);

        // Appends resume cleanly from the recovered boundary.
        assert_eq!(journal.append(&test_digest(999)).await.unwrap(), 10);
        assert_eq!(journal.read(10).await.unwrap(), test_digest(999));

        journal.destroy().await.unwrap();
    });
}

/// Test recovery when the oldest blob is empty but a newer blob still holds durable items.
///
/// This is the fixed-journal analog of the variable-journal empty-oldest-blob gap bug. A
/// contiguous journal can only populate a later blob after filling the earlier one, so an
/// empty oldest blob with a populated newer blob is an orphaned gap. Length-based recovery
/// walks from the oldest blob, finds it short (empty), and truncates everything from there,
/// aligning the journal to empty without panicking.
#[test_traced]
fn test_fixed_recovery_empty_oldest_blob_orphaned_newer_blob() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(10));

        // Durably persist blobs 0 and 1 (positions 0..20).
        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .unwrap();
        for i in 0..20u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.sync().await.unwrap();
        drop(journal);

        // Empty the oldest blob (external corruption). The watermark (20) now exceeds the
        // recoverable size (0), which is corruption.
        let (blob0, size0) = context
            .open(&blob_partition(&cfg), &0u64.to_be_bytes())
            .await
            .unwrap();
        assert!(size0 > 0);
        blob0.resize(0).await.unwrap();
        blob0.sync().await.unwrap();

        let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
        assert!(matches!(result, Err(Error::Corruption(_))));
    });
}

/// Test the contiguous fixed journal with items_per_blob: 1.
///
/// This is an edge case where each item creates its own blob, and the
/// tail blob is always empty after sync (because the item fills the blob
/// and a new empty one is created).
#[test_traced]
fn test_single_item_per_blob() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = Config {
            partition: "single-item-per-blob".into(),
            items_per_blob: NZU64!(1),
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: NZUsize!(2048),
        };

        // === Test 1: Basic single item operation ===
        let mut journal = Journal::init(context.child("first"), cfg.clone())
            .await
            .expect("failed to initialize journal");

        // Verify empty state
        let bounds = journal.bounds();
        assert_eq!(bounds.end, 0);
        assert!(bounds.is_empty());

        // Append 1 item
        let pos = journal
            .append(&test_digest(0))
            .await
            .expect("failed to append");
        assert_eq!(pos, 0);
        assert_eq!(journal.size(), 1);

        // Sync
        journal.sync().await.expect("failed to sync");

        // Read from size() - 1
        let value = journal
            .read(journal.size() - 1)
            .await
            .expect("failed to read");
        assert_eq!(value, test_digest(0));

        // === Test 2: Multiple items with single item per blob ===
        for i in 1..10u64 {
            let pos = journal
                .append(&test_digest(i))
                .await
                .expect("failed to append");
            assert_eq!(pos, i);
            assert_eq!(journal.size(), i + 1);

            // Verify we can read the just-appended item at size() - 1
            let value = journal
                .read(journal.size() - 1)
                .await
                .expect("failed to read");
            assert_eq!(value, test_digest(i));
        }

        // Verify all items can be read
        for i in 0..10u64 {
            assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
        }

        journal.sync().await.expect("failed to sync");

        // === Test 3: Pruning with single item per blob ===
        // Prune to position 5 (removes positions 0-4)
        journal.prune(5).await.expect("failed to prune");

        // Size should still be 10
        assert_eq!(journal.size(), 10);

        // bounds.start should be 5
        assert_eq!(journal.bounds().start, 5);

        // Reading from size() - 1 (position 9) should still work
        let value = journal
            .read(journal.size() - 1)
            .await
            .expect("failed to read");
        assert_eq!(value, test_digest(9));

        // Reading from pruned positions should return ItemPruned
        for i in 0..5 {
            assert!(matches!(journal.read(i).await, Err(Error::ItemPruned(_))));
        }

        // Reading from retained positions should work
        for i in 5..10u64 {
            assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
        }

        // Append more items after pruning
        for i in 10..15u64 {
            let pos = journal
                .append(&test_digest(i))
                .await
                .expect("failed to append");
            assert_eq!(pos, i);

            // Verify we can read from size() - 1
            let value = journal
                .read(journal.size() - 1)
                .await
                .expect("failed to read");
            assert_eq!(value, test_digest(i));
        }

        journal.sync().await.expect("failed to sync");
        drop(journal);

        // === Test 4: Restart persistence with single item per blob ===
        let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .expect("failed to re-initialize journal");

        // Verify size is preserved
        assert_eq!(journal.size(), 15);

        // Verify bounds.start is preserved
        assert_eq!(journal.bounds().start, 5);

        // Reading from size() - 1 should work after restart
        let value = journal
            .read(journal.size() - 1)
            .await
            .expect("failed to read");
        assert_eq!(value, test_digest(14));

        // Reading all retained positions should work
        for i in 5..15u64 {
            assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
        }

        journal.destroy().await.expect("failed to destroy journal");

        // === Test 5: Restart after pruning with non-zero index ===
        // Fresh journal for this test
        let mut journal = Journal::init(context.child("third"), cfg.clone())
            .await
            .expect("failed to initialize journal");

        // Append 10 items (positions 0-9)
        for i in 0..10u64 {
            journal.append(&test_digest(i + 100)).await.unwrap();
        }

        // Prune to position 5 (removes positions 0-4)
        journal.prune(5).await.unwrap();
        let bounds = journal.bounds();
        assert_eq!(bounds.end, 10);
        assert_eq!(bounds.start, 5);

        // Sync and restart
        journal.sync().await.unwrap();
        drop(journal);

        // Re-open journal
        let journal = Journal::<_, Digest>::init(context.child("fourth"), cfg.clone())
            .await
            .expect("failed to re-initialize journal");

        // Verify state after restart
        let bounds = journal.bounds();
        assert_eq!(bounds.end, 10);
        assert_eq!(bounds.start, 5);

        // Reading from size() - 1 (position 9) should work
        let value = journal.read(journal.size() - 1).await.unwrap();
        assert_eq!(value, test_digest(109));

        // Verify all retained positions (5-9) work
        for i in 5..10u64 {
            assert_eq!(journal.read(i).await.unwrap(), test_digest(i + 100));
        }

        journal.destroy().await.expect("failed to destroy journal");

        // === Test 6: Prune all items (edge case) ===
        let mut journal = Journal::init(context.child("storage"), cfg.clone())
            .await
            .expect("failed to initialize journal");

        for i in 0..5u64 {
            journal.append(&test_digest(i + 200)).await.unwrap();
        }
        journal.sync().await.unwrap();

        // Prune all items
        journal.prune(5).await.unwrap();
        let bounds = journal.bounds();
        assert_eq!(bounds.end, 5); // Size unchanged
        assert!(bounds.is_empty()); // All pruned

        // size() - 1 = 4, but position 4 is pruned
        let result = journal.read(journal.size() - 1).await;
        assert!(matches!(result, Err(Error::ItemPruned(4))));

        // After appending, reading works again
        journal.append(&test_digest(205)).await.unwrap();
        assert_eq!(journal.bounds().start, 5);
        assert_eq!(
            journal.read(journal.size() - 1).await.unwrap(),
            test_digest(205)
        );

        journal.destroy().await.expect("failed to destroy journal");
    });
}

#[test_traced]
fn test_fixed_journal_init_at_size_zero() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 0)
                .await
                .unwrap();

        let bounds = journal.bounds();
        assert_eq!(bounds.end, 0);
        assert!(bounds.is_empty());

        // Next append should get position 0
        let pos = journal.append(&test_digest(100)).await.unwrap();
        assert_eq!(pos, 0);
        assert_eq!(journal.size(), 1);
        assert_eq!(journal.read(0).await.unwrap(), test_digest(100));

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_append_after_max_size_returns_overflow() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let mut cfg = test_cfg(&context, NZU64!(1));
        cfg.partition = "max-size-append-overflow".into();
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), u64::MAX)
                .await
                .unwrap();

        let err = journal.append(&test_digest(100)).await.unwrap_err();
        assert!(matches!(err, Error::OffsetOverflow));
        assert_eq!(journal.bounds(), u64::MAX..u64::MAX);

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_init_at_size_blob_boundary() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));

        // Initialize at position 10 (exactly at blob 2 boundary with items_per_blob=5)
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 10)
                .await
                .unwrap();

        let bounds = journal.bounds();
        assert_eq!(bounds.end, 10);
        assert!(bounds.is_empty());

        // Next append should get position 10
        let pos = journal.append(&test_digest(1000)).await.unwrap();
        assert_eq!(pos, 10);
        assert_eq!(journal.size(), 11);
        assert_eq!(journal.read(10).await.unwrap(), test_digest(1000));

        // Can continue appending
        let pos = journal.append(&test_digest(1001)).await.unwrap();
        assert_eq!(pos, 11);
        assert_eq!(journal.read(11).await.unwrap(), test_digest(1001));

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_init_at_size_mid_blob() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));

        // Initialize at position 7 (middle of blob 1 with items_per_blob=5)
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 7)
                .await
                .unwrap();

        let bounds = journal.bounds();
        assert_eq!(bounds.end, 7);
        // No data exists yet after init_at_size
        assert!(bounds.is_empty());

        // Reading before bounds.start should return ItemPruned
        assert!(matches!(journal.read(5).await, Err(Error::ItemPruned(5))));
        assert!(matches!(journal.read(6).await, Err(Error::ItemPruned(6))));

        // Next append should get position 7
        let pos = journal.append(&test_digest(700)).await.unwrap();
        assert_eq!(pos, 7);
        assert_eq!(journal.size(), 8);
        assert_eq!(journal.read(7).await.unwrap(), test_digest(700));
        // Now bounds.start should be 7 (first data position)
        assert_eq!(journal.bounds().start, 7);

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_append_many_after_mid_blob_start() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(100));
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 150)
                .await
                .unwrap();

        let items: Vec<_> = (0..100u64).map(|i| test_digest(1500 + i)).collect();
        let last = journal.append_many(Many::Flat(&items)).await.unwrap();
        assert_eq!(last, 249);
        assert_eq!(journal.bounds(), 150..250);

        for (position, index) in [(150, 0), (199, 49), (200, 50), (249, 99)] {
            assert_eq!(
                journal.read(position).await.unwrap(),
                items[index],
                "item at position {position} did not match"
            );
        }

        journal.sync().await.unwrap();
        drop(journal);

        let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .unwrap();
        assert_eq!(journal.bounds(), 150..250);
        for (position, index) in [(150, 0), (199, 49), (200, 50), (249, 99)] {
            assert_eq!(
                journal.read(position).await.unwrap(),
                items[index],
                "item at position {position} did not match after reopen"
            );
        }

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_init_at_size_persistence() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));

        // Initialize at position 15
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 15)
                .await
                .unwrap();

        // Append some items
        for i in 0..5u64 {
            let pos = journal.append(&test_digest(1500 + i)).await.unwrap();
            assert_eq!(pos, 15 + i);
        }

        assert_eq!(journal.size(), 20);

        // Sync and reopen
        journal.sync().await.unwrap();
        drop(journal);

        let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .unwrap();

        // Size and data should be preserved
        let bounds = journal.bounds();
        assert_eq!(bounds.end, 20);
        assert_eq!(bounds.start, 15);

        // Verify data
        for i in 0..5u64 {
            assert_eq!(journal.read(15 + i).await.unwrap(), test_digest(1500 + i));
        }

        // Can continue appending
        let pos = journal.append(&test_digest(9999)).await.unwrap();
        assert_eq!(pos, 20);
        assert_eq!(journal.read(20).await.unwrap(), test_digest(9999));

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_init_at_size_persistence_without_data() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));

        // Initialize at position 15
        let journal =
            Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 15)
                .await
                .unwrap();

        let bounds = journal.bounds();
        assert_eq!(bounds.end, 15);
        assert!(bounds.is_empty());

        // Drop without writing any data
        drop(journal);

        // Reopen and verify size persisted
        let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .unwrap();

        let bounds = journal.bounds();
        assert_eq!(bounds.end, 15);
        assert!(bounds.is_empty());

        // Can append starting at position 15
        let pos = journal.append(&test_digest(1500)).await.unwrap();
        assert_eq!(pos, 15);
        assert_eq!(journal.read(15).await.unwrap(), test_digest(1500));

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_init_at_size_large_offset() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));

        // Initialize at a large position (position 1000)
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 1000)
                .await
                .unwrap();

        let bounds = journal.bounds();
        assert_eq!(bounds.end, 1000);
        assert!(bounds.is_empty());

        // Next append should get position 1000
        let pos = journal.append(&test_digest(100000)).await.unwrap();
        assert_eq!(pos, 1000);
        assert_eq!(journal.read(1000).await.unwrap(), test_digest(100000));

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_init_at_size_prune_and_append() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));

        // Initialize at position 20
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 20)
                .await
                .unwrap();

        // Append items 20-29
        for i in 0..10u64 {
            journal.append(&test_digest(2000 + i)).await.unwrap();
        }

        assert_eq!(journal.size(), 30);

        // Prune to position 25
        journal.prune(25).await.unwrap();

        let bounds = journal.bounds();
        assert_eq!(bounds.end, 30);
        assert_eq!(bounds.start, 25);

        // Verify remaining items are readable
        for i in 25..30u64 {
            assert_eq!(journal.read(i).await.unwrap(), test_digest(2000 + (i - 20)));
        }

        // Continue appending
        let pos = journal.append(&test_digest(3000)).await.unwrap();
        assert_eq!(pos, 30);

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_clear_to_size() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(10));
        let mut journal = Journal::init(context.child("journal"), cfg.clone())
            .await
            .expect("failed to initialize journal");

        // Append 25 items (positions 0-24, spanning 3 blobs)
        for i in 0..25u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        assert_eq!(journal.size(), 25);
        journal.sync().await.unwrap();

        // Clear to position 100, effectively resetting the journal
        journal.clear_to_size(100).await.unwrap();
        assert_eq!(journal.size(), 100);

        // Old positions should fail
        for i in 0..25 {
            assert!(matches!(journal.read(i).await, Err(Error::ItemPruned(_))));
        }

        // Verify size persists after restart without writing any data
        drop(journal);
        let mut journal =
            Journal::<_, Digest>::init(context.child("journal_after_clear"), cfg.clone())
                .await
                .expect("failed to re-initialize journal after clear");
        assert_eq!(journal.size(), 100);

        // Append new data starting at position 100
        for i in 100..105u64 {
            let pos = journal.append(&test_digest(i)).await.unwrap();
            assert_eq!(pos, i);
        }
        assert_eq!(journal.size(), 105);

        // New positions should be readable
        for i in 100..105u64 {
            assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
        }

        // Sync and re-init to verify persistence
        journal.sync().await.unwrap();
        drop(journal);

        let journal = Journal::<_, Digest>::init(context.child("journal_reopened"), cfg)
            .await
            .expect("failed to re-initialize journal");

        assert_eq!(journal.size(), 105);
        for i in 100..105u64 {
            assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
        }

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_sync_crash_meta_none_boundary_aligned() {
    // Old meta = None (aligned), new boundary = aligned.
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .unwrap();

        for i in 0..5u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.commit().await.unwrap();
        drop(journal);

        let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .unwrap();
        let bounds = journal.bounds();
        assert_eq!(bounds.start, 0);
        assert_eq!(bounds.end, 5);
        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_missing_metadata_with_short_blob_is_corruption() {
    // Clearing all metadata leaves no watermark. Recovery falls back to the blob boundary
    // and finds a short non-tail blob, violating the legacy rollover-sync invariant.
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                .await
                .unwrap();
        for i in 0..3u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.sync().await.unwrap();

        // Simulate metadata deletion (corruption).
        journal.metadata.clear();
        journal.metadata.sync().await.unwrap();
        drop(journal);

        let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
        assert!(matches!(result, Err(Error::Corruption(_))));
    });
}

#[test_traced]
fn test_fixed_journal_sync_crash_meta_mid_boundary_unchanged() {
    // Old meta = Some(mid), new boundary = mid-blob (same value).
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                .await
                .unwrap();
        for i in 0..3u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.commit().await.unwrap();
        drop(journal);

        let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .unwrap();
        let bounds = journal.bounds();
        assert_eq!(bounds.start, 7);
        assert_eq!(bounds.end, 10);
        journal.destroy().await.unwrap();
    });
}
#[test_traced]
fn test_fixed_journal_sync_crash_meta_mid_to_aligned_becomes_stale() {
    // Old meta = Some(mid), new boundary = aligned.
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                .await
                .unwrap();
        for i in 0..10u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        assert_eq!(journal.size(), 17);
        journal.prune(10).await.unwrap();

        journal.commit().await.unwrap();
        drop(journal);

        let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .unwrap();
        let bounds = journal.bounds();
        assert_eq!(bounds.start, 10);
        assert_eq!(bounds.end, 17);
        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_prune_does_not_move_boundary_backwards() {
    // Pruning to a position earlier than pruning_boundary (within the same blob)
    // should not move the boundary backwards.
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        // init_at_size(7) sets pruning_boundary = 7 (mid-blob in blob 1)
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                .await
                .unwrap();
        // Append 5 items at positions 7-11, filling blob 1 and part of blob 2
        for i in 0..5u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        // Prune to position 5 (blob 1 start) should NOT move boundary back from 7 to 5
        journal.prune(5).await.unwrap();
        assert_eq!(journal.bounds().start, 7);
        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_prune_adjusts_dirty_boundary() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal = Journal::<_, Digest>::init(context.child("journal"), cfg.clone())
            .await
            .unwrap();

        for i in 0..12 {
            journal.append(&test_digest(i)).await.unwrap();
        }

        journal.prune(5).await.unwrap();
        journal
            .commit()
            .await
            .expect("commit should not try to sync pruned dirty blobs");
        assert_eq!(journal.bounds(), 5..12);
        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_replay_after_init_at_size_spanning_blobs() {
    // Test replay when first blob begins mid-blob: init_at_size creates a journal
    // where pruning_boundary is mid-blob, then we append across multiple blobs.
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));

        // Initialize at position 7 (mid-blob with items_per_blob=5)
        // Blob 1 (positions 5-9) begins mid-blob: only positions 7, 8, 9 have data
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 7)
                .await
                .unwrap();

        // Append 13 items (positions 7-19), spanning blobs 1, 2, 3
        for i in 0..13u64 {
            let pos = journal.append(&test_digest(100 + i)).await.unwrap();
            assert_eq!(pos, 7 + i);
        }
        assert_eq!(journal.size(), 20);
        journal.sync().await.unwrap();

        // Replay from pruning_boundary
        {
            let reader = journal.reader();
            let stream = reader
                .replay(NZUsize!(1024), 7)
                .await
                .expect("failed to replay");
            pin_mut!(stream);
            let mut items: Vec<(u64, Digest)> = Vec::new();
            while let Some(result) = stream.next().await {
                items.push(result.expect("replay item failed"));
            }

            // Should get all 13 items with correct logical positions
            assert_eq!(items.len(), 13);
            for (i, (pos, item)) in items.iter().enumerate() {
                assert_eq!(*pos, 7 + i as u64);
                assert_eq!(*item, test_digest(100 + i as u64));
            }
        }

        // Replay from mid-stream (position 12)
        {
            let reader = journal.reader();
            let stream = reader
                .replay(NZUsize!(1024), 12)
                .await
                .expect("failed to replay from mid-stream");
            pin_mut!(stream);
            let mut items: Vec<(u64, Digest)> = Vec::new();
            while let Some(result) = stream.next().await {
                items.push(result.expect("replay item failed"));
            }

            // Should get items from position 12 onwards
            assert_eq!(items.len(), 8);
            for (i, (pos, item)) in items.iter().enumerate() {
                assert_eq!(*pos, 12 + i as u64);
                assert_eq!(*item, test_digest(100 + 5 + i as u64));
            }
        }

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_rewind_error_before_bounds_start() {
    // Test that rewind returns error when trying to rewind before bounds.start
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));

        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 10)
                .await
                .unwrap();

        // Append a few items (positions 10, 11, 12)
        for i in 0..3u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        assert_eq!(journal.size(), 13);

        // Rewind to position 11 should work
        journal.rewind(11).await.unwrap();
        assert_eq!(journal.size(), 11);

        // Rewind to position 10 (pruning_boundary) should work
        journal.rewind(10).await.unwrap();
        assert_eq!(journal.size(), 10);

        // Rewind to before pruning_boundary should fail
        let result = journal.rewind(9).await;
        assert!(matches!(result, Err(Error::InvalidRewind(9))));

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_init_at_size_crash_scenarios() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));

        // Setup: Create a journal with some data and mid-blob metadata
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                .await
                .unwrap();
        for i in 0..5u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.sync().await.unwrap();
        drop(journal);

        // Crash Scenario 1: after clear intent is synced and blobs are removed, but before
        // the new tail blob is created.
        let blob_part = blob_partition(&cfg);
        let meta_cfg = MetadataConfig {
            partition: format!("{}-metadata", cfg.partition),
            codec_config: (),
        };
        let mut metadata =
            Metadata::<_, u64, VecU64>::init(context.child("intent_meta"), meta_cfg.clone())
                .await
                .unwrap();
        metadata.put(CLEAR_TARGET_KEY, 12u64.into());
        metadata.sync().await.unwrap();
        drop(metadata);
        context.remove(&blob_part, None).await.unwrap();

        // Recovery should complete the interrupted init_at_size(12).
        let journal = Journal::<_, Digest>::init(
            context.child("crash").with_attribute("index", 1),
            cfg.clone(),
        )
        .await
        .expect("init failed after clear crash");
        let bounds = journal.bounds();
        assert_eq!(bounds.end, 12);
        assert_eq!(bounds.start, 12);
        drop(journal);

        // Restore metadata for next scenario (it might have been removed by init)
        let mut metadata =
            Metadata::<_, u64, VecU64>::init(context.child("restore_meta"), meta_cfg.clone())
                .await
                .unwrap();
        metadata.put(PRUNING_BOUNDARY_KEY, 7u64.into());
        metadata.put(CLEAR_TARGET_KEY, 2u64.into());
        metadata.sync().await.unwrap();
        drop(metadata);

        // Crash Scenario 2: after the new tail blob is created, but before final metadata
        // replaces the clear intent.
        let (blob, _) = context.open(&blob_part, &0u64.to_be_bytes()).await.unwrap();
        blob.sync().await.unwrap(); // Ensure it exists
        drop(blob);

        // Recovery should complete the interrupted init_at_size(2).
        let journal = Journal::<_, Digest>::init(
            context.child("crash").with_attribute("index", 2),
            cfg.clone(),
        )
        .await
        .expect("init failed after create crash");

        let bounds = journal.bounds();
        assert_eq!(bounds.start, 2);
        assert_eq!(bounds.end, 2);
        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_clear_to_size_crash_scenarios() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));

        // Setup: Init at 12 (Blob 2, offset 2)
        // Metadata = 12
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 12)
                .await
                .unwrap();
        journal.sync().await.unwrap();
        drop(journal);

        // Crash Scenario: clear_to_size(2) after the intent is synced and blob 0 is created,
        // but before final metadata replaces the clear intent.

        let blob_part = blob_partition(&cfg);
        let meta_cfg = MetadataConfig {
            partition: format!("{}-metadata", cfg.partition),
            codec_config: (),
        };
        let mut metadata = Metadata::<_, u64, VecU64>::init(context.child("meta"), meta_cfg)
            .await
            .unwrap();
        metadata.put(CLEAR_TARGET_KEY, 2u64.into());
        metadata.sync().await.unwrap();
        drop(metadata);

        context.remove(&blob_part, None).await.unwrap();

        let (blob, _) = context.open(&blob_part, &0u64.to_be_bytes()).await.unwrap();
        blob.sync().await.unwrap();

        let journal = Journal::<_, Digest>::init(context.child("crash_clear"), cfg.clone())
            .await
            .expect("init failed after clear_to_size crash");

        let bounds = journal.bounds();
        assert_eq!(bounds.start, 2);
        assert_eq!(bounds.end, 2);
        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_clear_to_size_crash_after_intent_before_blobs() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .unwrap();
        for i in 0..12u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.sync().await.unwrap();

        let meta_cfg = MetadataConfig {
            partition: format!("{}-metadata", cfg.partition),
            codec_config: (),
        };
        let mut metadata = Metadata::<_, u64, VecU64>::init(context.child("meta"), meta_cfg)
            .await
            .unwrap();
        metadata.put(CLEAR_TARGET_KEY, 100u64.into());
        metadata.sync().await.unwrap();
        drop(metadata);
        drop(journal);

        let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .expect("init failed after clear intent crash");
        assert_eq!(journal.bounds(), 100..100);
        let pos = journal.append(&test_digest(100)).await.unwrap();
        assert_eq!(pos, 100);
        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_clear_intent_skips_corrupt_stale_blobs() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let blob_part = blob_partition(&cfg);
        let meta_cfg = MetadataConfig {
            partition: format!("{}-metadata", cfg.partition),
            codec_config: (),
        };
        let mut metadata = Metadata::<_, u64, VecU64>::init(context.child("meta"), meta_cfg)
            .await
            .unwrap();
        metadata.put(CLEAR_TARGET_KEY, 12u64.into());
        metadata.sync().await.unwrap();
        drop(metadata);

        // This name would fail `RecoveryBlobs::open` if init tried to parse stale blobs before
        // honoring the clear intent.
        let (blob, _) = context.open(&blob_part, b"not-u64").await.unwrap();
        blob.write_at_sync(0, vec![1, 2, 3]).await.unwrap();
        drop(blob);

        let journal = Journal::<_, Digest>::init(context.child("recover"), cfg.clone())
            .await
            .expect("clear intent should discard stale corrupt blobs before blob parsing");
        assert_eq!(journal.bounds(), 12..12);
        assert_eq!(journal.recovery_watermark(), 12);
        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_clear_to_size_crash_after_mid_blob_intent_with_old_blobs_present() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(10));
        let mut journal =
            Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 10)
                .await
                .unwrap();

        for i in 0..6u64 {
            let pos = journal.append(&test_digest(i)).await.unwrap();
            assert_eq!(pos, 10 + i);
        }
        journal.sync().await.unwrap();

        let meta_cfg = MetadataConfig {
            partition: format!("{}-metadata", cfg.partition),
            codec_config: (),
        };
        let mut metadata = Metadata::<_, u64, VecU64>::init(context.child("meta"), meta_cfg)
            .await
            .unwrap();
        metadata.put(CLEAR_TARGET_KEY, 15u64.into());
        metadata.sync().await.unwrap();
        drop(metadata);
        drop(journal);

        let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
            .await
            .expect("init failed after mid-blob clear intent crash");
        assert_eq!(journal.bounds(), 15..15);
        drop(journal);

        let mut journal = Journal::<_, Digest>::init(context.child("third"), cfg.clone())
            .await
            .expect("init failed after completing mid-blob clear intent");
        assert_eq!(journal.bounds(), 15..15);
        assert!(matches!(journal.read(14).await, Err(Error::ItemPruned(14))));
        let pos = journal.append(&test_digest(100)).await.unwrap();
        assert_eq!(pos, 15);
        assert_eq!(journal.read(15).await.unwrap(), test_digest(100));
        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_rejects_watermark_with_aligned_empty_tail() {
    // Watermark beyond the recovered size with an aligned pruning boundary.
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));

        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .unwrap();
        for i in 0..10u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.sync().await.unwrap();
        drop(journal);

        // Remove all blobs and create a single empty blob 1, leaving
        // recovery_watermark=10 in metadata.
        let blob_part = blob_partition(&cfg);
        context.remove(&blob_part, None).await.unwrap();
        let (blob, _) = context.open(&blob_part, &1u64.to_be_bytes()).await.unwrap();
        blob.sync().await.unwrap();

        let result = Journal::<_, Digest>::init(context.child("crash"), cfg.clone()).await;
        assert!(matches!(result, Err(Error::Corruption(_))));
    });
}

#[test_traced]
fn test_fixed_journal_rejects_far_watermark_with_aligned_empty_tail() {
    // Same as above but the watermark is multiple blobs past the empty tail.
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));

        let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
            .await
            .unwrap();
        for i in 0..10u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.sync().await.unwrap();
        drop(journal);

        // Remove all blobs and create a single empty blob 0, leaving
        // recovery_watermark=10 in metadata.
        let blob_part = blob_partition(&cfg);
        context.remove(&blob_part, None).await.unwrap();
        let (blob, _) = context.open(&blob_part, &0u64.to_be_bytes()).await.unwrap();
        blob.sync().await.unwrap();

        let result = Journal::<_, Digest>::init(context.child("crash"), cfg.clone()).await;
        assert!(matches!(result, Err(Error::Corruption(_))));
    });
}

#[test_traced]
fn test_read_many_empty() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(10));
        let journal = Journal::<_, Digest>::init(context.child("j"), cfg)
            .await
            .unwrap();

        let items = journal.reader().read_many(&[]).await.unwrap();
        assert!(items.is_empty());

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_read_many_single_blob() {
    // All positions within one blob.
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(10));
        let mut journal = Journal::init(context.child("j"), cfg).await.unwrap();

        for i in 0..5u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        assert_eq!(journal.size(), 5);

        let items = journal.reader().read_many(&[0, 2, 4]).await.unwrap();
        assert_eq!(items, vec![test_digest(0), test_digest(2), test_digest(4)]);

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_read_many_across_blobs() {
    // Positions spanning multiple blobs (items_per_blob=3).
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(3));
        let mut journal = Journal::init(context.child("j"), cfg).await.unwrap();

        for i in 0..9u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        assert_eq!(journal.size(), 9);
        // Blobs: [0,1,2], [3,4,5], [6,7,8]

        let items = journal.reader().read_many(&[1, 4, 7]).await.unwrap();
        assert_eq!(items, vec![test_digest(1), test_digest(4), test_digest(7)]);

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_read_many_after_prune() {
    // Read from positions that survive pruning.
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(3));
        let mut journal = Journal::init(context.child("j"), cfg).await.unwrap();

        for i in 0..9u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        assert_eq!(journal.size(), 9);
        journal.sync().await.unwrap();

        // Prune first blob [0,1,2].
        journal.prune(3).await.unwrap();
        assert_eq!(journal.bounds(), 3..9);

        let items = journal.reader().read_many(&[3, 5, 8]).await.unwrap();
        assert_eq!(items, vec![test_digest(3), test_digest(5), test_digest(8)]);

        // Pruned position should error.
        let err = journal.reader().read_many(&[1]).await.unwrap_err();
        assert!(matches!(err, Error::ItemPruned(1)));

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_read_many_out_of_range() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(10));
        let mut journal = Journal::init(context.child("j"), cfg).await.unwrap();

        for i in 0..3u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        assert_eq!(journal.size(), 3);

        let err = journal.reader().read_many(&[0, 5]).await.unwrap_err();
        assert!(matches!(err, Error::ItemOutOfRange(5)));

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_read_many_matches_read() {
    // Verify batch read matches individual reads across blobs.
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(4));
        let mut journal = Journal::init(context.child("j"), cfg).await.unwrap();

        for i in 0..20u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        assert_eq!(journal.size(), 20);
        journal.sync().await.unwrap();

        let positions: Vec<u64> = (0..20).collect();
        let reader = journal.reader();
        let batch = reader.read_many(&positions).await.unwrap();

        for &pos in &positions {
            let single = reader.read(pos).await.unwrap();
            assert_eq!(batch[pos as usize], single);
        }
        drop(reader);

        journal.destroy().await.unwrap();
    });
}

#[test_traced]
fn test_fixed_journal_metrics() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(2));
        let mut journal =
            Journal::<_, Digest>::init(context.child("fixed_metrics"), cfg.clone())
                .await
                .unwrap();

        let items: Vec<_> = (0..5).map(test_digest).collect();
        journal.append_many(Many::Flat(&items)).await.unwrap();
        journal.append(&test_digest(5)).await.unwrap();
        journal.commit().await.unwrap();
        journal.sync().await.unwrap();
        journal.reader().read(0).await.unwrap();
        journal.reader().try_read_sync(0).unwrap();
        journal.reader().read_many(&[1, 2, 4]).await.unwrap();
        journal.prune(2).await.unwrap();
        journal.rewind(4).await.unwrap();

        let buffer = context.encode();
        for expected in [
            "fixed_metrics_size 4",
            "fixed_metrics_pruning_boundary 2",
            "fixed_metrics_retained 2",
            "fixed_metrics_tail_items 2",
            "fixed_metrics_append_calls_total 1",
            "fixed_metrics_append_many_calls_total 1",
            "fixed_metrics_read_calls_total 1",
            "fixed_metrics_read_many_calls_total 1",
            "fixed_metrics_try_read_sync_hits_total 1",
            "fixed_metrics_items_read_total 5",
            "fixed_metrics_commit_calls_total 1",
            "fixed_metrics_sync_calls_total 1",
            "fixed_metrics_append_duration_count 1",
            "fixed_metrics_append_many_duration_count 1",
            "fixed_metrics_read_duration_count 1",
            "fixed_metrics_read_many_duration_count 1",
            "fixed_metrics_commit_duration_count 1",
            "fixed_metrics_sync_duration_count 1",
            "fixed_metrics_cache_hits_total",
            "fixed_metrics_cache_misses_total",
            "fixed_metrics_blobs_tracked",
        ] {
            assert!(buffer.contains(expected), "{expected}\n{buffer}");
        }

        journal.destroy().await.unwrap();
    });
}
/// A snapshot's bounds and contents are frozen across appends and rolls.
#[test_traced]
fn test_snapshot_frozen_across_roll() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal = Journal::<_, Digest>::init(context.child("j"), cfg)
            .await
            .unwrap();
        for i in 0..7u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }

        let snapshot = journal.reader();
        assert_eq!(snapshot.bounds(), 0..7);

        // Appending past the blob boundary rolls the snapshot's tail blob into
        // history; the snapshot keeps reading it through its own handle.
        for i in 7..23u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        assert_eq!(snapshot.bounds(), 0..7);
        for i in 0..7u64 {
            assert_eq!(snapshot.read(i).await.unwrap(), test_digest(i));
        }
        assert!(matches!(
            snapshot.read(7).await,
            Err(Error::ItemOutOfRange(7))
        ));

        let fresh = journal.reader();
        assert_eq!(fresh.bounds(), 0..23);
        assert_eq!(fresh.read(22).await.unwrap(), test_digest(22));

        drop(snapshot);
        drop(fresh);
        journal.destroy().await.unwrap();
    });
}

/// A snapshot taken before a prune keeps reading the pruned range; later snapshots observe
/// the new boundary.
#[test_traced]
fn test_prune_under_snapshot() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal = Journal::<_, Digest>::init(context.child("j"), cfg)
            .await
            .unwrap();
        for i in 0..17u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.sync().await.unwrap();

        let snapshot = journal.reader();
        assert!(journal.prune(12).await.unwrap());

        // The straggler reads the pruned range through its own handles.
        assert_eq!(snapshot.bounds(), 0..17);
        for i in 0..17u64 {
            assert_eq!(snapshot.read(i).await.unwrap(), test_digest(i));
        }

        let fresh = journal.reader();
        assert_eq!(fresh.bounds(), 10..17);
        assert!(matches!(fresh.read(3).await, Err(Error::ItemPruned(3))));

        drop(snapshot);
        drop(fresh);
        journal.destroy().await.unwrap();
    });
}

/// Rewind into a sealed blob refuses while any snapshot is outstanding and succeeds once
/// readers drop.
#[test_traced]
fn test_rewind_sealed_blob_in_use() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal = Journal::<_, Digest>::init(context.child("j"), cfg)
            .await
            .unwrap();
        for i in 0..12u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.sync().await.unwrap();

        let snapshot = journal.reader();
        assert!(matches!(journal.rewind(3).await, Err(Error::BlobInUse(0))));

        // The refused rewind left the journal fully usable.
        assert_eq!(snapshot.read(11).await.unwrap(), test_digest(11));
        drop(snapshot);

        journal.rewind(3).await.unwrap();
        assert_eq!(journal.bounds(), 0..3);
        for i in 3..9u64 {
            assert_eq!(journal.append(&test_digest(i + 100)).await.unwrap(), i);
        }
        assert_eq!(journal.read(8).await.unwrap(), test_digest(108));

        journal.destroy().await.unwrap();
    });
}

/// A stale snapshot reading past a tail rewind gets a clean error, never torn bytes.
#[test_traced]
fn test_rewind_tail_stale_snapshot_errors_cleanly() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(10));
        let mut journal = Journal::<_, Digest>::init(context.child("j"), cfg)
            .await
            .unwrap();
        for i in 0..8u64 {
            journal.append(&test_digest(i)).await.unwrap();
        }
        journal.sync().await.unwrap();

        let snapshot = journal.reader();
        journal.rewind(2).await.unwrap();

        // Within the rewound range the snapshot still reads its bytes.
        assert_eq!(snapshot.read(1).await.unwrap(), test_digest(1));
        // Past it, the read fails cleanly.
        assert!(snapshot.read(6).await.is_err());

        drop(snapshot);
        journal.destroy().await.unwrap();
    });
}

/// Every snapshot shipped to a concurrent task is fully readable while the writer keeps
/// appending and rolling.
#[test_traced]
fn test_snapshots_readable_during_concurrent_appends() {
    let executor = deterministic::Runner::seeded(7);
    executor.start(|context| async move {
        let cfg = test_cfg(&context, NZU64!(5));
        let mut journal = Journal::<_, Digest>::init(context.child("j"), cfg)
            .await
            .unwrap();

        let (mut tx, mut rx) = futures::channel::mpsc::channel::<Reader<Context, Digest>>(8);
        let validator = context.child("validator").spawn(|_| async move {
            let mut validated = 0usize;
            while let Some(snapshot) = rx.next().await {
                let bounds = snapshot.bounds();
                for i in bounds.clone() {
                    assert_eq!(snapshot.read(i).await.unwrap(), test_digest(i));
                }
                validated += (bounds.end - bounds.start) as usize;
            }
            validated
        });

        for i in 0..40u64 {
            journal.append(&test_digest(i)).await.unwrap();
            if i % 7 == 0 {
                let snapshot = journal.reader();
                if tx.try_send(snapshot).is_err() {
                    break;
                }
            }
        }
        drop(tx);
        assert!(validator.await.unwrap() > 0);

        journal.destroy().await.unwrap();
    });
}

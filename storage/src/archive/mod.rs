//! A write-once key-value store for ordered data.
//!
//! [Archive] is a key-value store designed for workloads where all data is written only once and is
//! uniquely associated with both an `index` and a `key`.

use commonware_codec::Codec;
use commonware_utils::Array;
use std::future::Future;
use thiserror::Error;

pub mod immutable;
pub mod prunable;

/// Subject of a `get` or `has` operation.
pub enum Identifier<'a, K: Array> {
    Index(u64),
    Key(&'a K),
}

/// Errors that can occur when interacting with the archive.
#[derive(Debug, Error)]
pub enum Error {
    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),
    #[error("ordinal error: {0}")]
    Ordinal(#[from] crate::ordinal::Error),
    #[error("metadata error: {0}")]
    Metadata(#[from] crate::metadata::Error),
    #[error("freezer error: {0}")]
    Freezer(#[from] crate::freezer::Error),
    #[error("record corrupted")]
    RecordCorrupted,
    #[error("already pruned to: {0}")]
    AlreadyPrunedTo(u64),
    #[error("record too large")]
    RecordTooLarge,
}

/// A write-once key-value store where each key is associated with a unique index.
pub trait Archive {
    /// The type of the key.
    type Key: Array;

    /// The type of the value.
    type Value: Codec;

    /// Store an item in [Archive]. Both indices and keys are assumed to both be globally unique.
    ///
    /// If the index already exists, put does nothing and returns. If the same key is stored multiple times
    /// at different indices (not recommended), any value associated with the key may be returned.
    fn put(
        &mut self,
        index: u64,
        key: Self::Key,
        value: Self::Value,
    ) -> impl Future<Output = Result<(), Error>>;

    /// Perform a [Archive::put] and [Archive::sync] in a single operation.
    fn put_sync(
        &mut self,
        index: u64,
        key: Self::Key,
        value: Self::Value,
    ) -> impl Future<Output = Result<(), Error>> {
        async move {
            self.put(index, key, value).await?;
            self.sync().await
        }
    }

    /// Retrieve an item from [Archive].
    fn get(
        &self,
        identifier: Identifier<'_, Self::Key>,
    ) -> impl Future<Output = Result<Option<Self::Value>, Error>>;

    /// Check if an item exists in [Archive].
    fn has(
        &self,
        identifier: Identifier<'_, Self::Key>,
    ) -> impl Future<Output = Result<bool, Error>>;

    /// Retrieve the end of the current range including `index` (inclusive) and
    /// the start of the next range after `index` (if it exists).
    ///
    /// This is useful for driving backfill operations over the archive.
    fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>);

    /// Returns up to `max` missing items starting from `start`.
    ///
    /// This method iterates through gaps between existing ranges, collecting missing indices
    /// until either `max` items are found or there are no more gaps to fill.
    fn missing_items(&self, index: u64, max: usize) -> Vec<u64>;

    /// Retrieve an iterator over all populated ranges (inclusive) within the [Archive].
    fn ranges(&self) -> impl Iterator<Item = (u64, u64)>;

    /// Retrieve the first index in the [Archive].
    fn first_index(&self) -> Option<u64>;

    /// Retrieve the last index in the [Archive].
    fn last_index(&self) -> Option<u64>;

    /// Sync all pending writes.
    fn sync(&mut self) -> impl Future<Output = Result<(), Error>>;

    /// Close [Archive] (and underlying storage).
    ///
    /// Any pending writes are synced prior to closing.
    fn close(self) -> impl Future<Output = Result<(), Error>>;

    /// Remove all persistent data created by this [Archive].
    fn destroy(self) -> impl Future<Output = Result<(), Error>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::translator::TwoCap;
    use commonware_codec::DecodeExt;
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self, Context},
        Runner,
    };
    use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};
    use rand::Rng;
    use std::{collections::BTreeMap, num::NonZeroUsize};

    const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    fn test_key(key: &str) -> FixedBytes<64> {
        let mut buf = [0u8; 64];
        let key = key.as_bytes();
        assert!(key.len() <= buf.len());
        buf[..key.len()].copy_from_slice(key);
        FixedBytes::decode(buf.as_ref()).unwrap()
    }

    async fn create_prunable(
        context: Context,
        compression: Option<u8>,
    ) -> impl Archive<Key = FixedBytes<64>, Value = i32> {
        let cfg = prunable::Config {
            partition: "test".into(),
            translator: TwoCap,
            compression,
            codec_config: (),
            items_per_section: NZU64!(1024),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        };
        prunable::Archive::init(context, cfg).await.unwrap()
    }

    async fn create_immutable(
        context: Context,
        compression: Option<u8>,
    ) -> impl Archive<Key = FixedBytes<64>, Value = i32> {
        let cfg = immutable::Config {
            metadata_partition: "test_metadata".into(),
            freezer_table_partition: "test_table".into(),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 2,
            freezer_table_resize_chunk_size: 32,
            freezer_journal_partition: "test_journal".into(),
            freezer_journal_target_size: 1024 * 1024,
            freezer_journal_compression: compression,
            freezer_journal_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            ordinal_partition: "test_ordinal".into(),
            items_per_section: NZU64!(1024),
            write_buffer: NZUsize!(1024 * 1024),
            replay_buffer: NZUsize!(1024 * 1024),
            codec_config: (),
        };
        immutable::Archive::init(context, cfg).await.unwrap()
    }

    async fn test_put_get_impl(mut archive: impl Archive<Key = FixedBytes<64>, Value = i32>) {
        let index = 1u64;
        let key = test_key("testkey");
        let data = 1;

        // Has the key before put
        let has = archive
            .has(Identifier::Index(index))
            .await
            .expect("Failed to check key");
        assert!(!has);
        let has = archive
            .has(Identifier::Key(&key))
            .await
            .expect("Failed to check key");
        assert!(!has);

        // Put the key-data pair
        archive
            .put(index, key.clone(), data)
            .await
            .expect("Failed to put data");

        // Has the key after put
        let has = archive
            .has(Identifier::Index(index))
            .await
            .expect("Failed to check key");
        assert!(has);
        let has = archive
            .has(Identifier::Key(&key))
            .await
            .expect("Failed to check key");
        assert!(has);

        // Get the data by key
        let retrieved = archive
            .get(Identifier::Key(&key))
            .await
            .expect("Failed to get data");
        assert_eq!(retrieved, Some(data));

        // Get the data by index
        let retrieved = archive
            .get(Identifier::Index(index))
            .await
            .expect("Failed to get data");
        assert_eq!(retrieved, Some(data));

        // Force a sync
        archive.sync().await.expect("Failed to sync data");

        // Close the archive
        archive.close().await.expect("Failed to close archive");
    }

    #[test_traced]
    fn test_put_get_prunable_no_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let archive = create_prunable(context, None).await;
            test_put_get_impl(archive).await;
        });
    }

    #[test_traced]
    fn test_put_get_prunable_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let archive = create_prunable(context, Some(3)).await;
            test_put_get_impl(archive).await;
        });
    }

    #[test_traced]
    fn test_put_get_immutable_no_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let archive = create_immutable(context, None).await;
            test_put_get_impl(archive).await;
        });
    }

    #[test_traced]
    fn test_put_get_immutable_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let archive = create_immutable(context, Some(3)).await;
            test_put_get_impl(archive).await;
        });
    }

    async fn test_duplicate_key_impl(mut archive: impl Archive<Key = FixedBytes<64>, Value = i32>) {
        let index = 1u64;
        let key = test_key("duplicate");
        let data1 = 1;
        let data2 = 2;

        // Put the key-data pair
        archive
            .put(index, key.clone(), data1)
            .await
            .expect("Failed to put data");

        // Put the key-data pair again (should be idempotent)
        archive
            .put(index, key.clone(), data2)
            .await
            .expect("Duplicate put should not fail");

        // Get the data back - should still be the first value
        let retrieved = archive
            .get(Identifier::Index(index))
            .await
            .expect("Failed to get data")
            .expect("Data not found");
        assert_eq!(retrieved, data1);

        let retrieved = archive
            .get(Identifier::Key(&key))
            .await
            .expect("Failed to get data")
            .expect("Data not found");
        assert_eq!(retrieved, data1);

        archive.close().await.expect("Failed to close archive");
    }

    #[test_traced]
    fn test_duplicate_key_prunable_no_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let archive = create_prunable(context, None).await;
            test_duplicate_key_impl(archive).await;
        });
    }

    #[test_traced]
    fn test_duplicate_key_prunable_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let archive = create_prunable(context, Some(3)).await;
            test_duplicate_key_impl(archive).await;
        });
    }

    #[test_traced]
    fn test_duplicate_key_immutable_no_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let archive = create_immutable(context, None).await;
            test_duplicate_key_impl(archive).await;
        });
    }

    #[test_traced]
    fn test_duplicate_key_immutable_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let archive = create_immutable(context, Some(3)).await;
            test_duplicate_key_impl(archive).await;
        });
    }

    async fn test_get_nonexistent_impl(archive: impl Archive<Key = FixedBytes<64>, Value = i32>) {
        // Attempt to get an index that doesn't exist
        let index = 1u64;
        let retrieved: Option<i32> = archive
            .get(Identifier::Index(index))
            .await
            .expect("Failed to get data");
        assert!(retrieved.is_none());

        // Attempt to get a key that doesn't exist
        let key = test_key("nonexistent");
        let retrieved = archive
            .get(Identifier::Key(&key))
            .await
            .expect("Failed to get data");
        assert!(retrieved.is_none());

        archive.close().await.expect("Failed to close archive");
    }

    #[test_traced]
    fn test_get_nonexistent_prunable_no_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let archive = create_prunable(context, None).await;
            test_get_nonexistent_impl(archive).await;
        });
    }

    #[test_traced]
    fn test_get_nonexistent_prunable_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let archive = create_prunable(context, Some(3)).await;
            test_get_nonexistent_impl(archive).await;
        });
    }

    #[test_traced]
    fn test_get_nonexistent_immutable_no_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let archive = create_immutable(context, None).await;
            test_get_nonexistent_impl(archive).await;
        });
    }

    #[test_traced]
    fn test_get_nonexistent_immutable_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let archive = create_immutable(context, Some(3)).await;
            test_get_nonexistent_impl(archive).await;
        });
    }

    async fn test_persistence_impl<A, F, Fut>(context: Context, creator: F, compression: Option<u8>)
    where
        A: Archive<Key = FixedBytes<64>, Value = i32>,
        F: Fn(Context, Option<u8>) -> Fut,
        Fut: Future<Output = A>,
    {
        // Create and populate archive
        {
            let mut archive = creator(context.clone(), compression).await;

            // Insert multiple keys
            let keys = vec![
                (1u64, test_key("key1"), 1),
                (2u64, test_key("key2"), 2),
                (3u64, test_key("key3"), 3),
            ];

            for (index, key, data) in &keys {
                archive
                    .put(*index, key.clone(), *data)
                    .await
                    .expect("Failed to put data");
            }

            // Close the archive
            archive.close().await.expect("Failed to close archive");
        }

        // Reopen and verify data
        {
            let archive = creator(context, compression).await;

            // Verify all keys are still present
            let keys = vec![
                (1u64, test_key("key1"), 1),
                (2u64, test_key("key2"), 2),
                (3u64, test_key("key3"), 3),
            ];

            for (index, key, expected_data) in &keys {
                let retrieved = archive
                    .get(Identifier::Index(*index))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(retrieved, *expected_data);

                let retrieved = archive
                    .get(Identifier::Key(key))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(retrieved, *expected_data);
            }

            archive.close().await.expect("Failed to close archive");
        }
    }

    #[test_traced]
    fn test_persistence_prunable_no_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            test_persistence_impl(context, create_prunable, None).await;
        });
    }

    #[test_traced]
    fn test_persistence_prunable_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            test_persistence_impl(context, create_prunable, Some(3)).await;
        });
    }

    #[test_traced]
    fn test_persistence_immutable_no_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            test_persistence_impl(context, create_immutable, None).await;
        });
    }

    #[test_traced]
    fn test_persistence_immutable_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            test_persistence_impl(context, create_immutable, Some(3)).await;
        });
    }

    async fn test_ranges_impl<A, F, Fut>(mut context: Context, creator: F, compression: Option<u8>)
    where
        A: Archive<Key = FixedBytes<64>, Value = i32>,
        F: Fn(Context, Option<u8>) -> Fut,
        Fut: Future<Output = A>,
    {
        let mut keys = BTreeMap::new();
        {
            let mut archive = creator(context.clone(), compression).await;

            // Insert 100 keys with gaps
            let mut last_index = 0u64;
            while keys.len() < 100 {
                let gap: u64 = context.gen_range(1..=10);
                let index = last_index + gap;
                last_index = index;

                let mut key_bytes = [0u8; 64];
                context.fill(&mut key_bytes);
                let key = FixedBytes::<64>::decode(key_bytes.as_ref()).unwrap();
                let data: i32 = context.gen();

                if keys.contains_key(&index) {
                    continue;
                }
                keys.insert(index, (key.clone(), data));

                archive
                    .put(index, key, data)
                    .await
                    .expect("Failed to put data");
            }

            archive.close().await.expect("Failed to close archive");
        }

        {
            let archive = creator(context, compression).await;
            let sorted_indices: Vec<u64> = keys.keys().cloned().collect();

            // Check gap before the first element
            let (current_end, start_next) = archive.next_gap(0);
            assert!(current_end.is_none());
            assert_eq!(start_next, Some(sorted_indices[0]));

            // Check gaps between elements
            let mut i = 0;
            while i < sorted_indices.len() {
                let current_index = sorted_indices[i];

                // Find the end of the current contiguous block
                let mut j = i;
                while j + 1 < sorted_indices.len() && sorted_indices[j + 1] == sorted_indices[j] + 1
                {
                    j += 1;
                }
                let block_end_index = sorted_indices[j];
                let next_actual_index = if j + 1 < sorted_indices.len() {
                    Some(sorted_indices[j + 1])
                } else {
                    None
                };

                let (current_end, start_next) = archive.next_gap(current_index);
                assert_eq!(current_end, Some(block_end_index));
                assert_eq!(start_next, next_actual_index);

                // If there's a gap, check an index within the gap
                if let Some(next_index) = next_actual_index {
                    if next_index > block_end_index + 1 {
                        let in_gap_index = block_end_index + 1;
                        let (current_end, start_next) = archive.next_gap(in_gap_index);
                        assert!(current_end.is_none());
                        assert_eq!(start_next, Some(next_index));
                    }
                }
                i = j + 1;
            }

            // Check the last element
            let last_index = *sorted_indices.last().unwrap();
            let (current_end, start_next) = archive.next_gap(last_index);
            assert!(current_end.is_some());
            assert!(start_next.is_none());

            archive.close().await.expect("Failed to close archive");
        }
    }

    #[test_traced]
    fn test_ranges_prunable_no_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            test_ranges_impl(context, create_prunable, None).await;
        });
    }

    #[test_traced]
    fn test_ranges_prunable_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            test_ranges_impl(context, create_prunable, Some(3)).await;
        });
    }

    #[test_traced]
    fn test_ranges_immutable_no_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            test_ranges_impl(context, create_immutable, None).await;
        });
    }

    #[test_traced]
    fn test_ranges_immutable_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            test_ranges_impl(context, create_immutable, Some(3)).await;
        });
    }

    async fn test_many_keys_impl<A, F, Fut>(
        mut context: Context,
        creator: F,
        compression: Option<u8>,
        num: usize,
    ) where
        A: Archive<Key = FixedBytes<64>, Value = i32>,
        F: Fn(Context, Option<u8>) -> Fut,
        Fut: Future<Output = A>,
    {
        // Insert many keys
        let mut keys = BTreeMap::new();
        {
            let mut archive = creator(context.clone(), compression).await;
            while keys.len() < num {
                let index = keys.len() as u64;
                let mut key = [0u8; 64];
                context.fill(&mut key);
                let key = FixedBytes::<64>::decode(key.as_ref()).unwrap();
                let data: i32 = context.gen();

                archive
                    .put(index, key.clone(), data)
                    .await
                    .expect("Failed to put data");
                keys.insert(key, (index, data));

                // Randomly sync the archive
                if context.gen_bool(0.1) {
                    archive.sync().await.expect("Failed to sync archive");
                }
            }
            archive.sync().await.expect("Failed to sync archive");

            // Ensure all keys can be retrieved
            for (key, (index, data)) in &keys {
                let retrieved = archive
                    .get(Identifier::Index(*index))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(&retrieved, data);
                let retrieved = archive
                    .get(Identifier::Key(key))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(&retrieved, data);
            }

            archive.close().await.expect("Failed to close archive");
        }

        // Reinitialize and verify
        {
            let archive = creator(context.clone(), compression).await;

            // Ensure all keys can be retrieved
            for (key, (index, data)) in &keys {
                let retrieved = archive
                    .get(Identifier::Index(*index))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(&retrieved, data);
                let retrieved = archive
                    .get(Identifier::Key(key))
                    .await
                    .expect("Failed to get data")
                    .expect("Data not found");
                assert_eq!(&retrieved, data);
            }

            archive.close().await.expect("Failed to close archive");
        }
    }

    fn test_many_keys_determinism<F, Fut, A>(creator: F, compression: Option<u8>, num: usize)
    where
        A: Archive<Key = FixedBytes<64>, Value = i32>,
        F: Fn(Context, Option<u8>) -> Fut + Copy + Send + 'static,
        Fut: Future<Output = A> + Send,
    {
        let executor = deterministic::Runner::default();
        let state1 = executor.start(|context| async move {
            test_many_keys_impl(context.clone(), creator, compression, num).await;
            context.auditor().state()
        });
        let executor = deterministic::Runner::default();
        let state2 = executor.start(|context| async move {
            test_many_keys_impl(context.clone(), creator, compression, num).await;
            context.auditor().state()
        });
        assert_eq!(state1, state2);
    }

    #[test_traced]
    fn test_many_keys_prunable_no_compression() {
        test_many_keys_determinism(create_prunable, None, 1_000);
    }

    #[test_traced]
    fn test_many_keys_prunable_compression() {
        test_many_keys_determinism(create_prunable, Some(3), 1_000);
    }

    #[test_traced]
    fn test_many_keys_immutable_no_compression() {
        test_many_keys_determinism(create_immutable, None, 1_000);
    }

    #[test_traced]
    fn test_many_keys_immutable_compression() {
        test_many_keys_determinism(create_immutable, Some(3), 1_000);
    }

    #[test_traced]
    #[ignore]
    fn test_many_keys_prunable_large() {
        test_many_keys_determinism(create_prunable, None, 50_000);
    }

    #[test_traced]
    #[ignore]
    fn test_many_keys_immutable_large() {
        test_many_keys_determinism(create_immutable, None, 50_000);
    }
}

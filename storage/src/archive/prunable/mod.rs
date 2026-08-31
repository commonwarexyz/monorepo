//! A prunable key-value store for ordered data.
//!
//! Data is stored across two backends: [crate::journal::segmented::fixed] for fixed-size index entries and
//! [crate::journal::segmented::glob::Glob] for values (managed by [crate::journal::segmented::oversized]).
//! The location of written data is stored in-memory by both index and key (via [crate::index::unordered::Index])
//! to enable efficient lookups (on average).
//!
//! _Notably, [Archive] does not make use of compaction nor on-disk indexes (and thus has no read
//! nor write amplification during normal operation).
//!
//! # Format
//!
//! [Archive] uses a two-journal structure for efficient page cache usage:
//!
//! **Index Journal (segmented/fixed)** - Fixed-size entries for fast startup replay:
//! ```text
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |10 |11 |12 |13 |14 |15 |16 |17 |18 |19 |20 |21 |22 |23 |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |          Index(u64)           |Key(Fixed Size)|        val_offset(u64)        | val_size(u32) |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! ```
//!
//! **Value Blob** - Raw values with CRC32 checksums (direct reads, no page cache):
//! ```text
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! |     Compressed Data (variable)    |   CRC32   |
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! ```
//!
//! # Uniqueness
//!
//! Indices are unique for [Archive] and writing to an occupied index is a no-op. Duplicate
//! indices can be stored via [`crate::archive::MultiArchive::put_multi`].
//!
//! Keys may be stored at multiple indices with either put variant. A lookup by
//! [`crate::archive::Identifier::Key`] may return any of the values at that key. Entries
//! whose index has been pruned are never returned or reported as present, so a key matching
//! both a pruned and a non-pruned entry resolves to the non-pruned entry.
//!
//! ## Conflicts
//!
//! Because a translated representation of a key is only ever stored in memory, it is possible (and
//! expected) that two keys will eventually be represented by the same translated key. To handle
//! this case, [Archive] must check the persisted form of all conflicting keys to ensure data from
//! the correct key is returned. To support efficient checks, [Archive] (via
//! [crate::index::unordered::Index]) keeps a linked list of all keys with the same translated
//! prefix:
//!
//! ```rust
//! struct Record {
//!     index: u64,
//!
//!     next: Option<Box<Record>>,
//! }
//! ```
//!
//! _To avoid random memory reads in the common case, the in-memory index directly stores the first
//! item in the linked list instead of a pointer to the first item._
//!
//! `index` is the key to the map used to serve lookups by `index` that stores the position in the
//! index journal (selected by `section = index / items_per_section * items_per_section` to minimize
//! the number of open blobs):
//!
//! ```text
//! // Maps index -> position in index journal
//! indices: BTreeMap<u64, u64>
//! ```
//!
//! _If the [Translator] provided by the caller does not uniformly distribute keys across the key
//! space or uses a translated representation that means keys on average have many conflicts,
//! performance will degrade._
//!
//! ## Memory Overhead
//!
//! [Archive] uses two maps to enable lookups by both index and key. The memory used to track each
//! index item is `8 + 8` (where `8` is the index and `8` is the position in the index journal).
//! The memory used to track each key item is `~translated(key).len() + 16` bytes (where `16` is the
//! size of the `Record` struct). This means that an [Archive] employing a [Translator] that uses
//! the first `8` bytes of a key will use `~40` bytes to index each key.
//!
//! ### MultiArchive Overhead
//!
//! [Archive] stores index positions in a dual-map layout:
//! - `indices: BTreeMap<u64, u64>` tracks the first position for each index.
//! - `extra_indices: BTreeMap<u64, Vec<u64>>` tracks additional positions for indices written via
//!   [crate::archive::MultiArchive::put_multi].
//!
//! This means the baseline overhead above remains unchanged for the first item at an index. For
//! indices with duplicates, the additional in-memory payload is:
//! - one `Vec<u64>` header (`24` bytes), and
//! - `n * 8` bytes for `n` additional positions.
//!
//! Equivalently, this is `24 + (n * 8)` bytes per duplicated index, excluding `BTreeMap` node
//! overhead for `extra_indices`.
//!
//! # Pruning
//!
//! [Archive] supports pruning up to a minimum `index` using the `prune` method. After `prune` is
//! called on a `section`, entries below the pruned `section` are gone: `get` returns `None`,
//! and a `put` below the floor is satisfied without storing.
//!
//! ## Lazy Index Cleanup
//!
//! Instead of performing a full iteration of the in-memory index, storing an additional in-memory
//! index per `section`, or replaying a `section` of the value blob,
//! [Archive] lazily cleans up the [crate::index::unordered::Index] after pruning. When a new key is
//! stored that overlaps (same translated value) with a pruned key, the pruned key is removed from
//! the in-memory index.
//!
//! # Read Path
//!
//! All reads (by index or key) first read the index entry from the index journal to get the
//! value location (offset and size), then read the value from the value blob. The index journal
//! uses a page cache for caching, so hot entries are served from memory. Values are read directly
//! from disk without caching to avoid polluting the page cache with large values.
//!
//! # Compression
//!
//! [Archive] supports compressing data before storing it on disk. This can be enabled by setting
//! the `compression` field in the `Config` struct to a valid `zstd` compression level. This setting
//! can be changed between initializations of [Archive], however, it must remain populated if any
//! data was written with compression enabled.
//!
//! # Querying for Gaps
//!
//! [Archive] tracks gaps in the index space to enable the caller to efficiently fetch unknown keys
//! using `next_gap`. This is a very common pattern when syncing blocks in a blockchain.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic, buffer::paged::CacheRef};
//! use commonware_cryptography::{Hasher as _, Sha256};
//! use commonware_storage::{
//!     translator::FourCap,
//!     archive::{
//!         Archive as _,
//!         prunable::{Archive, Config},
//!     },
//! };
//! use commonware_utils::{NZUsize, NZU16, NZU64};
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create an archive
//!     let cfg = Config {
//!         translator: FourCap,
//!         metadata_partition: "demo-metadata".into(),
//!         key_partition: "demo-index".into(),
//!         key_page_cache: CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10)),
//!         value_partition: "demo-value".into(),
//!         compression: Some(3),
//!         codec_config: (),
//!         items_per_section: NZU64!(1024),
//!         key_write_buffer: NZUsize!(1024 * 1024),
//!         value_write_buffer: NZUsize!(1024 * 1024),
//!         replay_buffer: NZUsize!(4096),
//!     };
//!     let mut archive = Archive::init(context, cfg).await.unwrap();
//!
//!     // Put a key
//!     archive = archive.put(1, Sha256::hash(&[b"data"]), 10).await.unwrap();
//!
//!     // Sync the archive
//!     archive.sync().await.unwrap();
//! });
//! ```

use crate::translator::Translator;
use commonware_runtime::buffer::paged::CacheRef;
use std::num::{NonZeroU64, NonZeroUsize};

mod storage;
pub use storage::Archive;

/// Configuration for [Archive] storage.
#[derive(Clone)]
pub struct Config<T: Translator, C> {
    /// Logic to transform keys into their index representation.
    ///
    /// [Archive] assumes that all internal keys are spread uniformly across the key space.
    /// If that is not the case, lookups may be O(n) instead of O(1).
    pub translator: T,

    /// The partition to use for per-section validation markers. Recovery adopts entries
    /// below a section's marker without re-validating their values.
    pub metadata_partition: String,

    /// The partition to use for the key journal (stores index+key metadata).
    pub key_partition: String,

    /// The page cache to use for the key journal.
    pub key_page_cache: CacheRef,

    /// The partition to use for the value blob (stores values).
    pub value_partition: String,

    /// The compression level to use for the value blob.
    pub compression: Option<u8>,

    /// The [commonware_codec::Codec] configuration to use for the value stored in the archive.
    pub codec_config: C,

    /// The number of items per section (the granularity of pruning).
    pub items_per_section: NonZeroU64,

    /// The amount of bytes that can be buffered for the key journal before being written to a
    /// [commonware_runtime::Blob].
    pub key_write_buffer: NonZeroUsize,

    /// The amount of bytes that can be buffered for the value journal before being written to a
    /// [commonware_runtime::Blob].
    pub value_write_buffer: NonZeroUsize,

    /// The buffer size to use when replaying a [commonware_runtime::Blob].
    pub replay_buffer: NonZeroUsize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive::{Archive as _, Error, Identifier, MultiArchive as _},
        journal::{Error as JournalError, segmented::glob::corrupt_frame},
        translator::{FourCap, TwoCap},
    };
    use commonware_codec::{DecodeExt, Error as CodecError, FixedSize};
    use commonware_cryptography::Crc32;
    use commonware_macros::{test_group, test_traced};
    use commonware_runtime::{
        Blob as _, BufferPooler, Error as RError, Metrics as _, ReadOptions, Runner, Spawner as _,
        Storage as _, Supervisor as _, WriteOptions, deterministic,
        mocks::{
            DelayedSyncContext, PendingSyncs, drive_pending_syncs, fail_pending_syncs,
            release_next_pending_syncs, release_pending_syncs,
        },
        telemetry::metrics::has_metric_value,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, sequence::FixedBytes};
    use rand::RngExt as _;
    use std::{
        collections::BTreeMap,
        num::{NonZeroU16, NonZeroU64},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    fn test_key(key: &str) -> FixedBytes<64> {
        let mut buf = [0u8; 64];
        let key = key.as_bytes();
        assert!(key.len() <= buf.len());
        buf[..key.len()].copy_from_slice(key);
        FixedBytes::decode(buf.as_ref()).unwrap()
    }

    const DEFAULT_ITEMS_PER_SECTION: u64 = 65536;
    const DEFAULT_WRITE_BUFFER: usize = 1024;
    const DEFAULT_REPLAY_BUFFER: usize = 4096;
    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    fn test_config<E: BufferPooler>(
        context: &E,
        partition_prefix: &str,
        items_per_section: NonZeroU64,
    ) -> Config<FourCap, ()> {
        Config {
            translator: FourCap,
            metadata_partition: format!("{partition_prefix}-metadata"),
            key_partition: format!("{partition_prefix}-index"),
            key_page_cache: CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE),
            value_partition: format!("{partition_prefix}-value"),
            codec_config: (),
            compression: None,
            key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
            value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
            replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
            items_per_section,
        }
    }

    /// Physical size of one uncompressed i32 value frame in the value journal, per the
    /// glob's frame layout (encoded value followed by its CRC32).
    const I32_VALUE_FRAME_SIZE: u64 =
        (i32::SIZE + crate::journal::segmented::glob::CHECKSUM_SIZE) as u64;

    #[test_traced]
    fn test_put_after_start_sync_is_accepted_before_handle_completes() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_config(&context, "test", NZU64!(DEFAULT_ITEMS_PER_SECTION));
            let archive = Archive::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize archive");

            let (mut archive, handle) = archive
                .put_start_sync(1, test_key("aaa"), 10)
                .await
                .expect("Failed to start sync");
            let pending_after_start = pending.lock().len();
            assert!(
                pending_after_start > 0,
                "put_start_sync should return while the sync handle is still pending"
            );

            archive = archive
                .put(2, test_key("bbb"), 20)
                .await
                .expect("archive should remain usable before sync completion");
            assert_eq!(
                pending.lock().len(),
                pending_after_start,
                "put should not issue a new storage sync while accepting later data"
            );
            assert_eq!(archive.get(Identifier::Index(1)).await.unwrap(), Some(10));

            release_pending_syncs(&pending);
            handle.await.expect("sync handle should complete");

            let (_archive, follow_up) = archive
                .start_sync()
                .await
                .expect("Failed to start next sync");
            assert!(
                !pending.lock().is_empty(),
                "the later put must remain pending for a future sync"
            );
            release_pending_syncs(&pending);
            follow_up.await.expect("follow-up sync should complete");
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let cfg = test_config(&context, "test", NZU64!(DEFAULT_ITEMS_PER_SECTION));
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(context.child("reopen"), cfg)
                .await
                .expect("Failed to reopen archive");

            assert_eq!(archive.get(Identifier::Index(1)).await.unwrap(), Some(10));
            assert_eq!(archive.get(Identifier::Index(2)).await.unwrap(), Some(20));
        });
    }

    #[test_traced]
    fn test_duplicate_put_start_sync_observes_in_flight_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_config(&context, "test", NZU64!(DEFAULT_ITEMS_PER_SECTION));
            let archive = Archive::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize archive");

            let (archive, first) = archive
                .put_start_sync(1, test_key("aaa"), 10)
                .await
                .expect("Failed to start sync");
            assert_eq!(pending.lock().len(), 2);

            let (archive, second) = archive
                .put_start_sync(1, test_key("duplicate"), 99)
                .await
                .expect("Failed to start duplicate sync");
            assert_eq!(
                pending.lock().len(),
                2,
                "duplicate put_start_sync must not issue a new storage sync"
            );

            let started = Arc::new(AtomicUsize::new(0));
            let completed = Arc::new(AtomicUsize::new(0));
            let started_clone = started.clone();
            let completed_clone = completed.clone();
            let waiter = context.inner.child("duplicate").spawn(|_| async move {
                started_clone.fetch_add(1, Ordering::Relaxed);
                second.await.expect("duplicate sync handle should complete");
                completed_clone.fetch_add(1, Ordering::Relaxed);
            });

            while started.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            commonware_runtime::reschedule().await;
            assert_eq!(
                completed.load(Ordering::Relaxed),
                0,
                "duplicate put_start_sync must observe the original in-flight sync"
            );

            release_pending_syncs(&pending);
            first.await.expect("first sync handle should complete");
            while completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            waiter.await.expect("duplicate waiter failed");

            assert_eq!(archive.get(Identifier::Index(1)).await.unwrap(), Some(10));
        });
    }

    #[test_traced]
    fn test_below_floor_put_start_sync_covers_prior_pending_write() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_config(&context, "test", NZU64!(1));
            let archive = Archive::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize archive");

            // Raise the prune floor above index 0, then buffer an unsynced write to retained
            // section 2.
            let archive = archive.prune(1).await.expect("Failed to set prune floor");
            let archive = archive
                .put(2, test_key("pending"), 20)
                .await
                .expect("Failed to buffer retained write");

            // The below-floor put stores nothing, yet the returned handle must cover every
            // previously accepted write. The two parked operations are section 2's index and
            // value syncs.
            assert!(pending.lock().is_empty());
            let (archive, handle) = archive
                .put_start_sync(0, test_key("pruned"), 0)
                .await
                .expect("Failed to request sync through below-floor put");
            assert_eq!(
                pending.lock().len(),
                2,
                "the sync combinator must cover writes accepted before its below-floor put"
            );

            // Releasing the parked syncs completes the handle, proving the covered write
            // durable while the below-floor index stays absent.
            release_pending_syncs(&pending);
            handle.await.expect("covering sync should complete");
            assert_eq!(archive.get(Identifier::Index(2)).await.unwrap(), Some(20));
            assert_eq!(archive.get(Identifier::Index(0)).await.unwrap(), None);
        });
    }

    #[test_traced]
    fn test_below_floor_put_multi_sync_covers_prior_pending_write() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_config(&context, "test", NZU64!(1));
            let archive = Archive::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize archive");

            // Raise the prune floor above index 0, then buffer an unsynced write to retained
            // section 2.
            let archive = archive.prune(1).await.expect("Failed to set prune floor");
            let archive = archive
                .put_multi(2, test_key("pending"), 20)
                .await
                .expect("Failed to buffer retained write");

            // Run the blocking combinator in a spawned task so the test can observe whether it
            // returns while the covering sync is still parked.
            pending.arm();
            let completed = Arc::new(AtomicUsize::new(0));
            let completed_clone = completed.clone();
            let task = context.inner.child("put_sync").spawn(|_| async move {
                let result = archive.put_multi_sync(0, test_key("pruned"), 0).await;
                completed_clone.store(1, Ordering::Relaxed);
                result
            });
            while pending.calls() == 0 && completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }

            // The below-floor put stores nothing, yet the blocking call must not return before
            // the previously buffered write is durable.
            assert_eq!(
                completed.load(Ordering::Relaxed),
                0,
                "put_multi_sync must wait for writes accepted before its below-floor put"
            );
            assert!(pending.calls() > 0);
            release_pending_syncs(&pending);
            let archive = task
                .await
                .expect("put_multi_sync task failed")
                .expect("put_multi_sync failed");

            // The covered write survives while the below-floor index stays absent.
            assert_eq!(archive.get_all(2).await.unwrap(), Some(vec![20]));
            assert_eq!(archive.get_all(0).await.unwrap(), None);
        });
    }

    #[test_traced]
    fn test_overlapping_put_start_sync_waits_for_in_flight_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_config(&context, "test", NZU64!(DEFAULT_ITEMS_PER_SECTION));
            let archive = Archive::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize archive");

            let (archive, first) = archive
                .put_start_sync(1, test_key("aaa"), 10)
                .await
                .expect("Failed to start sync");
            let pending_after_first = pending.lock().len();
            assert!(pending_after_first > 0);

            let started = Arc::new(AtomicUsize::new(0));
            let completed = Arc::new(AtomicUsize::new(0));
            let started_clone = started.clone();
            let completed_clone = completed.clone();
            let waiter = context.inner.child("second").spawn(|_| async move {
                started_clone.fetch_add(1, Ordering::Relaxed);
                let (archive, second) = archive
                    .put_start_sync(2, test_key("bbb"), 20)
                    .await
                    .expect("Failed to start second sync");
                completed_clone.fetch_add(1, Ordering::Relaxed);
                (archive, second)
            });

            while started.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            commonware_runtime::reschedule().await;
            assert_eq!(completed.load(Ordering::Relaxed), 0);
            assert_eq!(
                pending.lock().len(),
                pending_after_first,
                "second put_start_sync must not start new syncs before the first completes"
            );

            release_pending_syncs(&pending);
            first.await.expect("first sync handle should complete");
            while completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            let (archive, second) = waiter.await.expect("second put task failed");
            assert!(!pending.lock().is_empty());
            release_pending_syncs(&pending);
            second.await.expect("second sync handle should complete");

            assert_eq!(archive.get(Identifier::Index(1)).await.unwrap(), Some(10));
            assert_eq!(archive.get(Identifier::Index(2)).await.unwrap(), Some(20));
        });
    }

    #[test_traced]
    fn test_sync_after_put_start_sync_waits_for_in_flight_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_config(&context, "test", NZU64!(DEFAULT_ITEMS_PER_SECTION));
            let archive = Archive::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize archive");

            let (archive, first) = archive
                .put_start_sync(1, test_key("aaa"), 10)
                .await
                .expect("Failed to start sync");
            assert!(!pending.lock().is_empty());

            let started = Arc::new(AtomicUsize::new(0));
            let completed = Arc::new(AtomicUsize::new(0));
            let started_clone = started.clone();
            let completed_clone = completed.clone();
            let waiter = context.inner.child("sync").spawn(|_| async move {
                started_clone.fetch_add(1, Ordering::Relaxed);
                let archive = archive.sync().await.expect("sync should complete");
                completed_clone.fetch_add(1, Ordering::Relaxed);
                archive
            });

            while started.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            commonware_runtime::reschedule().await;
            assert_eq!(
                completed.load(Ordering::Relaxed),
                0,
                "shutdown sync must wait for the in-flight put_start_sync handle"
            );

            release_pending_syncs(&pending);
            first.await.expect("first sync handle should complete");
            while completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            let archive = waiter.await.expect("sync task failed");
            assert_eq!(archive.get(Identifier::Index(1)).await.unwrap(), Some(10));
        });
    }

    #[test_traced]
    fn test_destroy_after_put_start_sync_waits_for_in_flight_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_config(&context, "test", NZU64!(DEFAULT_ITEMS_PER_SECTION));
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize archive");

            let (archive, first) = archive
                .put_start_sync(1, test_key("aaa"), 10)
                .await
                .expect("Failed to start sync");
            assert!(!pending.lock().is_empty());

            let started = Arc::new(AtomicUsize::new(0));
            let completed = Arc::new(AtomicUsize::new(0));
            let started_clone = started.clone();
            let completed_clone = completed.clone();
            let waiter = context.inner.child("destroy").spawn(|_| async move {
                started_clone.fetch_add(1, Ordering::Relaxed);
                archive.destroy().await.expect("destroy should complete");
                completed_clone.fetch_add(1, Ordering::Relaxed);
            });

            while started.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            commonware_runtime::reschedule().await;
            assert_eq!(
                completed.load(Ordering::Relaxed),
                0,
                "destroy must wait for the in-flight put_start_sync handle"
            );

            release_pending_syncs(&pending);
            first.await.expect("first sync handle should complete");
            while completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            waiter.await.expect("destroy task failed");
        });
    }

    #[test_traced]
    fn test_prune_after_put_start_sync_waits_for_in_flight_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_config(&context, "test", NZU64!(1));
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize archive");

            let (archive, first) = archive
                .put_start_sync(1, test_key("aaa"), 10)
                .await
                .expect("Failed to start sync");
            assert!(!pending.lock().is_empty());

            let started = Arc::new(AtomicUsize::new(0));
            let completed = Arc::new(AtomicUsize::new(0));
            let started_clone = started.clone();
            let completed_clone = completed.clone();
            let waiter = context.inner.child("prune").spawn(|_| async move {
                started_clone.fetch_add(1, Ordering::Relaxed);
                let archive = archive.prune(2).await.expect("prune should complete");
                completed_clone.fetch_add(1, Ordering::Relaxed);
                archive
            });

            while started.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            commonware_runtime::reschedule().await;
            assert_eq!(
                completed.load(Ordering::Relaxed),
                0,
                "prune must wait for in-flight syncs on pruned sections"
            );

            release_pending_syncs(&pending);
            first
                .await
                .expect("sync handle should complete despite pruning");
            while completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            let archive = waiter.await.expect("prune task failed");
            assert_eq!(archive.get(Identifier::Index(1)).await.unwrap(), None);
        });
    }

    #[test_traced]
    fn test_prune_surfaces_failed_in_flight_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_config(&context, "test", NZU64!(1));
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize archive");

            let (archive, first) = archive
                .put_start_sync(1, test_key("aaa"), 10)
                .await
                .expect("Failed to start sync");
            fail_pending_syncs(&pending);

            let err = archive
                .prune(2)
                .await
                .expect_err("prune must surface a failed in-flight sync");
            assert!(matches!(
                err,
                Error::Journal(JournalError::Runtime(RError::Io(_)))
            ));

            let err = first.await.expect_err("first sync handle should fail");
            assert!(matches!(err, RError::Io(_)));
        });
    }

    #[test_traced]
    fn test_put_start_sync_after_prune_drops_pruned_sync_requests() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_config(&context, "test", NZU64!(1));
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize archive");

            let (archive, first) = archive
                .put_start_sync(1, test_key("aaa"), 10)
                .await
                .expect("Failed to start sync");
            release_pending_syncs(&pending);
            first.await.expect("first sync handle should complete");

            let archive = archive.prune(2).await.expect("Failed to prune");

            // If pruning left section 1 in the retained sync-request set, these calls would trip
            // the journal's prune guard.
            let (archive, second) = archive
                .put_start_sync(2, test_key("bbb"), 20)
                .await
                .expect("put_start_sync after prune should succeed");
            release_pending_syncs(&pending);
            second.await.expect("second sync handle should complete");
            let archive = drive_pending_syncs(&pending, archive.sync())
                .await
                .expect("sync after prune should succeed");

            assert_eq!(archive.get(Identifier::Index(1)).await.unwrap(), None);
            assert_eq!(archive.get(Identifier::Index(2)).await.unwrap(), Some(20));
        });
    }

    #[test_traced]
    fn test_overlapping_put_start_sync_restarts_after_all_handles_complete() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_config(&context, "test", NZU64!(1));
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize archive");

            let (archive, first) = archive
                .put_start_sync(1, test_key("aaa"), 10)
                .await
                .expect("Failed to start first sync");
            assert_eq!(pending.lock().len(), 2);

            let (_archive, second) = archive
                .put_start_sync(2, test_key("bbb"), 20)
                .await
                .expect("Failed to start second sync");
            assert_eq!(
                pending.lock().len(),
                4,
                "different sections should be able to have independent in-flight syncs"
            );

            release_pending_syncs(&pending);
            first.await.expect("first sync handle should complete");
            second.await.expect("second sync handle should complete");
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let cfg = test_config(&context, "test", NZU64!(1));
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(context.child("reopen"), cfg)
                .await
                .expect("Failed to reopen archive");

            assert_eq!(archive.get(Identifier::Index(1)).await.unwrap(), Some(10));
            assert_eq!(archive.get(Identifier::Index(2)).await.unwrap(), Some(20));
        });
    }

    #[test_traced]
    fn test_overlapping_put_start_sync_restarts_only_completed_handles() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_config(&context, "test", NZU64!(1));
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize archive");

            let (archive, first) = archive
                .put_start_sync(1, test_key("aaa"), 10)
                .await
                .expect("Failed to start first sync");
            let (archive, second) = archive
                .put_start_sync(2, test_key("bbb"), 20)
                .await
                .expect("Failed to start second sync");
            assert_eq!(pending.lock().len(), 4);

            release_next_pending_syncs(&pending, 2);
            first.await.expect("first sync handle should complete");

            drop(second);
            drop(archive);
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let cfg = test_config(&context, "test", NZU64!(1));
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(context.child("reopen"), cfg)
                .await
                .expect("Failed to reopen archive");

            assert_eq!(archive.get(Identifier::Index(1)).await.unwrap(), Some(10));
            assert_eq!(archive.get(Identifier::Index(2)).await.unwrap(), None);
        });
    }

    #[test_traced]
    fn test_failed_start_sync_is_returned_by_next_start_sync_handle() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_config(&context, "test", NZU64!(DEFAULT_ITEMS_PER_SECTION));
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize archive");

            let (archive, first) = archive
                .put_start_sync(1, test_key("aaa"), 10)
                .await
                .expect("Failed to start sync");
            assert_eq!(pending.lock().len(), 2);
            fail_pending_syncs(&pending);

            let archive = archive
                .put(2, test_key("bbb"), 20)
                .await
                .expect("write should be accepted before observing the failed sync");

            let (_archive, second) = archive
                .start_sync()
                .await
                .expect("start_sync should return a handle for the failed sync");
            let err = second
                .await
                .expect_err("next start_sync handle should observe failed in-flight sync");
            assert!(matches!(err, RError::Io(_)));

            let err = first.await.expect_err("first sync handle should fail");
            assert!(matches!(err, RError::Io(_)));
        });
    }

    #[test_traced]
    fn test_archive_truncates_at_first_invalid_value() {
        deterministic::Runner::default().start(|context| async move {
            for (name, bad_position, retained) in [("first", 0, 0), ("middle", 1, 1)] {
                let cfg = test_config(&context, &format!("invalid-{name}"), NZU64!(4));

                // Seed three values in one section. The sync leaves them durable with no marker
                // (the active section's boundary stays debt), so reopen must CRC-validate every
                // frame from position 0.
                let mut archive = Archive::init(context.child(name), cfg.clone())
                    .await
                    .unwrap();
                for (index, value) in [10, 20, 30].into_iter().enumerate() {
                    archive = archive
                        .put(index as u64, test_key(&format!("key-{index}")), value)
                        .await
                        .unwrap();
                }
                archive = archive.sync().await.unwrap();
                drop(archive);

                corrupt_frame(
                    &context,
                    &cfg.value_partition,
                    &0u64.to_be_bytes(),
                    bad_position,
                    I32_VALUE_FRAME_SIZE,
                )
                .await;

                // Every frame after the first invalid one belongs to the same uncommitted suffix,
                // even if its own CRC is valid:
                //
                // first:  [bad]              [valid] [valid] -> []
                // middle: [valid, retained]  [bad]   [valid] -> [valid]
                let archive =
                    Archive::<_, _, FixedBytes<64>, i32>::init(context.child(name), cfg.clone())
                        .await
                        .unwrap();
                assert_eq!(
                    archive.ranges().collect::<Vec<_>>(),
                    if retained == 0 {
                        Vec::new()
                    } else {
                        vec![(0, retained - 1)]
                    }
                );
                for (index, value) in [10, 20, 30].into_iter().enumerate() {
                    let expected = (index < retained as usize).then_some(value);
                    assert_eq!(
                        archive.get(Identifier::Index(index as u64)).await.unwrap(),
                        expected
                    );
                }
                drop(archive);

                // The truncation was made durable before the first reopen returned: a second
                // reopen observes the same retained prefix.
                let archive = Archive::<_, _, FixedBytes<64>, i32>::init(context.child(name), cfg)
                    .await
                    .unwrap();
                assert_eq!(archive.last_index(), retained.checked_sub(1));
                archive.destroy().await.unwrap();
            }
        });
    }

    #[test_traced]
    fn test_archive_completes_interrupted_rewind_to_empty_section() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = test_config(&context, "empty-rewind", NZU64!(4));

            // Seed one durable value, then drop the sidecar so startup cannot consult markers
            // and must reconcile the journals alone.
            let archive = Archive::init(context.child("seed"), cfg.clone())
                .await
                .unwrap();
            let archive = archive.put(0, test_key("zero"), 10).await.unwrap();
            let archive = archive.sync().await.unwrap();
            drop(archive);
            context.remove(&cfg.metadata_partition, None).await.unwrap();

            // Model a crash between Archive's two durable section truncations:
            //
            //     before: index [A] -> values [A]
            //     crash:  index [ ]    values [A]
            //
            // Archive owns both journals, so startup must finish removing the unindexed value.
            let (index, _) = context
                .open(&cfg.key_partition, &0u64.to_be_bytes())
                .await
                .unwrap();
            index.resize(0).await.unwrap();
            index.sync().await.unwrap();
            drop(index);
            let (_, value_size) = context
                .open(&cfg.value_partition, &0u64.to_be_bytes())
                .await
                .unwrap();
            assert_eq!(value_size, I32_VALUE_FRAME_SIZE);

            let archive =
                Archive::<_, _, FixedBytes<64>, i32>::init(context.child("repair"), cfg.clone())
                    .await
                    .unwrap();
            assert_eq!(archive.last_index(), None);
            drop(archive);
            let (_, value_size) = context
                .open(&cfg.value_partition, &0u64.to_be_bytes())
                .await
                .unwrap();
            assert_eq!(value_size, 0, "startup must finish the value truncation");
            context.remove(&cfg.metadata_partition, None).await.unwrap();

            // Once both halves of the rewind are empty, missing derived metadata does not require
            // durability work:
            //
            //     index [ ]    values [ ]    metadata [ ] -> no rewind, no sync
            //
            // This keeps the recovery write bounded to the restart that actually finds the
            // orphaned value bytes.
            let pending = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("clean_restart"),
                pending: pending.clone(),
            };
            pending.arm();
            let completed = Arc::new(AtomicUsize::new(0));
            let completed_clone = completed.clone();
            let cfg_clone = cfg.clone();
            let task = context.child("clean_restart_task").spawn(|_| async move {
                let result = Archive::init(delayed.child("archive"), cfg_clone).await;
                completed_clone.store(1, Ordering::Relaxed);
                result
            });
            while pending.calls() == 0 && completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            if pending.calls() != 0 {
                pending.unblock();
                let _ = task.await;
                panic!("clean empty-section restart must not issue durability operations");
            }
            pending.unblock();
            let archive = task.await.unwrap().unwrap();

            // The repaired empty section accepts a fresh write at the reclaimed offsets, and
            // the write survives reopen.
            let archive = archive.put(0, test_key("new"), 20).await.unwrap();
            let archive = archive.sync().await.unwrap();
            drop(archive);
            let (_, value_size) = context
                .open(&cfg.value_partition, &0u64.to_be_bytes())
                .await
                .unwrap();
            assert_eq!(value_size, I32_VALUE_FRAME_SIZE);

            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(context.child("reopen"), cfg)
                .await
                .unwrap();
            assert_eq!(archive.get(Identifier::Index(0)).await.unwrap(), Some(20));
            archive.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_validation_marker_skips_previously_validated_values() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(&context, "marker-skip", NZU64!(4));

            // Seed two durable values with no published marker.
            let mut archive = Archive::init(context.child("seed"), cfg.clone())
                .await
                .unwrap();
            archive = archive.put(0, test_key("zero"), 10).await.unwrap();
            archive = archive.put(1, test_key("one"), 20).await.unwrap();
            archive = archive.sync().await.unwrap();
            drop(archive);

            // Simulate an archive created before validation markers existed. The first open
            // scans every retained value and writes the additive sidecar:
            //
            // first open:  [value 0] [value 1] -> validate 2
            // second open: [marker covers both] -> validate 0
            context.remove(&cfg.metadata_partition, None).await.unwrap();
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(
                context.child("first_open"),
                cfg.clone(),
            )
            .await
            .unwrap();
            assert_eq!(archive.ranges().collect::<Vec<_>>(), vec![(0, 1)]);
            drop(archive);

            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(
                context.child("second_open"),
                cfg.clone(),
            )
            .await
            .unwrap();
            assert_eq!(archive.get(Identifier::Index(0)).await.unwrap(), Some(10));
            assert_eq!(archive.get(Identifier::Index(1)).await.unwrap(), Some(20));

            // Append a third value above the marker. Its boundary stays debt, so the third open
            // must validate the suffix and adopt the covered pair into one contiguous range.
            let archive = archive.put(2, test_key("two"), 30).await.unwrap();
            let archive = archive.sync().await.unwrap();
            drop(archive);

            let archive =
                Archive::<_, _, FixedBytes<64>, i32>::init(context.child("third_open"), cfg)
                    .await
                    .unwrap();
            assert_eq!(archive.ranges().collect::<Vec<_>>(), vec![(0, 2)]);
            assert_eq!(archive.get(Identifier::Index(0)).await.unwrap(), Some(10));
            assert_eq!(archive.get(Identifier::Index(1)).await.unwrap(), Some(20));
            assert_eq!(archive.get(Identifier::Index(2)).await.unwrap(), Some(30));
        });
    }

    #[test_traced]
    fn test_validation_marker_skips_covered_interior_values() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = test_config(&context, "marker-covered-interior", NZU64!(4));

            // Publish a boundary covering both values. The terminal value remains the floor's
            // cross-journal proof. The earlier value must not be revisited during startup.
            let archive = Archive::init(context.child("seed"), cfg.clone())
                .await
                .unwrap();
            let archive = archive.put(0, test_key("zero"), 10).await.unwrap();
            let archive = archive.put(1, test_key("one"), 20).await.unwrap();

            // The first sync proves the data durable. The second publishes the resulting marker.
            let archive = archive.sync().await.unwrap();
            let archive = archive.sync().await.unwrap();
            drop(archive);

            // Damage only the covered interior frame. Initialization succeeds because the marker
            // skips it, while a direct read still exposes its invalid checksum.
            corrupt_frame(
                &context,
                &cfg.value_partition,
                &0u64.to_be_bytes(),
                0,
                I32_VALUE_FRAME_SIZE,
            )
            .await;
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(context.child("reopen"), cfg)
                .await
                .unwrap();
            assert!(archive.get(Identifier::Index(0)).await.is_err());
            assert_eq!(archive.get(Identifier::Index(1)).await.unwrap(), Some(20));
        });
    }

    #[test_traced]
    fn test_validation_marker_damage_never_mutates() {
        #[derive(Clone, Copy)]
        enum Damage {
            MissingIndex,
            MissingValues,
            TruncatedIndex,
            TruncatedValues,
            CorruptIndex,
            CorruptValues,
        }

        deterministic::Runner::default().start(|context| async move {
            // Every shape damages data at or below a published marker. Marked bytes were proven
            // durable before publication, so startup must treat their loss as corruption (or
            // leave it to lazy reads) without mutating either journal.
            for (name, damage) in [
                ("missing_index", Damage::MissingIndex),
                ("missing_values", Damage::MissingValues),
                ("truncated_index", Damage::TruncatedIndex),
                ("truncated_values", Damage::TruncatedValues),
                ("corrupt_index", Damage::CorruptIndex),
                ("corrupt_values", Damage::CorruptValues),
            ] {
                let case = context.child(name);
                let cfg = test_config(&case, name, NZU64!(4));

                // Seed one marked item: the blocking put proves it durable and the trailing
                // sync publishes its marker.
                let archive = Archive::init(case.child("seed"), cfg.clone())
                    .await
                    .unwrap();
                let archive = archive.put_sync(0, test_key("zero"), 10).await.unwrap();
                let archive = archive.sync().await.unwrap();
                drop(archive);

                // The marker proves that both journals contained one durable validated item:
                //
                // metadata: section 0 -> 1
                // index:    section 0 -> [record]
                // values:   section 0 -> [frame]
                //
                // Prune removes the marker durably before either journal, so missing or truncated
                // marked data is corruption, not an interrupted prune.
                let (_, index_size) = context
                    .open(&cfg.key_partition, &0u64.to_be_bytes())
                    .await
                    .unwrap();
                let (_, value_size) = context
                    .open(&cfg.value_partition, &0u64.to_be_bytes())
                    .await
                    .unwrap();
                let damage_index = matches!(
                    damage,
                    Damage::MissingIndex | Damage::TruncatedIndex | Damage::CorruptIndex
                );
                let damaged_partition = if damage_index {
                    &cfg.key_partition
                } else {
                    &cfg.value_partition
                };
                let damaged_size = match damage {
                    Damage::MissingIndex | Damage::MissingValues => {
                        context
                            .remove(damaged_partition, Some(&0u64.to_be_bytes()))
                            .await
                            .unwrap();
                        None
                    }
                    Damage::TruncatedIndex | Damage::TruncatedValues => {
                        let (blob, size) = context
                            .open(damaged_partition, &0u64.to_be_bytes())
                            .await
                            .unwrap();
                        let size = if damage_index { size - 1 } else { 0 };
                        blob.resize(size).await.unwrap();
                        blob.sync().await.unwrap();
                        Some(size)
                    }
                    Damage::CorruptIndex | Damage::CorruptValues => {
                        let (blob, size) = context
                            .open(damaged_partition, &0u64.to_be_bytes())
                            .await
                            .unwrap();
                        let byte = blob
                            .read_at(0, 1, ReadOptions::default())
                            .await
                            .unwrap()
                            .coalesce();
                        let byte = byte.as_ref()[0];
                        blob.write_at(0, vec![byte ^ 0xFF], WriteOptions::SYNC)
                            .await
                            .unwrap();
                        Some(size)
                    }
                };

                // Marked values are never re-read at startup: value damage that preserves the
                // floor's byte range surfaces lazily at get, like covered interior values.
                if matches!(damage, Damage::CorruptValues) {
                    for child in ["first", "second"] {
                        let archive = Archive::<_, _, FixedBytes<64>, i32>::init(
                            case.child(child),
                            cfg.clone(),
                        )
                        .await
                        .expect("marked value damage must not fail startup");
                        assert!(archive.get(Identifier::Index(0)).await.is_err());
                        drop(archive);
                        let (_, size) = context
                            .open(&cfg.value_partition, &0u64.to_be_bytes())
                            .await
                            .unwrap();
                        assert_eq!(size, value_size, "adoption must preserve the damaged frame");
                    }
                    continue;
                }

                // Failed startups must be byte-stable across repeated opens: rejection happens
                // before any repair could mutate the marked section.
                for child in ["first", "second"] {
                    let result =
                        Archive::<_, _, FixedBytes<64>, i32>::init(case.child(child), cfg.clone())
                            .await;
                    assert!(
                        matches!(result, Err(Error::Journal(JournalError::Corruption(_)))),
                        "damaged marked section must remain visible as corruption"
                    );

                    let (surviving_partition, surviving_size) = if damage_index {
                        (&cfg.value_partition, value_size)
                    } else {
                        (&cfg.key_partition, index_size)
                    };
                    let (_, size) = context
                        .open(surviving_partition, &0u64.to_be_bytes())
                        .await
                        .unwrap();
                    assert_eq!(
                        size, surviving_size,
                        "failed startup must preserve the surviving journal section"
                    );
                    if let Some(damaged_size) = damaged_size {
                        let (_, size) = context
                            .open(damaged_partition, &0u64.to_be_bytes())
                            .await
                            .unwrap();
                        assert_eq!(
                            size, damaged_size,
                            "failed startup must not normalize the damaged journal section"
                        );
                    }
                }
            }
        });
    }

    #[test_traced]
    fn test_validation_floor_rejection_precedes_index_suffix_repair() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = test_config(&context, "floor-order", NZU64!(4));

            // Seed one marked item: the blocking put proves it durable and the trailing sync
            // publishes its marker.
            let archive =
                Archive::<_, _, FixedBytes<64>, i32>::init(context.child("seed"), cfg.clone())
                    .await
                    .unwrap();
            let archive = archive.put_sync(0, test_key("zero"), 10).await.unwrap();
            let archive = archive.sync().await.unwrap();
            drop(archive);

            // Append trailing junk past the index tail. Alone, this is repairable damage that
            // suffix repair would truncate on the next open.
            let (index, index_size) = context
                .open(&cfg.key_partition, &0u64.to_be_bytes())
                .await
                .unwrap();
            index
                .write_at(index_size, vec![0xA5; 7], WriteOptions::SYNC)
                .await
                .unwrap();
            let expected_size = index_size + 7;

            // Break the floor's terminal index page so preflight rejects the section before
            // the repairable trailing junk can be truncated.
            let byte = index
                .read_at(0, 1, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            index
                .write_at(0, vec![byte.as_ref()[0] ^ 0xFF], WriteOptions::SYNC)
                .await
                .unwrap();
            let expected = index
                .read_at(0, expected_size as usize, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            drop(index);

            // Repeated failed opens must leave the section byte-identical, junk included: the
            // floor check rejects the section before suffix repair can truncate anything.
            for child in ["first", "second"] {
                let result =
                    Archive::<_, _, FixedBytes<64>, i32>::init(context.child(child), cfg.clone())
                        .await;
                assert!(matches!(
                    result,
                    Err(Error::Journal(JournalError::Corruption(_)))
                ));

                let (index, actual_size) = context
                    .open(&cfg.key_partition, &0u64.to_be_bytes())
                    .await
                    .unwrap();
                assert_eq!(actual_size, expected_size);
                let actual = index
                    .read_at(0, actual_size as usize, ReadOptions::default())
                    .await
                    .unwrap()
                    .coalesce();
                assert_eq!(actual.as_ref(), expected.as_ref());
            }
        });
    }

    #[test_traced]
    fn test_validation_marker_survives_torn_index_tail_rewrite() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let cfg = test_config(&context, "marker-torn-tail", NZU64!(4));
            let archive = Archive::init(context.child("seed"), cfg.clone())
                .await
                .unwrap();

            // Publish a marker for one record while its index occupies only part of the first page.
            let archive = archive.put_sync(0, test_key("zero"), 10).await.unwrap();
            let archive = archive.sync().await.unwrap();

            // A physical page is the logical page plus a two-slot trailer, where each slot is a
            // two-byte length and a four-byte checksum over that length's prefix of the page:
            //
            //   [ records ... pad ......][len0 crc0][len1 crc1]
            //   0               page_size         +6        +12
            //
            // The first write filled slot 0 for one record and left slot 1 zeroed.
            let page_size = usize::from(PAGE_SIZE.get());
            let physical_page_size = page_size + 12;
            let record_size = u64::SIZE + FixedBytes::<64>::SIZE + u64::SIZE + u32::SIZE;
            assert!(record_size < page_size);
            let (index, size) = context
                .open(&cfg.key_partition, &0u64.to_be_bytes())
                .await
                .unwrap();
            assert_eq!(size, physical_page_size as u64);
            let old_page = index
                .read_at(0, physical_page_size, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            let old_page = old_page.as_ref().to_vec();
            drop(index);
            let old_len =
                u16::from_be_bytes(old_page[page_size..page_size + 2].try_into().unwrap()) as usize;
            let old_crc =
                u32::from_be_bytes(old_page[page_size + 2..page_size + 6].try_into().unwrap());
            assert_eq!(old_len, record_size);
            assert_eq!(old_crc, Crc32::checksum(&old_page[..old_len]));

            // Capture Archive's same-page extension, then persist only the prefix through the new
            // slot's length. This is the exact Prefix fault cut: the old slot remains valid while
            // the new slot's checksum retains its prior zero bytes.
            let archive = archive.put_sync(1, test_key("one"), 20).await.unwrap();
            drop(archive);
            let (index, size) = context
                .open(&cfg.key_partition, &0u64.to_be_bytes())
                .await
                .unwrap();
            assert_eq!(size, physical_page_size as u64);
            let new_page = index
                .read_at(0, physical_page_size, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            let new_page = new_page.as_ref().to_vec();
            assert_eq!(
                &new_page[page_size..page_size + 6],
                &old_page[page_size..page_size + 6],
            );
            let new_len =
                u16::from_be_bytes(new_page[page_size + 6..page_size + 8].try_into().unwrap())
                    as usize;
            let new_crc =
                u32::from_be_bytes(new_page[page_size + 8..page_size + 12].try_into().unwrap());
            assert_eq!(new_len, 2 * record_size);
            assert_eq!(new_crc, Crc32::checksum(&new_page[..new_len]));

            // Restore the one-record image, then replay the extended image only through slot
            // 1's length. The stored page now holds both records' data, a valid slot 0 covering
            // one record, and a slot 1 that advertises two records with a stale zero checksum:
            //
            //   [ record 0 | record 1 | pad ][len0 crc0][len1 crc1]
            //     persisted prefix ends after len1 --------------^
            index
                .write_at(0, old_page.clone(), WriteOptions::SYNC)
                .await
                .unwrap();
            let torn_prefix = page_size + 6 + 2;
            index
                .write_at(0, new_page[..torn_prefix].to_vec(), WriteOptions::SYNC)
                .await
                .unwrap();
            let torn_page = index
                .read_at(0, physical_page_size, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            let torn_page = torn_page.as_ref();
            assert_eq!(
                &torn_page[page_size..page_size + 6],
                &old_page[page_size..page_size + 6],
            );
            assert_eq!(
                u16::from_be_bytes(torn_page[page_size + 6..page_size + 8].try_into().unwrap(),)
                    as usize,
                new_len,
            );
            let torn_crc =
                u32::from_be_bytes(torn_page[page_size + 8..page_size + 12].try_into().unwrap());
            assert_ne!(torn_crc, Crc32::checksum(&torn_page[..new_len]));
            drop(index);

            // Both value frames survive the torn index write, leaving recovery to decide which
            // bytes are orphaned.
            let (_, value_size) = context
                .open(&cfg.value_partition, &0u64.to_be_bytes())
                .await
                .unwrap();
            assert_eq!(value_size, 2 * I32_VALUE_FRAME_SIZE);
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let pending = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: pending.clone(),
            };
            pending.arm();
            let cfg = test_config(&delayed, "marker-torn-tail", NZU64!(4));

            // Recovery must trust the marker-covered record, select the older checksum slot, and
            // durably remove only the orphaned value suffix.
            let archive = drive_pending_syncs(
                &pending,
                Archive::<_, _, FixedBytes<64>, i32>::init(delayed.child("reopen"), cfg.clone()),
            )
            .await
            .unwrap();
            assert_eq!(pending.calls(), 1);
            assert_eq!(archive.last_index(), Some(0));
            assert_eq!(archive.ranges().collect::<Vec<_>>(), vec![(0, 0)]);
            assert_eq!(archive.get(Identifier::Index(0)).await.unwrap(), Some(10));
            assert_eq!(archive.get(Identifier::Index(1)).await.unwrap(), None);
            drop(archive);

            let (_, value_size) = context
                .open(&cfg.value_partition, &0u64.to_be_bytes())
                .await
                .unwrap();
            assert_eq!(value_size, I32_VALUE_FRAME_SIZE);
        });
    }

    #[test_traced]
    fn test_startup_publishes_validated_marker_without_data_resync() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = test_config(&context, "startup-order", NZU64!(4));

            // Seed one durable value with no published marker, so the next startup must
            // validate it and derive the marker itself.
            let archive = Archive::init(context.child("seed"), cfg.clone())
                .await
                .unwrap();
            let archive = archive.put(0, test_key("zero"), 10).await.unwrap();
            let archive = archive.sync().await.unwrap();
            drop(archive);

            // Reopen through the armed wrapper to count every durability operation startup
            // issues.
            let pending = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: pending.clone(),
            };
            pending.arm();
            let completed = Arc::new(AtomicUsize::new(0));
            let completed_clone = completed.clone();
            let reopen_cfg = cfg.clone();
            let task = context.child("startup").spawn(|_| async move {
                let result =
                    Archive::<_, _, FixedBytes<64>, i32>::init(delayed.child("reopen"), reopen_cfg)
                        .await;
                completed_clone.store(1, Ordering::Relaxed);
                result
            });

            while pending.calls() == 0 && completed.load(Ordering::Relaxed) == 0 {
                commonware_runtime::reschedule().await;
            }
            commonware_runtime::reschedule().await;

            // Startup-readable bytes are already durable. A clean reopen should start only the
            // derived marker and return while that metadata sync drives itself in the background.
            let calls = pending.calls();
            let finished = completed.load(Ordering::Relaxed);
            if calls != 1 || finished != 1 {
                pending.unblock();
                let _ = task.await;
                panic!(
                    "clean startup must return after starting one marker sync, calls={calls}, \
                     finished={finished}"
                );
            }

            pending.unblock();
            let archive = task.await.unwrap().unwrap().sync().await.unwrap();
            assert_eq!(archive.get(Identifier::Index(0)).await.unwrap(), Some(10));
            drop(archive);

            // The published marker must leave a reopenable archive.
            Archive::<_, _, FixedBytes<64>, i32>::init(context.child("marker_reopen"), cfg)
                .await
                .unwrap()
                .destroy()
                .await
                .unwrap();
        });
    }

    #[test_traced]
    fn test_startup_marker_failure_fails_next_sync() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = test_config(&context, "startup-marker-failure", NZU64!(4));

            // Seed one durable value with no published marker, so reopen must derive one.
            let archive = Archive::init(context.child("seed"), cfg.clone())
                .await
                .unwrap();
            let archive = archive.put(0, test_key("zero"), 10).await.unwrap();
            let archive = archive.sync().await.unwrap();
            drop(archive);

            // Reopen with the armed wrapper. The only durability operation startup issues is
            // the derived marker sync, left parked.
            let pending = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: pending.clone(),
            };
            pending.arm();
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(delayed.child("reopen"), cfg)
                .await
                .unwrap();
            assert_eq!(pending.lock().len(), 1);

            // A marker sync failure must not vanish: the next sync call observes the completed
            // generation and surfaces the failure as a metadata error.
            fail_pending_syncs(&pending);
            assert!(matches!(archive.sync().await, Err(Error::Metadata(_))));
        });
    }

    #[test_traced]
    fn test_start_sync_publishes_closed_section_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(&context, "marker-lag", NZU64!(4));

            let pending = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: pending.clone(),
            };
            let archive = Archive::init(delayed.child("archive"), cfg.clone())
                .await
                .unwrap();

            // The first call has no prior durability proof, so it starts only the index and value
            // syncs. Moving to section 4 closes section 0 and publishes its completed boundary
            // alongside the new section's data syncs:
            //
            // call 1: section 0 data durable, marker absent
            // call 2: section 4 data pending, section 0 marker pending
            let (archive, first) = archive
                .put_start_sync(0, test_key("zero"), 10)
                .await
                .unwrap();
            assert_eq!(pending.lock().len(), 2);
            release_pending_syncs(&pending);
            first.await.unwrap();

            let archive = archive.put(4, test_key("four"), 40).await.unwrap();
            let (archive, second) = archive.start_sync().await.unwrap();
            assert_eq!(pending.lock().len(), 3);
            release_pending_syncs(&pending);
            second.await.unwrap();
            drop(archive);

            // Reopen adopts section 0 through its published marker and validates section 4
            // above its absent one. Both items must survive.
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(
                context.child("first_reopen"),
                cfg.clone(),
            )
            .await
            .unwrap();
            assert_eq!(archive.ranges().collect::<Vec<_>>(), vec![(0, 0), (4, 4)]);
            drop(archive);

            Archive::<_, _, FixedBytes<64>, i32>::init(context.child("second_reopen"), cfg)
                .await
                .unwrap()
                .destroy()
                .await
                .unwrap();
        });
    }

    #[test_traced]
    fn test_sync_publishes_closed_section_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(&context, "blocking-marker-lag", NZU64!(4));

            let pending = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: pending.clone(),
            };
            let archive = Archive::init(delayed.child("archive"), cfg.clone())
                .await
                .unwrap();

            // Prove section 0's single item durable so its boundary becomes publishable debt.
            let (archive, first) = archive
                .put_start_sync(0, test_key("zero"), 10)
                .await
                .unwrap();
            assert_eq!(pending.lock().len(), 2);
            release_pending_syncs(&pending);
            first.await.unwrap();

            // Buffer section 4 and park its blocking sync behind the armed gate.
            let archive = archive.put(4, test_key("four"), 40).await.unwrap();
            pending.arm();
            let completed = Arc::new(AtomicUsize::new(0));
            let completed_clone = completed.clone();
            let task = delayed.inner.child("sync").spawn(|_| async move {
                let archive = archive.sync().await.unwrap();
                completed_clone.store(1, Ordering::Relaxed);
                archive
            });

            while pending.calls() < 2 {
                commonware_runtime::reschedule().await;
            }
            commonware_runtime::reschedule().await;

            // The marker for closed section 0 must start alongside section 4's data sync, rather
            // than after it:
            //
            // data:   section 4 [0 -------- 1)  <- current sync, two journals
            // marker: section 0 [0 -------- 1)  <- previous durable boundary
            let parked_syncs = pending.lock().len();
            if parked_syncs != 3 {
                // Let the spawned operation unwind before reporting the regression. Otherwise the
                // deterministic runner would correctly keep waiting for its parked durability work.
                pending.unblock();
                let _ = task.await;
                panic!(
                    "blocking sync must not serialize the derived marker behind data: \
                     parked {parked_syncs} durability operations"
                );
            }

            // The two data journals enqueue first. Release only the metadata operation to prove
            // that publishing the older boundary cannot satisfy the blocking data contract. The
            // marker future is polled only when a later request observes it, so this test
            // cannot wait for it to park before releasing it.
            let metadata = pending.lock().remove(2);
            metadata.release.send(Ok(())).unwrap();
            commonware_runtime::reschedule().await;
            assert_eq!(
                completed.load(Ordering::Relaxed),
                0,
                "publishing the previous marker must not complete the current data sync"
            );

            release_pending_syncs(&pending);
            let archive = task.await.unwrap();
            drop(archive);

            // Both items survive reopen: the published marker adopts section 0 and validation
            // covers section 4.
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(
                delayed.inner.child("first_reopen"),
                cfg.clone(),
            )
            .await
            .unwrap();
            assert_eq!(archive.get(Identifier::Index(0)).await.unwrap(), Some(10));
            assert_eq!(archive.get(Identifier::Index(4)).await.unwrap(), Some(40));
            drop(archive);

            Archive::<_, _, FixedBytes<64>, i32>::init(delayed.inner.child("second_reopen"), cfg)
                .await
                .unwrap()
                .destroy()
                .await
                .unwrap();
        });
    }

    #[test_traced]
    fn test_sync_delays_immediately_ready_durable_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Started durability operations complete immediately and are only counted.
            let pending = PendingSyncs::default();
            pending.unblock();
            let immediate = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_config(&immediate, "ready-marker-lag", NZU64!(4));

            let archive = Archive::init(immediate.child("archive"), cfg)
                .await
                .unwrap();
            let initial_starts = pending.starts();
            let archive = archive.put_sync(0, test_key("zero"), 10).await.unwrap();

            // The unblocked wrapper returns immediately-ready data-sync handles while retaining
            // the number of durability operations. The current boundary must still become
            // publication debt for the next sync, rather than making this call synchronously
            // persist a marker after its data:
            //
            // call 1: two data syncs, marker absent
            // call 2: no new data, one marker sync
            assert_eq!(pending.starts() - initial_starts, 2);

            let archive = archive.sync().await.unwrap();
            assert_eq!(pending.starts() - initial_starts, 3);
            archive.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_sync_batches_markers_by_active_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Started durability operations complete immediately and are only counted.
            let pending = PendingSyncs::default();
            pending.unblock();
            let immediate = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_config(&immediate, "section-marker-batch", NZU64!(4));
            let archive = Archive::init(immediate.child("archive"), cfg)
                .await
                .unwrap();
            let initial_starts = pending.starts();

            // Repeated writes in one active section start only the index and value durability
            // operations. Its marker remains debt until writes move to another section.
            let archive = archive.put_sync(0, test_key("zero"), 10).await.unwrap();
            let archive = archive.put_sync(1, test_key("one"), 20).await.unwrap();
            assert_eq!(pending.starts() - initial_starts, 4);

            // Moving to section 4 publishes section 0's completed boundary alongside the two data
            // operations for section 4. An explicit empty sync then flushes the final partial
            // section once. Another empty sync has no durability work.
            let archive = archive.put_sync(4, test_key("four"), 40).await.unwrap();
            assert_eq!(pending.starts() - initial_starts, 7);
            let archive = archive.sync().await.unwrap();
            assert_eq!(pending.starts() - initial_starts, 8);
            let archive = archive.sync().await.unwrap();
            assert_eq!(pending.starts() - initial_starts, 8);
            archive.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_start_sync_withholds_marker_for_unproven_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(&context, "marker-unproven-boundary", NZU64!(4));

            let pending = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: pending.clone(),
            };
            let archive = Archive::init(delayed.child("archive"), cfg.clone())
                .await
                .unwrap();

            // Prove section 0's single item so it owns publishable marker debt.
            let (archive, first) = archive
                .put_start_sync(0, test_key("zero"), 10)
                .await
                .unwrap();
            release_pending_syncs(&pending);
            first.await.unwrap();

            // Moving to section 4 starts its data syncs and publishes section 0's boundary.
            let archive = archive.put(4, test_key("four"), 40).await.unwrap();
            let (archive, second) = archive.start_sync().await.unwrap();
            assert_eq!(pending.lock().len(), 3);

            // Complete only the marker generation, which parked last. Section 4's data syncs
            // stay in flight, so nothing beyond its published floor is proven. Sync futures
            // are lazy, so the released marker resolves when the next request polls it.
            let marker = pending.lock().pop().expect("marker sync parked");
            marker
                .release
                .send(Ok(()))
                .expect("marker sync receiver dropped");

            // The next request observes the completed marker generation and retires caught-up
            // barriers. It must not manufacture a durability proof for section 4: publishing
            // its unproven length as a marker would let a crash that keeps the marker but
            // loses the in-flight items make every reopen fail. The two operations started
            // here are section 8's index and value syncs.
            let archive = archive.put(8, test_key("eight"), 80).await.unwrap();
            let before = pending.starts();
            let (archive, third) = archive.start_sync().await.unwrap();
            assert_eq!(pending.starts() - before, 2);

            release_pending_syncs(&pending);
            second.await.unwrap();
            third.await.unwrap();

            // Every boundary publishes once proven. A blocking sync flushes the remaining
            // debt and a reopen sees all three sections.
            let archive = drive_pending_syncs(&pending, archive.sync()).await.unwrap();
            drop(archive);
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(context.child("reopen"), cfg)
                .await
                .unwrap();
            assert_eq!(
                archive.ranges().collect::<Vec<_>>(),
                vec![(0, 0), (4, 4), (8, 8)]
            );
            archive.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_sync_publishes_previous_durable_sections_across_section_changes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(&context, "cross-section-marker-lag", NZU64!(1));

            let pending = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: pending.clone(),
            };
            let archive = Archive::init(delayed.child("archive"), cfg.clone())
                .await
                .unwrap();

            // Three items land in three single-item sections, each through its own blocking
            // sync.
            let archive = drive_pending_syncs(&pending, archive.put_sync(0, test_key("zero"), 10))
                .await
                .unwrap();
            let archive = drive_pending_syncs(&pending, archive.put_sync(1, test_key("one"), 20))
                .await
                .unwrap();
            let archive = drive_pending_syncs(&pending, archive.put_sync(2, test_key("two"), 30))
                .await
                .unwrap();
            drop(archive);

            // Every item occupies its own section. Each blocking sync publishes the preceding
            // call's completed section while synchronizing the current section:
            //
            // call 1: data section 0, marker absent
            // call 2: data section 1, marker section 0
            // call 3: data section 2, marker section 1
            //
            // Markers may trail durable data, but changing sections must not strand every earlier
            // proof and turn startup validation into an unbounded full-archive scan.
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(
                context.child("first_reopen"),
                cfg.clone(),
            )
            .await
            .unwrap();
            assert_eq!(archive.get(Identifier::Index(0)).await.unwrap(), Some(10));
            assert_eq!(archive.get(Identifier::Index(1)).await.unwrap(), Some(20));
            assert_eq!(archive.get(Identifier::Index(2)).await.unwrap(), Some(30));
            drop(archive);

            Archive::<_, _, FixedBytes<64>, i32>::init(context.child("second_reopen"), cfg)
                .await
                .unwrap()
                .destroy()
                .await
                .unwrap();
        });
    }

    #[test_traced]
    fn test_empty_sync_publishes_final_durable_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(&context, "empty-sync-marker", NZU64!(1));

            let pending = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: pending.clone(),
            };
            let archive = Archive::init(delayed.child("archive"), cfg.clone())
                .await
                .unwrap();

            // Seed one durable item. The two starts are section 0's index and value syncs.
            let archive = drive_pending_syncs(&pending, archive.put_sync(0, test_key("zero"), 10))
                .await
                .unwrap();
            assert_eq!(pending.starts(), 2);

            // A blocking sync with no new data flushes the final lagging marker without
            // re-synchronizing the already durable section:
            //
            // call 1: data section 0, marker absent
            // call 2: data absent,    marker section 0
            let archive = drive_pending_syncs(&pending, archive.sync()).await.unwrap();
            assert_eq!(pending.starts(), 3);

            // Once the marker completes, another empty sync has no durability work.
            let archive = drive_pending_syncs(&pending, archive.sync()).await.unwrap();
            assert_eq!(pending.starts(), 3);
            drop(archive);

            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(context.child("reopen"), cfg)
                .await
                .unwrap();
            assert_eq!(archive.get(Identifier::Index(0)).await.unwrap(), Some(10));
        });
    }

    #[test_traced]
    fn test_sync_recreates_settled_section_barrier() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(&context, "marker-recreate", NZU64!(2));

            let pending = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: pending.clone(),
            };
            let archive = Archive::init(delayed.child("archive"), cfg.clone())
                .await
                .unwrap();

            // Each successful call publishes the preceding section and retains the current one as
            // marker debt. Returning to section 0 must start its new barrier at the retained
            // one-item prefix rather than at zero.
            let archive = drive_pending_syncs(&pending, archive.put_sync(0, test_key("zero"), 10))
                .await
                .unwrap();
            assert_eq!(pending.starts(), 2);
            let archive = drive_pending_syncs(&pending, archive.put_sync(2, test_key("two"), 30))
                .await
                .unwrap();
            assert_eq!(pending.starts(), 5);
            let archive = drive_pending_syncs(&pending, archive.put_sync(1, test_key("one"), 20))
                .await
                .unwrap();
            assert_eq!(pending.starts(), 8);

            // Flush the final marker, then prove another empty sync has no retained work.
            let archive = drive_pending_syncs(&pending, archive.sync()).await.unwrap();
            assert_eq!(pending.starts(), 9);
            let archive = drive_pending_syncs(&pending, archive.sync()).await.unwrap();
            assert_eq!(pending.starts(), 9);
            drop(archive);

            // The recreated barrier's final marker covers section 0's full two-item prefix, so
            // a reopen sees every value.
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(context.child("reopen"), cfg)
                .await
                .unwrap();
            assert_eq!(archive.get(Identifier::Index(0)).await.unwrap(), Some(10));
            assert_eq!(archive.get(Identifier::Index(1)).await.unwrap(), Some(20));
            assert_eq!(archive.get(Identifier::Index(2)).await.unwrap(), Some(30));
        });
    }

    #[test_traced]
    fn test_prune_clears_validation_marker_before_section_reuse() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(&context, "marker-reuse", NZU64!(2));

            // Seed one marked item in section 0 (the trailing sync publishes its marker), then
            // prune the section away. Prune must remove the durable marker along with the data:
            // a surviving marker would make the next init fail by claiming a marked section
            // with no journals.
            let archive = Archive::init(context.child("seed"), cfg.clone())
                .await
                .unwrap();
            let archive = archive.put_sync(0, test_key("old"), 10).await.unwrap();
            let archive = archive.sync().await.unwrap();
            let archive = archive.prune(2).await.unwrap();
            drop(archive);

            // Reinitialization resets the in-memory prune floor, so section 0 can be created again
            // if the application does not reapply its durable floor. Make the replacement bytes
            // durable without a second sync call that could publish their new marker:
            //
            // old section 0: [position 0 -> 10] --prune--> absent
            // new section 0: [position 0 -> 20] --sync data only--> validate on reopen
            //
            // A stale marker from the old incarnation would incorrectly skip that validation.
            let pending = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: pending.clone(),
            };
            let archive = Archive::init(delayed.child("reuse"), cfg.clone())
                .await
                .unwrap();
            let archive = archive.put(0, test_key("new"), 20).await.unwrap();
            let (archive, handle) = archive.start_sync().await.unwrap();
            assert_eq!(pending.lock().len(), 2);
            release_pending_syncs(&pending);
            handle.await.unwrap();
            drop(archive);

            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(context.child("reopen"), cfg)
                .await
                .unwrap();
            assert_eq!(archive.get(Identifier::Index(0)).await.unwrap(), Some(20));
        });
    }

    #[test_traced]
    fn test_archive_compression_then_none() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the archive
            let cfg = Config {
                translator: FourCap,
                metadata_partition: "test-metadata".into(),
                key_partition: "test-index".into(),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value".into(),
                codec_config: (),
                compression: Some(3),
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(DEFAULT_ITEMS_PER_SECTION),
            };
            let mut archive = Archive::init(context.child("first"), cfg.clone())
                .await
                .expect("Failed to initialize archive");

            // Put the key-data pair
            let index = 1u64;
            let key = test_key("testkey");
            let data = 1;
            archive = archive
                .put(index, key.clone(), data)
                .await
                .expect("Failed to put data");

            // Sync and drop the archive
            let archive = archive.sync().await.expect("Failed to sync archive");
            drop(archive);

            // Initialize the archive again without compression.
            // Index journal replay succeeds (no compression), but value reads will fail.
            let cfg = Config {
                translator: FourCap,
                metadata_partition: "test-metadata".into(),
                key_partition: "test-index".into(),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value".into(),
                codec_config: (),
                compression: None,
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(DEFAULT_ITEMS_PER_SECTION),
            };
            let archive =
                Archive::<_, _, FixedBytes<64>, i32>::init(context.child("second"), cfg.clone())
                    .await
                    .unwrap();

            // Getting the value should fail because compression settings mismatch.
            // Without compression, the codec sees extra bytes after decoding the value
            // (because the compressed data doesn't match the expected format).
            let result: Result<Option<i32>, _> = archive.get(Identifier::Index(index)).await;
            assert!(matches!(
                result,
                Err(Error::Journal(JournalError::Codec(CodecError::ExtraData(
                    _
                ))))
            ));
        });
    }

    #[test_traced]
    fn test_archive_overlapping_key_basic() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the archive
            let cfg = Config {
                translator: FourCap,
                metadata_partition: "test-metadata".into(),
                key_partition: "test-index".into(),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value".into(),
                codec_config: (),
                compression: None,
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(DEFAULT_ITEMS_PER_SECTION),
            };
            let mut archive = Archive::init(context.child("storage"), cfg.clone())
                .await
                .expect("Failed to initialize archive");

            let index1 = 1u64;
            let key1 = test_key("keys1");
            let data1 = 1;
            let index2 = 2u64;
            let key2 = test_key("keys2");
            let data2 = 2;

            // Put the key-data pair
            archive = archive
                .put(index1, key1.clone(), data1)
                .await
                .expect("Failed to put data");

            // Put the key-data pair
            archive = archive
                .put(index2, key2.clone(), data2)
                .await
                .expect("Failed to put data");

            // Get the data back
            let retrieved = archive
                .get(Identifier::Key(&key1))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data1);

            // Get the data back
            let retrieved = archive
                .get(Identifier::Key(&key2))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data2);

            // Check metrics
            let buffer = context.encode();
            assert!(has_metric_value(&buffer, "items_tracked", 2));
            assert!(buffer.contains("unnecessary_reads_total 1"));
            assert!(buffer.contains("gets_total 2"));
        });
    }

    #[test_traced]
    fn test_archive_overlapping_key_multiple_sections() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the archive
            let cfg = Config {
                translator: FourCap,
                metadata_partition: "test-metadata".into(),
                key_partition: "test-index".into(),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value".into(),
                codec_config: (),
                compression: None,
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(DEFAULT_ITEMS_PER_SECTION),
            };
            let mut archive = Archive::init(context.child("storage"), cfg.clone())
                .await
                .expect("Failed to initialize archive");

            let index1 = 1u64;
            let key1 = test_key("keys1");
            let data1 = 1;
            let index2 = 2_000_000u64;
            let key2 = test_key("keys2");
            let data2 = 2;

            // Put the key-data pair
            archive = archive
                .put(index1, key1.clone(), data1)
                .await
                .expect("Failed to put data");

            // Put the key-data pair
            archive = archive
                .put(index2, key2.clone(), data2)
                .await
                .expect("Failed to put data");

            // Get the data back
            let retrieved = archive
                .get(Identifier::Key(&key1))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data1);

            // Get the data back
            let retrieved = archive
                .get(Identifier::Key(&key2))
                .await
                .expect("Failed to get data")
                .expect("Data not found");
            assert_eq!(retrieved, data2);
        });
    }

    #[test_traced]
    fn test_archive_prune_keys() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the archive
            let cfg = Config {
                translator: FourCap,
                metadata_partition: "test-metadata".into(),
                key_partition: "test-index".into(),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value".into(),
                codec_config: (),
                compression: None,
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(1), // no mask - each item is its own section
            };
            let mut archive = Archive::init(context.child("storage"), cfg.clone())
                .await
                .expect("Failed to initialize archive");

            // Insert multiple keys across different sections
            let keys = vec![
                (1u64, test_key("key1-blah"), 1),
                (2u64, test_key("key2-blah"), 2),
                (3u64, test_key("key3-blah"), 3),
                (4u64, test_key("key3-bleh"), 3),
                (5u64, test_key("key4-blah"), 4),
            ];

            for (index, key, data) in &keys {
                archive = archive
                    .put(*index, key.clone(), *data)
                    .await
                    .expect("Failed to put data");
            }

            // Check metrics
            let buffer = context.encode();
            assert!(has_metric_value(&buffer, "items_tracked", 5));

            // Prune sections less than 3
            archive = archive.prune(3).await.expect("Failed to prune");

            // Ensure keys 1 and 2 are no longer present
            for (index, key, data) in keys {
                let retrieved = archive
                    .get(Identifier::Key(&key))
                    .await
                    .expect("Failed to get data");
                if index < 3 {
                    assert!(retrieved.is_none());
                } else {
                    assert_eq!(retrieved.expect("Data not found"), data);
                }
            }

            // Check metrics
            let buffer = context.encode();
            assert!(has_metric_value(&buffer, "items_tracked", 3));
            assert!(has_metric_value(&buffer, "indices_pruned_total", 2));
            assert!(has_metric_value(&buffer, "pruned_total", 0)); // no lazy cleanup yet

            // Try to prune older section
            archive = archive.prune(2).await.expect("Failed to prune");

            // Try to prune current section again
            archive = archive.prune(3).await.expect("Failed to prune");

            // Trigger lazy removal of keys
            archive = archive
                .put(6, test_key("key2-blfh"), 5)
                .await
                .expect("Failed to put data");

            // Check metrics
            let buffer = context.encode();
            assert!(has_metric_value(&buffer, "items_tracked", 4)); // lazily remove one, add one
            assert!(has_metric_value(&buffer, "indices_pruned_total", 2));
            assert!(has_metric_value(&buffer, "pruned_total", 1));

            // A put below the prune floor is satisfied without storing
            let archive = archive
                .put(1, test_key("key1-blah"), 1)
                .await
                .expect("Failed to put below floor");
            assert_eq!(
                archive
                    .get(Identifier::Key(&test_key("key1-blah")))
                    .await
                    .expect("Failed to get data"),
                None
            );

            // With no earlier pending writes, the below-floor sync combinators complete without
            // storing the pruned item.
            let (archive, handle) = archive
                .put_start_sync(1, test_key("key1-blah"), 1)
                .await
                .expect("Failed to put_start_sync below floor");
            handle.await.expect("handle must resolve");
            let archive = archive
                .put_sync(2, test_key("key2-blfh"), 2)
                .await
                .expect("Failed to put_sync below floor");
            assert_eq!(archive.get(Identifier::Index(1)).await.unwrap(), None);
            assert_eq!(archive.get(Identifier::Index(2)).await.unwrap(), None);
        });
    }

    fn test_archive_keys_and_restart(num_keys: usize) -> String {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Initialize the archive
            let items_per_section = 256u64;
            let cfg = Config {
                translator: TwoCap,
                metadata_partition: "test-metadata".into(),
                key_partition: "test-index".into(),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value".into(),
                codec_config: (),
                compression: None,
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(items_per_section),
            };
            let mut archive = Archive::init(
                context.child("init").with_attribute("index", 1),
                cfg.clone(),
            )
            .await
            .expect("Failed to initialize archive");

            // Insert multiple keys across different sections
            let mut keys = BTreeMap::new();
            while keys.len() < num_keys {
                let index = keys.len() as u64;
                let mut key = [0u8; 64];
                context.fill(&mut key);
                let key = FixedBytes::<64>::decode(key.as_ref()).unwrap();
                let mut data = [0u8; 1024];
                context.fill(&mut data);
                let data = FixedBytes::<1024>::decode(data.as_ref()).unwrap();

                archive = archive
                    .put(index, key.clone(), data.clone())
                    .await
                    .expect("Failed to put data");
                keys.insert(key, (index, data));
            }

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

            // Check metrics
            let buffer = context.encode();
            assert!(has_metric_value(&buffer, "items_tracked", num_keys));
            assert!(has_metric_value(&buffer, "pruned_total", 0));

            // Sync and drop the archive
            let archive = archive.sync().await.expect("Failed to sync archive");
            drop(archive);

            // Reinitialize the archive
            let cfg = Config {
                translator: TwoCap,
                metadata_partition: "test-metadata".into(),
                key_partition: "test-index".into(),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value".into(),
                codec_config: (),
                compression: None,
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(items_per_section),
            };
            let mut archive = Archive::<_, _, _, FixedBytes<1024>>::init(
                context.child("init").with_attribute("index", 2),
                cfg.clone(),
            )
            .await
            .expect("Failed to initialize archive");

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

            // Prune first half
            let min = (keys.len() / 2) as u64;
            archive = archive.prune(min).await.expect("Failed to prune");

            // Ensure all keys can be retrieved that haven't been pruned
            let min = (min / items_per_section) * items_per_section;
            let mut removed = 0;
            for (key, (index, data)) in keys {
                if index >= min {
                    let retrieved = archive
                        .get(Identifier::Key(&key))
                        .await
                        .expect("Failed to get data")
                        .expect("Data not found");
                    assert_eq!(retrieved, data);

                    // Check range
                    let (current_end, start_next) = archive.next_gap(index);
                    assert_eq!(current_end.unwrap(), num_keys as u64 - 1);
                    assert!(start_next.is_none());
                } else {
                    let retrieved = archive
                        .get(Identifier::Key(&key))
                        .await
                        .expect("Failed to get data");
                    assert!(retrieved.is_none());
                    removed += 1;

                    // Check range
                    let (current_end, start_next) = archive.next_gap(index);
                    assert!(current_end.is_none());
                    assert_eq!(start_next.unwrap(), min);
                }
            }

            // Check metrics
            let buffer = context.encode();
            assert!(has_metric_value(
                &buffer,
                "items_tracked",
                num_keys - removed
            ));
            assert!(has_metric_value(&buffer, "indices_pruned_total", removed));
            assert!(has_metric_value(&buffer, "pruned_total", 0)); // have not lazily removed keys yet

            context.auditor().state()
        })
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_archive_many_keys_and_restart() {
        test_archive_keys_and_restart(100_000);
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_determinism() {
        let state1 = test_archive_keys_and_restart(5_000);
        let state2 = test_archive_keys_and_restart(5_000);
        assert_eq!(state1, state2);
    }

    /// Regression: when the same key is stored at multiple indices and the
    /// earlier index is pruned, a subsequent `get`/`has` by key must resolve
    /// to the surviving, non-pruned entry rather than report the pruned one.
    /// Callers such as consensus's marshal cache rely on this to retain a
    /// reproposal of the same block at a later index even after the
    /// earlier index's retention window closes.
    #[test_traced]
    fn test_archive_key_lookup_skips_pruned_duplicates() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                translator: FourCap,
                metadata_partition: "test-metadata".into(),
                key_partition: "test-index".into(),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value".into(),
                codec_config: (),
                compression: None,
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(1),
            };
            let mut archive = Archive::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize archive");

            // Same key stored at two different indices. Distinct values only
            // to make it observable which entry wins; a real caller would
            // store the same value (e.g. the same block) at both indices.
            let key = test_key("dupe-key");
            archive = archive.put(2, key.clone(), 20).await.unwrap();
            archive = archive.put(5, key.clone(), 50).await.unwrap();

            // Before pruning, either entry is a permitted answer per the
            // trait contract. The implementation happens to return the
            // earlier index, but we only assert a value is present.
            assert!(archive.get(Identifier::Key(&key)).await.unwrap().is_some());
            assert!(archive.has(Identifier::Key(&key)).await.unwrap());

            // Prune the earlier index (section 2). The later index must be
            // the sole surviving answer.
            archive = archive.prune(3).await.unwrap();
            let got = archive.get(Identifier::Key(&key)).await.unwrap();
            assert_eq!(
                got,
                Some(50),
                "key lookup must skip the pruned entry and return the surviving one"
            );
            assert!(archive.has(Identifier::Key(&key)).await.unwrap());

            // Prune past the later index too — now nothing survives.
            let archive = archive.prune(6).await.unwrap();
            assert_eq!(archive.get(Identifier::Key(&key)).await.unwrap(), None);
            assert!(!archive.has(Identifier::Key(&key)).await.unwrap());
        });
    }

    #[test_traced]
    fn test_get_all_after_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                translator: FourCap,
                metadata_partition: "test-metadata".into(),
                key_partition: "test-index".into(),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value".into(),
                codec_config: (),
                compression: None,
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(1),
            };
            let mut archive = Archive::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize archive");

            archive = archive.put_multi(1, test_key("aaa"), 10).await.unwrap();
            archive = archive.put_multi(1, test_key("bbb"), 20).await.unwrap();
            archive = archive.put_multi(3, test_key("ccc"), 30).await.unwrap();

            // Prune below index 3
            let archive = archive.prune(3).await.unwrap();

            // Pruned index returns None
            let all = archive.get_all(1).await.unwrap();
            assert_eq!(all, None);

            // Surviving index still works
            let all = archive.get_all(3).await.unwrap();
            assert_eq!(all, Some(vec![30]));
        });
    }

    #[test_traced]
    fn test_has_at() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let cfg = test_config(&context, "test", NZU64!(2));
            let mut archive = Archive::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize archive");

            // Vacant index
            assert!(!archive.has_at(1, &test_key("aaaa1")).await.unwrap());

            // Exact key at the index
            archive = archive.put_multi(1, test_key("aaaa1"), 10).await.unwrap();
            assert!(archive.has_at(1, &test_key("aaaa1")).await.unwrap());

            // Same key is not reported at other indices
            assert!(!archive.has_at(2, &test_key("aaaa1")).await.unwrap());

            // A translated-key collision (FourCap shares the "aaaa" prefix)
            // must not produce a false positive
            assert!(!archive.has_at(1, &test_key("aaaa2")).await.unwrap());

            // A second entry at the same index is visible alongside the first
            archive = archive.put_multi(1, test_key("aaaa2"), 20).await.unwrap();
            assert!(archive.has_at(1, &test_key("aaaa1")).await.unwrap());
            assert!(archive.has_at(1, &test_key("aaaa2")).await.unwrap());

            // A different key at an occupied index is absent
            assert!(!archive.has_at(1, &test_key("bbbb")).await.unwrap());

            archive = archive.put_multi(3, test_key("cccc"), 30).await.unwrap();
            archive.sync().await.unwrap();
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let cfg = test_config(&context, "test", NZU64!(2));
            let archive = Archive::<_, _, FixedBytes<64>, i32>::init(context.child("reopen"), cfg)
                .await
                .expect("Failed to reopen archive");

            // Replay rebuilds both entries at the shared index
            assert!(archive.has_at(1, &test_key("aaaa1")).await.unwrap());
            assert!(archive.has_at(1, &test_key("aaaa2")).await.unwrap());
            assert!(!archive.has_at(1, &test_key("bbbb")).await.unwrap());

            // Pruned indices report absent
            let archive = archive.prune(2).await.unwrap();
            assert!(!archive.has_at(1, &test_key("aaaa1")).await.unwrap());
            assert!(!archive.has_at(1, &test_key("aaaa2")).await.unwrap());
            assert!(archive.has_at(3, &test_key("cccc")).await.unwrap());

            archive.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_has_key() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(&context, "test", NZU64!(2));
            let mut archive = Archive::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize archive");

            // Absent key
            let key = test_key("aaaa1");
            assert!(!archive.has(Identifier::Key(&key)).await.unwrap());

            // Exact key
            archive = archive.put(1, key.clone(), 10).await.unwrap();
            assert!(archive.has(Identifier::Key(&key)).await.unwrap());

            // A translated-key collision (FourCap shares the "aaaa" prefix)
            // must not produce a false positive
            let collision = test_key("aaaa2");
            assert!(!archive.has(Identifier::Key(&collision)).await.unwrap());
            archive = archive.put(2, collision.clone(), 20).await.unwrap();
            assert!(archive.has(Identifier::Key(&collision)).await.unwrap());

            // Pruned keys report absent. Pruning is section-granular
            // (items_per_section = 2), so prune at a section boundary that
            // drops indices 1 and 2 while retaining index 4.
            archive = archive.put(4, test_key("cccc"), 30).await.unwrap();
            let archive = archive.prune(4).await.unwrap();
            assert!(!archive.has(Identifier::Key(&key)).await.unwrap());
            assert!(!archive.has(Identifier::Key(&collision)).await.unwrap());
            assert!(
                archive
                    .has(Identifier::Key(&test_key("cccc")))
                    .await
                    .unwrap()
            );

            archive.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_put_multi_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                translator: FourCap,
                metadata_partition: "test-metadata".into(),
                key_partition: "test-index".into(),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: "test-value".into(),
                codec_config: (),
                compression: None,
                key_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                value_write_buffer: NZUsize!(DEFAULT_WRITE_BUFFER),
                replay_buffer: NZUsize!(DEFAULT_REPLAY_BUFFER),
                items_per_section: NZU64!(1),
            };
            let mut archive = Archive::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize archive");

            // Two items at index 1, one at index 3
            archive = archive.put_multi(1, test_key("aaa"), 10).await.unwrap();
            archive = archive.put_multi(1, test_key("bbb"), 20).await.unwrap();
            archive = archive.put_multi(3, test_key("ccc"), 30).await.unwrap();

            let buffer = context.encode();
            assert!(has_metric_value(&buffer, "items_tracked", 2));

            // Prune below index 3
            let archive = archive.prune(3).await.unwrap();

            // Both items at index 1 are gone
            assert_eq!(
                archive
                    .get(Identifier::Key(&test_key("aaa")))
                    .await
                    .unwrap(),
                None
            );
            assert_eq!(
                archive
                    .get(Identifier::Key(&test_key("bbb")))
                    .await
                    .unwrap(),
                None
            );

            // Item at index 3 survives
            assert_eq!(
                archive
                    .get(Identifier::Key(&test_key("ccc")))
                    .await
                    .unwrap(),
                Some(30)
            );

            let buffer = context.encode();
            assert!(has_metric_value(&buffer, "items_tracked", 1));
            assert!(has_metric_value(&buffer, "indices_pruned_total", 1));

            // put_multi below the prune floor is satisfied without storing
            let archive = archive
                .put_multi(2, test_key("ddd"), 40)
                .await
                .expect("Failed to put below floor");
            assert_eq!(
                archive
                    .get(Identifier::Key(&test_key("ddd")))
                    .await
                    .expect("Failed to get data"),
                None
            );

            // With no earlier pending writes, put_multi_start_sync below the prune floor returns
            // a ready handle without storing the pruned item.
            let (archive, handle) = archive
                .put_multi_start_sync(2, test_key("ddd"), 41)
                .await
                .expect("Failed to put_multi_start_sync below floor");
            handle.await.expect("handle must resolve");
            assert_eq!(archive.get_all(2).await.expect("Failed to get data"), None);

            // put_multi_sync below the prune floor stores nothing.
            let archive = archive
                .put_multi_sync(2, test_key("ddd"), 42)
                .await
                .expect("Failed to put_multi_sync below floor");
            assert_eq!(archive.get_all(2).await.expect("Failed to get data"), None);
        });
    }
}

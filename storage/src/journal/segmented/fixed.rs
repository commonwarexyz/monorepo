//! Segmented journal for fixed-size items.
//!
//! # Format
//!
//! Data is stored in one blob per section. Within each blob, items are stored with
//! their checksum (CRC32):
//!
//! ```text
//! +--------+-----------+--------+-----------+--------+----------+-------------+
//! | item_0 | C(Item_0) | item_1 | C(Item_1) |   ...  | item_n-1 | C(Item_n-1) |
//! +--------+-----------+--------+-----------+--------+----------+-------------+
//!
//! C = CRC32
//! ```
//!
//! # Sync
//!
//! Data written to `Journal` may not be immediately persisted to `Storage`. Use the
//! `sync` method to force pending data to be written.
//!
//! # Pruning
//!
//! All data must be assigned to a `section`. This allows pruning entire sections
//! (and their corresponding blobs) independently.

use super::manager::{AppendFactory, Config as ManagerConfig, Manager};
use crate::journal::Error;
use bytes::BufMut;
use commonware_codec::{CodecFixed, DecodeExt as _, FixedSize};
use commonware_runtime::{
    buffer::{PoolRef, Read},
    Blob, Error as RError, Metrics, Storage,
};
use futures::{
    stream::{self, Stream},
    StreamExt,
};
use std::{marker::PhantomData, num::NonZeroUsize};
use tracing::{trace, warn};

/// Configuration for the fixed segmented journal.
#[derive(Clone)]
pub struct Config {
    /// The partition to use for storing blobs.
    pub partition: String,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,

    /// The size of the write buffer to use for each blob.
    pub write_buffer: NonZeroUsize,
}

/// A segmented journal with fixed-size entries.
///
/// Each section is stored in a separate blob. Within each blob, items are
/// fixed-size with a CRC32 checksum appended.
pub struct Journal<E: Storage + Metrics, A: CodecFixed> {
    manager: Manager<E, AppendFactory>,
    _array: PhantomData<A>,
}

impl<E: Storage + Metrics, A: CodecFixed<Cfg = ()>> Journal<E, A> {
    /// Size of each entry: item + CRC32 checksum.
    pub const CHUNK_SIZE: usize = A::SIZE + u32::SIZE;
    const CHUNK_SIZE_U64: u64 = Self::CHUNK_SIZE as u64;

    /// Initialize a new `Journal` instance.
    ///
    /// All backing blobs are opened but not read during initialization. Use `replay`
    /// to iterate over all items.
    ///
    /// # Repair
    ///
    /// Corrupted trailing data in blobs is automatically truncated during replay.
    pub async fn init(context: E, cfg: Config) -> Result<Self, Error> {
        let manager_cfg = ManagerConfig {
            partition: cfg.partition,
            factory: AppendFactory {
                write_buffer: cfg.write_buffer,
                pool_ref: cfg.buffer_pool,
            },
        };
        let manager = Manager::init(context, manager_cfg).await?;
        Ok(Self {
            manager,
            _array: PhantomData,
        })
    }

    /// Append a new item to the journal in the given section.
    ///
    /// Returns the position of the item within the section (0-indexed).
    pub async fn append(&mut self, section: u64, item: A) -> Result<u64, Error> {
        let blob = self.manager.get_or_create(section).await?;

        let size = blob.size().await;
        if !size.is_multiple_of(Self::CHUNK_SIZE_U64) {
            return Err(Error::InvalidBlobSize(section, size));
        }
        let position = size / Self::CHUNK_SIZE_U64;

        // Pre-allocate exact size and write directly to avoid copying
        let mut buf: Vec<u8> = Vec::with_capacity(Self::CHUNK_SIZE);
        item.write(&mut buf);
        let checksum = crc32fast::hash(&buf);
        buf.put_u32(checksum);

        blob.append(buf).await?;
        trace!(section, position, "appended item");

        Ok(position)
    }

    /// Read the item at the given section and position.
    ///
    /// # Errors
    ///
    /// - [Error::AlreadyPrunedToSection] if the section has been pruned.
    /// - [Error::SectionOutOfRange] if the section doesn't exist.
    /// - [Error::ItemOutOfRange] if the position is beyond the blob size.
    pub async fn get(&self, section: u64, position: u64) -> Result<A, Error> {
        let blob = self
            .manager
            .get(section)?
            .ok_or(Error::SectionOutOfRange(section))?;

        let offset = position
            .checked_mul(Self::CHUNK_SIZE_U64)
            .ok_or(Error::ItemOutOfRange(position))?;
        let end = offset
            .checked_add(Self::CHUNK_SIZE_U64)
            .ok_or(Error::ItemOutOfRange(position))?;
        if end > blob.size().await {
            return Err(Error::ItemOutOfRange(position));
        }

        let buf = blob.read_at(vec![0u8; Self::CHUNK_SIZE], offset).await?;
        Self::verify_integrity(buf.as_ref())
    }

    /// Read the last item in a section, if any.
    pub async fn last(&self, section: u64) -> Result<Option<A>, Error> {
        let blob = self
            .manager
            .get(section)?
            .ok_or(Error::SectionOutOfRange(section))?;

        let size = blob.size().await;
        if size < Self::CHUNK_SIZE_U64 {
            return Ok(None);
        }

        let last_position = (size / Self::CHUNK_SIZE_U64) - 1;
        let offset = last_position * Self::CHUNK_SIZE_U64;
        let buf = blob.read_at(vec![0u8; Self::CHUNK_SIZE], offset).await?;
        Self::verify_integrity(buf.as_ref()).map(Some)
    }

    /// Verify the integrity of the item + checksum in `buf`.
    fn verify_integrity(buf: &[u8]) -> Result<A, Error> {
        let stored_checksum =
            u32::from_be_bytes(buf[A::SIZE..].try_into().expect("checksum is 4 bytes"));
        let checksum = crc32fast::hash(&buf[..A::SIZE]);
        if checksum != stored_checksum {
            return Err(Error::ChecksumMismatch(stored_checksum, checksum));
        }
        A::decode(&buf[..A::SIZE]).map_err(Error::Codec)
    }

    /// Returns a stream of all items starting from the given section.
    ///
    /// Each item is returned as (section, position, item).
    ///
    /// # Repair
    ///
    /// Corrupted trailing data is automatically truncated.
    pub async fn replay(
        &self,
        start_section: u64,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, u64, A), Error>> + '_, Error> {
        let mut blob_info = Vec::new();
        for (&section, blob) in self.manager.sections_from(start_section) {
            let size = blob.size().await;
            blob_info.push((section, blob.clone(), size));
        }

        Ok(
            stream::iter(blob_info).flat_map(move |(section, blob, blob_size)| {
                let reader = Read::new(blob, blob_size, buffer);
                let buf = vec![0u8; Self::CHUNK_SIZE];

                stream::unfold(
                    (section, buf, reader, 0u64, 0u64),
                    move |(section, mut buf, mut reader, offset, valid_size)| async move {
                        if offset >= reader.blob_size() {
                            return None;
                        }

                        let position = offset / Self::CHUNK_SIZE_U64;
                        match reader.read_exact(&mut buf, Self::CHUNK_SIZE).await {
                            Ok(()) => {
                                let next_offset = offset + Self::CHUNK_SIZE_U64;
                                match Self::verify_integrity(&buf) {
                                    Ok(item) => Some((
                                        Ok((section, position, item)),
                                        (section, buf, reader, next_offset, next_offset),
                                    )),
                                    Err(Error::ChecksumMismatch(expected, found)) => {
                                        warn!(
                                            section,
                                            position,
                                            expected,
                                            found,
                                            new_size = valid_size,
                                            "corruption detected: truncating"
                                        );
                                        reader.resize(valid_size).await.ok()?;
                                        None
                                    }
                                    Err(err) => {
                                        Some((Err(err), (section, buf, reader, offset, valid_size)))
                                    }
                                }
                            }
                            Err(RError::BlobInsufficientLength) => {
                                warn!(
                                    section,
                                    position,
                                    new_size = valid_size,
                                    "trailing bytes detected: truncating"
                                );
                                reader.resize(valid_size).await.ok()?;
                                None
                            }
                            Err(err) => {
                                warn!(section, position, ?err, "unexpected error");
                                Some((
                                    Err(Error::Runtime(err)),
                                    (section, buf, reader, offset, valid_size),
                                ))
                            }
                        }
                    },
                )
            }),
        )
    }

    /// Sync the given section to storage.
    pub async fn sync(&self, section: u64) -> Result<(), Error> {
        self.manager.sync(section).await
    }

    /// Sync all sections to storage.
    pub async fn sync_all(&self) -> Result<(), Error> {
        self.manager.sync_all().await
    }

    /// Prune all sections less than `min`. Returns true if any were pruned.
    pub async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        self.manager.prune(min).await
    }

    /// Returns the oldest section number, if any blobs exist.
    pub fn oldest_section(&self) -> Option<u64> {
        self.manager.oldest_section()
    }

    /// Returns the newest section number, if any blobs exist.
    pub fn newest_section(&self) -> Option<u64> {
        self.manager.newest_section()
    }

    /// Returns an iterator over all section numbers.
    pub fn sections(&self) -> impl Iterator<Item = u64> + '_ {
        self.manager.sections_from(0).map(|(section, _)| *section)
    }

    /// Returns the number of items in the given section.
    pub async fn section_len(&self, section: u64) -> Result<u64, Error> {
        let size = self.manager.size(section).await?;
        Ok(size / Self::CHUNK_SIZE_U64)
    }

    /// Returns the byte size of the given section.
    pub async fn size(&self, section: u64) -> Result<u64, Error> {
        self.manager.size(section).await
    }

    /// Rewind the journal to a specific section and byte offset.
    ///
    /// This truncates the section to the given size. All sections
    /// after `section` are removed.
    pub async fn rewind(&mut self, section: u64, offset: u64) -> Result<(), Error> {
        self.manager.rewind(section, offset).await
    }

    /// Rewind only the given section to a specific byte offset.
    ///
    /// Unlike `rewind`, this does not affect other sections.
    pub async fn rewind_section(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.manager.rewind_section(section, size).await
    }

    /// Remove all underlying blobs.
    pub async fn destroy(self) -> Result<(), Error> {
        self.manager.destroy().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{sha256::Digest, Hasher as _, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
    use commonware_utils::NZUsize;
    use futures::{pin_mut, StreamExt};

    const PAGE_SIZE: NonZeroUsize = NZUsize!(44);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(3);

    fn test_digest(value: u64) -> Digest {
        Sha256::hash(&value.to_be_bytes())
    }

    fn test_cfg() -> Config {
        Config {
            partition: "test_partition".into(),
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: NZUsize!(2048),
        }
    }

    #[test_traced]
    fn test_segmented_fixed_append_and_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to init");

            let pos0 = journal
                .append(1, test_digest(0))
                .await
                .expect("failed to append");
            assert_eq!(pos0, 0);

            let pos1 = journal
                .append(1, test_digest(1))
                .await
                .expect("failed to append");
            assert_eq!(pos1, 1);

            let pos2 = journal
                .append(2, test_digest(2))
                .await
                .expect("failed to append");
            assert_eq!(pos2, 0);

            let item0 = journal.get(1, 0).await.expect("failed to get");
            assert_eq!(item0, test_digest(0));

            let item1 = journal.get(1, 1).await.expect("failed to get");
            assert_eq!(item1, test_digest(1));

            let item2 = journal.get(2, 0).await.expect("failed to get");
            assert_eq!(item2, test_digest(2));

            let err = journal.get(1, 2).await;
            assert!(matches!(err, Err(Error::ItemOutOfRange(2))));

            let err = journal.get(3, 0).await;
            assert!(matches!(err, Err(Error::SectionOutOfRange(3))));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to init");

            for i in 0u64..10 {
                journal
                    .append(1, test_digest(i))
                    .await
                    .expect("failed to append");
            }
            for i in 10u64..20 {
                journal
                    .append(2, test_digest(i))
                    .await
                    .expect("failed to append");
            }

            journal.sync_all().await.expect("failed to sync");
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("failed to re-init");

            let items = {
                let stream = journal
                    .replay(0, NZUsize!(1024))
                    .await
                    .expect("failed to replay");
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((section, pos, item)) => items.push((section, pos, item)),
                        Err(err) => panic!("replay error: {err}"),
                    }
                }
                items
            };

            assert_eq!(items.len(), 20);
            for (i, item) in items.iter().enumerate().take(10) {
                assert_eq!(item.0, 1);
                assert_eq!(item.1, i as u64);
                assert_eq!(item.2, test_digest(i as u64));
            }
            for (i, item) in items.iter().enumerate().skip(10).take(10) {
                assert_eq!(item.0, 2);
                assert_eq!(item.1, (i - 10) as u64);
                assert_eq!(item.2, test_digest(i as u64));
            }

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to init");

            for section in 1u64..=5 {
                journal
                    .append(section, test_digest(section))
                    .await
                    .expect("failed to append");
            }
            journal.sync_all().await.expect("failed to sync");

            journal.prune(3).await.expect("failed to prune");

            let err = journal.get(1, 0).await;
            assert!(matches!(err, Err(Error::AlreadyPrunedToSection(3))));

            let err = journal.get(2, 0).await;
            assert!(matches!(err, Err(Error::AlreadyPrunedToSection(3))));

            let item = journal.get(3, 0).await.expect("should exist");
            assert_eq!(item, test_digest(3));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_rewind() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to init");

            // Create sections 1, 2, 3
            for section in 1u64..=3 {
                journal
                    .append(section, test_digest(section))
                    .await
                    .expect("failed to append");
            }
            journal.sync_all().await.expect("failed to sync");

            // Verify all sections exist
            for section in 1u64..=3 {
                let size = journal.size(section).await.expect("failed to get size");
                assert!(size > 0, "section {section} should have data");
            }

            // Rewind to section 1 (should remove sections 2, 3)
            let size = journal.size(1).await.expect("failed to get size");
            journal.rewind(1, size).await.expect("failed to rewind");

            // Verify section 1 still has data
            let size = journal.size(1).await.expect("failed to get size");
            assert!(size > 0, "section 1 should still have data");

            // Verify sections 2, 3 are removed
            for section in 2u64..=3 {
                let size = journal.size(section).await.expect("failed to get size");
                assert_eq!(size, 0, "section {section} should be removed");
            }

            // Verify data in section 1 is still readable
            let item = journal.get(1, 0).await.expect("failed to get");
            assert_eq!(item, test_digest(1));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_rewind_many_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to init");

            // Create sections 1-10
            for section in 1u64..=10 {
                journal
                    .append(section, test_digest(section))
                    .await
                    .expect("failed to append");
            }
            journal.sync_all().await.expect("failed to sync");

            // Rewind to section 5 (should remove sections 6-10)
            let size = journal.size(5).await.expect("failed to get size");
            journal.rewind(5, size).await.expect("failed to rewind");

            // Verify sections 1-5 still have data
            for section in 1u64..=5 {
                let size = journal.size(section).await.expect("failed to get size");
                assert!(size > 0, "section {section} should still have data");
            }

            // Verify sections 6-10 are removed
            for section in 6u64..=10 {
                let size = journal.size(section).await.expect("failed to get size");
                assert_eq!(size, 0, "section {section} should be removed");
            }

            // Verify data integrity via replay
            {
                let stream = journal
                    .replay(0, NZUsize!(1024))
                    .await
                    .expect("failed to replay");
                pin_mut!(stream);
                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, _, item) = result.expect("failed to read");
                    items.push((section, item));
                }
                assert_eq!(items.len(), 5);
                for (i, (section, item)) in items.iter().enumerate() {
                    assert_eq!(*section, (i + 1) as u64);
                    assert_eq!(*item, test_digest((i + 1) as u64));
                }
            }

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_rewind_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create sections 1-5
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to init");
            for section in 1u64..=5 {
                journal
                    .append(section, test_digest(section))
                    .await
                    .expect("failed to append");
            }
            journal.sync_all().await.expect("failed to sync");

            // Rewind to section 2
            let size = journal.size(2).await.expect("failed to get size");
            journal.rewind(2, size).await.expect("failed to rewind");
            journal.sync_all().await.expect("failed to sync");
            drop(journal);

            // Re-init and verify only sections 1-2 exist
            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("failed to re-init");

            // Verify sections 1-2 have data
            for section in 1u64..=2 {
                let size = journal.size(section).await.expect("failed to get size");
                assert!(size > 0, "section {section} should have data after restart");
            }

            // Verify sections 3-5 are gone
            for section in 3u64..=5 {
                let size = journal.size(section).await.expect("failed to get size");
                assert_eq!(size, 0, "section {section} should be gone after restart");
            }

            // Verify data integrity
            let item1 = journal.get(1, 0).await.expect("failed to get");
            assert_eq!(item1, test_digest(1));
            let item2 = journal.get(2, 0).await.expect("failed to get");
            assert_eq!(item2, test_digest(2));

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_corruption_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to init");

            for i in 0u64..5 {
                journal
                    .append(1, test_digest(i))
                    .await
                    .expect("failed to append");
            }
            journal.sync_all().await.expect("failed to sync");
            drop(journal);

            let (blob, size) = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .expect("failed to open blob");
            blob.resize(size - 1).await.expect("failed to truncate");
            blob.sync().await.expect("failed to sync");

            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("failed to re-init");

            let count = {
                let stream = journal
                    .replay(0, NZUsize!(1024))
                    .await
                    .expect("failed to replay");
                pin_mut!(stream);

                let mut count = 0;
                while let Some(result) = stream.next().await {
                    result.expect("should be ok");
                    count += 1;
                }
                count
            };
            assert_eq!(count, 4);

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate journal
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to init");

            for i in 0u64..5 {
                journal
                    .append(1, test_digest(i))
                    .await
                    .expect("failed to append");
            }
            journal.sync_all().await.expect("failed to sync");
            drop(journal);

            // Reopen and verify data persisted
            let journal = Journal::<_, Digest>::init(context.clone(), cfg)
                .await
                .expect("failed to re-init");

            for i in 0u64..5 {
                let item = journal.get(1, i).await.expect("failed to get");
                assert_eq!(item, test_digest(i));
            }

            journal.destroy().await.expect("failed to destroy");
        });
    }

    #[test_traced]
    fn test_segmented_fixed_section_len() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to init");

            assert_eq!(journal.section_len(1).await.unwrap(), 0);

            for i in 0u64..5 {
                journal
                    .append(1, test_digest(i))
                    .await
                    .expect("failed to append");
            }

            assert_eq!(journal.section_len(1).await.unwrap(), 5);
            assert_eq!(journal.section_len(2).await.unwrap(), 0);

            journal.destroy().await.expect("failed to destroy");
        });
    }
}

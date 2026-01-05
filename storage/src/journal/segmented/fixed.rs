//! A segmented append-only log for storing fixed-length items.
//!
//! `fixed::Journal` combines the fixed-size entry format of `contiguous/fixed` with
//! the section-based organization of `segmented/variable`. This is ideal for storing
//! index entries that need to be pruned in sync with variable-size data journals.
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
//! # Use Case
//!
//! This journal is designed for key index entries that need to be stored separately
//! from large values. The fixed-size entries provide excellent cache locality since
//! many entries fit in each buffer pool page.
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

use crate::journal::Error;
use bytes::BufMut;
use commonware_codec::{CodecFixed, DecodeExt as _, FixedSize};
use commonware_runtime::{
    buffer::{Append, PoolRef, Read},
    telemetry::metrics::status::GaugeExt,
    Blob, Error as RError, Metrics, Storage,
};
use commonware_utils::hex;
use futures::{
    stream::{self, Stream},
    StreamExt,
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::{collections::BTreeMap, marker::PhantomData, num::NonZeroUsize};
use tracing::{debug, trace, warn};

/// Configuration for `Journal` storage.
#[derive(Clone)]
pub struct Config {
    /// The `commonware-runtime::Storage` partition to use for storing journal blobs.
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
    context: E,
    cfg: Config,

    /// Stores one blob per section.
    blobs: BTreeMap<u64, Append<E::Blob>>,

    /// A section number before which all sections have been pruned.
    oldest_retained_section: u64,

    tracked: Gauge,
    synced: Counter,
    pruned: Counter,

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
        let mut blobs = BTreeMap::new();
        let stored_blobs = match context.scan(&cfg.partition).await {
            Ok(blobs) => blobs,
            Err(RError::PartitionMissing(_)) => Vec::new(),
            Err(err) => return Err(Error::Runtime(err)),
        };

        for name in stored_blobs {
            let (blob, size) = context.open(&cfg.partition, &name).await?;
            let hex_name = hex(&name);
            let section = match name.try_into() {
                Ok(section) => u64::from_be_bytes(section),
                Err(_) => return Err(Error::InvalidBlobName(hex_name)),
            };
            debug!(section, blob = hex_name, size, "loaded section");
            let blob = Append::new(blob, size, cfg.write_buffer, cfg.buffer_pool.clone()).await?;
            blobs.insert(section, blob);
        }

        let tracked = Gauge::default();
        let synced = Counter::default();
        let pruned = Counter::default();
        context.register("tracked", "Number of blobs", tracked.clone());
        context.register("synced", "Number of syncs", synced.clone());
        context.register("pruned", "Number of blobs pruned", pruned.clone());
        let _ = tracked.try_set(blobs.len());

        Ok(Self {
            context,
            cfg,
            blobs,
            oldest_retained_section: 0,
            tracked,
            synced,
            pruned,
            _array: PhantomData,
        })
    }

    /// Ensures that a section pruned during the current execution is not accessed.
    const fn prune_guard(&self, section: u64) -> Result<(), Error> {
        if section < self.oldest_retained_section {
            Err(Error::AlreadyPrunedToSection(self.oldest_retained_section))
        } else {
            Ok(())
        }
    }

    /// Append a new item to the journal in the given section.
    ///
    /// Returns the position of the item within the section (0-indexed).
    pub async fn append(&mut self, section: u64, item: A) -> Result<u32, Error> {
        self.prune_guard(section)?;

        let blob = match self.blobs.get_mut(&section) {
            Some(blob) => blob,
            None => {
                let name = section.to_be_bytes();
                let (blob, size) = self.context.open(&self.cfg.partition, &name).await?;
                let blob = Append::new(
                    blob,
                    size,
                    self.cfg.write_buffer,
                    self.cfg.buffer_pool.clone(),
                )
                .await?;
                self.tracked.inc();
                self.blobs.entry(section).or_insert(blob)
            }
        };

        let size = blob.size().await;
        if !size.is_multiple_of(Self::CHUNK_SIZE_U64) {
            return Err(Error::InvalidBlobSize(section, size));
        }
        let position = (size / Self::CHUNK_SIZE_U64) as u32;

        let mut buf: Vec<u8> = Vec::with_capacity(Self::CHUNK_SIZE);
        let encoded = item.encode();
        let checksum = crc32fast::hash(&encoded);
        buf.extend_from_slice(&encoded);
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
    pub async fn get(&self, section: u64, position: u32) -> Result<A, Error> {
        self.prune_guard(section)?;

        let blob = self
            .blobs
            .get(&section)
            .ok_or(Error::SectionOutOfRange(section))?;

        let offset = position as u64 * Self::CHUNK_SIZE_U64;
        if offset + Self::CHUNK_SIZE_U64 > blob.size().await {
            return Err(Error::ItemOutOfRange(position as u64));
        }

        let buf = blob.read_at(vec![0u8; Self::CHUNK_SIZE], offset).await?;
        Self::verify_integrity(buf.as_ref())
    }

    /// Verify the integrity of the item + checksum in `buf`.
    fn verify_integrity(buf: &[u8]) -> Result<A, Error> {
        let stored_checksum = u32::from_be_bytes(buf[A::SIZE..].try_into().unwrap());
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
    ) -> Result<impl Stream<Item = Result<(u64, u32, A), Error>> + '_, Error> {
        let mut blob_info = Vec::new();
        for (&section, blob) in self.blobs.range(start_section..) {
            let size = blob.size().await;
            blob_info.push((section, blob.clone_blob(), size));
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

                        let position = (offset / Self::CHUNK_SIZE_U64) as u32;
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
        self.prune_guard(section)?;
        if let Some(blob) = self.blobs.get(&section) {
            self.synced.inc();
            blob.sync().await.map_err(Error::Runtime)?;
        }
        Ok(())
    }

    /// Sync all sections to storage.
    pub async fn sync_all(&self) -> Result<(), Error> {
        for blob in self.blobs.values() {
            self.synced.inc();
            blob.sync().await.map_err(Error::Runtime)?;
        }
        Ok(())
    }

    /// Prune all sections less than `min`. Returns true if any were pruned.
    pub async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        let mut pruned = false;
        while let Some((&section, _)) = self.blobs.first_key_value() {
            if section >= min {
                break;
            }

            let blob = self.blobs.remove(&section).unwrap();
            let size = blob.size().await;
            drop(blob);

            self.context
                .remove(&self.cfg.partition, Some(&section.to_be_bytes()))
                .await?;
            pruned = true;

            debug!(section, size, "pruned blob");
            self.tracked.dec();
            self.pruned.inc();
        }

        if pruned {
            self.oldest_retained_section = min;
        }

        Ok(pruned)
    }

    /// Returns the oldest section number, if any blobs exist.
    pub fn oldest_section(&self) -> Option<u64> {
        self.blobs.first_key_value().map(|(&s, _)| s)
    }

    /// Returns the number of items in the given section.
    pub async fn section_len(&self, section: u64) -> Result<u32, Error> {
        self.prune_guard(section)?;
        match self.blobs.get(&section) {
            Some(blob) => {
                let size = blob.size().await;
                Ok((size / Self::CHUNK_SIZE_U64) as u32)
            }
            None => Ok(0),
        }
    }

    /// Returns the byte size of the given section.
    pub async fn size(&self, section: u64) -> Result<u64, Error> {
        self.prune_guard(section)?;
        match self.blobs.get(&section) {
            Some(blob) => Ok(blob.size().await),
            None => Ok(0),
        }
    }

    /// Rewind the journal to a specific section and byte offset.
    ///
    /// This truncates the section to the given size. All sections
    /// after `section` are removed.
    pub async fn rewind(&mut self, section: u64, offset: u64) -> Result<(), Error> {
        // Remove all sections after this one
        let sections_to_remove: Vec<u64> =
            self.blobs.range((section + 1)..).map(|(&s, _)| s).collect();

        for s in sections_to_remove {
            let blob = self.blobs.remove(&s).unwrap();
            drop(blob);
            self.context
                .remove(&self.cfg.partition, Some(&s.to_be_bytes()))
                .await?;
            self.tracked.dec();
            debug!(section = s, "removed blob during rewind");
        }

        // Resize the target section if it exists
        if let Some(blob) = self.blobs.get(&section) {
            let current_size = blob.size().await;
            if offset < current_size {
                blob.resize(offset).await?;
                debug!(
                    section,
                    old_size = current_size,
                    new_size = offset,
                    "rewound blob"
                );
            }
        }

        Ok(())
    }

    /// Remove all underlying blobs.
    pub async fn destroy(self) -> Result<(), Error> {
        for (section, blob) in self.blobs.into_iter() {
            let size = blob.size().await;
            drop(blob);
            debug!(section, size, "destroyed blob");
            self.context
                .remove(&self.cfg.partition, Some(&section.to_be_bytes()))
                .await?;
        }
        match self.context.remove(&self.cfg.partition, None).await {
            Ok(()) => {}
            Err(RError::PartitionMissing(_)) => {}
            Err(err) => return Err(Error::Runtime(err)),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{sha256::Digest, Hasher as _, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};
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
                assert_eq!(item.1, i as u32);
                assert_eq!(item.2, test_digest(i as u64));
            }
            for (i, item) in items.iter().enumerate().skip(10).take(10) {
                assert_eq!(item.0, 2);
                assert_eq!(item.1, (i - 10) as u32);
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

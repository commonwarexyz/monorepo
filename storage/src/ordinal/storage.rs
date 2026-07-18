use super::{Config, Error};
use crate::{rmap::RMap, Context};
use commonware_codec::{CodecFixed, Encode, FixedSize, Read, ReadExt, Write as CodecWrite};
use commonware_cryptography::{crc32, Crc32};
use commonware_formatting::hex;
use commonware_runtime::{
    buffer::{Read as ReadBuffer, Write},
    telemetry::metrics::{Counter, MetricsExt as _},
    Buf, BufMut, BufferPooler, Error as RError,
};
use commonware_utils::bitmap::BitMap;
use futures::future::try_join_all;
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    marker::PhantomData,
};
use tracing::debug;

/// Value stored in the index file.
#[derive(Debug, Clone)]
struct Record<V: CodecFixed<Cfg = ()>> {
    value: V,
    crc: u32,
}

impl<V: CodecFixed<Cfg = ()>> Record<V> {
    fn new(value: V) -> Self {
        let crc = Crc32::checksum(&value.encode());
        Self { value, crc }
    }

    fn is_valid(&self) -> bool {
        self.crc == Crc32::checksum(&self.value.encode())
    }
}

impl<V: CodecFixed<Cfg = ()>> FixedSize for Record<V> {
    const SIZE: usize = V::SIZE + crc32::Digest::SIZE;
}

impl<V: CodecFixed<Cfg = ()>> CodecWrite for Record<V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.value.write(buf);
        self.crc.write(buf);
    }
}

impl<V: CodecFixed<Cfg = ()>> Read for Record<V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let value = V::read(buf)?;
        let crc = u32::read(buf)?;

        Ok(Self { value, crc })
    }
}

#[cfg(feature = "arbitrary")]
impl<V: CodecFixed<Cfg = ()>> arbitrary::Arbitrary<'_> for Record<V>
where
    V: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let value = V::arbitrary(u)?;
        Ok(Self::new(value))
    }
}

/// Implementation of [Ordinal].
pub struct Ordinal<E: BufferPooler + Context, V: CodecFixed<Cfg = ()>> {
    // Configuration and context
    context: E,
    config: Config,

    // Index blobs for storing key records
    blobs: BTreeMap<u64, Write<E::Blob>>,

    // RMap for interval tracking
    intervals: RMap,

    // Pending sections to be synced.
    pending: BTreeSet<u64>,

    // Metrics
    puts: Counter,
    gets: Counter,
    has: Counter,
    syncs: Counter,
    pruned: Counter,

    _phantom: PhantomData<V>,
}

impl<E: BufferPooler + Context, V: CodecFixed<Cfg = ()>> Ordinal<E, V> {
    /// Initialize a new [Ordinal] instance with a collection of [BitMap]s (indicating which
    /// records should be considered available).
    ///
    /// If a section is not provided in the [BTreeMap], all records in that section are considered
    /// unavailable. If a [BitMap] is provided for a section, all records in that section are
    /// considered available if and only if the [BitMap] is set for the record. If a section is provided
    /// but no [BitMap] is populated, all records in that section are considered available.
    ///
    /// Passing `Some(BTreeMap::new())` or `None` removes all stored sections and starts empty.
    pub async fn init(
        context: E,
        config: Config,
        bits: Option<BTreeMap<u64, &Option<BitMap>>>,
    ) -> Result<Self, Error> {
        // Reset the store unless committed bits are provided to recover from the stored blobs
        let record_size = Record::<V>::SIZE as u64;
        let items_per_blob = config.items_per_blob.get();
        let mut blobs = BTreeMap::new();
        let stored_blobs = if bits.is_none() {
            match context.remove(&config.partition, None).await {
                Ok(()) | Err(RError::PartitionMissing(_)) => Vec::new(),
                Err(err) => return Err(Error::Runtime(err)),
            }
        } else {
            match context.scan(&config.partition).await {
                Ok(blobs) => blobs,
                Err(RError::PartitionMissing(_)) => Vec::new(),
                Err(err) => return Err(Error::Runtime(err)),
            }
        };

        // Open all blobs and check for partial records
        for name in stored_blobs {
            let (blob, len) = context.open(&config.partition, &name).await?;
            let index = match name.try_into() {
                Ok(index) => u64::from_be_bytes(index),
                Err(nm) => Err(Error::InvalidBlobName(hex(&nm)))?,
            };

            // The storage backend guarantees per-blob atomic sync, so torn
            // writes cannot survive a crash: a size that is not a record
            // multiple is corruption or tampering
            if len % record_size != 0 {
                return Err(Error::Corruption(format!(
                    "section {index} size {len} is not a multiple of record size {record_size}"
                )));
            }

            debug!(blob = index, len, "found index blob");
            blobs.insert(index, (blob, len));
        }

        // Initialize intervals by scanning committed records
        debug!(
            blobs = blobs.len(),
            "rebuilding intervals from existing index"
        );
        let start = context.current();
        let mut items = 0;
        let mut intervals = RMap::new();
        if let Some(bits) = &bits {
            // Drop sections the committed bits do not cover: every removal lands in
            // ONE atomic commit
            let sections_to_remove: Vec<u64> = blobs
                .keys()
                .filter(|section| match bits.get(section) {
                    Some(Some(bits)) => bits.count_ones() == 0,
                    Some(None) => false,
                    None => true,
                })
                .copied()
                .collect();
            if !sections_to_remove.is_empty() {
                let mut batch = context.batch().await.map_err(Error::Runtime)?;
                for &section in &sections_to_remove {
                    let blob = blobs.remove(&section).expect("collected from keys");
                    drop(blob);
                    commonware_runtime::WriteBatch::remove(
                        &mut batch,
                        &config.partition,
                        Some(&section.to_be_bytes()),
                    );
                }
                commonware_runtime::WriteBatch::apply_sync(batch)
                    .await
                    .map_err(Error::Runtime)?;
            }

            // Rebuild intervals from the committed records
            for (section, bits) in bits {
                if let Some(bits) = bits {
                    if bits.count_ones() == 0 {
                        continue;
                    }
                }

                let Some((blob, size)) = blobs.get(section) else {
                    return Err(Error::MissingRecord(section * items_per_blob));
                };

                // A section replays every record unless a bitmap restricts replay
                // to the records it marks
                let mut set_indices = bits.as_ref().map(|bits| bits.ones_iter());
                let mut all_indices = 0..items_per_blob;
                let mut replay_blob =
                    ReadBuffer::from_pooler(&context, blob.clone(), *size, config.replay_buffer);
                while let Some(bit_index) = set_indices
                    .as_mut()
                    .map_or_else(|| all_indices.next(), |indices| indices.next())
                {
                    let index = section * items_per_blob + bit_index;
                    if bit_index >= items_per_blob {
                        return Err(Error::MissingRecord(index));
                    }
                    let offset = bit_index * record_size;
                    if offset + record_size > *size {
                        return Err(Error::MissingRecord(index));
                    }

                    // A committed record that is missing or invalid cannot be recovered
                    replay_blob.seek_to(offset)?;
                    let mut record_buf = replay_blob.read(Record::<V>::SIZE).await?;
                    if let Ok(record) = Record::<V>::read(&mut record_buf) {
                        if record.is_valid() {
                            items += 1;
                            intervals.insert(index);
                            continue;
                        }
                    }
                    return Err(Error::MissingRecord(index));
                }
            }
        }
        debug!(
            items,
            elapsed = ?context.current().duration_since(start).unwrap_or_default(),
            "rebuilt intervals"
        );

        // Wrap blobs in write buffers
        let blobs = blobs
            .into_iter()
            .map(|(index, (blob, len))| {
                (
                    index,
                    Write::from_pooler(&context, blob, len, config.write_buffer),
                )
            })
            .collect();

        // Initialize metrics
        let puts = context.counter("puts", "Number of put calls");
        let gets = context.counter("gets", "Number of get calls");
        let has = context.counter("has", "Number of has calls");
        let syncs = context.counter("syncs", "Number of sync calls");
        let pruned = context.counter("pruned", "Number of pruned blobs");

        Ok(Self {
            context,
            config,
            blobs,
            intervals,
            pending: BTreeSet::new(),
            puts,
            gets,
            has,
            syncs,
            pruned,
            _phantom: PhantomData,
        })
    }

    /// Add a value at the specified index (pending until sync).
    pub async fn put(&mut self, index: u64, value: V) -> Result<(), Error> {
        self.puts.inc();

        // Check if blob exists
        let items_per_blob = self.config.items_per_blob.get();
        let section = index / items_per_blob;
        if let Entry::Vacant(entry) = self.blobs.entry(section) {
            // Stage the blob's creation in a creation-only batch, published WITHOUT
            // a commit: its entry becomes durable at the next commit (records are
            // pending until sync anyway), or a crash before one erases the section
            // together with its unsynced records
            let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
            let blob = commonware_runtime::WriteBatch::create(
                &mut batch,
                &self.config.partition,
                &section.to_be_bytes(),
            )
            .await?;
            commonware_runtime::WriteBatch::apply(batch)
                .await
                .map_err(Error::Runtime)?;
            entry.insert(Write::from_pooler(
                &self.context,
                blob,
                0,
                self.config.write_buffer,
            ));
            debug!(section, "created blob");
        }

        // Write the value to the blob
        let blob = self.blobs.get_mut(&section).unwrap();
        let offset = (index % items_per_blob) * Record::<V>::SIZE as u64;
        let record = Record::new(value);
        blob.write_at(offset, record.encode_mut()).await?;
        self.pending.insert(section);

        // Add to intervals
        self.intervals.insert(index);

        Ok(())
    }

    /// Get the value for a given index.
    pub async fn get(&self, index: u64) -> Result<Option<V>, Error> {
        self.gets.inc();

        // If get isn't in an interval, it doesn't exist and we don't need to access disk
        if self.intervals.get(&index).is_none() {
            return Ok(None);
        }

        // Read from disk
        let items_per_blob = self.config.items_per_blob.get();
        let section = index / items_per_blob;
        let blob = self.blobs.get(&section).unwrap();
        let offset = (index % items_per_blob) * Record::<V>::SIZE as u64;
        let mut read_buf = blob.read_at(offset, Record::<V>::SIZE).await?;
        let record = Record::<V>::read(&mut read_buf)?;

        // If record is valid, return it
        if record.is_valid() {
            Ok(Some(record.value))
        } else {
            Err(Error::InvalidRecord(index))
        }
    }

    /// Check if an index exists.
    pub fn has(&self, index: u64) -> bool {
        self.has.inc();

        self.intervals.get(&index).is_some()
    }

    /// Get the next gap information for backfill operations.
    pub fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.intervals.next_gap(index)
    }

    /// Get an iterator over all ranges in the [Ordinal].
    pub fn ranges(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.intervals.iter().map(|(&s, &e)| (s, e))
    }

    /// Get an iterator over ranges that overlap or follow `from`.
    pub fn ranges_from(&self, from: u64) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.intervals.iter_from(from).map(|(&s, &e)| (s, e))
    }

    /// Retrieve the first index in the [Ordinal].
    pub fn first_index(&self) -> Option<u64> {
        self.intervals.first_index()
    }

    /// Retrieve the last index in the [Ordinal].
    pub fn last_index(&self) -> Option<u64> {
        self.intervals.last_index()
    }

    /// Returns up to `max` missing items starting from `start`.
    ///
    /// This method iterates through gaps between existing ranges, collecting missing indices
    /// until either `max` items are found or there are no more gaps to fill.
    pub fn missing_items(&self, start: u64, max: usize) -> Vec<u64> {
        self.intervals.missing_items(start, max)
    }

    /// Prune indices older than `min` by removing entire blobs: every removal lands in ONE
    /// atomic commit.
    ///
    /// Pruning is done at blob boundaries to avoid partial deletions. A blob is pruned only if
    /// all possible indices in that blob are less than `min`.
    pub async fn prune(&mut self, min: u64) -> Result<(), Error> {
        // Collect sections to remove
        let items_per_blob = self.config.items_per_blob.get();
        let min_section = min / items_per_blob;
        let sections_to_remove: Vec<u64> = self
            .blobs
            .keys()
            .filter(|&&section| section < min_section)
            .copied()
            .collect();

        // Stage the collected sections' removals in one batch
        if !sections_to_remove.is_empty() {
            let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
            for &section in &sections_to_remove {
                let blob = self.blobs.remove(&section).expect("collected from keys");
                drop(blob);
                commonware_runtime::WriteBatch::remove(
                    &mut batch,
                    &self.config.partition,
                    Some(&section.to_be_bytes()),
                );

                // Remove the corresponding index range from intervals
                let start_index = section * items_per_blob;
                let end_index = (section + 1) * items_per_blob - 1;
                self.intervals.remove(start_index, end_index);
                debug!(section, start_index, end_index, "pruned blob");

                // Update metrics
                self.pruned.inc();
            }
            commonware_runtime::WriteBatch::apply_sync(batch)
                .await
                .map_err(Error::Runtime)?;
        }

        // Clean pending entries that fall into pruned sections.
        self.pending.retain(|&section| section >= min_section);

        Ok(())
    }

    /// Write all pending entries and sync all modified [commonware_runtime::Blob]s.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.syncs.inc();

        if self.pending.is_empty() {
            return Ok(());
        }

        let futures: Vec<_> = self
            .blobs
            .iter_mut()
            .filter(|(section, _)| self.pending.contains(section))
            .map(|(_, blob)| blob.sync())
            .collect();
        try_join_all(futures).await?;

        // Clear pending sections.
        self.pending.clear();

        Ok(())
    }

    /// Write all pending entries and stage the modified [commonware_runtime::Blob]s' durability
    /// with `batch`.
    pub async fn sync_into<T: commonware_runtime::WriteBatch<Blob = E::Blob>>(
        &mut self,
        batch: &mut T,
    ) -> Result<(), Error> {
        self.syncs.inc();

        if self.pending.is_empty() {
            return Ok(());
        }
        let pending = &self.pending;
        for (_, blob) in self
            .blobs
            .iter_mut()
            .filter(|(section, _)| pending.contains(section))
        {
            blob.sync_into(batch).await?;
        }
        self.pending.clear();
        Ok(())
    }

    /// Destroy [Ordinal] and remove all data, in ONE atomic commit.
    pub async fn destroy(self) -> Result<(), Error> {
        let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
        self.destroy_into(&mut batch).await?;
        commonware_runtime::WriteBatch::apply_sync(batch)
            .await
            .map_err(Error::Runtime)
    }

    /// [Self::destroy], staged with `batch`: every blob's removal and the partition's land
    /// when the caller applies the batch with `apply_sync`, atomically with everything else
    /// it stages.
    pub(crate) async fn destroy_into<T: commonware_runtime::WriteBatch<Blob = E::Blob>>(
        self,
        batch: &mut T,
    ) -> Result<(), Error> {
        drop(self.blobs);
        // The partition may never have been created (an ordinal that never held a record);
        // staging its removal would then fail the whole batch.
        match self.context.scan(&self.config.partition).await {
            Ok(_) => batch.remove(&self.config.partition, None),
            Err(RError::PartitionMissing(_)) => {}
            Err(err) => return Err(Error::Runtime(err)),
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use commonware_codec::conformance::CodecConformance;

    commonware_conformance::conformance_tests! {
        CodecConformance<Record<u32>>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::deterministic::Context;

    type TestOrdinal = Ordinal<Context, u64>;

    fn is_send<T: Send>(_: T) {}

    #[allow(dead_code)]
    fn assert_ordinal_futures_are_send(ordinal: &mut TestOrdinal, key: u64) {
        is_send(ordinal.get(key));
        is_send(ordinal.put(key, 0u64));
    }

    #[allow(dead_code)]
    fn assert_ordinal_destroy_is_send(ordinal: TestOrdinal) {
        is_send(ordinal.destroy());
    }
}

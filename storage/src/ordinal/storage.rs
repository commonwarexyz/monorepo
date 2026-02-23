use super::{Config, Error};
use crate::{kv, rmap::RMap, Persistable};
use commonware_codec::{
    CodecFixed, CodecFixedShared, Encode, FixedSize, Read, ReadExt, Write as CodecWrite,
};
use commonware_cryptography::{crc32, Crc32};
use commonware_runtime::{
    buffer::{Read as ReadBuffer, Write},
    Blob, Buf, BufMut, BufferPooler, Clock, Error as RError, Metrics, Storage,
};
use commonware_utils::{bitmap::BitMap, hex, sync::AsyncMutex};
use futures::future::try_join_all;
use prometheus_client::metrics::counter::Counter;
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    marker::PhantomData,
};
use tracing::{debug, warn};

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
pub struct Ordinal<E: BufferPooler + Storage + Metrics + Clock, V: CodecFixed<Cfg = ()>> {
    // Configuration and context
    context: E,
    config: Config,

    // Index blobs for storing key records
    blobs: BTreeMap<u64, Write<E::Blob>>,

    // RMap for interval tracking
    intervals: RMap,

    // Pending sections to be synced. The async mutex serializes
    // concurrent sync calls so a second sync cannot return before
    // the first has finished flushing.
    pending: AsyncMutex<BTreeSet<u64>>,

    // Metrics
    puts: Counter,
    gets: Counter,
    has: Counter,
    syncs: Counter,
    pruned: Counter,

    _phantom: PhantomData<V>,
}

impl<E: BufferPooler + Storage + Metrics + Clock, V: CodecFixed<Cfg = ()>> Ordinal<E, V> {
    /// Initialize a new [Ordinal] instance.
    pub async fn init(context: E, config: Config) -> Result<Self, Error> {
        Self::init_with_bits(context, config, None).await
    }

    /// Initialize a new [Ordinal] instance with a collection of [BitMap]s (indicating which
    /// records should be considered available).
    ///
    /// If a section is not provided in the [BTreeMap], all records in that section are considered
    /// unavailable. If a [BitMap] is provided for a section, all records in that section are
    /// considered available if and only if the [BitMap] is set for the record. If a section is provided
    /// but no [BitMap] is populated, all records in that section are considered available.
    // TODO(#1227): Hide this complexity from the caller.
    pub async fn init_with_bits(
        context: E,
        config: Config,
        bits: Option<BTreeMap<u64, &Option<BitMap>>>,
    ) -> Result<Self, Error> {
        // Scan for all blobs in the partition
        let mut raw_blobs = BTreeMap::new();
        let stored_blobs = match context.scan(&config.partition).await {
            Ok(blobs) => blobs,
            Err(commonware_runtime::Error::PartitionMissing(_)) => Vec::new(),
            Err(err) => return Err(Error::Runtime(err)),
        };

        // Open all blobs and check for partial records
        for name in stored_blobs {
            let (blob, mut len) = context.open(&config.partition, &name).await?;
            let index = match name.try_into() {
                Ok(index) => u64::from_be_bytes(index),
                Err(nm) => Err(Error::InvalidBlobName(hex(&nm)))?,
            };

            // Check if blob size is aligned to record size
            let record_size = Record::<V>::SIZE as u64;
            if len % record_size != 0 {
                warn!(
                    blob = index,
                    invalid_size = len,
                    record_size,
                    "blob size is not a multiple of record size, truncating"
                );
                len -= len % record_size;
                blob.resize(len).await?;
                blob.sync().await?;
            }

            debug!(blob = index, len, "found index blob");
            raw_blobs.insert(index, (blob, len));
        }

        // Initialize intervals by scanning existing records
        debug!(
            blobs = raw_blobs.len(),
            "rebuilding intervals from existing index"
        );
        let start = context.current();
        let mut items = 0;
        let mut intervals = RMap::new();
        for (section, (blob, size)) in &raw_blobs {
            // Skip if bits are provided and the section is not in the bits
            if let Some(bits) = &bits {
                if !bits.contains_key(section) {
                    warn!(section, "skipping section without bits");
                    continue;
                }
            }
            let mut replay_blob =
                ReadBuffer::from_pooler(&context, blob.clone(), *size, config.replay_buffer);

            // Iterate over all records in the blob
            let mut offset = 0;
            let items_per_blob = config.items_per_blob.get();
            while offset < *size {
                // Calculate index for this record
                let index = section * items_per_blob + (offset / Record::<V>::SIZE as u64);

                // If bits are provided, skip if not set
                let mut must_exist = false;
                if let Some(bits) = &bits {
                    // If bits are provided, check if the record exists
                    let bits = bits.get(section).unwrap();
                    if let Some(bits) = bits {
                        let bit_index = offset as usize / Record::<V>::SIZE;
                        if !bits.get(bit_index as u64) {
                            offset += Record::<V>::SIZE as u64;
                            continue;
                        }
                    }

                    // If bit section exists but it is empty, we must have all records
                    must_exist = true;
                }

                // Attempt to read record at offset
                replay_blob.seek_to(offset)?;
                let mut read_buf = replay_blob.read_exact(Record::<V>::SIZE).await?;
                offset += Record::<V>::SIZE as u64;

                // If record is valid, add to intervals
                if let Ok(record) = Record::<V>::read(&mut read_buf) {
                    if record.is_valid() {
                        items += 1;
                        intervals.insert(index);
                        continue;
                    }
                };

                // If record is invalid, it may either be empty or corrupted. We only care
                // which is which if the provided bits indicate that the record must exist.
                if must_exist {
                    return Err(Error::MissingRecord(index));
                }
            }
        }
        debug!(
            items,
            elapsed = ?context.current().duration_since(start).unwrap_or_default(),
            "rebuilt intervals"
        );

        let mut blobs = BTreeMap::new();
        for (index, (blob, len)) in raw_blobs {
            let wrapped_blob = Write::from_pooler(&context, blob, len, config.write_buffer);
            blobs.insert(index, wrapped_blob);
        }

        // Initialize metrics
        let puts = Counter::default();
        let gets = Counter::default();
        let has = Counter::default();
        let syncs = Counter::default();
        let pruned = Counter::default();
        context.register("puts", "Number of put calls", puts.clone());
        context.register("gets", "Number of get calls", gets.clone());
        context.register("has", "Number of has calls", has.clone());
        context.register("syncs", "Number of sync calls", syncs.clone());
        context.register("pruned", "Number of pruned blobs", pruned.clone());

        Ok(Self {
            context,
            config,
            blobs,
            intervals,
            pending: AsyncMutex::new(BTreeSet::new()),
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
            let (blob, len) = self
                .context
                .open(&self.config.partition, &section.to_be_bytes())
                .await?;
            entry.insert(Write::from_pooler(
                &self.context,
                blob,
                len,
                self.config.write_buffer,
            ));
            debug!(section, "created blob");
        }

        // Write the value to the blob
        let blob = self.blobs.get(&section).unwrap();
        let offset = (index % items_per_blob) * Record::<V>::SIZE as u64;
        let record = Record::new(value);
        blob.write_at(offset, record.encode_mut()).await?;
        self.pending.lock().await.insert(section);

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

    /// Prune indices older than `min` by removing entire blobs.
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

        // Remove the collected sections
        for section in sections_to_remove {
            if let Some(blob) = self.blobs.remove(&section) {
                drop(blob);
                self.context
                    .remove(&self.config.partition, Some(&section.to_be_bytes()))
                    .await?;

                // Remove the corresponding index range from intervals
                let start_index = section * items_per_blob;
                let end_index = (section + 1) * items_per_blob - 1;
                self.intervals.remove(start_index, end_index);
                debug!(section, start_index, end_index, "pruned blob");
            }

            // Update metrics
            self.pruned.inc();
        }

        // Clean pending entries that fall into pruned sections.
        self.pending
            .lock()
            .await
            .retain(|&section| section >= min_section);

        Ok(())
    }

    /// Write all pending entries and sync all modified [Blob]s.
    pub async fn sync(&self) -> Result<(), Error> {
        self.syncs.inc();

        // Hold the lock across the entire flush so a concurrent sync
        // cannot return before durability is established.
        let mut pending = self.pending.lock().await;
        if pending.is_empty() {
            return Ok(());
        }

        let mut futures = Vec::with_capacity(pending.len());
        for section in pending.iter() {
            futures.push(self.blobs.get(section).unwrap().sync());
        }
        try_join_all(futures).await?;

        // Clear pending sections.
        pending.clear();

        Ok(())
    }

    /// Destroy [Ordinal] and remove all data.
    pub async fn destroy(self) -> Result<(), Error> {
        for (i, blob) in self.blobs.into_iter() {
            drop(blob);
            self.context
                .remove(&self.config.partition, Some(&i.to_be_bytes()))
                .await?;
            debug!(section = i, "destroyed blob");
        }
        match self.context.remove(&self.config.partition, None).await {
            Ok(()) => {}
            Err(RError::PartitionMissing(_)) => {
                // Partition already removed or never existed.
            }
            Err(err) => return Err(Error::Runtime(err)),
        }
        Ok(())
    }
}

impl<E: BufferPooler + Storage + Metrics + Clock, V: CodecFixedShared> kv::Gettable
    for Ordinal<E, V>
{
    type Key = u64;
    type Value = V;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        self.get(*key).await
    }
}

impl<E: BufferPooler + Storage + Metrics + Clock, V: CodecFixedShared> kv::Updatable
    for Ordinal<E, V>
{
    async fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        self.put(key, value).await
    }
}

impl<E: BufferPooler + Storage + Metrics + Clock, V: CodecFixedShared> Persistable
    for Ordinal<E, V>
{
    type Error = Error;

    async fn commit(&self) -> Result<(), Self::Error> {
        self.sync().await
    }

    async fn sync(&self) -> Result<(), Self::Error> {
        self.sync().await
    }

    async fn destroy(self) -> Result<(), Self::Error> {
        self.destroy().await
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
    use crate::kv::tests::{assert_gettable, assert_send, assert_updatable};
    use commonware_runtime::deterministic::Context;

    type TestOrdinal = Ordinal<Context, u64>;

    #[allow(dead_code)]
    fn assert_ordinal_futures_are_send(ordinal: &mut TestOrdinal, key: u64) {
        assert_gettable(ordinal, &key);
        assert_updatable(ordinal, key, 0u64);
    }

    #[allow(dead_code)]
    fn assert_ordinal_destroy_is_send(ordinal: TestOrdinal) {
        assert_send(ordinal.destroy());
    }
}

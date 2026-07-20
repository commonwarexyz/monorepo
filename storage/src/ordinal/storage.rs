use super::{Config, Error};
use crate::{rmap::RMap, Context};
use commonware_codec::{CodecFixed, Encode, FixedSize, Read, ReadExt, Write as CodecWrite};
use commonware_cryptography::{crc32, Crc32};
use commonware_runtime::{
    buffer::{Read as ReadBuffer, Write},
    telemetry::metrics::{Counter, MetricsExt as _},
    Blob as _, Buf, BufMut, BufferPooler, Error as RError,
};
use std::marker::PhantomData;
use tracing::debug;

/// Name of the single blob holding all records.
pub(super) const BLOB_NAME: &[u8] = b"ordinal";

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
    partition: String,

    // The single blob holding every record
    blob: Write<E::Blob>,

    // RMap for interval tracking
    intervals: RMap,

    // Whether the blob has mutations not yet staged for durability
    dirty: bool,

    // Metrics
    puts: Counter,
    gets: Counter,
    has: Counter,
    syncs: Counter,
    pruned: Counter,

    _phantom: PhantomData<V>,
}

impl<E: BufferPooler + Context, V: CodecFixed<Cfg = ()>> Ordinal<E, V> {
    /// Size of each record in bytes (as u64).
    const RECORD_SIZE: u64 = Record::<V>::SIZE as u64;

    /// Resolve an index to its record's byte offset, or `None` when the record's byte range is
    /// not representable in a `u64`.
    fn record_offset(index: u64) -> Option<u64> {
        let offset = index.checked_mul(Self::RECORD_SIZE)?;
        offset.checked_add(Self::RECORD_SIZE)?;
        Some(offset)
    }

    /// Initialize a new [Ordinal] instance from the indices durably `committed` by the caller.
    ///
    /// Each committed record's CRC32 is checked to confirm it was written (a never-written hole
    /// fails the check) and the set is adopted as the in-memory [RMap]. A committed record that
    /// is missing or invalid fails initialization with [Error::MissingRecord]. Stored records
    /// outside `committed` are ignored: they are unreachable through [Ordinal] and are
    /// overwritten by future puts.
    ///
    /// Passing `None` removes all stored data and starts empty. The removal is durable before
    /// `init` returns.
    pub async fn init(context: E, config: Config, committed: Option<RMap>) -> Result<Self, Error> {
        // Reset the store unless committed indices are provided to recover from the stored blob
        if committed.is_none() {
            // The durable wipe is this path's only commit and no adjacent
            // durable operation exists to batch it with. Deferring it to ride
            // a later commit would let a crash resurrect the removed blob,
            // and a future init naming its records would replay their stale
            // contents as committed.
            match context.remove(&config.partition, None).await {
                Ok(()) | Err(RError::PartitionMissing(_)) => {}
                Err(err) => return Err(Error::Runtime(err)),
            }
        }

        // Open the blob and check for partial records. The storage backend guarantees per-blob
        // atomic sync, so torn writes cannot survive a crash: a size that is not a record
        // multiple is corruption or tampering. The same holds for the pruned floor (the store
        // only ever prunes at record multiples).
        let (blob, size) = context.open(&config.partition, BLOB_NAME).await?;
        if !size.is_multiple_of(Self::RECORD_SIZE) {
            return Err(Error::Corruption(format!(
                "blob size {size} is not a multiple of record size {}",
                Self::RECORD_SIZE
            )));
        }
        let floor = blob.floor();
        if !floor.is_multiple_of(Self::RECORD_SIZE) {
            return Err(Error::Corruption(format!(
                "pruned floor splits a record: {floor} bytes (foreign write or record size change)"
            )));
        }

        // Verify the committed records
        let mut intervals = RMap::new();
        if let Some(committed) = committed {
            debug!(size, floor, "rebuilding intervals from existing index");
            let start = context.current();
            let mut items = 0;
            let mut replay =
                ReadBuffer::from_pooler(&context, blob.clone(), size, config.replay_buffer);
            for (&range_start, &range_end) in committed.iter() {
                for index in range_start..=range_end {
                    // A committed record must lie fully within the blob's readable range: below
                    // the floor or beyond the size, it can never have been written (or was
                    // pruned by a boundary the caller has already committed past).
                    let offset = match Self::record_offset(index) {
                        Some(offset) if offset >= floor && offset + Self::RECORD_SIZE <= size => {
                            offset
                        }
                        _ => return Err(Error::MissingRecord(index)),
                    };

                    // A committed record that is missing or invalid cannot be recovered
                    replay.seek_to(offset)?;
                    let mut record_buf = replay.read(Record::<V>::SIZE).await?;
                    if let Ok(record) = Record::<V>::read(&mut record_buf) {
                        if record.is_valid() {
                            items += 1;
                            continue;
                        }
                    }
                    return Err(Error::MissingRecord(index));
                }
            }
            debug!(
                items,
                elapsed = ?context.current().duration_since(start).unwrap_or_default(),
                "rebuilt intervals"
            );
            intervals = committed;
        }

        // Wrap the blob in a write buffer
        let blob = Write::from_pooler(&context, blob, size, config.write_buffer);

        // Initialize metrics
        let puts = context.counter("puts", "Number of put calls");
        let gets = context.counter("gets", "Number of get calls");
        let has = context.counter("has", "Number of has calls");
        let syncs = context.counter("syncs", "Number of sync calls");
        let pruned = context.counter("pruned", "Number of prunes that advanced the boundary");

        Ok(Self {
            context,
            partition: config.partition,
            blob,
            intervals,
            dirty: false,
            puts,
            gets,
            has,
            syncs,
            pruned,
            _phantom: PhantomData,
        })
    }

    /// Add a value at the specified index (pending until sync).
    ///
    /// Returns [Error::IndexOverflow] if the record's byte range is not representable and
    /// [Error::IndexPruned] if the index precedes the pruning boundary.
    pub async fn put(&mut self, index: u64, value: V) -> Result<(), Error> {
        self.puts.inc();

        let offset = Self::record_offset(index).ok_or(Error::IndexOverflow(index))?;
        if offset < self.blob.floor() {
            return Err(Error::IndexPruned(index));
        }

        // Write the value to the blob
        let record = Record::new(value);
        self.blob.write_at(offset, record.encode_mut()).await?;
        self.dirty = true;

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
        let offset = Self::record_offset(index).expect("interval index has a valid offset");
        let mut read_buf = self.blob.read_at(offset, Record::<V>::SIZE).await?;
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

    /// Prune indices below `min` (capped to one past the highest written index), exactly: the
    /// new pruning boundary IS the (capped) requested index. Bytes below the boundary drop via
    /// the runtime's native [commonware_runtime::Blob::prune], and subsequent puts below it
    /// fail with [Error::IndexPruned].
    ///
    /// The new floor is a mutation, not a durability point: it persists at the next sync, and
    /// a crash may regress it to the last synced floor — never the reverse — so consumers
    /// re-prune after recovery.
    pub async fn prune(&mut self, min: u64) -> Result<(), Error> {
        // Cap to one past the highest written index (the blob's size is always a record
        // multiple, so the cap is exact).
        let min = min.min(self.blob.size() / Self::RECORD_SIZE);
        let target = min * Self::RECORD_SIZE;
        if target <= self.blob.floor() {
            return Ok(());
        }

        // The native prune is exact, so the boundary lands at the requested offset. `min` is
        // nonzero (the target exceeds the floor), so the removed range is well-formed.
        self.blob.prune(target).await?;
        self.intervals.remove(0, min - 1);
        self.dirty = true;

        // Update metrics
        self.pruned.inc();

        Ok(())
    }

    /// Write all pending entries and sync the [commonware_runtime::Blob].
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.syncs.inc();

        if !self.dirty {
            return Ok(());
        }
        self.blob.sync().await?;
        self.dirty = false;

        Ok(())
    }

    /// Write all pending entries and stage the [commonware_runtime::Blob]'s durability
    /// with `batch`.
    pub async fn sync_into<T: commonware_runtime::WriteBatch<Blob = E::Blob>>(
        &mut self,
        batch: &mut T,
    ) -> Result<(), Error> {
        self.syncs.inc();

        if !self.dirty {
            return Ok(());
        }
        self.blob.sync_into(batch).await?;
        self.dirty = false;

        Ok(())
    }

    /// Destroy [Ordinal] and remove all data, in ONE atomic commit.
    pub async fn destroy(self) -> Result<(), Error> {
        let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
        self.destroy_into(&mut batch);
        commonware_runtime::WriteBatch::apply_sync(batch)
            .await
            .map_err(Error::Runtime)
    }

    /// [Self::destroy], staged with `batch`: the partition's removal lands when the caller
    /// applies the batch with `apply_sync`, atomically with everything else it stages. The
    /// partition always exists (its blob is opened at initialization), so staging the removal
    /// cannot fail the batch.
    pub(crate) fn destroy_into<T: commonware_runtime::WriteBatch<Blob = E::Blob>>(
        self,
        batch: &mut T,
    ) {
        drop(self.blob);
        batch.remove(&self.partition, None);
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

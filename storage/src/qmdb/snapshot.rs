//! Rebuild snapshot indexes and activity bitmaps from the operations log.
//!
//! A build has two phases. It first replays the log once, writing a small record for every keyed
//! operation into the bucket that owns the key's partition. It then sorts each bucket by key and
//! location, which puts the operations of one key side by side with the newest last, and loads
//! the keys whose newest operation is not a delete. Buckets of a build too large to hold in
//! memory live in a scratch blob until they are sorted.
//!
//! The tasks that replay the log can also hash its operations for the journal's Merkle structure,
//! so that initialization reads the log once.

use super::Error;
use crate::{
    index::{
        Unordered as Index,
        partitioned::{PartitionRange, Partitioned},
    },
    journal::{
        authenticated::{Chunk, ChunkHasher, LeafSink},
        contiguous::Contiguous,
    },
    merkle::{self, Family, Location, hasher::Hasher as MerkleHasher},
    qmdb::operation::Operation,
    translator::Translator,
};
use commonware_codec::Encode;
use commonware_runtime::{
    Blob, Error as RuntimeError, Handle, IoBufMut, ReadOptions, Spawner, Storage, WriteOptions,
};
use commonware_utils::{
    bitmap::{Atomic, BitMap},
    sync::{AsyncMutex, Mutex},
};
use core::{
    num::NonZeroUsize,
    ops::Range,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};
use futures::{StreamExt as _, pin_mut, stream::FuturesUnordered};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

/// Operations per chunk of the log that a build task replays at a time, unless the journal
/// chooses the chunks (see [Scan]). Small in tests so ordinary logs span several chunks.
#[cfg(not(test))]
const DECODE_CHUNK: u64 = 1 << 17;
#[cfg(test)]
const DECODE_CHUNK: u64 = 64;

/// Bytes of records per bucket in a build. A bucket is sorted in memory, so this bounds
/// the working set of the task sorting it. Small in tests so ordinary logs fill several buckets.
#[cfg(not(test))]
const BUCKET_BYTES: u64 = 128 << 20;
#[cfg(test)]
const BUCKET_BYTES: u64 = 4096;

/// Bytes of records below which a build does not shrink its buckets to give every task
/// one. Small in tests so ordinary logs sort on several tasks.
#[cfg(not(test))]
const MIN_BUCKET_BYTES: u64 = 1 << 20;
#[cfg(test)]
const MIN_BUCKET_BYTES: u64 = 512;

/// Bytes of records a decoder stages for one bucket before moving them into it, which keeps the
/// bucket's lock off the path of most operations. Small in tests so ordinary logs move several
/// times.
#[cfg(not(test))]
const STAGE_BYTES: usize = 8 * 1024;
#[cfg(test)]
const STAGE_BYTES: usize = 64;

/// Bytes of records a build holds in memory across its buckets before they start writing theirs
/// to the scratch blob. A build that never holds more creates no blob. The records are counted
/// as they arrive, so the bound holds whatever size the keys are. Small in tests so ordinary
/// logs use a blob.
#[cfg(not(test))]
const MEMORY_BYTES: u64 = 64 << 20;
#[cfg(test)]
const MEMORY_BYTES: u64 = 1024;

/// Bytes of records a bucket collects before it writes them to the scratch blob, once the build
/// holds more than [MEMORY_BYTES]. Small in tests so ordinary logs write several times.
#[cfg(not(test))]
const SPILL_BYTES: usize = 1 << 20;
#[cfg(test)]
const SPILL_BYTES: usize = 256;

/// Bytes of a bucket's runs read back from the scratch blob at a time. A run larger than this
/// is read on its own.
#[cfg(not(test))]
const READ_BYTES: usize = 8 << 20;
#[cfg(test)]
const READ_BYTES: usize = 512;

/// Name of a build's blob in its scratch partition.
const SCRATCH_BLOB: &[u8] = b"records";

/// Bytes of records sorted at a time. A bucket's records are first split by key into groups of
/// about this size, so that sorting a group and loading its keys stays within a processor's
/// cache. Small in tests so ordinary buckets split into several groups.
#[cfg(not(test))]
const GROUP_BYTES: usize = 256 << 10;
#[cfg(test)]
const GROUP_BYTES: usize = 256;

/// Bytes of records above which a bucket is sorted in pieces that are then merged, rather than
/// all at once. Buckets of the expected size stay below it. A bucket exceeds it when keys crowd
/// into few partitions or are rewritten many times. Small in tests so ordinary logs merge.
#[cfg(not(test))]
const MERGE_BYTES: usize = 256 << 20;
#[cfg(test)]
const MERGE_BYTES: usize = 6144;

/// Bytes of records per piece of a bucket that is sorted in pieces. Small in tests so a merged
/// bucket has several.
#[cfg(not(test))]
const PIECE_BYTES: usize = 128 << 20;
#[cfg(test)]
const PIECE_BYTES: usize = 2048;

/// Sorted runs merged at a time, each of which holds one block in memory. A bucket with more
/// runs is merged in several passes. Small in tests so a merged bucket takes several.
#[cfg(not(test))]
const MERGE_RUNS: usize = 64;
#[cfg(test)]
const MERGE_RUNS: usize = 3;

/// Keys a merged bucket loads into one partition at a time. Small in tests so a partition is
/// loaded several times.
#[cfg(not(test))]
const LOAD_KEYS: usize = 1 << 16;
#[cfg(test)]
const LOAD_KEYS: usize = 8;

/// Bytes of keys a merged bucket holds before it loads them, however few keys that is. A key
/// larger than this is loaded on its own. Small in tests so long keys are loaded a few at a time.
#[cfg(not(test))]
const LOAD_BYTES: usize = 4 << 20;
#[cfg(test)]
const LOAD_BYTES: usize = 512;

/// How a build assigns operations to buckets and encodes their records.
///
/// A record is the key's length, the operation's tagged location, then the key's bytes, which
/// identify it (see [Key](crate::qmdb::operation::Key)). A length below 255 takes one byte, and
/// a longer key writes 255 followed by its length in four little-endian bytes. The tagged
/// location is the operation's offset from `floor` shifted left by one, with the low bit set
/// for a delete, in `loc_bytes` little-endian bytes.
#[derive(Clone, Copy)]
struct Layout {
    /// Maps a key to its index partition.
    partition_of: fn(&[u8]) -> usize,
    /// Partitions per bucket: bucket = `partition_of(key) / per_bucket`.
    per_bucket: usize,
    /// The first replayed location.
    floor: u64,
    /// Bytes of a record's tagged location.
    loc_bytes: usize,
    /// Expected bytes per record, which sizes buffers.
    record_bytes: usize,
}

impl Layout {
    /// The tagged location of the operation at `loc`.
    const fn tag(&self, loc: u64, is_delete: bool) -> u64 {
        ((loc - self.floor) << 1) | is_delete as u64
    }

    /// Append the record of an operation on `key` to `buf`.
    fn encode(&self, buf: &mut Vec<u8>, key: &[u8], tagged: u64) {
        match u8::try_from(key.len()) {
            Ok(len) if len < u8::MAX => buf.push(len),
            _ => {
                let len = u32::try_from(key.len()).expect("key too long");
                buf.push(u8::MAX);
                buf.extend_from_slice(&len.to_le_bytes());
            }
        }
        buf.extend_from_slice(&tagged.to_le_bytes()[..self.loc_bytes]);
        buf.extend_from_slice(key);
    }

    /// Read the record at `at` in `data`. Returns its tagged location, where its key starts and
    /// the key's length. The next record follows the key.
    fn decode(&self, data: &[u8], mut at: usize) -> (u64, usize, usize) {
        let mut len = data[at] as usize;
        at += 1;
        if len == u8::MAX as usize {
            len = u32::from_le_bytes(data[at..at + 4].try_into().expect("4 bytes")) as usize;
            at += 4;
        }
        let mut tagged = [0u8; 8];
        tagged[..self.loc_bytes].copy_from_slice(&data[at..at + self.loc_bytes]);
        (u64::from_le_bytes(tagged), at + self.loc_bytes, len)
    }

    /// The smallest and largest key prefix (see [key_prefix]) among the records in `data`, or
    /// `(u64::MAX, 0)` if it holds none.
    fn prefixes(&self, data: &[u8]) -> (u64, u64) {
        let (mut min, mut max) = (u64::MAX, 0);
        let mut at = 0;
        while at < data.len() {
            let (_, key_at, key_len) = self.decode(data, at);
            at = key_at + key_len;
            let prefix = key_prefix(&data[key_at..at]);
            min = min.min(prefix);
            max = max.max(prefix);
        }
        (min, max)
    }
}

/// The first eight bytes of `key` as an integer that orders as they do, padded with zeros.
fn key_prefix(key: &[u8]) -> u64 {
    let mut prefix = [0u8; 8];
    let shared = key.len().min(prefix.len());
    prefix[..shared].copy_from_slice(&key[..shared]);
    u64::from_be_bytes(prefix)
}

/// A record of a bucket being sorted in memory.
#[derive(Clone, Copy)]
struct Record {
    /// The key's first eight bytes, which decide most comparisons.
    prefix: u64,
    /// The tagged location, which orders a key's operations oldest first.
    tagged: u64,
    /// Where the key starts in the bucket's records.
    key_at: u32,
    key_len: u32,
}

impl Record {
    /// The record's key in `data`, the records it was parsed from.
    fn key<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.key_at as usize..][..self.key_len as usize]
    }
}

/// Fill `records` with the newest record of each key in `data`, records in any order, in
/// ascending key order.
fn sort_records(data: &[u8], layout: Layout, records: &mut Vec<Record>) {
    assert!(
        u32::try_from(data.len()).is_ok(),
        "too many records to sort at once"
    );
    records.clear();
    records.reserve(data.len() / layout.record_bytes + 1);
    let mut at = 0;
    while at < data.len() {
        let (tagged, key_at, key_len) = layout.decode(data, at);
        at = key_at + key_len;
        records.push(Record {
            prefix: key_prefix(&data[key_at..at]),
            tagged,
            key_at: key_at as u32,
            key_len: key_len as u32,
        });
    }

    // Operations of one key end up adjacent, oldest first. Keys are compared in full, so keys
    // that share a translated key stay apart.
    records.sort_unstable_by(|a, b| {
        a.prefix
            .cmp(&b.prefix)
            .then_with(|| a.key(data).cmp(b.key(data)))
            .then_with(|| a.tagged.cmp(&b.tagged))
    });
    let mut kept = 0;
    for i in 0..records.len() {
        let record = records[i];
        let newest = records
            .get(i + 1)
            .is_none_or(|next| next.prefix != record.prefix || next.key(data) != record.key(data));
        if newest {
            records[kept] = record;
            kept += 1;
        }
    }
    records.truncate(kept);
}

/// The memory a task sorts records in, kept from one bucket to the next.
///
/// Records are split by key into groups (see [GROUP_BYTES]) before any are sorted. Every key of
/// a group sorts before every key of the next, so sorting the groups in turn visits the keys in
/// ascending order.
#[derive(Default)]
struct Sorter {
    /// One region of `width` bytes per group, back to back, which the group's records fill
    /// from its start.
    regions: Vec<u8>,
    width: usize,
    /// Bytes of records in each group's region.
    lens: Vec<usize>,
    /// The records of each group that did not fit its region.
    rest: BTreeMap<usize, Vec<u8>>,
    /// A key belongs to the group at its prefix less `base`, shifted right by `shift`.
    base: u64,
    shift: u32,

    /// The group last sorted (see [Self::sort]): all its records if some did not fit its
    /// region, and the records it kept.
    whole: Vec<u8>,
    records: Vec<Record>,
}

impl Sorter {
    /// Prepare to split `bytes` of records whose key prefixes span `prefixes`, their smallest
    /// and largest.
    fn start(&mut self, bytes: usize, (min, max): (u64, u64)) {
        // Groups cover equal ranges of prefixes, a power of two wide, so keys that crowd into
        // part of the span leave groups larger than intended. Those still sort correctly.
        let span = max.saturating_sub(min);
        let bits = u64::BITS - span.leading_zeros();
        let wanted = bytes
            .div_ceil(GROUP_BYTES)
            .max(1)
            .next_power_of_two()
            .trailing_zeros();
        self.base = min;
        self.shift = bits.saturating_sub(wanted).min(u64::BITS - 1);
        let groups = (span >> self.shift) as usize + 1;

        // A region has room for a group of the expected size and some more, so that the records
        // of few groups go elsewhere.
        let expected = bytes / groups;
        self.width = expected + expected / 4;
        self.lens.clear();
        self.lens.resize(groups, 0);
        self.rest.clear();
        self.whole = Vec::new();
        if self.regions.len() < groups * self.width {
            // Free the old regions before the new ones are allocated.
            self.regions = Vec::new();
            self.regions = vec![0; groups * self.width];
        }
    }

    /// The number of groups.
    const fn groups(&self) -> usize {
        self.lens.len()
    }

    /// Add the records in `data`, whole records in any order, to their groups.
    fn split(&mut self, data: &[u8], layout: Layout) {
        let last = self.groups() - 1;
        let mut at = 0;
        while at < data.len() {
            let (_, key_at, key_len) = layout.decode(data, at);
            let end = key_at + key_len;
            let record = &data[at..end];
            at = end;

            // A prefix outside the span joins the nearest group, which keeps the groups in key
            // order. The group is bounded before it is narrowed, because a prefix far above the
            // span would otherwise wrap where addresses are narrower than a prefix.
            let prefix = key_prefix(&data[key_at..end]);
            let group = (prefix.saturating_sub(self.base) >> self.shift).min(last as u64) as usize;
            let len = self.lens[group];
            let region = &mut self.regions[group * self.width..][len..self.width];
            match region.get_mut(..record.len()) {
                Some(room) => {
                    room.copy_from_slice(record);
                    self.lens[group] = len + record.len();
                }
                None => self
                    .rest
                    .entry(group)
                    .or_default()
                    .extend_from_slice(record),
            }
        }
    }

    /// Sort `group` (see [sort_records]) and return its records with the bytes they refer to.
    fn sort(&mut self, group: usize, layout: Layout) -> (&[Record], &[u8]) {
        let region = &self.regions[group * self.width..][..self.lens[group]];
        let data = match self.rest.remove(&group) {
            None => region,
            Some(mut rest) => {
                rest.extend_from_slice(region);
                self.whole = rest;
                &self.whole
            }
        };
        sort_records(data, layout, &mut self.records);
        (&self.records, data)
    }
}

/// The survivors of one partition that are waiting to be loaded into it: their keys back to
/// back, and each one's place among the keys with its offset from the floor.
struct Loader {
    partition: usize,
    keys: Vec<u8>,
    entries: Vec<(usize, usize, u64)>,
    /// Keys and bytes of keys held before they are loaded, whatever else their partition has.
    max_keys: usize,
    max_bytes: usize,
}

impl Loader {
    /// A loader that holds a partition's survivors until it has them all, which sizes the
    /// partition exactly. For survivors that memory already holds.
    const fn whole() -> Self {
        Self::new(usize::MAX, usize::MAX)
    }

    /// A loader that holds at most [LOAD_KEYS] keys and [LOAD_BYTES] of them.
    const fn bounded() -> Self {
        Self::new(LOAD_KEYS, LOAD_BYTES)
    }

    const fn new(max_keys: usize, max_bytes: usize) -> Self {
        Self {
            partition: 0,
            keys: Vec::new(),
            entries: Vec::new(),
            max_keys,
            max_bytes,
        }
    }

    /// Add the survivor `key`, whose operation is `offset` from the floor. Survivors must
    /// arrive in ascending key order.
    fn push<F, R>(&mut self, index: &mut R, layout: Layout, key: &[u8], offset: u64)
    where
        F: Family,
        R: PartitionRange<Value = Location<F>>,
    {
        let of = (layout.partition_of)(key);
        if !self.entries.is_empty()
            && (of != self.partition
                || self.entries.len() >= self.max_keys
                || self.keys.len().saturating_add(key.len()) > self.max_bytes)
        {
            self.load(index, layout);
        }
        self.partition = of;
        self.entries.push((self.keys.len(), key.len(), offset));
        self.keys.extend_from_slice(key);
    }

    /// Load the survivors held into `index`.
    fn load<F, R>(&mut self, index: &mut R, layout: Layout)
    where
        F: Family,
        R: PartitionRange<Value = Location<F>>,
    {
        if self.entries.is_empty() {
            return;
        }
        index.load(self.entries.iter().map(|&(at, len, offset)| {
            (
                &self.keys[at..at + len],
                Location::new(layout.floor + offset),
            )
        }));
        self.keys.clear();
        self.entries.clear();
    }
}

/// Insert the keys that survive the records split in `sorter`, one bucket's, into `index` in
/// ascending key order. A key survives if its newest operation is not a delete. Calls `activate`
/// with each survivor's offset from the floor and returns their number.
fn load_bucket<F, R>(
    index: &mut R,
    sorter: &mut Sorter,
    layout: Layout,
    mut activate: impl FnMut(u64),
) -> usize
where
    F: Family,
    R: PartitionRange<Value = Location<F>>,
{
    // A partition's keys are contiguous in key order but can span groups.
    let mut loader = Loader::whole();
    let mut survivors = 0;
    for group in 0..sorter.groups() {
        let (records, data) = sorter.sort(group, layout);
        for record in records {
            if record.tagged & 1 != 0 {
                continue;
            }
            let offset = record.tagged >> 1;
            activate(offset);
            loader.push(index, layout, record.key(data), offset);
            survivors += 1;
        }
    }
    loader.load(index, layout);
    survivors
}

/// A sorted run of a bucket being merged, read from the scratch blob a block at a time. Each
/// block holds whole records.
struct Run {
    /// The run's blocks that are yet to be read.
    blocks: std::vec::IntoIter<(u64, usize)>,
    /// The block being read, in the buffer it was read into.
    block: IoBufMut,

    /// The current record: its key's first eight bytes, its tagged location, and where its key
    /// sits in `block`.
    prefix: u64,
    tagged: u64,
    key_at: usize,
    key_len: usize,
}

impl Run {
    /// A run over `blocks`, positioned before its first record.
    fn new(blocks: Vec<(u64, usize)>) -> Self {
        Self {
            blocks: blocks.into_iter(),
            block: IoBufMut::default(),
            prefix: 0,
            tagged: 0,
            key_at: 0,
            key_len: 0,
        }
    }

    /// The current record's key.
    fn key(&self) -> &[u8] {
        &self.block.as_ref()[self.key_at..][..self.key_len]
    }

    /// Whether the current record sorts before `other`'s: by key, then oldest first.
    fn precedes(&self, other: &Self) -> bool {
        self.prefix
            .cmp(&other.prefix)
            .then_with(|| self.key().cmp(other.key()))
            .then_with(|| self.tagged.cmp(&other.tagged))
            .is_lt()
    }

    /// Move to the next record. Returns false once the run has none left.
    async fn advance(&mut self, blob: &impl Blob, layout: Layout) -> Result<bool, RuntimeError> {
        let mut at = self.key_at + self.key_len;
        if at == self.block.len() {
            let Some((offset, len)) = self.blocks.next() else {
                *self = Self::new(Vec::new());
                return Ok(false);
            };
            self.block = blob
                .read_at(offset, len, ReadOptions::DONT_CACHE)
                .await?
                .coalesce();
            at = 0;
        }
        (self.tagged, self.key_at, self.key_len) = layout.decode(self.block.as_ref(), at);
        self.prefix = key_prefix(self.key());
        Ok(true)
    }
}

/// Restore the heap order of `heap`, indices into `runs` with the run whose record sorts first
/// on top, after the entry at `at` moved to a later record.
fn sift_down(heap: &mut [usize], mut at: usize, runs: &[Run]) {
    loop {
        let mut first = at;
        for child in [2 * at + 1, 2 * at + 2] {
            if child < heap.len() && runs[heap[child]].precedes(&runs[heap[first]]) {
                first = child;
            }
        }
        if first == at {
            return;
        }
        heap.swap(at, first);
        at = first;
    }
}

/// A merge of sorted runs that yields the newest record of each key, in ascending key order.
struct Merge {
    runs: Vec<Run>,
    /// The runs that have records left, as indices into `runs` in heap order with the run whose
    /// record sorts first on top.
    heap: Vec<usize>,
    /// The key last returned by [Self::next].
    key: Vec<u8>,
}

impl Merge {
    /// Start a merge of `runs`, reading the first block of each.
    async fn new(
        blob: &impl Blob,
        layout: Layout,
        mut runs: Vec<Run>,
    ) -> Result<Self, RuntimeError> {
        let mut heap = Vec::with_capacity(runs.len());
        for (run, state) in runs.iter_mut().enumerate() {
            if state.advance(blob, layout).await? {
                heap.push(run);
            }
        }
        for at in (0..heap.len() / 2).rev() {
            sift_down(&mut heap, at, &runs);
        }
        Ok(Self {
            runs,
            heap,
            key: Vec::new(),
        })
    }

    /// Move to the next key, leaving it in `self.key`, and return the tagged location of its
    /// newest record. Returns `None` once every run is exhausted.
    async fn next(
        &mut self,
        blob: &impl Blob,
        layout: Layout,
    ) -> Result<Option<u64>, RuntimeError> {
        let Some(&top) = self.heap.first() else {
            return Ok(None);
        };
        self.key.clear();
        self.key.extend_from_slice(self.runs[top].key());
        loop {
            // The top run holds the oldest unread record of the key. Read past it, dropping the
            // run once it has no record left.
            let top = self.heap[0];
            let newest = self.runs[top].tagged;
            if !self.runs[top].advance(blob, layout).await? {
                self.heap.swap_remove(0);
            }
            sift_down(&mut self.heap, 0, &self.runs);
            match self.heap.first() {
                Some(&next) if self.runs[next].key() == self.key.as_slice() => {}
                _ => return Ok(Some(newest)),
            }
        }
    }
}

/// A sorted run being written to the scratch blob in blocks of whole records.
#[derive(Default)]
struct RunWriter {
    /// The block being filled.
    block: Vec<u8>,
    /// Offset and length of each block written.
    blocks: Vec<(u64, usize)>,
}

/// The records of a bucket.
struct Records {
    /// Records not yet written to the scratch blob.
    buf: Vec<u8>,
    /// Offset and length of each run of records written to the scratch blob.
    runs: Vec<(u64, usize)>,
    /// The smallest and largest key prefix (see [key_prefix]) among the records.
    prefixes: (u64, u64),
}

impl Default for Records {
    fn default() -> Self {
        Self {
            buf: Vec::new(),
            runs: Vec::new(),
            prefixes: (u64::MAX, 0),
        }
    }
}

/// One bucket of a build: the records of the operations whose keys fall in a contiguous
/// range of partitions, and those partitions.
struct Bucket<R> {
    /// The bucket's records, taken by the task that sorts them.
    records: Records,
    /// The bucket's partitions, taken by the task that fills them.
    range: Option<R>,
}

/// The number of leading `runs` whose lengths total at most `limit` bytes, and at least one if
/// there are any.
const fn leading_runs(runs: &[(u64, usize)], limit: usize) -> usize {
    let mut bytes = 0;
    let mut count = 0;
    while count < runs.len() && (count == 0 || bytes + runs[count].1 <= limit) {
        bytes += runs[count].1;
        count += 1;
    }
    count
}

/// The buckets of a build, shared by its tasks.
struct Buckets<B, R> {
    layout: Layout,
    buckets: Vec<Mutex<Bucket<R>>>,
    /// Bytes of records the buckets hold in memory.
    held: AtomicU64,
    /// Sets of empty staging buffers, one buffer per bucket, that decoders pass between them.
    spare: Mutex<Vec<Vec<Vec<u8>>>>,

    /// The partition of the scratch blob.
    scratch: String,
    /// The scratch blob, opened by the first write to it. Storage allows one open handle to a
    /// blob, so the lock is held while it opens. The blob is never synced, so it must stay open
    /// until its records are read back.
    blob: AsyncMutex<Option<Arc<B>>>,
    /// The scratch blob's next free offset.
    end: AtomicU64,
}

impl<B: Blob, R> Buckets<B, R> {
    /// Write `records` to the scratch blob and return their offset and length.
    async fn write(
        &self,
        context: &impl Storage<Blob = B>,
        records: Vec<u8>,
    ) -> Result<(u64, usize), RuntimeError> {
        let blob = {
            let mut opened = self.blob.lock().await;
            match &*opened {
                Some(blob) => blob.clone(),
                None => {
                    let (blob, _) = context.open(&self.scratch, SCRATCH_BLOB).await?;
                    opened.insert(Arc::new(blob)).clone()
                }
            }
        };
        let len = records.len();
        let offset = self.end.fetch_add(len as u64, Ordering::Relaxed);
        blob.write_at(offset, records, WriteOptions::DONT_CACHE)
            .await?;
        Ok((offset, len))
    }

    /// Pass the records of `runs` to `each`, a run at a time.
    async fn read(
        &self,
        runs: &[(u64, usize)],
        mut each: impl FnMut(&[u8]) + Send,
    ) -> Result<(), RuntimeError> {
        let mut rest = runs;
        let mut batches = core::iter::from_fn(|| {
            let (batch, later) = rest.split_at(leading_runs(rest, READ_BYTES));
            rest = later;
            (!batch.is_empty()).then_some(batch)
        });

        // A bucket that was never written to the blob may find none.
        let Some(first) = batches.next() else {
            return Ok(());
        };
        let blob = self.blob.lock().await.clone().expect("runs were written");
        let mut reading = blob.start_read_many(first, ReadOptions::DONT_CACHE).await;
        loop {
            // The next batch is requested before this one is passed on, so that storage reads
            // while the caller works.
            let next = match batches.next() {
                Some(batch) => Some(blob.start_read_many(batch, ReadOptions::DONT_CACHE).await),
                None => None,
            };
            for run in reading.await? {
                each(run.coalesce().as_ref());
            }
            let Some(next) = next else {
                return Ok(());
            };
            reading = next;
        }
    }

    /// Take a set of empty staging buffers, one per bucket.
    fn stage(&self) -> Vec<Vec<u8>> {
        let spare = self.spare.lock().pop();
        spare.unwrap_or_else(|| {
            (0..self.buckets.len())
                .map(|_| Vec::with_capacity(STAGE_BYTES))
                .collect()
        })
    }

    /// Return a set of staging buffers, now empty, for another decoder to take.
    fn unstage(&self, staged: Vec<Vec<u8>>) {
        self.spare.lock().push(staged);
    }

    /// Move the records in `staged` into `bucket`, leaving `staged` empty. Once the build holds
    /// more than [MEMORY_BYTES] of records in memory, a bucket that has collected enough of them
    /// writes them to the scratch blob.
    async fn append(
        &self,
        context: &impl Storage<Blob = B>,
        bucket: usize,
        staged: &mut Vec<u8>,
    ) -> Result<(), RuntimeError> {
        let (min, max) = self.layout.prefixes(staged);
        let run = {
            let mut bucket = self.buckets[bucket].lock();
            let records = &mut bucket.records;
            records.prefixes = (records.prefixes.0.min(min), records.prefixes.1.max(max));
            records.buf.extend_from_slice(staged);
            let added = staged.len() as u64;
            staged.clear();
            let held = self.held.fetch_add(added, Ordering::Relaxed) + added;
            if held <= MEMORY_BYTES || records.buf.len() < SPILL_BYTES {
                return Ok(());
            }
            self.held
                .fetch_sub(records.buf.len() as u64, Ordering::Relaxed);
            core::mem::replace(
                &mut records.buf,
                Vec::with_capacity(SPILL_BYTES + STAGE_BYTES),
            )
        };

        // Buckets are read back only after every decoder is done, so the run can be recorded
        // once its write completes.
        let run = self.write(context, run).await?;
        self.buckets[bucket].lock().records.runs.push(run);
        Ok(())
    }

    /// Take `bucket`'s partitions and its records. A bucket can be taken once.
    fn take(&self, bucket: usize) -> (R, Records) {
        let mut bucket = self.buckets[bucket].lock();
        (
            bucket.range.take().expect("bucket taken twice"),
            core::mem::take(&mut bucket.records),
        )
    }

    /// Append the record of an operation on `key` to `run`, writing a block that has filled.
    async fn push(
        &self,
        context: &impl Storage<Blob = B>,
        run: &mut RunWriter,
        key: &[u8],
        tagged: u64,
    ) -> Result<(), RuntimeError> {
        self.layout.encode(&mut run.block, key, tagged);
        if run.block.len() >= SPILL_BYTES {
            let full = core::mem::replace(
                &mut run.block,
                Vec::with_capacity(SPILL_BYTES + STAGE_BYTES),
            );
            run.blocks.push(self.write(context, full).await?);
        }
        Ok(())
    }

    /// Write what `run` still holds and return the run for reading.
    async fn finish(
        &self,
        context: &impl Storage<Blob = B>,
        run: RunWriter,
    ) -> Result<Run, RuntimeError> {
        let RunWriter { block, mut blocks } = run;
        if !block.is_empty() {
            blocks.push(self.write(context, block).await?);
        }
        Ok(Run::new(blocks))
    }

    /// Insert the keys that survive a bucket too large to sort at once into `index`, where
    /// `records` are the bucket's. Calls `activate` with each survivor's offset from the floor
    /// and returns their number.
    ///
    /// The records are sorted a piece at a time. Each piece keeps the newest record of each of
    /// its keys and returns to the scratch blob as a sorted run. Merging runs brings every
    /// key's remaining records together, oldest first. At most [MERGE_RUNS] runs are merged at
    /// a time, into a longer run while more remain, so memory holds that many blocks however
    /// many records the bucket has.
    async fn merge<F>(
        &self,
        context: &impl Storage<Blob = B>,
        index: &mut R,
        sorter: &mut Sorter,
        records: Records,
        mut activate: impl FnMut(u64) + Send,
    ) -> Result<usize, RuntimeError>
    where
        F: Family,
        R: PartitionRange<Value = Location<F>> + Send,
    {
        let layout = self.layout;
        let Records {
            buf,
            runs,
            prefixes,
        } = records;
        let mut sorted = VecDeque::new();
        let mut unsorted = runs.as_slice();
        let mut buf = Some(buf);
        while buf.is_some() {
            // A piece is as many runs as fit, and at least one. The last piece starts from the
            // records still in memory, so it is sized once for both.
            let (piece, rest) = unsorted.split_at(leading_runs(unsorted, PIECE_BYTES));
            unsorted = rest;
            let held = if unsorted.is_empty() {
                buf.take().expect("records in memory join once")
            } else {
                Vec::new()
            };
            let stored: usize = piece.iter().map(|(_, len)| len).sum();
            sorter.start(stored + held.len(), prefixes);
            sorter.split(&held, layout);
            drop(held);
            self.read(piece, |run| sorter.split(run, layout)).await?;
            let mut run = RunWriter::default();
            for group in 0..sorter.groups() {
                let (records, data) = sorter.sort(group, layout);
                for record in records {
                    self.push(context, &mut run, record.key(data), record.tagged)
                        .await?;
                }
            }
            sorted.push_back(self.finish(context, run).await?);
        }
        let blob = self.blob.lock().await.clone().expect("runs were written");
        let blob = &*blob;

        // Merge the oldest runs into one longer run until few enough remain to merge at once.
        // A merged run keeps deletes, which still decide against records in other runs.
        while sorted.len() > MERGE_RUNS {
            let mut merge = Merge::new(blob, layout, sorted.drain(..MERGE_RUNS).collect()).await?;
            let mut run = RunWriter::default();
            while let Some(tagged) = merge.next(blob, layout).await? {
                self.push(context, &mut run, &merge.key, tagged).await?;
            }
            sorted.push_back(self.finish(context, run).await?);
        }

        let mut loader = Loader::bounded();
        let mut merge = Merge::new(blob, layout, sorted.into()).await?;
        let mut survivors = 0;
        while let Some(tagged) = merge.next(blob, layout).await? {
            if tagged & 1 != 0 {
                continue;
            }
            let offset = tagged >> 1;
            activate(offset);
            loader.push(index, layout, &merge.key, offset);
            survivors += 1;
        }
        loader.load(index, layout);
        Ok(survivors)
    }
}

/// What a build's decoder does with each operation of its chunk besides routing it.
trait ChunkVisitor<F: Family, Item>: Send + 'static {
    /// The chunk's result, passed on in position order once the chunk is routed.
    type Output: Send + 'static;

    /// See the chunk's next operation, in position order.
    fn visit(&mut self, item: &Item);

    /// The chunk's result, once every operation in it has been visited.
    fn finish(self) -> Result<Self::Output, merkle::Error<F>>;
}

impl<F: Family, Item> ChunkVisitor<F, Item> for () {
    type Output = ();

    fn visit(&mut self, _: &Item) {}

    fn finish(self) -> Result<(), merkle::Error<F>> {
        Ok(())
    }
}

impl<F: Family, H: MerkleHasher<F> + 'static, Item: Encode> ChunkVisitor<F, Item>
    for ChunkHasher<F, H>
{
    type Output = Chunk<F, H::Digest>;

    fn visit(&mut self, item: &Item) {
        Self::push(self, item);
    }

    fn finish(self) -> Result<Self::Output, merkle::Error<F>> {
        Self::finish(self)
    }
}

/// The operations a build decodes, and what its decoders do with them besides routing those at
/// or after the floor. They do nothing more, or hash them for the journal's Merkle structure.
trait Scan<F: Family, Item>: Send + Sync {
    type Visitor: ChunkVisitor<F, Item>;

    /// The chunks to decode, in position order, for a build from `floor` to `end`.
    fn chunks(&self, floor: u64, end: u64) -> impl Iterator<Item = Range<u64>> + Send + 'static;

    /// The visitor of `chunk`, one of [Self::chunks], that its decoder calls.
    fn visitor(&self, chunk: Range<u64>) -> Self::Visitor;

    /// Pass a routed chunk's result on. Chunks are passed on in position order. Returns false to
    /// stop the build.
    fn send(
        &self,
        output: <Self::Visitor as ChunkVisitor<F, Item>>::Output,
    ) -> impl Future<Output = bool> + Send;
}

/// A build that only routes, decoding from the floor.
struct IndexOnly;

impl<F: Family, Item> Scan<F, Item> for IndexOnly {
    type Visitor = ();

    fn chunks(&self, floor: u64, end: u64) -> impl Iterator<Item = Range<u64>> + Send + 'static {
        (floor..end)
            .step_by(usize::try_from(DECODE_CHUNK).expect("chunk size fits usize"))
            .map(move |start| start..(start + DECODE_CHUNK).min(end))
    }

    fn visitor(&self, _: Range<u64>) {}

    async fn send(&self, _: ()) -> bool {
        true
    }
}

/// A build that also hashes every operation from the journal's boundary, in the journal's chunks.
impl<F: Family, H: MerkleHasher<F> + 'static, Item: Encode> Scan<F, Item> for LeafSink<F, H> {
    type Visitor = ChunkHasher<F, H>;

    // Starts at the journal's pruning boundary, which initialization keeps at or before the floor.
    fn chunks(&self, _: u64, _: u64) -> impl Iterator<Item = Range<u64>> + Send + 'static {
        Self::chunks(self)
    }

    fn visitor(&self, chunk: Range<u64>) -> ChunkHasher<F, H> {
        self.chunk_hasher(chunk)
    }

    async fn send(&self, chunk: Chunk<F, H::Digest>) -> bool {
        Self::send(self, chunk).await
    }
}

/// Replay `chunk` of the log, appending the record of every keyed operation at or after the floor
/// to the bucket that owns its key. `visitor` sees every replayed operation, including those
/// before the floor.
async fn route<F, E, C, R, V>(
    context: &E,
    log: &C,
    chunk: Range<u64>,
    init_buffer: NonZeroUsize,
    buckets: &Buckets<E::Blob, R>,
    visitor: &mut V,
) -> Result<(), Error<F>>
where
    F: Family,
    E: Storage,
    C: Contiguous<Item: Operation<F>>,
    R: Send,
    V: ChunkVisitor<F, C::Item>,
{
    let layout = buckets.layout;
    let mut staged = buckets.stage();

    // Init reads every operation once, so the replayed pages are not kept in the OS page cache.
    let stream = log
        .replay(chunk, init_buffer, ReadOptions::DONT_CACHE)
        .await?;
    pin_mut!(stream);
    while let Some(batch) = stream.next().await {
        for (loc, op) in batch? {
            visitor.visit(&op);
            if loc < layout.floor {
                continue;
            }
            let Some(key) = op.key() else { continue };

            // The bytes a lookup probes the index with.
            let key: &[u8] = key.as_ref();
            let bucket = (layout.partition_of)(key) / layout.per_bucket;
            let staged = &mut staged[bucket];
            layout.encode(staged, key, layout.tag(loc, op.is_delete()));
            if staged.len() >= STAGE_BYTES {
                buckets.append(context, bucket, staged).await?;
            }
        }
    }
    for (bucket, staged) in staged.iter_mut().enumerate() {
        if !staged.is_empty() {
            buckets.append(context, bucket, staged).await?;
        }
    }
    buckets.unstage(staged);
    Ok(())
}

/// The tasks of a build that are still running. Dropping them aborts each one.
struct Tasks<T: Send + 'static>(FuturesUnordered<Handle<T>>);

impl<T: Send + 'static> Tasks<T> {
    /// Abort every task still running.
    fn abort(&self) {
        for task in &self.0 {
            task.abort();
        }
    }

    /// Abort every task still running and wait for each to end.
    async fn stop(&mut self) {
        self.abort();
        while self.0.next().await.is_some() {}
    }
}

impl<T: Send + 'static, F: Family> Tasks<Result<T, Error<F>>> {
    /// Wait for the tasks and return what they produced, in the order they finished. The first
    /// to fail aborts those still running. Every task has ended when this returns.
    async fn join(mut self) -> Result<Vec<T>, Error<F>> {
        let mut outputs = Vec::with_capacity(self.0.len());
        let joined = async {
            while let Some(output) = self.0.next().await {
                outputs.push(output??);
            }
            Ok(())
        }
        .await;
        self.stop().await;
        joined.map(|()| outputs)
    }
}

impl<T: Send + 'static> Drop for Tasks<T> {
    fn drop(&mut self) {
        self.abort();
    }
}

/// Replay the chunks of `scan` into `buckets` (see [route]), on up to `tasks` tasks at a time,
/// and pass each chunk's result on in position order. Returns false if `scan` stopped the build.
///
/// Every task has ended when this returns, whatever it returns. A failure, or a scan that stops
/// the build, aborts the tasks still replaying.
#[allow(clippy::too_many_arguments)]
async fn route_chunks<F, E, C, R, S>(
    context: &E,
    log: &Arc<C>,
    scan: &S,
    floor: u64,
    end: u64,
    tasks: usize,
    init_buffer: NonZeroUsize,
    buckets: &Arc<Buckets<E::Blob, R>>,
) -> Result<bool, Error<F>>
where
    F: Family,
    E: Spawner + crate::Context,
    C: Contiguous<Item: Operation<F>> + 'static,
    R: Send + 'static,
    S: Scan<F, C::Item>,
{
    // A decoder beyond the number of chunks would have nothing to replay.
    let chunks: Vec<_> = scan.chunks(floor, end).collect();
    let decoders = tasks.min(chunks.len());
    if decoders <= 1 {
        for chunk in chunks {
            let mut visitor = scan.visitor(chunk.clone());
            route(context, &**log, chunk, init_buffer, buckets, &mut visitor).await?;
            if !scan.send(visitor.finish()?).await {
                return Ok(false);
            }
        }
        return Ok(true);
    }

    // Buckets are sorted later, so chunks are routed in whatever order their decoders finish.
    // Their results are still passed on in order, so one that finishes early waits for those
    // before it. A chunk starts only within `window` of the next to pass on, which bounds how
    // many wait without idling a decoder behind a slow chunk.
    let window = 2 * decoders;
    let mut chunks = chunks.into_iter().enumerate();
    let mut running = Tasks(FuturesUnordered::new());
    let mut waiting = BTreeMap::new();
    let (mut started, mut passed) = (0, 0);
    let routed = async {
        loop {
            while running.0.len() < decoders && started - passed < window {
                let Some((index, chunk)) = chunks.next() else {
                    break;
                };
                let mut visitor = scan.visitor(chunk.clone());
                let (log, buckets) = (log.clone(), buckets.clone());
                let decoder = context.child("snapshot_decoder").dedicated().spawn(
                    move |context| async move {
                        route(&context, &*log, chunk, init_buffer, &buckets, &mut visitor).await?;
                        Ok::<_, Error<F>>((index, visitor.finish()?))
                    },
                );
                running.0.push(decoder);
                started += 1;
            }
            let Some(output) = running.0.next().await else {
                return Ok(true);
            };
            let (index, output) = output??;
            waiting.insert(index, output);
            while let Some(output) = waiting.remove(&passed) {
                if !scan.send(output).await {
                    return Ok(false);
                }
                passed += 1;
            }
        }
    }
    .await;

    // Decoders are still running if one failed or the scan stopped the build. Abort them, and
    // wait for each to end so that none outlives the build.
    running.stop().await;
    routed
}

/// Sort buckets claimed from `next` and insert their surviving keys, until no bucket is left.
/// Sets the activity bit of every survivor in `active`, which is indexed from the floor. Returns
/// the filled partitions and the number of keys in them.
async fn sort_and_load<F, E, R>(
    context: &E,
    buckets: &Buckets<E::Blob, R>,
    next: &AtomicUsize,
    active: &Atomic,
) -> Result<(Vec<R>, usize), Error<F>>
where
    F: Family,
    E: Storage,
    R: PartitionRange<Value = Location<F>> + Send,
{
    let layout = buckets.layout;
    let mut sorter = Sorter::default();
    let mut filled = Vec::new();
    let mut active_keys = 0;
    loop {
        let bucket = next.fetch_add(1, Ordering::Relaxed);
        if bucket >= buckets.buckets.len() {
            return Ok((filled, active_keys));
        }
        let (mut range, records) = buckets.take(bucket);

        // A bucket's records can exceed what a narrow address space counts, and such a bucket
        // is merged, so they are counted in 64 bits.
        let stored: u64 = records.runs.iter().map(|&(_, len)| len as u64).sum();
        let bytes = stored + records.buf.len() as u64;
        let activate = |offset| active.set(offset);
        active_keys += if records.runs.is_empty() || bytes <= MERGE_BYTES as u64 {
            let Records {
                buf,
                runs,
                prefixes,
            } = records;
            sorter.start(bytes as usize, prefixes);
            sorter.split(&buf, layout);
            drop(buf);
            buckets.read(&runs, |run| sorter.split(run, layout)).await?;
            load_bucket::<F, _>(&mut range, &mut sorter, layout, activate)
        } else {
            buckets
                .merge::<F>(context, &mut range, &mut sorter, records, activate)
                .await?
        };
        filled.push(range);
    }
}

/// Remove a build's blob from the `scratch` partition, and the partition with it unless
/// something else is kept there. Neither has to exist, and storage is left untouched if neither
/// does.
async fn remove_scratch(context: &impl Storage, scratch: &str) -> Result<(), RuntimeError> {
    let blobs = match context.scan(scratch).await {
        Ok(blobs) => blobs,
        Err(RuntimeError::PartitionMissing(_)) => return Ok(()),
        Err(err) => return Err(err),
    };
    let ours = blobs.iter().any(|blob| blob == SCRATCH_BLOB);
    if ours {
        context.remove(scratch, Some(SCRATCH_BLOB)).await?;
    }
    if blobs.len() == usize::from(ours) {
        match context.remove(scratch, None).await {
            Ok(()) | Err(RuntimeError::PartitionMissing(_)) => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Build `snapshot` from `log` in two phases that each use every task of `init_concurrency`.
///
/// First, tasks replay the log in chunks and append the record of every keyed operation to the
/// bucket that owns its key's partition. Then tasks sort each bucket by key and location, let
/// the newest operation of each key decide whether the key survives, and load the survivors in
/// key order. The order operations arrive in does not matter, because a key's operations are
/// compared directly.
///
/// A build that holds more than [MEMORY_BYTES] of records keeps the rest in a blob of the
/// `scratch` partition. Returns the number of active keys and the activity bitmap (see
/// [Rebuild::build_snapshot]).
///
/// `scan` chooses the chunks of the first phase and sees each one's operations (see [Scan]). If
/// it stops the build, nothing is sorted and the result is unspecified.
#[allow(clippy::too_many_arguments)]
async fn build<F, E, C, I, S>(
    snapshot: &mut I,
    context: E,
    inactivity_floor_loc: Location<F>,
    log: &Arc<C>,
    init_concurrency: NonZeroUsize,
    init_buffer: NonZeroUsize,
    scratch: &str,
    scan: S,
) -> Result<(usize, BitMap), Error<F>>
where
    F: Family,
    E: Spawner + crate::Context,
    C: Contiguous<Item: Operation<F>> + 'static,
    I: Partitioned + Index<Value = Location<F>>,
    S: Scan<F, C::Item>,
{
    let floor = *inactivity_floor_loc;
    let end = log.bounds().end;
    let ops = end - floor;
    let tasks = init_concurrency.get();

    // A tagged location holds an offset below `ops` and the delete bit.
    assert!(ops < 1 << 63, "too many operations to replay");
    let loc_bytes = (u64::BITS - ops.leading_zeros() + 1).div_ceil(8) as usize;

    // The bytes of records to expect, taking a key to be as large as its type. Keys of variable
    // length can be larger, which makes buckets larger than planned. A bucket that outgrows
    // [MERGE_BYTES] is merged, so the estimate affects speed and not what memory holds.
    let record_bytes = 1 + loc_bytes + core::mem::size_of::<<C::Item as Operation<F>>::Key>();
    let bytes = ops.saturating_mul(record_bytes as u64);

    // Split the partitions into buckets of whole partitions, enough of them to bound each
    // bucket's records and to occupy every task when there are records to go around.
    let partitions = snapshot.partition_count();
    let bucket_bytes = (bytes / tasks as u64).clamp(MIN_BUCKET_BYTES, BUCKET_BYTES);
    let buckets = usize::try_from(bytes.div_ceil(bucket_bytes))
        .unwrap_or(usize::MAX)
        .clamp(1, partitions);
    let per_bucket = partitions.div_ceil(buckets);
    let buckets = partitions.div_ceil(per_bucket);

    // Records left by an interrupted build are never read.
    remove_scratch(&context, scratch).await?;
    let shared = Arc::new(Buckets {
        layout: Layout {
            partition_of: I::partition_of,
            per_bucket,
            floor,
            loc_bytes,
            record_bytes,
        },
        buckets: (0..buckets)
            .map(|bucket| {
                let lo = bucket * per_bucket;
                Mutex::new(Bucket {
                    records: Records::default(),
                    range: Some(snapshot.new_range(lo, per_bucket.min(partitions - lo))),
                })
            })
            .collect(),
        held: AtomicU64::new(0),
        spare: Mutex::new(Vec::new()),
        scratch: scratch.to_string(),
        blob: AsyncMutex::new(None),
        end: AtomicU64::new(0),
    });

    // Fill the buckets. The scan has seen every chunk once this returns, so it is released
    // before the buckets are sorted.
    let routed = route_chunks(
        &context,
        log,
        &scan,
        floor,
        end,
        tasks,
        init_buffer,
        &shared,
    )
    .await?;
    drop(scan);

    // All sorters share one atomic bitmap to track the activity bits. Keys are partitioned
    // across buckets, so every bit has a single writer.
    let active = Arc::new(Atomic::zeroes(ops));
    let sorters = tasks.min(buckets);
    let next = Arc::new(AtomicUsize::new(0));
    let filled = if !routed {
        // The scan reports why it stopped the build, and its caller discards the result.
        Vec::new()
    } else if sorters <= 1 {
        vec![sort_and_load::<F, _, _>(&context, &shared, &next, &active).await?]
    } else {
        // A sorter fills the partitions of the buckets it claims, so the order the sorters
        // finish in does not matter.
        let running = Tasks(FuturesUnordered::new());
        for sorter in 0..sorters {
            let next = next.clone();
            let shared = shared.clone();
            let active = active.clone();
            let handle = context
                .child("snapshot_sorter")
                .with_attribute("sorter", sorter)
                .dedicated()
                .spawn(move |context| async move {
                    sort_and_load::<F, _, _>(&context, &shared, &next, &active).await
                });
            running.0.push(handle);
        }
        running.join().await?
    };

    // The joins reclaimed exclusive ownership of the buckets and the bitmap. Dropping the
    // buckets closes the scratch blob, if the build needed one.
    let spilled = Arc::into_inner(shared)
        .expect("tasks were joined")
        .blob
        .into_inner()
        .is_some();
    if spilled {
        remove_scratch(&context, scratch).await?;
    }
    let mut active = Arc::into_inner(active)
        .expect("tasks were joined")
        .into_bitmap();

    // Install each bucket's partitions into the snapshot and fold its active-key count in.
    let mut total_items = 0;
    for (ranges, keys) in filled {
        for range in ranges {
            snapshot.install_range(range);
        }
        total_items += keys;
    }

    // The last operation is the final commit (a log always ends with one), which stays active.
    // An empty log has none.
    if let Some(last_commit) = end.checked_sub(1)
        && last_commit >= floor
    {
        active.set(last_commit - floor, true);
    }

    Ok((total_items, active))
}

/// Configures snapshot rebuilding during QMDB initialization.
///
/// This trait is sealed to the index types provided by this crate.
#[expect(
    private_bounds,
    reason = "the Rebuild supertrait is private so only QMDB can call build_snapshot"
)]
pub trait SnapshotBuild<F: Family>:
    Index<Value = Location<F>> + Rebuild<F> + Sized + 'static
{
}

/// Replays the log into an index owned by initialization. Implementations must drop all log
/// clones before returning, including on error.
pub(super) trait Rebuild<F: Family>: Index<Value = Location<F>> + Sized {
    /// Replay `log` from `inactivity_floor_loc` on `init_concurrency` tasks, populating `self`,
    /// which must be empty. Returns the number of active keys and the activity status of every
    /// replayed location, in location order: a location's bit is set iff it holds the current
    /// operation of an active key or is the last commit.
    ///
    /// `init_buffer` sizes the replay read buffer (in bytes). `scratch` names a partition the
    /// build may keep temporary data in, which it removes before returning successfully.
    fn build_snapshot<E, C>(
        &mut self,
        context: E,
        inactivity_floor_loc: Location<F>,
        log: &Arc<C>,
        init_concurrency: NonZeroUsize,
        init_buffer: NonZeroUsize,
        scratch: &str,
    ) -> impl Future<Output = Result<(usize, BitMap), Error<F>>> + Send
    where
        E: Spawner + crate::Context,
        C: Contiguous<Item: Operation<F>> + 'static;

    /// Like [Self::build_snapshot], but the tasks that replay the log also hash every chunk of
    /// `leaves` and send them to it in order. If `leaves` stops accepting chunks, the journal
    /// reports why and the result is unspecified.
    #[allow(clippy::too_many_arguments)]
    fn build_snapshot_hashing<E, C, H>(
        &mut self,
        context: E,
        inactivity_floor_loc: Location<F>,
        log: &Arc<C>,
        init_concurrency: NonZeroUsize,
        init_buffer: NonZeroUsize,
        scratch: &str,
        leaves: LeafSink<F, H>,
    ) -> impl Future<Output = Result<(usize, BitMap), Error<F>>> + Send
    where
        E: Spawner + crate::Context,
        C: Contiguous<Item: Operation<F> + Encode> + 'static,
        H: MerkleHasher<F> + 'static;
}

impl<F: Family, T: Translator> SnapshotBuild<F> for crate::index::unordered::Index<T, Location<F>> {}
impl<F: Family, T: Translator> SnapshotBuild<F> for crate::index::ordered::Index<T, Location<F>> {}
impl<F: Family, T: Translator, const P: usize> SnapshotBuild<F>
    for crate::index::partitioned::unordered::Index<T, Location<F>, P>
{
}
impl<F: Family, T: Translator, const P: usize> SnapshotBuild<F>
    for crate::index::partitioned::ordered::Index<T, Location<F>, P>
{
}

impl<F: Family, I: Partitioned<Value = Location<F>>> Rebuild<F> for I {
    async fn build_snapshot<E, C>(
        &mut self,
        context: E,
        inactivity_floor_loc: Location<F>,
        log: &Arc<C>,
        init_concurrency: NonZeroUsize,
        init_buffer: NonZeroUsize,
        scratch: &str,
    ) -> Result<(usize, BitMap), Error<F>>
    where
        E: Spawner + crate::Context,
        C: Contiguous<Item: Operation<F>> + 'static,
    {
        build(
            self,
            context,
            inactivity_floor_loc,
            log,
            init_concurrency,
            init_buffer,
            scratch,
            IndexOnly,
        )
        .await
    }

    async fn build_snapshot_hashing<E, C, H>(
        &mut self,
        context: E,
        inactivity_floor_loc: Location<F>,
        log: &Arc<C>,
        init_concurrency: NonZeroUsize,
        init_buffer: NonZeroUsize,
        scratch: &str,
        leaves: LeafSink<F, H>,
    ) -> Result<(usize, BitMap), Error<F>>
    where
        E: Spawner + crate::Context,
        C: Contiguous<Item: Operation<F> + Encode> + 'static,
        H: MerkleHasher<F> + 'static,
    {
        build(
            self,
            context,
            inactivity_floor_loc,
            log,
            init_concurrency,
            init_buffer,
            scratch,
            leaves,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        index::{ordered, partitioned, unordered},
        journal::{Error as JournalError, contiguous::Batch},
        merkle::mmr,
        qmdb::operation::Committable,
        translator::{EightCap, OneCap},
    };
    use commonware_runtime::{
        BlobVersion, Clock as _, Runner as _, Supervisor as _, deterministic, reschedule,
    };
    use commonware_utils::{NZUsize, TestRng, probability, test_rng};
    use core::{ops::Range, time::Duration};
    use futures::{
        Stream,
        future::{pending, ready},
        stream,
    };
    use rand::RngExt as _;
    use std::collections::HashMap;

    /// An operation of a log held in memory.
    #[derive(Clone)]
    enum TestOp {
        Update(Vec<u8>),
        Delete(Vec<u8>),
        Commit,
    }

    impl Committable<mmr::Family> for TestOp {
        fn inactivity_floor(&self) -> Option<Location<mmr::Family>> {
            matches!(self, Self::Commit).then(|| Location::new(0))
        }

        fn initial_commit() -> Self {
            Self::Commit
        }
    }

    impl Operation<mmr::Family> for TestOp {
        type Key = Vec<u8>;

        fn key(&self) -> Option<&Vec<u8>> {
            match self {
                Self::Update(key) | Self::Delete(key) => Some(key),
                Self::Commit => None,
            }
        }

        fn into_key(self) -> Option<Vec<u8>> {
            match self {
                Self::Update(key) | Self::Delete(key) => Some(key),
                Self::Commit => None,
            }
        }

        fn is_update(&self) -> bool {
            matches!(self, Self::Update(_))
        }

        fn is_delete(&self) -> bool {
            matches!(self, Self::Delete(_))
        }
    }

    /// A log held in memory, replayed a few operations at a time.
    struct MemoryLog(Vec<TestOp>);

    impl Contiguous for MemoryLog {
        type Item = TestOp;

        fn bounds(&self) -> Range<u64> {
            0..self.0.len() as u64
        }

        fn read(
            &self,
            position: u64,
        ) -> impl Future<Output = Result<Self::Item, JournalError>> + Send {
            ready(Ok(self.0[position as usize].clone()))
        }

        fn read_many(
            &self,
            positions: &[u64],
        ) -> impl Future<Output = Result<Vec<Self::Item>, JournalError>> + Send {
            ready(Ok(positions
                .iter()
                .map(|&position| self.0[position as usize].clone())
                .collect()))
        }

        fn try_read_sync(&self, position: u64) -> Option<Self::Item> {
            self.0.get(position as usize).cloned()
        }

        fn try_read_many_sync(&self, positions: &[u64]) -> Vec<Option<Self::Item>> {
            positions
                .iter()
                .map(|&position| self.try_read_sync(position))
                .collect()
        }

        fn replay(
            &self,
            range: Range<u64>,
            _buffer: NonZeroUsize,
            _read_options: ReadOptions,
        ) -> impl Future<
            Output = Result<
                impl Stream<Item = Result<Batch<Self::Item>, JournalError>> + Send,
                JournalError,
            >,
        > + Send {
            let batches: Vec<_> = range
                .clone()
                .step_by(5)
                .map(|start| {
                    let stop = (start + 5).min(range.end);
                    Ok(Batch {
                        start,
                        items: self.0[start as usize..stop as usize].to_vec(),
                    })
                })
                .collect();
            ready(Ok(stream::iter(batches)))
        }
    }

    /// A log of `ops` operations over the keys `key` draws, ending in a commit. A fifth of the
    /// operations delete their key, and a commit follows every hundredth.
    fn test_log(ops: usize, mut key: impl FnMut(&mut TestRng) -> Vec<u8>) -> Vec<TestOp> {
        let mut rng = test_rng();
        let mut log = Vec::with_capacity(ops + ops / 100 + 1);
        for i in 0..ops {
            let key = key(&mut rng);
            log.push(if rng.random_range(0..5) == 0 {
                TestOp::Delete(key)
            } else {
                TestOp::Update(key)
            });
            if i % 100 == 99 {
                log.push(TestOp::Commit);
            }
        }
        log.push(TestOp::Commit);
        log
    }

    /// The chunks a scan passed on, each with the number of operations its visitor saw.
    type Passed = Arc<Mutex<Vec<(Range<u64>, u64)>>>;

    /// Counts the operations of a chunk.
    struct Counter(Range<u64>, u64);

    impl ChunkVisitor<mmr::Family, TestOp> for Counter {
        type Output = (Range<u64>, u64);

        fn visit(&mut self, _: &TestOp) {
            self.1 += 1;
        }

        fn finish(self) -> Result<Self::Output, merkle::Error<mmr::Family>> {
            Ok((self.0, self.1))
        }
    }

    /// A scan of the whole log in chunks of uneven sizes, as a journal that hashes them chooses
    /// its own. Records each chunk passed on and stops the build at the `limit`th.
    struct Recorder {
        end: u64,
        passed: Passed,
        limit: usize,
    }

    impl Scan<mmr::Family, TestOp> for Recorder {
        type Visitor = Counter;

        fn chunks(&self, _: u64, _: u64) -> impl Iterator<Item = Range<u64>> + Send + 'static {
            let (end, mut next) = (self.end, 0);
            [7, 64, 1, 120, 33]
                .into_iter()
                .cycle()
                .map_while(move |width: u64| {
                    (next < end).then(|| {
                        let chunk = next..(next + width).min(end);
                        next = chunk.end;
                        chunk
                    })
                })
        }

        fn visitor(&self, chunk: Range<u64>) -> Counter {
            Counter(chunk, 0)
        }

        async fn send(&self, output: (Range<u64>, u64)) -> bool {
            let mut passed = self.passed.lock();
            passed.push(output);
            passed.len() < self.limit
        }
    }

    /// The operations a [check_build] replays.
    #[derive(Clone, Copy)]
    enum Replay {
        /// Those from the floor, as a build that only routes.
        Floor,
        /// The whole log, as a build that also hashes it.
        Log,
    }

    /// Build the snapshot of `log` from `floor` into `index` on `tasks` tasks, and check the
    /// index, the active-key count and the activity bitmap against the operations applied in
    /// order. A build that replays the whole log must also pass every chunk on once, in order.
    async fn check_build<I>(
        context: deterministic::Context,
        mut index: I,
        log: Vec<TestOp>,
        floor: u64,
        tasks: usize,
        replay: Replay,
    ) where
        I: Partitioned + Index<Value = Location<mmr::Family>>,
    {
        let mut expected = HashMap::new();
        for (loc, op) in log.iter().enumerate().skip(floor as usize) {
            match op {
                TestOp::Update(key) => {
                    expected.insert(key.clone(), loc as u64);
                }
                TestOp::Delete(key) => {
                    expected.remove(key);
                }
                TestOp::Commit => {}
            }
        }
        let end = log.len() as u64;
        let log = Arc::new(MemoryLog(log));
        let passed = Passed::default();
        let (start, tasks) = (Location::new(floor), NonZeroUsize::new(tasks).unwrap());
        let (build_context, buffer) = (context.child("build"), NZUsize!(1024));
        let (active_keys, active) = match replay {
            Replay::Floor => {
                let scan = IndexOnly;
                build(
                    &mut index,
                    build_context,
                    start,
                    &log,
                    tasks,
                    buffer,
                    "scratch",
                    scan,
                )
                .await
            }
            Replay::Log => {
                let scan = Recorder {
                    end,
                    passed: passed.clone(),
                    limit: usize::MAX,
                };
                build(
                    &mut index,
                    build_context,
                    start,
                    &log,
                    tasks,
                    buffer,
                    "scratch",
                    scan,
                )
                .await
            }
        }
        .unwrap();
        if matches!(replay, Replay::Log) {
            let mut next = 0;
            for (chunk, seen) in passed.lock().iter() {
                assert_eq!(chunk.start, next);
                assert_eq!(*seen, chunk.end - chunk.start);
                next = chunk.end;
            }
            assert_eq!(next, end);
        }
        assert_eq!(Arc::strong_count(&log), 1);
        assert!(matches!(
            context.scan("scratch").await,
            Err(RuntimeError::PartitionMissing(_))
        ));
        assert_eq!(active_keys, expected.len());
        assert_eq!(index.items(), expected.len());
        for (key, loc) in &expected {
            assert!(index.get(key).any(|found| **found == *loc));
        }

        // The current operation of every active key is active, and so is the last commit.
        let mut ones: Vec<u64> = expected.values().map(|loc| loc - floor).collect();
        ones.push(end - 1 - floor);
        ones.sort_unstable();
        assert_eq!(active.len(), end - floor);
        assert_eq!(
            (0..active.len())
                .filter(|&bit| active.get(bit))
                .collect::<Vec<_>>(),
            ones
        );
    }

    /// Run [check_build] on `log` for every index type, with translators that do and do
    /// not make keys collide, from the start of the log and from part way in, inline and on
    /// several tasks, replaying from the floor and from the start of the log.
    fn check_builds(log: Vec<TestOp>) {
        deterministic::Runner::default().start(|context| async move {
            let mut case = 0;
            let floors = [0, log.len() as u64 / 3];
            let replays = [Replay::Floor, Replay::Log];
            for (floor, replay) in floors.into_iter().flat_map(|f| replays.map(|r| (f, r))) {
                for tasks in [1, 3] {
                    let context = context.child("run").with_attribute("case", case);
                    case += 1;
                    check_build(
                        context.child("unordered_one"),
                        partitioned::unordered::Index::<_, _, 1>::new(context.child("a"), OneCap),
                        log.clone(),
                        floor,
                        tasks,
                        replay,
                    )
                    .await;
                    check_build(
                        context.child("unordered_eight"),
                        partitioned::unordered::Index::<_, _, 1>::new(context.child("b"), EightCap),
                        log.clone(),
                        floor,
                        tasks,
                        replay,
                    )
                    .await;
                    check_build(
                        context.child("ordered_one"),
                        partitioned::ordered::Index::<_, _, 1>::new(context.child("c"), OneCap),
                        log.clone(),
                        floor,
                        tasks,
                        replay,
                    )
                    .await;
                    check_build(
                        context.child("ordered_eight"),
                        partitioned::ordered::Index::<_, _, 2>::new(context.child("d"), EightCap),
                        log.clone(),
                        floor,
                        tasks,
                        replay,
                    )
                    .await;
                    check_build(
                        context.child("flat_unordered"),
                        unordered::Index::new(context.child("e"), EightCap),
                        log.clone(),
                        floor,
                        tasks,
                        replay,
                    )
                    .await;
                    check_build(
                        context.child("flat_ordered"),
                        ordered::Index::new(context.child("f"), OneCap),
                        log.clone(),
                        floor,
                        tasks,
                        replay,
                    )
                    .await;
                }
            }
        });
    }

    #[test]
    fn test_build_spread_keys() {
        // Keys spread over every partition, each written a few times.
        check_builds(test_log(4000, |rng| {
            let mut key = vec![0u8; 32];
            key[..2].copy_from_slice(&rng.random_range(0u16..1500).to_be_bytes());
            key[0] = key[0].wrapping_mul(97).wrapping_add(key[1]);
            key
        }));
    }

    #[test]
    fn test_build_crowded_keys() {
        // Every key shares its first three bytes, so one bucket receives all of the records and
        // is sorted in pieces.
        check_builds(test_log(4000, |rng| {
            let mut key = vec![7u8; 32];
            key[3..5].copy_from_slice(&rng.random_range(0u16..1500).to_be_bytes());
            key
        }));
    }

    #[test]
    fn test_build_rewritten_keys() {
        // A handful of keys take every operation.
        check_builds(test_log(4000, |rng| vec![rng.random_range(0u8..5); 20]));
    }

    #[test]
    fn test_build_key_lengths() {
        // Keys from empty to longer than a one-byte length holds, many of them prefixes of
        // others. Half crowd into a few partitions, whose bucket is sorted in pieces. The rest
        // are short and spread over every partition.
        check_builds(test_log(3000, |rng| {
            if rng.random_range(0..2) == 0 {
                return vec![rng.random(); rng.random_range(0..10)];
            }
            let len = match rng.random_range(0..3) {
                0 => rng.random_range(0..4),
                1 => rng.random_range(250..260),
                _ => rng.random_range(0..600),
            };
            vec![rng.random_range(0u8..3); len]
        }));
    }

    #[test]
    fn test_build_removes_leftover_scratch() {
        // A build that was interrupted leaves its scratch blob behind. The next build must not
        // read it and must remove it.
        deterministic::Runner::default().start(|context| async move {
            let (blob, _) = context.open("scratch", SCRATCH_BLOB).await.unwrap();
            blob.write_at(0, vec![0xFF; 4096], WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();
            drop(blob);
            for (case, ops) in [10, 4000].into_iter().enumerate() {
                let context = context.child("run").with_attribute("case", case);
                check_build(
                    context.child("build"),
                    partitioned::unordered::Index::<_, _, 1>::new(context.child("index"), EightCap),
                    test_log(ops, |rng| vec![rng.random(); 32]),
                    0,
                    3,
                    Replay::Floor,
                )
                .await;
            }
        });
    }

    /// A storage whose opens yield once before they run, so that two tasks can both be opening
    /// a blob at the same time.
    struct SlowOpen(deterministic::Context);

    impl Storage for SlowOpen {
        type Blob = <deterministic::Context as Storage>::Blob;

        async fn open_versioned(
            &self,
            partition: &str,
            name: &[u8],
            versions: core::ops::RangeInclusive<BlobVersion>,
        ) -> Result<(Self::Blob, u64, BlobVersion), RuntimeError> {
            reschedule().await;
            self.0.open_versioned(partition, name, versions).await
        }

        async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), RuntimeError> {
            self.0.remove(partition, name).await
        }

        async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, RuntimeError> {
            self.0.scan(partition).await
        }
    }

    #[test]
    fn test_build_opens_scratch_once() {
        // Tasks whose first writes to scratch overlap must end up sharing one handle to the
        // blob, which storage allows to be open only once.
        deterministic::Runner::default().start(|context| async move {
            let storage = SlowOpen(context.child("storage"));
            let buckets = Buckets::<_, ()> {
                layout: Layout {
                    partition_of: |_| 0,
                    per_bucket: 1,
                    floor: 0,
                    loc_bytes: 1,
                    record_bytes: 1,
                },
                buckets: Vec::new(),
                held: AtomicU64::new(0),
                spare: Default::default(),
                scratch: "scratch".to_string(),
                blob: Default::default(),
                end: AtomicU64::new(0),
            };
            let (first, second) = futures::join!(
                buckets.write(&storage, vec![1; 100]),
                buckets.write(&storage, vec![2; 100]),
            );
            let runs = [first.unwrap(), second.unwrap()];
            assert_ne!(runs[0].0, runs[1].0);
            let mut data = Vec::new();
            buckets
                .read(&runs, |run| data.extend_from_slice(run))
                .await
                .unwrap();
            data.sort_unstable();
            assert_eq!(data, [vec![1; 100], vec![2; 100]].concat());
        });
    }

    #[test]
    fn test_build_spills_long_keys() {
        // Few operations on keys much longer than their type suggests. The build must count the
        // records it actually holds, so it has to write these to scratch, which a build that
        // cannot write shows by failing.
        deterministic::Runner::default().start(|context| async move {
            let log = test_log(20, |rng| vec![rng.random(); 500]);
            for faulty in [false, true] {
                let context = context.child("case").with_attribute("faulty", faulty);
                if !faulty {
                    check_build(
                        context.child("build"),
                        unordered::Index::new(context.child("index"), EightCap),
                        log.clone(),
                        0,
                        1,
                        Replay::Floor,
                    )
                    .await;
                    continue;
                }
                context.storage_fault_config().write().write_rate =
                    Some(deterministic::WriteConfig {
                        failure_rate: probability!(1.0),
                        retention_rate: probability!(0.0),
                        mode: deterministic::PartialWriteMode::Prefix,
                    });
                let mut index = unordered::Index::new(context.child("index"), EightCap);
                let result = build(
                    &mut index,
                    context.child("build"),
                    Location::<mmr::Family>::new(0),
                    &Arc::new(MemoryLog(log.clone())),
                    NonZeroUsize::MIN,
                    NZUsize!(1024),
                    "scratch",
                    IndexOnly,
                )
                .await;
                assert!(matches!(result, Err(Error::Runtime(_))));
                context.storage_fault_config().write().write_rate = None;
            }
        });
    }

    #[test]
    fn test_build_stops_with_its_scan() {
        // A scan that stops accepting chunks ends the build without an error of its own, since
        // the scan reports why. Every task must have ended and nothing may be left in scratch.
        deterministic::Runner::default().start(|context| async move {
            let ops = test_log(4000, |rng| vec![rng.random(); 32]);
            for tasks in [1, 3] {
                let context = context.child("case").with_attribute("tasks", tasks);
                let log = Arc::new(MemoryLog(ops.clone()));
                let passed = Passed::default();
                let scan = Recorder {
                    end: ops.len() as u64,
                    passed: passed.clone(),
                    limit: 5,
                };
                let mut index =
                    partitioned::unordered::Index::<_, _, 1>::new(context.child("index"), EightCap);
                build(
                    &mut index,
                    context.child("build"),
                    Location::<mmr::Family>::new(0),
                    &log,
                    NZUsize!(tasks),
                    NZUsize!(1024),
                    "scratch",
                    scan,
                )
                .await
                .unwrap();
                assert_eq!(passed.lock().len(), 5);
                assert_eq!(Arc::strong_count(&log), 1);
                assert!(matches!(
                    context.scan("scratch").await,
                    Err(RuntimeError::PartitionMissing(_))
                ));
            }
        });
    }

    /// A log whose first chunk fails to replay, or replays as [MemoryLog]'s does, and whose other
    /// chunks never finish replaying.
    struct StuckLog {
        log: MemoryLog,
        fail: bool,
    }

    impl Contiguous for StuckLog {
        type Item = TestOp;

        fn bounds(&self) -> Range<u64> {
            self.log.bounds()
        }

        fn read(
            &self,
            position: u64,
        ) -> impl Future<Output = Result<Self::Item, JournalError>> + Send {
            self.log.read(position)
        }

        fn read_many(
            &self,
            positions: &[u64],
        ) -> impl Future<Output = Result<Vec<Self::Item>, JournalError>> + Send {
            self.log.read_many(positions)
        }

        fn try_read_sync(&self, position: u64) -> Option<Self::Item> {
            self.log.try_read_sync(position)
        }

        fn try_read_many_sync(&self, positions: &[u64]) -> Vec<Option<Self::Item>> {
            self.log.try_read_many_sync(positions)
        }

        async fn replay(
            &self,
            range: Range<u64>,
            buffer: NonZeroUsize,
            read_options: ReadOptions,
        ) -> Result<impl Stream<Item = Result<Batch<Self::Item>, JournalError>> + Send, JournalError>
        {
            if range.start > 0 {
                pending::<()>().await;
            }

            // The decoders of the other chunks get a turn first, so that they are replaying by
            // the time this chunk's replay returns.
            reschedule().await;
            if self.fail {
                return Err(JournalError::Runtime(RuntimeError::ReadFailed));
            }
            self.log.replay(range, buffer, read_options).await
        }
    }

    #[test]
    fn test_build_aborts_decoders() {
        // A decoder whose read never returns must not hold up a build that has failed, or one
        // that its scan has stopped. Every task must still have ended when the build returns.
        deterministic::Runner::default().start(|context| async move {
            let ops = test_log(4000, |rng| vec![rng.random(); 32]);
            for fail in [true, false] {
                let context = context.child("case").with_attribute("fail", fail);
                let log = Arc::new(StuckLog {
                    log: MemoryLog(ops.clone()),
                    fail,
                });
                let passed = Passed::default();
                let scan = Recorder {
                    end: ops.len() as u64,
                    passed: passed.clone(),
                    limit: 1,
                };
                let building = {
                    let (context, log) = (context.child("build"), log.clone());
                    async move {
                        let mut index = unordered::Index::new(context.child("index"), EightCap);
                        build(
                            &mut index,
                            context,
                            Location::<mmr::Family>::new(0),
                            &log,
                            NZUsize!(3),
                            NZUsize!(1024),
                            "scratch",
                            scan,
                        )
                        .await
                        .map(|_| ())
                    }
                };
                let result = context
                    .timeout(Duration::from_secs(1), building)
                    .await
                    .expect("build waited on a decoder");
                if fail {
                    assert!(matches!(
                        result,
                        Err(Error::Journal(JournalError::Runtime(
                            RuntimeError::ReadFailed
                        )))
                    ));
                    assert!(passed.lock().is_empty());
                } else {
                    result.unwrap();
                    assert_eq!(passed.lock().len(), 1);
                }
                assert_eq!(Arc::strong_count(&log), 1);
            }
        });
    }

    #[test]
    fn test_tasks_join() {
        deterministic::Runner::default().start(|context| async move {
            // Every task's output is returned.
            let tasks = Tasks(FuturesUnordered::new());
            for output in 0..3 {
                let task = context.child("task").with_attribute("output", output);
                tasks.0.push(task.spawn(move |_| async move {
                    for _ in output..3 {
                        reschedule().await;
                    }
                    Ok::<_, Error<mmr::Family>>(output)
                }));
            }
            let mut outputs = tasks.join().await.unwrap();
            outputs.sort_unstable();
            assert_eq!(outputs, [0, 1, 2]);

            // A task that fails ends the join, even while one spawned before it never finishes
            // on its own. That task has ended by the time the join returns.
            let held = Arc::new(());
            let tasks = Tasks(FuturesUnordered::new());
            let stuck = held.clone();
            tasks
                .0
                .push(context.child("stuck").spawn(move |_| async move {
                    let _stuck = stuck;
                    pending::<()>().await;
                    Ok::<_, Error<mmr::Family>>(())
                }));
            tasks.0.push(context.child("failed").spawn(|_| async move {
                reschedule().await;
                Err(Error::Runtime(RuntimeError::ReadFailed))
            }));
            let result = context
                .timeout(Duration::from_secs(1), tasks.join())
                .await
                .expect("join waited on a task");
            assert!(matches!(
                result,
                Err(Error::Runtime(RuntimeError::ReadFailed))
            ));
            assert_eq!(Arc::strong_count(&held), 1);
        });
    }

    #[test]
    fn test_build_without_keys() {
        check_builds(vec![TestOp::Commit]);
        check_builds(vec![TestOp::Commit; 300]);
    }

    /// Split the records of `ops`, each a key and a tagged location, through a [Sorter] started
    /// for `prefixes`, and check that its groups in turn yield the newest record of every key in
    /// ascending key order. The records arrive `piece` at a time.
    fn check_sorter(ops: &[(Vec<u8>, u64)], prefixes: (u64, u64), piece: usize) {
        let layout = Layout {
            partition_of: |_| 0,
            per_bucket: 1,
            floor: 0,
            loc_bytes: 3,
            record_bytes: 12,
        };
        let mut pieces = Vec::new();
        let mut bytes = 0;
        for chunk in ops.chunks(piece.max(1)) {
            let mut data = Vec::new();
            for (key, tagged) in chunk {
                layout.encode(&mut data, key, *tagged);
            }
            bytes += data.len();
            pieces.push(data);
        }
        let mut sorter = Sorter::default();

        // A sorter is reused, so one that held other records must give the same result.
        for round in 0..2 {
            sorter.start(bytes, prefixes);
            for data in &pieces {
                sorter.split(data, layout);
            }
            let mut sorted = Vec::new();
            for group in 0..sorter.groups() {
                let (records, data) = sorter.sort(group, layout);
                sorted.extend(records.iter().map(|r| (r.key(data).to_vec(), r.tagged)));
            }
            let mut newest = BTreeMap::new();
            for (key, tagged) in ops {
                let entry = newest.entry(key.clone()).or_insert(*tagged);
                *entry = (*entry).max(*tagged);
            }
            let expected: Vec<_> = newest.into_iter().collect();
            assert_eq!(sorted, expected, "round {round}");
        }
    }

    /// The smallest and largest key prefix among `ops`.
    fn prefixes_of(ops: &[(Vec<u8>, u64)]) -> (u64, u64) {
        ops.iter().fold((u64::MAX, 0), |(min, max), (key, _)| {
            let prefix = key_prefix(key);
            (min.min(prefix), max.max(prefix))
        })
    }

    #[test]
    fn test_sorter_orders_groups() {
        let mut rng = test_rng();

        // Keys spread over every prefix, each rewritten a few times.
        let mut spread = Vec::new();
        for tagged in 0..2000u64 {
            let mut key = vec![0u8; 9];
            key[0] = rng.random();
            key[1] = rng.random();
            key[8] = rng.random::<u8>() % 3;
            spread.push((key, tagged));
        }
        for piece in [1, 7, 2000] {
            check_sorter(&spread, prefixes_of(&spread), piece);
        }

        // Keys of a narrow span, of every length up to and beyond the prefix.
        let mut narrow = Vec::new();
        for tagged in 0..1500u64 {
            let len = rng.random_range(0..12usize);
            let mut key = vec![7u8; len];
            if let Some(last) = key.last_mut() {
                *last = rng.random();
            }
            narrow.push((key, tagged));
        }
        check_sorter(&narrow, prefixes_of(&narrow), 100);

        // Nothing to sort.
        check_sorter(&[], (u64::MAX, 0), 1);
    }

    #[test]
    fn test_sorter_orders_crowded_groups() {
        let mut rng = test_rng();

        // Every key shares its prefix, so they all crowd into one group, which holds far more
        // than its region does.
        let mut crowded = Vec::new();
        for tagged in 0..1500u64 {
            let mut key = vec![9u8; 10];
            key[8] = rng.random();
            key[9] = rng.random::<u8>() % 4;
            crowded.push((key, tagged));
        }
        check_sorter(&crowded, prefixes_of(&crowded), 64);

        // Most keys crowd at one end of a span that the rest stretch to its widest.
        let mut lopsided = crowded.clone();
        lopsided.push((vec![0u8; 8], 5000));
        lopsided.push((vec![0xFFu8; 8], 5001));
        check_sorter(&lopsided, prefixes_of(&lopsided), 64);
        assert_eq!(prefixes_of(&lopsided), (0, u64::MAX));
    }

    #[test]
    fn test_sorter_orders_keys_outside_its_span() {
        let mut rng = test_rng();
        let mut ops = Vec::new();
        for tagged in 0..1000u64 {
            ops.push((rng.random::<[u8; 8]>().to_vec(), tagged));
        }

        // A span that covers none, some or all of the keys changes only how they are grouped.
        let (min, max) = prefixes_of(&ops);
        let middle = min / 2 + max / 2;
        for prefixes in [
            (u64::MAX, 0),
            (middle, middle),
            (middle, max),
            (min, middle),
            (0, u64::MAX),
        ] {
            check_sorter(&ops, prefixes, 50);
        }
    }
}

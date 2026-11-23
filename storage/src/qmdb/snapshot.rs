//! Rebuild snapshot indexes and activity bitmaps from the operations log.
//!
//! A build has two phases. It first replays the log, writing a small record for every keyed
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
use bytes::BufMut as _;
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
/// as they arrive, so the bound holds whatever size the keys are. A larger budget buys little:
/// in benchmarks, a build that held every record in memory was less than 2% faster. Small in
/// tests so ordinary logs use a blob.
#[cfg(not(test))]
const MEMORY_BYTES: u64 = 64 << 20;
#[cfg(test)]
const MEMORY_BYTES: u64 = 1024;

/// Bytes of records a bucket collects before it writes them to the scratch blob, once the build
/// holds more than [MEMORY_BYTES]. A bucket with fewer keeps them in memory, so a build with many
/// buckets holds up to this much for each. Small writes are costly: in benchmarks, a build that
/// wrote 256 KiB at a time took 19% longer. Small in tests so ordinary logs write several times.
#[cfg(not(test))]
const SPILL_BYTES: usize = 4 << 20;
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

/// Return the newest record of each key in `data`, records in any order, in ascending key order.
fn sort_records(data: &[u8], layout: Layout) -> Vec<Record> {
    assert!(
        u32::try_from(data.len()).is_ok(),
        "too many records to sort at once"
    );
    let mut records = Vec::with_capacity(data.len() / layout.record_bytes + 1);
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
    records
}

/// Insert the keys that survive `data`, one bucket's records, into `index` in ascending key order.
/// A key survives if its newest operation is not a delete. Calls `activate` with each survivor's
/// offset from the floor and returns their number.
fn load_bucket<F, R>(
    index: &mut R,
    data: &[u8],
    layout: Layout,
    mut activate: impl FnMut(u64),
) -> usize
where
    F: Family,
    R: PartitionRange<Value = Location<F>>,
{
    let mut records = sort_records(data, layout);
    records.retain(|record| {
        let survives = record.tagged & 1 == 0;
        if survives {
            activate(record.tagged >> 1);
        }
        survives
    });

    // Survivors are distinct keys in ascending order, and a partition's keys are contiguous in
    // that order, so each partition is loaded at once. A key's partition depends only on its
    // first bytes, which the prefix holds.
    let partition = |record: &Record| {
        let prefix = record.prefix.to_be_bytes();
        (layout.partition_of)(&prefix[..(record.key_len as usize).min(prefix.len())])
    };
    let mut rest = records.as_slice();
    while let Some(first) = rest.first() {
        let first = partition(first);
        let (run, tail) = rest.split_at(rest.partition_point(|record| partition(record) == first));
        index.load(run.iter().map(|record| {
            (
                record.key(data),
                Location::new(layout.floor + (record.tagged >> 1)),
            )
        }));
        rest = tail;
    }
    records.len()
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

/// One bucket of a build: the records of the operations whose keys fall in a contiguous
/// range of partitions, and those partitions.
struct Bucket<R> {
    /// Records not yet written to the scratch blob.
    buf: Vec<u8>,
    /// Offset and length of each run of records written to the scratch blob.
    runs: Vec<(u64, usize)>,
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

    /// Append the records of `runs` to `data`, in whatever order their reads finish.
    async fn read(&self, runs: &[(u64, usize)], data: &mut Vec<u8>) -> Result<(), RuntimeError> {
        let blob = self.blob.lock().await.clone().expect("runs were written");
        let mut rest = runs;
        while !rest.is_empty() {
            let (batch, later) = rest.split_at(leading_runs(rest, READ_BYTES));
            rest = later;
            let reads = blob.read_many(batch, ReadOptions::DONT_CACHE);
            pin_mut!(reads);
            while let Some(read) = reads.next().await {
                let (_, run) = read?;
                data.put(run);
            }
        }
        Ok(())
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
        let run = {
            let mut bucket = self.buckets[bucket].lock();
            bucket.buf.extend_from_slice(staged);
            let added = staged.len() as u64;
            staged.clear();
            let held = self.held.fetch_add(added, Ordering::Relaxed) + added;
            if held <= MEMORY_BYTES || bucket.buf.len() < SPILL_BYTES {
                return Ok(());
            }
            self.held
                .fetch_sub(bucket.buf.len() as u64, Ordering::Relaxed);
            core::mem::replace(
                &mut bucket.buf,
                Vec::with_capacity(SPILL_BYTES + STAGE_BYTES),
            )
        };

        // Buckets are read back only after every decoder is done, so the run can be recorded
        // once its write completes.
        let run = self.write(context, run).await?;
        self.buckets[bucket].lock().runs.push(run);
        Ok(())
    }

    /// Take `bucket`'s partitions, the records it holds in memory and its runs in the scratch
    /// blob. A bucket can be taken once.
    fn take(&self, bucket: usize) -> (R, Vec<u8>, Vec<(u64, usize)>) {
        let mut bucket = self.buckets[bucket].lock();
        (
            bucket.range.take().expect("bucket taken twice"),
            core::mem::take(&mut bucket.buf),
            core::mem::take(&mut bucket.runs),
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

    /// Insert the keys that survive a bucket too large to sort at once into `index`, where `buf`
    /// and `runs` hold the bucket's records. Calls `activate` with each survivor's offset from
    /// the floor and returns their number.
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
        buf: Vec<u8>,
        runs: Vec<(u64, usize)>,
        mut activate: impl FnMut(u64) + Send,
    ) -> Result<usize, RuntimeError>
    where
        F: Family,
        R: PartitionRange<Value = Location<F>> + Send,
    {
        let layout = self.layout;
        let mut sorted = VecDeque::new();
        let mut unsorted = runs.as_slice();
        let mut buf = Some(buf);
        while buf.is_some() {
            // A piece is as many runs as fit, and at least one. The last piece starts from the
            // records still in memory, so it is sized once for both.
            let (piece, rest) = unsorted.split_at(leading_runs(unsorted, PIECE_BYTES));
            unsorted = rest;
            let mut data = if unsorted.is_empty() {
                buf.take().expect("records in memory join once")
            } else {
                Vec::new()
            };
            data.reserve_exact(piece.iter().map(|(_, len)| len).sum());
            self.read(piece, &mut data).await?;
            let mut run = RunWriter::default();
            for record in sort_records(&data, layout) {
                self.push(context, &mut run, record.key(&data), record.tagged)
                    .await?;
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

        // The survivors of one partition that are waiting to be loaded: their keys back to back,
        // and each one's place among the keys with its offset from the floor.
        let mut partition = 0;
        let mut keys = Vec::new();
        let mut entries: Vec<(usize, usize, u64)> = Vec::new();
        let mut load = |keys: &mut Vec<u8>, entries: &mut Vec<(usize, usize, u64)>| {
            index.load(entries.iter().map(|&(at, len, offset)| {
                (&keys[at..at + len], Location::new(layout.floor + offset))
            }));
            keys.clear();
            entries.clear();
        };
        let mut merge = Merge::new(blob, layout, sorted.into()).await?;
        let mut survivors = 0;
        while let Some(tagged) = merge.next(blob, layout).await? {
            if tagged & 1 != 0 {
                continue;
            }
            let of = (layout.partition_of)(&merge.key);
            if !entries.is_empty()
                && (of != partition
                    || entries.len() >= LOAD_KEYS
                    || keys.len() + merge.key.len() > LOAD_BYTES)
            {
                load(&mut keys, &mut entries);
            }
            partition = of;
            entries.push((keys.len(), merge.key.len(), tagged >> 1));
            keys.extend_from_slice(&merge.key);
            activate(tagged >> 1);
            survivors += 1;
        }
        if !entries.is_empty() {
            load(&mut keys, &mut entries);
        }
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
    let mut filled = Vec::new();
    let mut active_keys = 0;
    loop {
        let bucket = next.fetch_add(1, Ordering::Relaxed);
        if bucket >= buckets.buckets.len() {
            return Ok((filled, active_keys));
        }
        let (mut range, buf, runs) = buckets.take(bucket);

        // A bucket's records can exceed what a narrow address space counts, and such a bucket
        // is merged, so they are counted in 64 bits.
        let stored: u64 = runs.iter().map(|&(_, len)| len as u64).sum();
        let activate = |offset| active.set(offset);
        active_keys += if runs.is_empty() {
            load_bucket::<F, _>(&mut range, &buf, buckets.layout, activate)
        } else if stored + buf.len() as u64 <= MERGE_BYTES as u64 {
            let mut data = buf;
            data.reserve_exact(stored as usize);
            buckets.read(&runs, &mut data).await?;
            load_bucket::<F, _>(&mut range, &data, buckets.layout, activate)
        } else {
            buckets
                .merge::<F>(context, &mut range, buf, runs, activate)
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
                    buf: Vec::new(),
                    runs: Vec::new(),
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
            buckets.read(&runs, &mut data).await.unwrap();
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
}

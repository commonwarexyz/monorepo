//! Blocks: every block marshal holds, in two append streams over one index.
//!
//! The custody stream takes blocks the engine or the application needs promptly (staged,
//! subscribed, broadcast); the bulk stream takes blocks fetched for ordering and catch-up. Each
//! stream is its own [`Log`] with its own current segment and cuts, so a custody cut never waits
//! behind bulk bytes. One [`Index`] covers both: a block is identified by its exact reference,
//! and several digests may share a height.
//!
//! Rows hold the fixed-width header and the body location, so the index (headers included) is
//! rebuilt at open from index rows alone. Blocks below a chain's retention floor are dropped at
//! open and when the floor rises; a segment is reclaimed once none of its rows is retained.

use super::{
    Buffers, Error,
    log::{self, Access, Durability, Log},
};
use crate::{
    Epochable as _,
    multimmit::types::{BlockRef, Body, TransactionBlock, TransactionBlockHeader},
    types::{Epoch, Height},
};
use bytes::BufMut;
use commonware_codec::{
    Buf, EncodeSize as _, Error as CodecError, FixedSize, Read, ReadExt as _, Write,
};
use commonware_cryptography::{Digest, Hasher, crc32};
use commonware_storage::{Context, journal::segmented::oversized::Record};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};

/// One of the two append streams.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Stream {
    /// Blocks needed promptly: staged, subscribed and broadcast blocks.
    Custody = 0,
    /// Blocks fetched for ordering and catch-up.
    Bulk = 1,
}

impl Stream {
    /// Both streams.
    pub(crate) const ALL: [Self; 2] = [Self::Custody, Self::Bulk];

    const fn name(self) -> &'static str {
        match self {
            Self::Custody => "custody",
            Self::Bulk => "bulk",
        }
    }

    pub(crate) const fn index(self) -> usize {
        self as usize
    }
}

/// An index row: the fixed-width header and the location of the complete block.
///
/// Values are stored uncompressed, so a frame's size is the encoded block length plus the CRC32
/// trailer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Row<D: Digest> {
    header: TransactionBlockHeader<D>,
    offset: u64,
    size: u32,
}

impl<D: Digest> Read for Row<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let header = TransactionBlockHeader::read_fixed(buf)?;
        let offset = u64::read(buf)?;
        let size = u32::read(buf)?;
        if (size as usize) < crc32::Digest::SIZE {
            return Err(CodecError::Invalid(
                "consensus::multimmit::marshal::blocks::Row",
                "frame is smaller than its checksum",
            ));
        }
        Ok(Self {
            header,
            offset,
            size,
        })
    }
}

impl<D: Digest> Write for Row<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.header.write_fixed(buf);
        self.offset.write(buf);
        self.size.write(buf);
    }
}

impl<D: Digest> FixedSize for Row<D> {
    const SIZE: usize = TransactionBlockHeader::<D>::FIXED_SIZE + u64::SIZE + u32::SIZE;
}

impl<D: Digest> Record for Row<D> {
    fn value_location(&self) -> (u64, u32) {
        (self.offset, self.size)
    }

    fn with_location(mut self, offset: u64, size: u32) -> Self {
        self.offset = offset;
        self.size = size;
        self
    }
}

/// A complete block.
pub(crate) type Block<H, B> = Arc<TransactionBlock<H, B>>;

/// The offset and size of a stored frame within its segment.
pub(crate) type Location = (u64, u32);

/// How a held block can be read, and where its frame is.
pub(crate) type Located<E, H, B> = (Access<E, Block<H, B>>, Location);

/// The log of one stream.
type StreamLog<E, H, B> = Log<E, Row<<H as Hasher>::Digest>, Block<H, B>>;

/// Where a held block lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Held<D: Digest> {
    /// The block's header.
    pub(crate) header: TransactionBlockHeader<D>,
    /// The stream holding the block.
    pub(crate) stream: Stream,
    /// The block's position in its stream.
    pub(crate) position: u64,
    offset: u64,
    size: u32,
}

impl<D: Digest> Held<D> {
    /// Returns the encoded length of the complete block.
    pub(crate) fn encoded_len(&self) -> u64 {
        u64::from(self.size) - crc32::Digest::SIZE as u64
    }

    /// Returns the location of the block's frame in its segment.
    pub(crate) const fn location(&self) -> (u64, u32) {
        (self.offset, self.size)
    }
}

/// The index of held blocks: by digest, and by chain and height for retention.
pub(crate) struct Index<D: Digest> {
    epoch: Epoch,
    held: HashMap<D, Held<D>>,
    heights: Vec<BTreeMap<Height, Vec<D>>>,
    floors: Vec<Height>,
}

impl<D: Digest> Index<D> {
    /// Creates an empty index retaining heights at or above `floors`, one per chain.
    pub(crate) fn new(epoch: Epoch, floors: Vec<Height>) -> Self {
        Self {
            epoch,
            held: HashMap::new(),
            heights: vec![BTreeMap::new(); floors.len()],
            floors,
        }
    }

    /// Returns the number of chains.
    pub(crate) const fn chains(&self) -> usize {
        self.floors.len()
    }

    /// Returns whether a block at `reference` may be retained.
    pub(crate) fn admits(&self, reference: BlockRef<D>) -> bool {
        self.floors
            .get(reference.chain().get() as usize)
            .is_some_and(|floor| reference.height() >= *floor)
    }

    /// Returns the held block with exactly `reference`.
    pub(crate) fn get(&self, reference: BlockRef<D>) -> Option<&Held<D>> {
        self.held.get(&reference.digest()).filter(|held| {
            held.header.chain() == reference.chain() && held.header.height() == reference.height()
        })
    }

    /// Returns the number of held blocks.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.held.len()
    }

    /// Indexes a stored row whose header digest is `digest`, returning whether it is retained.
    ///
    /// Rows below the floor, of another epoch or chain, or duplicating a held block are not.
    fn insert(&mut self, digest: D, held: Held<D>) -> bool {
        let header = &held.header;
        let chain = header.chain().get() as usize;
        if header.epoch() != self.epoch
            || chain >= self.chains()
            || header.height() < self.floors[chain]
            || self.held.contains_key(&digest)
        {
            return false;
        }
        self.heights[chain]
            .entry(header.height())
            .or_default()
            .push(digest);
        self.held.insert(digest, held);
        true
    }

    /// Raises retention floors, removing what falls below and returning it.
    fn raise(&mut self, floors: &[Height]) -> Vec<Held<D>> {
        let mut removed = Vec::new();
        for (chain, floor) in floors.iter().enumerate().take(self.chains()) {
            if *floor <= self.floors[chain] {
                continue;
            }
            self.floors[chain] = *floor;
            let retained = self.heights[chain].split_off(floor);
            let dropped = std::mem::replace(&mut self.heights[chain], retained);
            removed.extend(
                dropped
                    .into_values()
                    .flatten()
                    .filter_map(|digest| self.held.remove(&digest)),
            );
        }
        removed
    }
}

/// Construction inputs for [`Blocks`].
pub(crate) struct Config<C> {
    /// Prefix from which every partition is derived.
    pub(crate) prefix: String,
    /// Journal buffers and page cache.
    pub(crate) buffers: Buffers,
    /// Bounds used to decode block bodies.
    pub(crate) body_codec: C,
    /// Epoch every held block belongs to.
    pub(crate) epoch: Epoch,
    /// Blocks in each segment; fixed when the stores are created.
    pub(crate) segment_capacity: NonZeroU64,
    /// Most segments each stream retains.
    pub(crate) max_segments: NonZeroUsize,
}

/// The outcome of inserting a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Inserted {
    /// The block is queued for its stream.
    Queued,
    /// The block is already held or queued.
    Known,
    /// The block is below its chain's retention floor, or of another epoch or chain.
    Refused,
}

/// A storage job of one stream.
pub(crate) type Job<E, H, B> = log::Job<E, Row<<H as Hasher>::Digest>, Block<H, B>>;

/// A completed storage job of one stream.
pub(crate) type Done<E, H, B> = log::Done<E, Row<<H as Hasher>::Digest>, Block<H, B>>;

/// What finishing a job produced.
pub(crate) enum Finished {
    /// Blocks are held, not yet durable.
    Appended,
    /// A cut whose durability completes with its end.
    Cut(Durability),
    /// Segments were reclaimed.
    Reclaimed,
}

/// Every block marshal holds.
pub(crate) struct Blocks<E: Context, H: Hasher, B: Body<H>> {
    index: Index<H::Digest>,
    logs: [StreamLog<E, H, B>; 2],
    /// Blocks waiting for their stream, with their encoded lengths.
    queued: [VecDeque<(Block<H, B>, u64)>; 2],
    /// Encoded bytes queued per stream.
    queued_bytes: [u64; 2],
    /// Encoded bytes of each stream's running append.
    appending_bytes: [u64; 2],
    /// Blocks queued or being appended, by digest.
    pending: HashMap<H::Digest, Block<H, B>>,
}

impl<E: Context, H: Hasher, B: Body<H>> Blocks<E, H, B> {
    /// Opens both streams and rebuilds the index, dropping blocks below `floors`.
    pub(crate) async fn open(
        context: E,
        config: Config<B::Cfg>,
        floors: Vec<Height>,
    ) -> Result<Self, Error> {
        let mut index = Index::new(config.epoch, floors);
        let open = |stream: Stream| {
            StreamLog::<E, H, B>::open(
                context.child(stream.name()),
                log::Config {
                    prefix: format!("{}_{}", config.prefix, stream.name()),
                    buffers: config.buffers.clone(),
                    codec: config.body_codec.clone(),
                    segment_capacity: config.segment_capacity,
                    max_segments: config.max_segments,
                },
            )
        };
        let (mut custody, custody_rows) = open(Stream::Custody).await?;
        let (mut bulk, bulk_rows) = open(Stream::Bulk).await?;
        for (stream, log, rows) in [
            (Stream::Custody, &mut custody, custody_rows),
            (Stream::Bulk, &mut bulk, bulk_rows),
        ] {
            for (position, row) in rows {
                let digest = row.header.digest::<H>();
                let held = Held {
                    header: row.header,
                    stream,
                    position,
                    offset: row.offset,
                    size: row.size,
                };
                if !index.insert(digest, held) {
                    log.release(position);
                }
            }
        }
        Ok(Self {
            index,
            logs: [custody, bulk],
            queued: [VecDeque::new(), VecDeque::new()],
            queued_bytes: [0; 2],
            appending_bytes: [0; 2],
            pending: HashMap::new(),
        })
    }

    /// Returns the index of held blocks.
    pub(crate) const fn index(&self) -> &Index<H::Digest> {
        &self.index
    }

    /// Returns whether the exact block is held durably.
    pub(crate) fn durable(&self, reference: BlockRef<H::Digest>) -> bool {
        self.index
            .get(reference)
            .is_some_and(|held| held.position < self.logs[held.stream.index()].durable())
    }

    /// Returns whether the exact block is held or queued.
    pub(crate) fn known(&self, reference: BlockRef<H::Digest>) -> bool {
        self.header(reference).is_some()
    }

    /// Returns the header of the exact block, held or queued.
    pub(crate) fn header(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Option<&TransactionBlockHeader<H::Digest>> {
        self.index.get(reference).map_or_else(
            || self.pending(reference).map(|block| block.header()),
            |held| Some(&held.header),
        )
    }

    /// Returns the exact block when it is queued or being appended.
    pub(crate) fn pending(&self, reference: BlockRef<H::Digest>) -> Option<&Block<H, B>> {
        self.pending
            .get(&reference.digest())
            .filter(|block| block.reference() == reference)
    }

    /// Queues `block` for `stream`.
    ///
    /// The caller authenticated the block: its header digest is its reference's digest, and its
    /// body matches the header.
    pub(crate) fn insert(&mut self, stream: Stream, block: Block<H, B>) -> Inserted {
        let reference = block.reference();
        let header = block.header();
        if !self.index.admits(reference) || header.epoch() != self.index.epoch {
            return Inserted::Refused;
        }
        if self.known(reference) {
            return Inserted::Known;
        }
        let len = block.encode_size() as u64;
        self.pending.insert(reference.digest(), Arc::clone(&block));
        self.queued_bytes[stream.index()] += len;
        self.queued[stream.index()].push_back((block, len));
        Inserted::Queued
    }

    /// Returns the encoded bytes queued for `stream`.
    #[cfg(test)]
    pub(crate) const fn queued_bytes(&self, stream: Stream) -> u64 {
        self.queued_bytes[stream.index()]
    }

    /// Returns the encoded bytes accepted for `stream` and not yet appended: queued, or in its
    /// running append.
    pub(crate) const fn pending_bytes(&self, stream: Stream) -> u64 {
        self.queued_bytes[stream.index()] + self.appending_bytes[stream.index()]
    }

    /// Returns whether `stream` has appends no started cut covers.
    pub(crate) fn dirty(&self, stream: Stream) -> bool {
        self.logs[stream.index()].dirty()
    }

    /// Returns whether no job of `stream` is running.
    pub(crate) const fn idle(&self, stream: Stream) -> bool {
        self.logs[stream.index()].idle()
    }

    /// Returns the next position of `stream`.
    #[cfg(test)]
    pub(crate) const fn next(&self, stream: Stream) -> u64 {
        self.logs[stream.index()].next()
    }

    /// Starts appending queued blocks to `stream`, up to the current segment's room and
    /// `max_bytes` (one block always fits), or returns `None` when none is queued or a job runs.
    pub(crate) fn start_append(&mut self, stream: Stream, max_bytes: u64) -> Option<Job<E, H, B>> {
        let log = &mut self.logs[stream.index()];
        if !log.idle() || self.queued[stream.index()].is_empty() {
            return None;
        }
        let room = log.room();
        let queue = &mut self.queued[stream.index()];
        let mut entries = Vec::new();
        let mut bytes = 0u64;
        while let Some((_, len)) = queue.front() {
            if entries.len() as u64 == room || (!entries.is_empty() && bytes + len > max_bytes) {
                break;
            }
            let (block, len) = queue.pop_front().expect("peeked");
            bytes += len;
            let row = Row {
                header: block.header().clone(),
                offset: 0,
                size: 0,
            };
            entries.push((row, block));
        }
        self.queued_bytes[stream.index()] -= bytes;
        self.appending_bytes[stream.index()] = bytes;
        Some(Job::Append(log.start_append(entries)))
    }

    /// Starts a cut of `stream`, or returns `None` when nothing is dirty or a job runs.
    pub(crate) fn start_cut(&mut self, stream: Stream) -> Result<Option<Job<E, H, B>>, Error> {
        let log = &mut self.logs[stream.index()];
        if !log.idle() {
            return Ok(None);
        }
        Ok(log.start_cut()?.map(Job::Cut))
    }

    /// Starts reclaiming `stream`'s segments without retained blocks, or returns `None`.
    pub(crate) fn start_reclaim(&mut self, stream: Stream) -> Option<Job<E, H, B>> {
        let log = &mut self.logs[stream.index()];
        if !log.idle() {
            return None;
        }
        log.start_reclaim().map(Job::Reclaim)
    }

    /// Takes back a completed job of `stream`.
    pub(crate) fn finish(&mut self, stream: Stream, done: Done<E, H, B>) -> Finished {
        let log = &mut self.logs[stream.index()];
        match log.finish(done) {
            log::Finished::Appended(rows) => {
                self.appending_bytes[stream.index()] = 0;
                for (position, row) in rows {
                    let digest = row.header.digest::<H>();
                    self.pending.remove(&digest);
                    let entry = Held {
                        header: row.header,
                        stream,
                        position,
                        offset: row.offset,
                        size: row.size,
                    };
                    // A floor may have risen while the block was queued.
                    if !self.index.insert(digest, entry) {
                        log.release(position);
                    }
                }
                Finished::Appended
            }
            log::Finished::Cut(durability) => Finished::Cut(durability),
            log::Finished::Reclaimed => Finished::Reclaimed,
        }
    }

    /// Records that `stream`'s cut ending at `end` is durable.
    pub(crate) fn mark_durable(&mut self, stream: Stream, end: u64) {
        self.logs[stream.index()].mark_durable(end);
    }

    /// Raises retention floors, dropping every held or queued block below them.
    ///
    /// The caller persists the floors first, so a crash cannot resurrect what is dropped here.
    pub(crate) fn prune(&mut self, floors: &[Height]) {
        for held in self.index.raise(floors) {
            self.logs[held.stream.index()].release(held.position);
        }
        for stream in Stream::ALL {
            let queue = &mut self.queued[stream.index()];
            let index = &self.index;
            let pending = &mut self.pending;
            let mut dropped = 0;
            queue.retain(|(block, len)| {
                let keep = index.admits(block.reference());
                if !keep {
                    pending.remove(&block.reference().digest());
                    dropped += len;
                }
                keep
            });
            self.queued_bytes[stream.index()] -= dropped;
        }
        for log in &mut self.logs {
            log.release_snapshots();
        }
    }

    /// Returns how the exact block can be read, with its frame location, or `None` when it is
    /// not held.
    pub(crate) fn access(&mut self, reference: BlockRef<H::Digest>) -> Option<Located<E, H, B>> {
        let held = self.index.get(reference)?;
        let location = held.location();
        let access = self.logs[held.stream.index()].access(held.position);
        Some((access, location))
    }

    /// Installs an opened segment of `stream`.
    pub(crate) fn finish_open(&mut self, stream: Stream, opened: log::Opened<E, Block<H, B>>) {
        self.logs[stream.index()].finish_open(opened);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::{testing::TestBody, types::ChainId};
    use commonware_cryptography::{Digestible as _, Sha256, sha256::Digest as Sha256Digest};
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};

    type TestBlocks = Blocks<deterministic::Context, Sha256, TestBody>;
    type TestBlock = Block<Sha256, TestBody>;

    const EPOCH: Epoch = Epoch::new(7);

    fn config() -> Config<()> {
        Config {
            prefix: "blocks".into(),
            buffers: Buffers {
                page_cache: CacheRef::new(NZU16!(1024), NZUsize!(16)),
                index_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            body_codec: (),
            epoch: EPOCH,
            segment_capacity: NZU64!(2),
            max_segments: NZUsize!(1024),
        }
    }

    /// A block at `height` on `chain`; `nonce` distinguishes rival blocks at one height.
    fn block_in(epoch: Epoch, chain: u32, height: u64, nonce: u64) -> TestBlock {
        let body = TestBody::new(Sha256::hash(&[b"parent"]), Height::new(height), nonce);
        let header = TransactionBlockHeader::new(
            epoch,
            ChainId::new(chain),
            Height::new(height),
            Sha256Digest::from([chain as u8; 32]),
            body.digest(),
        )
        .unwrap();
        Arc::new(TransactionBlock::new(header, body).unwrap())
    }

    fn block(chain: u32, height: u64, nonce: u64) -> TestBlock {
        block_in(EPOCH, chain, height, nonce)
    }

    async fn open(context: &deterministic::Context, floors: Vec<Height>) -> TestBlocks {
        Blocks::open(context.child("blocks"), config(), floors)
            .await
            .unwrap()
    }

    /// Runs one job and finishes it, returning what it produced.
    async fn run(
        blocks: &mut TestBlocks,
        stream: Stream,
        job: Job<deterministic::Context, Sha256, TestBody>,
    ) -> Finished {
        let done = job.run().await.unwrap();
        blocks.finish(stream, done)
    }

    /// Appends everything queued on `stream` and cuts it durably.
    async fn flush(blocks: &mut TestBlocks, stream: Stream) {
        while let Some(job) = blocks.start_append(stream, u64::MAX) {
            let Finished::Appended = run(blocks, stream, job).await else {
                panic!("an append appends");
            };
        }
        if let Some(job) = blocks.start_cut(stream).unwrap() {
            let Finished::Cut(durability) = run(blocks, stream, job).await else {
                panic!("a cut cuts");
            };
            let end = durability.await.unwrap();
            blocks.mark_durable(stream, end);
        }
    }

    async fn read(blocks: &mut TestBlocks, reference: BlockRef<Sha256Digest>) -> TestBlock {
        let held = blocks.index().get(reference).unwrap().clone();
        let (access, (offset, size)) = blocks.access(reference).unwrap();
        let reader = match access {
            Access::Ready(reader) => reader,
            Access::Open(job) => {
                blocks.finish_open(held.stream, job.run().await.unwrap());
                let Some((Access::Ready(reader), _)) = blocks.access(reference) else {
                    panic!("an opened segment is readable");
                };
                reader
            }
            Access::Opening | Access::Uncut => panic!("block is not readable"),
        };
        reader.get(offset, size).await.unwrap()
    }

    #[test]
    fn blocks_become_durable_per_stream_and_survive_reopen() {
        deterministic::Runner::default().start(|context| async move {
            let mut blocks = open(&context, vec![Height::zero(); 2]).await;
            let staged = block(0, 1, 0);
            let fetched = [block(1, 1, 0), block(1, 2, 0), block(1, 3, 0)];
            assert_eq!(
                blocks.insert(Stream::Custody, staged.clone()),
                Inserted::Queued
            );
            for block in &fetched {
                assert_eq!(blocks.insert(Stream::Bulk, block.clone()), Inserted::Queued);
            }
            // Queued blocks are known but not held.
            assert!(blocks.known(staged.reference()));
            assert_eq!(blocks.insert(Stream::Bulk, staged.clone()), Inserted::Known);
            assert!(blocks.index().get(staged.reference()).is_none());

            // A custody cut makes the staged block durable without the bulk stream.
            flush(&mut blocks, Stream::Custody).await;
            assert!(blocks.index().get(staged.reference()).is_some());
            assert!(blocks.durable(staged.reference()));
            assert!(blocks.known(fetched[0].reference()));
            assert!(!blocks.durable(fetched[0].reference()));
            assert_eq!(
                blocks.queued_bytes(Stream::Bulk),
                fetched
                    .iter()
                    .map(|block| block.encode_size() as u64)
                    .sum::<u64>()
            );

            flush(&mut blocks, Stream::Bulk).await;
            assert_eq!(blocks.queued_bytes(Stream::Bulk), 0);
            for block in &fetched {
                assert!(blocks.durable(block.reference()));
                assert_eq!(read(&mut blocks, block.reference()).await, *block);
            }
            assert_eq!(blocks.index().len(), 4);
            drop(blocks);

            let mut blocks = open(&context, vec![Height::zero(); 2]).await;
            assert_eq!(blocks.index().len(), 4);
            for block in fetched.iter().chain([&staged]) {
                assert!(blocks.durable(block.reference()));
                let held = blocks.index().get(block.reference()).unwrap();
                assert_eq!(held.header, *block.header());
                assert_eq!(held.encoded_len(), block.encode_size() as u64);
                assert_eq!(read(&mut blocks, block.reference()).await, *block);
            }
        });
    }

    #[test]
    fn rival_blocks_share_a_height_and_lookups_are_exact() {
        deterministic::Runner::default().start(|context| async move {
            let mut blocks = open(&context, vec![Height::zero()]).await;
            let first = block(0, 4, 1);
            let rival = block(0, 4, 2);
            blocks.insert(Stream::Bulk, first.clone());
            blocks.insert(Stream::Bulk, rival.clone());
            flush(&mut blocks, Stream::Bulk).await;
            assert_eq!(read(&mut blocks, first.reference()).await, first);
            assert_eq!(read(&mut blocks, rival.reference()).await, rival);
            // A reference naming a held digest at another height is not held.
            let wrong = BlockRef::new(ChainId::new(0), Height::new(5), first.reference().digest());
            assert!(blocks.index().get(wrong).is_none());
            assert!(!blocks.durable(wrong));
        });
    }

    #[test]
    fn floors_drop_blocks_and_reclaim_segments() {
        deterministic::Runner::default().start(|context| async move {
            let mut blocks = open(&context, vec![Height::zero()]).await;
            let chain = (1..=6)
                .map(|height| block(0, height, 0))
                .collect::<Vec<_>>();
            for block in &chain {
                blocks.insert(Stream::Bulk, block.clone());
            }
            flush(&mut blocks, Stream::Bulk).await;

            // Other epochs, chains and heights below the floor are refused.
            assert_eq!(
                blocks.insert(Stream::Bulk, block_in(Epoch::new(8), 0, 9, 0)),
                Inserted::Refused
            );
            assert_eq!(
                blocks.insert(Stream::Bulk, block(3, 9, 0)),
                Inserted::Refused
            );
            blocks.prune(&[Height::new(5)]);
            assert_eq!(
                blocks.insert(Stream::Bulk, block(0, 4, 9)),
                Inserted::Refused
            );
            assert_eq!(blocks.index().len(), 2);
            assert!(blocks.index().get(chain[3].reference()).is_none());
            // Segments 0 and 1 (heights 1 to 4) hold nothing retained; segment 2 is current.
            let job = blocks.start_reclaim(Stream::Bulk).unwrap();
            let Finished::Reclaimed = run(&mut blocks, Stream::Bulk, job).await else {
                panic!("a reclamation reclaims");
            };
            drop(blocks);

            // Reopening with the floor keeps exactly the retained blocks.
            let mut blocks = open(&context, vec![Height::new(5)]).await;
            assert_eq!(blocks.index().len(), 2);
            for block in &chain[4..] {
                assert_eq!(read(&mut blocks, block.reference()).await, *block);
            }
            drop(blocks);
            // A higher floor at open drops more without reclaiming eagerly.
            let blocks = open(&context, vec![Height::new(6)]).await;
            assert_eq!(blocks.index().len(), 1);
        });
    }

    #[test]
    fn queued_blocks_below_a_raised_floor_are_dropped() {
        deterministic::Runner::default().start(|context| async move {
            let mut blocks = open(&context, vec![Height::zero()]).await;
            let low = block(0, 1, 0);
            let high = block(0, 3, 0);
            blocks.insert(Stream::Bulk, low.clone());
            blocks.insert(Stream::Bulk, high.clone());
            blocks.prune(&[Height::new(2)]);
            assert!(!blocks.known(low.reference()));
            assert_eq!(blocks.queued_bytes(Stream::Bulk), high.encode_size() as u64);
            flush(&mut blocks, Stream::Bulk).await;
            assert!(blocks.index().get(high.reference()).is_some());
            assert!(blocks.index().get(low.reference()).is_none());
        });
    }

    #[test]
    fn appends_respect_the_byte_bound_but_always_take_one_block() {
        deterministic::Runner::default().start(|context| async move {
            let mut blocks = open(&context, vec![Height::zero()]).await;
            blocks.insert(Stream::Bulk, block(0, 1, 0));
            blocks.insert(Stream::Bulk, block(0, 2, 0));
            let job = blocks.start_append(Stream::Bulk, 1).unwrap();
            let Finished::Appended = run(&mut blocks, Stream::Bulk, job).await else {
                panic!("an append appends");
            };
            assert_eq!(blocks.index().len(), 1);
            assert_eq!(blocks.next(Stream::Bulk), 1);
        });
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use arbitrary::{Arbitrary, Unstructured};
        use commonware_codec::{DecodeExt as _, Encode as _, conformance::generate_value};
        use commonware_conformance::Conformance;

        impl<'a> Arbitrary<'a> for Row<Sha256Digest> {
            fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
                Ok(Self {
                    header: u.arbitrary()?,
                    offset: u.arbitrary()?,
                    size: u.int_in_range(crc32::Digest::SIZE as u32..=u32::MAX)?,
                })
            }
        }

        struct RowConformance;

        impl Conformance for RowConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let row = generate_value::<Row<Sha256Digest>>(seed);
                let encoded = row.encode();
                assert_eq!(Row::decode(encoded.clone()).unwrap(), row);
                encoded.to_vec()
            }
        }

        commonware_conformance::conformance_tests! {
            RowConformance => 256,
        }
    }
}

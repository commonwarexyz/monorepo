//! The Merkle digests of an authenticated journal, held in memory or rebuilt from its operations.
//!
//! Digests live in two places:
//!
//! - `mem` holds no nodes, only pinned digests. It pins the peaks at its size, peaks at earlier
//!   sizes until [Tree::flush], and the digests pinned at the tree's boundary.
//! - `resident` holds every node at or above the resident height, at or past the boundary.
//!
//! A lower node is rebuilt ("filled") when read, from its region. A region is an aligned run of
//! `2^resident_height` leaves and the nodes above them up to the resident height.
//!
//! A node is born once the tree contains it. In an MMB some parents are born a few leaves after
//! their last leaf. A node's ordinal is its index among the nodes of its height.
//!
//! A filled digest is never served unchecked. Every region has a node above its rebuilt digests
//! that is resident or pinned, and a fill recomputes that node and compares it.

use super::{Config, metrics::Metrics};
use crate::{
    journal::{
        Error as JournalError,
        contiguous::{Batch, Contiguous},
    },
    merkle::{self, Family, Location, Position, Readable, batch, hasher::Hasher, mem::Mem},
};
use commonware_codec::{Encode, EncodeShared};
use commonware_cryptography::Digest;
use commonware_parallel::Strategy;
use commonware_runtime::{AbortOnDrop, ReadOptions, Spawner, telemetry::metrics::GaugeExt as _};
use commonware_utils::channel::mpsc;
use futures::{Stream, StreamExt as _, TryStreamExt as _, pin_mut, stream};
use std::{
    collections::{BTreeMap, VecDeque},
    num::{NonZeroU64, NonZeroUsize},
    ops::Range,
    sync::Arc,
};

/// Encoded bytes after which a replay batch ends.
const REPLAY_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// Regions filled concurrently by one request.
const CONCURRENT_FILLS: usize = 8;

/// Chunks a replay reads and hashes concurrently.
const CONCURRENT_CHUNKS: usize = 8;

/// Born nodes of one resident height at or past the boundary, in ordinal order.
struct Level<D> {
    /// Ordinal of the first node.
    first: u64,
    nodes: VecDeque<D>,
}

impl<D: Copy> Level<D> {
    fn get(&self, ordinal: u64) -> Option<D> {
        let index = usize::try_from(ordinal.checked_sub(self.first)?).ok()?;
        self.nodes.get(index).copied()
    }

    /// The number of nodes of this height born so far.
    fn end(&self) -> u64 {
        self.first + self.nodes.len() as u64
    }
}

/// Nodes at or above `height`. Nodes of one height are born in ordinal order, including delayed
/// MMB parents.
struct Resident<D> {
    height: u32,
    /// Level `i` holds height `height + i`.
    levels: Vec<Level<D>>,
}

impl<D: Copy> Resident<D> {
    /// Empty levels for a tree pruned to `boundary`.
    fn new<F: Family>(height: u32, boundary: Position<F>) -> Self {
        let levels = born(boundary)[height as usize..]
            .iter()
            .map(|&first| Level {
                first,
                nodes: VecDeque::new(),
            })
            .collect();
        Self { height, levels }
    }

    /// The node at `pos`, of height `h`.
    fn get<F: Family>(&self, pos: Position<F>, h: u32) -> Option<D> {
        let level = self.levels.get(h.checked_sub(self.height)? as usize)?;
        level.get(*F::leftmost_leaf(pos, h) >> h)
    }

    /// Add the nodes born by size `end`, whose digests `node` returns.
    fn extend<F: Family>(
        &mut self,
        end: Position<F>,
        node: impl Fn(Position<F>) -> Option<D>,
    ) -> Result<(), merkle::Error<F>> {
        self.extend_with(end, |height, ordinal| {
            let pos = F::subtree_root_position(Location::new(ordinal << height), height);
            node(pos).ok_or(merkle::Error::MissingNode(pos))
        })
    }

    /// Like [Self::extend], but `node` returns each digest by its height and ordinal.
    fn extend_with<F: Family>(
        &mut self,
        end: Position<F>,
        mut node: impl FnMut(u32, u64) -> Result<D, merkle::Error<F>>,
    ) -> Result<(), merkle::Error<F>> {
        let born = born(end);
        for (index, (level, &to)) in self
            .levels
            .iter_mut()
            .zip(&born[self.height as usize..])
            .enumerate()
        {
            let height = self.height + index as u32;
            for ordinal in level.end()..to {
                level.nodes.push_back(node(height, ordinal)?);
            }
        }
        Ok(())
    }

    /// Drop nodes before `boundary`.
    fn trim<F: Family>(&mut self, boundary: Position<F>) {
        let born = born(boundary);
        for (level, &end) in self.levels.iter_mut().zip(&born[self.height as usize..]) {
            let stale = end
                .saturating_sub(level.first)
                .min(level.nodes.len() as u64);
            level.nodes.drain(..stale as usize);
            level.first += stale;
            if level.nodes.len() <= level.nodes.capacity() / 4 {
                level.nodes.shrink_to_fit();
            }
        }
    }

    /// Digests held.
    fn len(&self) -> usize {
        self.levels.iter().map(|level| level.nodes.len()).sum()
    }
}

/// The number of nodes of each height born by `size`. Counting from the peaks, rather than from
/// the leaf count, leaves out MMB parents not yet born, whose positions can lie past the supported
/// range.
fn born<F: Family>(size: Position<F>) -> [u64; u64::BITS as usize] {
    let mut born = [0; u64::BITS as usize];
    for (_, peak) in F::peaks(size) {
        for h in 0..=peak {
            born[h as usize] += 1 << (peak - h);
        }
    }
    born
}

/// Digests of one aligned region of leaves, in height-major slots. Leaves come first, then
/// height-one nodes, and so on up to the region root. A slot is empty until rebuilt.
type Region<D> = Box<[Option<D>]>;

/// The layout of the regions below the resident height.
struct Regions {
    /// The resident height, so each region spans `2^height` leaves.
    height: u32,
}

impl Regions {
    const fn width(&self) -> u64 {
        1 << self.height
    }

    fn empty<D: Digest>(&self) -> Region<D> {
        vec![None; (2usize << self.height) - 1].into_boxed_slice()
    }

    /// The first slot of height `h`.
    const fn row(&self, h: u32) -> usize {
        let width = 2 * self.width();
        (width - (width >> h)) as usize
    }

    /// The region and slot of `pos`, whose height `h` is below the resident height.
    fn locate<F: Family>(&self, pos: Position<F>, h: u32) -> (u64, usize) {
        let leaf = *F::leftmost_leaf(pos, h);
        let local = (leaf & (self.width() - 1)) >> h;
        (leaf >> self.height, self.row(h) + local as usize)
    }
}

/// Leaf encodings packed into one buffer, so hashing a batch allocates nothing per leaf.
struct Encoded<F: Family> {
    bytes: Vec<u8>,
    leaves: Vec<(Position<F>, Range<usize>)>,
}

impl<F: Family> Encoded<F> {
    const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            leaves: Vec::new(),
        }
    }

    fn push(&mut self, pos: Position<F>, item: &impl Encode) {
        let start = self.bytes.len();
        item.write(&mut self.bytes);
        self.leaves.push((pos, start..self.bytes.len()));
    }

    /// Hash each leaf, in push order.
    fn hash<D: Digest, H: Hasher<F, Digest = D>>(
        &self,
        strategy: &impl Strategy,
        hasher: &H,
    ) -> Vec<D> {
        strategy.map_init_collect_vec(
            &self.leaves,
            || hasher.clone(),
            |h, (pos, range)| h.leaf_digest(*pos, &self.bytes[range.clone()]),
        )
    }
}

/// How a replay of the leaves in `range` splits into chunks. Most are whole aligned subtrees of
/// `2^height` leaves, with partial chunks before the first and after the last.
#[derive(Clone)]
pub(crate) struct ChunkPlan {
    range: Range<u64>,
    height: u32,
    /// The lowest height of a subtree's nodes that appending it reads. It is the resident height,
    /// or the subtree root's if lower.
    min_height: u32,
}

impl ChunkPlan {
    /// The first leaf of the first chunk.
    pub(crate) const fn start(&self) -> u64 {
        self.range.start
    }

    /// The chunks, in position order.
    pub(crate) fn chunks(&self) -> impl Iterator<Item = Range<u64>> + Send + 'static {
        let (mut next, end, width) = (self.range.start, self.range.end, 1u64 << self.height);
        std::iter::from_fn(move || {
            (next < end).then(|| {
                let stop = (next / width + 1).saturating_mul(width).min(end);
                let chunk = next..stop;
                next = stop;
                chunk
            })
        })
    }

    /// A hasher for `chunk`, one of [Self::chunks].
    pub(crate) fn hasher<F: Family, H: Hasher<F>>(
        &self,
        chunk: Range<u64>,
        hasher: H,
    ) -> ChunkHasher<F, H> {
        let width = 1u64 << self.height;
        ChunkHasher {
            is_subtree: chunk.start.is_multiple_of(width) && chunk.end - chunk.start == width,
            leaves: Vec::with_capacity((chunk.end - chunk.start) as usize),
            chunk,
            height: self.height,
            min_height: self.min_height,
            hasher,
            encoded: Vec::new(),
        }
    }
}

/// Hashes the operations of one replay chunk, given in position order.
pub(crate) struct ChunkHasher<F: Family, H: Hasher<F>> {
    chunk: Range<u64>,
    /// Whether the chunk is a whole aligned subtree.
    is_subtree: bool,
    height: u32,
    min_height: u32,
    hasher: H,
    leaves: Vec<H::Digest>,
    /// Scratch for each operation's encoding.
    encoded: Vec<u8>,
}

impl<F: Family, H: Hasher<F>> ChunkHasher<F, H> {
    /// Hash the chunk's next operation into its leaf.
    pub(crate) fn push(&mut self, item: &impl Encode) {
        let loc = Location::new(self.chunk.start + self.leaves.len() as u64);
        self.encoded.clear();
        item.write(&mut self.encoded);
        let digest = self
            .hasher
            .leaf_digest(F::location_to_position(loc), &self.encoded);
        self.leaves.push(digest);
    }

    /// The chunk's digests, once every operation in it has been pushed.
    pub(crate) fn finish(self) -> Result<Chunk<F, H::Digest>, merkle::Error<F>> {
        if self.leaves.len() as u64 != self.chunk.end - self.chunk.start {
            return Err(merkle::Error::DataCorrupted(
                "replay ended before its range",
            ));
        }
        if !self.is_subtree {
            return Ok(Chunk::Leaves {
                start: self.chunk.start,
                digests: self.leaves,
            });
        }
        let (start, height, min_height) = (self.chunk.start, self.height, self.min_height);

        // The tree's peaks at the subtree's end that lie in it below `min_height`.
        let end = F::location_to_position(Location::new(self.chunk.end));
        let low_peaks: Vec<_> = F::peaks(end)
            .filter(|&(pos, h)| h < min_height && *F::leftmost_leaf(pos, h) >= start)
            .collect();

        // Hash each height in place from the one below, keeping the rows from `min_height` up and
        // the low peaks.
        let mut level = self.leaves;
        let mut rows = Vec::with_capacity((2usize << height >> min_height) - 1);
        let mut peaks = Vec::with_capacity(low_peaks.len());
        for h in 0..=height {
            if h > 0 {
                hash_level(&self.hasher, &mut level, start, h);
            }
            for &(pos, _) in low_peaks.iter().filter(|&&(_, peak)| peak == h) {
                let index = (*F::leftmost_leaf(pos, h) - start) >> h;
                peaks.push((pos, level[index as usize]));
            }
            if h >= min_height {
                rows.extend_from_slice(&level);
            }
        }
        Ok(Chunk::Subtree(SubtreeNodes {
            start,
            height,
            min_height,
            rows,
            peaks,
        }))
    }
}

/// Replace `level`, the nodes of height `h - 1` of the aligned subtree whose first leaf is `start`,
/// with the nodes of height `h`, hashing two at a time.
fn hash_level<F: Family, H: Hasher<F>>(hasher: &H, level: &mut Vec<H::Digest>, start: u64, h: u32) {
    let pos = |i: usize| F::subtree_root_position(Location::new(start + ((i as u64) << h)), h);
    let count = level.len() / 2;
    let mut i = 0;
    while i + 1 < count {
        let (a, b) = hasher.node_digest_pair([
            (pos(i), &level[2 * i], &level[2 * i + 1]),
            (pos(i + 1), &level[2 * i + 2], &level[2 * i + 3]),
        ]);
        level[i] = a;
        level[i + 1] = b;
        i += 2;
    }
    if i < count {
        let digest = hasher.node_digest(pos(i), &level[2 * i], &level[2 * i + 1]);
        level[i] = digest;
    }
    level.truncate(count);
}

/// The digests of one replay chunk, as the tree appends them.
pub(crate) enum Chunk<F: Family, D> {
    /// A whole aligned subtree.
    Subtree(SubtreeNodes<F, D>),
    /// The leaves of a partial chunk.
    Leaves {
        /// The chunk's first leaf.
        start: u64,
        digests: Vec<D>,
    },
}

/// The nodes of one aligned subtree that appending it reads.
pub(crate) struct SubtreeNodes<F: Family, D> {
    /// The subtree's first leaf.
    start: u64,
    height: u32,
    /// The lowest height in `rows`.
    min_height: u32,
    /// Every node from height `min_height` up to the root, one height after another.
    rows: Vec<D>,
    /// The tree's peaks at the subtree's end that lie in it below `min_height`.
    peaks: Vec<(Position<F>, D)>,
}

impl<F: Family, D: Digest> SubtreeNodes<F, D> {
    /// The node of height `h` whose leftmost leaf is `leaf`, born by the end of the subtree. A
    /// born node outside the subtree is hashed from its children, which were born with it or
    /// were peaks before the subtree, pinned in `mem`. `computed` holds the nodes hashed so far.
    fn node(
        &self,
        mem: &Mem<F, D>,
        hasher: &impl Hasher<F, Digest = D>,
        computed: &mut BTreeMap<Position<F>, D>,
        leaf: u64,
        h: u32,
    ) -> Result<D, merkle::Error<F>> {
        let inside = h <= self.height && leaf >= self.start && leaf - self.start < 1 << self.height;
        if inside && h >= self.min_height {
            let width = 2u64 << self.height;
            let slot = (width >> self.min_height) - (width >> h) + ((leaf - self.start) >> h);
            return Ok(self.rows[slot as usize]);
        }
        let pos = F::subtree_root_position(Location::new(leaf), h);
        if inside {
            return self
                .peaks
                .iter()
                .find(|&&(peak, _)| peak == pos)
                .map(|&(_, digest)| digest)
                .ok_or(merkle::Error::MissingNode(pos));
        }
        if let Some(digest) = computed.get(&pos).copied().or_else(|| mem.get_node(pos)) {
            return Ok(digest);
        }
        if h == 0 {
            return Err(merkle::Error::MissingNode(pos));
        }
        let left = self.node(mem, hasher, computed, leaf, h - 1)?;
        let right = self.node(mem, hasher, computed, leaf + (1 << (h - 1)), h - 1)?;
        let digest = hasher.node_digest(pos, &left, &right);
        computed.insert(pos, digest);
        Ok(digest)
    }
}

/// A replay task's clone of the journal, and its clone of the replay's `released` sender, which it
/// drops only after the journal. Fields drop in declaration order.
struct TaskJournal<C> {
    journal: Arc<C>,
    _released: mpsc::Sender<()>,
}

/// The Merkle digests of an authenticated journal. Only `mem` is shared with batches.
pub(crate) struct Tree<F: Family, D: Digest, S: Strategy> {
    mem: Arc<Mem<F, D>>,
    metrics: Box<Metrics>,
    /// First retained leaf.
    boundary: Location<F>,
    /// Digests pinned at the boundary, which [Self::flush] keeps pinned in `mem`.
    pins: BTreeMap<Position<F>, D>,
    resident: Resident<D>,
    regions: Regions,
    strategy: S,
    replay_buffer: NonZeroUsize,
}

impl<F: Family, D: Digest, S: Strategy> Tree<F, D, S> {
    /// An empty tree pruned to `boundary`. `pins` are the digests [`Family::nodes_to_pin`] lists
    /// for it.
    pub(crate) fn new(
        boundary: Location<F>,
        pins: Vec<D>,
        config: &Config<S>,
        metrics: Metrics,
    ) -> Result<Self, super::Error<F>> {
        config
            .cache
            .validate()
            .map_err(|error| JournalError::InvalidConfiguration(error.into()))?;
        let mem = Mem::from_components(Vec::new(), boundary, pins.clone())?;
        let tree = Self {
            mem: Arc::new(mem),
            metrics: Box::new(metrics),
            boundary,
            pins: F::nodes_to_pin(boundary).zip(pins).collect(),
            resident: Resident::new(
                config.cache.resident_height,
                F::location_to_position(boundary),
            ),
            regions: Regions {
                height: config.cache.resident_height,
            },
            strategy: config.strategy.clone(),
            replay_buffer: config.replay_buffer,
        };
        tree.update_metrics();
        Ok(tree)
    }

    /// Restart the empty tree at `boundary`, whose pinned digests are `pins`.
    pub(crate) fn rebase(
        &mut self,
        boundary: Location<F>,
        pins: Vec<D>,
    ) -> Result<(), super::Error<F>> {
        assert_eq!(
            self.leaves(),
            self.boundary,
            "only an empty tree can be rebased"
        );
        self.mem = Arc::new(Mem::from_components(Vec::new(), boundary, pins.clone())?);
        self.boundary = boundary;
        self.pins = F::nodes_to_pin(boundary).zip(pins).collect();
        self.resident = Resident::new(self.resident.height, F::location_to_position(boundary));
        self.update_metrics();
        Ok(())
    }

    fn update_metrics(&self) {
        let bytes = self.resident.len().saturating_mul(size_of::<D>());
        let _ = self.metrics.resident_bytes.try_set(bytes);
    }

    /// Append the digests of the operations from the current size to `end`.
    pub(crate) async fn replay<C, H>(
        mut self,
        journal: &C,
        hasher: &H,
        end: Location<F>,
        batch_size: NonZeroU64,
    ) -> Result<Self, super::Error<F>>
    where
        C: Contiguous<Item: EncodeShared>,
        H: Hasher<F, Digest = D> + 'static,
    {
        if !end.is_valid()
            || end < self.leaves()
            || *end > journal.bounds().end
            || *self.leaves() < journal.bounds().start
        {
            return Err(merkle::Error::RangeOutOfBounds(end).into());
        }
        let stream = journal
            .replay(
                *self.leaves()..*end,
                self.replay_buffer,
                ReadOptions::default(),
            )
            .await?
            .fuse();
        pin_mut!(stream);
        let max_items = usize::try_from(batch_size.get()).unwrap_or(usize::MAX);
        let mut loc = self.leaves();
        let mut pending = Vec::new().into_iter();
        let mut next = Self::read_encoded(&mut stream, &mut pending, loc, max_items).await?;
        // Read each batch while the previous one hashes.
        while !next.leaves.is_empty() {
            loc += next.leaves.len() as u64;
            (self, next) = futures::try_join!(
                self.apply_encoded(hasher, next),
                Self::read_encoded(&mut stream, &mut pending, loc, max_items),
            )?;
        }
        if self.leaves() != end {
            return Err(merkle::Error::DataCorrupted("replay ended before its range").into());
        }
        Ok(self)
    }

    /// Read and encode up to `max_items` leaves from `loc`, ending early once the batch holds
    /// [REPLAY_BATCH_BYTES] bytes or `stream` ends. `pending` holds items read but not encoded.
    async fn read_encoded<I: Encode>(
        stream: &mut (impl Stream<Item = Result<Batch<I>, JournalError>> + Unpin),
        pending: &mut std::vec::IntoIter<I>,
        mut loc: Location<F>,
        max_items: usize,
    ) -> Result<Encoded<F>, super::Error<F>> {
        let mut encoded = Encoded::new();
        while encoded.leaves.len() < max_items && encoded.bytes.len() < REPLAY_BATCH_BYTES {
            if let Some(item) = pending.next() {
                encoded.push(F::location_to_position(loc), &item);
                loc += 1;
            } else if let Some(batch) = stream.next().await {
                *pending = batch?.items.into_iter();
            } else {
                break;
            }
        }
        Ok(encoded)
    }

    async fn apply_encoded<H>(
        self,
        hasher: &H,
        encoded: Encoded<F>,
    ) -> Result<Self, super::Error<F>>
    where
        H: Hasher<F, Digest = D> + 'static,
    {
        let digests = {
            let hasher = hasher.clone();
            self.strategy
                .spawn(encoded.leaves.len(), move |strategy| {
                    encoded.hash(&strategy, &hasher)
                })
                .await
        };
        Ok(self.apply_digests(hasher, digests).await?)
    }

    /// Append leaves with `digests`, hashing their parents on the strategy.
    async fn apply_digests<H>(
        mut self,
        hasher: &H,
        digests: Vec<D>,
    ) -> Result<Self, merkle::Error<F>>
    where
        H: Hasher<F, Digest = D> + 'static,
    {
        self.metrics.replayed_leaves.inc_by(digests.len() as u64);
        let mem = self.snapshot();
        let hasher = hasher.clone();
        let batch = self.new_batch();
        let batch = self
            .strategy
            .spawn(digests.len(), move |_| {
                batch.add_leaf_digests(digests).merkleize(&mem, &hasher)
            })
            .await;
        self = self.apply_batch(&batch)?;
        self.flush();
        Ok(self)
    }

    /// How a replay from the current size to `end` splits into chunks, with whole subtrees of
    /// `2^height` leaves.
    pub(crate) fn chunk_plan(&self, end: Location<F>, height: u32) -> ChunkPlan {
        ChunkPlan {
            range: *self.leaves()..*end,
            height,
            min_height: self.resident.height.min(height),
        }
    }

    /// Append the next chunk of a replay that [Self::chunk_plan] planned.
    pub(crate) async fn apply_chunk<H>(
        self,
        hasher: &H,
        chunk: Chunk<F, D>,
    ) -> Result<Self, merkle::Error<F>>
    where
        H: Hasher<F, Digest = D> + 'static,
    {
        match chunk {
            Chunk::Subtree(subtree) => self.apply_subtree(hasher, &subtree),
            Chunk::Leaves { start, .. } if start != *self.leaves() => Err(
                merkle::Error::DataCorrupted("chunk does not start at the end"),
            ),
            Chunk::Leaves { digests, .. } => self.apply_digests(hasher, digests).await,
        }
    }

    /// Like [Self::replay], but the chunks of a [Self::chunk_plan] with subtrees of `2^height`
    /// leaves are read and hashed on tasks of their own spawned from `context`, with
    /// [CONCURRENT_CHUNKS] at once, and appended in order. Appending a whole subtree hashes only
    /// the nodes above its root.
    ///
    /// Each task holds a clone of `released` until it drops its clone of `journal`, so once every
    /// clone of `released` is dropped, no task still holds the journal, even after the replay is
    /// aborted or fails.
    pub(crate) async fn replay_subtrees<E, C, H>(
        mut self,
        context: E,
        journal: &Arc<C>,
        hasher: &H,
        end: Location<F>,
        height: u32,
        released: mpsc::Sender<()>,
    ) -> Result<Self, super::Error<F>>
    where
        E: Spawner,
        C: Contiguous<Item: EncodeShared> + 'static,
        H: Hasher<F, Digest = D> + 'static,
    {
        if !end.is_valid()
            || end < self.leaves()
            || *end > journal.bounds().end
            || *self.leaves() < journal.bounds().start
        {
            return Err(merkle::Error::RangeOutOfBounds(end).into());
        }
        let plan = self.chunk_plan(end, height);
        let buffer = self.replay_buffer;
        let mut chunks = plan.chunks();
        let mut spawn_next = |pending: &mut VecDeque<AbortOnDrop<_>>| {
            let Some(chunk) = chunks.next() else {
                return;
            };
            let task_journal = TaskJournal {
                journal: journal.clone(),
                _released: released.clone(),
            };
            let chunk_hasher = plan.hasher(chunk.clone(), hasher.clone());
            let task = context
                .child("replay_chunk")
                .dedicated()
                .spawn(move |_| Self::hash_chunk(task_journal, chunk, chunk_hasher, buffer));
            pending.push_back(task.abort_on_drop());
        };

        // Hash chunks ahead of appending them, and append them in order.
        let mut pending = VecDeque::with_capacity(CONCURRENT_CHUNKS);
        for _ in 0..CONCURRENT_CHUNKS {
            spawn_next(&mut pending);
        }
        while let Some(task) = pending.pop_front() {
            let appended = match task.join().await {
                Ok(Ok(chunk)) => {
                    spawn_next(&mut pending);
                    self.apply_chunk(hasher, chunk)
                        .await
                        .map_err(super::Error::from)
                }
                Ok(Err(error)) => Err(error),
                Err(error) => Err(JournalError::from(error).into()),
            };
            match appended {
                Ok(tree) => self = tree,
                Err(error) => {
                    // Join the rest, so none outlives the replay holding the journal.
                    for task in pending {
                        task.abort().await;
                    }
                    return Err(error);
                }
            }
        }
        Ok(self)
    }

    /// Read the operations in `chunk` from `task_journal`'s journal and hash them with `hasher`.
    /// `task_journal` is taken whole, so its `released` sender lives until its journal is dropped.
    async fn hash_chunk<C, H>(
        task_journal: TaskJournal<C>,
        chunk: Range<u64>,
        mut hasher: ChunkHasher<F, H>,
        buffer: NonZeroUsize,
    ) -> Result<Chunk<F, D>, super::Error<F>>
    where
        C: Contiguous<Item: EncodeShared>,
        H: Hasher<F, Digest = D>,
    {
        let stream = task_journal
            .journal
            .replay(chunk, buffer, ReadOptions::DONT_CACHE)
            .await?;
        pin_mut!(stream);
        while let Some(batch) = stream.next().await {
            for item in batch?.items {
                hasher.push(&item);
            }
        }
        Ok(hasher.finish()?)
    }

    /// Append the aligned subtree at the current size. Only the nodes the tree keeps are read:
    /// resident nodes and peaks born by the subtree's end, hashing the ones above its root.
    fn apply_subtree<H>(
        mut self,
        hasher: &H,
        subtree: &SubtreeNodes<F, D>,
    ) -> Result<Self, merkle::Error<F>>
    where
        H: Hasher<F, Digest = D>,
    {
        if subtree.start != *self.leaves() {
            return Err(merkle::Error::DataCorrupted(
                "chunk does not start at the end",
            ));
        }
        let width = 1u64 << subtree.height;
        let initial = self.size();
        let leaves = Location::new(subtree.start + width);
        let mut computed = BTreeMap::new();
        let Self { mem, resident, .. } = &mut self;
        resident.extend_with(F::location_to_position(leaves), |h, ordinal| {
            subtree.node(mem, hasher, &mut computed, ordinal << h, h)
        })?;
        let peaks = F::nodes_to_pin(leaves)
            .filter(|&pos| pos >= initial)
            .map(|pos| {
                let h = F::pos_to_height(pos);
                let leaf = *F::leftmost_leaf(pos, h);
                Ok((pos, subtree.node(mem, hasher, &mut computed, leaf, h)?))
            })
            .collect::<Result<Vec<_>, merkle::Error<F>>>()?;
        Arc::make_mut(mem).skip_to(leaves, peaks)?;
        self.metrics.replayed_leaves.inc_by(width);
        self.flush();
        Ok(self)
    }

    pub(crate) fn size(&self) -> Position<F> {
        self.mem.size()
    }

    pub(crate) fn leaves(&self) -> Location<F> {
        self.mem.leaves()
    }

    pub(crate) fn bounds(&self) -> Range<Location<F>> {
        self.boundary..self.leaves()
    }

    pub(crate) const fn strategy(&self) -> &S {
        &self.strategy
    }

    pub(crate) fn snapshot(&self) -> Arc<Mem<F, D>> {
        Arc::clone(&self.mem)
    }

    pub(crate) fn mem(&self) -> &Mem<F, D> {
        &self.mem
    }

    pub(crate) fn root(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        inactive: usize,
    ) -> Result<D, merkle::Error<F>> {
        self.mem.root(hasher, inactive)
    }

    pub(crate) fn new_batch(&self) -> batch::UnmerkleizedBatch<F, D, S> {
        self.mem.new_batch_with_strategy(self.strategy.clone())
    }

    pub(crate) fn to_batch(&self) -> Arc<batch::MerkleizedBatch<F, D, S>> {
        batch::MerkleizedBatch::from_mem_with_strategy(&self.mem, self.strategy.clone())
    }

    /// Apply a batch of appends, keeping only its new resident nodes and peaks. Lower nodes can be
    /// rebuilt from operations, and batches keep their own nodes for speculative proofs.
    pub(crate) fn apply_batch(
        mut self,
        batch: &batch::MerkleizedBatch<F, D, S>,
    ) -> Result<Self, merkle::Error<F>> {
        // Collect resident nodes from each unapplied record before advancing the tree's tip.
        let initial = self.size();
        let mut end = initial;
        for run in batch.unapplied(&self.mem)? {
            let start = end;
            let node = |pos: Position<F>| {
                let index = usize::try_from((*pos).checked_sub(*start)?).ok()?;
                run.get(index).copied()
            };
            end = start + run.len() as u64;
            self.resident.extend(end, node)?;
        }

        // Pin the new tip's peaks alongside peaks from earlier published states. Batches retain
        // the appended nodes needed to prove intermediate states.
        let leaves = Location::try_from(end)?;
        let peaks = F::nodes_to_pin(leaves)
            .filter(|&pos| pos >= initial)
            .map(|pos| {
                batch
                    .get_node(pos)
                    .map(|digest| (pos, digest))
                    .ok_or(merkle::Error::MissingNode(pos))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Arc::make_mut(&mut self.mem).skip_to(leaves, peaks)?;
        Ok(self)
    }

    /// Unpin peaks from sizes before the current one. Nothing is written.
    pub(crate) fn flush(&mut self) {
        Arc::make_mut(&mut self.mem).compact(&self.pins);
        self.update_metrics();
    }

    /// Drop nodes before `boundary`. `pins` are the digests [`Family::nodes_to_pin`] lists for it.
    pub(crate) fn prune(&mut self, boundary: Location<F>, pins: Vec<D>) {
        debug_assert_eq!(F::nodes_to_pin(boundary).count(), pins.len());
        self.boundary = boundary;
        self.pins = F::nodes_to_pin(boundary).zip(pins).collect();
        self.resident.trim(F::location_to_position(boundary));
        self.flush();
    }

    fn available(&self, pos: Position<F>) -> bool {
        pos < self.size()
            && (pos >= F::location_to_position(self.boundary) || self.pins.contains_key(&pos))
    }

    /// The node at `pos`, of height `h`, if resident or pinned.
    fn held(&self, pos: Position<F>, h: u32) -> Option<D> {
        self.resident.get(pos, h).or_else(|| self.mem.get_node(pos))
    }

    /// The digests at `positions`, which need not be sorted.
    pub(crate) async fn get_nodes<C, H>(
        &self,
        journal: &C,
        hasher: &H,
        positions: &[Position<F>],
    ) -> Result<Vec<D>, merkle::Error<F>>
    where
        C: Contiguous<Item: EncodeShared>,
        H: Hasher<F, Digest = D> + 'static,
    {
        let mut result = vec![D::EMPTY; positions.len()];
        let mut fills = BTreeMap::<u64, Vec<(usize, usize)>>::new();
        let mut resident_hits = 0;
        for (index, &pos) in positions.iter().enumerate() {
            if !self.available(pos) {
                return Err(merkle::Error::ElementPruned(pos));
            }
            let h = F::pos_to_height(pos);
            if let Some(digest) = self.held(pos, h) {
                result[index] = digest;
                resident_hits += 1;
                continue;
            }
            if h >= self.resident.height {
                return Err(merkle::Error::MissingNode(pos));
            }
            let (region, slot) = self.regions.locate(pos, h);
            fills.entry(region).or_default().push((index, slot));
        }
        self.metrics.resident_hits.inc_by(resident_hits);
        if fills.is_empty() {
            return Ok(result);
        }
        let mut fills = stream::iter(fills)
            .map(|(region, low_peaks)| async move {
                let filled = self.fill_region(journal, hasher, region).await?;
                Ok::<_, merkle::Error<F>>((filled, low_peaks))
            })
            .buffer_unordered(CONCURRENT_FILLS);
        while let Some((filled, low_peaks)) = fills.try_next().await? {
            for (index, slot) in low_peaks {
                result[index] =
                    filled[slot].ok_or(merkle::Error::DataCorrupted("incomplete region fill"))?;
            }
        }
        Ok(result)
    }

    /// The digests [`Family::nodes_to_pin`] lists for `location`, in that order.
    pub(crate) async fn pinned_nodes_at<C, H>(
        &self,
        journal: &C,
        hasher: &H,
        location: Location<F>,
    ) -> Result<Vec<D>, merkle::Error<F>>
    where
        C: Contiguous<Item: EncodeShared>,
        H: Hasher<F, Digest = D> + 'static,
    {
        let positions: Vec<_> = F::nodes_to_pin(location).collect();
        self.get_nodes(journal, hasher, &positions).await
    }

    /// The digest at `pos`, or `None` if it is pruned or past the end.
    pub(crate) async fn get_node<C, H>(
        &self,
        journal: &C,
        hasher: &H,
        pos: Position<F>,
    ) -> Result<Option<D>, merkle::Error<F>>
    where
        C: Contiguous<Item: EncodeShared>,
        H: Hasher<F, Digest = D> + 'static,
    {
        if !self.available(pos) {
            return Ok(None);
        }
        Ok(self.get_nodes(journal, hasher, &[pos]).await?.pop())
    }

    /// Rebuild every born, available node of region `index`.
    async fn fill_region<C, H>(
        &self,
        journal: &C,
        hasher: &H,
        index: u64,
    ) -> Result<Region<D>, merkle::Error<F>>
    where
        C: Contiguous<Item: EncodeShared>,
        H: Hasher<F, Digest = D> + 'static,
    {
        self.metrics.region_fills.inc();
        let mut region = self.regions.empty();
        let height = self.regions.height;
        let width = self.regions.width();
        let base = index << height;
        let size = self.size();
        let boundary = F::location_to_position(self.boundary);

        // Read the leaves that are neither pinned nor pruned.
        let mut reads = Vec::new();
        for loc in base..(base + width).min(*self.leaves()) {
            let pos = F::location_to_position(Location::new(loc));
            if let Some(digest) = self.mem.get_node(pos) {
                region[(loc - base) as usize] = Some(digest);
            } else if pos >= boundary {
                reads.push(loc);
            }
        }
        if !reads.is_empty() {
            let items = journal.read_many(&reads).await?;
            let mut encoded = Encoded::new();
            for (&loc, item) in reads.iter().zip(items) {
                encoded.push(F::location_to_position(Location::new(loc)), &item);
            }
            self.metrics.filled_leaves.inc_by(reads.len() as u64);
            let hasher = hasher.clone();
            let digests = self
                .strategy
                .spawn(reads.len(), move |strategy| {
                    encoded.hash(&strategy, &hasher)
                })
                .await;
            for (&loc, digest) in reads.iter().zip(digests) {
                region[(loc - base) as usize] = Some(digest);
            }
        }

        // Hash parents bottom-up through the region root. Where a parent is already resident or
        // pinned, the hash must match it, which checks every digest beneath.
        let born = born(size);
        for h in 1..=height {
            let (row, below) = (self.regions.row(h), self.regions.row(h - 1));
            for i in 0..width >> h {
                if (base >> h) + i >= born[h as usize] {
                    break;
                }
                let pos = F::subtree_root_position(Location::new(base + (i << h)), h);
                let held = self.held(pos, h);
                if held.is_none() && pos < boundary {
                    continue;
                }
                let left = region[below + 2 * i as usize];
                let right = region[below + 2 * i as usize + 1];
                let digest = match (left, right, held) {
                    (Some(left), Some(right), held) => {
                        let digest = hasher.node_digest(pos, &left, &right);
                        if held.is_some_and(|held| held != digest) {
                            return Err(merkle::Error::DataCorrupted(
                                "rebuilt region does not match",
                            ));
                        }
                        digest
                    }
                    (_, _, Some(held)) => held,
                    _ => return Err(merkle::Error::MissingNode(pos)),
                };
                region[row + i as usize] = Some(digest);
            }
        }
        Ok(region)
    }
}

/// The nodes the tree holds in memory, resident or pinned. A node below the resident height that
/// is not pinned reads as absent, since it is rebuilt from operations.
impl<F: Family, D: Digest, S: Strategy> Readable for Tree<F, D, S> {
    type Family = F;
    type Digest = D;

    fn size(&self) -> Position<F> {
        self.size()
    }

    fn get_node(&self, pos: Position<F>) -> Option<D> {
        if pos >= self.size() {
            return None;
        }
        self.held(pos, F::pos_to_height(pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        journal::{Error as JournalError, authenticated::CacheConfig, contiguous::Batch},
        merkle::{Bagging, hasher::Standard, mmb, mmr},
    };
    use commonware_cryptography::{Sha256, sha256::Digest as D};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        ReadOptions, Runner as _, Supervisor as _, deterministic, reschedule,
    };
    use commonware_utils::NZU64;
    use std::{
        ops::Range,
        sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    };

    struct Operations {
        bounds: Range<u64>,
        /// The location `reads` counts from.
        origin: u64,
        reads: Vec<AtomicUsize>,
        /// A location whose stored operation differs from the one replayed, or `u64::MAX`.
        corrupt: AtomicU64,
    }

    impl Operations {
        fn new(end: u64) -> Self {
            Self::range(0..end)
        }
        fn range(bounds: Range<u64>) -> Self {
            Self {
                origin: bounds.start,
                reads: bounds.clone().map(|_| AtomicUsize::new(0)).collect(),
                bounds,
                corrupt: AtomicU64::new(u64::MAX),
            }
        }
        fn item(&self, position: u64) -> u64 {
            if position == self.corrupt.load(Ordering::Relaxed) {
                position + 1
            } else {
                position
            }
        }
        fn clear_reads(&self) {
            for reads in &self.reads {
                reads.store(0, Ordering::Relaxed);
            }
        }
        fn reads(&self) -> usize {
            self.reads.iter().map(|r| r.load(Ordering::Relaxed)).sum()
        }
    }

    impl Contiguous for Operations {
        type Item = u64;
        fn bounds(&self) -> Range<u64> {
            self.bounds.clone()
        }
        async fn read(&self, position: u64) -> Result<u64, JournalError> {
            assert!(
                self.bounds.contains(&position),
                "read an unavailable operation at {position}"
            );
            self.reads[(position - self.origin) as usize].fetch_add(1, Ordering::Relaxed);
            Ok(self.item(position))
        }
        async fn read_many(&self, positions: &[u64]) -> Result<Vec<u64>, JournalError> {
            // Yield like real I/O, so concurrent requests overlap.
            reschedule().await;
            let mut result = Vec::new();
            for &position in positions {
                result.push(self.read(position).await?);
            }
            Ok(result)
        }
        fn try_read_sync(&self, _: u64) -> Option<u64> {
            None
        }
        fn try_read_many_sync(&self, positions: &[u64]) -> Vec<Option<u64>> {
            vec![None; positions.len()]
        }
        async fn replay(
            &self,
            range: Range<u64>,
            _: NonZeroUsize,
            _: ReadOptions,
        ) -> Result<
            impl futures::Stream<Item = Result<Batch<u64>, JournalError>> + Send,
            JournalError,
        > {
            assert!(range.start >= self.bounds.start && range.end <= self.bounds.end);
            Ok(stream::iter(range).then(move |start| async move {
                let items = vec![self.read(start).await?];
                Ok(Batch { start, items })
            }))
        }
    }

    fn oracle<F: Family>(ops: &Operations, hasher: &Standard<Sha256>) -> Mem<F, D> {
        let mut mem = Mem::new();
        let mut batch = mem.new_batch();
        for loc in 0..ops.bounds.end {
            batch = batch.add(hasher, &ops.item(loc).encode());
        }
        mem.apply_batch(&batch.merkleize(&mem, hasher)).unwrap();
        mem
    }

    fn config(resident_height: u32) -> Config<Sequential> {
        Config {
            metadata_partition: String::new(),
            cache: CacheConfig { resident_height },
            replay_buffer: NonZeroUsize::MIN,
            strategy: Sequential,
        }
    }

    /// A replay batch holds at most `max_items` items, carrying the rest of a journal batch over.
    #[test]
    fn read_encoded_splits_journal_batches() {
        deterministic::Runner::default().start(|_| async move {
            let items = (0..100u64).collect();
            let mut stream = stream::iter([Ok(Batch { start: 0, items })]);
            let mut pending = Vec::new().into_iter();
            let mut read = async |loc, max_items| {
                Tree::<mmr::Family, D, Sequential>::read_encoded(
                    &mut stream,
                    &mut pending,
                    Location::new(loc),
                    max_items,
                )
                .await
                .unwrap()
                .leaves
                .len()
            };
            assert_eq!(read(0, 1).await, 1);
            assert_eq!(read(1, 1000).await, 99);
            assert_eq!(read(100, 1000).await, 0);
        });
    }

    /// A tree of `ops` replayed from genesis through `end`.
    async fn replayed<F: Family>(
        context: &deterministic::Context,
        ops: &Operations,
        hasher: &Standard<Sha256>,
        resident_height: u32,
        end: u64,
    ) -> Tree<F, D, Sequential> {
        let cfg = config(resident_height);
        Tree::new(Location::new(0), Vec::new(), &cfg, Metrics::new(context))
            .unwrap()
            .replay(ops, hasher, Location::new(end), NZU64!(7))
            .await
            .unwrap()
    }

    /// Every node at or past the boundary, and every pinned node, matches an in-memory oracle at
    /// each resident height, both as the boundary advances over one tree and in a tree opened at
    /// the boundary. Other nodes read as pruned.
    async fn matches_oracle<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(Bagging::ForwardFold);
        let mut ops = Operations::new(513);
        let expected = oracle::<F>(&ops, &hasher);
        for height in 0..=8 {
            ops.bounds.start = 0;
            let mut tree = replayed::<F>(&context, &ops, &hasher, height, 513).await;
            assert_eq!(
                tree.root(&hasher, 0).unwrap(),
                expected.root(&hasher, 0).unwrap()
            );
            for boundary in [0, 1, 7, 31, 32, 33, 46, 47, 48, 255, 256, 257] {
                let boundary = Location::new(boundary);
                let first = F::location_to_position(boundary);
                let pinned: Vec<_> = F::nodes_to_pin(boundary).collect();
                let pins: Vec<_> = pinned
                    .iter()
                    .map(|&p| expected.get_node(p).unwrap())
                    .collect();
                tree.prune(boundary, pins.clone());
                let resident = (*first..*expected.size())
                    .filter(|&p| F::pos_to_height(Position::new(p)) >= height)
                    .count();
                assert_eq!(tree.resident.len(), resident, "pruned nodes retained");
                ops.bounds.start = *boundary;
                let opened = Tree::new(boundary, pins, &config(height), Metrics::new(&context))
                    .unwrap()
                    .replay(&ops, &hasher, Location::new(513), NZU64!(7))
                    .await
                    .unwrap();

                let positions: Vec<_> = (*first..*expected.size())
                    .map(Position::new)
                    .chain(pinned.iter().copied())
                    .collect();
                for tree in [&tree, &opened] {
                    ops.clear_reads();
                    let got = tree.get_nodes(&ops, &hasher, &positions).await.unwrap();
                    for (&pos, node) in positions.iter().zip(got) {
                        assert_eq!(
                            Some(node),
                            expected.get_node(pos),
                            "height {height}, boundary {boundary}, position {pos}"
                        );
                    }
                    for (loc, count) in ops.reads.iter().enumerate() {
                        assert!(
                            count.load(Ordering::Relaxed) <= 1,
                            "operation {loc} read twice in one request"
                        );
                    }
                    if height == 0 {
                        assert_eq!(ops.reads(), 0, "resident nodes need no reads");
                    }
                    for pos in (0..*first).map(Position::new) {
                        if !pinned.contains(&pos) {
                            assert!(matches!(tree.get_node(&ops, &hasher, pos).await, Ok(None)));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn matches_oracle_mmr() {
        deterministic::Runner::default().start(matches_oracle::<mmr::Family>);
    }
    #[test]
    fn matches_oracle_mmb() {
        deterministic::Runner::default().start(matches_oracle::<mmb::Family>);
    }

    /// Replaying in aligned subtrees builds the same tree as replaying in batches: subtrees of
    /// several heights, opened at boundaries on and off subtree edges, replayed to ends before, on,
    /// and past them. Every node at or past the boundary matches an oracle.
    async fn subtrees_match_batches<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(Bagging::ForwardFold);
        let total = 200;
        let expected = oracle::<F>(&Operations::new(total), &hasher);
        for subtree in [1, 2, 4] {
            for resident in [0, 2, 5] {
                for boundary in [0, 1, 5, 16, 17, 45] {
                    for end in [boundary, boundary + 1, 16, 31, 64, 100, 129, total] {
                        if end < boundary {
                            continue;
                        }
                        let case = format!(
                            "subtree {subtree}, resident {resident}, boundary {boundary}, end {end}"
                        );
                        let pins: Vec<_> = F::nodes_to_pin(Location::new(boundary))
                            .map(|p| expected.get_node(p).unwrap())
                            .collect();
                        let ops = Arc::new(Operations::range(boundary..total));
                        let open = || {
                            Tree::new(
                                Location::new(boundary),
                                pins.clone(),
                                &config(resident),
                                Metrics::new(&context),
                            )
                            .unwrap()
                        };
                        let batched = open()
                            .replay(&*ops, &hasher, Location::new(end), NZU64!(7))
                            .await
                            .unwrap();
                        let (released, _released_rx) = mpsc::channel(1);
                        let subtrees = open()
                            .replay_subtrees(
                                context.child("replay"),
                                &ops,
                                &hasher,
                                Location::new(end),
                                subtree,
                                released,
                            )
                            .await
                            .unwrap();
                        assert_eq!(subtrees.size(), batched.size(), "{case}");
                        assert_eq!(
                            subtrees.root(&hasher, 0).unwrap(),
                            batched.root(&hasher, 0).unwrap(),
                            "{case}"
                        );
                        assert_eq!(
                            subtrees.mem().pinned_nodes(),
                            batched.mem().pinned_nodes(),
                            "{case}"
                        );
                        assert_eq!(subtrees.resident.len(), batched.resident.len(), "{case}");
                        let first = *F::location_to_position(Location::new(boundary));
                        let positions: Vec<_> =
                            (first..*subtrees.size()).map(Position::new).collect();
                        let got = subtrees
                            .get_nodes(&*ops, &hasher, &positions)
                            .await
                            .unwrap();
                        for (&pos, node) in positions.iter().zip(got) {
                            assert_eq!(
                                Some(node),
                                expected.get_node(pos),
                                "{case}, position {pos}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn subtrees_match_batches_mmr() {
        deterministic::Runner::default().start(subtrees_match_batches::<mmr::Family>);
    }
    #[test]
    fn subtrees_match_batches_mmb() {
        deterministic::Runner::default().start(subtrees_match_batches::<mmb::Family>);
    }

    /// A chunk, whole or partial, that does not start at the tree's end is rejected.
    async fn misplaced_chunks_are_rejected<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(Bagging::ForwardFold);
        let tree = Tree::<F, D, Sequential>::new(
            Location::new(0),
            Vec::new(),
            &config(2),
            Metrics::new(&context),
        )
        .unwrap();
        let plan = tree.chunk_plan(Location::new(40), 4);
        let chunks: Vec<_> = plan.chunks().collect();
        assert_eq!(chunks, [0..16, 16..32, 32..40]);
        for chunk in [16..32, 32..40] {
            let mut chunk_hasher = plan.hasher::<F, _>(chunk.clone(), hasher.clone());
            for loc in chunk {
                chunk_hasher.push(&loc);
            }
            let chunk = chunk_hasher.finish().unwrap();
            let tree = Tree::<F, D, Sequential>::new(
                Location::new(0),
                Vec::new(),
                &config(2),
                Metrics::new(&context),
            )
            .unwrap();
            assert!(matches!(
                tree.apply_chunk(&hasher, chunk).await,
                Err(merkle::Error::DataCorrupted(_))
            ));
        }
    }

    #[test]
    fn misplaced_chunks_are_rejected_mmr() {
        deterministic::Runner::default().start(misplaced_chunks_are_rejected::<mmr::Family>);
    }
    #[test]
    fn misplaced_chunks_are_rejected_mmb() {
        deterministic::Runner::default().start(misplaced_chunks_are_rejected::<mmb::Family>);
    }

    /// Appending up to the largest supported size matches an oracle, and rebuilding the regions
    /// there never places a node that is not born yet.
    async fn appends_near_maximum<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(Bagging::ForwardFold);
        let boundary = Location::<F>::new(*F::MAX_LEAVES - 40);
        let ops = Operations::range(*boundary..*F::MAX_LEAVES);
        let pins: Vec<_> = F::nodes_to_pin(boundary).map(|_| Sha256::fill(7)).collect();
        let tree = Tree::<F, D, _>::new(boundary, pins.clone(), &config(5), Metrics::new(&context))
            .unwrap();
        let mut batch = tree.new_batch();
        for loc in ops.bounds.clone() {
            batch = batch.add(&hasher, &ops.item(loc).encode());
        }
        let batch = batch.merkleize(tree.mem(), &hasher);
        let mut tree = tree.apply_batch(&batch).unwrap();
        assert_eq!(*tree.leaves(), ops.bounds.end);

        // An oracle that retains every node past the same boundary.
        let mut expected = Mem::from_components(Vec::new(), boundary, pins).unwrap();
        let mut batch = expected.new_batch();
        for loc in ops.bounds.clone() {
            batch = batch.add(&hasher, &ops.item(loc).encode());
        }
        expected
            .apply_batch(&batch.merkleize(&expected, &hasher))
            .unwrap();
        assert_eq!(tree.size(), expected.size());

        // Every node past the boundary matches, before and after a prune near the end.
        for boundary in [boundary, Location::new(*F::MAX_LEAVES - 8)] {
            let pins: Vec<_> = F::nodes_to_pin(boundary)
                .map(|p| expected.get_node(p).unwrap())
                .collect();
            tree.prune(boundary, pins);
            let positions: Vec<_> = (*F::location_to_position(boundary)..*tree.size())
                .map(Position::new)
                .collect();
            let got = tree.get_nodes(&ops, &hasher, &positions).await.unwrap();
            for (&pos, node) in positions.iter().zip(got) {
                assert_eq!(Some(node), expected.get_node(pos), "position {pos}");
            }
        }
    }

    #[test]
    fn appends_near_maximum_mmr() {
        deterministic::Runner::default().start(appends_near_maximum::<mmr::Family>);
    }
    #[test]
    fn appends_near_maximum_mmb() {
        deterministic::Runner::default().start(appends_near_maximum::<mmb::Family>);
    }

    /// Each batch in an applied chain proves its leaves after its ancestors are dropped.
    async fn applied_chain<F: Family>(context: deterministic::Context) {
        // Start from an applied prefix so proofs need both base nodes and nodes from the chain.
        let hasher = Standard::<Sha256>::new(Bagging::ForwardFold);
        let ops = Operations::new(20);
        let tree = replayed::<F>(&context, &ops, &hasher, 2, 9).await;

        // Retain each intermediate batch while building a tip that includes every append.
        let (mut chain, mut tip, mut start) = (Vec::new(), tree.to_batch(), 9);
        for len in [3, 1, 2, 5] {
            let mut batch = tip.new_batch();
            for loc in start..start + len {
                batch = batch.add(&hasher, &ops.item(loc).encode());
            }
            tip = batch.merkleize(tree.mem(), &hasher);
            chain.push((
                Location::new(start)..Location::new(start + len),
                Arc::clone(&tip),
            ));
            start += len;
        }

        // Publish the final tip without separately applying intermediate batches.
        let tree = tree.apply_batch(&tip).unwrap();
        drop(tip);

        // Consume batches from oldest to newest, checking each proof after its ancestors drop.
        for (range, batch) in chain {
            let leaves: Vec<_> = (*range.start..*range.end)
                .map(|loc| ops.item(loc).encode())
                .collect();
            let root = batch.root(&hasher, 0).unwrap();
            let proof = batch
                .range_proof(tree.mem(), &hasher, range.clone(), 0)
                .unwrap();
            assert!(proof.verify_range_inclusion(&hasher, range.start, &leaves, &root));
        }

        // Compare reconstructed nodes with a tree that retains every node.
        let expected = oracle::<F>(&ops, &hasher);
        let positions: Vec<_> = (0..*expected.size()).map(Position::new).collect();
        let nodes = tree.get_nodes(&ops, &hasher, &positions).await.unwrap();
        for (pos, node) in positions.into_iter().zip(nodes) {
            assert_eq!(Some(node), expected.get_node(pos), "position {pos}");
        }
    }

    /// A chain that overwrites a node is rejected, since the tree applies only appended nodes.
    async fn rejects_overwrites<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(Bagging::ForwardFold);
        let ops = Operations::new(4);
        let tree = replayed::<F>(&context, &ops, &hasher, 2, 2).await;
        let parent = tree
            .new_batch()
            .add(&hasher, &ops.item(2).encode())
            .add(&hasher, &ops.item(3).encode())
            .merkleize(tree.mem(), &hasher);
        let child = parent
            .new_batch()
            .update_leaf_digest(Location::new(3), Sha256::fill(1))
            .unwrap()
            .merkleize(tree.mem(), &hasher);
        assert!(matches!(
            tree.apply_batch(&child),
            Err(merkle::Error::DataCorrupted(_))
        ));
    }

    #[test]
    fn rejects_overwrites_mmr() {
        deterministic::Runner::default().start(rejects_overwrites::<mmr::Family>);
    }
    #[test]
    fn rejects_overwrites_mmb() {
        deterministic::Runner::default().start(rejects_overwrites::<mmb::Family>);
    }

    #[test]
    fn applied_chain_mmr() {
        deterministic::Runner::default().start(applied_chain::<mmr::Family>);
    }
    #[test]
    fn applied_chain_mmb() {
        deterministic::Runner::default().start(applied_chain::<mmb::Family>);
    }

    /// A stored operation that differs from the one replayed fails the check against its region's
    /// root, or against the peak above it while the region root is unborn.
    async fn corrupt_operation<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(Bagging::ForwardFold);
        for leaves in [128, 40, 70] {
            let ops = Operations::new(leaves);
            let tree = replayed::<F>(&context, &ops, &hasher, 5, leaves).await;
            ops.corrupt.store(33, Ordering::Relaxed);
            let pos = F::location_to_position(Location::new(32));
            assert!(
                matches!(
                    tree.get_node(&ops, &hasher, pos).await,
                    Err(merkle::Error::DataCorrupted(_))
                ),
                "{leaves} leaves"
            );
        }
    }

    #[test]
    fn corrupt_operation_mmr() {
        deterministic::Runner::default().start(corrupt_operation::<mmr::Family>);
    }
    #[test]
    fn corrupt_operation_mmb() {
        deterministic::Runner::default().start(corrupt_operation::<mmb::Family>);
    }

    /// After a prune at any boundary, a corrupt operation retained in the boundary's region still
    /// fails a check.
    async fn corrupt_operation_after_prune<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(Bagging::ForwardFold);
        let mut ops = Operations::new(100);
        let expected = oracle::<F>(&ops, &hasher);
        for boundary in 1..100 {
            ops.bounds.start = 0;
            let mut tree = replayed::<F>(&context, &ops, &hasher, 5, 100).await;
            let pins = F::nodes_to_pin(Location::new(boundary))
                .map(|p| expected.get_node(p).unwrap())
                .collect();
            tree.prune(Location::new(boundary), pins);
            ops.bounds.start = boundary;
            for corrupt in boundary..((boundary | 31) + 1).min(100) {
                ops.corrupt.store(corrupt, Ordering::Relaxed);
                let pos = F::location_to_position(Location::new(corrupt));
                assert!(
                    matches!(
                        tree.get_node(&ops, &hasher, pos).await,
                        Err(merkle::Error::DataCorrupted(_))
                    ),
                    "boundary {boundary}, corrupt {corrupt}"
                );
            }
            ops.corrupt.store(u64::MAX, Ordering::Relaxed);
        }
    }

    #[test]
    fn corrupt_operation_after_prune_mmr() {
        deterministic::Runner::default().start(corrupt_operation_after_prune::<mmr::Family>);
    }
    #[test]
    fn corrupt_operation_after_prune_mmb() {
        deterministic::Runner::default().start(corrupt_operation_after_prune::<mmb::Family>);
    }
}

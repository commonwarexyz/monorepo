//! The Merkle digests of an authenticated journal, held in memory or rebuilt from its operations.
//!
//! Digests live in three places:
//!
//! - `mem` holds no nodes, only pinned digests. It pins the peaks at its size, peaks at earlier
//!   sizes until [Tree::flush], and the digests pinned at the tree's boundary.
//! - `resident` holds every node at or above the resident height, at or past the boundary.
//! - `regions` caches lower nodes. Each region is an aligned run of `2^resident_height` leaves
//!   and the nodes above them up to the resident height, rebuilt ("filled") from its operations.
//!
//! A node is born once the tree contains it. In an MMB some parents are born a few leaves after
//! their last leaf. A node's ordinal is its index among the nodes of its height.
//!
//! A filled digest is never served unchecked. Every region has a node above its rebuilt digests
//! that is resident or pinned, and a fill recomputes that node and compares it before caching the
//! region. Batches only append, so a cached digest never changes.

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
use commonware_runtime::{ReadOptions, telemetry::metrics::GaugeExt as _};
use commonware_utils::{
    cache::Cache,
    sync::{AsyncMutex, RwLock},
};
use futures::{Stream, StreamExt as _, TryStreamExt as _, pin_mut, stream};
use std::{
    collections::{BTreeMap, VecDeque},
    num::{NonZeroU64, NonZeroUsize},
    ops::Range,
    sync::Arc,
};

/// Encoded bytes after which a replay batch ends.
const REPLAY_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// Locks that serialize fills, shared by regions whose indices are congruent modulo this count.
const FILL_LOCKS: usize = 64;

/// Regions filled concurrently by one request.
const CONCURRENT_FILLS: usize = 8;

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
        let born = born(end);
        for (index, (level, &to)) in self
            .levels
            .iter_mut()
            .zip(&born[self.height as usize..])
            .enumerate()
        {
            let height = self.height + index as u32;
            for ordinal in level.end()..to {
                let pos = F::subtree_root_position(Location::new(ordinal << height), height);
                level
                    .nodes
                    .push_back(node(pos).ok_or(merkle::Error::MissingNode(pos))?);
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

type RegionCache<D> = Cache<u64, Arc<Region<D>>>;

/// A bounded cache of regions shared by concurrent readers.
struct Regions<D> {
    /// The resident height, so each region spans `2^height` leaves.
    height: u32,
    cache: RwLock<Option<Box<RegionCache<D>>>>,
    fill_locks: Box<[AsyncMutex<()>; FILL_LOCKS]>,
}

impl<D: Digest> Regions<D> {
    fn new(height: u32, capacity: Option<NonZeroUsize>) -> Self {
        Self {
            height,
            cache: RwLock::new(capacity.map(|capacity| Box::new(Cache::new(capacity)))),
            fill_locks: Box::new(std::array::from_fn(|_| AsyncMutex::new(()))),
        }
    }

    const fn width(&self) -> u64 {
        1 << self.height
    }

    fn empty(&self) -> Region<D> {
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

    fn get(&self, index: u64) -> Option<Arc<Region<D>>> {
        self.cache.read().as_ref()?.get(&index).cloned()
    }

    fn fill_lock(&self, index: u64) -> &AsyncMutex<()> {
        &self.fill_locks[index as usize % FILL_LOCKS]
    }

    fn insert(&self, index: u64, region: Arc<Region<D>>) {
        if let Some(cache) = self.cache.write().as_mut() {
            cache.put(index, region);
        }
    }

    /// Drop regions holding leaves before `boundary`.
    fn retain_from<F: Family>(&mut self, boundary: Location<F>) {
        let height = self.height;
        if let Some(cache) = self.cache.get_mut().as_mut() {
            cache.retain(|index, _| (*index << height) >= *boundary);
        }
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

/// The Merkle digests of an authenticated journal. Only `mem` is shared with batches.
pub(crate) struct Tree<F: Family, D: Digest, S: Strategy> {
    mem: Arc<Mem<F, D>>,
    metrics: Box<Metrics>,
    /// First retained leaf.
    boundary: Location<F>,
    /// Digests pinned at the boundary, which [Self::flush] keeps pinned in `mem`.
    pins: BTreeMap<Position<F>, D>,
    resident: Resident<D>,
    regions: Regions<D>,
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
        let capacity = config
            .cache
            .capacity::<D>()
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
            regions: Regions::new(config.cache.resident_height, capacity),
            strategy: config.strategy.clone(),
            replay_buffer: config.replay_buffer,
        };
        tree.update_metrics();
        Ok(tree)
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
        let mut next = Self::read_encoded(&mut stream, loc, max_items).await?;
        // Read each batch while the previous one hashes.
        while !next.leaves.is_empty() {
            loc += next.leaves.len() as u64;
            (self, next) = futures::try_join!(
                self.apply_encoded(hasher, next),
                Self::read_encoded(&mut stream, loc, max_items),
            )?;
        }
        if self.leaves() != end {
            return Err(merkle::Error::DataCorrupted("replay ended before its range").into());
        }
        Ok(self)
    }

    /// Read and encode the leaves from `loc`, stopping once a batch holds at least `max_items`
    /// items or [REPLAY_BATCH_BYTES] bytes, or `stream` ends.
    async fn read_encoded<I: Encode>(
        stream: &mut (impl Stream<Item = Result<Batch<I>, JournalError>> + Unpin),
        mut loc: Location<F>,
        max_items: usize,
    ) -> Result<Encoded<F>, super::Error<F>> {
        let mut encoded = Encoded::new();
        while encoded.leaves.len() < max_items && encoded.bytes.len() < REPLAY_BATCH_BYTES {
            let Some(batch) = stream.next().await else {
                break;
            };
            for item in batch?.items {
                encoded.push(F::location_to_position(loc), &item);
                loc += 1;
            }
        }
        Ok(encoded)
    }

    async fn apply_encoded<H>(
        mut self,
        hasher: &H,
        encoded: Encoded<F>,
    ) -> Result<Self, super::Error<F>>
    where
        H: Hasher<F, Digest = D> + 'static,
    {
        self.metrics
            .replayed_leaves
            .inc_by(encoded.leaves.len() as u64);
        let mem = self.snapshot();
        let hasher = hasher.clone();
        let batch = self.new_batch();
        let batch = self
            .strategy
            .spawn(encoded.leaves.len(), move |strategy| {
                let digests = encoded.hash(&strategy, &hasher);
                batch.add_leaf_digests(digests).merkleize(&mem, &hasher)
            })
            .await;
        self = self.apply_batch(&batch)?;
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
        let runs = batch.unapplied(self.size())?;
        if runs.iter().any(|(_, overwrites)| !overwrites.is_empty()) {
            return Err(merkle::Error::DataCorrupted("batch overwrites nodes"));
        }
        // Apply each batch of the chain in turn, so the peaks at every size in it stay pinned
        // until the next flush.
        for (run, _) in runs {
            let start = self.size();
            let node = |pos: Position<F>| {
                let index = usize::try_from((*pos).checked_sub(*start)?).ok()?;
                run.get(index).copied()
            };
            let end = start + run.len() as u64;
            self.resident.extend(end, node)?;

            // Peaks before `start` are already pinned in `mem`.
            let leaves = Location::try_from(end)?;
            let peaks = F::nodes_to_pin(leaves)
                .filter(|&pos| pos >= start)
                .map(|pos| {
                    node(pos)
                        .map(|digest| (pos, digest))
                        .ok_or(merkle::Error::MissingNode(pos))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Arc::make_mut(&mut self.mem).skip_to(leaves, peaks)?;
        }
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
        self.regions.retain_from(boundary);
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
        let (mut resident_hits, mut region_hits) = (0, 0);
        {
            let cache = self.regions.cache.read();
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
                match cache.as_deref().and_then(|cache| cache.get(&region)?[slot]) {
                    Some(digest) => {
                        result[index] = digest;
                        region_hits += 1;
                    }
                    None => fills.entry(region).or_default().push((index, slot)),
                }
            }
        }
        self.metrics.resident_hits.inc_by(resident_hits);
        self.metrics.region_hits.inc_by(region_hits);
        if fills.is_empty() {
            return Ok(result);
        }
        let mut fills = stream::iter(fills)
            .map(|(region, wanted)| async move {
                let slots: Vec<usize> = wanted.iter().map(|&(_, slot)| slot).collect();
                let filled = self.fill_region(journal, hasher, region, &slots).await?;
                Ok::<_, merkle::Error<F>>((filled, wanted))
            })
            .buffer_unordered(CONCURRENT_FILLS);
        while let Some((filled, wanted)) = fills.try_next().await? {
            for (index, slot) in wanted {
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

    /// Rebuild every born, available node of region `index` that it lacks, unless another fill
    /// already provided `wanted`.
    async fn fill_region<C, H>(
        &self,
        journal: &C,
        hasher: &H,
        index: u64,
        wanted: &[usize],
    ) -> Result<Arc<Region<D>>, merkle::Error<F>>
    where
        C: Contiguous<Item: EncodeShared>,
        H: Hasher<F, Digest = D> + 'static,
    {
        let _guard = self.regions.fill_lock(index).lock().await;
        let old = self.regions.get(index);
        if let Some(region) = &old
            && wanted.iter().all(|&slot| region[slot].is_some())
        {
            self.metrics.region_hits.inc_by(wanted.len() as u64);
            return Ok(Arc::clone(region));
        }
        self.metrics.region_fills.inc();
        let mut region = old
            .as_deref()
            .cloned()
            .unwrap_or_else(|| self.regions.empty());
        let height = self.regions.height;
        let width = self.regions.width();
        let base = index << height;
        let size = self.size();
        let boundary = F::location_to_position(self.boundary);

        // Read the leaves that are neither cached, pinned nor pruned.
        let mut reads = Vec::new();
        for loc in base..(base + width).min(*self.leaves()) {
            let slot = (loc - base) as usize;
            if region[slot].is_some() {
                continue;
            }
            let pos = F::location_to_position(Location::new(loc));
            if let Some(digest) = self.mem.get_node(pos) {
                region[slot] = Some(digest);
            } else if pos >= boundary {
                reads.push(loc);
            }
        }
        if !reads.is_empty() {
            let items = journal.read_many(&reads).await?;
            let mut encoded = Encoded::new();
            for (&loc, item) in reads.iter().zip(&items) {
                encoded.push(F::location_to_position(Location::new(loc)), item);
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
                let slot = row + i as usize;
                if region[slot].is_some() {
                    continue;
                }
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
                            return Err(merkle::Error::RootMismatch);
                        }
                        digest
                    }
                    (_, _, Some(held)) => held,
                    _ => return Err(merkle::Error::MissingNode(pos)),
                };
                region[slot] = Some(digest);
            }
        }
        let region = Arc::new(region);
        self.regions.insert(index, Arc::clone(&region));
        Ok(region)
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
    use commonware_runtime::{ReadOptions, Runner as _, deterministic, reschedule};
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

    fn config(resident_height: u32, region_cache_bytes: usize) -> Config<Sequential> {
        Config {
            metadata_partition: String::new(),
            cache: CacheConfig {
                resident_height,
                region_cache_bytes,
            },
            replay_buffer: NonZeroUsize::MIN,
            strategy: Sequential,
        }
    }

    /// A tree of `ops` replayed from genesis through `end`.
    async fn replayed<F: Family>(
        context: &deterministic::Context,
        ops: &Operations,
        hasher: &Standard<Sha256>,
        resident_height: u32,
        region_cache_bytes: usize,
        end: u64,
    ) -> Tree<F, D, Sequential> {
        let cfg = config(resident_height, region_cache_bytes);
        Tree::new(Location::new(0), Vec::new(), &cfg, Metrics::new(context))
            .unwrap()
            .replay(ops, hasher, Location::new(end), NZU64!(7))
            .await
            .unwrap()
    }

    /// Every available node matches an in-memory oracle at each resident height and cache budget,
    /// as the boundary advances over one tree.
    async fn matches_oracle<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(Bagging::ForwardFold);
        let mut ops = Operations::new(513);
        let expected = oracle::<F>(&ops, &hasher);
        for height in 0..=8 {
            for budget in [0, 8 * 1024 * 1024] {
                ops.bounds.start = 0;
                let mut tree = replayed::<F>(&context, &ops, &hasher, height, budget, 513).await;
                assert_eq!(
                    tree.root(&hasher, 0).unwrap(),
                    expected.root(&hasher, 0).unwrap()
                );
                assert!(
                    tree.regions.get(0).is_none(),
                    "startup must not warm regions"
                );
                for boundary in [0, 1, 7, 31, 32, 33, 46, 47, 48, 255, 256, 257] {
                    let boundary = Location::new(boundary);
                    let pins = F::nodes_to_pin(boundary)
                        .map(|p| expected.get_node(p).unwrap())
                        .collect();
                    tree.prune(boundary, pins);
                    let (end, start) = (born(tree.size()), born(F::location_to_position(boundary)));
                    let held: u64 = (height as usize..end.len())
                        .map(|h| end[h] - start[h])
                        .sum();
                    assert_eq!(tree.resident.len() as u64, held, "pruned nodes retained");
                    if let Some(cache) = tree.regions.cache.get_mut() {
                        cache.retain(|region, _| {
                            assert!(region << height >= *boundary, "pruned region retained");
                            true
                        });
                    }
                    ops.bounds.start = *boundary;
                    ops.clear_reads();
                    let positions: Vec<_> = (0..*expected.size())
                        .map(Position::new)
                        .filter(|&p| tree.available(p))
                        .collect();
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
                    if budget > 0 || height == 0 {
                        ops.clear_reads();
                        tree.get_nodes(&ops, &hasher, &positions).await.unwrap();
                        assert_eq!(ops.reads(), 0, "cached regions must not read operations");
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

    /// Appending up to the largest supported size, and rebuilding the regions there, never places
    /// a node that is not born yet.
    async fn appends_near_maximum<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(Bagging::ForwardFold);
        let boundary = Location::<F>::new(*F::MAX_LEAVES - 40);
        let ops = Operations::range(*boundary..*F::MAX_LEAVES);
        let pins = F::nodes_to_pin(boundary).map(|_| Sha256::fill(7)).collect();
        let tree =
            Tree::<F, D, _>::new(boundary, pins, &config(5, 0), Metrics::new(&context)).unwrap();
        let mut batch = tree.new_batch();
        for loc in ops.bounds.clone() {
            batch = batch.add(&hasher, &ops.item(loc).encode());
        }
        let batch = batch.merkleize(tree.mem(), &hasher);
        let tree = tree.apply_batch(&batch).unwrap();
        assert_eq!(*tree.leaves(), ops.bounds.end);
        for loc in ops.bounds.clone() {
            let pos = F::location_to_position(Location::new(loc));
            assert!(tree.get_node(&ops, &hasher, pos).await.unwrap().is_some());
        }
        tree.pinned_nodes_at(&ops, &hasher, tree.leaves())
            .await
            .unwrap();
    }

    #[test]
    fn appends_near_maximum_mmr() {
        deterministic::Runner::default().start(appends_near_maximum::<mmr::Family>);
    }
    #[test]
    fn appends_near_maximum_mmb() {
        deterministic::Runner::default().start(appends_near_maximum::<mmb::Family>);
    }

    /// Applying the tip of a chain keeps the peaks at every size in it until the next flush, so
    /// each batch still proves its leaves once its ancestors are dropped.
    async fn applied_chain<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(Bagging::ForwardFold);
        let ops = Operations::new(20);
        let tree = replayed::<F>(&context, &ops, &hasher, 2, 0, 9).await;
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
        let tree = tree.apply_batch(&tip).unwrap();
        drop(tip);
        for (range, batch) in chain {
            let leaves: Vec<_> = (*range.start..*range.end)
                .map(|loc| ops.item(loc).encode())
                .collect();
            let root = batch.root(tree.mem(), &hasher, 0).unwrap();
            let proof = batch
                .range_proof(tree.mem(), &hasher, range.clone(), 0)
                .unwrap();
            assert!(proof.verify_range_inclusion(&hasher, &leaves, range.start, &root));
        }
        let expected = oracle::<F>(&ops, &hasher);
        let positions: Vec<_> = (0..*expected.size()).map(Position::new).collect();
        let nodes = tree.get_nodes(&ops, &hasher, &positions).await.unwrap();
        for (pos, node) in positions.into_iter().zip(nodes) {
            assert_eq!(Some(node), expected.get_node(pos), "position {pos}");
        }
    }

    #[test]
    fn applied_chain_mmr() {
        deterministic::Runner::default().start(applied_chain::<mmr::Family>);
    }
    #[test]
    fn applied_chain_mmb() {
        deterministic::Runner::default().start(applied_chain::<mmb::Family>);
    }

    /// A cold fill reads its region once, resident nodes need no reads, concurrent requests share
    /// a fill, and a dropped fill caches nothing.
    async fn region_cache<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(Bagging::BackwardFold);
        let ops = Operations::new(128);
        let budget = CacheConfig::with_regions::<D>(5, 1).region_cache_bytes;
        let mut tree = replayed::<F>(&context, &ops, &hasher, 5, budget, 128).await;
        ops.clear_reads();
        let region = 1 << 5;
        let pos = F::location_to_position(Location::new(0));
        let first = tree.get_node(&ops, &hasher, pos).await.unwrap().unwrap();
        assert_eq!(ops.reads(), region, "a cold fill reads its whole region");
        let resident = (0..*tree.size())
            .map(Position::new)
            .find(|&p| F::pos_to_height(p) >= 5)
            .unwrap();
        tree.get_node(&ops, &hasher, resident).await.unwrap();
        assert_eq!(ops.reads(), region, "resident nodes need no reads");

        // Multiple fills can evict earlier regions, but each request still reads each leaf once.
        ops.clear_reads();
        let positions: Vec<_> = (0..*tree.size()).map(Position::new).collect();
        tree.get_nodes(&ops, &hasher, &positions).await.unwrap();
        assert!(ops.reads.iter().all(|r| r.load(Ordering::Relaxed) <= 1));
        if let Some(cache) = tree.regions.cache.get_mut() {
            cache.clear();
        }
        ops.clear_reads();
        let reads = (0..32).map(|_| tree.get_node(&ops, &hasher, pos));
        for result in futures::future::join_all(reads).await {
            assert_eq!(result.unwrap(), Some(first));
        }
        assert_eq!(
            ops.reads(),
            region,
            "concurrent requests must share one fill"
        );

        // A dropped fill releases its lock and caches nothing, so the next request fills.
        if let Some(cache) = tree.regions.cache.get_mut() {
            cache.clear();
        }
        ops.clear_reads();
        {
            let dropped = tree.get_node(&ops, &hasher, pos);
            futures::pin_mut!(dropped);
            assert!(futures::poll!(dropped).is_pending());
        }
        assert!(tree.regions.get(0).is_none());
        assert_eq!(
            tree.get_node(&ops, &hasher, pos).await.unwrap(),
            Some(first)
        );
        assert_eq!(ops.reads(), region);
    }

    #[test]
    fn region_cache_mmr() {
        deterministic::Runner::default().start(region_cache::<mmr::Family>);
    }
    #[test]
    fn region_cache_mmb() {
        deterministic::Runner::default().start(region_cache::<mmb::Family>);
    }

    /// A region cached while partial keeps its leaves when later appends complete it, including
    /// across a prune that empties a resident level.
    async fn completed_region<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(Bagging::ForwardFold);
        let mut ops = Operations::new(128);
        let expected = oracle::<F>(&ops, &hasher);
        let mut tree = replayed::<F>(&context, &ops, &hasher, 5, 8 * 1024 * 1024, 40).await;
        let leaf = F::location_to_position(Location::new(32));
        assert_eq!(
            tree.get_node(&ops, &hasher, leaf).await.unwrap(),
            expected.get_node(leaf)
        );

        let boundary = Location::new(32);
        let pins = F::nodes_to_pin(boundary)
            .map(|p| expected.get_node(p).unwrap())
            .collect();
        tree.prune(boundary, pins);
        ops.bounds.start = *boundary;
        let tree = tree
            .replay(&ops, &hasher, Location::new(128), NZU64!(7))
            .await
            .unwrap();
        assert_eq!(
            tree.root(&hasher, 0).unwrap(),
            expected.root(&hasher, 0).unwrap()
        );

        ops.clear_reads();
        let positions: Vec<_> = (0..*tree.size())
            .map(Position::new)
            .filter(|&p| tree.available(p))
            .collect();
        let got = tree.get_nodes(&ops, &hasher, &positions).await.unwrap();
        for (&pos, node) in positions.iter().zip(got) {
            assert_eq!(Some(node), expected.get_node(pos), "position {pos}");
        }
        assert!(
            ops.reads[32..40]
                .iter()
                .all(|r| r.load(Ordering::Relaxed) == 0),
            "cached leaves must not be read again"
        );
    }

    #[test]
    fn completed_region_mmr() {
        deterministic::Runner::default().start(completed_region::<mmr::Family>);
    }
    #[test]
    fn completed_region_mmb() {
        deterministic::Runner::default().start(completed_region::<mmb::Family>);
    }

    /// A stored operation that differs from the one replayed fails the check against its region's
    /// root, or against the peak above it while the region root is unborn.
    async fn corrupt_operation<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(Bagging::ForwardFold);
        for leaves in [128, 40, 70] {
            let ops = Operations::new(leaves);
            let tree = replayed::<F>(&context, &ops, &hasher, 5, 0, leaves).await;
            ops.corrupt.store(33, Ordering::Relaxed);
            let pos = F::location_to_position(Location::new(32));
            assert!(
                matches!(
                    tree.get_node(&ops, &hasher, pos).await,
                    Err(merkle::Error::RootMismatch)
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
}

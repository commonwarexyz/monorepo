//! Volatile Merkle digests of an operation-backed authenticated journal.
//!
//! Nodes at or above the resident height are kept in memory. Lower nodes are rebuilt from the
//! operations under them, one aligned region of `2^resident_height` leaves at a time, and kept in
//! a bounded cache of regions. Invariants:
//!
//! - `mem` retains no nodes: its pruning boundary equals its size. It pins the peaks at its size,
//!   peaks at earlier sizes until [Tree::flush], and the digests at the pruning boundary.
//! - Each resident level holds every born node of its height at or past the boundary position.
//! - Batches only append, so a cached digest never changes.
//! - At most one fill of a region runs at a time.

use super::{Config, EncodedReader, ReplayEncoded, metrics::Metrics};
use crate::{
    journal::contiguous::Contiguous,
    merkle::{self, Family, Location, Position, Readable, batch, hasher::Hasher, mem::Mem},
};
use commonware_codec::{Encode, EncodeShared};
use commonware_cryptography::Digest;
use commonware_parallel::Strategy;
use commonware_runtime::telemetry::metrics::GaugeExt as _;
use commonware_utils::{
    bitmap::BitMap,
    cache::Cache,
    sync::{AsyncMutex, RwLock},
};
use futures::{StreamExt as _, TryStreamExt as _, stream};
use std::{
    collections::{BTreeMap, VecDeque},
    num::{NonZeroU64, NonZeroUsize},
    ops::Range,
    sync::Arc,
};

/// Default for [`Tree::hash_batch_bytes`].
const HASH_BATCH_BYTES: usize = 8 << 20;

/// Locks that serialize fills, shared by regions whose indices are congruent modulo this count.
const FILL_LOCKS: usize = 64;

/// Regions filled concurrently by one request.
const CONCURRENT_FILLS: usize = 8;

/// Born nodes of one resident height at or past the boundary, in ordinal order.
struct Level<D> {
    first: u64,
    nodes: VecDeque<D>,
}

impl<D: Copy> Level<D> {
    fn get(&self, ordinal: u64) -> Option<D> {
        let index = usize::try_from(ordinal.checked_sub(self.first)?).ok()?;
        self.nodes.get(index).copied()
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
    const fn new(height: u32) -> Self {
        Self {
            height,
            levels: Vec::new(),
        }
    }

    /// The node at `pos`, whose height `h` is at least the resident height.
    fn get<F: Family>(&self, pos: Position<F>, h: u32) -> Option<D> {
        let level = self.levels.get((h - self.height) as usize)?;
        level.get(*F::leftmost_leaf(pos, h) >> h)
    }

    /// The root of `region`, if born.
    fn region_root(&self, region: u64) -> Option<D> {
        self.levels.first()?.get(region)
    }

    /// Add the nodes born between sizes `start` and `end`, whose digests `node` returns.
    fn extend<F: Family>(
        &mut self,
        start: Position<F>,
        end: Position<F>,
        node: impl Fn(Position<F>) -> Option<D>,
    ) -> Result<(), merkle::Error<F>> {
        let start_leaves = *Location::try_from(start)?;
        let leaves = *Location::try_from(end)?;
        for height in self.height..u64::BITS {
            if 1u64 << height > leaves {
                break;
            }
            let root =
                |ordinal: u64| F::subtree_root_position(Location::new(ordinal << height), height);
            let index = (height - self.height) as usize;
            if index == self.levels.len() {
                self.levels.push(Level {
                    first: 0,
                    nodes: VecDeque::new(),
                });
            }
            let level = &mut self.levels[index];
            let mut ordinal = if level.nodes.is_empty() {
                // The subtree holding the next leaf is unborn; MMB may also delay earlier ones.
                let mut ordinal = start_leaves >> height;
                while ordinal > 0 && root(ordinal - 1) >= start {
                    ordinal -= 1;
                }
                level.first = ordinal;
                ordinal
            } else {
                level.first + level.nodes.len() as u64
            };
            loop {
                let pos = root(ordinal);
                if pos >= end {
                    break;
                }
                if pos < start {
                    return Err(merkle::Error::DataCorrupted("noncontiguous resident level"));
                }
                level
                    .nodes
                    .push_back(node(pos).ok_or(merkle::Error::MissingNode(pos))?);
                ordinal += 1;
            }
        }
        Ok(())
    }

    /// Drop nodes before `boundary`.
    fn trim<F: Family>(&mut self, boundary: Position<F>) {
        for (index, level) in self.levels.iter_mut().enumerate() {
            let height = self.height + index as u32;
            while !level.nodes.is_empty() {
                let pos = F::subtree_root_position(Location::new(level.first << height), height);
                if pos >= boundary {
                    break;
                }
                level.nodes.pop_front();
                level.first += 1;
            }
            if level.nodes.len() <= level.nodes.capacity() / 4 {
                level.nodes.shrink_to_fit();
            }
        }
    }

    /// Digests held and digest slots allocated.
    fn usage(&self) -> (usize, usize) {
        self.levels.iter().fold((0, 0), |(len, capacity), level| {
            (len + level.nodes.len(), capacity + level.nodes.capacity())
        })
    }
}

/// Digests below the resident height for one aligned region of leaves, in height-major slots:
/// leaves, then height-one nodes, and so on.
#[derive(Clone)]
struct Region<D> {
    digests: Box<[D]>,
    valid: BitMap,
}

impl<D: Digest> Region<D> {
    fn new(slots: usize) -> Self {
        Self {
            digests: vec![D::EMPTY; slots].into_boxed_slice(),
            valid: BitMap::zeroes(slots as u64),
        }
    }

    fn get(&self, slot: usize) -> Option<D> {
        self.valid.get(slot as u64).then(|| self.digests[slot])
    }

    fn put(&mut self, slot: usize, digest: D) {
        self.digests[slot] = digest;
        self.valid.set(slot as u64, true);
    }
}

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
        Region::new((2usize << self.height) - 2)
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

    fn get(&self, region: u64) -> Option<Arc<Region<D>>> {
        self.cache.read().as_ref()?.get(&region).cloned()
    }

    fn fill_lock(&self, region: u64) -> &AsyncMutex<()> {
        &self.fill_locks[region as usize % FILL_LOCKS]
    }

    /// Cache `region`, returning the number of cached regions.
    fn insert(&self, index: u64, region: Arc<Region<D>>) -> Option<usize> {
        let mut cache = self.cache.write();
        let cache = cache.as_mut()?;
        cache.put(index, region);
        Some(cache.len())
    }

    /// Drop regions holding leaves before `boundary`, returning the number of cached regions.
    fn retain_from<F: Family>(&mut self, boundary: Location<F>) -> Option<usize> {
        let height = self.height;
        let cache = self.cache.get_mut().as_mut()?;
        cache.retain(|region, _| (*region << height) >= *boundary);
        Some(cache.len())
    }
}

/// Where an available node's digest is.
enum Lookup<D> {
    /// Held in memory.
    Resident(D),
    /// Held in a cached region.
    Cached(D),
    /// Must be rebuilt in `region`, at `slot`.
    Fill { region: u64, slot: usize },
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
    fn hash<D: Digest, H: Hasher<F, Digest = D> + Clone>(
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

/// Volatile operation-tree state. Only the working frontier is shared with batch snapshots.
pub(crate) struct Tree<F: Family, D: Digest, S: Strategy> {
    mem: Arc<Mem<F, D>>,
    metrics: Metrics,
    boundary: Location<F>,
    pins: BTreeMap<Position<F>, D>,
    resident: Resident<D>,
    regions: Regions<D>,
    strategy: S,
    replay_buffer: NonZeroUsize,
    /// Encoded bytes after which a replay batch ends.
    hash_batch_bytes: usize,
}

impl<F: Family, D: Digest, S: Strategy> Tree<F, D, S> {
    /// An empty tree pruned to `boundary`, whose digests [`Family::nodes_to_pin`] lists as `pins`.
    pub(crate) fn new(
        boundary: Location<F>,
        pins: Vec<D>,
        config: &Config<S>,
        metrics: Metrics,
    ) -> Result<Self, super::Error<F>> {
        let capacity = config
            .cache
            .capacity::<D>()
            .map_err(super::Error::InvalidConfig)?;
        let mem = Mem::from_components(Vec::new(), boundary, pins.clone())?;
        let _ = metrics
            .region_capacity
            .try_set(capacity.map_or(0, NonZeroUsize::get));
        let _ = metrics.cached_regions.try_set(0);
        let tree = Self {
            mem: Arc::new(mem),
            metrics,
            boundary,
            pins: F::nodes_to_pin(boundary).zip(pins).collect(),
            resident: Resident::new(config.cache.resident_height),
            regions: Regions::new(config.cache.resident_height, capacity),
            strategy: config.strategy.clone(),
            replay_buffer: config.replay_buffer,
            hash_batch_bytes: HASH_BATCH_BYTES,
        };
        tree.update_metrics();
        Ok(tree)
    }

    fn update_metrics(&self) {
        let (len, capacity) = self.resident.usage();
        let _ = self
            .metrics
            .resident_bytes
            .try_set(len.saturating_mul(size_of::<D>()));
        let _ = self
            .metrics
            .resident_capacity_bytes
            .try_set(capacity.saturating_mul(size_of::<D>()));
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
        C: ReplayEncoded,
        H: Hasher<F, Digest = D> + Clone + Send + Sync + 'static,
    {
        if !end.is_valid()
            || end < self.leaves()
            || *end > journal.bounds().end
            || *self.leaves() < journal.bounds().start
        {
            return Err(merkle::Error::RangeOutOfBounds(end).into());
        }
        let mut reader = journal
            .replay_encoded(*self.leaves()..*end, self.replay_buffer)
            .await?;
        let max_items = usize::try_from(batch_size.get()).unwrap_or(usize::MAX);
        let max_bytes = self.hash_batch_bytes;
        let mut loc = self.leaves();
        let mut next = Self::read_encoded(&mut reader, loc, max_items, max_bytes).await?;
        // Read each batch while the previous one hashes.
        while !next.leaves.is_empty() {
            loc += next.leaves.len() as u64;
            let encoded = std::mem::replace(&mut next, Encoded::new());
            (self, next) = futures::try_join!(
                self.apply_encoded(hasher, encoded),
                Self::read_encoded(&mut reader, loc, max_items, max_bytes),
            )?;
        }
        Ok(self)
    }

    /// Read the next replay batch, whose first item is at `loc`.
    async fn read_encoded(
        reader: &mut impl EncodedReader,
        loc: Location<F>,
        max_items: usize,
        max_bytes: usize,
    ) -> Result<Encoded<F>, super::Error<F>> {
        let mut encoded = Encoded::new();
        let mut ends = Vec::new();
        reader
            .read(&mut encoded.bytes, &mut ends, max_items, max_bytes)
            .await?;
        let mut start = 0;
        encoded.leaves = ends
            .into_iter()
            .zip(*loc..)
            .map(|(end, loc)| {
                let leaf = (F::location_to_position(Location::new(loc)), start..end);
                start = end;
                leaf
            })
            .collect();
        Ok(encoded)
    }

    async fn apply_encoded<H>(
        mut self,
        hasher: &H,
        encoded: Encoded<F>,
    ) -> Result<Self, super::Error<F>>
    where
        H: Hasher<F, Digest = D> + Clone + Send + Sync + 'static,
    {
        if encoded.leaves.is_empty() {
            return Ok(self);
        }
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

    /// Apply a batch of appends. Only its new resident nodes and peaks are kept: lower nodes can
    /// be rebuilt from operations, and batches keep their own nodes for speculative proofs.
    pub(crate) fn apply_batch(
        mut self,
        batch: &batch::MerkleizedBatch<F, D, S>,
    ) -> Result<Self, merkle::Error<F>> {
        let start = self.size();
        let runs = batch.unapplied(start)?;
        if runs.iter().any(|(_, overwrites)| !overwrites.is_empty()) {
            return Err(merkle::Error::DataCorrupted("batch overwrites nodes"));
        }
        let node = |pos: Position<F>| {
            let mut index = (*pos).checked_sub(*start)?;
            for (run, _) in &runs {
                if let Some(digest) = usize::try_from(index).ok().and_then(|i| run.get(i)) {
                    return Some(*digest);
                }
                index -= run.len() as u64;
            }
            None
        };
        let end = batch.size();
        self.resident.extend(start, end, node)?;

        // Older peaks are already pinned as part of the previous frontier.
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
        Ok(self)
    }

    /// Unpin peaks from sizes before the current one.
    pub(crate) fn flush(&mut self) {
        Arc::make_mut(&mut self.mem).compact(&self.pins);
        self.update_metrics();
    }

    /// Drop nodes before `boundary`, whose digests [`Family::nodes_to_pin`] lists as `pins`.
    pub(crate) fn prune(&mut self, boundary: Location<F>, pins: Vec<D>) {
        debug_assert_eq!(F::nodes_to_pin(boundary).count(), pins.len());
        self.boundary = boundary;
        self.pins = F::nodes_to_pin(boundary).zip(pins).collect();
        self.resident.trim(F::location_to_position(boundary));
        if let Some(len) = self.regions.retain_from(boundary) {
            let _ = self.metrics.cached_regions.try_set(len);
        }
        self.flush();
    }

    fn available(&self, pos: Position<F>) -> bool {
        pos < self.size()
            && (pos >= F::location_to_position(self.boundary) || self.pins.contains_key(&pos))
    }

    /// Find the available node at `pos` among resident and cached digests.
    fn lookup(
        &self,
        cache: Option<&RegionCache<D>>,
        pos: Position<F>,
    ) -> Result<Lookup<D>, merkle::Error<F>> {
        let h = F::pos_to_height(pos);
        if h >= self.resident.height {
            return self
                .resident
                .get(pos, h)
                .or_else(|| self.mem.get_node(pos))
                .map(Lookup::Resident)
                .ok_or(merkle::Error::MissingNode(pos));
        }
        if let Some(digest) = self.mem.get_node(pos) {
            return Ok(Lookup::Resident(digest));
        }
        let (region, slot) = self.regions.locate(pos, h);
        Ok(cache
            .and_then(|cache| cache.get(&region)?.get(slot))
            .map_or(Lookup::Fill { region, slot }, Lookup::Cached))
    }

    pub(crate) async fn get_nodes<C, H>(
        &self,
        journal: &C,
        hasher: &H,
        positions: &[Position<F>],
    ) -> Result<Vec<D>, merkle::Error<F>>
    where
        C: Contiguous<Item: EncodeShared>,
        H: Hasher<F, Digest = D> + Clone + Send + Sync + 'static,
    {
        assert!(
            positions.is_sorted_by(|a, b| a < b),
            "positions must be strictly increasing"
        );
        let mut result = vec![D::EMPTY; positions.len()];
        let mut fills = BTreeMap::<u64, Vec<(usize, usize)>>::new();
        let (mut resident_hits, mut region_hits) = (0, 0);
        {
            let cache = self.regions.cache.read();
            for (index, &pos) in positions.iter().enumerate() {
                if !self.available(pos) {
                    return Err(merkle::Error::ElementPruned(pos));
                }
                match self.lookup(cache.as_deref(), pos)? {
                    Lookup::Resident(digest) => {
                        result[index] = digest;
                        resident_hits += 1;
                    }
                    Lookup::Cached(digest) => {
                        result[index] = digest;
                        region_hits += 1;
                    }
                    Lookup::Fill { region, slot } => {
                        fills.entry(region).or_default().push((index, slot));
                    }
                }
            }
        }
        self.metrics.resident_hits.inc_by(resident_hits);
        self.metrics.region_hits.inc_by(region_hits);
        if fills.is_empty() {
            return Ok(result);
        }
        let fills = stream::iter(fills)
            .map(|(region, wanted)| async move {
                let slots: Vec<usize> = wanted.iter().map(|&(_, slot)| slot).collect();
                let filled = self.fill_region(journal, hasher, region, &slots).await?;
                Ok::<_, merkle::Error<F>>((filled, wanted))
            })
            .buffer_unordered(CONCURRENT_FILLS);
        futures::pin_mut!(fills);
        while let Some((filled, wanted)) = fills.try_next().await? {
            for (index, slot) in wanted {
                result[index] = filled.get(slot).ok_or(merkle::Error::DataCorrupted(
                    "incomplete regional reconstruction",
                ))?;
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
        H: Hasher<F, Digest = D> + Clone + Send + Sync + 'static,
    {
        let positions: Vec<_> = F::nodes_to_pin(location).collect();
        let mut sorted = positions.clone();
        sorted.sort_unstable();
        let nodes = self.get_nodes(journal, hasher, &sorted).await?;
        Ok(positions
            .iter()
            .map(|p| nodes[sorted.binary_search(p).expect("pin in request")])
            .collect())
    }

    pub(crate) async fn get_node<C, H>(
        &self,
        journal: &C,
        hasher: &H,
        pos: Position<F>,
    ) -> Result<Option<D>, merkle::Error<F>>
    where
        C: Contiguous<Item: EncodeShared>,
        H: Hasher<F, Digest = D> + Clone + Send + Sync + 'static,
    {
        if !self.available(pos) {
            return Ok(None);
        }
        let lookup = self.lookup(self.regions.cache.read().as_deref(), pos)?;
        let digest = match lookup {
            Lookup::Resident(digest) => {
                self.metrics.resident_hits.inc();
                digest
            }
            Lookup::Cached(digest) => {
                self.metrics.region_hits.inc();
                digest
            }
            Lookup::Fill { region, slot } => self
                .fill_region(journal, hasher, region, &[slot])
                .await?
                .get(slot)
                .ok_or(merkle::Error::DataCorrupted(
                    "incomplete regional reconstruction",
                ))?,
        };
        Ok(Some(digest))
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
        H: Hasher<F, Digest = D> + Clone + Send + Sync + 'static,
    {
        let _guard = self.regions.fill_lock(index).lock().await;
        let old = self.regions.get(index);
        if let Some(region) = &old
            && wanted.iter().all(|&slot| region.get(slot).is_some())
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
        for i in 0..width {
            let loc = Location::new(base + i);
            if loc >= self.leaves() {
                break;
            }
            let slot = i as usize;
            if region.get(slot).is_some() {
                continue;
            }
            let pos = F::location_to_position(loc);
            if let Some(digest) = self.mem.get_node(pos) {
                region.put(slot, digest);
            } else if pos >= boundary {
                reads.push((loc, pos, slot));
            }
        }
        if !reads.is_empty() {
            let locations: Vec<u64> = reads.iter().map(|&(loc, ..)| *loc).collect();
            let items = journal.read_many(&locations).await?;
            let mut encoded = Encoded::new();
            for (&(_, pos, _), item) in reads.iter().zip(&items) {
                encoded.push(pos, item);
            }
            self.metrics.reconstructed_leaves.inc_by(reads.len() as u64);
            self.metrics
                .reconstructed_bytes
                .inc_by(encoded.bytes.len() as u64);
            let hasher = hasher.clone();
            let digests = self
                .strategy
                .spawn(reads.len(), move |strategy| {
                    encoded.hash(&strategy, &hasher)
                })
                .await;
            for (&(.., slot), digest) in reads.iter().zip(digests) {
                region.put(slot, digest);
            }
        }

        // Hash parents bottom-up. A parent at or past the boundary has children that are either
        // also past it or pinned. A pinned parent with both children present checks them, which
        // covers regions whose root is unborn.
        let mut parents = 0;
        for h in 1..height {
            let (row, below) = (self.regions.row(h), self.regions.row(h - 1));
            for i in 0..width >> h {
                let slot = row + i as usize;
                if region.get(slot).is_some() {
                    continue;
                }
                let pos = F::subtree_root_position(Location::new(base + (i << h)), h);
                if pos >= size {
                    break;
                }
                let pinned = self.mem.get_node(pos);
                if pinned.is_none() && pos < boundary {
                    continue;
                }
                let left = region.get(below + 2 * i as usize);
                let right = region.get(below + 2 * i as usize + 1);
                let digest = match (left, right, pinned) {
                    (Some(left), Some(right), pinned) => {
                        let digest = hasher.node_digest(pos, &left, &right);
                        parents += 1;
                        if pinned.is_some_and(|pinned| pinned != digest) {
                            return Err(merkle::Error::RootMismatch);
                        }
                        digest
                    }
                    (_, _, Some(pinned)) => pinned,
                    _ => return Err(merkle::Error::MissingNode(pos)),
                };
                region.put(slot, digest);
            }
        }
        self.metrics.reconstructed_parents.inc_by(parents);

        // A resident region root proves the region is born, even for MMB.
        if let Some(root) = self.resident.region_root(index) {
            let pos = F::subtree_root_position(Location::new(base), height);
            let below = self.regions.row(height - 1);
            if let (Some(left), Some(right)) = (region.get(below), region.get(below + 1))
                && hasher.node_digest(pos, &left, &right) != root
            {
                return Err(merkle::Error::RootMismatch);
            }
        }
        let region = Arc::new(region);
        if let Some(len) = self.regions.insert(index, Arc::clone(&region)) {
            let _ = self.metrics.cached_regions.try_set(len);
        }
        Ok(region)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        journal::{Error as JournalError, authenticated::CacheConfig},
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
        reads: Vec<AtomicUsize>,
        /// A location whose stored operation differs from the one replayed, or `u64::MAX`.
        corrupt: AtomicU64,
    }

    impl Operations {
        fn new(end: u64) -> Self {
            Self {
                bounds: 0..end,
                reads: (0..end).map(|_| AtomicUsize::new(0)).collect(),
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
                "reconstructed an unavailable operation at {position}"
            );
            self.reads[position as usize].fetch_add(1, Ordering::Relaxed);
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
        async fn replay_range(
            &self,
            range: Range<u64>,
            _: NonZeroUsize,
            _: ReadOptions,
        ) -> Result<
            impl futures::Stream<Item = Result<(u64, u64), JournalError>> + Send,
            JournalError,
        > {
            assert!(range.start >= self.bounds.start && range.end <= self.bounds.end);
            Ok(
                stream::iter(range)
                    .then(move |loc| async move { Ok((loc, self.read(loc).await?)) }),
            )
        }
    }

    struct OperationsReader<'a> {
        ops: &'a Operations,
        range: Range<u64>,
    }

    impl EncodedReader for OperationsReader<'_> {
        async fn read(
            &mut self,
            bytes: &mut Vec<u8>,
            ends: &mut Vec<usize>,
            max_items: usize,
            max_bytes: usize,
        ) -> Result<usize, JournalError> {
            let mut read = 0;
            while read < max_items && bytes.len() < max_bytes {
                let Some(loc) = self.range.next() else {
                    break;
                };
                bytes.extend_from_slice(&self.ops.read(loc).await?.encode());
                ends.push(bytes.len());
                read += 1;
            }
            Ok(read)
        }
    }

    impl ReplayEncoded for Operations {
        async fn replay_encoded(
            &self,
            range: Range<u64>,
            _: NonZeroUsize,
        ) -> Result<impl EncodedReader, JournalError> {
            assert!(range.start >= self.bounds.start && range.end <= self.bounds.end);
            Ok(OperationsReader { ops: self, range })
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

    fn config(
        resident_height: u32,
        region_cache_bytes: usize,
        replay_buffer: usize,
    ) -> Config<Sequential> {
        Config {
            metadata_partition: String::new(),
            cache: CacheConfig {
                resident_height,
                region_cache_bytes,
            },
            replay_buffer: NonZeroUsize::new(replay_buffer).unwrap(),
            strategy: Sequential,
        }
    }

    /// Every available node matches an in-memory oracle at each resident height and cache budget,
    /// as the boundary advances over one tree.
    async fn reconstruction<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(Bagging::ForwardFold);
        let mut ops = Operations::new(513);
        let expected = oracle::<F>(&ops, &hasher);
        for height in 0..=8 {
            for budget in [0, 8 * 1024 * 1024] {
                ops.bounds.start = 0;
                let mut tree = Tree::<F, D, _>::new(
                    Location::new(0),
                    Vec::new(),
                    &config(height, budget, 73),
                    Metrics::new(&context),
                )
                .unwrap();
                tree.hash_batch_bytes = 73;
                let mut tree = tree
                    .replay(&ops, &hasher, Location::new(513), NZU64!(17))
                    .await
                    .unwrap();
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
                            "operation {loc} reconstructed twice in one request"
                        );
                    }
                    if budget > 0 || height == 0 {
                        ops.clear_reads();
                        tree.get_nodes(&ops, &hasher, &positions).await.unwrap();
                        assert_eq!(
                            ops.reads(),
                            0,
                            "warm reconstruction must not read operations"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn reconstructs_mmr() {
        deterministic::Runner::default().start(reconstruction::<mmr::Family>);
    }
    #[test]
    fn reconstructs_mmb() {
        deterministic::Runner::default().start(reconstruction::<mmb::Family>);
    }

    async fn demand_cache<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(Bagging::BackwardFold);
        let ops = Operations::new(128);
        let mut tree = Tree::<F, D, _>::new(
            Location::new(0),
            Vec::new(),
            &config(5, 2048, 31),
            Metrics::new(&context),
        )
        .unwrap();
        tree.hash_batch_bytes = 31;
        let mut tree = tree
            .replay(&ops, &hasher, Location::new(128), NZU64!(7))
            .await
            .unwrap();
        ops.clear_reads();
        let region = 1 << 5;
        let pos = F::location_to_position(Location::new(0));
        let first = tree.get_node(&ops, &hasher, pos).await.unwrap().unwrap();
        assert_eq!(ops.reads(), region, "a cold fill reads its whole region");
        assert_eq!(
            tree.get_node(&ops, &hasher, pos).await.unwrap(),
            Some(first)
        );
        assert_eq!(ops.reads(), region);
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
            "concurrent requests must share their regional fill"
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
    fn demand_cache_mmr() {
        deterministic::Runner::default().start(demand_cache::<mmr::Family>);
    }
    #[test]
    fn demand_cache_mmb() {
        deterministic::Runner::default().start(demand_cache::<mmb::Family>);
    }

    /// A region cached while partial keeps its leaves when later appends complete it, including
    /// across a prune that empties a resident level.
    async fn completed_region<F: Family>(context: deterministic::Context) {
        let hasher = Standard::<Sha256>::new(Bagging::ForwardFold);
        let mut ops = Operations::new(128);
        let expected = oracle::<F>(&ops, &hasher);
        let tree = Tree::<F, D, _>::new(
            Location::new(0),
            Vec::new(),
            &config(5, 8 * 1024 * 1024, 31),
            Metrics::new(&context),
        )
        .unwrap();
        let mut tree = tree
            .replay(&ops, &hasher, Location::new(40), NZU64!(7))
            .await
            .unwrap();
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
            let tree = Tree::<F, D, _>::new(
                Location::new(0),
                Vec::new(),
                &config(5, 0, 31),
                Metrics::new(&context),
            )
            .unwrap()
            .replay(&ops, &hasher, Location::new(leaves), NZU64!(7))
            .await
            .unwrap();
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

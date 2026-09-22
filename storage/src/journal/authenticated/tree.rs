use super::{CacheConfig, metrics::Metrics};
use crate::{
    journal::contiguous::Contiguous,
    merkle::{self, Family, Location, Position, Readable, batch, hasher::Hasher, mem::Mem},
};
use commonware_codec::{Encode, EncodeShared};
use commonware_cryptography::Digest;
use commonware_parallel::Strategy;
use commonware_runtime::{ReadOptions, telemetry::metrics::GaugeExt as _};
use commonware_utils::{
    bitmap::BitMap,
    cache::Cache,
    sync::{AsyncMutex, RwLock},
};
use futures::{StreamExt as _, TryStreamExt as _, stream};
use std::{
    collections::{BTreeMap, VecDeque},
    num::NonZeroUsize,
    sync::Arc,
};

// Actual nodes at each height arrive in aligned subtree order, including delayed MMB parents.
#[derive(Default)]
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

    fn put<F: Family>(&mut self, slot: usize, digest: D) -> Result<(), merkle::Error<F>> {
        if self.get(slot).is_some_and(|old| old != digest) {
            return Err(merkle::Error::DataCorrupted("conflicting cached digest"));
        }
        self.digests[slot] = digest;
        self.valid.set(slot as u64, true);
        Ok(())
    }
}

type LowerCache<D> = RwLock<Option<Box<Cache<u64, Arc<Region<D>>>>>>;

/// Volatile operation-tree state. Only the working frontier is shared with batch snapshots.
pub(crate) struct Tree<F: Family, D: Digest, S: Strategy> {
    mem: Arc<Mem<F, D>>,
    metrics: Arc<Metrics>,
    boundary: Location<F>,
    pins: BTreeMap<Position<F>, D>,
    levels: Vec<Level<D>>,
    lower: LowerCache<D>,
    fills: Box<[AsyncMutex<()>; 64]>,
    height: u32,
    slots: usize,
    pub(crate) strategy: S,
    pub(crate) replay_buffer: NonZeroUsize,
}

impl<F: Family, D: Digest, S: Strategy> Tree<F, D, S> {
    pub(crate) fn new(
        boundary: Location<F>,
        pins: Vec<D>,
        config: &CacheConfig,
        replay_buffer: NonZeroUsize,
        strategy: S,
    ) -> Result<Self, super::Error<F>> {
        let capacity = config
            .capacity::<D>()
            .map_err(super::Error::InvalidConfig)?;
        let slots = (2usize << config.resident_height) - 2;
        let mem = Mem::from_components(Vec::new(), boundary, pins.clone())?;
        Ok(Self {
            mem: Arc::new(mem),
            metrics: Arc::new(Metrics::default()),
            boundary,
            pins: F::nodes_to_pin(boundary).zip(pins).collect(),
            levels: (0..64)
                .map(|_| Level {
                    first: 0,
                    nodes: VecDeque::new(),
                })
                .collect(),
            lower: RwLock::new(capacity.map(|capacity| Box::new(Cache::new(capacity)))),
            fills: Box::new(std::array::from_fn(|_| AsyncMutex::new(()))),
            height: config.resident_height,
            slots,
            strategy,
            replay_buffer,
        })
    }

    pub(super) fn with_metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = Arc::new(metrics);
        let capacity = self
            .lower
            .read()
            .as_ref()
            .map_or(0, |cache| cache.capacity());
        let _ = self.metrics.cache_capacity.try_set(capacity);
        self.update_metrics();
        self
    }

    fn update_metrics(&self) {
        let count: usize = self.levels.iter().map(|level| level.nodes.len()).sum();
        let capacity: usize = self.levels.iter().map(|level| level.nodes.capacity()).sum();
        let _ = self
            .metrics
            .upper_payload_bytes
            .try_set(count.saturating_mul(size_of::<D>()));
        let _ = self
            .metrics
            .upper_capacity_bytes
            .try_set(capacity.saturating_mul(size_of::<D>()));
        let _ = self
            .metrics
            .cached_regions
            .try_set(self.lower.read().as_ref().map_or(0, |cache| cache.len()));
    }

    pub(crate) async fn replay<C, H>(
        mut self,
        journal: &C,
        hasher: &H,
        end: Location<F>,
        batch_size: u64,
    ) -> Result<Self, super::Error<F>>
    where
        C: Contiguous<Item: EncodeShared>,
        H: Hasher<F, Digest = D> + Clone + Send + Sync + 'static,
    {
        if batch_size == 0 {
            return Err(super::Error::InvalidConfig("zero replay batch size"));
        }
        if !end.is_valid()
            || end < self.leaves()
            || *end > journal.bounds().end
            || *self.leaves() < journal.bounds().start
        {
            return Err(merkle::Error::RangeOutOfBounds(end).into());
        }
        let replay = journal
            .replay_range(
                *self.leaves()..*end,
                self.replay_buffer,
                ReadOptions::default(),
            )
            .await?;
        futures::pin_mut!(replay);
        let mut items = Vec::new();
        let mut bytes = 0usize;
        while let Some((loc, item)) = replay.try_next().await? {
            let item = item.encode();
            if !items.is_empty()
                && (items.len() as u64 >= batch_size
                    || item.len() > self.replay_buffer.get().saturating_sub(bytes))
            {
                self = self
                    .apply_encoded(hasher, std::mem::take(&mut items))
                    .await?;
                bytes = 0;
            }
            bytes += item.len();
            items.push((F::location_to_position(Location::new(loc)), item));
        }
        self.apply_encoded(hasher, items).await
    }

    async fn apply_encoded<H>(
        mut self,
        hasher: &H,
        items: Vec<(Position<F>, bytes::Bytes)>,
    ) -> Result<Self, super::Error<F>>
    where
        H: Hasher<F, Digest = D> + Clone + Send + Sync + 'static,
    {
        if items.is_empty() {
            return Ok(self);
        }
        self.metrics.replayed_leaves.inc_by(items.len() as u64);
        let mem = self.snapshot();
        let hasher = hasher.clone();
        let batch = self.new_batch();
        let batch = self
            .strategy
            .spawn(items.len(), move |strategy| {
                let digests = strategy.map_init_collect_vec(
                    items,
                    || hasher.clone(),
                    |h, (pos, bytes)| h.leaf_digest(pos, &bytes),
                );
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
    pub(crate) fn bounds(&self) -> std::ops::Range<Location<F>> {
        self.boundary..self.leaves()
    }
    pub(crate) const fn strategy(&self) -> &S {
        &self.strategy
    }
    pub(crate) fn snapshot(&self) -> Arc<Mem<F, D>> {
        Arc::clone(&self.mem)
    }
    pub(crate) fn with_mem<R>(&self, f: impl FnOnce(&Mem<F, D>) -> R) -> R {
        f(&self.mem)
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

    pub(crate) fn apply_batch(
        mut self,
        batch: &batch::MerkleizedBatch<F, D, S>,
    ) -> Result<Self, merkle::Error<F>> {
        let start = self.leaves();
        Arc::make_mut(&mut self.mem).apply_batch(batch)?;
        let mut pos = F::location_to_position(start);
        for leaf in *start..*self.leaves() {
            for height in std::iter::once(0).chain(F::parent_heights(Location::new(leaf))) {
                if height >= self.height {
                    let ordinal = *F::leftmost_leaf(pos, height) >> height;
                    let level = &mut self.levels[height as usize];
                    if level.nodes.is_empty() {
                        level.first = ordinal;
                    }
                    if ordinal != level.first + level.nodes.len() as u64 {
                        return Err(merkle::Error::DataCorrupted("noncontiguous upper level"));
                    }
                    level.nodes.push_back(
                        self.mem
                            .get_node(pos)
                            .ok_or(merkle::Error::MissingNode(pos))?,
                    );
                }
                pos += 1;
            }
        }
        self.update_metrics();
        Ok(self)
    }

    pub(crate) fn flush(&mut self) {
        let leaves = self.leaves();
        let pins = F::nodes_to_pin(leaves)
            .map(|p| self.mem.get_node(p).expect("working frontier present"))
            .collect();
        let mut mem =
            Mem::from_components(Vec::new(), leaves, pins).expect("valid working frontier");
        mem.add_pinned_nodes(self.pins.clone());
        self.mem = Arc::new(mem);
    }

    pub(crate) fn prune(&mut self, boundary: Location<F>, pins: Vec<D>) {
        self.boundary = boundary;
        self.pins = F::nodes_to_pin(boundary).zip(pins).collect();
        self.trim_levels();
        if let Some(cache) = self.lower.get_mut() {
            cache.retain(|region, _| (*region << self.height) >= *boundary);
        }
        self.flush();
        self.update_metrics();
    }

    pub(crate) fn rewind(
        &mut self,
        size: Location<F>,
        pins: Vec<D>,
    ) -> Result<(), merkle::Error<F>> {
        self.mem = Arc::new(Mem::from_components(Vec::new(), size, pins)?);
        Arc::make_mut(&mut self.mem).add_pinned_nodes(self.pins.clone());
        self.trim_levels();
        if let Some(cache) = self.lower.get_mut() {
            cache.clear();
        }
        self.update_metrics();
        Ok(())
    }

    fn trim_levels(&mut self) {
        let lower = F::location_to_position(self.boundary);
        let upper = self.size();
        for (height, level) in self.levels.iter_mut().enumerate() {
            while !level.nodes.is_empty() {
                let pos =
                    F::subtree_root_position(Location::new(level.first << height), height as u32);
                if pos >= lower {
                    break;
                }
                level.nodes.pop_front();
                level.first += 1;
            }
            while !level.nodes.is_empty() {
                let ordinal = level.first + level.nodes.len() as u64 - 1;
                let pos = F::subtree_root_position(Location::new(ordinal << height), height as u32);
                if pos < upper {
                    break;
                }
                level.nodes.pop_back();
            }
            if level.nodes.len() <= level.nodes.capacity() / 4 {
                level.nodes.shrink_to_fit();
            }
        }
    }

    fn available(&self, pos: Position<F>) -> bool {
        pos < self.size()
            && (pos >= F::location_to_position(self.boundary) || self.pins.contains_key(&pos))
    }

    fn resident(&self, pos: Position<F>) -> Option<D> {
        if !self.available(pos) {
            return None;
        }
        self.mem.get_node(pos).or_else(|| {
            let h = F::pos_to_height(pos);
            (h >= self.height)
                .then(|| self.levels[h as usize].get(*F::leftmost_leaf(pos, h) >> h))
                .flatten()
        })
    }

    // Height-major layout within a region: leaves, height-one nodes, then higher nodes.
    fn slot(&self, pos: Position<F>) -> usize {
        let h = F::pos_to_height(pos);
        let width = 1u64 << self.height;
        let local = *F::leftmost_leaf(pos, h) & (width - 1);
        ((2 * width) - ((2 * width) >> h) + (local >> h)) as usize
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
        let mut regions = BTreeMap::<u64, Vec<(usize, Position<F>)>>::new();
        {
            let cache = self.lower.read();
            for (index, &pos) in positions.iter().enumerate() {
                if !self.available(pos) {
                    return Err(merkle::Error::ElementPruned(pos));
                }
                if let Some(digest) = self.resident(pos) {
                    result[index] = digest;
                    self.metrics.resident_hits.inc();
                    continue;
                }
                let h = F::pos_to_height(pos);
                if h >= self.height {
                    return Err(merkle::Error::MissingNode(pos));
                }
                let region = *F::leftmost_leaf(pos, h) >> self.height;
                if let Some(digest) = cache
                    .as_ref()
                    .and_then(|cache| cache.get(&region))
                    .and_then(|entry| entry.get(self.slot(pos)))
                {
                    result[index] = digest;
                    self.metrics.lower_hits.inc();
                } else {
                    regions.entry(region).or_default().push((index, pos));
                }
            }
        }
        if regions.is_empty() {
            return Ok(result);
        }
        let fills =
            stream::iter(regions)
                .map(|(region, nodes)| async move {
                    self.fill_region(journal, hasher, region, nodes).await
                })
                .buffer_unordered(8);
        futures::pin_mut!(fills);
        while let Some(nodes) = fills.try_next().await? {
            for (index, digest) in nodes {
                result[index] = digest;
            }
        }
        Ok(result)
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
        if let Some(digest) = self.resident(pos) {
            self.metrics.resident_hits.inc();
            return Ok(Some(digest));
        }
        let h = F::pos_to_height(pos);
        if h >= self.height {
            return Err(merkle::Error::MissingNode(pos));
        }
        let region = *F::leftmost_leaf(pos, h) >> self.height;
        if let Some(digest) = self
            .lower
            .read()
            .as_ref()
            .and_then(|cache| cache.get(&region))
            .and_then(|entry| entry.get(self.slot(pos)))
        {
            self.metrics.lower_hits.inc();
            return Ok(Some(digest));
        }
        Ok(self
            .fill_region(journal, hasher, region, vec![(0, pos)])
            .await?
            .pop()
            .map(|(_, digest)| digest))
    }

    fn cached(&self, region: u64) -> Option<Arc<Region<D>>> {
        self.lower.read().as_ref()?.get(&region).cloned()
    }

    async fn fill_region<C, H>(
        &self,
        journal: &C,
        hasher: &H,
        region: u64,
        nodes: Vec<(usize, Position<F>)>,
    ) -> Result<Vec<(usize, D)>, merkle::Error<F>>
    where
        C: Contiguous<Item: EncodeShared>,
        H: Hasher<F, Digest = D> + Clone + Send + Sync + 'static,
    {
        let read_hits = |entry: &Region<D>| {
            nodes
                .iter()
                .map(|&(i, p)| entry.get(self.slot(p)).map(|d| (i, d)))
                .collect::<Option<Vec<_>>>()
        };
        if let Some(entry) = self.cached(region)
            && let Some(hits) = read_hits(&entry)
        {
            self.metrics.lower_hits.inc_by(hits.len() as u64);
            return Ok(hits);
        }
        let _guard = self.fills[region as usize % self.fills.len()].lock().await;
        let old = self.cached(region);
        if let Some(entry) = &old
            && let Some(hits) = read_hits(entry)
        {
            self.metrics.lower_hits.inc_by(hits.len() as u64);
            return Ok(hits);
        }
        self.metrics.region_fills.inc();
        let mut entry = old
            .as_deref()
            .cloned()
            .unwrap_or_else(|| Region::new(self.slots));
        let mut seen: BitMap = BitMap::zeroes(self.slots as u64);
        let mut parents = Vec::new();
        let mut leaves = Vec::new();
        for &(_, root) in &nodes {
            let mut stack = vec![(root, false)];
            while let Some((pos, expanded)) = stack.pop() {
                let slot = self.slot(pos);
                if expanded {
                    parents.push(pos);
                    continue;
                }
                if seen.get(slot as u64) {
                    continue;
                }
                seen.set(slot as u64, true);
                if !self.available(pos) {
                    return Err(merkle::Error::ElementPruned(pos));
                }
                if let Some(d) = self.resident(pos) {
                    entry.put::<F>(slot, d)?;
                }
                if entry.get(slot).is_some() {
                    continue;
                }
                let h = F::pos_to_height(pos);
                if h == 0 {
                    leaves.push((F::leftmost_leaf(pos, 0), pos));
                } else {
                    let (left, right) = F::children(pos, h);
                    stack.extend([(pos, true), (right, false), (left, false)]);
                }
            }
        }
        leaves.sort_unstable_by_key(|&(loc, _)| loc);
        let mut offset = 0;
        while offset < leaves.len() {
            let start = offset;
            offset += 1;
            while offset < leaves.len() && leaves[offset].0 == leaves[offset - 1].0 + 1 {
                offset += 1;
            }
            let range = *leaves[start].0..*leaves[offset - 1].0 + 1;
            let replay = journal
                .replay_range(range, self.replay_buffer, ReadOptions::default())
                .await?;
            futures::pin_mut!(replay);
            let mut encoded = Vec::new();
            let mut bytes = 0;
            while let Some((loc, item)) = replay.try_next().await? {
                let item = item.encode();
                if !encoded.is_empty()
                    && item.len() > self.replay_buffer.get().saturating_sub(bytes)
                {
                    self.hash_leaves(hasher, &mut entry, std::mem::take(&mut encoded))
                        .await?;
                    bytes = 0;
                }
                bytes += item.len();
                encoded.push((F::location_to_position(Location::new(loc)), item));
            }
            self.hash_leaves(hasher, &mut entry, encoded).await?;
        }
        self.metrics
            .reconstructed_parents
            .inc_by(parents.len() as u64);
        for pos in parents {
            let (left, right) = F::children(pos, F::pos_to_height(pos));
            let left = entry
                .get(self.slot(left))
                .ok_or(merkle::Error::MissingNode(left))?;
            let right = entry
                .get(self.slot(right))
                .ok_or(merkle::Error::MissingNode(right))?;
            entry.put::<F>(self.slot(pos), hasher.node_digest(pos, &left, &right))?;
        }
        // A root's presence in the upper index proves it has actually been born, even for MMB.
        if let Some(root) = self.levels[self.height as usize].get(region) {
            let pos = F::subtree_root_position(Location::new(region << self.height), self.height);
            let (left, right) = F::children(pos, self.height);
            if let (Some(left), Some(right)) =
                (entry.get(self.slot(left)), entry.get(self.slot(right)))
                && hasher.node_digest(pos, &left, &right) != root
            {
                return Err(merkle::Error::RootMismatch);
            }
        }
        let result = read_hits(&entry).ok_or(merkle::Error::DataCorrupted(
            "incomplete regional reconstruction",
        ))?;
        if let Some(cache) = self.lower.write().as_mut() {
            cache.put(region, Arc::new(entry));
            let _ = self.metrics.cached_regions.try_set(cache.len());
        }
        Ok(result)
    }

    async fn hash_leaves<H: Hasher<F, Digest = D> + Clone + Send + Sync + 'static>(
        &self,
        hasher: &H,
        entry: &mut Region<D>,
        items: Vec<(Position<F>, bytes::Bytes)>,
    ) -> Result<(), merkle::Error<F>> {
        if items.is_empty() {
            return Ok(());
        }
        self.metrics.reconstructed_leaves.inc_by(items.len() as u64);
        self.metrics
            .reconstructed_bytes
            .inc_by(items.iter().map(|(_, bytes)| bytes.len() as u64).sum());
        let hasher = hasher.clone();
        let digests = self
            .strategy
            .spawn(items.len(), move |strategy| {
                strategy.map_init_collect_vec(
                    items,
                    || hasher.clone(),
                    |h, (pos, bytes)| (pos, h.leaf_digest(pos, &bytes)),
                )
            })
            .await;
        for (pos, digest) in digests {
            entry.put::<F>(self.slot(pos), digest)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        journal::Error as JournalError,
        merkle::{Bagging, hasher::Standard, mmb, mmr},
    };
    use commonware_cryptography::{Sha256, sha256::Digest as D};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::NZUsize;
    use std::{
        ops::Range,
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct Operations {
        bounds: Range<u64>,
        reads: Vec<AtomicUsize>,
        salt: u64,
        salt_start: u64,
    }

    impl Operations {
        fn new(end: u64) -> Self {
            Self {
                bounds: 0..end,
                reads: (0..end).map(|_| AtomicUsize::new(0)).collect(),
                salt: 0,
                salt_start: 0,
            }
        }
        fn item(&self, position: u64) -> u64 {
            position
                + if position >= self.salt_start {
                    self.salt
                } else {
                    0
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

    fn oracle<F: Family>(ops: &Operations, hasher: &Standard<Sha256>) -> Mem<F, D> {
        let mut mem = Mem::new();
        let mut batch = mem.new_batch();
        for loc in 0..ops.bounds.end {
            batch = batch.add(hasher, &ops.item(loc).encode());
        }
        mem.apply_batch(&batch.merkleize(&mem, hasher)).unwrap();
        mem
    }

    async fn reconstruction<F: Family>() {
        let hasher = Standard::<Sha256>::new(Bagging::ForwardFold);
        let mut ops = Operations::new(513);
        let expected = oracle::<F>(&ops, &hasher);
        for height in 0..=8 {
            for budget in [0, 8 * 1024 * 1024] {
                for boundary in [0, 1, 7, 31, 32, 33, 46, 47, 48, 255, 256, 257] {
                    ops.bounds.start = 0;
                    let config = CacheConfig {
                        resident_height: height,
                        lower_cache_bytes: budget,
                    };
                    let mut tree = Tree::<F, D, _>::new(
                        Location::new(0),
                        Vec::new(),
                        &config,
                        NZUsize!(73),
                        Sequential,
                    )
                    .unwrap()
                    .replay(&ops, &hasher, Location::new(513), 17)
                    .await
                    .unwrap();
                    assert_eq!(
                        tree.root(&hasher, 0).unwrap(),
                        expected.root(&hasher, 0).unwrap()
                    );
                    assert!(
                        tree.cached(0).is_none(),
                        "startup must not warm lower regions"
                    );
                    let boundary = Location::new(boundary);
                    let pins = F::nodes_to_pin(boundary)
                        .map(|p| expected.get_node(p).unwrap())
                        .collect();
                    tree.prune(boundary, pins);
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
        deterministic::Runner::default().start(|_| reconstruction::<mmr::Family>());
    }
    #[test]
    fn reconstructs_mmb() {
        deterministic::Runner::default().start(|_| reconstruction::<mmb::Family>());
    }

    async fn demand_and_rewind<F: Family>() {
        let hasher = Standard::<Sha256>::new(Bagging::BackwardFold);
        let mut ops = Operations::new(128);
        let config = CacheConfig {
            resident_height: 5,
            lower_cache_bytes: 2048,
        };
        let mut tree = Tree::<F, D, _>::new(
            Location::new(0),
            Vec::new(),
            &config,
            NZUsize!(31),
            Sequential,
        )
        .unwrap()
        .replay(&ops, &hasher, Location::new(128), 7)
        .await
        .unwrap();
        ops.clear_reads();
        let pos = F::location_to_position(Location::new(0));
        let first = tree.get_node(&ops, &hasher, pos).await.unwrap().unwrap();
        assert_eq!(ops.reads(), 1, "cold leaf overfetches its region");
        assert_eq!(
            tree.get_node(&ops, &hasher, pos).await.unwrap(),
            Some(first)
        );
        assert_eq!(ops.reads(), 1);
        let upper = (0..*tree.size())
            .map(Position::new)
            .find(|&p| F::pos_to_height(p) >= 5)
            .unwrap();
        tree.get_node(&ops, &hasher, upper).await.unwrap();
        assert_eq!(ops.reads(), 1, "upper nodes must remain resident");

        // Multiple fills can evict earlier regions, but each request still computes each leaf once.
        ops.clear_reads();
        let positions: Vec<_> = (0..*tree.size()).map(Position::new).collect();
        tree.get_nodes(&ops, &hasher, &positions).await.unwrap();
        assert!(ops.reads.iter().all(|r| r.load(Ordering::Relaxed) <= 1));
        if let Some(cache) = tree.lower.get_mut() {
            cache.clear();
        }
        ops.clear_reads();
        let reads = (0..32).map(|_| tree.get_node(&ops, &hasher, pos));
        for result in futures::future::join_all(reads).await {
            assert_eq!(result.unwrap(), Some(first));
        }
        assert_eq!(
            ops.reads(),
            1,
            "concurrent requests must share their regional fill"
        );
        let boundary = Location::new(47);
        let expected = oracle::<F>(&ops, &hasher);
        let pins = F::nodes_to_pin(boundary)
            .map(|p| expected.get_node(p).unwrap())
            .collect();
        tree.rewind(boundary, pins).unwrap();
        ops.salt = 500;
        ops.salt_start = 47;
        tree = tree
            .replay(&ops, &hasher, Location::new(128), 11)
            .await
            .unwrap();
        let expected = oracle::<F>(&ops, &hasher);
        let positions: Vec<_> = (0..*tree.size()).map(Position::new).collect();
        for (pos, node) in positions
            .iter()
            .zip(tree.get_nodes(&ops, &hasher, &positions).await.unwrap())
        {
            assert_eq!(expected.get_node(*pos), Some(node));
        }
        tree.rewind(Location::new(0), Vec::new()).unwrap();
        assert!(tree.cached(0).is_none());
        ops.salt = 1_000;
        ops.salt_start = 0;
        tree = tree
            .replay(&ops, &hasher, Location::new(128), 11)
            .await
            .unwrap();
        assert_ne!(
            tree.get_node(&ops, &hasher, pos).await.unwrap(),
            Some(first)
        );
        assert_eq!(
            tree.root(&hasher, 0).unwrap(),
            oracle::<F>(&ops, &hasher).root(&hasher, 0).unwrap()
        );
    }

    #[test]
    fn demand_cache_and_rewind_mmr() {
        deterministic::Runner::default().start(|_| demand_and_rewind::<mmr::Family>());
    }
    #[test]
    fn demand_cache_and_rewind_mmb() {
        deterministic::Runner::default().start(|_| demand_and_rewind::<mmb::Family>());
    }
}

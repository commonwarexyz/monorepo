//! Bounded reuse of authenticated producer paths.

use crate::{
    multimmit::types::{BlockRef, SelectedCommitments},
    types::{Epoch, Height},
};
use commonware_cryptography::Digest;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

/// The endpoints that identify one retained path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PathKey<D: Digest> {
    /// Oldest reference of the path.
    first: BlockRef<D>,
    /// Newest reference of the path.
    last: BlockRef<D>,
}

/// Caches authenticated producer-chain paths so ancestry walks can skip per-header fetches.
///
/// A fixed reference budget covers complete path allocations and bounds the lookup index. Each
/// indexed block belongs to its newest retained path; FIFO eviction preserves newer owners.
pub(crate) struct PathCache<D: Digest> {
    epoch: Epoch,
    capacity: usize,
    retained: usize,
    chains: usize,
    paths: BTreeMap<PathKey<D>, Arc<[BlockRef<D>]>>,
    by_block: BTreeMap<BlockRef<D>, PathKey<D>>,
    order: VecDeque<PathKey<D>>,
}

impl<D: Digest> PathCache<D> {
    pub(crate) const fn new(epoch: Epoch, chains: usize, capacity: usize) -> Self {
        Self {
            epoch,
            capacity,
            retained: 0,
            chains,
            paths: BTreeMap::new(),
            by_block: BTreeMap::new(),
            order: VecDeque::new(),
        }
    }

    pub(crate) fn insert(&mut self, commitments: &SelectedCommitments<D>) {
        if commitments.epoch() != self.epoch {
            return;
        }
        for path in commitments.paths() {
            if path.len() < 2 || path.len() > self.capacity {
                continue;
            }
            let key = PathKey {
                first: path[0],
                last: path[path.len() - 1],
            };
            let in_epoch =
                usize::try_from(key.first.chain().get()).is_ok_and(|chain| chain < self.chains);
            if !in_epoch || self.paths.contains_key(&key) {
                continue;
            }
            while self.retained > self.capacity - path.len() {
                let oldest = self
                    .order
                    .pop_front()
                    .expect("retained paths own FIFO entries");
                let removed = self
                    .paths
                    .remove(&oldest)
                    .expect("FIFO entries own retained paths");
                for reference in &removed[1..] {
                    if self.by_block.get(reference) == Some(&oldest) {
                        self.by_block.remove(reference);
                    }
                }
                self.retained -= removed.len();
            }
            self.retained += path.len();
            for reference in &path[1..] {
                self.by_block.insert(*reference, key);
            }
            self.paths.insert(key, Arc::clone(path));
            self.order.push_back(key);
        }
    }

    fn suffix(&self, tip: BlockRef<D>) -> Option<&Arc<[BlockRef<D>]>> {
        self.paths.get(self.by_block.get(&tip)?)
    }

    pub(crate) fn parent(&self, tip: BlockRef<D>) -> Option<BlockRef<D>> {
        at(self.suffix(tip)?, tip.height().previous()?)
    }

    /// Joins authenticated ranges by exact references, without walking their individual edges.
    pub(crate) fn resolve(&self, low: BlockRef<D>, high: BlockRef<D>) -> Option<Branch<D>> {
        if low.chain() != high.chain() || low.height() >= high.height() {
            return None;
        }
        let mut tip = high;
        let mut ranges = Vec::new();
        while tip.height() > low.height() {
            let path = self.suffix(tip)?;
            let start = path[0].height().max(low.height());
            let ancestor = at(path, start)?;
            if start == low.height() && ancestor != low {
                return None;
            }
            ranges.push(Range {
                path: Arc::clone(path),
                low: start,
                high: tip.height(),
            });
            tip = ancestor;
        }
        ranges.reverse();
        Some(Branch { ranges })
    }
}

struct Range<D: Digest> {
    path: Arc<[BlockRef<D>]>,
    low: Height,
    high: Height,
}

/// A branch pinned for one output plan, independent of cache eviction.
pub(crate) struct Branch<D: Digest> {
    ranges: Vec<Range<D>>,
}

impl<D: Digest> Branch<D> {
    pub(crate) fn get(&self, height: Height) -> Option<BlockRef<D>> {
        let index = self.ranges.partition_point(|range| range.high < height);
        let range = self.ranges.get(index)?;
        (height >= range.low)
            .then(|| at(&range.path, height))
            .flatten()
    }
}

fn at<D: Digest>(path: &[BlockRef<D>], height: Height) -> Option<BlockRef<D>> {
    let offset = height.get().checked_sub(path.first()?.height().get())?;
    path.get(usize::try_from(offset).ok()?).copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::types::{ChainId, TransactionBlockHeader};
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest as D};

    fn path(
        chain: u32,
        parent: Option<BlockRef<D>>,
        length: usize,
        salt: u8,
    ) -> Arc<[BlockRef<D>]> {
        let mut path = vec![parent.unwrap_or_else(|| {
            BlockRef::new(
                ChainId::new(chain),
                Height::zero(),
                Sha256::hash(&[&[chain as u8]]),
            )
        })];
        for _ in 0..length {
            let previous = *path.last().unwrap();
            path.push(
                TransactionBlockHeader::new(
                    Epoch::new(1),
                    previous.chain(),
                    Height::new(previous.height().get() + 1),
                    previous.digest(),
                    Sha256::hash(&[&[salt]]),
                )
                .unwrap()
                .block_ref::<Sha256>(),
            );
        }
        path.into()
    }

    #[test]
    fn exact_endpoints_join_overlapping_ranges_without_copying() {
        let first = path(0, None, 5, 0);
        let next = path(0, Some(first[3]), 6, 1);
        let mut cache = PathCache::new(Epoch::new(1), 2, 32);
        cache.insert(&SelectedCommitments::new(
            Epoch::new(1),
            vec![first.clone(), next.clone()],
        ));
        let selected = cache.resolve(first[1], next[5]).unwrap();
        let expected = first[1..=3]
            .iter()
            .chain(&next[1..=5])
            .copied()
            .collect::<Vec<_>>();
        for reference in expected {
            assert_eq!(selected.get(reference.height()), Some(reference));
        }
        assert!(Arc::ptr_eq(&selected.ranges[0].path, &first));
        assert!(Arc::ptr_eq(&selected.ranges[1].path, &next));
        assert!(selected.get(Height::zero()).is_none());
        assert!(selected.get(Height::new(9)).is_none());
    }

    #[test]
    fn forks_and_unknown_anchor_prefixes_cannot_be_selected_by_height() {
        let prefix = path(0, None, 3, 0);
        let left = path(0, Some(prefix[3]), 4, 1);
        let right = path(0, Some(prefix[3]), 4, 2);
        let mut cache = PathCache::new(Epoch::new(1), 2, 32);
        cache.insert(&SelectedCommitments::new(
            Epoch::new(1),
            vec![left.clone(), right.clone()],
        ));
        assert!(cache.resolve(prefix[0], left[4]).is_none());
        assert!(cache.resolve(left[1], right[4]).is_none());
        assert!(cache.resolve(prefix[3], right[4]).is_some());
        assert_eq!(cache.parent(left[4]), Some(left[3]));
        assert!(cache.parent(prefix[3]).is_none());
        cache.insert(&SelectedCommitments::new(
            Epoch::new(1),
            vec![prefix.clone()],
        ));
        assert!(cache.resolve(prefix[0], left[4]).is_some());
        assert!(cache.resolve(prefix[0], right[4]).is_some());
    }

    #[test]
    fn thousands_of_adjacent_ranges_share_exact_lookup_and_survive_overlapping_eviction() {
        let full = path(0, None, 4096, 0);
        let pieces = full.windows(2).map(Arc::from).collect::<Vec<_>>();
        let mut cache = PathCache::new(Epoch::new(1), 2, 8192);
        cache.insert(&SelectedCommitments::new(Epoch::new(1), pieces));
        let selected = cache.resolve(full[0], full[4096]).unwrap();
        assert_eq!(selected.ranges.len(), 4096);
        assert_eq!(cache.by_block.len(), 4096);
        for reference in full.iter() {
            assert_eq!(selected.get(reference.height()), Some(*reference));
        }
        let suffix: Arc<[BlockRef<D>]> = full[4000..].into();
        cache.insert(&SelectedCommitments::new(
            Epoch::new(1),
            vec![suffix.clone()],
        ));
        assert_eq!(cache.parent(full[4096]), Some(full[4095]));
        assert!(Arc::ptr_eq(cache.suffix(full[4096]).unwrap(), &suffix));
        assert!(cache.retained <= cache.capacity);
        assert!(cache.by_block.len() <= cache.retained);
        assert!(cache.resolve(full[0], full[4096]).is_none());
        assert_eq!(selected.get(full[1].height()), Some(full[1]));
    }

    #[test]
    fn evicting_overlapping_paths_preserves_only_the_retained_owner() {
        let first = path(0, None, 4, 0);
        let suffix: Arc<[BlockRef<D>]> = first[2..].into();
        let mut cache = PathCache::new(Epoch::new(1), 2, 10);
        for range in [first.clone(), suffix.clone(), path(1, None, 4, 1)] {
            cache.insert(&SelectedCommitments::new(Epoch::new(1), vec![range]));
        }
        assert_eq!(cache.parent(first[4]), Some(first[3]));
        assert!(Arc::ptr_eq(cache.suffix(first[4]).unwrap(), &suffix));
        assert!(cache.parent(first[2]).is_none());
        cache.insert(&SelectedCommitments::new(
            Epoch::new(1),
            vec![path(1, None, 4, 2)],
        ));
        assert!(cache.parent(first[4]).is_none());
        assert!(cache.by_block.len() <= cache.retained);
    }

    #[test]
    fn full_allocation_budget_eviction_and_epoch_are_independent_of_active_plan() {
        let first = path(0, None, 4, 0);
        let next = path(1, None, 4, 0);
        let mut cache = PathCache::new(Epoch::new(1), 2, 5);
        let hint = SelectedCommitments::new(Epoch::new(1), vec![first.clone()]);
        cache.insert(&hint);
        cache.insert(&hint);
        assert_eq!(cache.retained, 5);
        let selected = cache.resolve(first[2], first[4]).unwrap();
        cache.insert(&SelectedCommitments::new(Epoch::new(2), vec![next.clone()]));
        assert!(cache.resolve(first[0], first[4]).is_some());
        cache.insert(&SelectedCommitments::new(Epoch::new(1), vec![next.clone()]));
        assert_eq!(cache.retained, 5);
        assert!(cache.resolve(first[0], first[4]).is_none());
        assert_eq!(selected.get(first[3].height()), Some(first[3]));
        cache.insert(&SelectedCommitments::new(
            Epoch::new(1),
            vec![path(0, None, 5, 0)],
        ));
        assert_eq!(cache.retained, 5);
        assert!(cache.resolve(next[0], next[4]).is_some());
    }
}

//! First network arrival of each transaction block.

use crate::multimmit::types::BlockRef;
use commonware_cryptography::Digest;
use std::{
    collections::{BTreeMap, VecDeque},
    time::SystemTime,
};

/// Bounded first-arrival times for network-observed transaction blocks.
///
/// Feeds the DA-vote ingest latency histogram; blocks that never reach a DA vote are evicted
/// once the arrival window fills.
pub(crate) struct BlockArrivals<D: Digest> {
    times: BTreeMap<BlockRef<D>, SystemTime>,
    order: VecDeque<(BlockRef<D>, SystemTime)>,
}

impl<D: Digest> BlockArrivals<D> {
    pub(crate) const CAPACITY: usize = 4_096;

    pub(crate) const fn new() -> Self {
        Self {
            times: BTreeMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Records the first observation of `reference`; later duplicates keep the original stamp.
    pub(crate) fn record(&mut self, reference: BlockRef<D>, at: SystemTime) {
        if self.times.contains_key(&reference) {
            return;
        }
        while self.order.len() >= Self::CAPACITY {
            // A consumed entry leaves its order slot behind; evict only the stamp it recorded so
            // a later re-observation of the same block is not dropped early.
            if let Some((evicted, stamp)) = self.order.pop_front()
                && self.times.get(&evicted) == Some(&stamp)
            {
                self.times.remove(&evicted);
            }
        }
        self.times.insert(reference, at);
        self.order.push_back((reference, at));
    }

    /// Removes and returns the first arrival of `reference`.
    pub(crate) fn take(&mut self, reference: &BlockRef<D>) -> Option<SystemTime> {
        self.times.remove(reference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{multimmit::types::ChainId, types::Height};
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest as Sha256Digest};
    use std::time::Duration;

    #[test]
    fn block_arrivals_keep_first_stamp_and_evict_oldest() {
        let mut arrivals = BlockArrivals::<Sha256Digest>::new();
        let reference = |seed: u64| {
            BlockRef::new(
                ChainId::new(0),
                Height::new(seed),
                Sha256::hash(&[&seed.to_be_bytes()]),
            )
        };
        let first = SystemTime::UNIX_EPOCH;
        let later = first + Duration::from_millis(5);
        arrivals.record(reference(1), first);
        arrivals.record(reference(1), later);
        assert_eq!(arrivals.take(&reference(1)), Some(first));
        assert_eq!(arrivals.take(&reference(1)), None);

        let mut arrivals = BlockArrivals::<Sha256Digest>::new();
        for seed in 0..=(BlockArrivals::<Sha256Digest>::CAPACITY as u64) {
            arrivals.record(reference(seed), first + Duration::from_millis(seed));
        }
        assert_eq!(arrivals.take(&reference(0)), None);
        assert_eq!(
            arrivals.take(&reference(1)),
            Some(first + Duration::from_millis(1))
        );
    }
}

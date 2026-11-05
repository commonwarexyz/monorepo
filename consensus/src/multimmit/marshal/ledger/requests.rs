//! Requests to peers: those in flight with the bytes they reserve, and those waiting for the
//! fetch budget, oldest first.
//!
//! One structure owns both, with every key and every requested head indexed, so deduplicating a
//! want or a fetch is O(1).

use crate::multimmit::{marshal::wire::Key, types::BlockRef};
use commonware_cryptography::Digest;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::SystemTime,
};

/// Every request marshal made to peers and not yet settled.
pub(super) struct Requests<D: Digest> {
    /// Requests in flight, with the bytes each reserves and when the resolver was last asked.
    inflight: HashMap<Key<D>, (u64, SystemTime)>,
    /// Bytes reserved by requests in flight.
    bytes: u64,
    /// Requests over the budget, oldest first; entries whose key left `waiting` are stale.
    deferred: VecDeque<(Key<D>, u64)>,
    /// Keys deferred and not yet issued or evicted.
    waiting: HashSet<Key<D>>,
    /// Heads of the block requests in flight or deferred, with how many requests name each.
    heads: HashMap<BlockRef<D>, u32>,
    /// Most deferred requests.
    max_deferred: usize,
}

impl<D: Digest> Requests<D> {
    pub(super) fn new(max_deferred: usize) -> Self {
        Self {
            inflight: HashMap::new(),
            bytes: 0,
            deferred: VecDeque::new(),
            waiting: HashSet::new(),
            heads: HashMap::new(),
            max_deferred,
        }
    }

    /// Returns whether `key` is in flight or deferred.
    pub(super) fn contains(&self, key: &Key<D>) -> bool {
        self.inflight.contains_key(key) || self.waiting.contains(key)
    }

    /// Returns whether `key` is in flight.
    pub(super) fn in_flight(&self, key: &Key<D>) -> bool {
        self.inflight.contains_key(key)
    }

    /// Returns whether a block request with `head` is in flight or deferred.
    pub(super) fn requests_head(&self, head: &BlockRef<D>) -> bool {
        self.heads.contains_key(head)
    }

    /// Returns whether nothing is in flight.
    pub(super) fn idle(&self) -> bool {
        self.inflight.is_empty()
    }

    /// Returns the bytes reserved by requests in flight.
    pub(super) const fn bytes(&self) -> u64 {
        self.bytes
    }

    fn name(&mut self, key: &Key<D>) {
        if let Key::Blocks { head, .. } = key {
            *self.heads.entry(*head).or_default() += 1;
        }
    }

    fn unname(&mut self, key: &Key<D>) {
        if let Key::Blocks { head, .. } = key {
            if let Some(count) = self.heads.get_mut(head) {
                *count -= 1;
                if *count == 0 {
                    self.heads.remove(head);
                }
            }
        }
    }

    /// Records `key` as in flight, reserving `reserve` bytes, asked at `now`.
    pub(super) fn issue(&mut self, key: Key<D>, reserve: u64, now: SystemTime) {
        self.name(&key);
        self.inflight.insert(key, (reserve, now));
        self.bytes += reserve;
    }

    /// Defers `key` until the budget has room, evicting the oldest deferred request when full.
    pub(super) fn defer(&mut self, key: Key<D>, reserve: u64) {
        if self.waiting.len() == self.max_deferred {
            // The oldest deferred request is the least likely to still be needed; a position
            // that still needs its block wants it again.
            while let Some((oldest, _)) = self.deferred.pop_front() {
                if self.waiting.remove(&oldest) {
                    self.unname(&oldest);
                    break;
                }
            }
        }
        self.name(&key);
        self.waiting.insert(key);
        self.deferred.push_back((key, reserve));
    }

    /// Returns the oldest deferred request without taking it.
    pub(super) fn next_deferred(&mut self) -> Option<(Key<D>, u64)> {
        while let Some(&(key, reserve)) = self.deferred.front() {
            if self.waiting.contains(&key) {
                return Some((key, reserve));
            }
            self.deferred.pop_front();
        }
        None
    }

    /// Takes the oldest deferred request, which [`Self::next_deferred`] returned.
    pub(super) fn take_deferred(&mut self) {
        if let Some((key, _)) = self.deferred.pop_front() {
            if self.waiting.remove(&key) {
                self.unname(&key);
            }
        }
    }

    /// Settles `key` in flight, returning whether it was.
    pub(super) fn settle(&mut self, key: &Key<D>) -> bool {
        let Some((reserve, _)) = self.inflight.remove(key) else {
            return false;
        };
        self.bytes -= reserve;
        self.unname(key);
        true
    }

    /// Returns the requests in flight since before `before`, in key order, marking them asked at
    /// `now`.
    pub(super) fn stale(&mut self, before: SystemTime, now: SystemTime) -> Vec<Key<D>> {
        let mut stale = Vec::new();
        for (key, (_, asked)) in &mut self.inflight {
            if *asked <= before {
                *asked = now;
                stale.push(*key);
            }
        }
        // The map's order is arbitrary; the resolver sees a deterministic one.
        stale.sort_unstable();
        stale
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{multimmit::types::ChainId, types::Height};
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest as D};
    use core::num::NonZeroU16;
    use std::time::Duration;

    fn blocks(head: u64, len: u16) -> Key<D> {
        Key::Blocks {
            head: BlockRef::new(
                ChainId::new(0),
                Height::new(head),
                Sha256::hash(&[&head.to_be_bytes()]),
            ),
            len: NonZeroU16::new(len).unwrap(),
        }
    }

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn keys_and_heads_are_tracked_while_in_flight_or_deferred() {
        let mut requests = Requests::new(4);
        let (short, long) = (blocks(9, 1), blocks(9, 4));
        let Key::Blocks { head, .. } = short else {
            unreachable!()
        };
        requests.issue(short, 10, at(0));
        requests.defer(long, 40);
        assert!(requests.contains(&short) && requests.in_flight(&short));
        assert!(requests.contains(&long) && !requests.in_flight(&long));
        assert_eq!(requests.bytes(), 10);
        assert!(requests.requests_head(&head));

        // The head stays named until both requests naming it are gone.
        assert!(requests.settle(&short));
        assert!(!requests.settle(&short));
        assert!(requests.requests_head(&head));
        assert_eq!(requests.next_deferred(), Some((long, 40)));
        requests.take_deferred();
        assert!(!requests.requests_head(&head));
        assert!(requests.idle() && requests.bytes() == 0);
    }

    #[test]
    fn a_full_deferral_queue_evicts_its_oldest_request() {
        let mut requests = Requests::new(2);
        for head in 1..=3 {
            requests.defer(blocks(head, 1), 1);
        }
        assert!(!requests.contains(&blocks(1, 1)));
        assert_eq!(requests.next_deferred(), Some((blocks(2, 1), 1)));
        requests.take_deferred();
        assert_eq!(requests.next_deferred(), Some((blocks(3, 1), 1)));
        requests.take_deferred();
        assert_eq!(requests.next_deferred(), None);
    }

    #[test]
    fn stale_requests_are_reasserted_once_per_period_in_key_order() {
        let mut requests = Requests::new(4);
        for head in [7, 3, 5] {
            requests.issue(blocks(head, 1), 1, at(0));
        }
        requests.issue(blocks(1, 1), 1, at(8));
        assert_eq!(
            requests.stale(at(5), at(10)),
            vec![blocks(3, 1), blocks(5, 1), blocks(7, 1)]
        );
        // Re-asserted requests are fresh again.
        assert!(requests.stale(at(5), at(11)).is_empty());
        assert_eq!(requests.stale(at(10), at(20)), {
            let mut all = vec![blocks(1, 1), blocks(3, 1), blocks(5, 1), blocks(7, 1)];
            all.sort_unstable();
            all
        });
    }
}

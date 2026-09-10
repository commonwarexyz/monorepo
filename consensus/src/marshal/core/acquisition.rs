use super::Variant;
use commonware_utils::channel::oneshot;
use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    future::poll_fn,
    ops::Range,
    sync::Arc,
    task::Poll,
};

enum Phase<B> {
    Queued(u64),
    Active,
    Ready(B),
}

struct Demand<V: Variant> {
    owners: BTreeSet<u64>,
    phase: Phase<V::Block>,
}

struct Lease<C> {
    commitments: Arc<[C]>,
    range: Range<usize>,
    sender: oneshot::Sender<()>,
}

/// Speculative commitment demand with a shared bound on active fetches and unconsumed bodies.
///
/// Leases register metadata for an entire range. Fulfillment retires all demand for
/// that commitment; only a subsequent lease can enqueue it again.
pub(super) struct Acquisitions<V: Variant> {
    capacity: usize,
    entries: BTreeMap<V::Commitment, Demand<V>>,
    queue: BTreeMap<u64, V::Commitment>,
    next_queued: u64,
    leases: BTreeMap<u64, Lease<V::Commitment>>,
    next_lease: u64,
}

impl<V: Variant> Acquisitions<V> {
    pub(super) const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: BTreeMap::new(),
            queue: BTreeMap::new(),
            next_queued: 0,
            leases: BTreeMap::new(),
            next_lease: 0,
        }
    }

    fn demand(&mut self, commitment: V::Commitment) -> &mut Demand<V> {
        match self.entries.entry(commitment) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let id = self.next_queued;
                self.next_queued = id.checked_add(1).expect("acquisition queue IDs exhausted");
                self.queue.insert(id, commitment);
                entry.insert(Demand {
                    owners: BTreeSet::new(),
                    phase: Phase::Queued(id),
                })
            }
        }
    }

    pub(super) fn contains(&self, commitment: &V::Commitment) -> bool {
        self.entries.contains_key(commitment)
    }

    pub(super) fn lease(
        &mut self,
        commitments: Arc<[V::Commitment]>,
        range: Range<usize>,
        sender: oneshot::Sender<()>,
    ) {
        if sender.is_closed() {
            return;
        }
        let Some(selected) = commitments.get(range.clone()) else {
            return;
        };
        if selected.is_empty() {
            return;
        }
        let id = self.next_lease;
        self.next_lease = id.checked_add(1).expect("acquisition lease IDs exhausted");
        for commitment in selected {
            self.demand(*commitment).owners.insert(id);
        }
        self.leases.insert(
            id,
            Lease {
                commitments,
                range,
                sender,
            },
        );
    }

    pub(super) fn ready(&self) -> bool {
        !self.queue.is_empty() && self.entries.len() - self.queue.len() < self.capacity
    }

    /// Reserves a speculative body slot before returning the next commitment to fetch.
    pub(super) fn next(&mut self) -> Option<V::Commitment> {
        if !self.ready() {
            return None;
        }
        let (_, commitment) = self.queue.pop_first()?;
        self.entries
            .get_mut(&commitment)
            .expect("queued commitment has demand")
            .phase = Phase::Active;
        Some(commitment)
    }

    fn remove(&mut self, commitment: &V::Commitment) -> Option<Demand<V>> {
        let demand = self.entries.remove(commitment)?;
        if let Phase::Queued(id) = &demand.phase {
            self.queue.remove(id);
        }
        Some(demand)
    }

    pub(super) fn get_ready(&self, commitment: &V::Commitment) -> Option<V::Block> {
        match &self.entries.get(commitment)?.phase {
            Phase::Ready(block) => Some(block.clone()),
            Phase::Queued(_) | Phase::Active => None,
        }
    }

    /// Transfers demand to an explicit caller and reports whether a fetch is active.
    pub(super) fn claim(&mut self, commitment: V::Commitment) -> bool {
        self.remove(&commitment)
            .is_some_and(|demand| matches!(demand.phase, Phase::Active))
    }

    /// Retires best-effort demand after availability has been established.
    pub(super) fn satisfied(&mut self, commitment: V::Commitment) {
        self.remove(&commitment);
    }

    /// Retains a prefetched body only in a slot reserved by an active request.
    pub(super) fn complete(&mut self, block: V::Block) {
        let commitment = V::commitment(&block);
        if let Some(demand) = self.entries.get_mut(&commitment)
            && !matches!(demand.phase, Phase::Queued(_))
        {
            demand.phase = Phase::Ready(block);
            return;
        }
        self.satisfied(commitment);
    }

    /// Removes closed leases and returns commitments whose final owner disappeared.
    pub(super) async fn closed(&mut self) -> Vec<V::Commitment> {
        poll_fn(|cx| {
            let closed: Vec<_> = self
                .leases
                .iter_mut()
                .filter_map(|(id, lease)| lease.sender.poll_closed(cx).is_ready().then_some(*id))
                .collect();
            if closed.is_empty() {
                return Poll::Pending;
            }
            let mut removed = Vec::new();
            for id in closed {
                let lease = self.leases.remove(&id).expect("closed lease exists");
                for commitment in &lease.commitments[lease.range] {
                    let Some(demand) = self.entries.get_mut(commitment) else {
                        continue;
                    };
                    demand.owners.remove(&id);
                    if demand.owners.is_empty() {
                        self.remove(commitment);
                        removed.push(*commitment);
                    }
                }
            }
            Poll::Ready(removed)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::{mocks::block::EmptyBlock, standard::Standard},
        types::Height,
    };
    use commonware_cryptography::{
        Digestible,
        sha256::{Digest, Sha256},
    };
    use commonware_macros::select;
    use commonware_runtime::{Clock, Runner as _, deterministic};
    use futures::FutureExt;

    type TestBlock = EmptyBlock<Sha256>;
    type TestAcquisitions = Acquisitions<Standard<TestBlock>>;

    fn block(height: u64) -> Arc<TestBlock> {
        Arc::new(TestBlock::new(Sha256::fill(0), Height::new(height), height))
    }

    fn lease(acquisitions: &mut TestAcquisitions, commitments: &[Digest]) -> oneshot::Receiver<()> {
        let (sender, receiver) = oneshot::channel();
        acquisitions.lease(Arc::from(commitments), 0..commitments.len(), sender);
        receiver
    }

    #[test]
    fn forward_order_shares_slots_between_active_and_ready() {
        let mut acquisitions = TestAcquisitions::new(2);
        let blocks: Vec<_> = (1..=4).map(block).collect();
        let commitments: Vec<_> = blocks.iter().map(Digestible::digest).collect();
        let _lease = lease(&mut acquisitions, &commitments);
        assert_eq!(acquisitions.entries.len(), 4);
        assert_eq!(acquisitions.next(), Some(commitments[0]));
        assert_eq!(acquisitions.next(), Some(commitments[1]));
        assert_eq!(acquisitions.next(), None);
        acquisitions.complete(blocks[1].clone());
        assert_eq!(acquisitions.next(), None);
        assert!(acquisitions.get_ready(&commitments[0]).is_none());
        acquisitions.complete(blocks[0].clone());
        assert_eq!(acquisitions.next(), None);
        assert_eq!(
            acquisitions.get_ready(&commitments[0]).unwrap().digest(),
            commitments[0]
        );
        assert_eq!(acquisitions.next(), None);
        assert_eq!(
            acquisitions.get_ready(&commitments[0]).unwrap().digest(),
            commitments[0]
        );
        acquisitions.satisfied(commitments[0]);
        assert!(acquisitions.get_ready(&commitments[0]).is_none());
        assert_eq!(acquisitions.next(), Some(commitments[2]));
        assert_eq!(acquisitions.next(), None);
        assert_eq!(
            acquisitions.get_ready(&commitments[1]).unwrap().digest(),
            commitments[1]
        );
        assert_eq!(acquisitions.next(), None);
        acquisitions.satisfied(commitments[1]);
        assert_eq!(acquisitions.next(), Some(commitments[3]));
    }

    #[test]
    fn overlapping_leases_share_and_release_ready_bodies() {
        let mut acquisitions = TestAcquisitions::new(1);
        let body = block(1);
        let commitment = body.digest();
        let first = lease(&mut acquisitions, &[commitment]);
        let second = lease(&mut acquisitions, &[commitment]);
        assert_eq!(acquisitions.next(), Some(commitment));
        assert_eq!(acquisitions.next(), None);
        acquisitions.complete(body.clone());
        assert_eq!(Arc::strong_count(&body), 2);
        drop(first);
        assert_eq!(acquisitions.closed().now_or_never(), Some(Vec::new()));
        assert_eq!(Arc::strong_count(&body), 2);
        drop(second);
        assert_eq!(acquisitions.closed().now_or_never(), Some(vec![commitment]));
        assert_eq!(Arc::strong_count(&body), 1);
        assert!(acquisitions.entries.is_empty());
    }

    #[test]
    fn claimed_active_request_releases_slot_and_old_lease_cannot_cancel_new_demand() {
        let mut acquisitions = TestAcquisitions::new(1);
        let first = block(1).digest();
        let second = block(2).digest();
        let old = lease(&mut acquisitions, &[first]);
        let _pending = lease(&mut acquisitions, &[second]);
        assert!(acquisitions.ready());
        assert_eq!(acquisitions.next(), Some(first));
        assert!(!acquisitions.ready());
        assert!(acquisitions.claim(first));
        assert!(acquisitions.ready());
        let _new = lease(&mut acquisitions, &[first]);
        drop(old);
        assert_eq!(acquisitions.closed().now_or_never(), Some(Vec::new()));
        assert_eq!(acquisitions.next(), Some(second));
        acquisitions.satisfied(second);
        assert_eq!(acquisitions.next(), Some(first));
        acquisitions.satisfied(first);
        assert!(!acquisitions.claim(first));
        let _renewed = lease(&mut acquisitions, &[second]);
        assert_eq!(acquisitions.next(), Some(second));
    }

    #[test]
    fn duplicate_and_reinserted_keys_preserve_fifo() {
        let mut acquisitions = TestAcquisitions::new(3);
        let first = block(1).digest();
        let second = block(2).digest();
        let old = lease(&mut acquisitions, &[first, first]);
        let _second = lease(&mut acquisitions, &[second]);
        drop(old);
        assert_eq!(acquisitions.closed().now_or_never(), Some(vec![first]));
        let _first = lease(&mut acquisitions, &[first]);
        assert_eq!(acquisitions.next(), Some(second));
        assert_eq!(acquisitions.next(), Some(first));
        assert_eq!(acquisitions.next(), None);
    }

    #[test]
    fn zero_capacity_and_unsolicited_bodies_retain_no_body() {
        let mut acquisitions = TestAcquisitions::new(0);
        let body = block(1);
        let retained = lease(&mut acquisitions, &[body.digest()]);
        assert_eq!(acquisitions.next(), None);
        acquisitions.complete(body.clone());
        assert!(acquisitions.entries.is_empty());
        assert_eq!(Arc::strong_count(&body), 1);
        let canceled = lease(&mut acquisitions, &[]);
        assert!(canceled.now_or_never().unwrap().is_err());
        drop(retained);
        assert_eq!(acquisitions.closed().now_or_never(), Some(Vec::new()));
        assert!(acquisitions.leases.is_empty());
    }

    #[test]
    fn lease_range_shares_metadata_and_rejects_invalid_bounds() {
        let mut acquisitions = TestAcquisitions::new(2);
        let commitments: Arc<[_]> = (1..=3).map(|height| block(height).digest()).collect();
        for range in [
            0..0,
            Range { start: 2, end: 1 },
            0..4,
            usize::MAX..usize::MAX,
        ] {
            let (sender, receiver) = oneshot::channel();
            acquisitions.lease(commitments.clone(), range, sender);
            assert!(receiver.now_or_never().unwrap().is_err());
            assert!(acquisitions.entries.is_empty());
            assert!(acquisitions.leases.is_empty());
        }
        let (sender, receiver) = oneshot::channel();
        acquisitions.lease(commitments.clone(), 1..3, sender);
        assert_eq!(Arc::strong_count(&commitments), 2);
        assert!(!acquisitions.contains(&commitments[0]));
        assert_eq!(acquisitions.next(), Some(commitments[1]));
        assert_eq!(acquisitions.next(), Some(commitments[2]));
        drop(receiver);
        assert_eq!(
            acquisitions.closed().now_or_never(),
            Some(vec![commitments[1], commitments[2]])
        );
        assert_eq!(Arc::strong_count(&commitments), 1);
    }

    #[test]
    fn cancellation_wakes_idle_scheduler_and_releases_active_slot() {
        deterministic::Runner::default().start(|context| async move {
            let mut acquisitions = TestAcquisitions::new(1);
            let first = block(1).digest();
            let second = block(2).digest();
            let receiver = lease(&mut acquisitions, &[first]);
            assert_eq!(acquisitions.next(), Some(first));
            let _second = lease(&mut acquisitions, &[second]);
            select! {
                removed = acquisitions.closed() => assert_eq!(removed, vec![first]),
                _ = async {
                    context.sleep(std::time::Duration::from_millis(1)).await;
                    drop(receiver);
                    std::future::pending::<()>().await;
                } => unreachable!(),
                _ = context.sleep(std::time::Duration::from_secs(1)) => {
                    panic!("lease cancellation must wake the scheduler");
                },
            }
            assert_eq!(acquisitions.next(), Some(second));
        });
    }
}

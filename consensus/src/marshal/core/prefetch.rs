//! Speculative fetches of block bodies on behalf of range leases.

use super::Variant;
use commonware_utils::channel::oneshot;
use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    future::poll_fn,
    ops::Range,
    sync::Arc,
    task::Poll,
};

/// Progress of speculative demand for one commitment.
enum Phase<B> {
    /// Waiting for a free slot, at this position in the fetch queue.
    Queued(u64),
    /// Holding a slot while its fetch is outstanding.
    Active,
    /// Holding a slot with the fetched body.
    Ready(B),
}

/// Speculative demand for one commitment, owned by the leases that selected it.
struct Demand<V: Variant> {
    owners: BTreeSet<u64>,
    phase: Phase<V::Block>,
}

/// A caller's lease on `commitments[range]`, open until the caller drops the receiver paired
/// with `sender`.
struct Lease<C> {
    commitments: Arc<[C]>,
    range: Range<usize>,
    sender: oneshot::Sender<()>,
}

/// Speculative commitment demand with a shared bound on active fetches and unconsumed bodies.
///
/// A lease registers every commitment in its range. Demand lasts until its last lease closes or it
/// is retired earlier, and only a later lease can enqueue it again.
pub(super) struct Prefetches<V: Variant> {
    /// Maximum number of active and ready commitments.
    capacity: usize,
    /// Demand in every phase, by commitment.
    entries: BTreeMap<V::Commitment, Demand<V>>,
    /// Queued commitments by arrival. Every other entry holds a slot.
    queue: BTreeMap<u64, V::Commitment>,
    /// Next queue position. Positions only increase, so the queue keeps arrival order.
    next_queued: u64,
    /// Open leases by ID.
    leases: BTreeMap<u64, Lease<V::Commitment>>,
    /// Next lease ID. IDs are never reused, so a closed lease cannot release newer demand.
    next_lease: u64,
}

impl<V: Variant> Prefetches<V> {
    /// Creates an empty set that holds at most `capacity` active and ready commitments.
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

    /// Returns the demand for `commitment`, queueing new demand behind earlier arrivals.
    fn demand(&mut self, commitment: V::Commitment) -> &mut Demand<V> {
        match self.entries.entry(commitment) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let id = self.next_queued;
                self.next_queued = id.checked_add(1).expect("queue IDs must not overflow");
                self.queue.insert(id, commitment);
                entry.insert(Demand {
                    owners: BTreeSet::new(),
                    phase: Phase::Queued(id),
                })
            }
        }
    }

    /// Registers a lease on `range` within `commitments`.
    ///
    /// A closed sender or an empty or invalid range registers nothing, and dropping `sender` then
    /// closes the caller's receiver.
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

        // Each selected commitment gains this lease as an owner, queueing any new demand.
        let id = self.next_lease;
        self.next_lease = id.checked_add(1).expect("lease IDs must not overflow");
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

    /// Returns whether queued demand has a free slot.
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
            .expect("queued commitment must have demand")
            .phase = Phase::Active;
        Some(commitment)
    }

    /// Removes demand for `commitment` in any phase, along with its queue position.
    fn remove(&mut self, commitment: &V::Commitment) -> Option<Demand<V>> {
        let demand = self.entries.remove(commitment)?;
        if let Phase::Queued(id) = &demand.phase {
            self.queue.remove(id);
        }
        Some(demand)
    }

    /// Returns the fetched body for `commitment` if its demand is ready.
    pub(super) fn get_ready(&self, commitment: &V::Commitment) -> Option<&V::Block> {
        match &self.entries.get(commitment)?.phase {
            Phase::Ready(block) => Some(block),
            Phase::Queued(_) | Phase::Active => None,
        }
    }

    /// Retires speculative demand and returns whether its fetch was active.
    ///
    /// The caller owns canceling any resolver request for an active fetch.
    pub(super) fn retire(&mut self, commitment: V::Commitment) -> bool {
        self.remove(&commitment)
            .is_some_and(|demand| matches!(demand.phase, Phase::Active))
    }

    /// Keeps a fetched body in the slot its demand holds, and retires demand that holds no slot.
    ///
    /// Returns whether the demand was active, in which case its resolver request may still be
    /// outstanding.
    pub(super) fn complete(&mut self, block: V::Block) -> bool {
        let commitment = V::commitment(&block);
        if let Some(demand) = self.entries.get_mut(&commitment)
            && !matches!(demand.phase, Phase::Queued(_))
        {
            let active = matches!(demand.phase, Phase::Active);
            demand.phase = Phase::Ready(block);
            return active;
        }
        self.retire(commitment);
        false
    }

    /// Removes closed leases and returns active fetches whose final owner disappeared.
    pub(super) async fn closed(&mut self) -> Vec<V::Commitment> {
        poll_fn(|cx| {
            // Collect the leases whose receivers closed, registering a wake for the rest.
            let closed: Vec<_> = self
                .leases
                .iter_mut()
                .filter_map(|(id, lease)| lease.sender.poll_closed(cx).is_ready().then_some(*id))
                .collect();
            if closed.is_empty() {
                return Poll::Pending;
            }

            // Drop each closed lease as an owner. Demand left without owners retires, and any
            // active fetch among it is returned so its request can be canceled.
            let mut removed = Vec::new();
            for id in closed {
                let lease = self.leases.remove(&id).expect("closed lease must exist");
                for commitment in &lease.commitments[lease.range] {
                    let Some(demand) = self.entries.get_mut(commitment) else {
                        continue;
                    };
                    demand.owners.remove(&id);
                    if demand.owners.is_empty() && self.retire(*commitment) {
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
        marshal::{
            mocks::block::{EmptyBlock, ready},
            standard::Standard,
        },
        types::Height,
    };
    use commonware_cryptography::{
        Digested, Digestible,
        sha256::{Digest, Sha256},
    };
    use commonware_macros::select;
    use commonware_runtime::{Clock, Runner as _, deterministic};
    use futures::FutureExt;
    use std::time::Duration;

    type TestBlock = EmptyBlock<Sha256>;
    type TestPrefetches = Prefetches<Standard<TestBlock>>;

    /// Delay before a test cancels a lease, so the scheduler under test is already waiting.
    const CANCEL_DELAY: Duration = Duration::from_millis(1);

    /// Time a cancellation has to wake the scheduler that waits on it.
    const WAKE_TIMEOUT: Duration = Duration::from_secs(1);

    /// Returns a digested test block at `height`, distinct for each height.
    fn block(height: u64) -> Digested<TestBlock> {
        ready(TestBlock::new(Sha256::fill(0), Height::new(height), height))
    }

    /// Counts references to the block body, excluding the probe itself.
    fn strong_count(block: &Digested<TestBlock>) -> usize {
        Arc::strong_count(&block.inner_shared()) - 1
    }

    /// Requests a lease on all of `commitments` and returns its receiver.
    fn lease(prefetch: &mut TestPrefetches, commitments: &[Digest]) -> oneshot::Receiver<()> {
        let (sender, receiver) = oneshot::channel();
        prefetch.lease(Arc::from(commitments), 0..commitments.len(), sender);
        receiver
    }

    /// Active fetches and ready bodies share the capacity, so a completed body holds its slot until
    /// it is retired. Queued commitments start in lease order as slots free.
    #[test]
    fn forward_order_shares_slots_between_active_and_ready() {
        // Lease four commitments with room for two.
        let mut prefetch = TestPrefetches::new(2);
        let blocks: Vec<_> = (1..=4).map(block).collect();
        let commitments: Vec<_> = blocks.iter().map(Digestible::digest).collect();
        let _lease = lease(&mut prefetch, &commitments);
        assert_eq!(prefetch.entries.len(), 4);

        // The first two start, and the third waits for a slot.
        assert_eq!(prefetch.next(), Some(commitments[0]));
        assert_eq!(prefetch.next(), Some(commitments[1]));
        assert_eq!(prefetch.next(), None);

        // Completing both keeps their bodies in the slots, out of order, so nothing else starts.
        prefetch.complete(blocks[1].clone());
        assert_eq!(prefetch.next(), None);
        assert!(prefetch.get_ready(&commitments[0]).is_none());
        prefetch.complete(blocks[0].clone());
        assert_eq!(prefetch.next(), None);
        assert_eq!(
            prefetch.get_ready(&commitments[0]).unwrap().digest(),
            commitments[0]
        );
        assert_eq!(prefetch.next(), None);
        assert_eq!(
            prefetch.get_ready(&commitments[0]).unwrap().digest(),
            commitments[0]
        );

        // Retiring a ready body frees one slot for the next queued commitment.
        prefetch.retire(commitments[0]);
        assert!(prefetch.get_ready(&commitments[0]).is_none());
        assert_eq!(prefetch.next(), Some(commitments[2]));
        assert_eq!(prefetch.next(), None);
        assert_eq!(
            prefetch.get_ready(&commitments[1]).unwrap().digest(),
            commitments[1]
        );
        assert_eq!(prefetch.next(), None);
        prefetch.retire(commitments[1]);
        assert_eq!(prefetch.next(), Some(commitments[3]));
    }

    /// `complete` returns true only for demand whose fetch was active. Completing queued demand
    /// retires it, and a repeated or unleased body reports nothing.
    #[test]
    fn complete_reports_only_active_demand() {
        // Two of three leased commitments start fetching.
        let mut prefetch = TestPrefetches::new(2);
        let blocks: Vec<_> = (1..=3).map(block).collect();
        let commitments: Vec<_> = blocks.iter().map(Digestible::digest).collect();
        let _lease = lease(&mut prefetch, &commitments);
        assert_eq!(prefetch.next(), Some(commitments[0]));
        assert_eq!(prefetch.next(), Some(commitments[1]));

        // A queued body retires its demand, an active one becomes ready, and repeating it or
        // completing an unleased body reports nothing.
        assert!(!prefetch.complete(blocks[2].clone()));
        assert!(!prefetch.entries.contains_key(&commitments[2]));
        assert!(prefetch.complete(blocks[0].clone()));
        assert!(!prefetch.complete(blocks[0].clone()));
        assert!(prefetch.get_ready(&commitments[0]).is_some());
        assert!(!prefetch.complete(block(4)));
        assert!(prefetch.get_ready(&commitments[1]).is_none());
    }

    /// A commitment selected by two leases is fetched once, and its ready body stays held until the
    /// last of those leases closes.
    #[test]
    fn overlapping_leases_share_and_release_ready_bodies() {
        // Two leases select one commitment, and it is fetched once.
        let mut prefetch = TestPrefetches::new(1);
        let body = block(1);
        let commitment = body.digest();
        let first = lease(&mut prefetch, &[commitment]);
        let second = lease(&mut prefetch, &[commitment]);
        assert_eq!(prefetch.next(), Some(commitment));
        assert_eq!(prefetch.next(), None);

        // The ready body survives the first lease and is released with the second.
        prefetch.complete(body.clone());
        assert_eq!(strong_count(&body), 2);
        drop(first);
        assert_eq!(prefetch.closed().now_or_never(), Some(Vec::new()));
        assert_eq!(strong_count(&body), 2);
        drop(second);
        assert_eq!(prefetch.closed().now_or_never(), Some(Vec::new()));
        assert_eq!(strong_count(&body), 1);
        assert!(prefetch.entries.is_empty());
    }

    /// Retiring an active fetch frees its slot. A lease that closes after its demand was retired
    /// and leased again leaves the newer demand queued in order.
    #[test]
    fn claimed_active_request_releases_slot_and_old_lease_cannot_cancel_new_demand() {
        // The first commitment takes the only slot.
        let mut prefetch = TestPrefetches::new(1);
        let first = block(1).digest();
        let second = block(2).digest();
        let old = lease(&mut prefetch, &[first]);
        let _pending = lease(&mut prefetch, &[second]);
        assert!(prefetch.ready());
        assert_eq!(prefetch.next(), Some(first));
        assert!(!prefetch.ready());

        // Retiring the active fetch frees the slot.
        assert!(prefetch.retire(first));
        assert!(prefetch.ready());

        // A new lease re-queues the first commitment, and closing the old lease leaves it queued.
        let _new = lease(&mut prefetch, &[first]);
        drop(old);
        assert_eq!(prefetch.closed().now_or_never(), Some(Vec::new()));

        // Demand runs in queue order, and retired demand can be leased again.
        assert_eq!(prefetch.next(), Some(second));
        prefetch.retire(second);
        assert_eq!(prefetch.next(), Some(first));
        prefetch.retire(first);
        assert!(!prefetch.retire(first));
        let _renewed = lease(&mut prefetch, &[second]);
        assert_eq!(prefetch.next(), Some(second));
    }

    /// A lease naming a commitment twice registers one demand, and demand leased again after it
    /// retired queues behind demand that arrived in between.
    #[test]
    fn duplicate_and_reinserted_keys_preserve_fifo() {
        // A lease naming the first commitment twice closes after a second commitment queues.
        let mut prefetch = TestPrefetches::new(3);
        let first = block(1).digest();
        let second = block(2).digest();
        let old = lease(&mut prefetch, &[first, first]);
        let _second = lease(&mut prefetch, &[second]);
        drop(old);
        assert_eq!(prefetch.closed().now_or_never(), Some(Vec::new()));

        // Leasing the first again queues it behind the second.
        let _first = lease(&mut prefetch, &[first]);
        assert_eq!(prefetch.next(), Some(second));
        assert_eq!(prefetch.next(), Some(first));
        assert_eq!(prefetch.next(), None);
    }

    /// With zero capacity no fetch starts, and a body completed for demand that never started is
    /// dropped. An empty lease closes its receiver at once, and closing the last lease leaves no
    /// state.
    #[test]
    fn zero_capacity_and_unsolicited_bodies_retain_no_body() {
        // With zero capacity the lease cannot start, and its body is not retained.
        let mut prefetch = TestPrefetches::new(0);
        let body = block(1);
        let retained = lease(&mut prefetch, &[body.digest()]);
        assert_eq!(prefetch.next(), None);
        prefetch.complete(body.clone());
        assert!(prefetch.entries.is_empty());
        assert_eq!(strong_count(&body), 1);

        // An empty lease closes its receiver immediately.
        let canceled = lease(&mut prefetch, &[]);
        assert!(canceled.now_or_never().unwrap().is_err());

        // Closing the remaining lease leaves no state behind.
        drop(retained);
        assert_eq!(prefetch.closed().now_or_never(), Some(Vec::new()));
        assert!(prefetch.leases.is_empty());
    }

    /// Empty, reversed, and out-of-bounds ranges close the receiver and register nothing. A valid
    /// range shares the commitment sequence without copying it and demands only the commitments it
    /// selects.
    #[test]
    fn lease_range_shares_metadata_and_rejects_invalid_bounds() {
        // Three commitments with room for two fetches.
        let mut prefetch = TestPrefetches::new(2);
        let commitments: Arc<[_]> = (1..=3).map(|height| block(height).digest()).collect();

        // Empty, reversed, and out-of-bounds ranges close their receivers and leave no state.
        for range in [
            0..0,
            Range { start: 2, end: 1 },
            0..4,
            usize::MAX..usize::MAX,
        ] {
            let (sender, receiver) = oneshot::channel();
            prefetch.lease(commitments.clone(), range, sender);
            assert!(receiver.now_or_never().unwrap().is_err());
            assert!(prefetch.entries.is_empty());
            assert!(prefetch.leases.is_empty());
        }

        // A valid range holds the sequence without copying it and selects only its indices.
        let (sender, receiver) = oneshot::channel();
        prefetch.lease(commitments.clone(), 1..3, sender);
        assert_eq!(Arc::strong_count(&commitments), 2);
        assert!(!prefetch.entries.contains_key(&commitments[0]));
        assert_eq!(prefetch.next(), Some(commitments[1]));
        assert_eq!(prefetch.next(), Some(commitments[2]));

        // Closing the lease retires both active fetches, reports them for cancellation, and
        // releases the sequence.
        drop(receiver);
        assert_eq!(
            prefetch.closed().now_or_never(),
            Some(vec![commitments[1], commitments[2]])
        );
        assert_eq!(Arc::strong_count(&commitments), 1);
    }

    /// Closing a lease wakes a scheduler already waiting in `closed`, and `closed` returns the
    /// canceled active fetch. The freed slot then starts the next queued commitment.
    #[test]
    fn cancellation_wakes_idle_scheduler_and_releases_active_slot() {
        deterministic::Runner::default().start(|context| async move {
            // The first lease takes the only slot, and the second waits behind it.
            let mut prefetch = TestPrefetches::new(1);
            let first = block(1).digest();
            let second = block(2).digest();
            let receiver = lease(&mut prefetch, &[first]);
            assert_eq!(prefetch.next(), Some(first));
            let _second = lease(&mut prefetch, &[second]);

            // Dropping the first lease after the scheduler waits must wake it with the canceled
            // fetch.
            select! {
                removed = prefetch.closed() => assert_eq!(removed, vec![first]),
                _ = async {
                    context.sleep(CANCEL_DELAY).await;
                    drop(receiver);
                    std::future::pending::<()>().await;
                } => unreachable!(),
                _ = context.sleep(WAKE_TIMEOUT) => {
                    panic!("lease cancellation must wake the scheduler");
                },
            }

            // The freed slot starts the queued commitment.
            assert_eq!(prefetch.next(), Some(second));
        });
    }
}

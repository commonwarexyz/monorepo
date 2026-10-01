//! Committee reply sampling shared by the stateful, DKG, and executor probes.

use commonware_utils::Faults;
use std::collections::BTreeMap;

/// A sample that selects the highest-ranked reply from `f + 1` distinct peers.
///
/// Callers verify replies and enforce committee membership before recording them. With at most
/// `f` faulty committee members, the selected reply ranks at least as high as an honest reply in
/// the sample. Callers determine which recorded replies remain judgeable at selection time.
pub(crate) struct Sample<P, R>
where
    P: Ord,
    R: Clone,
{
    /// `None` reserves a peer while its reply is being verified.
    replies: BTreeMap<P, Option<R>>,
    floor: Option<R>,
}

impl<P, R> Sample<P, R>
where
    P: Ord,
    R: Clone,
{
    /// Creates an empty sample.
    pub(crate) const fn new() -> Self {
        Self {
            replies: BTreeMap::new(),
            floor: None,
        }
    }

    /// Returns the selected floor, if the sample has resolved.
    pub(crate) const fn floor(&self) -> Option<&R> {
        self.floor.as_ref()
    }

    /// Returns whether `peer` has neither a pending nor a verified reply in an unresolved sample.
    ///
    /// Callers check this before decoding or verifying replies to avoid duplicate work.
    pub(crate) fn awaits(&self, peer: &P) -> bool {
        self.floor.is_none() && !self.replies.contains_key(peer)
    }

    /// Reserves `peer` for verification if its reply is still awaited.
    ///
    /// Pending replies are excluded from selection. Callers record a verified reply or release
    /// the reservation when verification fails. A reset discards all reservations; callers must
    /// discard verification results belonging to an earlier sample.
    pub(crate) fn reserve(&mut self, peer: P) -> bool {
        if !self.awaits(&peer) {
            return false;
        }
        self.replies.insert(peer, None);
        true
    }

    /// Releases `peer`'s pending reservation, retaining any verified reply.
    pub(crate) fn release(&mut self, peer: &P) {
        if matches!(self.replies.get(peer), Some(None)) {
            self.replies.remove(peer);
        }
    }

    /// Records a verified reply, retaining the first verified reply from each peer.
    pub(crate) fn record(&mut self, peer: P, reply: R) {
        self.replies.entry(peer).or_default().get_or_insert(reply);
    }

    /// Returns all verified replies, excluding pending reservations.
    pub(crate) fn replies(&self) -> impl Iterator<Item = &R> {
        self.replies.values().filter_map(Option::as_ref)
    }

    /// Discards the selected floor, verified replies, and pending reservations.
    pub(crate) fn reset(&mut self) {
        self.replies.clear();
        self.floor = None;
    }

    /// Selects the highest-ranked judgeable reply once `f + 1` replies are judgeable, where `f`
    /// is the fault model's maximum fault count for `committee_size`.
    ///
    /// Returns the floor exactly once, when it is first selected, and `None` otherwise.
    pub(crate) fn select<F: Faults, Rank: Ord>(
        &mut self,
        committee_size: usize,
        judgeable: impl Fn(&R) -> bool,
        rank: impl Fn(&R) -> Rank,
    ) -> Option<R> {
        if self.floor.is_some() {
            return None;
        }

        let (floor, count) = self
            .replies()
            .fold((None, 0usize), |(floor, count), reply| {
                if !judgeable(reply) {
                    return (floor, count);
                }
                let floor = floor
                    .is_none_or(|candidate: &R| rank(reply) > rank(candidate))
                    .then_some(reply)
                    .or(floor);
                (floor, count + 1)
            });
        let floor = floor?;
        if count < F::max_faults(committee_size) as usize + 1 {
            return None;
        }

        self.floor = Some(floor.clone());
        self.floor.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::{N3f1, faults::N5f1Nullification};

    fn assert_threshold<F: Faults>(committee_size: usize, threshold: usize) {
        let mut sample = Sample::new();
        for peer in 0..threshold - 1 {
            sample.record(peer, peer);
            assert_eq!(
                sample.select::<F, _>(committee_size, |_| true, |r| *r),
                None
            );
        }
        sample.record(threshold - 1, threshold - 1);
        assert_eq!(
            sample.select::<F, _>(committee_size, |_| true, |r| *r),
            Some(threshold - 1)
        );
    }

    #[test]
    fn thresholds_follow_fault_model() {
        for (size, n3f1, n5f1) in [(1, 1, 1), (4, 2, 1), (7, 3, 2), (11, 4, 3), (50, 17, 10)] {
            assert_threshold::<N3f1>(size, n3f1);
            assert_threshold::<N5f1Nullification>(size, n5f1);
        }
    }

    #[test]
    fn duplicate_replies_retain_first_and_do_not_complete_sample() {
        let mut sample = Sample::new();
        sample.record(1, 10);
        sample.record(1, 100);
        assert_eq!(sample.replies().copied().collect::<Vec<_>>(), vec![10]);
        assert_eq!(sample.select::<N3f1, _>(4, |_| true, |r| *r), None);

        sample.record(2, 5);
        assert_eq!(sample.select::<N3f1, _>(4, |_| true, |r| *r), Some(10));
        assert_eq!(sample.floor(), Some(&10));
        assert_eq!(sample.select::<N3f1, _>(4, |_| true, |r| *r), None);
        assert!(!sample.awaits(&3));
        assert!(!sample.reserve(3));
    }

    #[test]
    fn highest_rank_wins() {
        let mut sample = Sample::new();
        sample.record(1, (10, "stale"));
        sample.record(2, (99, "newest"));
        sample.record(3, (20, "middle"));
        assert_eq!(
            sample.select::<N3f1, _>(7, |_| true, |r| r.0),
            Some((99, "newest"))
        );
    }

    #[test]
    fn unjudgeable_replies_neither_count_nor_win() {
        let mut sample = Sample::new();
        sample.record(1, (100, false));
        sample.record(2, (10, true));
        assert_eq!(sample.select::<N3f1, _>(4, |r| r.1, |r| r.0), None);
        sample.record(3, (20, true));
        assert_eq!(
            sample.select::<N3f1, _>(4, |r| r.1, |r| r.0),
            Some((20, true))
        );
    }

    #[test]
    fn pending_replies_neither_count_nor_reserve_twice() {
        let mut sample = Sample::new();
        assert!(sample.reserve(1));
        assert!(!sample.awaits(&1));
        assert!(!sample.reserve(1));
        assert_eq!(sample.replies().count(), 0);
        sample.record(2, 20);
        assert_eq!(sample.select::<N3f1, _>(4, |_| true, |r| *r), None);

        sample.release(&1);
        assert!(sample.awaits(&1));
        assert!(sample.reserve(1));
        sample.record(1, 30);
        sample.record(1, 100);
        sample.release(&1);
        assert!(!sample.awaits(&1));
        assert_eq!(sample.replies().copied().collect::<Vec<_>>(), vec![30, 20]);
        assert_eq!(sample.select::<N3f1, _>(4, |_| true, |r| *r), Some(30));
    }

    #[test]
    fn reset_clears_replies_reservations_and_floor() {
        let mut sample = Sample::new();
        assert!(sample.reserve(1));
        sample.record(2, 20);
        sample.record(3, 15);
        assert_eq!(sample.select::<N3f1, _>(4, |_| true, |r| *r), Some(20));
        sample.reset();
        assert!(sample.floor().is_none());
        assert_eq!(sample.replies().count(), 0);
        assert!(sample.awaits(&1));
        assert!(sample.awaits(&2));
        assert!(sample.awaits(&3));
        sample.record(1, 10);
        assert_eq!(sample.select::<N3f1, _>(4, |_| true, |r| *r), None);
        sample.record(2, 5);
        assert_eq!(sample.select::<N3f1, _>(4, |_| true, |r| *r), Some(10));
    }
}

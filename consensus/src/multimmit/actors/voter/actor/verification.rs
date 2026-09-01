//! Verification jobs waiting for worker capacity.
//!
//! View-critical jobs drain ahead of bulk header and availability work: the finalization path
//! waits on vote and certificate verdicts, while bulk verdicts only feed eligibility. The drain
//! still interleaves, so a stream of forged certificates cannot starve bulk verification.

use super::{DigestOf, VoterTypes};
use crate::{multimmit::machine::VerifyJob, types::Round};
use std::{collections::VecDeque, time::SystemTime};
use tracing::Span;

/// Fast jobs tried before each bulk job in one drain.
///
/// View-critical artifacts are the most forgeable class (self-certifying certificates skip the
/// future-view gate before verification), so an exhaustive fast drain would let one peer's forged
/// certificate stream starve header and availability verification entirely.
const FAST_DRAIN: usize = 4;

/// The queue a verification job waits in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Urgency {
    /// The job carries view progress and leads the drain.
    Critical,
    /// Header and availability work.
    Bulk,
}

/// A machine-issued verification job waiting for worker capacity.
pub(crate) struct PendingVerification<T: VoterTypes> {
    pub(crate) span: Span,
    pub(crate) root: Span,
    pub(crate) round: Round,
    pub(crate) job: VerifyJob<T::Variant, DigestOf<T>>,
    pub(crate) queued_at: SystemTime,
}

impl<T: VoterTypes> PendingVerification<T> {
    /// Returns the queue this job waits in.
    pub(crate) fn urgency(&self) -> Urgency {
        if self.job.view_critical() {
            Urgency::Critical
        } else {
            Urgency::Bulk
        }
    }
}

/// Bounded fast and bulk queues of jobs waiting for worker capacity.
pub(crate) struct VerificationQueue<T> {
    fast: VecDeque<T>,
    bulk: VecDeque<T>,
    limit: usize,
}

impl<T> VerificationQueue<T> {
    /// Creates empty queues holding at most `limit` jobs together.
    pub(crate) const fn new(limit: usize) -> Self {
        Self {
            fast: VecDeque::new(),
            bulk: VecDeque::new(),
            limit,
        }
    }

    /// Returns whether no job is waiting.
    pub(crate) fn is_empty(&self) -> bool {
        self.fast.is_empty() && self.bulk.is_empty()
    }

    /// Appends `item` to the queue for `urgency`, or returns it when both queues are full.
    pub(crate) fn push(&mut self, item: T, urgency: Urgency) -> Result<(), T> {
        if self.fast.len() + self.bulk.len() >= self.limit {
            return Err(item);
        }
        match urgency {
            Urgency::Critical => self.fast.push_back(item),
            Urgency::Bulk => self.bulk.push_back(item),
        }
        Ok(())
    }

    /// Starts one drain over the jobs waiting now.
    pub(crate) fn pass(&self) -> Pass {
        Pass {
            fast: self.fast.len(),
            bulk: self.bulk.len(),
            lead: 0,
            bulk_due: false,
            from: Urgency::Critical,
        }
    }

    /// Drops every waiting job.
    pub(crate) fn clear(&mut self) {
        self.fast.clear();
        self.bulk.clear();
    }
}

/// One drain over the jobs that were waiting when it started.
///
/// Each round tries up to [`FAST_DRAIN`] fast jobs, then one bulk job, until every job waiting at
/// the start was tried once. A job that still does not fit goes back to the tail of its queue.
pub(crate) struct Pass {
    fast: usize,
    bulk: usize,
    lead: usize,
    bulk_due: bool,
    from: Urgency,
}

impl Pass {
    /// Removes the next job to try, or returns `None` when the drain is complete.
    pub(crate) fn next<T>(&mut self, queue: &mut VerificationQueue<T>) -> Option<T> {
        loop {
            if self.lead > 0 {
                self.lead -= 1;
                self.fast -= 1;
                self.from = Urgency::Critical;
                return Some(
                    queue
                        .fast
                        .pop_front()
                        .expect("the pass length came from this queue"),
                );
            }
            if self.bulk_due {
                self.bulk_due = false;
                if self.bulk > 0 {
                    self.bulk -= 1;
                    self.from = Urgency::Bulk;
                    return Some(
                        queue
                            .bulk
                            .pop_front()
                            .expect("the pass length came from this queue"),
                    );
                }
            }
            if self.fast == 0 && self.bulk == 0 {
                return None;
            }
            self.lead = self.fast.min(FAST_DRAIN);
            self.bulk_due = true;
        }
    }

    /// Returns the job last taken by [`Self::next`] to the tail of its queue.
    pub(crate) fn defer<T>(&self, queue: &mut VerificationQueue<T>, item: T) {
        match self.from {
            Urgency::Critical => queue.fast.push_back(item),
            Urgency::Bulk => queue.bulk.push_back(item),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drains `queue`, deferring every job for which `fits` is false; returns the try order.
    fn drain(queue: &mut VerificationQueue<u32>, fits: impl Fn(u32) -> bool) -> Vec<u32> {
        let mut tried = Vec::new();
        let mut pass = queue.pass();
        while let Some(job) = pass.next(queue) {
            tried.push(job);
            if !fits(job) {
                pass.defer(queue, job);
            }
        }
        tried
    }

    #[test]
    fn fast_jobs_lead_but_each_round_tries_one_bulk_job() {
        let mut queue = VerificationQueue::new(64);
        for job in 0..10 {
            queue.push(job, Urgency::Critical).unwrap();
        }
        for job in 100..103 {
            queue.push(job, Urgency::Bulk).unwrap();
        }
        let tried = drain(&mut queue, |_| true);
        assert_eq!(tried, [0, 1, 2, 3, 100, 4, 5, 6, 7, 101, 8, 9, 102]);
        assert!(queue.is_empty());
    }

    #[test]
    fn deferred_jobs_keep_their_queue_and_are_tried_once_per_pass() {
        let mut queue = VerificationQueue::new(64);
        for job in 0..2 {
            queue.push(job, Urgency::Critical).unwrap();
        }
        queue.push(100, Urgency::Bulk).unwrap();
        let tried = drain(&mut queue, |_| false);
        assert_eq!(tried, [0, 1, 100]);
        let tried = drain(&mut queue, |job| job != 1);
        assert_eq!(tried, [0, 1, 100]);
        let tried = drain(&mut queue, |_| true);
        assert_eq!(tried, [1]);
        assert!(queue.is_empty());
    }

    #[test]
    fn push_rejects_beyond_the_shared_limit() {
        let mut queue = VerificationQueue::new(2);
        queue.push(0, Urgency::Critical).unwrap();
        queue.push(1, Urgency::Bulk).unwrap();
        assert_eq!(queue.push(2, Urgency::Bulk), Err(2));
        queue.clear();
        assert!(queue.is_empty());
    }
}

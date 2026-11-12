//! Routes wakeups for Wide work between the worker groups of a registry.
//!
//! Each group runs the sleep protocol on its own counters. A Wide job is offered to one group first
//! and then to the others in cyclic order. A worker that leaves the idle state can pass the wakeup
//! on to the next group. Paired fences keep an injected job visible to every worker the walk
//! counted as idle or sleeping.

use super::{Ordering, Registry, Tag, fence};

impl Registry {
    /// Signals that a job any worker may take was queued, offering it to the workers of group
    /// `near` first and then to the other groups in cyclic order.
    ///
    /// The walk marks each visited group's jobs event counter active and stops at the first group
    /// that covers the job, through an awake idle worker when the queue was empty or otherwise by
    /// waking a sleeper.
    ///
    /// ```text
    /// wide job queued with near = 1 in a pool of three groups
    ///
    ///   +---------+  uncovered   +---------+  uncovered   +---------+
    ///   | group 1 | -----------> | group 2 | -----------> | group 0 |
    ///   +---------+              +---------+              +---------+
    ///        |                        |                        |
    ///     covered                  covered                  covered
    ///        v                        v                        v
    ///       stop                     stop                     stop
    /// ```
    ///
    /// Coverage reserves no worker, so a covering worker may take other work. On either exit from
    /// the idle loop, `work_found` wakes local sleepers first. If none wake, starting or resuming
    /// Wide work continues the chain in other groups, and so does Local work while Wide work
    /// remains queued. A worker that stays idle searches every Wide queue before sleeping.
    ///
    /// [`Self::new_injected_wide_job`] fences once before the walk reads any group's counters. That
    /// fence pairs with a sleeper's fence between registering as asleep and checking its queues,
    /// and with an idle exit's fence between decrementing the idle count and checking Wide queues.
    ///
    /// Together they keep a queued injection visible to every worker its publisher counted idle.
    /// Internal pushes use upstream's lighter protocol, since the publishing worker can pop its own
    /// jobs.
    pub(super) fn new_wide_job(&self, near: usize, queue_was_empty: bool) {
        let n_groups = self.groups.len();
        let mut uncovered = 1;
        for group in (near..n_groups).chain(0..near) {
            uncovered = self.groups[group]
                .sleep
                .new_jobs(uncovered, queue_was_empty);
            if uncovered == 0 {
                return;
            }
        }
    }

    /// Signals that a job was pushed into the Wide injector, then offers it as
    /// [`Self::new_wide_job`] does.
    #[inline]
    pub(super) fn new_injected_wide_job(&self, near: usize, queue_was_empty: bool) {
        // Pair with the sleepers' and idle exits' fences, so the job is visible to any worker
        // the walk counts as idle or sleeping.
        fence(Ordering::SeqCst);
        self.new_wide_job(near, queue_was_empty);
    }

    /// Leaves the idle state and continues the wake chain for Wide work.
    #[inline]
    pub(super) fn work_found(&self, group: usize, tag: Tag) {
        if self.groups[group].sleep.work_found() || self.groups.len() == 1 {
            return;
        }

        if tag == Tag::Local {
            // Pair with the injector's fence so an injection either sees this worker active
            // or appears in the queue check below.
            fence(Ordering::SeqCst);
            if self.injector.is_empty(self.injector.wide())
                && self
                    .thread_infos
                    .iter()
                    .all(|thread| thread.wide.is_empty())
            {
                return;
            }
        }

        self.new_wide_job((group + 1) % self.groups.len(), false);
    }

    /// Whether a job is waiting in `group`'s incoming queue or in the Wide queue.
    pub(super) fn has_injected_job(&self, group: usize) -> bool {
        !self.injector.is_empty(group) || !self.injector.is_empty(self.injector.wide())
    }
}

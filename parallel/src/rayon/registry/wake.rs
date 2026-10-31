use super::{Ordering, Registry, Tag, fence};

impl Registry {
    /// Signals that a job any worker may take was queued, offering it to the workers of group
    /// `near` first and then to the other groups in cyclic order. `injected` says whether the job
    /// went to the wide injector rather than to a worker's wide deque.
    ///
    /// Each group runs upstream's sleep protocol on its own counters. The walk marks each
    /// visited group's jobs event counter active and stops at the first group that covers the
    /// job. For an empty queue, an awake idle worker counts as coverage. Otherwise the group must
    /// wake a sleeper. `Sleep::new_jobs` reports any uncovered work to continue the walk.
    ///
    /// Coverage reserves no worker. A covering worker may take local work or resume a job whose
    /// latch was set. On either exit from the idle loop, `work_found` wakes local sleepers first.
    /// If none wake, starting or resuming wide work continues the chain in other groups. Local
    /// work continues it only while wide work remains queued. A wide transition can wake another
    /// worker after the last queued job has been taken. A worker that stays idle searches every
    /// wide queue before sleeping.
    ///
    /// An injection fences between queuing the job and reading each group's counters. A sleeper
    /// fences between registering as asleep and checking its broadcast deque, its group's
    /// injector, and the wide injector. An idle exit similarly fences between decrementing the
    /// idle count and checking wide queues for a local transition. These paired fences keep a
    /// queued injection visible when its publisher counted the worker idle. Internal pushes use
    /// upstream's lighter protocol, with the publishing worker able to pop its own jobs.
    pub(super) fn new_wide_jobs(&self, near: usize, queue_was_empty: bool, injected: bool) {
        let n_groups = self.groups.len();
        let mut uncovered = 1;
        for group in (near..n_groups).chain(0..near) {
            let sleep = &self.groups[group].sleep;
            uncovered = if injected {
                sleep.new_injected_jobs(uncovered, queue_was_empty)
            } else {
                sleep.new_internal_jobs(uncovered, queue_was_empty)
            };
            if uncovered == 0 {
                return;
            }
        }
    }

    /// Leaves the idle state and continues the wake chain for wide work.
    #[inline]
    pub(super) fn work_found(&self, group: usize, tag: Tag) {
        if self.groups[group].sleep.work_found() || self.groups.len() == 1 {
            return;
        }

        if tag == Tag::Local {
            // Pair with the injector's fence so an injection either sees this worker active
            // or appears in the queue check below.
            fence(Ordering::SeqCst);
            if self.wide_injected_jobs.is_empty()
                && self
                    .thread_infos
                    .iter()
                    .all(|thread| thread.wide.is_empty())
            {
                return;
            }
        }

        self.new_wide_jobs((group + 1) % self.groups.len(), false, false);
    }

    /// Whether a job is waiting in `group`'s injector or in the wide injector.
    pub(super) fn has_injected_job(&self, group: usize) -> bool {
        !self.groups[group].injected_jobs.is_empty() || !self.wide_injected_jobs.is_empty()
    }
}

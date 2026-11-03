use super::JobRef;
use crossbeam_utils::CachePadded;
use std::{
    collections::VecDeque,
    sync::{
        Mutex, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
};

/// The jobs waiting in each queue, in one admission order across all of them.
struct Queues {
    jobs: Box<[VecDeque<(u64, JobRef)>]>,
    next: u64,
}

/// A registry's incoming queues: one Local queue per group, then the shared Wide queue, under one
/// admission order. The empty flags support the scheduler's wake protocol without requiring the
/// queue lock.
pub(super) struct Injector {
    queues: Mutex<Queues>,

    /// Whether each queue is empty, indexed like the queues.
    empty: Box<[CachePadded<AtomicBool>]>,
}

impl Injector {
    /// Creates the Local queues of `groups` groups and the Wide queue after them.
    pub(super) fn new(groups: usize) -> Self {
        Self {
            queues: Mutex::new(Queues {
                jobs: (0..=groups).map(|_| VecDeque::new()).collect(),
                next: 0,
            }),
            empty: (0..=groups)
                .map(|_| CachePadded::new(AtomicBool::new(true)))
                .collect(),
        }
    }

    /// The index of the Wide queue.
    pub(super) const fn wide(&self) -> usize {
        self.empty.len() - 1
    }

    /// Queues a job in `queue` and returns whether that queue was empty.
    pub(super) fn push(&self, queue: usize, job: JobRef) -> bool {
        let mut queues = self.queues.lock().unwrap();

        // Assign the order and publish the job in the same critical section.
        // Exhaustion aborts before an arrival number can repeat.
        let order = queues.next;
        queues.next = order
            .checked_add(1)
            .unwrap_or_else(|| std::process::abort());
        let jobs = &mut queues.jobs[queue];
        let was_empty = jobs.is_empty();
        jobs.push_back((order, job));
        if was_empty {
            self.empty[queue].store(false, Ordering::Release);
        }
        was_empty
    }

    /// Takes the oldest job across `group`'s Local queue and the Wide queue, or declines if another
    /// thread holds the lock. The lock covers the head comparison and removal, so an older arrival
    /// cannot be skipped. Contending workers resume their work search without parking.
    pub(super) fn pop(&self, group: usize) -> Option<JobRef> {
        let wide = self.wide();
        if self.is_empty(group) && self.is_empty(wide) {
            return None;
        }

        let mut queues = match self.queues.try_lock() {
            Ok(queues) => queues,
            Err(TryLockError::WouldBlock) => return None,
            Err(TryLockError::Poisoned(error)) => panic!("{error}"),
        };
        let queue = match (queues.jobs[group].front(), queues.jobs[wide].front()) {
            (Some((local, _)), Some((wide_order, _))) if local < wide_order => group,
            (Some(_), None) => group,
            (Some(_), Some(_)) | (None, Some(_)) => wide,
            (None, None) => return None,
        };
        let jobs = &mut queues.jobs[queue];
        let (_, job) = jobs.pop_front().unwrap();
        if jobs.is_empty() {
            self.empty[queue].store(true, Ordering::Release);
        }
        Some(job)
    }

    /// Whether `queue` is empty.
    pub(super) fn is_empty(&self, queue: usize) -> bool {
        self.empty[queue].load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use crate::rayon::{ThreadPoolBuilder, Yield, registry::Placement};
    use std::{
        sync::{Arc, mpsc},
        time::Duration,
    };

    #[test]
    fn contended_admission_keeps_the_worker_available() {
        let pool = Arc::new(
            ThreadPoolBuilder::new()
                .num_threads(1)
                .group_width(1)
                .build()
                .unwrap(),
        );
        let timeout = Duration::from_secs(10);
        let (ready_tx, ready_rx) = mpsc::channel();
        let (phase_tx, phase_rx) = mpsc::channel();
        let (yielded_tx, yielded_rx) = mpsc::channel();
        let worker_pool = Arc::clone(&pool);
        pool.spawn(move || {
            ready_tx.send(()).unwrap();
            phase_rx.recv().unwrap();
            yielded_tx.send(worker_pool.yield_now()).unwrap();
            phase_rx.recv().unwrap();
        });
        ready_rx.recv_timeout(timeout).unwrap();

        let (job_tx, job_rx) = mpsc::channel();
        for (index, placement) in [Placement::Local(0), Placement::Wide { near: 0 }]
            .into_iter()
            .enumerate()
        {
            let job_tx = job_tx.clone();
            pool.spawn_in(placement, move || job_tx.send(index).unwrap());
        }

        let registry = pool.registry();
        let held = registry.injector.queues.lock().unwrap();
        phase_tx.send(()).unwrap();
        let yielded = yielded_rx.recv_timeout(timeout);
        let injector = &registry.injector;
        let jobs_remain = !injector.is_empty(0) && !injector.is_empty(injector.wide());
        drop(held);
        phase_tx.send(()).unwrap();
        let completed = [
            job_rx.recv_timeout(timeout).unwrap(),
            job_rx.recv_timeout(timeout).unwrap(),
        ];

        assert_eq!(yielded.unwrap(), Some(Yield::Idle));
        assert!(jobs_remain);
        assert_eq!(completed, [0, 1]);
    }
}

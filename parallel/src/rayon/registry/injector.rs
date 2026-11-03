use super::JobRef;
use crossbeam_utils::CachePadded;
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
};

struct Queues {
    jobs: Vec<VecDeque<(u64, JobRef)>>,
    next: u64,
}

/// An incoming queue in the registry's shared admission order. The empty flag supports the
/// scheduler's wake protocol without requiring the queue lock.
pub(super) struct Injector {
    queues: Arc<Mutex<Queues>>,
    index: usize,
    empty: CachePadded<AtomicBool>,
}

impl Injector {
    /// Creates the Local injectors and the shared Wide injector under one admission lock.
    pub(super) fn new(groups: usize) -> (Vec<Self>, Self) {
        let queues = Arc::new(Mutex::new(Queues {
            jobs: (0..=groups).map(|_| VecDeque::new()).collect(),
            next: 0,
        }));
        let mut injectors: Vec<_> = (0..=groups)
            .map(|index| Self {
                queues: Arc::clone(&queues),
                index,
                empty: CachePadded::new(AtomicBool::new(true)),
            })
            .collect();
        let wide = injectors.pop().unwrap();
        (injectors, wide)
    }

    /// Queues a job and returns whether the queue was empty.
    pub(super) fn push(&self, job: JobRef) -> bool {
        let mut queues = self.queues.lock().unwrap();

        // Assign the order and publish the job in the same critical section.
        // Exhaustion aborts before an arrival number can repeat.
        let order = queues.next;
        queues.next = order
            .checked_add(1)
            .unwrap_or_else(|| std::process::abort());
        let jobs = &mut queues.jobs[self.index];
        let was_empty = jobs.is_empty();
        jobs.push_back((order, job));
        if was_empty {
            self.empty.store(false, Ordering::Release);
        }
        was_empty
    }

    /// Takes the oldest eligible incoming job, or declines if another thread holds the lock.
    /// The shared lock covers the head comparison and removal, so an older arrival cannot be
    /// skipped. Contending workers resume their work search without parking.
    pub(super) fn pop(local: &Self, wide: &Self) -> Option<JobRef> {
        debug_assert!(Arc::ptr_eq(&local.queues, &wide.queues));
        if local.is_empty() && wide.is_empty() {
            return None;
        }

        let mut queues = match wide.queues.try_lock() {
            Ok(queues) => queues,
            Err(TryLockError::WouldBlock) => return None,
            Err(TryLockError::Poisoned(error)) => panic!("{error}"),
        };
        let take_local = match (
            queues.jobs[local.index].front(),
            queues.jobs[wide.index].front(),
        ) {
            (Some((local, _)), Some((wide, _))) => local < wide,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => return None,
        };
        let injector = if take_local { local } else { wide };
        let jobs = &mut queues.jobs[injector.index];
        let (_, job) = jobs.pop_front().unwrap();
        if jobs.is_empty() {
            injector.empty.store(true, Ordering::Release);
        }
        Some(job)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.empty.load(Ordering::Acquire)
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
        let held = registry.wide_injected_jobs.queues.lock().unwrap();
        phase_tx.send(()).unwrap();
        let yielded = yielded_rx.recv_timeout(timeout);
        let jobs_remain =
            !registry.groups[0].injected_jobs.is_empty() && !registry.wide_injected_jobs.is_empty();
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

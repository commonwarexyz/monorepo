//! Compiles the native wake routing and sleep state machine with Loom synchronization.
//!
//! Queues model release publication, acquire observation, and exclusive removal. This is
//! the boundary assumed by the sleep protocol; Crossbeam's queue metadata uses stronger orders.
//! Publication entry points are reimplemented over these queues. Queue allocation, latch setting,
//! and the worker's choice of a Local job or continuation remain covered by the native tests.
//! A Local idle exit starts after that choice, before the idle count is decremented. Running job
//! bodies are outside the model.
//!
//! The models use two or three groups, at most four threads, one wide job, and a preemption
//! bound of three. They check finite wake handoffs under eventual scheduling of runnable workers;
//! they do not model unbounded job streams or progress through blocking job bodies.

#![allow(
    clippy::duplicate_mod,
    reason = "The native and modeled modules bind different synchronization types."
)]

use crate::rayon::{
    latch::{self, AsCoreLatch, OnceLatch},
    registry::Tag,
};
use loom::{
    sync::{
        self, Arc,
        atomic::{AtomicUsize, Ordering, fence},
    },
    thread::{self as loom_thread, JoinHandle},
};

// Loom's yield prunes stale reads across the yield. Native yields have no memory
// ordering, so the sleep protocol's yields are empty steps in the model.
mod thread {
    pub(super) const fn yield_now() {}
}

#[allow(
    dead_code,
    reason = "The models exercise the sleep and wake transitions."
)]
#[path = "mod.rs"]
mod sleep;
use sleep::{IdleState, ROUNDS_UNTIL_SLEEPY, Sleep};

#[path = "../registry/wake.rs"]
mod wake;

/// Atomic publication and exclusive removal, without queue payloads or allocation.
#[derive(Default)]
struct Queue {
    jobs: AtomicUsize,
}

impl Queue {
    fn push(&self) {
        self.jobs.fetch_add(1, Ordering::Release);
    }

    fn is_empty(&self) -> bool {
        self.jobs.load(Ordering::Acquire) == 0
    }

    fn take(&self) -> bool {
        // Competing searches may observe one publication, but only one can consume it.
        let mut jobs = self.jobs.load(Ordering::Acquire);
        while jobs != 0 {
            match self.jobs.compare_exchange_weak(
                jobs,
                jobs - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(current) => jobs = current,
            }
        }
        false
    }
}

/// Local publications and sleep counters for one worker group.
struct Group {
    injected_jobs: Queue,
    sleep: Sleep,
}

/// Per-worker wide queue exposed to the shared registry code.
struct ThreadInfo {
    wide: Queue,
}

/// Queue and group state consumed by the native wake-routing methods.
struct Registry {
    groups: Vec<Group>,
    thread_infos: Vec<ThreadInfo>,
    wide_injected_jobs: Queue,
}

impl Registry {
    /// Builds the declared groups with every worker initially outside the idle loop.
    fn new(widths: &[usize]) -> Arc<Self> {
        // Group capacity includes the busy workers that the scenario never lets search.
        Arc::new(Self {
            groups: widths
                .iter()
                .map(|&width| Group {
                    injected_jobs: Queue::default(),
                    sleep: Sleep::new(width),
                })
                .collect(),
            thread_infos: (0..widths.iter().sum())
                .map(|_| ThreadInfo {
                    wide: Queue::default(),
                })
                .collect(),
            wide_injected_jobs: Queue::default(),
        })
    }

    fn inject_wide(&self, near: usize) {
        let queue_was_empty = self.wide_injected_jobs.is_empty();
        self.wide_injected_jobs.push();
        self.new_wide_jobs(near, queue_was_empty, true);
    }

    fn inject_local(&self, group: usize) {
        let group = &self.groups[group];
        let queue_was_empty = group.injected_jobs.is_empty();
        group.injected_jobs.push();
        group.sleep.new_injected_jobs(1, queue_was_empty);
    }

    fn find_work(&self, group: usize) -> Option<Tag> {
        // A worker counted as coverage for Wide work may choose a Local job first.
        if self.groups[group].injected_jobs.take() {
            Some(Tag::Local)
        } else if self.thread_infos.iter().any(|info| info.wide.take())
            || self.wide_injected_jobs.take()
        {
            Some(Tag::Wide)
        } else {
            None
        }
    }
}

fn model(f: impl Fn() + Send + Sync + 'static) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder.check(f);
}

/// Searches until one job is taken, including the native idle-exit wake handoff.
fn worker(registry: &Arc<Registry>, group: usize, offset: usize) -> JoinHandle<Tag> {
    let registry = Arc::clone(registry);
    loom_thread::spawn(move || {
        // This latch stays on one thread and is never signalled. The worker must
        // leave idle by finding work, with the sleep protocol providing any wakeup.
        let sleep = &registry.groups[group].sleep;
        let mut idle = sleep.start_looking(offset);
        let latch = OnceLatch::new();
        loop {
            if let Some(tag) = registry.find_work(group) {
                registry.work_found(group, tag);
                return tag;
            }

            // The initial rounds only yield; retain the announcement and final search.
            idle.rounds = idle.rounds.max(ROUNDS_UNTIL_SLEEPY);
            sleep.no_work_found(&mut idle, latch.as_core_latch(), || {
                registry.has_injected_job(group)
            });
        }
    })
}

/// Waits for a registered sleeper before the scenario starts its race.
fn wait_for_sleep(registry: &Registry, group: usize) {
    let sleep = &registry.groups[group].sleep;
    loop {
        if sleep.sleeping_threads() != 0 {
            return;
        }
        loom_thread::yield_now();
    }
}

/// Selects Local work but leaves the worker registered idle for a later `work_found` call.
fn selected_local(registry: &Registry, group: usize, offset: usize) -> IdleState {
    let idle = registry.groups[group].sleep.start_looking(offset);
    registry.inject_local(group);
    assert_eq!(registry.find_work(group), Some(Tag::Local));
    idle
}

/// A wide injection cannot leave its only available worker asleep.
#[test]
fn injection_races_sleep() {
    for groups in [2, 3] {
        for prior_work in [false, true] {
            model(move || {
                // The last group supplies the only worker available to take the job.
                let registry = Registry::new(&vec![1; groups]);

                // Completed work leaves the JEC active, so publication need not increment it.
                if prior_work {
                    let _idle = selected_local(&registry, groups - 1, 0);
                    registry.work_found(groups - 1, Tag::Local);
                }

                // Publish concurrently with the worker's searches and sleep transitions.
                let searching = worker(&registry, groups - 1, 0);
                registry.inject_wide(0);

                // Joining requires the worker to find and consume the injected job.
                assert_eq!(searching.join().unwrap(), Tag::Wide);
                assert!(registry.wide_injected_jobs.is_empty());
            });
        }
    }
}

/// A Local idle exit transfers concurrent wide work to an available group.
#[test]
fn injection_races_local_idle_exit() {
    for groups in [2, 3] {
        model(move || {
            // Park the remote worker, then stop the near worker between selecting
            // Local work and leaving idle. No other worker can take the wide job.
            let registry = Registry::new(&vec![1; groups]);
            let remote = worker(&registry, groups - 1, 0);
            wait_for_sleep(&registry, groups - 1);
            let _idle = selected_local(&registry, 0, 0);

            // Race the idle decrement and wide-queue check against publication.
            let leaving = {
                let registry = Arc::clone(&registry);
                loom_thread::spawn(move || registry.work_found(0, Tag::Local))
            };

            registry.inject_wide(0);
            leaving.join().unwrap();

            // Once both actions finish, the remote sleeper must have received the
            // handoff. Joining then checks that it actually consumes the job.
            assert_eq!(
                registry.groups[groups - 1].sleep.sleeping_threads(),
                0,
                "the local idle exit must hand off the injected job"
            );
            assert_eq!(remote.join().unwrap(), Tag::Wide);
            assert!(registry.wide_injected_jobs.is_empty());
        });
    }
}

/// A woken peer that chooses Local work still passes wide work to another group.
#[test]
fn injection_races_local_wake_handoff() {
    model(|| {
        // Park a peer of the near worker and a remote worker. The middle group
        // stays occupied, so wide coverage may need to pass through two Local exits.
        let registry = Registry::new(&[2, 1, 1]);
        let local = worker(&registry, 0, 1);
        let remote = worker(&registry, 2, 0);
        wait_for_sleep(&registry, 0);
        wait_for_sleep(&registry, 2);
        let _idle = selected_local(&registry, 0, 0);

        // The first worker has selected a Local job. Its peer can take the next one.
        registry.inject_local(0);

        // Race the first Local exit with publication while its peer can wake and
        // select the second Local job. Either Local exit may carry the handoff.
        let leaving = {
            let registry = Arc::clone(&registry);
            loom_thread::spawn(move || registry.work_found(0, Tag::Local))
        };
        registry.inject_wide(0);
        leaving.join().unwrap();

        // Completing Local work cannot discharge the wide job: the remote sleeper
        // must also be woken and consume it.
        assert_eq!(local.join().unwrap(), Tag::Local);
        assert_eq!(
            registry.groups[2].sleep.sleeping_threads(),
            0,
            "a local wake must retain the wide handoff obligation"
        );
        assert_eq!(remote.join().unwrap(), Tag::Wide);
        assert!(registry.wide_injected_jobs.is_empty());
    });
}

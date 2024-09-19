//! A deterministic runtime that randomly selects tasks to run based on a seed.
//!
//! # Example
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic::Executor};
//! use std::time::Duration;
//!
//! let (runner, context) = Executor::init(42, Duration::from_millis(1));
//! runner.start(async move {
//!     println!("Parent started");
//!     let result = context.spawn(async move {
//!         println!("Child started");
//!         "hello"
//!     });
//!     println!("Child result: {:?}", result.await);
//!     println!("Parent exited");
//! });
//! ```

use crate::Handle;
use futures::task::{waker_ref, ArcWake};
use rand::{prelude::SliceRandom, rngs::StdRng, RngCore, SeedableRng};
use std::{
    collections::BinaryHeap,
    future::Future,
    mem::replace,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{self, Poll, Waker},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::debug;

struct Task {
    tasks: Arc<Tasks>,

    root: bool,
    future: Mutex<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
}

impl ArcWake for Task {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.tasks.enqueue(arc_self.clone());
    }
}

struct Tasks {
    queue: Mutex<Vec<Arc<Task>>>,
}

impl Tasks {
    fn register(
        arc_self: &Arc<Self>,
        root: bool,
        future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) {
        let mut queue = arc_self.queue.lock().unwrap();
        queue.push(Arc::new(Task {
            root,
            future: Mutex::new(future),
            tasks: arc_self.clone(),
        }));
    }

    fn enqueue(&self, task: Arc<Task>) {
        let mut queue = self.queue.lock().unwrap();
        queue.push(task);
    }

    fn drain(&self) -> Vec<Arc<Task>> {
        let mut queue = self.queue.lock().unwrap();
        let len = queue.len();
        replace(&mut *queue, Vec::with_capacity(len))
    }

    fn len(&self) -> usize {
        self.queue.lock().unwrap().len()
    }
}

/// Deterministic runtime that randomly selects tasks to run based on a seed.
pub struct Executor {
    cycle: Duration,
    rng: Mutex<StdRng>,
    time: Mutex<SystemTime>,
    tasks: Arc<Tasks>,
    sleeping: Mutex<BinaryHeap<Alarm>>,
}

impl Executor {
    /// Initialize a new deterministic runtime with the given seed and cycle duration.
    ///
    /// The cycle duration determines how much time is advanced after each iteration of the event
    /// loop. This is useful to prevent starvation if some task never yields.
    pub fn init(seed: u64, cycle: Duration) -> (Runner, Context) {
        let executor = Arc::new(Self {
            cycle,
            rng: Mutex::new(StdRng::seed_from_u64(seed)),
            time: Mutex::new(UNIX_EPOCH),
            tasks: Arc::new(Tasks {
                queue: Mutex::new(Vec::new()),
            }),
            sleeping: Mutex::new(BinaryHeap::new()),
        });
        (
            Runner {
                executor: executor.clone(),
            },
            Context { executor },
        )
    }
}

/// Implementation of [`crate::Runner`] for the `deterministic` runtime.
pub struct Runner {
    executor: Arc<Executor>,
}

impl crate::Runner for Runner {
    fn start<F>(self, f: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        // Add root task to the queue
        let output = Arc::new(Mutex::new(None));
        Tasks::register(
            &self.executor.tasks,
            true,
            Box::pin({
                let output = output.clone();
                async move {
                    *output.lock().unwrap() = Some(f.await);
                }
            }),
        );

        // Process tasks until root task completes or progress stalls
        loop {
            // Snapshot available tasks
            let mut tasks = self.executor.tasks.drain();

            // Shuffle tasks
            {
                let mut rng = self.executor.rng.lock().unwrap();
                tasks.shuffle(&mut *rng);
            }

            // Run all snapshotted tasks
            //
            // This approach is more efficient than randomly selecting a task one-at-a-time
            // because it ensures we don't pull the same pending task multiple times in a row (without
            // processing a different task required for other tasks to make progress).
            for task in tasks {
                let waker = waker_ref(&task);
                let mut context = task::Context::from_waker(&waker);
                let mut future = task.future.lock().unwrap();
                if future.as_mut().poll(&mut context).is_pending() {
                    // Task is re-queued in its `wake_by_ref` implementation.
                } else if task.root {
                    // Root task completed
                    return output.lock().unwrap().take().unwrap();
                }
            }

            // Advance time by cycle
            //
            // This approach prevents starvation if some task never yields (to approximate this,
            // duration can be set to 1ns).
            let mut current;
            {
                let mut time = self.executor.time.lock().unwrap();
                *time += self.executor.cycle;
                current = *time;
            }
            debug!(
                now = current.duration_since(UNIX_EPOCH).unwrap().as_millis(),
                "time advanced",
            );

            // Skip time if there is nothing to do
            if self.executor.tasks.len() == 0 {
                let mut skip = None;
                {
                    let sleeping = self.executor.sleeping.lock().unwrap();
                    if let Some(next) = sleeping.peek() {
                        if next.time > current {
                            skip = Some(next.time);
                        }
                    }
                }
                if skip.is_some() {
                    {
                        let mut time = self.executor.time.lock().unwrap();
                        *time = skip.unwrap();
                        current = *time;
                    }
                    debug!(
                        now = current.duration_since(UNIX_EPOCH).unwrap().as_millis(),
                        "time skipped",
                    );
                }
            }

            // Wake all sleeping tasks that are ready
            let mut to_wake = Vec::new();
            let mut remaining;
            {
                let mut sleeping = self.executor.sleeping.lock().unwrap();
                while let Some(next) = sleeping.peek() {
                    if next.time <= current {
                        let sleeper = sleeping.pop().unwrap();
                        to_wake.push(sleeper.waker);
                    } else {
                        break;
                    }
                }
                remaining = sleeping.len();
            }
            for waker in to_wake {
                waker.wake();
            }

            // Account for remaining tasks
            remaining += self.executor.tasks.len();

            // If there are no tasks to run and no tasks sleeping, the executor is stalled
            // and will never finish.
            if remaining == 0 {
                panic!("runtime stalled");
            }
            debug!(remaining, "tasks remaining");
        }
    }
}

/// Implementation of [`crate::Spawner`] and [`crate::Clock`]
/// for the `deterministic` runtime.
#[derive(Clone)]
pub struct Context {
    executor: Arc<Executor>,
}

impl crate::Spawner for Context {
    fn spawn<F, T>(&self, f: F) -> Handle<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let (f, handle) = Handle::init(f);
        Tasks::register(&self.executor.tasks, false, Box::pin(f));
        handle
    }
}

struct Sleeper {
    executor: Arc<Executor>,
    time: SystemTime,
    registered: bool,
}

struct Alarm {
    time: SystemTime,
    waker: Waker,
}

impl PartialEq for Alarm {
    fn eq(&self, other: &Self) -> bool {
        self.time.eq(&other.time)
    }
}

impl Eq for Alarm {}

impl PartialOrd for Alarm {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Alarm {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse the ordering for min-heap
        other.time.cmp(&self.time)
    }
}

impl Future for Sleeper {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        {
            let current_time = *self.executor.time.lock().unwrap();
            if current_time >= self.time {
                return Poll::Ready(());
            }
        }
        if !self.registered {
            self.registered = true;
            self.executor.sleeping.lock().unwrap().push(Alarm {
                time: self.time,
                waker: cx.waker().clone(),
            });
        }
        Poll::Pending
    }
}

impl crate::Clock for Context {
    fn current(&self) -> SystemTime {
        *self.executor.time.lock().unwrap()
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
        let time = self
            .current()
            .checked_add(duration)
            .expect("overflow when setting wake time");
        Sleeper {
            executor: self.executor.clone(),

            time,
            registered: false,
        }
    }

    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static {
        Sleeper {
            executor: self.executor.clone(),

            time: deadline,
            registered: false,
        }
    }
}

impl RngCore for Context {
    fn next_u32(&mut self) -> u32 {
        self.executor.rng.lock().unwrap().next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.executor.rng.lock().unwrap().next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.executor.rng.lock().unwrap().fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.executor.rng.lock().unwrap().try_fill_bytes(dest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::run_tasks;
    use futures::task::noop_waker;

    fn run_with_seed(seed: u64) -> Vec<usize> {
        let (runner, context) = Executor::init(seed, Duration::from_millis(1));
        run_tasks(30, runner, context)
    }

    #[test]
    fn test_same_seed_same_order() {
        // Generate initial outputs
        let mut outputs = Vec::new();
        for seed in 0..1000 {
            let output = run_with_seed(seed);
            outputs.push(output);
        }

        // Ensure they match
        for seed in 0..1000 {
            let output = run_with_seed(seed);
            assert_eq!(output, outputs[seed as usize]);
        }
    }

    #[test]
    fn test_different_seeds_different_order() {
        let output1 = run_with_seed(12345);
        let output2 = run_with_seed(54321);
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_alarm_min_heap() {
        // Populate heap
        let now = SystemTime::now();
        let alarms = vec![
            Alarm {
                time: now + Duration::new(10, 0),
                waker: noop_waker(),
            },
            Alarm {
                time: now + Duration::new(5, 0),
                waker: noop_waker(),
            },
            Alarm {
                time: now + Duration::new(15, 0),
                waker: noop_waker(),
            },
            Alarm {
                time: now + Duration::new(5, 0),
                waker: noop_waker(),
            },
        ];
        let mut heap = BinaryHeap::new();
        for alarm in alarms {
            heap.push(alarm);
        }

        // Verify min-heap
        let mut sorted_times = Vec::new();
        while let Some(alarm) = heap.pop() {
            sorted_times.push(alarm.time);
        }
        assert_eq!(
            sorted_times,
            vec![
                now + Duration::new(5, 0),
                now + Duration::new(5, 0),
                now + Duration::new(10, 0),
                now + Duration::new(15, 0),
            ]
        );
    }
}

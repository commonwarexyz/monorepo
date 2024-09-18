//! A deterministic executor that randomly selects tasks to run based on a seed.
//!
//! # Example
//! ```rust
//! use commonware_executor::{utils, Executor, deterministic::Deterministic};
//!
//! let mut executor = Deterministic::new(42);
//! executor.run({
//!     let executor = executor.clone();
//!     async move {
//!         executor.spawn(async move {
//!             println!("Child started");
//!             for _ in 0..5 {
//!               // Simulate work
//!               utils::reschedule().await;
//!             }
//!             println!("Child completed");
//!         });
//!
//!         println!("Parent started");
//!         for _ in 0..3 {
//!           // Simulate work
//!           utils::reschedule().await;
//!         }
//!         println!("Parent completed");
//!     }
//! });
//! ```

use crate::{Clock, Executor};
use futures::task::{waker_ref, ArcWake};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::debug;

struct Task {
    root: bool,
    future: Mutex<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
    tasks: Arc<TaskQueue>,
}

impl ArcWake for Task {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        let mut queue = arc_self.tasks.queue.lock().unwrap();
        queue.push_back(arc_self.clone());
    }
}

struct TaskQueue {
    queue: Mutex<VecDeque<Arc<Task>>>,
}

impl TaskQueue {
    fn push(&self, task: Arc<Task>) {
        let mut queue = self.queue.lock().unwrap();
        queue.push_back(task);
    }

    fn get(&self, rng: Arc<Mutex<StdRng>>) -> Option<Arc<Task>> {
        let mut rng = rng.lock().unwrap();
        let mut queue = self.queue.lock().unwrap();
        if queue.is_empty() {
            None
        } else {
            let idx = rng.gen_range(0..queue.len());
            Some(queue.remove(idx).unwrap())
        }
    }
}

#[derive(Clone)]
pub struct Deterministic {
    rng: Arc<Mutex<StdRng>>,
    time: Arc<Mutex<SystemTime>>,
    tasks: Arc<TaskQueue>,
    sleeping: Arc<Mutex<BTreeMap<SystemTime, Vec<Waker>>>>,
}

impl Deterministic {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: Arc::new(Mutex::new(StdRng::seed_from_u64(seed))),
            time: Arc::new(Mutex::new(UNIX_EPOCH)),
            tasks: Arc::new(TaskQueue {
                queue: Mutex::new(VecDeque::new()),
            }),
            sleeping: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl Executor for Deterministic {
    fn spawn<F>(&self, f: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let task = Arc::new(Task {
            root: false,
            future: Mutex::new(Box::pin(f)),
            tasks: self.tasks.clone(),
        });
        self.tasks.push(task);
    }

    fn run<F>(&self, f: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        // Add root task to the queue
        let task = Arc::new(Task {
            root: true,
            future: Mutex::new(Box::pin(f)),
            tasks: self.tasks.clone(),
        });
        self.tasks.push(task);

        loop {
            // Run tasks until the queue is empty
            while let Some(task) = self.tasks.get(self.rng.clone()) {
                let waker = waker_ref(&task);
                let mut context = Context::from_waker(&waker);
                let mut future = task.future.lock().unwrap();
                if future.as_mut().poll(&mut context).is_pending() {
                    // Task is re-queued in its `wake_by_ref` implementation.
                } else if task.root {
                    // Root task completed
                    return;
                }
            }

            // Check to see if there are any sleeping tasks
            let mut sleeping = self.sleeping.lock().unwrap();
            if sleeping.is_empty() {
                break;
            }

            // Advance time to the next sleeping task
            let current;
            let next = sleeping.iter().next().unwrap().0;
            {
                let mut time = self.time.lock().unwrap();
                if *time < *next {
                    let old = *time;
                    *time = *next;
                    debug!(
                        old = old.duration_since(UNIX_EPOCH).unwrap().as_millis(),
                        new = time.duration_since(UNIX_EPOCH).unwrap().as_millis(),
                        "time advanced"
                    );
                }
                current = *time;
            }

            // Remove all sleeping tasks that are ready
            let mut revived = 0;
            let to_remove = sleeping
                .range(..=current)
                .map(&|(&time, _)| time)
                .collect::<Vec<_>>();
            for key in to_remove {
                let wakers = sleeping.remove(&key).unwrap();
                for waker in wakers {
                    waker.wake();
                    revived += 1;
                }
            }
            if revived > 0 {
                debug!(
                    current = current.duration_since(UNIX_EPOCH).unwrap().as_millis(),
                    revived, "tasks revived from time change"
                );
            }
        }
    }
}

struct SleepFuture {
    wake: SystemTime,
    executor: Deterministic,
    registered: bool,
}

impl Future for SleepFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let current_time = self.executor.current();
        if current_time >= self.wake {
            Poll::Ready(())
        } else {
            if !self.registered {
                {
                    let mut sleeping = self.executor.sleeping.lock().unwrap();
                    sleeping
                        .entry(self.wake)
                        .or_default()
                        .push(cx.waker().clone());
                }
                self.registered = true;
            }
            Poll::Pending
        }
    }
}

impl Clock for Deterministic {
    fn current(&self) -> SystemTime {
        *self.time.lock().unwrap()
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
        let wake = self
            .current()
            .checked_add(duration)
            .expect("overflow when setting wake time");
        SleepFuture {
            wake,
            executor: self.clone(),
            registered: false,
        }
    }

    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static {
        SleepFuture {
            wake: deadline,
            executor: self.clone(),
            registered: false,
        }
    }
}

impl RngCore for Deterministic {
    fn next_u32(&mut self) -> u32 {
        self.rng.lock().unwrap().next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.lock().unwrap().next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.lock().unwrap().fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.rng.lock().unwrap().try_fill_bytes(dest)
    }
}

pub async fn reschedule() {
    struct Reschedule {
        yielded: bool,
    }

    impl Future for Reschedule {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.yielded {
                Poll::Ready(())
            } else {
                self.yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    Reschedule { yielded: false }.await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn run_with_seed(seed: u64) -> Vec<&'static str> {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let executor = Deterministic::new(seed);
        executor.run({
            let messages = messages.clone();
            let executor = executor.clone();
            async move {
                executor.spawn(task("Task 1", messages.clone()));
                executor.spawn(task("Task 2", messages.clone()));
                executor.spawn(task("Task 3", messages.clone()));
            }
        });
        Arc::try_unwrap(messages).unwrap().into_inner().unwrap()
    }

    async fn task(name: &'static str, messages: Arc<Mutex<Vec<&'static str>>>) {
        for _ in 0..5 {
            reschedule().await;
        }
        messages.lock().unwrap().push(name);
    }

    #[test]
    fn test_same_seed_same_order() {
        // Generate initial outputs
        let mut outputs = Vec::new();
        for seed in 0..1000 {
            let output = run_with_seed(seed);
            assert_eq!(output.len(), 3);
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
    fn test_clock() {
        let executor = Deterministic::new(0);

        // Check initial time
        assert_eq!(executor.current(), SystemTime::UNIX_EPOCH);

        // Simulate sleeping task
        let sleep_duration = Duration::from_millis(10);
        executor.run({
            let executor = executor.clone();
            async move {
                executor.sleep(sleep_duration).await;
            }
        });

        // After run, time should have advanced
        let expected_time = SystemTime::UNIX_EPOCH + sleep_duration;
        assert_eq!(executor.current(), expected_time);
    }

    #[test]
    #[allow(clippy::empty_loop)]
    fn test_run_stops_when_root_task_ends() {
        let executor = Deterministic::new(0);
        executor.run({
            let executor = executor.clone();
            async move {
                executor.spawn(async { loop {} });
                executor.spawn(async { loop {} });
            }
            // Root task ends here without waiting for other tasks
        });
    }
}

//! A deterministic runtime that randomly selects tasks to run based on a seed.
//!
//! # Example
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic::{Executor, reschedule}};
//!
//! let (runner, context) = Executor::init(42);
//! runner.start(async move {
//!     context.spawn(async move {
//!         println!("Child started");
//!         for _ in 0..5 {
//!           // Simulate work
//!           reschedule().await;
//!         }
//!         println!("Child completed");
//!     });
//!
//!     println!("Parent started");
//!     for _ in 0..3 {
//!       // Simulate work
//!       reschedule().await;
//!     }
//!     println!("Parent completed");
//! });
//! ```

use futures::task::{waker_ref, ArcWake};
use rand::prelude::SliceRandom;
use rand::{rngs::StdRng, RngCore, SeedableRng};
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

pub struct Executor {
    rng: Mutex<StdRng>,
    time: Mutex<SystemTime>,
    tasks: Arc<Tasks>,
    sleeping: Mutex<BinaryHeap<Alarm>>,
}

impl Executor {
    pub fn init(seed: u64) -> (Runner, Context) {
        let e = Self {
            rng: Mutex::new(StdRng::seed_from_u64(seed)),
            time: Mutex::new(UNIX_EPOCH),
            tasks: Arc::new(Tasks {
                queue: Mutex::new(Vec::new()),
            }),
            sleeping: Mutex::new(BinaryHeap::new()),
        };
        let e = Arc::new(e);
        (
            Runner {
                executor: e.clone(),
            },
            Context { executor: e },
        )
    }
}

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

            // Run all snapshotted tasks at least once
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

            // If there are still tasks to run, try to run them again
            if self.executor.tasks.len() > 0 {
                continue;
            }

            // Check to see if there are any sleeping tasks to wake
            let mut to_wake = Vec::new();
            {
                // If there are no tasks to run and no tasks sleeping, the executor is stalled
                // and will never finish.
                let mut sleeping = self.executor.sleeping.lock().unwrap();
                if sleeping.is_empty() {
                    panic!("runtime stalled");
                }

                // Advance time to the next sleeping task.
                let current;
                let next = sleeping.peek().unwrap().time;
                {
                    let mut time = self.executor.time.lock().unwrap();
                    if *time < next {
                        let old = *time;
                        *time = next;
                        debug!(
                            old = old.duration_since(UNIX_EPOCH).unwrap().as_millis(),
                            new = next.duration_since(UNIX_EPOCH).unwrap().as_millis(),
                            "time advanced"
                        );
                    }
                    current = *time;
                }

                // Remove all sleeping tasks that are ready.
                while let Some(next) = sleeping.peek() {
                    if next.time <= current {
                        let sleeper = sleeping.pop().unwrap();
                        to_wake.push(sleeper.waker);
                    } else {
                        break;
                    }
                }
            }

            // Wake sleeping tasks.
            for waker in to_wake {
                waker.wake();
            }
        }
    }
}

#[derive(Clone)]
pub struct Context {
    executor: Arc<Executor>,
}

impl crate::Spawner for Context {
    fn spawn<F>(&self, f: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        Tasks::register(&self.executor.tasks, false, Box::pin(f));
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

pub async fn reschedule() {
    struct Reschedule {
        yielded: bool,
    }

    impl Future for Reschedule {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<()> {
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
    use crate::{Clock, Runner, Spawner};
    use futures::task::noop_waker;
    use tokio::sync::mpsc;

    fn run_with_seed(seed: u64) -> Vec<&'static str> {
        let (runner, context) = Executor::init(seed);
        runner.start(async move {
            // Randomly schedule tasks
            let (sender, mut receiver) = mpsc::unbounded_channel();
            context.spawn(task("Task 1", sender.clone()));
            context.spawn(task("Task 2", sender.clone()));
            context.spawn(task("Task 3", sender));

            // Collect output order
            let mut outputs = Vec::new();
            while let Some(message) = receiver.recv().await {
                outputs.push(message);
            }
            assert_eq!(outputs.len(), 3);
            outputs
        })
    }

    async fn task(name: &'static str, messages: mpsc::UnboundedSender<&'static str>) {
        for _ in 0..5 {
            reschedule().await;
        }
        messages.send(name).unwrap();
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
        let (runner, context) = Executor::init(0);

        // Check initial time
        assert_eq!(context.current(), SystemTime::UNIX_EPOCH);

        // Simulate sleeping task
        let sleep_duration = Duration::from_millis(10);
        runner.start(async move {
            context.sleep(sleep_duration).await;
            // After run, time should have advanced
            let expected_time = SystemTime::UNIX_EPOCH + sleep_duration;
            assert_eq!(context.current(), expected_time);
        });
    }

    #[test]
    #[allow(clippy::empty_loop)]
    fn test_run_stops_when_root_task_ends() {
        let (runner, context) = Executor::init(0);
        runner.start(async move {
            context.spawn(async { loop {} });
            context.spawn(async { loop {} });
            // Root task ends here without waiting for other tasks
        });
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
        let mut sorted_times = vec![];
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

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

use crate::{utils::reschedule, Clock, Executor};
use futures::task::{waker_ref, ArcWake};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::Context,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

struct Task {
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
}

impl Deterministic {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: Arc::new(Mutex::new(StdRng::seed_from_u64(seed))),
            time: Arc::new(Mutex::new(UNIX_EPOCH)),
            tasks: Arc::new(TaskQueue {
                queue: Mutex::new(VecDeque::new()),
            }),
        }
    }
}

impl Executor for Deterministic {
    fn spawn<F>(&self, f: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let task = Arc::new(Task {
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
        self.spawn(f);

        // Run tasks until the queue is empty
        while let Some(task) = self.tasks.get(self.rng.clone()) {
            let waker = waker_ref(&task);
            let mut context = Context::from_waker(&waker);

            let mut future = task.future.lock().unwrap();
            if future.as_mut().poll(&mut context).is_pending() {
                // Task is re-queued in its `wake_by_ref` implementation.
            }
        }
    }
}

impl Clock for Deterministic {
    fn current(&self) -> SystemTime {
        let mut time = self.time.lock().unwrap();
        let current = *time;
        *time += Duration::from_millis(1);
        current
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
        let self_clone = self.clone();
        async move {
            let end = self_clone.current() + duration;
            while self_clone.current() < end {
                reschedule().await;
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;
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
            utils::reschedule().await;
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
        let clock = Deterministic::new(0);

        // Check initial time
        assert_eq!(clock.current(), UNIX_EPOCH);

        // Check time after advancing
        assert_eq!(clock.current(), UNIX_EPOCH + Duration::from_millis(1));
    }
}
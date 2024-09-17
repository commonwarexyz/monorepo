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

use crate::Executor;
use futures::task::{waker_ref, ArcWake};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::Context,
};

struct Task {
    future: Mutex<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
    task_queue: Arc<TaskQueue>,
}

impl ArcWake for Task {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        let mut queue = arc_self.task_queue.queue.lock().unwrap();
        queue.push_back(arc_self.clone());
    }
}

struct TaskQueue {
    queue: Mutex<VecDeque<Arc<Task>>>,
}

#[derive(Clone)]
pub struct Deterministic {
    seed: u64,
    task_queue: Arc<TaskQueue>,
}

impl Deterministic {
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            task_queue: Arc::new(TaskQueue {
                queue: Mutex::new(VecDeque::new()),
            }),
        }
    }

    fn next_task(&mut self, rng: &mut StdRng) -> Option<Arc<Task>> {
        let mut queue = self.task_queue.queue.lock().unwrap();
        if queue.is_empty() {
            None
        } else {
            let idx = rng.gen_range(0..queue.len());
            Some(queue.remove(idx).unwrap())
        }
    }
}

impl Executor for Deterministic {
    fn spawn<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let task = Arc::new(Task {
            future: Mutex::new(Box::pin(future)),
            task_queue: self.task_queue.clone(),
        });
        let mut queue = self.task_queue.queue.lock().unwrap();
        queue.push_back(task);
    }

    fn run<F>(&mut self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        // Add root task to the queue
        self.spawn(future);

        // Run tasks until the queue is empty
        let mut rng = StdRng::seed_from_u64(self.seed);
        while let Some(task) = self.next_task(&mut rng) {
            let waker = waker_ref(&task);
            let mut context = Context::from_waker(&waker);

            let mut future = task.future.lock().unwrap();
            if future.as_mut().poll(&mut context).is_pending() {
                // Task is re-queued in its `wake_by_ref` implementation.
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;
    use std::sync::{Arc, Mutex};

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

    fn run_with_seed(seed: u64) -> Vec<&'static str> {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let mut executor = Deterministic::new(seed);
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
}

//! A deterministic executor that randomly selects tasks to run based on a seed.
//!
//! # Example
//! ```rust
//! use commonware_executor::{utils, Executor, deterministic::Deterministic};
//!
//! let mut executor = Deterministic::new(42);
//! executor.spawn(async move {
//!     println!("Task 1 started");
//!     for _ in 0..5 {
//!       // Simulate work
//!       utils::reschedule().await;
//!     }
//!     println!("Task 1 completed");
//! });
//! executor.spawn(async move {
//!     println!("Task 2 started");
//!     for _ in 0..5 {
//!       // Simulate work
//!       utils::reschedule().await;
//!     }
//!     println!("Task 2 completed");
//! });
//! executor.run();
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

pub struct Deterministic {
    task_queue: Arc<TaskQueue>,
    rng: StdRng,
}

impl Deterministic {
    pub fn new(seed: u64) -> Self {
        Self {
            task_queue: Arc::new(TaskQueue {
                queue: Mutex::new(VecDeque::new()),
            }),
            rng: StdRng::seed_from_u64(seed),
        }
    }

    fn next_task(&mut self) -> Option<Arc<Task>> {
        let mut queue = self.task_queue.queue.lock().unwrap();
        if queue.is_empty() {
            None
        } else {
            let idx = self.rng.gen_range(0..queue.len());
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

    fn run(&mut self) {
        while let Some(task) = self.next_task() {
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
        let seed = 12345;

        // First run
        let output1 = run_executor_with_seed(seed);

        // Second run
        let output2 = run_executor_with_seed(seed);

        assert_eq!(
            output1, output2,
            "Outputs should be the same with the same seed"
        );
    }

    #[test]
    fn test_different_seeds_different_order() {
        let seed1 = 12345;
        let seed2 = 54321;

        let output1 = run_executor_with_seed(seed1);
        let output2 = run_executor_with_seed(seed2);

        assert_ne!(
            output1, output2,
            "Outputs should differ with different seeds"
        );
    }

    #[test]
    fn test_tasks_complete() {
        let seed = 42;

        let output = run_executor_with_seed(seed);

        let expected_tasks = vec!["Task 1", "Task 2", "Task 3"];
        assert_eq!(
            output.len(),
            expected_tasks.len(),
            "All tasks should have completed"
        );

        for task_name in expected_tasks {
            assert!(
                output.contains(&task_name),
                "Output should contain {}",
                task_name
            );
        }
    }

    fn run_executor_with_seed(seed: u64) -> Vec<&'static str> {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let mut executor = Deterministic::new(seed);
        executor.spawn(task("Task 1", messages.clone()));
        executor.spawn(task("Task 2", messages.clone()));
        executor.spawn(task("Task 3", messages.clone()));
        executor.run();
        let messages = Arc::try_unwrap(messages).expect("Failed to unwrap Arc");
        messages.into_inner().expect("Failed to get messages")
    }

    async fn task(name: &'static str, messages: Arc<Mutex<Vec<&'static str>>>) {
        // Simulate work
        for _ in 0..5 {
            utils::reschedule().await;
        }
        let mut msgs = messages.lock().unwrap();
        msgs.push(name);
    }
}

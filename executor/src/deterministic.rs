//! A deterministic executor that randomly selects tasks to run based on a seed.
//!
//! # Example (Manual)
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
//!
//! # Example (Global)
//! ```rust
//! use commonware_executor::{utils, deterministic::{run, spawn}};
//!
//! run(42, async {
//!    spawn(async {
//!        println!("Task 1 started");
//!        for _ in 0..5 {
//!          // Simulate work
//!          utils::reschedule().await;
//!        }
//!        println!("Task 1 completed");
//!     });
//!     spawn(async move {
//!         println!("Task 2 started");
//!         for _ in 0..5 {
//!           // Simulate work
//!           utils::reschedule().await;
//!         }
//!         println!("Task 2 completed");
//!     });
//! });
//! ```

use crate::Executor;
use futures::task::{waker_ref, ArcWake};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{
    cell::RefCell,
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

    fn run(&mut self) {
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

thread_local! {
    static DETERMINISTIC_INSTANCE: RefCell<Option<Deterministic>> = const {RefCell::new(None)};
}

pub fn spawn<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    DETERMINISTIC_INSTANCE.with(|executor| {
        if let Some(executor) = executor.borrow().as_ref() {
            executor.spawn(future);
        } else {
            panic!("Executor not initialized.");
        }
    });
}

pub fn run<F>(seed: u64, future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    // Initialize the executor
    let mut executor = Deterministic::new(seed);
    DETERMINISTIC_INSTANCE.with(|executor_cell| {
        *executor_cell.borrow_mut() = Some(executor.clone());
    });

    // Spawn the initial future
    spawn(future);

    // Run the executor
    executor.run();

    // Clear the executor
    DETERMINISTIC_INSTANCE.with(|executor_cell| {
        *executor_cell.borrow_mut() = None;
    });
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
        let seed1 = 12345;
        let seed2 = 54321;

        let output1 = run_with_seed(seed1);
        let output2 = run_with_seed(seed2);

        assert_ne!(output1, output2);
    }

    fn run_with_seed(seed: u64) -> Vec<&'static str> {
        let messages = Arc::new(Mutex::new(Vec::new()));
        run(seed, {
            let messages = messages.clone();
            async move {
                spawn(task("Task 1", messages.clone()));
                spawn(task("Task 2", messages.clone()));
                spawn(task("Task 3", messages.clone()));
            }
        });
        let messages = Arc::try_unwrap(messages).unwrap();
        messages.into_inner().unwrap()
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

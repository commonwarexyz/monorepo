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

pub struct Executor {
    task_queue: Arc<TaskQueue>,
    rng: StdRng,
}

impl Executor {
    pub fn new(seed: u64) -> Self {
        Executor {
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

impl crate::Executor for Executor {
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

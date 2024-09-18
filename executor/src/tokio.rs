//! A non-deterministic executor based on Tokio.

use crate::{Clock, Executor};
use rand::RngCore;
use std::{
    future::Future,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::runtime::{Builder, Runtime};

#[derive(Clone)]
pub struct Tokio {
    runtime: Arc<Runtime>,
}

impl Tokio {
    pub fn new(threads: usize) -> Self {
        let runtime = Builder::new_multi_thread()
            .worker_threads(threads)
            .enable_all()
            .build()
            .expect("failed to create Tokio runtime");
        Self {
            runtime: Arc::new(runtime),
        }
    }
}

impl Executor for Tokio {
    fn spawn<F>(&self, f: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.runtime.spawn(f);
    }

    fn run<F>(&self, f: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.runtime.block_on(f);
    }
}

impl Clock for Tokio {
    fn current(&self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
        tokio::time::sleep(duration)
    }

    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static {
        let now = SystemTime::now();
        let duration_until_deadline = match deadline.duration_since(now) {
            Ok(duration) => duration,
            Err(_) => Duration::from_secs(0), // Deadline is in the past
        };
        let target_instant = tokio::time::Instant::now() + duration_until_deadline;
        tokio::time::sleep_until(target_instant)
    }
}

impl RngCore for Tokio {
    fn next_u32(&mut self) -> u32 {
        rand::thread_rng().next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        rand::thread_rng().next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand::thread_rng().fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        rand::thread_rng().try_fill_bytes(dest)
    }
}

pub async fn reschedule() {
    tokio::task::yield_now().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    async fn task(name: &'static str, messages: mpsc::UnboundedSender<&'static str>) {
        for _ in 0..5 {
            reschedule().await;
        }
        messages.send(name).unwrap();
    }

    #[test]
    fn test_executor_runs_tasks() {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let executor = Tokio::new(1);
        executor.run({
            let executor = executor.clone();
            async move {
                executor.spawn(task("Task 1", sender.clone()));
                executor.spawn(task("Task 2", sender.clone()));
                executor.spawn(task("Task 3", sender));

                let mut output = Vec::new();
                while let Some(message) = receiver.recv().await {
                    output.push(message);
                }
                assert_eq!(output.len(), 3);
            }
        });
    }

    #[test]
    fn test_clock_sleep() {
        let executor = Tokio::new(1);
        executor.run({
            let executor = executor.clone();
            async move {
                let start = executor.current();
                executor.sleep(Duration::from_millis(100)).await;
                let end = executor.current();
                assert!(end.duration_since(start).unwrap() >= Duration::from_millis(100));
            }
        });
    }
}

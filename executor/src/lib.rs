pub mod deterministic;
pub mod tokio;

use std::{
    future::Future,
    time::{Duration, SystemTime},
};

pub trait Executor: Clone + Send + 'static {
    fn spawn<F>(&self, f: F)
    where
        F: Future<Output = ()> + Send + 'static;

    fn run<F>(&self, f: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;
}
pub trait Clock: Executor {
    fn current(&self) -> SystemTime;
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static;
    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static;
}

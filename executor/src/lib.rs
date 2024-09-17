pub mod deterministic;
pub mod utils;

use std::{
    future::Future,
    time::{Duration, SystemTime},
};

pub trait Clock: Clone + Send + 'static {
    fn current(&self) -> SystemTime;
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static;
}

pub trait Executor: Clone + Send + 'static {
    fn spawn<F>(&self, f: F)
    where
        F: Future<Output = ()> + Send + 'static;

    fn run<F>(&self, f: F)
    where
        F: Future<Output = ()> + Send + 'static;
}

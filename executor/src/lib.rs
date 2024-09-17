pub mod deterministic;
pub mod utils;

use std::future::Future;

pub trait Executor: Clone {
    fn spawn<F>(&self, f: F)
    where
        F: Future<Output = ()> + Send + 'static;

    fn run<F>(&mut self, f: F)
    where
        F: Future<Output = ()> + Send + 'static;
}

pub mod deterministic;
pub mod utils;

use std::future::Future;

pub trait Executor {
    fn spawn<F>(&self, f: F)
    where
        F: Future<Output = ()> + Send + 'static;
    fn run(&mut self);
}

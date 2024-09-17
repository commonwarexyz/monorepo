pub mod deterministic;
pub mod utils;

use std::future::Future;

pub trait Clock: Clone {
    fn current(&self) -> u128;
    fn set(&self, milliseconds: u128);
    fn advance(&self, milliseconds: u128);
}

pub trait Executor: Clone {
    fn spawn<F>(&self, f: F)
    where
        F: Future<Output = ()> + Send + 'static;

    fn run<F>(&self, f: F)
    where
        F: Future<Output = ()> + Send + 'static;
}

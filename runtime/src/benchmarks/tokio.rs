//! Implements a [criterion]-compatible executor for the [tokio] runtime.

use super::context;
use crate::{tokio, Runner};
use criterion::async_executor::AsyncExecutor;
use futures::Future;

/// A [criterion]-compatible executor for the [tokio] runtime.
///
/// # Example
///
/// ```rust
/// use criterion::{criterion_group, criterion_main, Criterion, BatchSize};
/// use commonware_runtime::{Clock, benchmarks::{context, tokio}};
/// use std::time::Duration;
///
/// fn my_benchmark(c: &mut Criterion) {
///     let executor = tokio::Executor::default();
///     c.bench_function("sleep_benchmark", |b| {
///         b.to_async(&executor).iter_batched(|| (),
///         |_| async {
///             // Get the context
///             let ctx = context::get::<commonware_runtime::tokio::Context>();
///             // Use context features
///             ctx.sleep(Duration::from_micros(10)).await;
///         }, BatchSize::SmallInput);
///     });
/// }
/// ```
#[derive(Clone)]
pub struct Executor {
    cfg: tokio::Config,
}

impl Executor {
    /// Create a new bencher with the given configuration
    pub fn new(cfg: tokio::Config) -> Self {
        Self { cfg }
    }
}

impl Default for Executor {
    fn default() -> Self {
        Self::new(tokio::Config::default())
    }
}

impl AsyncExecutor for &Executor {
    fn block_on<T>(&self, future: impl Future<Output = T>) -> T {
        // Create and store our context
        let (executor, context) = tokio::Executor::init(self.cfg.clone());
        context::set(context);

        // Run the future
        let result = executor.start(future);

        // Clean up
        context::clear();

        result
    }
}

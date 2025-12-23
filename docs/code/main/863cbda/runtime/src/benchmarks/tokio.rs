//! Implements a [criterion]-compatible executor for the [tokio] runtime.

use super::context;
use crate::{tokio, Runner as _};
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
///     let executor = tokio::Runner::default();
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
pub struct Runner {
    cfg: tokio::Config,
}

impl Runner {
    /// Create a new bencher with the given configuration
    pub const fn new(cfg: tokio::Config) -> Self {
        Self { cfg }
    }
}

impl Default for Runner {
    fn default() -> Self {
        Self::new(tokio::Config::default())
    }
}

impl AsyncExecutor for &Runner {
    fn block_on<T>(&self, future: impl Future<Output = T>) -> T {
        let runner = tokio::Runner::new(self.cfg.clone());

        let result = runner.start(|ctx| {
            // Create and store our context
            context::set(ctx);

            // Run the future
            future
        });

        // Clean up
        context::clear();

        result
    }
}

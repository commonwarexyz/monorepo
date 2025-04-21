/// Criterion benchmark executor implementations.
use crate::Runner;
use criterion::async_executor::AsyncExecutor;
use futures::Future;
use std::any::Any;
use std::cell::RefCell;
use std::thread_local;

thread_local! {
    static CONTEXT: RefCell<Option<Box<dyn Any + Send>>> = RefCell::new(None);
}

/// Set the context value
fn set_context<C: Send + 'static>(context: C) {
    CONTEXT.with(|cell| {
        *cell.borrow_mut() = Some(Box::new(context));
    });
}

/// Get the context value
pub fn context<C: Send + 'static>() -> C {
    CONTEXT.with(|cell| {
        // Attempt to take the context from the thread-local storage
        let mut borrow = cell.borrow_mut();
        match borrow.take() {
            Some(context) => {
                // Convert the context back to the original type
                let context = context.downcast::<C>().expect("failed to downcast context");
                *context
            }
            None => panic!("no context set"),
        }
    })
}

/// Clear the context value
fn clear_context() {
    CONTEXT.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

/// Executor for the tokio runtime
///
/// # Example
///
/// ```rust
/// use criterion::{criterion_group, criterion_main, Criterion};
/// use commonware_runtime::criterion::{context, tokio::Executor};
/// use std::time::Duration;
///
/// fn my_benchmark(c: &mut Criterion) {
///     c.bench_function("sleep_benchmark", |b| {
///         b.to_async(Executor).run(|| async {
///             // Get the context
///             let ctx = context::<commonware_runtime::tokio::Context>();
///             // Use context features
///             ctx.sleep(Duration::from_micros(10)).await;
///         });
///     });
/// }
/// ```
#[derive(Clone)]
pub struct Executor {
    cfg: crate::tokio::Config,
}

impl AsyncExecutor for Executor {
    fn block_on<T>(&self, future: impl Future<Output = T>) -> T {
        // Create and store our context
        let (executor, context) = crate::tokio::Executor::init(self.cfg.clone());
        set_context(context);

        // Run the future
        let result = executor.start(future);

        // Clean up
        clear_context();

        result
    }
}

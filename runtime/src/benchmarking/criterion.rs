/// Criterion benchmark executor implementations.
use criterion::async_executor::AsyncExecutor;
use futures::Future;
use std::any::{Any, TypeId};
use std::cell::RefCell;
use std::collections::HashMap;
use std::thread_local;

thread_local! {
    static CONTEXT_MAP: RefCell<HashMap<TypeId, Box<dyn Any + Send>>> = RefCell::new(HashMap::new());
}

/// Set a context value of type C in the thread-local context map
fn set_context<C: Clone + Send + 'static>(context: C) {
    CONTEXT_MAP.with(|cell| {
        let mut map = cell.borrow_mut();
        map.insert(TypeId::of::<C>(), Box::new(context));
    });
}

/// Get a context value of type C from the thread-local context map
pub fn context<C: Clone + Send + 'static>() -> C {
    CONTEXT_MAP.with(|cell| {
        let map = cell.borrow();
        match map.get(&TypeId::of::<C>()) {
            Some(context) => {
                let context = context
                    .downcast_ref::<C>()
                    .expect("Context type mismatch - internal error");
                context.clone()
            }
            None => panic!(
                "No context of type {} available. Make sure you're using the correct executor.",
                std::any::type_name::<C>()
            ),
        }
    })
}

/// Clear all contexts from the thread-local context map
fn clear_contexts() {
    CONTEXT_MAP.with(|cell| {
        let mut map = cell.borrow_mut();
        map.clear();
    });
}

/// Convenience module for tokio-specific executor
pub mod tokio {
    use crate::Runner;

    use super::*;

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
    #[derive(Clone, Debug)]
    pub struct Executor;

    impl AsyncExecutor for Executor {
        fn block_on<T>(&self, future: impl Future<Output = T>) -> T {
            // Create a tokio runtime directly that supports non-Send futures
            let runtime = ::tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to build tokio runtime");

            // Create and store our context
            let (executor, context) = crate::tokio::Executor::default();
            set_context(context);

            // Run the future using tokio's runtime
            let result = executor.start(future);

            // Clean up
            clear_contexts();

            result
        }
    }
}

/// Convenience module for deterministic-specific executor
pub mod deterministic {
    use super::*;

    /// Executor for the deterministic runtime
    ///
    /// # Example
    ///
    /// ```rust
    /// use criterion::{criterion_group, criterion_main, Criterion};
    /// use commonware_runtime::criterion::{context, deterministic::Executor};
    /// use std::time::Duration;
    ///
    /// fn my_benchmark(c: &mut Criterion) {
    ///     c.bench_function("sleep_benchmark", |b| {
    ///         b.to_async(Executor::default()).run(|| async {
    ///             // Get the context
    ///             let ctx = context::<commonware_runtime::deterministic::Context>();
    ///             // Use context features
    ///             ctx.sleep(Duration::from_micros(10)).await;
    ///         });
    ///     });
    /// }
    /// ```
    #[derive(Clone, Debug)]
    pub struct Executor(pub u64);

    impl Executor {
        /// Create a new Executor with the specified seed
        pub fn new(seed: u64) -> Self {
            Self(seed)
        }
    }

    impl Default for Executor {
        fn default() -> Self {
            Self(42)
        }
    }

    impl AsyncExecutor for Executor {
        fn block_on<T>(&self, future: impl Future<Output = T>) -> T {
            // Create and store our context
            let seed = self.0;
            let (_, context, _) = crate::deterministic::Executor::seeded(seed);
            set_context(context);

            // Run the future using the futures crate's executor
            // which doesn't require futures to be Send
            let result = futures::executor::block_on(future);

            // Clean up
            clear_contexts();

            result
        }
    }
}

//! Augment the development of primitives with procedural macros.
//!
//! This crate provides:
//! - [`select!`] - Biased async select over multiple futures (requires `std` feature)
//! - [`select_loop!`] - Continuous select loop with shutdown handling (requires `std` feature)
//! - [`stability`], [`stability_mod!`], [`stability_scope!`] - API stability annotations
//! - [`test_async`], [`test_traced`], [`test_collect_traces`] - Test utilities
//! - [`test_group`] - Nextest filter group annotations

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

/// Select the first future that completes (biased by order).
///
/// This macro is powered by [tokio::select!](https://docs.rs/tokio/latest/tokio/macro.select.html)
/// in biased mode and is not bound to a particular executor or context.
///
/// # Example
///
/// ```rust
/// use std::time::Duration;
/// use futures::executor::block_on;
/// use futures_timer::Delay;
///
/// async fn task() -> usize {
///     42
/// }
///
/// block_on(async move {
///     commonware_macros::select! {
///         _ = Delay::new(Duration::from_secs(1)) => {
///             println!("timeout fired");
///         },
///         v = task() => {
///             println!("task completed with value: {}", v);
///         },
///     };
/// });
/// ```
#[cfg(feature = "std")]
pub use commonware_macros_impl::select;
/// Convenience macro to continuously [select!] over a set of futures in biased order,
/// with a required shutdown handler.
///
/// This macro automatically creates a shutdown future from the provided context and requires a
/// shutdown handler block. The shutdown future is created outside the loop, allowing it to
/// persist across iterations until shutdown is signaled. The shutdown branch is always checked
/// first (biased).
///
/// After the shutdown block is executed, the loop breaks by default. If different control flow
/// is desired (such as returning from the enclosing function), it must be handled explicitly.
///
/// # Syntax
///
/// ```rust,ignore
/// commonware_macros::select_loop! {
///     context,
///     on_start => { /* optional: runs at start of each iteration */ },
///     on_stopped => { cleanup },
///     pattern = future => block,
///     // ...
///     on_end => { /* optional: runs after non-shutdown arm completes */ },
/// }
/// ```
///
/// The order of blocks matches execution order:
/// 1. `on_start` (optional) - Runs at the start of each loop iteration, before the select.
///    Can use `continue` to skip the select or `break` to exit the loop.
/// 2. `on_stopped` (required) - The shutdown handler, executed when shutdown is signaled.
/// 3. Select arms - The futures to select over.
/// 4. `on_end` (optional) - Runs after a non-shutdown arm completes. Skipped when shutdown
///    is triggered. Useful for post-processing that should happen after each arm.
///
/// All blocks share the same lexical scope within the loop body. Variables declared in
/// `on_start` are visible in the select arms, `on_stopped`, and `on_end`. This allows
/// preparing state in `on_start` and using it throughout the iteration.
///
/// The `shutdown` variable (the future from `context.stopped()`) is accessible in the
/// shutdown block, allowing explicit cleanup such as `drop(shutdown)` before breaking or returning.
///
/// # Example
///
/// ```rust,ignore
/// async fn run(context: impl commonware_runtime::Spawner) {
///     let mut counter = 0;
///     commonware_macros::select_loop! {
///         context,
///         on_start => {
///             // Prepare state for this iteration (visible in arms and on_end)
///             let start_time = std::time::Instant::now();
///             counter += 1;
///         },
///         on_stopped => {
///             println!("shutting down after {} iterations", counter);
///             drop(shutdown);
///         },
///         msg = receiver.recv() => {
///             println!("received: {:?}", msg);
///         },
///         on_end => {
///             // Access variables from on_start
///             println!("iteration took {:?}", start_time.elapsed());
///         },
///     }
/// }
/// ```
#[cfg(feature = "std")]
pub use commonware_macros_impl::select_loop;
/// Marks an item with a stability level.
///
/// When building with `RUSTFLAGS="--cfg commonware_stability_X"`, items with stability
/// less than X are excluded. Unmarked items are always included.
///
/// See [commonware README](https://github.com/commonwarexyz/monorepo#stability) for stability level definitions.
///
/// # Example
/// ```rust,ignore
/// use commonware_macros::stability;
///
/// #[stability(BETA)]  // excluded at GAMMA, DELTA, EPSILON
/// pub struct StableApi { }
/// ```
///
/// # Limitation: `#[macro_export]` macros
///
/// Due to a Rust limitation ([rust-lang/rust#52234](https://github.com/rust-lang/rust/issues/52234)),
/// `#[macro_export]` macros cannot be placed inside `stability_scope!` or use `#[stability]`.
/// Macro-expanded `#[macro_export]` macros cannot be referenced by absolute paths.
///
/// For `#[macro_export]` macros, use manual cfg attributes instead:
/// ```rust,ignore
/// #[cfg(not(any(
///     commonware_stability_GAMMA,
///     commonware_stability_DELTA,
///     commonware_stability_EPSILON,
///     commonware_stability_RESERVED
/// )))] // BETA
/// #[macro_export]
/// macro_rules! my_macro { ... }
/// ```
pub use commonware_macros_impl::stability;
/// Marks a module with a stability level.
///
/// When building with `RUSTFLAGS="--cfg commonware_stability_N"`, modules with stability
/// less than N are excluded.
///
/// # Example
/// ```rust,ignore
/// use commonware_macros::stability_mod;
///
/// stability_mod!(BETA, pub mod stable_module);
/// ```
pub use commonware_macros_impl::stability_mod;
/// Marks all items within a scope with a stability level and optional cfg predicate.
///
/// When building with `RUSTFLAGS="--cfg commonware_stability_N"`, items with stability
/// less than N are excluded.
///
/// # Example
/// ```rust,ignore
/// use commonware_macros::stability_scope;
///
/// // Without cfg predicate
/// stability_scope!(BETA {
///     pub mod stable_module;
///     pub use crate::stable_module::Item;
/// });
///
/// // With cfg predicate
/// stability_scope!(BETA, cfg(feature = "std") {
///     pub mod std_only_module;
/// });
/// ```
///
/// # Limitation: `#[macro_export]` macros
///
/// `#[macro_export]` macros cannot be placed inside `stability_scope!` due to a Rust
/// limitation ([rust-lang/rust#52234](https://github.com/rust-lang/rust/issues/52234)).
/// Use manual cfg attributes instead. See [`stability`] for details.
pub use commonware_macros_impl::stability_scope;
/// Run a test function asynchronously.
///
/// This macro is powered by the [futures](https://docs.rs/futures) crate
/// and is not bound to a particular executor or context.
///
/// # Example
///
/// ```rust
/// #[commonware_macros::test_async]
/// async fn test_async_fn() {
///    assert_eq!(2 + 2, 4);
/// }
/// ```
pub use commonware_macros_impl::test_async;
/// Capture logs from a test run into an in-memory store.
///
/// This macro defaults to a log level of `DEBUG` on the `tracing_subscriber::fmt` layer if no level is provided.
///
/// This macro is powered by the [tracing](https://docs.rs/tracing),
/// [tracing-subscriber](https://docs.rs/tracing-subscriber), and
/// [commonware-runtime](https://docs.rs/commonware-runtime) crates.
///
/// # Note
///
/// This macro requires the resolution of the `commonware-runtime`, `tracing`, and `tracing_subscriber` crates.
///
/// # Example
/// ```rust,ignore
/// use commonware_runtime::telemetry::traces::collector::TraceStorage;
/// use tracing::{debug, info};
///
/// #[commonware_macros::test_collect_traces("INFO")]
/// fn test_info_level(traces: TraceStorage) {
///     // Filter applies to console output (FmtLayer)
///     info!("This is an info log");
///     debug!("This is a debug log (won't be shown in console output)");
///
///     // All traces are collected, regardless of level, by the CollectingLayer.
///     assert_eq!(traces.get_all().len(), 2);
/// }
/// ```
pub use commonware_macros_impl::test_collect_traces;
/// Prefix a test name with a nextest filter group.
///
/// This renames `test_some_behavior` into `test_some_behavior_<group>_`, making
/// it easy to filter tests by group postfixes in nextest.
pub use commonware_macros_impl::test_group;
/// Capture logs (based on the provided log level) from a test run using
/// [libtest's output capture functionality](https://doc.rust-lang.org/book/ch11-02-running-tests.html#showing-function-output).
///
/// This macro defaults to a log level of `DEBUG` if no level is provided.
///
/// This macro is powered by the [tracing](https://docs.rs/tracing) and
/// [tracing-subscriber](https://docs.rs/tracing-subscriber) crates.
///
/// # Example
///
/// ```rust
/// use tracing::{debug, info};
///
/// #[commonware_macros::test_traced("INFO")]
/// fn test_info_level() {
///     info!("This is an info log");
///     debug!("This is a debug log (won't be shown)");
///     assert_eq!(2 + 2, 4);
/// }
/// ```
pub use commonware_macros_impl::test_traced;

#[doc(hidden)]
#[cfg(feature = "std")]
pub mod __reexport {
    pub use tokio;
}

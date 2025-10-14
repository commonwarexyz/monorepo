//! Augment the development of primitives with procedural macros.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

/// Select the first future that completes (biased by order).
///
/// This macro is powered by the [futures](https://docs.rs/futures) crate
/// and is not bound to a particular executor or context.
///
/// # Fusing
///
/// This macro handles both the [fusing](https://docs.rs/futures/latest/futures/future/trait.FutureExt.html#method.fuse)
/// and [pinning](https://docs.rs/futures/latest/futures/macro.pin_mut.html) of (fused) futures in
/// a `select`-specific scope.
///
/// # Example
///
/// ```rust
/// use std::time::Duration;
/// use commonware_macros::select;
/// use futures::executor::block_on;
/// use futures_timer::Delay;
///
/// async fn task() -> usize {
///     42
/// }
//
/// block_on(async move {
///     select! {
///         _ = Delay::new(Duration::from_secs(1)) => {
///             println!("timeout fired");
///         },
///         v = task() => {
///             println!("task completed with value: {}", v);
///         },
///     };
/// });
/// ```
pub use commonware_proc_macros::select;

/// Run a test function asynchronously.
///
/// This macro is powered by the [futures](https://docs.rs/futures) crate
/// and is not bound to a particular executor or context.
///
/// # Example
/// ```rust
/// use commonware_macros::test_async;
///
/// #[test_async]
/// async fn test_async_fn() {
///    assert_eq!(2 + 2, 4);
/// }
/// ```
pub use commonware_proc_macros::test_async;

/// Capture logs (based on the provided log level) from a test run using
/// [libtest's output capture functionality](https://doc.rust-lang.org/book/ch11-02-running-tests.html#showing-function-output).
///
/// This macro defaults to a log level of `DEBUG` if no level is provided.
///
/// This macro is powered by the [tracing](https://docs.rs/tracing) and
/// [tracing-subscriber](https://docs.rs/tracing-subscriber) crates.
///
/// # Example
/// ```rust
/// use commonware_macros::test_traced;
/// use tracing::{debug, info};
///
/// #[test_traced("INFO")]
/// fn test_info_level() {
///     info!("This is an info log");
///     debug!("This is a debug log (won't be shown)");
///     assert_eq!(2 + 2, 4);
/// }
/// ```
pub use commonware_proc_macros::test_traced;

// Hidden from docs because these are needed for the proc macros to use 3rd
// party crates.
#[doc(hidden)]
pub use ::futures;
#[doc(hidden)]
pub use ::tracing;
#[doc(hidden)]
pub use ::tracing_subscriber;

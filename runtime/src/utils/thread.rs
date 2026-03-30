//! Helpers for resolving the configured thread stack size.

use std::{env, sync::OnceLock, thread};

/// Cached configured thread stack size.
static SYSTEM_THREAD_STACK_SIZE: OnceLock<usize> = OnceLock::new();

/// Rust's default thread stack size.
///
/// See <https://doc.rust-lang.org/std/thread/#stack-size>.
const RUST_DEFAULT_THREAD_STACK_SIZE: usize = 2 * 1024 * 1024;

/// Returns the value of the `RUST_MIN_STACK` environment variable, if set.
fn rust_min_stack() -> Option<usize> {
    env::var_os("RUST_MIN_STACK").and_then(|s| s.to_str().and_then(|s| s.parse().ok()))
}

/// Resolves the stack size to use for runtime-owned threads.
///
/// If `RUST_MIN_STACK` is set, this uses that value so runtime-owned threads
/// preserve Rust's process-wide spawned-thread override.
///
/// Otherwise, on Unix platforms other than macOS, this queries the default
/// stack size for newly created pthreads via `pthread_attr_init` and
/// `pthread_attr_getstacksize`.
///
/// On macOS, this instead uses `RLIMIT_STACK`. macOS distinguishes between the
/// process stack limit and the smaller default stack size for secondary
/// pthreads, so `pthread_attr_getstacksize` would otherwise resolve the wrong
/// default for this use case. In practice, that means preferring the larger
/// 8 MB process default over the 512 KB secondary-thread pthread default.
///
/// On other platforms, or if the platform-specific query fails, this falls back
/// to [RUST_DEFAULT_THREAD_STACK_SIZE].
pub(crate) fn system_thread_stack_size() -> usize {
    *SYSTEM_THREAD_STACK_SIZE.get_or_init(|| {
        rust_min_stack()
            .or(system_thread_stack_size_impl())
            .unwrap_or(RUST_DEFAULT_THREAD_STACK_SIZE)
    })
}

#[cfg(all(unix, not(target_os = "macos")))]
fn system_thread_stack_size_impl() -> Option<usize> {
    let mut attr = std::mem::MaybeUninit::<libc::pthread_attr_t>::uninit();

    // SAFETY: `attr` points to uninitialized storage reserved for
    // `pthread_attr_t`, exactly as required by `pthread_attr_init`.
    if unsafe { libc::pthread_attr_init(attr.as_mut_ptr()) } != 0 {
        return None;
    }

    // SAFETY: `pthread_attr_init` succeeded, so `attr` is now initialized.
    let mut attr = unsafe { attr.assume_init() };
    let mut stack_size = 0;
    // SAFETY: `attr` is a valid initialized pthread attribute object and
    // `stack_size` points to writable storage for the result.
    let get_result = unsafe { libc::pthread_attr_getstacksize(&attr, &mut stack_size) };
    // SAFETY: `attr` remains initialized until it is destroyed here.
    let destroy_result = unsafe { libc::pthread_attr_destroy(&mut attr) };

    if get_result != 0 || destroy_result != 0 || stack_size == 0 {
        return None;
    }

    Some(stack_size)
}

#[cfg(target_os = "macos")]
fn system_thread_stack_size_impl() -> Option<usize> {
    // macOS uses different defaults for the main thread and spawned threads:
    // the main thread stack is 8 MB, while secondary threads default to
    // 512 KB. We use `RLIMIT_STACK` here to avoid inheriting the smaller
    // secondary-thread default through `pthread_attr_getstacksize`.
    let mut stack_limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();

    // SAFETY: `stack_limit` points to uninitialized storage reserved for
    // `rlimit`, exactly as required by `getrlimit`.
    let limit_result = unsafe { libc::getrlimit(libc::RLIMIT_STACK, stack_limit.as_mut_ptr()) };
    if limit_result != 0 {
        return None;
    }

    // SAFETY: `getrlimit` succeeded, so `stack_limit` is initialized.
    let stack_limit = unsafe { stack_limit.assume_init() };
    if stack_limit.rlim_cur == libc::RLIM_INFINITY {
        return None;
    }

    let limit = usize::try_from(stack_limit.rlim_cur).ok()?;
    if limit == 0 {
        return None;
    }

    Some(limit)
}

#[cfg(not(unix))]
const fn system_thread_stack_size_impl() -> Option<usize> {
    None
}

/// Spawns a thread with an explicit stack size.
pub(crate) fn spawn<F, T>(stack_size: usize, f: F) -> thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    thread::Builder::new()
        .stack_size(stack_size)
        .spawn(f)
        .expect("failed to spawn thread")
}

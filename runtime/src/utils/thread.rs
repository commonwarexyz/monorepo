//! Helpers for resolving the default system thread stack size.

use std::{sync::OnceLock, thread};

/// Cached system thread stack size.
static SYSTEM_THREAD_STACK_SIZE: OnceLock<usize> = OnceLock::new();

/// Rust's default thread stack size when no explicit size is set.
///
/// See <https://doc.rust-lang.org/std/thread/#stack-size>.
pub(crate) const RUST_DEFAULT_THREAD_STACK_SIZE: usize = 2 * 1024 * 1024;

/// Returns the system thread stack size.
///
/// This uses the operating system's default spawned-thread stack size when it
/// can be queried, and otherwise falls back to Rust's default spawned-thread
/// stack size.
pub(crate) fn system_thread_stack_size() -> usize {
    *SYSTEM_THREAD_STACK_SIZE
        .get_or_init(|| system_thread_stack_size_impl().unwrap_or(RUST_DEFAULT_THREAD_STACK_SIZE))
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
    // the main thread stack is 8 MiB, while secondary threads default to
    // 512 KiB. We use `RLIMIT_STACK` here to avoid inheriting the smaller
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn test_spawn_with_system_thread_stack_size() {
        let expected = system_thread_stack_size();
        let observed = spawn(expected, || {
            let mut attr = std::mem::MaybeUninit::<libc::pthread_attr_t>::uninit();

            // SAFETY: `pthread_self` returns the current thread handle, and `attr`
            // points to uninitialized storage reserved for `pthread_attr_t`.
            let init_result =
                unsafe { libc::pthread_getattr_np(libc::pthread_self(), attr.as_mut_ptr()) };
            assert_eq!(init_result, 0, "failed to get current thread attributes");

            // SAFETY: `pthread_getattr_np` succeeded, so `attr` is now initialized.
            let mut attr = unsafe { attr.assume_init() };
            let mut stack_size = 0;

            // SAFETY: `attr` is a valid initialized pthread attribute object and
            // `stack_size` points to writable storage for the result.
            let get_result = unsafe { libc::pthread_attr_getstacksize(&attr, &mut stack_size) };
            // SAFETY: `attr` remains initialized until it is destroyed here.
            let destroy_result = unsafe { libc::pthread_attr_destroy(&mut attr) };

            assert_eq!(get_result, 0, "failed to get current thread stack size");
            assert_eq!(
                destroy_result, 0,
                "failed to destroy current thread attributes"
            );
            assert!(stack_size > 0, "current thread stack size must be positive");
            stack_size
        })
        .join()
        .expect("thread should complete successfully");

        assert_eq!(observed, expected);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_spawn_with_system_thread_stack_size() {
        let pthread_default = {
            let mut attr = std::mem::MaybeUninit::<libc::pthread_attr_t>::uninit();

            // SAFETY: `attr` points to uninitialized storage reserved for
            // `pthread_attr_t`, exactly as required by `pthread_attr_init`.
            let init_result = unsafe { libc::pthread_attr_init(attr.as_mut_ptr()) };
            assert_eq!(init_result, 0, "failed to initialize pthread attributes");

            // SAFETY: `pthread_attr_init` succeeded, so `attr` is now initialized.
            let mut attr = unsafe { attr.assume_init() };
            let mut pthread_default = 0;

            // SAFETY: `attr` is a valid initialized pthread attribute object and
            // `pthread_default` points to writable storage for the result.
            let get_result =
                unsafe { libc::pthread_attr_getstacksize(&attr, &mut pthread_default) };
            // SAFETY: `attr` remains initialized until it is destroyed here.
            let destroy_result = unsafe { libc::pthread_attr_destroy(&mut attr) };

            assert_eq!(
                get_result, 0,
                "failed to get pthread default thread stack size"
            );
            assert_eq!(
                destroy_result, 0,
                "failed to destroy pthread default attributes"
            );

            pthread_default
        };
        let expected = system_thread_stack_size();

        // On macOS, `pthread_attr_init` exposes the secondary-thread default,
        // while `system_thread_stack_size()` uses `RLIMIT_STACK` instead.
        assert!(
            expected >= pthread_default,
            "macOS system stack size should differ from the pthread secondary-thread default"
        );

        let observed = spawn(expected, || {
            // SAFETY: `pthread_self` returns the current thread handle for the
            // calling thread.
            unsafe { libc::pthread_get_stacksize_np(libc::pthread_self()) }
        })
        .join()
        .expect("thread should complete successfully");

        assert_eq!(observed, expected);
    }
}

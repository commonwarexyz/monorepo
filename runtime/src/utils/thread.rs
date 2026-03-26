//! Helpers for spawning OS threads with the platform default stack size.

use std::{sync::OnceLock, thread};

static SYSTEM_DEFAULT_STACK_SIZE: OnceLock<Option<usize>> = OnceLock::new();

/// Returns the operating system's default stack size for spawned threads when
/// that value can be queried on the current platform.
pub(crate) fn system_default_stack_size() -> Option<usize> {
    *SYSTEM_DEFAULT_STACK_SIZE.get_or_init(system_default_stack_size_impl)
}

#[cfg(unix)]
fn system_default_stack_size_impl() -> Option<usize> {
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

#[cfg(not(unix))]
const fn system_default_stack_size_impl() -> Option<usize> {
    None
}

/// Spawns a thread with the operating system's default stack size when the
/// platform exposes it. Falls back to Rust's default thread configuration.
pub(crate) fn spawn<F, T>(f: F) -> thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let mut builder = thread::Builder::new();
    if let Some(stack_size) = system_default_stack_size() {
        builder = builder.stack_size(stack_size);
    }
    builder.spawn(f).expect("failed to spawn thread")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_default_stack_size_is_positive_when_available() {
        assert!(system_default_stack_size().is_none_or(|stack_size| stack_size > 0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_spawn_uses_system_default_stack_size() {
        let expected = system_default_stack_size().expect("expected Linux default stack size");
        let observed = spawn(|| {
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
}

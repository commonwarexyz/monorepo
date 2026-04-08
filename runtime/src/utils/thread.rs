//! Helpers for resolving the configured thread stack size.

#[cfg(target_os = "linux")]
use commonware_utils::sync::Once;
use std::{env, sync::OnceLock, thread};

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
///
/// The result is cached after the first call.
pub(crate) fn system_thread_stack_size() -> usize {
    static SYSTEM_THREAD_STACK_SIZE: OnceLock<usize> = OnceLock::new();
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

/// Returns the number of available CPUs, or `None` if it cannot be determined.
///
/// The result is cached after the first call.
#[cfg(unix)]
pub fn available_cores() -> Option<usize> {
    static CORES: OnceLock<Option<usize>> = OnceLock::new();
    *CORES.get_or_init(|| {
        // SAFETY: `sysconf(_SC_NPROCESSORS_ONLN)` is a read-only query with no
        // preconditions.
        let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        if n <= 0 {
            None
        } else {
            Some(n as usize)
        }
    })
}

/// Returns the number of available CPUs, or `None` if it cannot be determined.
///
/// Always returns `None` on non-Unix platforms.
#[cfg(not(unix))]
pub const fn available_cores() -> Option<usize> {
    None
}

/// Pins the current thread to the given core.
///
/// If the CPU count cannot be queried or `sched_setaffinity` fails, a warning
/// is logged once and the thread continues unpinned.
///
/// # Panics
///
/// Panics if `core` is greater than or equal to the number of available CPUs.
#[cfg(target_os = "linux")]
pub(crate) fn pin_to_core(core: usize) {
    static WARN_CPUS: Once = Once::new();
    static WARN_AFFINITY: Once = Once::new();

    let Some(num_cores) = available_cores() else {
        WARN_CPUS.call_once(|| {
            tracing::warn!("failed to query CPU count, skipping core pinning");
        });
        return;
    };
    assert!(
        core < num_cores,
        "core {core} out of range ({num_cores} available)"
    );

    // SAFETY: `cpu_set` is zeroed and then a single valid CPU index is set.
    unsafe {
        let mut cpu_set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(core, &mut cpu_set);
        let result = libc::sched_setaffinity(
            0, // current thread
            std::mem::size_of::<libc::cpu_set_t>(),
            &cpu_set,
        );
        if result != 0 {
            WARN_AFFINITY.call_once(|| {
                tracing::warn!(core, "sched_setaffinity failed, skipping core pinning");
            });
        }
    }
}

/// Pins the current thread to the given core.
///
/// No-op on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub(crate) const fn pin_to_core(_core: usize) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn test_available_cores() {
        let n = available_cores().expect("available_cores returned None on Unix");
        assert!(n >= 1, "expected at least 1 core, got {n}");
    }

    #[cfg(not(unix))]
    #[test]
    fn test_available_cores_non_unix() {
        assert!(available_cores().is_none());
    }
}

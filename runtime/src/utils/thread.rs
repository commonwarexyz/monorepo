//! Helpers for resolving the configured thread stack size.

use commonware_utils::vec::NonEmptyVec;
use std::{env, sync::OnceLock, thread};

/// Rust's default thread stack size.
///
/// See <https://doc.rust-lang.org/std/thread/#stack-size>.
const RUST_DEFAULT_THREAD_STACK_SIZE: usize = 2 * 1024 * 1024;

/// Upper bound for affinity-mask probing and construction.
///
/// This keeps bogus CPU ids from forcing arbitrarily large allocations while
/// still leaving ample room beyond realistic machine sizes.
#[cfg(target_os = "linux")]
const MAX_AFFINITY_CPUS: usize = 1 << 20;

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

/// Attempts to spawn a thread with an explicit stack size.
pub(crate) fn try_spawn<F, T>(stack_size: usize, f: F) -> std::io::Result<thread::JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    thread::Builder::new().stack_size(stack_size).spawn(f)
}

/// Spawns a thread with an explicit stack size, panicking if thread creation fails.
///
/// # Panics
///
/// Panics if the thread cannot be created.
#[cfg(any(feature = "iouring-storage", feature = "iouring-network"))]
pub(crate) fn spawn<F, T>(stack_size: usize, f: F) -> thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    try_spawn(stack_size, f).expect("failed to spawn thread")
}

/// Returns the logical CPU ids currently allowed for the calling thread.
///
/// This queries the calling thread's affinity mask via `sched_getaffinity` and
/// returns `None` if that query fails.
#[cfg(target_os = "linux")]
pub(crate) fn available_cpus() -> Option<NonEmptyVec<usize>> {
    let word_bits = libc::c_ulong::BITS as usize;
    let mut words = 1usize;

    // Probe `sched_getaffinity` with an exponentially growing buffer until the
    // kernel either accepts it or reports a non-retryable error.
    let (mask, bytes) = loop {
        let mut mask = vec![0 as libc::c_ulong; words];
        let cpusetsize = std::mem::size_of_val(mask.as_slice());

        // SAFETY: `mask` points to writable storage for `cpusetsize` bytes, and
        // `pid == 0` targets the calling thread as documented by the syscall.
        let result = unsafe {
            libc::syscall(
                libc::SYS_sched_getaffinity,
                0,
                cpusetsize,
                mask.as_mut_ptr(),
            )
        };

        if result >= 0 {
            break (mask, result as usize);
        }

        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EINVAL) => {
                // Kernels with larger affinity masks require probing with a
                // larger buffer. Cap the probe size so invalid environments
                // cannot force unbounded growth.
                words = words.checked_mul(2)?;
                if words
                    .checked_mul(word_bits)
                    .is_none_or(|bits| bits > MAX_AFFINITY_CPUS)
                {
                    return None;
                }
            }
            _ => return None,
        }
    };

    let mut cpus = Vec::new();

    // `sched_getaffinity` reports how many bytes of the mask are meaningful.
    // Walk that returned bitset and collect the enabled logical CPU ids.
    for cpu in 0..(bytes * 8) {
        let index = cpu / word_bits;
        let offset = cpu % word_bits;
        if (mask[index] & ((1 as libc::c_ulong) << offset)) != 0 {
            cpus.push(cpu);
        }
    }
    cpus.try_into().ok()
}

/// Returns the logical CPU ids currently allowed for the calling thread.
///
/// Always returns `None` on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub(crate) fn available_cpus() -> Option<NonEmptyVec<usize>> {
    None
}

/// Sets the current thread's affinity mask to the given logical CPU ids.
#[cfg(target_os = "linux")]
pub(crate) fn set_cpu_affinity(cpus: &[usize]) -> Result<(), std::io::Error> {
    let Some(max_cpu) = cpus.iter().copied().max() else {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    };
    if max_cpu >= MAX_AFFINITY_CPUS {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }

    let word_bits = libc::c_ulong::BITS as usize;
    let words = (max_cpu / word_bits)
        .checked_add(1)
        .expect("cpu bitset size overflow");
    let mut mask = vec![0 as libc::c_ulong; words];
    for &cpu in cpus {
        mask[cpu / word_bits] |= (1 as libc::c_ulong) << (cpu % word_bits);
    }
    let cpusetsize = std::mem::size_of_val(mask.as_slice());

    loop {
        // SAFETY: `mask` points to readable storage for `cpusetsize` bytes, and
        // `pid == 0` targets the calling thread as documented by the syscall.
        let result =
            unsafe { libc::syscall(libc::SYS_sched_setaffinity, 0, cpusetsize, mask.as_ptr()) };
        if result == 0 {
            return Ok(());
        }

        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            _ => return Err(err),
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn set_cpu_affinity(_cpus: &[usize]) -> Result<(), std::io::Error> {
    Err(std::io::Error::other(
        "cpu pinning is not available on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn test_available_cpus_linux() {
        assert!(
            available_cpus().is_some(),
            "expected at least one available CPU"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_set_cpu_affinity_linux() {
        std::thread::spawn(|| {
            let cpus = available_cpus().unwrap();

            let cpu = *cpus.first();
            set_cpu_affinity(&[cpu]).unwrap();
            assert_eq!(available_cpus().unwrap().into_vec(), vec![cpu]);

            let invalid_cpu = (0..=MAX_AFFINITY_CPUS)
                .find(|candidate| !cpus.contains(candidate))
                .unwrap();
            assert!(
                set_cpu_affinity(&[invalid_cpu]).is_err(),
                "expected pinning to a disallowed CPU to fail",
            );
        })
        .join()
        .unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_available_cpus_non_linux() {
        assert!(available_cpus().is_none());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_set_cpu_affinity_non_linux() {
        for cpus in [vec![0], vec![1], vec![usize::MAX]] {
            assert!(set_cpu_affinity(&cpus).is_err());
        }
    }
}

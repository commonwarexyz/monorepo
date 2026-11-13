//! Helpers for resolving the configured thread stack size and spawning runtime-owned threads.

use std::{env, io, sync::OnceLock, thread};

/// Cached configured thread stack size.
static SYSTEM_THREAD_STACK_SIZE: OnceLock<usize> = OnceLock::new();

/// Rust's default thread stack size.
///
/// See <https://doc.rust-lang.org/std/thread/#stack-size>.
const RUST_DEFAULT_THREAD_STACK_SIZE: usize = 2 * 1024 * 1024;

/// Longest thread name Linux keeps, excluding the terminating NUL.
const MAX_THREAD_NAME: usize = 15;

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
/// If the platform-specific query fails, this falls back to
/// [RUST_DEFAULT_THREAD_STACK_SIZE].
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

/// Spawns a thread with an explicit stack size and an optional name, returning the OS error
/// when the thread cannot be created. A refused thread drops `f` before this returns.
pub(crate) fn try_spawn<F, T>(
    stack_size: usize,
    name: Option<&str>,
    f: F,
) -> io::Result<thread::JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    #[cfg(test)]
    if tests::take_spawn_failure() {
        drop(f);
        return Err(io::Error::other("injected thread spawn failure"));
    }

    let mut builder = thread::Builder::new().stack_size(stack_size);
    if let Some(name) = name {
        builder = builder.name(name.to_owned());
    }
    builder.spawn(f)
}

/// Returns the name of a runtime thread created by a context labeled `label`: the label's last
/// [MAX_THREAD_NAME] bytes, or `thread` when the label is empty.
pub(crate) fn name(label: &str) -> &str {
    if label.is_empty() {
        return "thread";
    }
    let mut start = label.len().saturating_sub(MAX_THREAD_NAME);
    while !label.is_char_boundary(start) {
        start += 1;
    }
    &label[start..]
}

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::Cell;

    thread_local! {
        /// Number of upcoming [super::try_spawn] calls on this thread that fail.
        static FAIL_SPAWNS: Cell<usize> = const { Cell::new(0) };
    }

    /// Make the next `count` calls to [super::try_spawn] on this thread fail.
    pub(crate) fn fail_spawns(count: usize) {
        FAIL_SPAWNS.set(count);
    }

    /// Consume one armed failure, if any.
    pub(super) fn take_spawn_failure() -> bool {
        let remaining = FAIL_SPAWNS.get();
        if remaining == 0 {
            return false;
        }
        FAIL_SPAWNS.set(remaining - 1);
        true
    }

    #[test]
    fn test_thread_name_keeps_label_suffix() {
        assert_eq!(super::name(""), "thread");
        assert_eq!(super::name("worker"), "worker");
        assert_eq!(super::name("snapshot_decoder_x"), "pshot_decoder_x");
    }
}

//! A wrapper type for secret values that prevents accidental leakage.
//!
//! `Secret<T>` provides the following guarantees:
//! - Debug and Display always show `[REDACTED]` instead of the actual value
//! - The inner value is zeroized on drop
//! - Access to the inner value requires an explicit `expose()` call
//! - Comparisons use constant-time operations to prevent timing attacks
//!
//! # Platform-Specific Behavior
//!
//! On Unix platforms, `Secret<T>` provides additional OS-level memory
//! protection:
//! - Memory is locked to prevent swapping (mlock)
//! - Memory is marked no-access except during expose() (mprotect)
//!
//! On Linux, additional hardening is applied:
//! - `memfd_secret` (Linux 5.14+): Memory is unmapped from the kernel's direct
//!   mapping, making it inaccessible via `/proc/pid/mem` even to root. Falls
//!   back to regular mmap if unavailable.
//! - `MADV_DONTDUMP`: Prevents the secret from appearing in core dumps
//! - `MADV_WIPEONFORK`: Zeros the memory in child processes after fork
//!
//! On other platforms, `Secret<T>` provides software-only protection
//! (zeroization and redacted debug output).
//!
//! # Type Constraints
//!
//! **Important**: `Secret<T>` is designed for flat data types without pointers
//! (e.g. `[u8; N]`). It does NOT provide full protection for types with
//! indirection. Types like `Vec<T>`, `String`, or `Box<T>` will only have their
//! metadata (pointer, length, capacity) protected and zeroized, the referenced
//! data remains intact. Do not use `Secret` with types that contain pointers.
//!
//! # Security Considerations
//!
//! This module provides defense-in-depth protection but is not a security
//! boundary against privileged attackers. A determined attacker with root
//! access or kernel exploits can still potentially access secrets. The primary
//! protections are:
//! - Preventing accidental leaks via logs, debug output, or core dumps
//! - Reducing the attack surface for memory disclosure bugs
//! - Preventing secrets from persisting on disk via swap

use core::fmt::{Debug, Display, Formatter};
use ctutils::CtEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Zeroize memory at the given pointer using volatile writes.
///
/// # Safety
///
/// `ptr` must point to allocated, writable memory of at least `size_of::<T>()` bytes.
#[inline]
unsafe fn zeroize_ptr<T>(ptr: *mut T) {
    let slice = core::slice::from_raw_parts_mut(ptr as *mut u8, core::mem::size_of::<T>());
    slice.zeroize();
}

// Use protected implementation on Unix with the feature enabled
#[cfg(unix)]
mod implementation {
    use core::{
        ptr::NonNull,
        sync::atomic::{AtomicUsize, Ordering},
    };

    /// Returns the system page size.
    fn page_size() -> usize {
        // SAFETY: sysconf is safe to call with _SC_PAGESIZE
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if size <= 0 {
            4096
        } else {
            size as usize
        }
    }

    /// Returns None if memfd_secret is not available or fails.
    ///
    /// [memfd_secret]: https://man7.org/linux/man-pages/man2/memfd_secret.2.html
    #[cfg(target_os = "linux")]
    fn try_memfd_secret(size: usize) -> Option<*mut libc::c_void> {
        // memfd_secret syscall number (added in Linux 5.14)
        const SYS_MEMFD_SECRET: libc::c_long = 447;
        // SAFETY: syscall with valid syscall number, flags=0
        let fd = unsafe { libc::syscall(SYS_MEMFD_SECRET, 0 as libc::c_uint) };
        if fd < 0 {
            return None;
        }
        let fd = fd as libc::c_int;

        // SAFETY: fd is valid from successful memfd_secret call above
        let (truncate_result, ptr) = unsafe {
            let truncate_result = libc::ftruncate(fd, size as libc::off_t);
            let ptr = if truncate_result == 0 {
                libc::mmap(
                    core::ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            } else {
                libc::MAP_FAILED
            };
            libc::close(fd);
            (truncate_result, ptr)
        };

        if truncate_result != 0 || ptr == libc::MAP_FAILED {
            return None;
        }

        Some(ptr)
    }

    /// Allocates memory using [mmap] with MAP_ANONYMOUS.
    ///
    /// [mmap]: https://man7.org/linux/man-pages/man2/mmap.2.html
    fn try_mmap_anonymous(size: usize) -> Option<*mut libc::c_void> {
        // SAFETY: mmap with MAP_ANONYMOUS returns page-aligned memory or MAP_FAILED
        let ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            None
        } else {
            Some(ptr)
        }
    }

    /// Applies madvise hints to protect secret memory (Linux only).
    ///
    /// - MADV_DONTDUMP: Prevents the memory from appearing in core dumps
    /// - MADV_WIPEONFORK (non-memfd_secret only): Zeros memory in child after fork
    ///
    /// MADV_WIPEONFORK is skipped for memfd_secret allocations because:
    /// 1. memfd_secret uses MAP_SHARED, and WIPEONFORK + MAP_SHARED interaction is unclear
    /// 2. memfd_secret already provides strong isolation (removed from kernel direct map)
    #[cfg(target_os = "linux")]
    fn apply_madvise_hints(ptr: *mut libc::c_void, size: usize, is_memfd_secret: bool) {
        // MADV_DONTDUMP: Exclude from core dumps
        // This is critical - core dumps are often written to disk and may persist
        // SAFETY: ptr and size are valid from successful mmap/memfd_secret
        unsafe { libc::madvise(ptr, size, libc::MADV_DONTDUMP) };

        // MADV_WIPEONFORK (Linux 4.14+): Zero this memory in child after fork
        // Only apply to MAP_PRIVATE allocations (not memfd_secret which uses MAP_SHARED)
        if !is_memfd_secret {
            // SAFETY: ptr and size are valid from successful mmap
            unsafe { libc::madvise(ptr, size, libc::MADV_WIPEONFORK) };
        }
    }

    /// State values for the reader count state machine.
    /// - 0: Memory is protected, no readers
    /// - 1: Transition in progress (unprotecting or protecting)
    /// - n >= 2: Memory is readable with (n - 1) active readers
    const PROTECTED: usize = 0;
    const TRANSITIONING: usize = 1;

    /// Guard that manages concurrent read access to protected memory.
    ///
    /// Uses a state machine to support multiple concurrent readers:
    /// - State 0 (PROTECTED): Memory is protected
    /// - State 1 (TRANSITIONING): mprotect in progress
    /// - State n >= 2: (n-1) readers are active, memory is readable
    ///
    /// This ensures thread-safety when `Secret<T>` is shared across threads.
    struct AccessGuard<'a> {
        ptr: *mut libc::c_void,
        size: usize,
        readers: &'a AtomicUsize,
    }

    impl<'a> AccessGuard<'a> {
        /// Acquires read access to protected memory.
        ///
        /// Uses a state machine to coordinate mprotect calls:
        /// - If state is PROTECTED (0), transition to TRANSITIONING, call mprotect, then set to 2
        /// - If state is TRANSITIONING (1), spin-wait until readable
        /// - If state >= 2, increment and proceed (memory already readable)
        ///
        /// # Panics
        ///
        /// Panics if mprotect fails to unprotect the memory.
        fn acquire(ptr: *mut libc::c_void, size: usize, readers: &'a AtomicUsize) -> Self {
            loop {
                let state = readers.load(Ordering::Acquire);

                if state == PROTECTED {
                    // Try to become the thread that unprotects
                    if readers
                        .compare_exchange(
                            PROTECTED,
                            TRANSITIONING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        // We won the race, unprotect memory
                        // SAFETY: ptr points to valid mmap'd memory of the given size
                        if unsafe { libc::mprotect(ptr, size, libc::PROT_READ) } != 0 {
                            // Restore to PROTECTED before panicking. If the panic is caught,
                            // future expose() calls can retry instead of spinning on TRANSITIONING.
                            readers.store(PROTECTED, Ordering::Release);
                            panic!("mprotect failed to unprotect memory");
                        }

                        // Transition to readable state with 1 reader
                        readers.store(2, Ordering::Release);
                        break;
                    }
                    // CAS failed, another thread is transitioning, retry
                } else if state == TRANSITIONING {
                    // Another thread is calling mprotect, spin wait
                    core::hint::spin_loop();
                } else {
                    // state >= 2: memory is readable, try to increment
                    if readers
                        .compare_exchange(state, state + 1, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        break;
                    }
                    // CAS failed, state changed, retry
                }
            }

            Self { ptr, size, readers }
        }
    }

    impl Drop for AccessGuard<'_> {
        fn drop(&mut self) {
            loop {
                let state = self.readers.load(Ordering::Acquire);
                assert!(state >= 2, "invalid reader state on drop");

                if state == 2 {
                    // We're the last reader, try to transition to protecting
                    if self
                        .readers
                        .compare_exchange(2, TRANSITIONING, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        // Re-protect memory
                        // SAFETY: ptr and size are valid from the Secret that created us
                        if unsafe { libc::mprotect(self.ptr, self.size, libc::PROT_NONE) } != 0 {
                            // Restore to PROTECTED so future expose calls can retry.
                            // Memory remains readable but next expose()'s mprotect(PROT_READ)
                            // may succeed, allowing recovery.
                            self.readers.store(PROTECTED, Ordering::Release);
                            panic!("mprotect failed to re-protect memory");
                        }

                        // Transition to protected state
                        self.readers.store(PROTECTED, Ordering::Release);
                        break;
                    }
                    // CAS failed, another reader appeared, retry
                } else {
                    // state > 2: other readers exist, just decrement
                    if self
                        .readers
                        .compare_exchange(state, state - 1, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        break;
                    }
                    // CAS failed, state changed, retry
                }
            }
        }
    }

    /// A wrapper for secret values with OS-level memory protection.
    ///
    /// Uses `mmap` for allocation instead of the global allocator because:
    /// - The global allocator may sub-allocate within pages, sharing pages with other data
    /// - `mmap` guarantees page-aligned, exclusively-owned memory
    /// - This ensures `mlock` and `mprotect` apply only to our secret data
    ///
    /// On Unix:
    /// - Memory is allocated via mmap (page-isolated)
    /// - Memory is locked to prevent swapping (mlock)
    /// - Memory is marked no-access except during expose() (mprotect)
    /// - Zeroized on drop
    ///
    /// Access requires explicit `expose()` call. Multiple concurrent readers are
    /// supported via atomic reference counting, memory remains readable as long
    /// as at least one reader holds access.
    ///
    /// # Type Constraints
    ///
    /// Only use with flat data types that have no pointers (e.g. `[u8; N]`).
    /// See [module-level documentation](super) for details.
    pub struct Secret<T> {
        ptr: NonNull<T>,
        size: usize,
        /// Tracks the number of concurrent readers for safe mprotect management.
        readers: AtomicUsize,
    }

    // SAFETY: Secret owns its memory and ensures proper synchronization through
    // atomic reference counting. The readers counter ensures mprotect calls are
    // coordinated: memory is unprotected when readers > 0 and protected when
    // readers == 0.
    unsafe impl<T: Send> Send for Secret<T> {}

    // SAFETY: Concurrent expose() calls are safe because AccessGuard uses atomic
    // operations to coordinate mprotect calls. Memory remains readable as long as
    // any reader holds an AccessGuard.
    unsafe impl<T: Sync> Sync for Secret<T> {}

    impl<T> Secret<T> {
        /// Creates a new `Secret` wrapping the given value.
        ///
        /// # Panics
        ///
        /// Panics if memory protection fails (allocation, mlock, or mprotect),
        /// or if `T` requires alignment greater than the system page size.
        #[inline]
        pub fn new(value: T) -> Self {
            Self::try_new(value).expect("failed to create protected secret")
        }

        /// Creates a new `Secret`, returning an error on failure.
        ///
        /// # Errors
        ///
        /// Returns an error if:
        /// - `T` requires alignment greater than the system page size
        /// - Memory allocation (mmap) fails
        /// - Memory locking (mlock) fails (except in test/unsafe-mlock mode)
        /// - Memory protection (mprotect) fails
        ///
        /// # Memory Allocation Strategy
        ///
        /// On Linux 5.14+, this function first attempts to use `memfd_secret` which
        /// provides stronger isolation (memory is unmapped from kernel direct mapping).
        /// If unavailable, it falls back to regular `mmap` with `MAP_ANONYMOUS`.
        pub fn try_new(value: T) -> Result<Self, &'static str> {
            let page_size = page_size();
            let type_align = core::mem::align_of::<T>();
            let type_size = core::mem::size_of::<T>();

            // Ensure T's alignment doesn't exceed page size (mmap returns page-aligned memory)
            if type_align > page_size {
                return Err("type alignment exceeds page size");
            }

            // Round up to page boundary (minimum one page)
            let size = type_size.max(1).next_multiple_of(page_size);

            // Try memfd_secret first on Linux (provides stronger kernel-level isolation)
            // Falls back to regular mmap if memfd_secret is unavailable
            #[cfg(target_os = "linux")]
            let (ptr, is_memfd_secret) = try_memfd_secret(size).map_or_else(
                || (try_mmap_anonymous(size), false),
                |ptr| (Some(ptr), true),
            );

            #[cfg(not(target_os = "linux"))]
            let ptr = try_mmap_anonymous(size);

            let Some(ptr) = ptr else {
                return Err("memory allocation failed");
            };

            // Apply madvise hints for additional protection (Linux only)
            #[cfg(target_os = "linux")]
            apply_madvise_hints(ptr, size, is_memfd_secret);

            let ptr = ptr as *mut T;

            // SAFETY: ptr is valid and properly aligned (mmap returns page-aligned memory,
            // and we verified type_align <= page_size above)
            unsafe { core::ptr::write(ptr, value) };

            // SAFETY: ptr points to valid mmap'd memory of size `size`
            // In unsafe-mlock mode (tests/benchmarks), we continue even if mlock fails.
            // The memory will still be protected via mprotect, just not pinned in RAM.
            if unsafe { libc::mlock(ptr as *const libc::c_void, size) } != 0 {
                // SAFETY: ptr points to valid T, drop then zeroize before freeing
                //         ptr and size match the mmap above
                #[cfg(not(any(test, feature = "unsafe-mlock")))]
                unsafe {
                    core::ptr::drop_in_place(ptr);
                    super::zeroize_ptr(ptr);
                    libc::munmap(ptr as *mut libc::c_void, size);
                    return Err("mlock failed: memory limit exceeded. Try increasing with `ulimit -l` or check /etc/security/limits.conf");
                }
            }

            // SAFETY: ptr points to valid memory of size `size`
            if unsafe { libc::mprotect(ptr as *mut libc::c_void, size, libc::PROT_NONE) } != 0 {
                // SAFETY: cleanup on failure - drop, zeroize, unlock (if locked), and unmap
                unsafe {
                    core::ptr::drop_in_place(ptr);
                    super::zeroize_ptr(ptr);
                    libc::munlock(ptr as *const libc::c_void, size);
                    libc::munmap(ptr as *mut libc::c_void, size);
                }
                return Err("mprotect failed");
            }

            Ok(Self {
                // SAFETY: ptr is non-null (mmap succeeded)
                ptr: unsafe { NonNull::new_unchecked(ptr) },
                size,
                readers: AtomicUsize::new(0),
            })
        }

        /// Exposes the secret value for read-only access within a closure.
        ///
        /// Memory is re-protected when all concurrent readers have finished,
        /// even if the closure panics.
        ///
        /// # Thread Safety
        ///
        /// Multiple threads can call `expose` concurrently. The memory remains
        /// readable as long as at least one reader is active.
        ///
        /// # Note
        ///
        /// The closure uses a higher-ranked trait bound (`for<'a>`) to prevent
        /// the returned value from containing references to the secret data.
        /// This ensures the reference cannot escape the closure scope. However,
        /// this does not prevent copying or cloning the secret value within
        /// the closure (e.g., `secret.expose(|s| s.clone())`). Callers should
        /// avoid leaking secrets through such patterns.
        #[inline]
        pub fn expose<R>(&self, f: impl for<'a> FnOnce(&'a T) -> R) -> R {
            let _guard = AccessGuard::acquire(
                self.ptr.as_ptr() as *mut libc::c_void,
                self.size,
                &self.readers,
            );

            // SAFETY: Memory is now readable and ptr is valid
            let value = unsafe { self.ptr.as_ref() };
            f(value)
        }

        /// Consumes the [Secret] and returns the inner value, zeroizing the original
        /// memory location.
        ///
        /// Use this when you need to transfer ownership of the secret value (e.g.,
        /// for APIs that consume the value).
        ///
        /// # Panics
        ///
        /// Panics if mprotect fails to unprotect the memory.
        #[inline]
        pub fn expose_unwrap(self) -> T {
            let ptr = self.ptr.as_ptr();
            let size = self.size;

            // SAFETY: ptr points to valid mmap'd memory of size bytes.
            // We unprotect, read, zeroize, and clean up the mapping.
            let value = unsafe {
                // Unprotect memory for read/write access
                if libc::mprotect(
                    ptr as *mut libc::c_void,
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                ) != 0
                {
                    panic!("mprotect failed to unprotect memory in expose_unwrap");
                }

                // Read the value out
                let value = core::ptr::read(ptr);

                // Zeroize the original memory
                super::zeroize_ptr(ptr);

                // Clean up the mapping
                libc::munlock(ptr as *const libc::c_void, size);
                libc::munmap(ptr as *mut libc::c_void, size);

                value
            };

            // Prevent Drop from running (memory is already cleaned up)
            core::mem::forget(self);

            value
        }
    }

    impl<T> Drop for Secret<T> {
        fn drop(&mut self) {
            // SAFETY: self.ptr points to valid mmap'd memory of self.size bytes.
            // We unprotect, drop inner value, zeroize, unlock, and unmap in proper sequence.
            // This is safe because we have exclusive access (&mut self), no concurrent readers can exist.
            unsafe {
                // Only drop and zeroize if we successfully unprotected the memory.
                // If mprotect failed attempting to access PROT_NONE memory would cause a segfault.
                if libc::mprotect(
                    self.ptr.as_ptr() as *mut libc::c_void,
                    self.size,
                    libc::PROT_READ | libc::PROT_WRITE,
                ) == 0
                {
                    core::ptr::drop_in_place(self.ptr.as_ptr());
                    super::zeroize_ptr(self.ptr.as_ptr());
                }

                // Always clean up the mapping regardless of mprotect result
                libc::munlock(self.ptr.as_ptr() as *const libc::c_void, self.size);
                libc::munmap(self.ptr.as_ptr() as *mut libc::c_void, self.size);
            }
        }
    }
}

// Simple implementation for non-Unix platforms
#[cfg(not(unix))]
mod implementation {
    use super::zeroize_ptr;
    use core::mem::ManuallyDrop;

    /// A wrapper for secret values that prevents accidental leakage.
    ///
    /// - Debug and Display show `[REDACTED]`
    /// - Zeroized on drop
    /// - Access requires explicit `expose()` call
    ///
    /// # Type Constraints
    ///
    /// Only use with flat data types that have no pointers (e.g. `[u8; N]`).
    /// See [module-level documentation](super) for details.
    pub struct Secret<T>(ManuallyDrop<T>);

    impl<T> Secret<T> {
        /// Creates a new `Secret` wrapping the given value.
        #[inline]
        #[allow(clippy::missing_const_for_fn)]
        pub fn new(value: T) -> Self {
            Self(ManuallyDrop::new(value))
        }

        /// Exposes the secret value for read-only access within a closure.
        ///
        /// # Note
        ///
        /// The closure uses a higher-ranked trait bound (`for<'a>`) to prevent
        /// the returned value from containing references to the secret data.
        /// This ensures the reference cannot escape the closure scope. However,
        /// this does not prevent copying or cloning the secret value within
        /// the closure (e.g., `secret.expose(|s| s.clone())`). Callers should
        /// avoid leaking secrets through such patterns.
        ///
        /// Additionally, any temporaries derived from the secret (e.g.
        /// `s.as_slice()`) may leave secret data on the stack that will not be
        /// automatically zeroized. Callers should wrap such temporaries in
        /// [`zeroize::Zeroizing`] if they contain sensitive data.
        #[inline]
        pub fn expose<R>(&self, f: impl for<'a> FnOnce(&'a T) -> R) -> R {
            f(&self.0)
        }

        /// Consumes the [Secret] and returns the inner value, zeroizing the original
        /// memory location.
        ///
        /// Use this when you need to transfer ownership of the secret value (e.g.,
        /// for APIs that consume the value).
        #[inline]
        pub fn expose_unwrap(mut self) -> T {
            let ptr = &raw mut *self.0;
            // SAFETY:
            // Pointer obtained while self.0 is still initialized,
            // self.0 is initialized and we have exclusive access
            let value = unsafe { ManuallyDrop::take(&mut self.0) };

            // Prevent Secret::drop from running (would double-zeroize or double-free on panic)
            core::mem::forget(self);

            // SAFETY: uses raw pointer (not reference) to zero memory after drop
            unsafe { zeroize_ptr(ptr) };

            value
        }
    }

    impl<T> Drop for Secret<T> {
        fn drop(&mut self) {
            let ptr = &raw mut *self.0;
            // SAFETY:
            // - Pointer obtained while self.0 is still initialized
            // - ManuallyDrop::drop: self.0 is initialized and we have exclusive access
            // - zeroize_ptr: uses raw pointer (not reference) to zero memory after drop
            unsafe {
                ManuallyDrop::drop(&mut self.0);
                zeroize_ptr(ptr);
            }
        }
    }
}

pub use implementation::*;

impl<T> Debug for Secret<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

impl<T> Display for Secret<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> ZeroizeOnDrop for Secret<T> {}

impl<T: Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        self.expose(|v| Self::new(v.clone()))
    }
}

impl<T: CtEq> PartialEq for Secret<T> {
    fn eq(&self, other: &Self) -> bool {
        self.expose(|a| other.expose(|b| a.ct_eq(b).into()))
    }
}

impl<T: CtEq> Eq for Secret<T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::group::Scalar;
    use commonware_math::algebra::Random;
    use rand::rngs::OsRng;
    #[cfg(unix)]
    use std::{panic, sync::Arc, thread};

    #[test]
    fn test_debug_redacted() {
        let secret = Secret::new([1u8, 2, 3, 4]);
        assert_eq!(format!("{:?}", secret), "Secret([REDACTED])");
    }

    #[test]
    fn test_display_redacted() {
        let secret = Secret::new([1u8, 2, 3, 4]);
        assert_eq!(format!("{}", secret), "[REDACTED]");
    }

    #[test]
    fn test_expose() {
        let secret = Secret::new([1u8, 2, 3, 4]);
        secret.expose(|v| {
            assert_eq!(v, &[1u8, 2, 3, 4]);
        });
    }

    #[test]
    fn test_expose_unwrap() {
        let secret = Secret::new([1u8, 2, 3, 4]);
        let value = secret.expose_unwrap();
        assert_eq!(value, [1u8, 2, 3, 4]);
    }

    #[test]
    fn test_clone() {
        let secret = Secret::new([1u8, 2, 3, 4]);
        let cloned = secret.clone();
        secret.expose(|a| {
            cloned.expose(|b| {
                assert_eq!(a, b);
            });
        });
    }

    #[test]
    fn test_equality() {
        let s1 = Secret::new([1u8, 2, 3, 4]);
        let s2 = Secret::new([1u8, 2, 3, 4]);
        let s3 = Secret::new([5u8, 6, 7, 8]);
        assert_eq!(s1, s2);
        assert_ne!(s1, s3);
    }

    #[test]
    fn test_multiple_expose() {
        let secret = Secret::new([42u8; 32]);

        // First expose
        secret.expose(|v| {
            assert_eq!(v[0], 42);
        });

        // Second expose
        secret.expose(|v| {
            assert_eq!(v[31], 42);
        });
    }

    #[cfg(unix)]
    #[test]
    fn test_with_bls_scalar() {
        let scalar = Scalar::random(&mut OsRng);
        let secret = Secret::new(scalar);

        secret.expose(|v| {
            let _ = format!("{:?}", *v);
        });
    }

    #[cfg(unix)]
    #[test]
    fn test_expose_reprotects_on_panic() {
        let secret = Secret::new([42u8; 32]);

        // Panic inside expose - memory should still be re-protected
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            secret.expose(|_v| {
                panic!("intentional panic");
            });
        }));
        assert!(result.is_err());

        // Should be able to expose again (memory was re-protected)
        secret.expose(|v| {
            assert_eq!(v[0], 42);
        });
    }

    #[test]
    fn test_scalar_equality() {
        let scalar1 = Scalar::random(&mut OsRng);
        let scalar2 = scalar1.clone();
        let scalar3 = Scalar::random(&mut OsRng);

        let s1 = Secret::new(scalar1);
        let s2 = Secret::new(scalar2);
        let s3 = Secret::new(scalar3);

        // Same scalar should be equal
        assert_eq!(s1, s2);
        // Different scalars should (very likely) be different
        assert_ne!(s1, s3);
    }

    #[cfg(unix)]
    #[test]
    fn test_concurrent_expose() {
        let secret = Arc::new(Secret::new([42u8; 32]));
        let mut handles = vec![];

        // Spawn multiple threads that concurrently expose the secret
        for _ in 0..10 {
            let secret = Arc::clone(&secret);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    secret.expose(|v| {
                        // Verify the value is correct
                        assert_eq!(v[0], 42);
                        assert_eq!(v[31], 42);
                    });
                }
            }));
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("thread panicked");
        }

        // Verify the secret is still accessible after concurrent access
        secret.expose(|v| {
            assert_eq!(v, &[42u8; 32]);
        });
    }

    /// Test fork behavior on Linux.
    ///
    /// The behavior depends on the allocation method:
    /// - memfd_secret (MAP_SHARED): Child inherits the secret (0xDE) - this is expected
    ///   since memfd_secret's protection is against kernel access, not fork inheritance
    /// - mmap anonymous (MAP_PRIVATE + WIPEONFORK): Child sees zeroed memory (0x00)
    ///
    /// Both outcomes are valid - memfd_secret provides stronger kernel isolation,
    /// while WIPEONFORK provides fork isolation.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_fork_behavior() {
        use std::{
            io::{Read, Write},
            os::unix::net::UnixStream,
        };

        let secret = Secret::new([0xDEu8; 32]);
        secret.expose(|v| assert_eq!(v[0], 0xDE));

        let (mut parent_sock, mut child_sock) = UnixStream::pair().unwrap();

        // SAFETY: fork is safe, we handle both parent and child cases
        let pid = unsafe { libc::fork() };

        if pid == 0 {
            // Child process
            drop(parent_sock);
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| secret.expose(|v| v[0])));
            let byte = result.unwrap_or(0xFF);
            child_sock.write_all(&[byte]).unwrap();
            std::process::exit(0);
        } else {
            // Parent process
            drop(child_sock);
            let mut status = 0;
            // SAFETY: pid is valid from fork, status is valid pointer
            unsafe { libc::waitpid(pid, &mut status, 0) };

            let mut buf = [0u8; 1];
            parent_sock.read_exact(&mut buf).unwrap();

            // Valid outcomes:
            // - 0xDE: memfd_secret was used (child inherits via MAP_SHARED)
            // - 0x00: mmap was used with WIPEONFORK (child sees zeroed memory)
            // - 0xFF: access failed in child
            assert!(
                buf[0] == 0xDE || buf[0] == 0x00 || buf[0] == 0xFF,
                "Unexpected value in child: {:#x}",
                buf[0]
            );

            // Parent's secret must be unchanged regardless of allocation method
            secret.expose(|v| assert_eq!(v[0], 0xDE));
        }
    }
}

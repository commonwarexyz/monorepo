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
//! On other platforms, `Secret<T>` provides software-only protection
//! (zeroization and redacted debug output).
//!
//! # Type Constraints
//!
//! When using protected memory, `Secret<T>` only provides full protection for
//! self-contained types (no heap pointers). Types like `Vec<T>` or `String`
//! will only have their metadata protected, not heap data.

use crate::bls12381::primitives::group::Scalar;
use core::{
    cmp::Ordering,
    fmt::{Debug, Display, Formatter},
};
use subtle::{ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Constant-time lexicographic comparison for equal-length byte slices.
///
/// # Panics
///
/// Panics if `a` and `b` have different lengths.
#[inline]
fn ct_cmp_bytes(a: &[u8], b: &[u8]) -> Ordering {
    assert_eq!(a.len(), b.len());

    let mut result = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        let is_eq = result.ct_eq(&0);
        result = u8::conditional_select(&result, &1, is_eq & x.ct_lt(&y));
        result = u8::conditional_select(&result, &2, is_eq & y.ct_lt(&x));
    }

    match result {
        0 => Ordering::Equal,
        1 => Ordering::Less,
        2 => Ordering::Greater,
        _ => unreachable!(),
    }
}

/// Zeroize memory at the given pointer using volatile writes.
///
/// # Safety
///
/// `ptr` must point to valid, writable memory of at least `size_of::<T>()` bytes.
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
                return Err("mmap failed");
            }

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
    use core::mem::MaybeUninit;

    /// A wrapper for secret values that prevents accidental leakage.
    ///
    /// Without OS-level protection (non-Unix):
    /// - Debug and Display show `[REDACTED]`
    /// - Zeroized on drop
    /// - Access requires explicit `expose()` call
    pub struct Secret<T>(MaybeUninit<T>);

    impl<T> Secret<T> {
        /// Creates a new `Secret` wrapping the given value.
        #[inline]
        #[allow(clippy::missing_const_for_fn)]
        pub fn new(value: T) -> Self {
            Self(MaybeUninit::new(value))
        }

        /// Creates a new `Secret`, returning an error on failure.
        ///
        /// On non-Unix platforms, this always succeeds.
        #[inline]
        pub fn try_new(value: T) -> Result<Self, &'static str> {
            Ok(Self::new(value))
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
        #[inline]
        pub fn expose<R>(&self, f: impl for<'a> FnOnce(&'a T) -> R) -> R {
            // SAFETY: self.0 is always initialized (set in new, only zeroed in drop)
            f(unsafe { self.0.assume_init_ref() })
        }
    }

    impl<T> Drop for Secret<T> {
        fn drop(&mut self) {
            // SAFETY: self.0 is initialized and we have exclusive access.
            // We drop the inner value first to run its destructor, then zeroize.
            unsafe {
                core::ptr::drop_in_place(self.0.as_mut_ptr());
                super::zeroize_ptr(self.0.as_mut_ptr());
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

impl<const N: usize> PartialEq for Secret<[u8; N]> {
    fn eq(&self, other: &Self) -> bool {
        self.expose(|a| other.expose(|b| a.ct_eq(b).into()))
    }
}

impl<const N: usize> Eq for Secret<[u8; N]> {}

impl<const N: usize> PartialOrd for Secret<[u8; N]> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize> Ord for Secret<[u8; N]> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.expose(|a| other.expose(|b| ct_cmp_bytes(a, b)))
    }
}

impl PartialEq for Secret<Scalar> {
    fn eq(&self, other: &Self) -> bool {
        self.expose(|a| other.expose(|b| a.as_slice().ct_eq(&b.as_slice()).into()))
    }
}

impl Eq for Secret<Scalar> {}

impl PartialOrd for Secret<Scalar> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Secret<Scalar> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.expose(|a| other.expose(|b| ct_cmp_bytes(&a.as_slice(), &b.as_slice())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::group::Scalar;
    use commonware_math::algebra::{Additive, Random, Ring};
    use core::cmp::Ordering;
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
    fn test_ordering() {
        // Test the specific bug case: [2, 1] vs [1, 2]
        let a = Secret::new([2u8, 1]);
        let b = Secret::new([1u8, 2]);
        assert_eq!(a.cmp(&b), Ordering::Greater); // [2, 1] > [1, 2] lexicographically

        // Additional ordering tests
        let c = Secret::new([1u8, 1]);
        let d = Secret::new([1u8, 2]);
        assert_eq!(c.cmp(&d), Ordering::Less);

        let e = Secret::new([1u8, 2]);
        let f = Secret::new([1u8, 2]);
        assert_eq!(e.cmp(&f), Ordering::Equal);

        // Single byte
        let g = Secret::new([0u8]);
        let h = Secret::new([255u8]);
        assert_eq!(g.cmp(&h), Ordering::Less);
        assert_eq!(h.cmp(&g), Ordering::Greater);
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
    fn test_partial_ord() {
        let s1 = Secret::new([1u8, 2]);
        let s2 = Secret::new([1u8, 3]);
        let s3 = Secret::new([1u8, 2]);

        assert!(s1 < s2);
        assert!(s2 > s1);
        assert!(s1 <= s3);
        assert!(s1 >= s3);

        assert_eq!(s1.partial_cmp(&s2), Some(core::cmp::Ordering::Less));
        assert_eq!(s2.partial_cmp(&s1), Some(core::cmp::Ordering::Greater));
        assert_eq!(s1.partial_cmp(&s3), Some(core::cmp::Ordering::Equal));
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

    #[test]
    fn test_scalar_ordering() {
        let zero = Scalar::zero();
        let one = Scalar::one();

        let s_zero = Secret::new(zero);
        let s_one = Secret::new(one);

        // Zero and one should compare consistently
        assert_ne!(s_zero, s_one);
        // Ordering should be deterministic
        let cmp1 = s_zero.cmp(&s_one);
        let cmp2 = s_zero.cmp(&s_one);
        assert_eq!(cmp1, cmp2);
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
}

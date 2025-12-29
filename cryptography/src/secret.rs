//! A wrapper type for secret values that prevents accidental leakage.
//!
//! # Status
//!
//! `Secret<T>` provides the following guarantees:
//! - Debug and Display always show `[REDACTED]` instead of the actual value
//! - The inner value is zeroized on drop
//! - Access to the inner value requires an explicit `expose()` call
//! - Comparisons use constant-time operations to prevent timing attacks
//!
//! # Platform-Specific Behavior
//!
//! On Unix platforms, `Secret<T>`
//! provides additional OS-level memory protection:
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

use core::cmp::Ordering;
use subtle::{ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};

/// Constant-time lexicographic comparison for byte slices.
#[inline]
fn ct_cmp_bytes(a: &[u8], b: &[u8]) -> Ordering {
    let mut result = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        let is_eq = result.ct_eq(&0);
        result = u8::conditional_select(&result, &1, is_eq & x.ct_lt(&y));
        result = u8::conditional_select(&result, &2, is_eq & y.ct_lt(&x));
    }

    match result {
        1 => Ordering::Less,
        2 => Ordering::Greater,
        _ => a.len().cmp(&b.len()),
    }
}

// Use protected implementation on Unix with the feature enabled
#[cfg(unix)]
mod implementation {
    use core::{
        cmp::Ordering,
        fmt::{Debug, Display, Formatter},
        hash::{Hash, Hasher},
        ptr::NonNull,
    };
    use subtle::ConstantTimeEq;
    use zeroize::{Zeroize, ZeroizeOnDrop};

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
    /// Access requires explicit `expose()` call which returns a guard.
    /// Memory is re-protected when the guard is dropped.
    pub struct Secret<T: Zeroize> {
        ptr: NonNull<T>,
        size: usize,
    }

    // SAFETY: Secret owns its memory and ensures proper synchronization
    // through the guard pattern. Access to the protected memory region is
    // controlled by mprotect calls that make the memory accessible only
    // during the lifetime of guard objects.
    unsafe impl<T: Zeroize + Send> Send for Secret<T> {}
    // SAFETY: Same reasoning as Send - the guard pattern ensures proper
    // synchronization of memory access.
    unsafe impl<T: Zeroize + Sync> Sync for Secret<T> {}

    impl<T: Zeroize> Secret<T> {
        /// Creates a new `Secret` wrapping the given value.
        ///
        /// # Panics
        ///
        /// Panics if memory protection fails (allocation, mlock, or mprotect).
        #[inline]
        pub fn new(value: T) -> Self {
            Self::try_new(value).expect("failed to create protected secret")
        }

        /// Creates a new `Secret`, returning an error on failure.
        #[allow(clippy::undocumented_unsafe_blocks)]
        pub fn try_new(value: T) -> Result<Self, &'static str> {
            let page_size = page_size();
            let type_size = core::mem::size_of::<T>();
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

            // SAFETY: ptr is valid and properly aligned (mmap returns page-aligned memory)
            unsafe { core::ptr::write(ptr, value) };

            // SAFETY: ptr points to valid mmap'd memory of size `size`
            // In soft-mlock mode (tests/benchmarks), we continue even if mlock fails.
            // The memory will still be protected via mprotect, just not pinned in RAM.
            if unsafe { libc::mlock(ptr as *const libc::c_void, size) } != 0 {
                #[cfg(not(any(test, feature = "soft-mlock")))]
                {
                    // SAFETY: ptr and size match the mmap above
                    unsafe { libc::munmap(ptr as *mut libc::c_void, size) };
                    return Err("mlock failed");
                }
            }

            // SAFETY: ptr points to valid memory of size `size`
            if unsafe { libc::mprotect(ptr as *mut libc::c_void, size, libc::PROT_NONE) } != 0 {
                // SAFETY: cleanup on failure - unlock (if locked) and unmap
                unsafe {
                    libc::munlock(ptr as *const libc::c_void, size);
                    libc::munmap(ptr as *mut libc::c_void, size);
                }
                return Err("mprotect failed");
            }

            Ok(Self {
                // SAFETY: ptr is non-null (mmap succeeded)
                ptr: unsafe { NonNull::new_unchecked(ptr) },
                size,
            })
        }

        /// Exposes the secret value for read-only access within a closure.
        ///
        /// Memory is re-protected immediately after the closure returns.
        #[inline]
        pub fn expose<R>(&self, f: impl FnOnce(&T) -> R) -> R {
            // SAFETY: self.ptr points to valid protected memory of self.size bytes
            let result = unsafe {
                libc::mprotect(
                    self.ptr.as_ptr() as *mut libc::c_void,
                    self.size,
                    libc::PROT_READ,
                )
            };
            assert_eq!(result, 0, "mprotect failed to unprotect memory");

            // SAFETY: Memory is now readable and ptr is valid
            let value = unsafe { self.ptr.as_ref() };
            let result = f(value);

            // SAFETY: Re-protect after use
            unsafe {
                libc::mprotect(
                    self.ptr.as_ptr() as *mut libc::c_void,
                    self.size,
                    libc::PROT_NONE,
                );
            }
            result
        }
    }

    impl<T: Zeroize> Debug for Secret<T> {
        fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
            f.write_str("[REDACTED]")
        }
    }

    impl<T: Zeroize> Display for Secret<T> {
        fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
            f.write_str("[REDACTED]")
        }
    }

    impl<T: Zeroize> Drop for Secret<T> {
        fn drop(&mut self) {
            // SAFETY: self.ptr points to valid mmap'd memory of self.size bytes.
            // We unprotect, zeroize, unlock, and unmap in proper sequence.
            // This is safe because we have exclusive access (&mut self).
            unsafe {
                libc::mprotect(
                    self.ptr.as_ptr() as *mut libc::c_void,
                    self.size,
                    libc::PROT_READ | libc::PROT_WRITE,
                );
                (*self.ptr.as_ptr()).zeroize();
                libc::munlock(self.ptr.as_ptr() as *const libc::c_void, self.size);
                libc::munmap(self.ptr.as_ptr() as *mut libc::c_void, self.size);
            }
        }
    }

    impl<T: Zeroize> ZeroizeOnDrop for Secret<T> {}

    impl<T: Zeroize + Clone> Clone for Secret<T> {
        fn clone(&self) -> Self {
            self.expose(|v| Self::new(v.clone()))
        }
    }

    impl<T: Zeroize> PartialEq for Secret<T> {
        fn eq(&self, other: &Self) -> bool {
            self.expose(|a| {
                other.expose(|b| {
                    // SAFETY: Reading raw bytes of T for constant-time comparison.
                    let (a, b) = unsafe {
                        (
                            core::slice::from_raw_parts(
                                a as *const T as *const u8,
                                core::mem::size_of::<T>(),
                            ),
                            core::slice::from_raw_parts(
                                b as *const T as *const u8,
                                core::mem::size_of::<T>(),
                            ),
                        )
                    };
                    a.ct_eq(b).into()
                })
            })
        }
    }

    impl<T: Zeroize> Eq for Secret<T> {}

    impl<T: Zeroize + Hash> Hash for Secret<T> {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.expose(|v| v.hash(state));
        }
    }

    impl<T: Zeroize> PartialOrd for Secret<T> {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl<T: Zeroize> Ord for Secret<T> {
        fn cmp(&self, other: &Self) -> Ordering {
            self.expose(|a| {
                other.expose(|b| {
                    // SAFETY: Reading raw bytes of T for constant-time comparison.
                    let (a, b) = unsafe {
                        (
                            core::slice::from_raw_parts(
                                a as *const T as *const u8,
                                core::mem::size_of::<T>(),
                            ),
                            core::slice::from_raw_parts(
                                b as *const T as *const u8,
                                core::mem::size_of::<T>(),
                            ),
                        )
                    };
                    super::ct_cmp_bytes(a, b)
                })
            })
        }
    }
}

// Simple implementation for non-Unix platforms
#[cfg(not(unix))]
mod implementation {
    use core::{
        cmp::Ordering,
        fmt::{Debug, Display, Formatter},
        hash::{Hash, Hasher},
    };
    use subtle::ConstantTimeEq;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    /// A wrapper for secret values that prevents accidental leakage.
    ///
    /// Without OS-level protection (non-Unix):
    /// - Debug and Display show `[REDACTED]`
    /// - Zeroized on drop
    /// - Access requires explicit `expose()` call
    pub struct Secret<T: Zeroize>(T);

    impl<T: Zeroize> Secret<T> {
        /// Creates a new `Secret` wrapping the given value.
        #[inline]
        #[allow(clippy::missing_const_for_fn)]
        pub fn new(value: T) -> Self {
            Self(value)
        }

        /// Exposes the secret value for read-only access within a closure.
        #[inline]
        pub fn expose<R>(&self, f: impl FnOnce(&T) -> R) -> R {
            f(&self.0)
        }
    }

    impl<T: Zeroize> Debug for Secret<T> {
        fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
            f.write_str("[REDACTED]")
        }
    }

    impl<T: Zeroize> Display for Secret<T> {
        fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
            f.write_str("[REDACTED]")
        }
    }

    impl<T: Zeroize> Zeroize for Secret<T> {
        fn zeroize(&mut self) {
            self.0.zeroize();
        }
    }

    impl<T: Zeroize> Drop for Secret<T> {
        fn drop(&mut self) {
            self.0.zeroize();
        }
    }

    impl<T: Zeroize> ZeroizeOnDrop for Secret<T> {}

    impl<T: Zeroize + Clone> Clone for Secret<T> {
        fn clone(&self) -> Self {
            self.expose(|v| Self::new(v.clone()))
        }
    }

    impl<T: Zeroize> PartialEq for Secret<T> {
        fn eq(&self, other: &Self) -> bool {
            self.expose(|a| {
                other.expose(|b| {
                    // SAFETY: Reading raw bytes of T for constant-time comparison.
                    let (a, b) = unsafe {
                        (
                            core::slice::from_raw_parts(
                                a as *const T as *const u8,
                                core::mem::size_of::<T>(),
                            ),
                            core::slice::from_raw_parts(
                                b as *const T as *const u8,
                                core::mem::size_of::<T>(),
                            ),
                        )
                    };
                    a.ct_eq(b).into()
                })
            })
        }
    }

    impl<T: Zeroize> Eq for Secret<T> {}

    impl<T: Zeroize + Hash> Hash for Secret<T> {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.expose(|v| v.hash(state));
        }
    }

    impl<T: Zeroize> PartialOrd for Secret<T> {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl<T: Zeroize> Ord for Secret<T> {
        fn cmp(&self, other: &Self) -> Ordering {
            self.expose(|a| {
                other.expose(|b| {
                    // SAFETY: Reading raw bytes of T for constant-time comparison.
                    let (a, b) = unsafe {
                        (
                            core::slice::from_raw_parts(
                                a as *const T as *const u8,
                                core::mem::size_of::<T>(),
                            ),
                            core::slice::from_raw_parts(
                                b as *const T as *const u8,
                                core::mem::size_of::<T>(),
                            ),
                        )
                    };
                    super::ct_cmp_bytes(a, b)
                })
            })
        }
    }
}

pub use implementation::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_redacted() {
        let secret = Secret::new([1u8, 2, 3, 4]);
        assert_eq!(format!("{:?}", secret), "[REDACTED]");
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
        use core::cmp::Ordering;

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
        use crate::bls12381::primitives::group::Scalar;
        use commonware_math::algebra::Random;
        use rand::rngs::OsRng;

        let scalar = Scalar::random(&mut OsRng);
        let secret = Secret::new(scalar);

        secret.expose(|v| {
            let _ = format!("{:?}", *v);
        });
    }
}

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

/// Constant-time equality comparison for byte slices.
///
/// XORs all bytes together and checks if the result is zero.
/// This prevents timing attacks by always comparing all bytes.
#[inline]
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Constant-time less-than comparison for byte slices (big-endian).
///
/// Returns true if a < b, using constant-time operations.
#[inline]
fn ct_lt_bytes(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    let mut result = 0u8; // 0 = equal so far, 1 = a < b, 2 = a > b
    for (x, y) in a.iter().zip(b.iter()) {
        // Only update result if we haven't found a difference yet (result == 0)
        let is_equal_so_far = result.wrapping_sub(1) >> 7; // 1 if result == 0, 0 otherwise
        let x_lt_y = ((*x as u16).wrapping_sub(*y as u16) >> 8) as u8; // 1 if x < y
        let x_gt_y = ((*y as u16).wrapping_sub(*x as u16) >> 8) as u8; // 1 if x > y
        result |= is_equal_so_far & ((x_lt_y) | (x_gt_y << 1));
    }
    result == 1
}

// Use protected implementation on Unix with the feature enabled
#[cfg(unix)]
mod implementation {
    use core::{
        fmt::{Debug, Display, Formatter},
        hash::{Hash, Hasher},
        ops::{Deref, DerefMut},
        ptr::NonNull,
    };
    use std::alloc::{alloc, dealloc, Layout};
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
    /// On Unix:
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
        ///
        /// # Safety Invariants
        ///
        /// This function performs several unsafe operations to set up protected memory:
        /// - Allocates page-aligned memory using the global allocator
        /// - Writes the value to the allocated memory
        /// - Locks the memory with mlock to prevent swapping
        /// - Protects the memory with mprotect to prevent unauthorized access
        ///
        /// All unsafe operations are properly sequenced and cleaned up on failure.
        #[allow(clippy::undocumented_unsafe_blocks)]
        pub fn try_new(value: T) -> Result<Self, &'static str> {
            let page_size = page_size();
            let type_size = core::mem::size_of::<T>();
            // Round up to page boundary (minimum one page)
            let size = type_size.max(1).next_multiple_of(page_size);

            let layout = Layout::from_size_align(size, page_size).map_err(|_| "invalid layout")?;

            // SAFETY: layout is valid (checked above), ptr may be null (checked below)
            let ptr = unsafe { alloc(layout) } as *mut T;

            if ptr.is_null() {
                return Err("allocation failed");
            }

            // SAFETY: ptr is non-null and properly aligned for T
            unsafe { core::ptr::write(ptr, value) };

            // SAFETY: ptr points to valid allocated memory of size `size`
            if unsafe { libc::mlock(ptr as *const libc::c_void, size) } != 0 {
                // SAFETY: ptr and layout match the allocation above
                unsafe { dealloc(ptr as *mut u8, layout) };
                return Err("mlock failed");
            }

            // SAFETY: ptr points to valid locked memory of size `size`
            if unsafe { libc::mprotect(ptr as *mut libc::c_void, size, libc::PROT_NONE) } != 0 {
                // SAFETY: cleanup on failure - unlock and deallocate
                unsafe {
                    libc::munlock(ptr as *const libc::c_void, size);
                    dealloc(ptr as *mut u8, layout);
                }
                return Err("mprotect failed");
            }

            Ok(Self {
                // SAFETY: ptr is non-null (checked above)
                ptr: unsafe { NonNull::new_unchecked(ptr) },
                size,
            })
        }

        /// Exposes the secret value for use.
        ///
        /// Returns a guard that re-protects memory when dropped.
        #[inline]
        pub fn expose(&self) -> SecretGuard<'_, T> {
            // SAFETY: self.ptr points to valid protected memory of self.size bytes
            let result = unsafe {
                libc::mprotect(
                    self.ptr.as_ptr() as *mut libc::c_void,
                    self.size,
                    libc::PROT_READ,
                )
            };
            assert_eq!(result, 0, "mprotect failed to unprotect memory");
            SecretGuard { secret: self }
        }

        /// Exposes the secret value mutably.
        ///
        /// Returns a guard that re-protects memory when dropped.
        #[inline]
        pub fn expose_mut(&mut self) -> SecretGuardMut<'_, T> {
            // SAFETY: self.ptr points to valid protected memory of self.size bytes
            let result = unsafe {
                libc::mprotect(
                    self.ptr.as_ptr() as *mut libc::c_void,
                    self.size,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            };
            assert_eq!(result, 0, "mprotect failed to unprotect memory");
            SecretGuardMut { secret: self }
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
            let page_size = page_size();
            // SAFETY: self.ptr points to valid memory that was allocated with page_size
            // alignment and self.size bytes. We unprotect, zeroize, unlock, and deallocate
            // in proper sequence. This is safe because we have exclusive access (&mut self).
            unsafe {
                libc::mprotect(
                    self.ptr.as_ptr() as *mut libc::c_void,
                    self.size,
                    libc::PROT_READ | libc::PROT_WRITE,
                );
                (*self.ptr.as_ptr()).zeroize();
                libc::munlock(self.ptr.as_ptr() as *const libc::c_void, self.size);
                let layout = Layout::from_size_align_unchecked(self.size, page_size);
                dealloc(self.ptr.as_ptr() as *mut u8, layout);
            }
        }
    }

    impl<T: Zeroize> ZeroizeOnDrop for Secret<T> {}

    impl<T: Zeroize + Clone> Clone for Secret<T> {
        fn clone(&self) -> Self {
            let guard = self.expose();
            Self::new((*guard).clone())
        }
    }

    impl<T: Zeroize> PartialEq for Secret<T> {
        fn eq(&self, other: &Self) -> bool {
            let guard_self = self.expose();
            let guard_other = other.expose();
            // SAFETY: We're reading the raw bytes of T for constant-time comparison.
            // This is safe because T is Sized and we only read size_of::<T>() bytes.
            let self_bytes = unsafe {
                core::slice::from_raw_parts(
                    &*guard_self as *const T as *const u8,
                    core::mem::size_of::<T>(),
                )
            };
            // SAFETY: Same as above - reading raw bytes of a Sized type.
            let other_bytes = unsafe {
                core::slice::from_raw_parts(
                    &*guard_other as *const T as *const u8,
                    core::mem::size_of::<T>(),
                )
            };
            super::ct_eq_bytes(self_bytes, other_bytes)
        }
    }

    impl<T: Zeroize> Eq for Secret<T> {}

    impl<T: Zeroize + Hash> Hash for Secret<T> {
        fn hash<H: Hasher>(&self, state: &mut H) {
            let guard = self.expose();
            (*guard).hash(state);
        }
    }

    impl<T: Zeroize> PartialOrd for Secret<T> {
        fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl<T: Zeroize> Ord for Secret<T> {
        fn cmp(&self, other: &Self) -> core::cmp::Ordering {
            let guard_self = self.expose();
            let guard_other = other.expose();
            // SAFETY: We're reading the raw bytes of T for constant-time comparison.
            // This is safe because T is Sized and we only read size_of::<T>() bytes.
            let self_bytes = unsafe {
                core::slice::from_raw_parts(
                    &*guard_self as *const T as *const u8,
                    core::mem::size_of::<T>(),
                )
            };
            // SAFETY: Same as above - reading raw bytes of a Sized type.
            let other_bytes = unsafe {
                core::slice::from_raw_parts(
                    &*guard_other as *const T as *const u8,
                    core::mem::size_of::<T>(),
                )
            };
            if super::ct_eq_bytes(self_bytes, other_bytes) {
                core::cmp::Ordering::Equal
            } else if super::ct_lt_bytes(self_bytes, other_bytes) {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Greater
            }
        }
    }

    /// RAII guard for read access to a secret.
    pub struct SecretGuard<'a, T: Zeroize> {
        secret: &'a Secret<T>,
    }

    impl<T: Zeroize> Deref for SecretGuard<'_, T> {
        type Target = T;

        #[inline]
        fn deref(&self) -> &T {
            // SAFETY: The memory is currently unprotected (PROT_READ) because
            // this guard exists, and the pointer is valid for the lifetime of Secret.
            unsafe { self.secret.ptr.as_ref() }
        }
    }

    impl<T: Zeroize> Drop for SecretGuard<'_, T> {
        fn drop(&mut self) {
            // SAFETY: Re-protect the memory when the guard is dropped.
            // The pointer and size are valid from the Secret.
            unsafe {
                libc::mprotect(
                    self.secret.ptr.as_ptr() as *mut libc::c_void,
                    self.secret.size,
                    libc::PROT_NONE,
                );
            }
        }
    }

    /// RAII guard for mutable access to a secret.
    pub struct SecretGuardMut<'a, T: Zeroize> {
        secret: &'a mut Secret<T>,
    }

    impl<T: Zeroize> Deref for SecretGuardMut<'_, T> {
        type Target = T;

        #[inline]
        fn deref(&self) -> &T {
            // SAFETY: The memory is currently unprotected (PROT_READ|PROT_WRITE) because
            // this guard exists, and the pointer is valid for the lifetime of Secret.
            unsafe { self.secret.ptr.as_ref() }
        }
    }

    impl<T: Zeroize> DerefMut for SecretGuardMut<'_, T> {
        #[inline]
        fn deref_mut(&mut self) -> &mut T {
            // SAFETY: The memory is currently unprotected (PROT_READ|PROT_WRITE) because
            // this guard exists, and we have exclusive mutable access.
            unsafe { self.secret.ptr.as_mut() }
        }
    }

    impl<T: Zeroize> Drop for SecretGuardMut<'_, T> {
        fn drop(&mut self) {
            // SAFETY: Re-protect the memory when the guard is dropped.
            // The pointer and size are valid from the Secret.
            unsafe {
                libc::mprotect(
                    self.secret.ptr.as_ptr() as *mut libc::c_void,
                    self.secret.size,
                    libc::PROT_NONE,
                );
            }
        }
    }
}

// Simple implementation for non-Unix platforms
#[cfg(not(unix))]
mod implementation {
    use core::{
        fmt::{Debug, Display, Formatter},
        hash::{Hash, Hasher},
    };
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
        pub const fn new(value: T) -> Self {
            Self(value)
        }

        /// Exposes the secret value for use.
        ///
        /// # Warning
        ///
        /// This method should be used sparingly and only when the secret
        /// value is actually needed for cryptographic operations.
        #[inline]
        pub fn expose(&self) -> SecretGuard<'_, T> {
            SecretGuard(&self.0)
        }

        /// Exposes the secret value mutably.
        ///
        /// # Warning
        ///
        /// This method should be used sparingly and only when mutable access
        /// to the secret value is actually needed.
        #[inline]
        pub fn expose_mut(&mut self) -> SecretGuardMut<'_, T> {
            SecretGuardMut(&mut self.0)
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
            Self(self.0.clone())
        }
    }

    impl<T: Zeroize> PartialEq for Secret<T> {
        fn eq(&self, other: &Self) -> bool {
            // SAFETY: We're reading the raw bytes of T for constant-time comparison.
            // This is safe because T is Sized and we only read size_of::<T>() bytes.
            let self_bytes = unsafe {
                core::slice::from_raw_parts(
                    &self.0 as *const T as *const u8,
                    core::mem::size_of::<T>(),
                )
            };
            let other_bytes = unsafe {
                core::slice::from_raw_parts(
                    &other.0 as *const T as *const u8,
                    core::mem::size_of::<T>(),
                )
            };
            super::ct_eq_bytes(self_bytes, other_bytes)
        }
    }

    impl<T: Zeroize> Eq for Secret<T> {}

    impl<T: Zeroize + Hash> Hash for Secret<T> {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.0.hash(state);
        }
    }

    impl<T: Zeroize> PartialOrd for Secret<T> {
        fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl<T: Zeroize> Ord for Secret<T> {
        fn cmp(&self, other: &Self) -> core::cmp::Ordering {
            // SAFETY: We're reading the raw bytes of T for constant-time comparison.
            // This is safe because T is Sized and we only read size_of::<T>() bytes.
            let self_bytes = unsafe {
                core::slice::from_raw_parts(
                    &self.0 as *const T as *const u8,
                    core::mem::size_of::<T>(),
                )
            };
            let other_bytes = unsafe {
                core::slice::from_raw_parts(
                    &other.0 as *const T as *const u8,
                    core::mem::size_of::<T>(),
                )
            };
            if super::ct_eq_bytes(self_bytes, other_bytes) {
                core::cmp::Ordering::Equal
            } else if super::ct_lt_bytes(self_bytes, other_bytes) {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Greater
            }
        }
    }

    use core::ops::{Deref, DerefMut};

    /// RAII guard for read access to a secret.
    ///
    /// On non-Unix platforms, this is a simple wrapper around a reference.
    pub struct SecretGuard<'a, T: Zeroize>(&'a T);

    impl<T: Zeroize> Deref for SecretGuard<'_, T> {
        type Target = T;

        #[inline]
        fn deref(&self) -> &T {
            self.0
        }
    }

    /// RAII guard for mutable access to a secret.
    ///
    /// On non-Unix platforms, this is a simple wrapper around a mutable reference.
    pub struct SecretGuardMut<'a, T: Zeroize>(&'a mut T);

    impl<T: Zeroize> Deref for SecretGuardMut<'_, T> {
        type Target = T;

        #[inline]
        fn deref(&self) -> &T {
            self.0
        }
    }

    impl<T: Zeroize> DerefMut for SecretGuardMut<'_, T> {
        #[inline]
        fn deref_mut(&mut self) -> &mut T {
            self.0
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
        let guard = secret.expose();
        assert_eq!(&*guard, &[1u8, 2, 3, 4]);
    }

    #[test]
    fn test_expose_mut() {
        let mut secret = Secret::new([1u8, 2, 3, 4]);
        {
            let mut guard = secret.expose_mut();
            guard[0] = 5;
        }
        let guard = secret.expose();
        assert_eq!(&*guard, &[5u8, 2, 3, 4]);
    }

    #[test]
    fn test_clone() {
        let secret = Secret::new([1u8, 2, 3, 4]);
        let cloned = secret.clone();
        assert_eq!(&*secret.expose(), &*cloned.expose());
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
        {
            let guard = secret.expose();
            assert_eq!(guard[0], 42);
        }

        // Second expose after first guard dropped
        {
            let guard = secret.expose();
            assert_eq!(guard[31], 42);
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_with_bls_scalar() {
        use crate::bls12381::primitives::group::Scalar;
        use commonware_math::algebra::Random;
        use rand::rngs::OsRng;

        let scalar = Scalar::random(&mut OsRng);
        let secret = Secret::new(scalar);

        {
            let guard = secret.expose();
            let _ = format!("{:?}", *guard);
        }
    }
}

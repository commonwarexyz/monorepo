//! A wrapper type for secret values that prevents accidental leakage.
//!
//! `Secret<T>` provides the following guarantees:
//! - Debug and Display always show `[REDACTED]` instead of the actual value
//! - The inner value is zeroized on drop
//! - Access to the inner value requires an explicit `expose()` call
//! - Comparisons use constant-time operations to prevent timing attacks
//!
//! # Type Constraints
//!
//! **Important**: `Secret<T>` is designed for flat data types without pointers
//! (e.g. `[u8; N]`). It does NOT provide full protection for types with
//! indirection. Types like `Vec<T>`, `String`, or `Box<T>` will only have their
//! metadata (pointer, length, capacity) zeroized, the referenced data remains
//! intact. Do not use `Secret` with types that contain pointers.

use core::{
    fmt::{Debug, Display, Formatter},
    mem::ManuallyDrop,
};
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

/// A wrapper for secret values that prevents accidental leakage.
///
/// - Debug and Display show `[REDACTED]`
/// - Zeroized on drop
/// - Access requires explicit `expose()` call
///
/// # Type Constraints
///
/// Only use with flat data types that have no pointers (e.g. `[u8; N]`).
/// See [module-level documentation](self) for details.
pub struct Secret<T>(ManuallyDrop<T>);

impl<T> Secret<T> {
    /// Creates a new `Secret` wrapping the given value.
    #[inline]
    pub const fn new(value: T) -> Self {
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
}

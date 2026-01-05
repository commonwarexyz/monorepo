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
//! `Secret<T>` only provides full protection for self-contained types (no heap
//! pointers). Types like `Vec<T>` or `String` will only have their stack
//! metadata zeroized, not heap data.

use crate::bls12381::primitives::group::Scalar;
use core::{
    cmp::Ordering,
    fmt::{Debug, Display, Formatter},
    mem::MaybeUninit,
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

/// A wrapper for secret values that prevents accidental leakage.
///
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
            zeroize_ptr(self.0.as_mut_ptr());
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
}

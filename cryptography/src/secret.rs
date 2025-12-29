//! A wrapper type for secret values that prevents accidental leakage.
//!
//! # Status
//!
//! `Secret<T>` provides the following guarantees:
//! - Debug and Display always show `[REDACTED]` instead of the actual value
//! - The inner value is zeroized on drop
//! - Access to the inner value requires an explicit `expose()` call

use core::{
    fmt::{Debug, Display, Formatter},
    hash::{Hash, Hasher},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A wrapper for secret values that prevents accidental leakage.
///
/// `Secret<T>` ensures that:
/// - Debug and Display always show `[REDACTED]` instead of the actual value
/// - The inner value is zeroized on drop when `T: Zeroize`
/// - Access to the inner value requires an explicit `expose()` call
///
/// # Example
///
/// ```
/// use commonware_cryptography::Secret;
/// use zeroize::Zeroize;
///
/// let secret = Secret::new([1u8, 2, 3, 4]);
///
/// // Debug output is redacted
/// assert_eq!(format!("{:?}", secret), "[REDACTED]");
///
/// // Access requires explicit call
/// assert_eq!(secret.expose(), &[1u8, 2, 3, 4]);
/// ```
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
    pub const fn expose(&self) -> &T {
        &self.0
    }

    /// Exposes the secret value mutably.
    ///
    /// # Warning
    ///
    /// This method should be used sparingly and only when mutable access
    /// to the secret value is actually needed.
    #[inline]
    pub const fn expose_mut(&mut self) -> &mut T {
        &mut self.0
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

// SAFETY: Secret<T> auto-zeroizes on drop via the Drop impl above.
// This marker trait indicates this behavior to users.
impl<T: Zeroize> ZeroizeOnDrop for Secret<T> {}

impl<T: Zeroize + Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Zeroize + PartialEq> PartialEq for Secret<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: Zeroize + Eq> Eq for Secret<T> {}

impl<T: Zeroize + Hash> Hash for Secret<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<T: Zeroize + PartialOrd> PartialOrd for Secret<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl<T: Zeroize + Ord> Ord for Secret<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

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
        assert_eq!(secret.expose(), &[1u8, 2, 3, 4]);
    }

    #[test]
    fn test_expose_mut() {
        let mut secret = Secret::new([1u8, 2, 3, 4]);
        secret.expose_mut()[0] = 5;
        assert_eq!(secret.expose(), &[5u8, 2, 3, 4]);
    }

    #[test]
    fn test_clone() {
        let secret = Secret::new([1u8, 2, 3, 4]);
        let cloned = secret.clone();
        assert_eq!(secret.expose(), cloned.expose());
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
    fn test_zeroize() {
        let mut secret = Secret::new([1u8, 2, 3, 4]);
        secret.zeroize();
        assert_eq!(secret.expose(), &[0u8, 0, 0, 0]);
    }

    #[test]
    fn test_hash() {
        use std::collections::hash_map::DefaultHasher;

        let s1 = Secret::new([1u8, 2, 3, 4]);
        let s2 = Secret::new([1u8, 2, 3, 4]);

        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();
        s1.hash(&mut hasher1);
        s2.hash(&mut hasher2);

        assert_eq!(hasher1.finish(), hasher2.finish());
    }

    #[test]
    fn test_ordering() {
        let s1 = Secret::new([1u8, 2, 3, 4]);
        let s2 = Secret::new([5u8, 6, 7, 8]);
        assert!(s1 < s2);
        assert!(s2 > s1);
    }
}

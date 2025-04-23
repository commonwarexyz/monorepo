//! Lightweight async RwLock for `commonware-runtime`.
//!
//! Internally this simply delegates to [`async_lock::RwLock`], giving us:
//! * no Tokio dependency
//! * fair writer acquisition (writers don’t starve)
//! * `try_read` / `try_write` without waiting
//!
//! Add to `Cargo.toml`:
//! ```toml
//! [dependencies]
//! async-lock = "3"
//! ```
//!
//! Usage:
//! ```rust,ignore
//! use commonware_runtime::rwlock::RwLock;
//!
//! # async fn demo() {
//! let lock = RwLock::new(0);
//!
//! // many concurrent readers
//! let r1 = lock.read().await;
//! let r2 = lock.read().await;
//! assert_eq!(*r1 + *r2, 0);
//!
//! // exclusive writer
//! drop((r1, r2));          // all readers must go away
//! let mut w = lock.write().await;
//! *w += 1;
//! # }
//! ```

use std::ops::{Deref, DerefMut};

/// Async reader–writer lock.
pub struct RwLock<T>(async_lock::RwLock<T>);

/// Shared guard returned by [`RwLock::read`].
pub type RwLockReadGuard<'a, T> = async_lock::RwLockReadGuard<'a, T>;
/// Exclusive guard returned by [`RwLock::write`].
pub type RwLockWriteGuard<'a, T> = async_lock::RwLockWriteGuard<'a, T>;

impl<T> RwLock<T> {
    /// Create a new lock.
    #[inline]
    pub const fn new(value: T) -> Self {
        Self(async_lock::RwLock::new(value))
    }

    /// Acquire a shared read guard.
    #[inline]
    pub async fn read(&self) -> RwLockReadGuard<'_, T> {
        self.0.read().await
    }

    /// Acquire an exclusive write guard.
    #[inline]
    pub async fn write(&self) -> RwLockWriteGuard<'_, T> {
        self.0.write().await
    }

    /// Try to get a read guard without waiting.
    #[inline]
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        self.0.try_read()
    }

    /// Try to get a write guard without waiting.
    #[inline]
    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
        self.0.try_write()
    }

    /// Get mutable access without locking (requires `&mut self`).
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        self.0.get_mut()
    }

    /// Consume the lock, returning the inner value.
    #[inline]
    pub fn into_inner(self) -> T {
        self.0.into_inner()
    }
}

// Convenience conversions / debug impls ------------------------------------

impl<T> From<T> for RwLock<T> {
    #[inline]
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for RwLock<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RwLock").finish_non_exhaustive()
    }
}

impl<T> Deref for RwLockReadGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &**self
    }
}

impl<T> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &**self
    }
}

impl<T> DerefMut for RwLockWriteGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut **self
    }
}

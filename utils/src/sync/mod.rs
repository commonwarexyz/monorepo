//! Utilities for working with synchronization primitives.
//!
//! # Choosing A Lock
//!
//! Prefer blocking locks for shared data:
//! - [Mutex]
//! - [RwLock]
//!
//! Use async locks only when you must hold a lock guard across an `.await` point:
//! - [AsyncMutex]
//! - [AsyncRwLock]
//! - [UpgradableAsyncRwLock] when you need to read first and then conditionally upgrade to write
//!   without allowing another writer to slip in between.
//!
//! Async locks are more expensive and should generally be reserved for coordination around
//! asynchronous I/O resources. For plain in-memory data, blocking locks are usually the right
//! default.
//!
//! Do not hold blocking lock guards across `.await`.
//!
//! Async lock guards may span `.await` when needed, but keep those critical sections as small as
//! possible because long-held guards increase contention and deadlock risk.

use core::ops::{Deref, DerefMut};
pub use parking_lot::{
    Condvar, MappedRwLockReadGuard, Mutex, MutexGuard, Once, RwLock, RwLockReadGuard,
    RwLockWriteGuard,
};
pub use tokio::sync::{
    Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard, RwLock as AsyncRwLock,
    RwLockReadGuard as AsyncRwLockReadGuard, RwLockWriteGuard as AsyncRwLockWriteGuard,
};

/// A Tokio-based async rwlock with an upgradable read mode.
///
/// All `write` and `upgradable_read` acquisitions take an internal async mutex ("gate") first.
/// This ensures that upgrading from read to write does not allow another writer to slip in.
pub struct UpgradableAsyncRwLock<T> {
    rw: tokio::sync::RwLock<T>,
    gate: tokio::sync::Mutex<()>,
}

impl<T> UpgradableAsyncRwLock<T> {
    /// Create a new lock wrapping `value`.
    pub fn new(value: T) -> Self {
        Self {
            rw: tokio::sync::RwLock::new(value),
            gate: tokio::sync::Mutex::new(()),
        }
    }

    /// Acquire a shared read guard.
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, T> {
        self.rw.read().await
    }

    /// Acquire an exclusive write guard.
    ///
    /// Writers are serialized through the internal gate.
    pub async fn write(&self) -> UpgradableAsyncRwLockWriteGuard<'_, T> {
        let gate_guard = self.gate.lock().await;
        let guard = self.rw.write().await;
        UpgradableAsyncRwLockWriteGuard {
            lock: self,
            guard,
            gate_guard,
        }
    }

    /// Acquire an upgradable read guard.
    ///
    /// This allows shared reads, then a later [UpgradableAsyncRwLockUpgradableReadGuard::upgrade]
    /// to exclusive write while holding the same gate token.
    pub async fn upgradable_read(&self) -> UpgradableAsyncRwLockUpgradableReadGuard<'_, T> {
        let gate_guard = self.gate.lock().await;
        let guard = self.rw.read().await;
        UpgradableAsyncRwLockUpgradableReadGuard {
            lock: self,
            guard,
            gate_guard,
        }
    }

    /// Consume the lock and return the wrapped value.
    pub fn into_inner(self) -> T {
        self.rw.into_inner()
    }
}

/// Exclusive write guard for [UpgradableAsyncRwLock].
pub struct UpgradableAsyncRwLockWriteGuard<'a, T> {
    lock: &'a UpgradableAsyncRwLock<T>,
    guard: tokio::sync::RwLockWriteGuard<'a, T>,
    gate_guard: tokio::sync::MutexGuard<'a, ()>,
}

impl<'a, T> UpgradableAsyncRwLockWriteGuard<'a, T> {
    /// Downgrade to an upgradable read guard while retaining the internal gate token.
    pub fn downgrade_to_upgradable(self) -> UpgradableAsyncRwLockUpgradableReadGuard<'a, T> {
        let Self {
            lock,
            guard,
            gate_guard,
        } = self;
        let guard = tokio::sync::RwLockWriteGuard::downgrade(guard);
        UpgradableAsyncRwLockUpgradableReadGuard {
            lock,
            guard,
            gate_guard,
        }
    }
}

impl<T> Deref for UpgradableAsyncRwLockWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> DerefMut for UpgradableAsyncRwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

/// Upgradable read guard for [UpgradableAsyncRwLock].
pub struct UpgradableAsyncRwLockUpgradableReadGuard<'a, T> {
    lock: &'a UpgradableAsyncRwLock<T>,
    guard: tokio::sync::RwLockReadGuard<'a, T>,
    gate_guard: tokio::sync::MutexGuard<'a, ()>,
}

impl<'a, T> UpgradableAsyncRwLockUpgradableReadGuard<'a, T> {
    /// Upgrade this guard to an exclusive writer.
    pub async fn upgrade(self) -> UpgradableAsyncRwLockWriteGuard<'a, T> {
        let Self {
            lock,
            guard,
            gate_guard,
        } = self;
        drop(guard);
        let guard = lock.rw.write().await;
        UpgradableAsyncRwLockWriteGuard {
            lock,
            guard,
            gate_guard,
        }
    }
}

impl<T> Deref for UpgradableAsyncRwLockUpgradableReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

#[cfg(test)]
mod tests {
    use super::{AsyncRwLock, UpgradableAsyncRwLock};
    use futures::{pin_mut, FutureExt};

    #[test]
    fn test_async_rwlock() {
        futures::executor::block_on(async {
            let lock = AsyncRwLock::new(100u64);

            let r1 = lock.read().await;
            let r2 = lock.read().await;
            assert_eq!(*r1 + *r2, 200);

            drop((r1, r2));
            let mut writer = lock.write().await;
            *writer += 1;

            assert_eq!(*writer, 101);
        });
    }

    #[test]
    fn test_upgradable_read_blocks_write() {
        futures::executor::block_on(async {
            let lock = UpgradableAsyncRwLock::new(1u64);
            let upgradable = lock.upgradable_read().await;

            let write = lock.write();
            pin_mut!(write);
            assert!(write.as_mut().now_or_never().is_none());

            drop(upgradable);

            let mut write = write.await;
            *write = 2;
            drop(write);

            assert_eq!(*lock.read().await, 2);
        });
    }

    #[test]
    fn test_read_allowed_during_upgradable_read() {
        futures::executor::block_on(async {
            let lock = UpgradableAsyncRwLock::new(5u64);
            let upgradable = lock.upgradable_read().await;
            let reader = lock.read().await;
            assert_eq!(*upgradable, 5);
            assert_eq!(*reader, 5);
        });
    }

    #[test]
    fn test_upgrade_prevents_writer_interleaving() {
        futures::executor::block_on(async {
            let lock = UpgradableAsyncRwLock::new(1u64);
            let upgradable = lock.upgradable_read().await;

            let writer = async {
                let mut writer = lock.write().await;
                let observed = *writer;
                *writer = 7;
                observed
            };
            pin_mut!(writer);
            assert!(writer.as_mut().now_or_never().is_none());

            let mut upgraded = upgradable.upgrade().await;
            *upgraded = 5;
            drop(upgraded);

            assert_eq!(writer.await, 5);
        });
    }

    #[test]
    fn test_downgrade_to_upgradable() {
        futures::executor::block_on(async {
            let lock = UpgradableAsyncRwLock::new(10u64);
            let mut writer = lock.write().await;
            *writer = 11;

            let upgradable = writer.downgrade_to_upgradable();
            let writer = lock.write();
            pin_mut!(writer);
            assert!(writer.as_mut().now_or_never().is_none());
            drop(upgradable);

            let writer = writer.await;
            assert_eq!(*writer, 11);
        });
    }
}

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
//!
//! Async locks are more expensive and should generally be reserved for coordination around
//! asynchronous I/O resources. For plain in-memory data, blocking locks are usually the right
//! default.
//!
//! Do not hold blocking lock guards across `.await`.
//!
//! Async lock guards may span `.await` when needed, but keep those critical sections as small as
//! possible because long-held guards increase contention and deadlock risk.

pub use parking_lot::{
    Condvar, Mutex, MutexGuard, Once, RwLock, RwLockReadGuard, RwLockWriteGuard,
};
pub use tokio::sync::{
    Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard, RwLock as AsyncRwLock,
    RwLockReadGuard as AsyncRwLockReadGuard, RwLockWriteGuard as AsyncRwLockWriteGuard,
};

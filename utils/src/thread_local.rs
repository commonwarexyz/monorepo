//! RAII guard for thread-local caching of expensive-to-construct objects.
//!
//! # Overview
//!
//! When an object is expensive to construct but cheap to reset and must be
//! used within a stateless function, keeping one instance per thread avoids
//! repeated allocation. The manual take-then-return pattern is fragile:
//! forgetting the return silently degrades to constructing a new instance.
//!
//! [`Cached`] is an RAII guard whose [`Drop`] automatically returns the
//! value to the thread-local slot, so forgetting the return is impossible.
//!
//! # Avoiding `.await`
//!
//! Do not hold a [`Cached`] guard across `.await` points. While the guard
//! is live the thread-local slot is empty, so any other task that runs on
//! the same thread during the suspension will pay the full construction
//! cost instead of reusing the cached instance. Prefer scoping the guard
//! tightly around the synchronous work that needs the cached object.
//!
//! # Examples
//!
//! ```
//! use commonware_utils::{thread_local_cache, Cached};
//!
//! thread_local_cache!(static POOL: String);
//!
//! let guard = Cached::take(&POOL, || Ok::<_, ()>(String::new()), |s| { s.clear(); Ok(()) }).unwrap();
//! assert_eq!(&*guard, "");
//! drop(guard);
//!
//! // Second take reuses the cached instance.
//! let guard = Cached::take(&POOL, || Ok::<_, ()>(String::new()), |s| { s.clear(); Ok(()) }).unwrap();
//! drop(guard);
//! ```

use std::{
    cell::RefCell,
    ops::{Deref, DerefMut},
    thread::LocalKey,
};

/// RAII guard that borrows a value from a thread-local cache and returns it
/// on drop.
pub struct Cached<T: 'static> {
    value: Option<T>,
    cache: &'static LocalKey<RefCell<Option<T>>>,
}

impl<T: 'static> Cached<T> {
    /// Take a value from the thread-local `cache`.
    ///
    /// On a cache hit the `reset` closure reconfigures the existing instance.
    /// On a miss the `create` closure constructs a new one. Both closures may
    /// fail with `E`.
    ///
    /// While the guard is live the thread-local slot is empty. Avoid holding
    /// the guard across `.await` points: any other task that runs on the same
    /// thread during the suspension will see an empty cache and pay the full
    /// construction cost.
    pub fn take<E>(
        cache: &'static LocalKey<RefCell<Option<T>>>,
        create: impl FnOnce() -> Result<T, E>,
        reset: impl FnOnce(&mut T) -> Result<(), E>,
    ) -> Result<Self, E> {
        let cached = cache.with(|cell| cell.borrow_mut().take());
        let value = match cached {
            Some(mut v) => {
                if let Err(err) = reset(&mut v) {
                    // Restore the previous value on reset failure so transient errors
                    // do not permanently evict the cache entry.
                    cache.with(|cell| {
                        let mut slot = cell.borrow_mut();
                        if slot.is_none() {
                            *slot = Some(v);
                        }
                    });
                    return Err(err);
                }
                v
            }
            None => create()?,
        };
        Ok(Self {
            value: Some(value),
            cache,
        })
    }
}

impl<T: 'static> Deref for Cached<T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.value.as_ref().expect("value taken after drop")
    }
}

impl<T: 'static> DerefMut for Cached<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.value.as_mut().expect("value taken after drop")
    }
}

impl<T: 'static> Drop for Cached<T> {
    fn drop(&mut self) {
        if let Some(v) = self.value.take() {
            self.cache.with(|cell| *cell.borrow_mut() = Some(v));
        }
    }
}

/// Declare a thread-local slot for use with [`Cached`].
///
/// ```ignore
/// thread_local_cache!(static SLOT: MyType);
/// ```
///
/// Expands to a `thread_local!` declaration wrapping `RefCell<Option<MyType>>`.
#[macro_export]
macro_rules! thread_local_cache {
    (static $name:ident : $ty:ty) => {
        ::std::thread_local! {
            static $name: ::std::cell::RefCell<::core::option::Option<$ty>> =
                const { ::std::cell::RefCell::new(::core::option::Option::None) };
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local_cache!(static TEST_CACHE: Vec<u8>);

    #[test]
    fn test_take_creates_on_miss() {
        let guard = Cached::take(&TEST_CACHE, || Ok::<_, ()>(vec![1, 2, 3]), |_v| Ok(())).unwrap();
        assert_eq!(&*guard, &[1, 2, 3]);
    }

    thread_local_cache!(static REUSE_CACHE: Vec<u8>);

    #[test]
    fn test_take_reuses_on_hit() {
        // First take: create
        let mut guard = Cached::take(
            &REUSE_CACHE,
            || Ok::<_, ()>(vec![1, 2, 3]),
            |v| {
                v.clear();
                Ok(())
            },
        )
        .unwrap();
        guard.push(4);
        drop(guard);

        // Second take: reuse (reset clears, so we get an empty vec)
        let guard = Cached::take(
            &REUSE_CACHE,
            || Ok::<_, ()>(vec![99]),
            |v| {
                v.clear();
                Ok(())
            },
        )
        .unwrap();
        assert!(guard.is_empty(), "reset should have cleared the vec");
    }

    thread_local_cache!(static DROP_CACHE: String);

    #[test]
    fn test_drop_returns_to_cache() {
        {
            let _guard = Cached::take(
                &DROP_CACHE,
                || Ok::<_, ()>(String::from("hello")),
                |_| Ok(()),
            )
            .unwrap();
            // guard drops here
        }

        // Cache should now hold the value
        let has_value = DROP_CACHE.with(|cell| cell.borrow().is_some());
        assert!(has_value, "drop should return value to cache");
    }

    thread_local_cache!(static ERR_CACHE: u32);

    #[test]
    fn test_create_error_propagates() {
        let result = Cached::take(&ERR_CACHE, || Err::<u32, &str>("create failed"), |_| Ok(()));
        assert!(result.is_err());
    }

    thread_local_cache!(static RESET_ERR_CACHE: u32);

    #[test]
    fn test_reset_error_propagates() {
        // Seed the cache
        {
            let _guard = Cached::take(&RESET_ERR_CACHE, || Ok::<_, &str>(42), |_| Ok(())).unwrap();
        }

        // Now take again; reset should fail
        let result = Cached::take(
            &RESET_ERR_CACHE,
            || Ok::<_, &str>(0),
            |_| Err("reset failed"),
        );
        assert!(result.is_err());

        // Failed reset should not evict the cached value.
        let cached = RESET_ERR_CACHE.with(|cell| *cell.borrow());
        assert_eq!(cached, Some(42));
    }

    thread_local_cache!(static NESTED_CACHE: Vec<u8>);

    #[test]
    fn test_nested_guards_last_drop_wins() {
        NESTED_CACHE.with(|cell| *cell.borrow_mut() = None);

        let mut outer = Cached::take(&NESTED_CACHE, || Ok::<_, ()>(vec![1]), |_| Ok(())).unwrap();
        outer.push(10);

        {
            let mut inner =
                Cached::take(&NESTED_CACHE, || Ok::<_, ()>(vec![2]), |_| Ok(())).unwrap();
            inner.push(20);
        }

        drop(outer);

        let cached = NESTED_CACHE.with(|cell| cell.borrow().clone());
        assert_eq!(cached, Some(vec![1, 10]));
    }
}

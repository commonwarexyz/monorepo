//! A wrapper that is [`Sync`] for any value by granting only exclusive access to it.

use core::fmt;

/// A value reachable only through exclusive access, which makes the wrapper [`Sync`] whatever
/// the value is.
///
/// Every accessor takes `&mut self` or `self`, so a shared reference to the wrapper cannot reach
/// the value. That is all `Sync` requires, which lets a value that is `Send` but not `Sync`,
/// such as a boxed future, live in a type that must be `Sync`.
pub struct Exclusive<T: ?Sized> {
    inner: T,
}

// SAFETY: The value is reachable only through `&mut Exclusive<T>` or by consuming the wrapper,
// never through `&Exclusive<T>`, so sharing the wrapper between threads cannot share the value.
unsafe impl<T: ?Sized> Sync for Exclusive<T> {}

impl<T> Exclusive<T> {
    /// Wrap `inner`.
    pub const fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Unwrap the value.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: ?Sized> Exclusive<T> {
    /// Access the value, which requires exclusive access to the wrapper.
    pub const fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: ?Sized> fmt::Debug for Exclusive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Exclusive").finish_non_exhaustive()
    }
}

#[cfg(test)]
#[commonware_macros::test_group("miri")]
mod tests {
    use super::Exclusive;
    use std::cell::Cell;

    #[test]
    fn test_exclusive_is_sync_and_grants_exclusive_access() {
        fn assert_sync<T: Sync>(_: &T) {}

        // Cell is Send but not Sync; the wrapper is both, so it can be shared across threads.
        let mut exclusive = Exclusive::new(Cell::new(1u32));
        assert_sync(&exclusive);
        std::thread::scope(|scope| {
            let shared = &exclusive;
            scope.spawn(move || {
                assert_eq!(format!("{shared:?}"), "Exclusive { .. }");
            });
        });

        exclusive.get_mut().set(2);
        assert_eq!(exclusive.into_inner().into_inner(), 2);
    }
}

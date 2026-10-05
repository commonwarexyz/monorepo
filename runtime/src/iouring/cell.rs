//! Shared `UnsafeCell` interface for loom and standard builds.
//!
//! Loom builds use loom's cell, whose `with` and `with_mut` record a read or a
//! write of the value for as long as their closure runs. Other builds wrap
//! [`std::cell::UnsafeCell`] in a transparent newtype with the same two
//! methods, which check nothing and cost nothing, so the same code compiles
//! against either. Every read of the value must happen inside one of these
//! closures, and every write inside `with_mut`, otherwise loom misses it.

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        pub use loom::cell::UnsafeCell;
    } else {
        /// [`std::cell::UnsafeCell`] behind loom's interface.
        #[derive(Default)]
        #[repr(transparent)]
        pub struct UnsafeCell<T>(std::cell::UnsafeCell<T>);

        impl<T> UnsafeCell<T> {
            /// Wrap `value`.
            pub const fn new(value: T) -> Self {
                Self(std::cell::UnsafeCell::new(value))
            }

            /// Run `f` with a pointer for reading the value.
            pub fn with<R>(&self, f: impl FnOnce(*const T) -> R) -> R {
                f(self.0.get())
            }

            /// Run `f` with a pointer for writing the value.
            pub fn with_mut<R>(&self, f: impl FnOnce(*mut T) -> R) -> R {
                f(self.0.get())
            }
        }
    }
}

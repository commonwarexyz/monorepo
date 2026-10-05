//! Shared `UnsafeCell` interface for loom and standard builds.
//!
//! Loom's cell exposes its value only through `with` and `with_mut`, which take
//! a closure so loom can track each access. Loom builds use it directly. Other
//! builds wrap [`std::cell::UnsafeCell`] in a transparent newtype with the same
//! two methods, at no cost, so the same code compiles against either. The
//! pointer must not escape the closure, otherwise loom misses the access.

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

            /// Run `f` with a pointer for reading the value. The pointer must
            /// not escape `f`.
            pub fn with<R>(&self, f: impl FnOnce(*const T) -> R) -> R {
                f(self.0.get())
            }

            /// Run `f` with a pointer for writing the value. The pointer must
            /// not escape `f`.
            pub fn with_mut<R>(&self, f: impl FnOnce(*mut T) -> R) -> R {
                f(self.0.get())
            }
        }
    }
}

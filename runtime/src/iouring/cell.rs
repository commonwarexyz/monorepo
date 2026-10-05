//! An `UnsafeCell` whose accesses loom checks.
//!
//! Loom builds use loom's cell, which reports any access that races another.
//! Other builds wrap the standard cell behind the same closure-based interface,
//! at no cost.

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        pub use loom::cell::UnsafeCell;
    } else {
        /// The standard cell behind loom's interface.
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

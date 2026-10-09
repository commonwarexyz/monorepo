//! Runtime backend selection at the outer operation boundary.

#[cfg(target_arch = "x86_64")]
use crate::native::NativeIceLake;
#[cfg(target_arch = "aarch64")]
use crate::native::{NativeArmV9, NativeNeon};
use crate::{Operation, Simd, emulated::EmulatedScalar};

/// Executes an operation once using the portable scalar backend on any host.
///
/// This provides a deterministic backend for consumer tests without CPU feature
/// detection. Child operations preserve the scalar backend selection. Specialized
/// instruction profiles are not exercised; use [`crate::check_consistent`] to
/// compare results across emulated profiles.
///
/// # Examples
///
/// ```
/// use commonware_simd::{Operation, Simd, test_dispatch};
///
/// struct Add(u64, u64);
/// impl<S: Simd> Operation<S> for Add {
///     type Output = u64;
///
///     fn portable(self, simd: S) -> u64 {
///         let sum = simd.u64_add(simd.u64_splat(self.0), simd.u64_splat(self.1));
///         simd.u64_extract::<0>(sum)
///     }
/// }
///
/// assert_eq!(test_dispatch(Add(u64::MAX, 1)), 0);
/// ```
#[inline]
pub fn test_dispatch<O, R>(operation: O) -> R
where
    O: Operation<EmulatedScalar, Output = R>,
{
    EmulatedScalar.execute(operation)
}

macro_rules! dispatch {
    ($($native:ident),* $(,)?) => {
        /// Executes an operation using the best available backend.
        ///
        /// The operation must implement each candidate backend with the same output type.
        /// Normalize backend-specific registers inside the operation before dispatching.
        ///
        /// Selects native Ice Lake on supported x86-64 CPUs, Armv9 or NEON on supported
        /// AArch64 CPUs, and the portable scalar backend elsewhere. With `std`, feature
        /// detection happens at this boundary; without it, only compile-time CPU features
        /// permit native construction. Child
        /// operations executed with the supplied token preserve its backend selection.
        ///
        /// # Examples
        ///
        /// ```
        /// use commonware_simd::{dispatch, Operation, Simd};
        ///
        /// struct Add(u64, u64);
        ///
        /// impl<S: Simd> Operation<S> for Add {
        ///     type Output = u64;
        ///
        ///     fn portable(self, simd: S) -> u64 {
        ///         let sum = simd.u64_add(simd.u64_splat(self.0), simd.u64_splat(self.1));
        ///         let mut output = vec![0; S::U64_LANES];
        ///         simd.u64_store(sum, &mut output);
        ///         output[0]
        ///     }
        /// }
        ///
        /// assert_eq!(dispatch(Add(u64::MAX, 1)), 0);
        /// ```
        #[inline]
        pub fn dispatch<O, R>(operation: O) -> R
        where
            O: Operation<EmulatedScalar, Output = R>
                $(+ Operation<$native, Output = R>)*,
        {
            $(
                if let Some(simd) = $native::new() {
                    return simd.execute(operation);
                }
            )*
            EmulatedScalar.execute(operation)
        }
    };
}

#[cfg(target_arch = "x86_64")]
dispatch!(NativeIceLake);
#[cfg(target_arch = "aarch64")]
dispatch!(NativeArmV9, NativeNeon);
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
dispatch!();

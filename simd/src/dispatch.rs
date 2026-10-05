//! Runtime backend selection at the outer operation boundary.

#[cfg(target_arch = "x86_64")]
use crate::native::NativeIceLake;
#[cfg(target_arch = "aarch64")]
use crate::native::{NativeArmV9, NativeNeon};
use crate::{Operation, Simd, emulated::EmulatedScalar};

/// Executes an operation using the best available backend.
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
/// impl Operation for Add {
///     type Output = u64;
///
///     fn portable<S: Simd>(self, s: S) -> u64 {
///         let sum = s.u64_add(s.u64_splat(self.0), s.u64_splat(self.1));
///         let mut output = vec![0; S::U64_LANES];
///         s.u64_store(sum, &mut output);
///         output[0]
///     }
/// }
///
/// assert_eq!(dispatch(Add(u64::MAX, 1)), 0);
/// ```
// Keep dispatched consumer kernels in the selected feature scope instead of outlining them.
#[inline]
pub fn dispatch<O: Operation>(operation: O) -> O::Output {
    #[cfg(target_arch = "x86_64")]
    if let Some(s) = NativeIceLake::new() {
        return s.execute(operation);
    }
    #[cfg(target_arch = "aarch64")]
    if let Some(s) = NativeArmV9::new() {
        return s.execute(operation);
    }
    #[cfg(target_arch = "aarch64")]
    if let Some(s) = NativeNeon::new() {
        return s.execute(operation);
    }
    EmulatedScalar.execute(operation)
}

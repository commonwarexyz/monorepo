//! Runtime backend selection at the outer operation boundary.

#[cfg(target_arch = "aarch64")]
use crate::native::NativeNeon;
use crate::{Operation, Simd, emulated::EmulatedScalar};

/// Executes an operation using the best available backend.
///
/// Selects native NEON on AArch64 CPUs that support it, and the portable scalar
/// backend everywhere else. Feature detection happens at this boundary. Child
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
    #[cfg(target_arch = "aarch64")]
    if let Some(s) = NativeNeon::new() {
        return s.execute(operation);
    }
    EmulatedScalar.execute(operation)
}

#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz;

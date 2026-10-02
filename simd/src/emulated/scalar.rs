//! Scalar execution with one unsigned 64-bit lane.

use super::shared::{add, load, store};
use crate::{Operation, Simd};

/// Scalar execution token with one unsigned 64-bit lane.
///
/// Executes the portable operation path.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmulatedScalar;

impl Simd for EmulatedScalar {
    type U64 = [u64; 1];

    const U64_LANES: usize = 1;

    // Expose the body to downstream loops so vector bounds checks can be eliminated.
    #[inline]
    fn u64_load(self, input: &[u64]) -> Self::U64 {
        load(input)
    }

    // Expose the body to downstream loops so vector bounds checks can be eliminated.
    #[inline]
    fn u64_store(self, value: Self::U64, output: &mut [u64]) {
        store(value, output);
    }

    fn u64_splat(self, value: u64) -> Self::U64 {
        [value; 1]
    }

    // Inline lane arithmetic into downstream loops instead of calling once per vector.
    #[inline]
    fn u64_add(self, a: Self::U64, b: Self::U64) -> Self::U64 {
        add(a, b)
    }

    fn execute<O: Operation>(self, operation: O) -> O::Output {
        operation.portable(self)
    }
}

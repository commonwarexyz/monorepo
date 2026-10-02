//! Emulation of the Ice Lake instruction profile.

use super::shared::{add, load, store};
use crate::{IceLake, Operation, Simd};

/// Emulated Ice Lake execution token with eight unsigned 64-bit lanes.
///
/// Executes the Ice Lake operation path without requiring native hardware features.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmulatedIceLake;

impl Simd for EmulatedIceLake {
    type U64 = [u64; 8];

    const U64_LANES: usize = 8;

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
        [value; 8]
    }

    // Inline lane arithmetic into downstream loops instead of calling once per vector.
    #[inline]
    fn u64_add(self, a: Self::U64, b: Self::U64) -> Self::U64 {
        add(a, b)
    }

    fn execute<O: Operation>(self, operation: O) -> O::Output {
        operation.ice_lake(self)
    }
}

impl IceLake for EmulatedIceLake {}

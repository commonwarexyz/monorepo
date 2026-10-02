//! Emulation of the Armv9 with SVE2 instruction profile.

use super::shared::{add, load, store};
use crate::{ArmV9, Operation, Simd};

/// Emulated Armv9 with SVE2 execution token with two unsigned 64-bit lanes.
///
/// Models a 128-bit SVE vector, matching Graviton4.
/// Executes the Armv9 operation path without requiring native hardware features.
///
/// # Examples
///
/// ```
/// use commonware_simd::{emulated::EmulatedArmV9, Simd};
///
/// let s = EmulatedArmV9;
/// assert_eq!(s.u64_splat(7), [7; 2]);
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct EmulatedArmV9;

impl Simd for EmulatedArmV9 {
    type U64 = [u64; 2];

    const U64_LANES: usize = 2;

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
        [value; 2]
    }

    // Inline lane arithmetic into downstream loops instead of calling once per vector.
    #[inline]
    fn u64_add(self, a: Self::U64, b: Self::U64) -> Self::U64 {
        add(a, b)
    }

    fn execute<O: Operation>(self, operation: O) -> O::Output {
        operation.arm_v9(self)
    }
}

impl ArmV9 for EmulatedArmV9 {}

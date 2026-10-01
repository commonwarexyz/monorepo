//! Emulation of the AArch64 NEON instruction profile.

use super::shared::{add, load, store};
use crate::{Neon, Operation, Simd};

/// Emulated NEON execution token with two unsigned 64-bit lanes.
///
/// Executes the NEON operation path without requiring native hardware features.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmulatedNeon;

impl Simd for EmulatedNeon {
    type U64 = [u64; 2];

    const U64_LANES: usize = 2;

    fn u64_load(self, input: &[u64]) -> Self::U64 {
        load(input)
    }

    fn u64_store(self, value: Self::U64, output: &mut [u64]) {
        store(value, output);
    }

    fn u64_splat(self, value: u64) -> Self::U64 {
        [value; 2]
    }

    fn u64_add(self, a: Self::U64, b: Self::U64) -> Self::U64 {
        add(a, b)
    }

    fn execute<O: Operation>(self, operation: O) -> O::Output {
        operation.neon(self)
    }
}

impl Neon for EmulatedNeon {}

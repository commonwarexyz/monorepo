//! Emulation of the Armv9 with SVE2 instruction profile.

use crate::{ArmV9, Neon, Operation, Simd};

/// Emulated Armv9 with SVE2 execution token with 16 byte, four u32, and two u64 lanes.
///
/// Models a 128-bit SVE vector, matching Graviton4.
/// Executes the Armv9 operation path without requiring native hardware features.
///
/// # Examples
///
/// ```
/// use commonware_simd::{emulated::EmulatedArmV9, Simd};
///
/// let simd = EmulatedArmV9;
/// assert_eq!(simd.u64_splat(7), [7; 2]);
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct EmulatedArmV9;

impl Simd for EmulatedArmV9 {
    type U32x4 = [u32; 4];

    #[inline]
    fn u32x4_load(self, input: &[u32]) -> Self::U32x4 {
        input[..4].try_into().unwrap()
    }

    #[inline]
    fn u32x4_store(self, value: Self::U32x4, output: &mut [u32]) {
        output[..4].copy_from_slice(&value);
    }

    #[inline]
    fn u32x4_add(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4 {
        core::array::from_fn(|i| a[i].wrapping_add(b[i]))
    }

    #[inline]
    fn u32x4_shuffle<const MASK: i32>(self, value: Self::U32x4) -> Self::U32x4 {
        assert!((0..256).contains(&MASK));
        core::array::from_fn(|i| value[((MASK >> (2 * i)) & 3) as usize])
    }

    #[inline]
    fn u32x4_load_be(self, input: &[u8]) -> Self::U32x4 {
        let input = &input[..16];
        core::array::from_fn(|i| u32::from_be_bytes(input[4 * i..4 * i + 4].try_into().unwrap()))
    }

    #[inline]
    fn u32x4_load_be2(self, input: &[u8]) -> Self::U32x4 {
        let input = &input[..8];
        [
            u32::from_be_bytes(input[..4].try_into().unwrap()),
            u32::from_be_bytes(input[4..8].try_into().unwrap()),
            0,
            0,
        ]
    }

    #[inline]
    fn u32x4_store_be(self, value: Self::U32x4, output: &mut [u8]) {
        let output = &mut output[..16];
        for (word, bytes) in value.into_iter().zip(output.as_chunks_mut::<4>().0) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
    }

    #[inline]
    fn u32x4_align<const N: i32>(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4 {
        assert!((0..=4).contains(&N));
        core::array::from_fn(|i| {
            let j = N as usize + i;
            if j < 4 { a[j] } else { b[j - 4] }
        })
    }

    #[inline]
    fn u32x4_blend<const MASK: i32>(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4 {
        assert!((0..16).contains(&MASK));
        core::array::from_fn(|i| if MASK & (1 << i) != 0 { b[i] } else { a[i] })
    }

    type U8 = [u8; 16];
    const U8_LANES: usize = 16;

    #[inline]
    fn u8_load(self, input: &[u8]) -> Self::U8 {
        let mut value = [0; Self::U8_LANES];
        value.copy_from_slice(&input[..Self::U8_LANES]);
        value
    }

    #[inline]
    fn u8_store(self, value: Self::U8, output: &mut [u8]) {
        output[..Self::U8_LANES].copy_from_slice(&value);
    }

    #[inline]
    fn u8_splat(self, value: u8) -> Self::U8 {
        [value; 16]
    }

    #[inline]
    fn u8_xor(self, a: Self::U8, b: Self::U8) -> Self::U8 {
        core::array::from_fn(|i| a[i] ^ b[i])
    }

    #[inline]
    fn u8_load_partial(self, input: &[u8]) -> Self::U8 {
        assert!(input.len() <= Self::U8_LANES);
        let mut value = [0; Self::U8_LANES];
        value[..input.len()].copy_from_slice(input);
        value
    }

    #[inline]
    fn u8_store_partial(self, value: Self::U8, output: &mut [u8]) {
        assert!(output.len() <= Self::U8_LANES);
        output.copy_from_slice(&value[..output.len()]);
    }

    #[inline]
    fn u8_and(self, a: Self::U8, b: Self::U8) -> Self::U8 {
        core::array::from_fn(|i| a[i] & b[i])
    }

    #[inline]
    fn u8_shl<const N: u32>(self, value: Self::U8) -> Self::U8 {
        assert!(N < 8);
        value.map(|v| v << N)
    }

    #[inline]
    fn u8_shr<const N: u32>(self, value: Self::U8) -> Self::U8 {
        assert!(N < 8);
        value.map(|v| v >> N)
    }

    #[inline]
    fn u8_xor_fold(self, value: Self::U8) -> u8 {
        value.into_iter().fold(0, |acc, v| acc ^ v)
    }

    type U32 = [u32; 4];
    const U32_LANES: usize = 4;

    #[inline]
    fn u32_load(self, input: &[u32]) -> Self::U32 {
        let mut value = [0; Self::U32_LANES];
        value.copy_from_slice(&input[..Self::U32_LANES]);
        value
    }

    #[inline]
    fn u32_store(self, value: Self::U32, output: &mut [u32]) {
        output[..Self::U32_LANES].copy_from_slice(&value);
    }

    #[inline]
    fn u32_splat(self, value: u32) -> Self::U32 {
        [value; 4]
    }

    #[inline]
    fn u32_xor(self, a: Self::U32, b: Self::U32) -> Self::U32 {
        core::array::from_fn(|i| a[i] ^ b[i])
    }

    #[inline]
    fn u32_add(self, a: Self::U32, b: Self::U32) -> Self::U32 {
        core::array::from_fn(|i| a[i].wrapping_add(b[i]))
    }

    #[inline]
    fn u32_rotate_right<const N: u32>(self, value: Self::U32) -> Self::U32 {
        assert!(N < 32);
        value.map(|v| v.rotate_right(N))
    }

    #[inline]
    fn u32_sub(self, a: Self::U32, b: Self::U32) -> Self::U32 {
        core::array::from_fn(|i| a[i].wrapping_sub(b[i]))
    }

    #[inline]
    fn u32_and(self, a: Self::U32, b: Self::U32) -> Self::U32 {
        core::array::from_fn(|i| a[i] & b[i])
    }

    #[inline]
    fn u32_or(self, a: Self::U32, b: Self::U32) -> Self::U32 {
        core::array::from_fn(|i| a[i] | b[i])
    }

    #[inline]
    fn u32_shl<const N: u32>(self, value: Self::U32) -> Self::U32 {
        assert!(N < 32);
        value.map(|v| v << N)
    }

    #[inline]
    fn u32_shr<const N: u32>(self, value: Self::U32) -> Self::U32 {
        assert!(N < 32);
        value.map(|v| v >> N)
    }

    #[inline]
    fn u32_select(self, mask: Self::U32, a: Self::U32, b: Self::U32) -> Self::U32 {
        core::array::from_fn(|i| (mask[i] & a[i]) | (!mask[i] & b[i]))
    }

    #[inline]
    fn u32_permute(self, value: Self::U32, indices: &[usize]) -> Self::U32 {
        let indices = &indices[..Self::U32_LANES];
        assert!(indices.iter().all(|&i| i < Self::U32_LANES));
        core::array::from_fn(|i| value[indices[i]])
    }

    #[inline]
    fn u32_permute2(self, a: Self::U32, b: Self::U32, indices: &[usize]) -> Self::U32 {
        let indices = &indices[..Self::U32_LANES];
        assert!(indices.iter().all(|&i| i < 2 * Self::U32_LANES));
        core::array::from_fn(|i| {
            let index = indices[i];
            if index < Self::U32_LANES {
                a[index]
            } else {
                b[index - Self::U32_LANES]
            }
        })
    }

    #[inline]
    fn u64_and(self, a: Self::U64, b: Self::U64) -> Self::U64 {
        core::array::from_fn(|i| a[i] & b[i])
    }

    #[inline]
    fn u64_or(self, a: Self::U64, b: Self::U64) -> Self::U64 {
        core::array::from_fn(|i| a[i] | b[i])
    }

    #[inline]
    fn u64_shl<const N: u32>(self, value: Self::U64) -> Self::U64 {
        assert!(N < 64);
        value.map(|v| v << N)
    }

    #[inline]
    fn u64_shr<const N: u32>(self, value: Self::U64) -> Self::U64 {
        assert!(N < 64);
        value.map(|v| v >> N)
    }

    type U64 = [u64; 2];

    const U64_LANES: usize = 2;

    // Expose the body to downstream loops so vector bounds checks can be eliminated.
    #[inline]
    fn u64_load(self, input: &[u64]) -> Self::U64 {
        let input = &input[..Self::U64_LANES];
        let mut value = [0; Self::U64_LANES];
        for (i, lane) in value.iter_mut().enumerate() {
            *lane = input[i];
        }
        value
    }

    // Expose the body to downstream loops so vector bounds checks can be eliminated.
    #[inline]
    fn u64_store(self, value: Self::U64, output: &mut [u64]) {
        let output = &mut output[..Self::U64_LANES];
        for (i, lane) in value.into_iter().enumerate() {
            output[i] = lane;
        }
    }

    fn u64_splat(self, value: u64) -> Self::U64 {
        [value; 2]
    }

    // Inline lane arithmetic into downstream loops instead of calling once per vector.
    #[inline]
    fn u64_add(self, a: Self::U64, b: Self::U64) -> Self::U64 {
        core::array::from_fn(|i| a[i].wrapping_add(b[i]))
    }

    #[inline]
    fn u64_sub(self, a: Self::U64, b: Self::U64) -> Self::U64 {
        core::array::from_fn(|i| a[i].wrapping_sub(b[i]))
    }

    #[inline]
    fn u64_xor(self, a: Self::U64, b: Self::U64) -> Self::U64 {
        core::array::from_fn(|i| a[i] ^ b[i])
    }

    #[inline]
    fn u64_select(self, mask: Self::U64, a: Self::U64, b: Self::U64) -> Self::U64 {
        core::array::from_fn(|i| (mask[i] & a[i]) | (!mask[i] & b[i]))
    }

    #[inline]
    fn u64_extract<const N: usize>(self, value: Self::U64) -> u64 {
        assert!(N < Self::U64_LANES);
        value[N]
    }

    #[inline]
    fn u64_insert<const N: usize>(self, mut value: Self::U64, lane: u64) -> Self::U64 {
        assert!(N < Self::U64_LANES);
        value[N] = lane;
        value
    }

    // Inline nested adapters across consumer code generation units.
    #[inline]
    fn execute<O: Operation<Self>>(self, operation: O) -> O::Output {
        operation.arm_v9(self)
    }
}

impl ArmV9 for EmulatedArmV9 {
    #[inline]
    fn u32_xor_rotate_right<const N: u32>(self, a: Self::U32, b: Self::U32) -> Self::U32 {
        assert!(N < 32);
        core::array::from_fn(|i| (a[i] ^ b[i]).rotate_right(N))
    }
}

impl Neon for EmulatedArmV9 {
    #[inline]
    fn sha256_h(self, abcd: Self::U32x4, efgh: Self::U32x4, wk: Self::U32x4) -> Self::U32x4 {
        super::neon::EmulatedNeon.sha256_h(abcd, efgh, wk)
    }
    #[inline]
    fn sha256_h2(self, efgh: Self::U32x4, abcd: Self::U32x4, wk: Self::U32x4) -> Self::U32x4 {
        super::neon::EmulatedNeon.sha256_h2(efgh, abcd, wk)
    }
    #[inline]
    fn sha256_su0(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4 {
        super::neon::EmulatedNeon.sha256_su0(a, b)
    }
    #[inline]
    fn sha256_su1(self, a: Self::U32x4, b: Self::U32x4, c: Self::U32x4) -> Self::U32x4 {
        super::neon::EmulatedNeon.sha256_su1(a, b, c)
    }

    type U16 = [u16; 8];

    #[inline]
    fn u8_table_lookup(self, table: Self::U8, indices: Self::U8) -> Self::U8 {
        indices.map(|index| table.get(usize::from(index)).copied().unwrap_or(0))
    }

    #[inline]
    fn u8_clmul_lo(self, a: Self::U8, b: Self::U8) -> Self::U16 {
        core::array::from_fn(|i| {
            let mut product = 0;
            for bit in 0..8 {
                if b[i] & (1 << bit) != 0 {
                    product ^= u16::from(a[i]) << bit;
                }
            }
            product
        })
    }

    #[inline]
    fn u8_clmul_hi(self, a: Self::U8, b: Self::U8) -> Self::U16 {
        core::array::from_fn(|i| {
            let mut product = 0;
            for bit in 0..8 {
                if b[i + 8] & (1 << bit) != 0 {
                    product ^= u16::from(a[i + 8]) << bit;
                }
            }
            product
        })
    }

    #[inline]
    fn u16_xor(self, a: Self::U16, b: Self::U16) -> Self::U16 {
        core::array::from_fn(|i| a[i] ^ b[i])
    }

    #[inline]
    fn u16_shl<const N: u32>(self, value: Self::U16) -> Self::U16 {
        assert!(N < 16);
        value.map(|v| v << N)
    }

    #[inline]
    fn u16_shr<const N: u32>(self, value: Self::U16) -> Self::U16 {
        assert!(N < 16);
        value.map(|v| v >> N)
    }

    #[inline]
    fn u16_narrow_pair(self, low: Self::U16, high: Self::U16) -> Self::U8 {
        core::array::from_fn(|i| {
            if i < 8 {
                low[i] as u8
            } else {
                high[i - 8] as u8
            }
        })
    }

    type U32Half = [u32; 2];
    fn u64_narrow(self, value: Self::U64) -> Self::U32Half {
        value.map(|v| v as u32)
    }
    fn u32_half_splat(self, value: u32) -> Self::U32Half {
        [value; 2]
    }
    fn u32_half_add(self, a: Self::U32Half, b: Self::U32Half) -> Self::U32Half {
        core::array::from_fn(|i| a[i].wrapping_add(b[i]))
    }
    fn u32_half_shl<const N: u32>(self, value: Self::U32Half) -> Self::U32Half {
        assert!(N < 32);
        value.map(|v| v << N)
    }
    fn u32_widen_mul(self, a: Self::U32Half, b: Self::U32Half) -> Self::U64 {
        core::array::from_fn(|i| u64::from(a[i]) * u64::from(b[i]))
    }

    #[inline]
    fn u32_widen_madd(self, acc: Self::U64, a: Self::U32Half, b: Self::U32Half) -> Self::U64 {
        core::array::from_fn(|i| acc[i].wrapping_add(u64::from(a[i]) * u64::from(b[i])))
    }
}

#[cfg(test)]
mod tests {
    use super::{super::test_utils::words, EmulatedArmV9};
    use crate::ArmV9;
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        vec::Vec,
    };

    fn arm<S: ArmV9>(simd: S) {
        let a: Vec<u32> = (0..S::U32_LANES)
            .map(|i| 0xf13a_75c9u32.rotate_left(i as u32 * 3))
            .collect();
        let b: Vec<u32> = (0..S::U32_LANES)
            .map(|i| 0x81fe_2390u32.wrapping_mul(i as u32 + 1))
            .collect();
        let av = simd.u32_load(&a);
        let bv = simd.u32_load(&b);
        macro_rules! rotations { ($($n:literal),*) => { $(
            assert_eq!(words(simd,simd.u32_xor_rotate_right::<$n>(av,bv)),a.iter().zip(&b).map(|(a,b)| (a ^ b).rotate_right($n)).collect::<Vec<_>>());
        )* }; }
        rotations!(0, 1, 7, 8, 12, 16, 31);
        assert!(
            catch_unwind(AssertUnwindSafe(|| simd.u32_xor_rotate_right::<32>(av, bv))).is_err()
        );
        assert!(
            catch_unwind(AssertUnwindSafe(
                || simd.u32_xor_rotate_right::<{ u32::MAX }>(av, bv)
            ))
            .is_err()
        );
        assert_eq!(words(simd, av), a);
        assert_eq!(words(simd, bv), b);
    }

    #[test]
    fn common_contracts() {
        super::super::test_utils::common(EmulatedArmV9);
        super::super::test_utils::basic_common(EmulatedArmV9);
    }

    #[test]
    fn profile_contracts() {
        arm(EmulatedArmV9);
        super::super::test_utils::neon(EmulatedArmV9);
        super::super::test_utils::widening(EmulatedArmV9);
    }
}

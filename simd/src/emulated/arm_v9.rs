//! Emulation of the Armv9 with SVE2 instruction profile.

use crate::{ArmV9, Neon};

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

super::common::impl_common!(EmulatedArmV9, 16, 4, 2, arm_v9);

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
        super::neon::EmulatedNeon.u8_table_lookup(table, indices)
    }

    #[inline]
    fn u8_clmul_lo(self, a: Self::U8, b: Self::U8) -> Self::U16 {
        super::neon::EmulatedNeon.u8_clmul_lo(a, b)
    }

    #[inline]
    fn u8_clmul_hi(self, a: Self::U8, b: Self::U8) -> Self::U16 {
        super::neon::EmulatedNeon.u8_clmul_hi(a, b)
    }

    #[inline]
    fn u16_xor(self, a: Self::U16, b: Self::U16) -> Self::U16 {
        super::neon::EmulatedNeon.u16_xor(a, b)
    }

    #[inline]
    fn u16_shl<const N: u32>(self, value: Self::U16) -> Self::U16 {
        super::neon::EmulatedNeon.u16_shl::<N>(value)
    }

    #[inline]
    fn u16_shr<const N: u32>(self, value: Self::U16) -> Self::U16 {
        super::neon::EmulatedNeon.u16_shr::<N>(value)
    }

    #[inline]
    fn u16_narrow_pair(self, low: Self::U16, high: Self::U16) -> Self::U8 {
        super::neon::EmulatedNeon.u16_narrow_pair(low, high)
    }

    type U32Half = [u32; 2];
    #[inline]
    fn u64_narrow(self, value: Self::U64) -> Self::U32Half {
        super::neon::EmulatedNeon.u64_narrow(value)
    }
    #[inline]
    fn u32_half_splat(self, value: u32) -> Self::U32Half {
        super::neon::EmulatedNeon.u32_half_splat(value)
    }
    #[inline]
    fn u32_half_add(self, a: Self::U32Half, b: Self::U32Half) -> Self::U32Half {
        super::neon::EmulatedNeon.u32_half_add(a, b)
    }
    #[inline]
    fn u32_half_shl<const N: u32>(self, value: Self::U32Half) -> Self::U32Half {
        super::neon::EmulatedNeon.u32_half_shl::<N>(value)
    }
    #[inline]
    fn u32_widen_mul(self, a: Self::U32Half, b: Self::U32Half) -> Self::U64 {
        super::neon::EmulatedNeon.u32_widen_mul(a, b)
    }

    #[inline]
    fn u32_widen_madd(self, acc: Self::U64, a: Self::U32Half, b: Self::U32Half) -> Self::U64 {
        super::neon::EmulatedNeon.u32_widen_madd(acc, a, b)
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

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

    #[inline]
    fn u64_xor_rotate_right<const N: u32>(self, a: Self::U64, b: Self::U64) -> Self::U64 {
        assert!(N < 64);
        core::array::from_fn(|i| (a[i] ^ b[i]).rotate_right(N))
    }

    #[inline]
    fn u64_bcax(self, a: Self::U64, b: Self::U64, c: Self::U64) -> Self::U64 {
        core::array::from_fn(|i| a[i] ^ (b[i] & !c[i]))
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
    fn u8_table(self, table: Self::U8) -> Self::U8Table {
        super::neon::EmulatedNeon.u8_table(table)
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

    fn arm_u64<S: ArmV9>(simd: S) {
        fn longs<S: ArmV9>(simd: S, value: S::U64) -> Vec<u64> {
            let mut output = [0; 2];
            simd.u64_store(value, &mut output);
            Vec::from(output)
        }
        let a = [0xf13a_75c9_0e8d_2b46u64, 0x8000_0000_0000_0001];
        let b = [0x81fe_2390_d1b5_4a32u64, 0x7fff_ffff_ffff_fffe];
        let c = [0xff00_f0f0_cccc_aaaau64, 0x0123_4567_89ab_cdef];
        let (av, bv, cv) = (simd.u64_load(&a), simd.u64_load(&b), simd.u64_load(&c));
        macro_rules! rotations { ($($n:literal),*) => { $(
            assert_eq!(longs(simd,simd.u64_xor_rotate_right::<$n>(av,bv)),a.iter().zip(&b).map(|(a,b)| (a ^ b).rotate_right($n)).collect::<Vec<_>>());
        )* }; }
        rotations!(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63
        );
        assert!(
            catch_unwind(AssertUnwindSafe(|| simd.u64_xor_rotate_right::<64>(av, bv))).is_err()
        );
        assert!(
            catch_unwind(AssertUnwindSafe(
                || simd.u64_xor_rotate_right::<{ u32::MAX }>(av, bv)
            ))
            .is_err()
        );
        // The complemented operand is the third: swapping b and c changes the result.
        assert_eq!(
            longs(simd, simd.u64_bcax(av, bv, cv)),
            (0..2).map(|i| a[i] ^ (b[i] & !c[i])).collect::<Vec<_>>()
        );
        assert_eq!(
            longs(simd, simd.u64_bcax(av, cv, bv)),
            (0..2).map(|i| a[i] ^ (c[i] & !b[i])).collect::<Vec<_>>()
        );
        assert_eq!(
            longs(simd, simd.u64_xor3(av, bv, cv)),
            (0..2).map(|i| a[i] ^ b[i] ^ c[i]).collect::<Vec<_>>()
        );
        assert_eq!(longs(simd, av), a);
        assert_eq!(longs(simd, bv), b);
        assert_eq!(longs(simd, cv), c);
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

    #[test]
    fn u64_profile_contracts() {
        arm_u64(EmulatedArmV9);
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon", not(miri)))]
    #[test]
    fn native_u64_profile_contracts() {
        if let Some(simd) = crate::native::NativeArmV9::new() {
            arm_u64(simd);
        }
    }
}

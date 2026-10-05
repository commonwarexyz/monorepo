//! Emulation of the Ice Lake instruction profile.

use crate::{IceLake, Operation, Simd};

/// Emulated Ice Lake execution token with 64 byte, 16 u32, and eight u64 lanes.
///
/// Executes the Ice Lake operation path without requiring native hardware features.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmulatedIceLake;

impl Simd for EmulatedIceLake {
    type U8 = [u8; 64];
    const U8_LANES: usize = 64;

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
        [value; 64]
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

    type U32 = [u32; 16];
    const U32_LANES: usize = 16;

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
        [value; 16]
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

    type U64 = [u64; 8];

    const U64_LANES: usize = 8;

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
        [value; 8]
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
    fn execute<O: Operation>(self, operation: O) -> O::Output {
        operation.ice_lake(self)
    }
}

impl IceLake for EmulatedIceLake {
    #[inline]
    fn u32_shuffle128<const MASK: i32>(self, value: Self::U32) -> Self::U32 {
        assert!((0..256).contains(&MASK));
        core::array::from_fn(|i| {
            let group = i / 4 * 4;
            let selector = ((MASK >> (2 * (i % 4))) & 3) as usize;
            value[group + selector]
        })
    }

    #[inline]
    fn u32_shuffle2_128<const MASK: i32>(self, a: Self::U32, b: Self::U32) -> Self::U32 {
        assert!((0..256).contains(&MASK));
        core::array::from_fn(|i| {
            let group = i / 4 * 4;
            let lane = i % 4;
            let selector = ((MASK >> (2 * lane)) & 3) as usize;
            if lane < 2 {
                a[group + selector]
            } else {
                b[group + selector]
            }
        })
    }

    #[inline]
    fn u32_blend128<const MASK: i32>(self, a: Self::U32, b: Self::U32) -> Self::U32 {
        assert!((0..16).contains(&MASK));
        core::array::from_fn(|i| {
            if MASK & (1 << (i % 4)) != 0 {
                b[i]
            } else {
                a[i]
            }
        })
    }

    #[inline]
    fn u32_unpacklo32(self, a: Self::U32, b: Self::U32) -> Self::U32 {
        core::array::from_fn(|i| {
            let source = i / 4 * 4 + i % 4 / 2;
            if i % 2 == 0 { a[source] } else { b[source] }
        })
    }

    #[inline]
    fn u32_unpackhi32(self, a: Self::U32, b: Self::U32) -> Self::U32 {
        core::array::from_fn(|i| {
            let source = i / 4 * 4 + 2 + i % 4 / 2;
            if i % 2 == 0 { a[source] } else { b[source] }
        })
    }

    #[inline]
    fn u32_unpacklo64(self, a: Self::U32, b: Self::U32) -> Self::U32 {
        core::array::from_fn(|i| {
            let source = i / 4 * 4 + i % 2;
            if i % 4 < 2 { a[source] } else { b[source] }
        })
    }

    fn u8_gf_mul(self, a: Self::U8, b: Self::U8) -> Self::U8 {
        core::array::from_fn(|i| {
            let mut a = a[i];
            let mut b = b[i];
            let mut product = 0;
            for _ in 0..8 {
                if b & 1 != 0 {
                    product ^= a;
                }
                let carry = a >> 7;
                a <<= 1;
                if carry != 0 {
                    a ^= 0x1b;
                }
                b >>= 1;
            }
            product
        })
    }
    fn u64_madd52lo(self, acc: Self::U64, a: Self::U64, b: Self::U64) -> Self::U64 {
        const MASK: u64 = (1 << 52) - 1;
        core::array::from_fn(|i| {
            let product = u128::from(a[i] & MASK) * u128::from(b[i] & MASK);
            acc[i].wrapping_add(product as u64 & MASK)
        })
    }
    fn u64_madd52hi(self, acc: Self::U64, a: Self::U64, b: Self::U64) -> Self::U64 {
        const MASK: u64 = (1 << 52) - 1;
        core::array::from_fn(|i| {
            let product = u128::from(a[i] & MASK) * u128::from(b[i] & MASK);
            acc[i].wrapping_add((product >> 52) as u64)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{super::test_utils::words, EmulatedIceLake};
    use crate::{IceLake, Simd};
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        vec::Vec,
    };

    fn ice<S: IceLake>(s: S) {
        let a: Vec<u32> = (0..16).map(|i| 0xa000_0000 + i * 0x10101).collect();
        let b: Vec<u32> = (0..16).map(|i| 0xb000_0000 + i * 0x30303).collect();
        let av = s.u32_load(&a);
        let bv = s.u32_load(&b);
        macro_rules! masks { ($($m:literal),*) => { $(
            let expected:Vec<u32>=(0..16).map(|i| a[i/4*4 + (($m >> (2*(i%4))) & 3)]).collect();
            assert_eq!(words(s,s.u32_shuffle128::<$m>(av)),expected);
            let expected:Vec<u32>=(0..16).map(|i| { let source=if i%4 < 2 { &a } else { &b }; source[i/4*4 + (($m >> (2*(i%4))) & 3)] }).collect();
            assert_eq!(words(s,s.u32_shuffle2_128::<$m>(av,bv)),expected);
        )* }; }
        masks!(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67,
            68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
            90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142,
            143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
            160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176,
            177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193,
            194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210,
            211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227,
            228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244,
            245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255
        );
        macro_rules! blends { ($($m:literal),*) => { $(
            let mask: u32 = $m;
            assert_eq!(words(s,s.u32_blend128::<$m>(av,bv)),(0..16).map(|i| if mask & (1 << (i%4)) != 0 { b[i] } else { a[i] }).collect::<Vec<_>>());
        )* }; }
        blends!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        for (actual, pattern) in [
            (
                s.u32_unpacklo32(av, bv),
                [(false, 0), (true, 0), (false, 1), (true, 1)],
            ),
            (
                s.u32_unpackhi32(av, bv),
                [(false, 2), (true, 2), (false, 3), (true, 3)],
            ),
            (
                s.u32_unpacklo64(av, bv),
                [(false, 0), (false, 1), (true, 0), (true, 1)],
            ),
        ] {
            assert_eq!(
                words(s, actual),
                (0..16)
                    .map(|i| {
                        let (second, lane) = pattern[i % 4];
                        if second {
                            b[i / 4 * 4 + lane]
                        } else {
                            a[i / 4 * 4 + lane]
                        }
                    })
                    .collect::<Vec<_>>()
            );
        }
        assert!(catch_unwind(AssertUnwindSafe(|| s.u32_blend128::<-1>(av, bv))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| s.u32_blend128::<16>(av, bv))).is_err());
        assert_eq!(words(s, av), a);
        assert_eq!(words(s, bv), b);
    }
    #[test]
    fn common_contracts() {
        super::super::test_utils::common(EmulatedIceLake);
        super::super::test_utils::basic_common(EmulatedIceLake);
    }

    #[test]
    fn profile_contracts() {
        ice(EmulatedIceLake);
        // Native providers may reject invalid shuffle immediates at compile time.
        let s = EmulatedIceLake;
        let a = s.u32_load(&(0..16).collect::<Vec<_>>());
        let b = s.u32_load(&(16..32).collect::<Vec<_>>());
        macro_rules! invalid_shuffle { ($($m:literal),*) => { $(
            assert!(catch_unwind(AssertUnwindSafe(|| s.u32_shuffle128::<$m>(a))).is_err());
            assert!(catch_unwind(AssertUnwindSafe(|| s.u32_shuffle2_128::<$m>(a,b))).is_err());
        )* }; }
        invalid_shuffle!(-1, 256);
        assert_eq!(words(s, a), (0..16).collect::<Vec<_>>());
        assert_eq!(words(s, b), (16..32).collect::<Vec<_>>());
    }

    #[test]
    fn ifma_truncation_and_accumulator_wrap() {
        let s = EmulatedIceLake;
        let values = [0, 1, (1 << 52) - 1, 1 << 52, u64::MAX];
        let mask = (1u128 << 52) - 1;
        for a in values {
            for b in values {
                for accumulator in values {
                    let product = (a as u128 & mask) * (b as u128 & mask);
                    let lo =
                        s.u64_madd52lo(s.u64_splat(accumulator), s.u64_splat(a), s.u64_splat(b));
                    let hi =
                        s.u64_madd52hi(s.u64_splat(accumulator), s.u64_splat(a), s.u64_splat(b));
                    assert_eq!(lo, [accumulator.wrapping_add((product & mask) as u64); 8]);
                    assert_eq!(hi, [accumulator.wrapping_add((product >> 52) as u64); 8]);
                }
            }
        }
    }

    #[test]
    fn gfni_all_byte_products() {
        let s = EmulatedIceLake;
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                // Polynomial multiplication followed by long division by x^8+x^4+x^3+x+1.
                let mut product = 0u16;
                for bit in 0..8 {
                    if (b >> bit) & 1 != 0 {
                        product ^= (a as u16) << bit;
                    }
                }
                for bit in (8..16).rev() {
                    if product & (1 << bit) != 0 {
                        product ^= 0x11b << (bit - 8);
                    }
                }
                assert_eq!(
                    s.u8_gf_mul(s.u8_splat(a), s.u8_splat(b)),
                    [product as u8; 64]
                );
            }
        }
    }
}

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
    fn sha256_rounds2(self, a: Self::U32x4, b: Self::U32x4, k: Self::U32x4) -> Self::U32x4 {
        let [mut h, mut g, mut d, mut c] = a;
        let [mut f, mut e, mut b, mut a] = b;
        for wk in &k[..2] {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let choice = (e & f) ^ (!e & g);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let t1 = h.wrapping_add(sum1).wrapping_add(choice).wrapping_add(*wk);
            let t2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        [f, e, b, a]
    }

    #[inline]
    fn sha256_msg1(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4 {
        let next = [a[1], a[2], a[3], b[0]];
        core::array::from_fn(|i| {
            let x = next[i];
            a[i].wrapping_add(x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3))
        })
    }

    #[inline]
    fn sha256_msg2(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4 {
        let mut r = [0u32; 4];
        for i in 0..4 {
            let x = if i < 2 { b[i + 2] } else { r[i - 2] };
            r[i] = a[i].wrapping_add(x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10));
        }
        r
    }

    #[inline]
    fn u32_ternary<const MASK: i32>(self, a: Self::U32, b: Self::U32, c: Self::U32) -> Self::U32 {
        assert!((0..256).contains(&MASK));
        core::array::from_fn(|i| {
            let mut result = 0;
            for bit in 0..32 {
                let index =
                    (((a[i] >> bit) & 1) << 2) | (((b[i] >> bit) & 1) << 1) | ((c[i] >> bit) & 1);
                result |= ((MASK as u32 >> index) & 1) << bit;
            }
            result
        })
    }

    #[inline]
    fn u8_shuffle128(self, value: Self::U8, indices: Self::U8) -> Self::U8 {
        core::array::from_fn(|i| {
            if indices[i] & 0x80 != 0 {
                0
            } else {
                value[i / 16 * 16 + (indices[i] & 15) as usize]
            }
        })
    }

    #[inline]
    fn u32_shuffle_groups<const MASK: i32>(self, a: Self::U32, b: Self::U32) -> Self::U32 {
        assert!((0..256).contains(&MASK));
        core::array::from_fn(|i| {
            let group = ((MASK >> (2 * (i / 4))) & 3) as usize;
            if i < 8 {
                a[group * 4 + i % 4]
            } else {
                b[group * 4 + i % 4]
            }
        })
    }

    #[inline]
    fn u32_unpackhi64(self, a: Self::U32, b: Self::U32) -> Self::U32 {
        core::array::from_fn(|i| {
            let source = i / 4 * 4 + 2 + i % 2;
            if i % 4 < 2 { a[source] } else { b[source] }
        })
    }

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
            let expected: Vec<u32> = (0..16).map(|i| {
                let source = if i < 8 { &a } else { &b };
                source[(($m >> (2 * (i / 4))) & 3) * 4 + i % 4]
            }).collect();
            assert_eq!(words(s, s.u32_shuffle_groups::<$m>(av, bv)), expected);
            let c = s.u32_splat(0xaaaa_aaaa);
            let expected: Vec<u32> = (0..16).map(|i| {
                (0..32).fold(0u32, |acc, bit| {
                    let index = 4 * ((a[i] >> bit) & 1) + 2 * ((b[i] >> bit) & 1) + ((0xaaaa_aaaau32 >> bit) & 1);
                    acc | ((($m as u32 >> index) & 1) << bit)
                })
            }).collect();
            assert_eq!(words(s, s.u32_ternary::<$m>(av, bv, c)), expected);
            let x = s.u32x4_load(&a);
            let mut out = [0; 4];
            s.u32x4_store(s.u32x4_shuffle::<$m>(x), &mut out);
            assert_eq!(out, core::array::from_fn(|i| a[($m >> (2 * i)) & 3]));
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
            (
                s.u32_unpackhi64(av, bv),
                [(false, 2), (false, 3), (true, 2), (true, 3)],
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
    fn sha256_schedule_and_rounds() {
        let s = EmulatedIceLake;
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let initial = [
            0x6a09e667u32,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19,
        ];
        for case in 0..3 {
            let mut w = [0u32; 64];
            if case == 0 {
                w[0] = 0x8000_0000;
            } else {
                for (i, word) in w[..16].iter_mut().enumerate() {
                    *word = (i as u32)
                        .wrapping_mul(0x9e37_79b9)
                        .wrapping_add((case as u32).wrapping_mul(0xffff_ffffu32));
                }
            }
            for i in 16..64 {
                let x = w[i - 15];
                let y = w[i - 2];
                let sigma0 = x.rotate_left(25) ^ x.rotate_left(14) ^ (x >> 3);
                let sigma1 = y.rotate_left(15) ^ y.rotate_left(13) ^ (y >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(sigma0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(sigma1);
            }
            for i in (16..64).step_by(4) {
                let partial = s.sha256_msg1(s.u32x4_load(&w[i - 16..]), s.u32x4_load(&w[i - 12..]));
                let partial = s.u32x4_add(partial, s.u32x4_load(&w[i - 7..]));
                assert_eq!(
                    s.sha256_msg2(partial, s.u32x4_load(&w[i - 4..])),
                    w[i..i + 4]
                );
            }
            let mut state = initial;
            let mut cdgh = [state[7], state[6], state[3], state[2]];
            let mut abef = [state[5], state[4], state[1], state[0]];
            for i in (0..64).step_by(2) {
                let wk = [
                    w[i].wrapping_add(K[i]),
                    w[i + 1].wrapping_add(K[i + 1]),
                    0xdeadbeef,
                    u32::MAX,
                ];
                let result = s.sha256_rounds2(cdgh, abef, wk);
                for j in i..i + 2 {
                    let [a, b, c, d, e, f, g, h] = state;
                    let choice = g ^ (e & (f ^ g));
                    let majority = (a & b) | (c & (a | b));
                    let sum1 = e.rotate_left(26) ^ e.rotate_left(21) ^ e.rotate_left(7);
                    let sum0 = a.rotate_left(30) ^ a.rotate_left(19) ^ a.rotate_left(10);
                    let t = h
                        .wrapping_add(sum1)
                        .wrapping_add(choice)
                        .wrapping_add(w[j])
                        .wrapping_add(K[j]);
                    state = [
                        t.wrapping_add(sum0).wrapping_add(majority),
                        a,
                        b,
                        c,
                        d.wrapping_add(t),
                        e,
                        f,
                        g,
                    ];
                }
                assert_eq!(result, [state[5], state[4], state[1], state[0]]);
                cdgh = abef;
                abef = result;
            }
            if case == 0 {
                let digest: [u32; 8] = core::array::from_fn(|i| state[i].wrapping_add(initial[i]));
                assert_eq!(
                    digest,
                    [
                        0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c,
                        0xa495991b, 0x7852b855
                    ]
                );
            }
        }
    }

    #[test]
    fn four_lane_and_byte_shuffle_contracts() {
        let s = EmulatedIceLake;
        assert_eq!(s.u32x4_load(&[1, 2, 3, 4, 5]), [1, 2, 3, 4]);
        assert_eq!(s.u32x4_add([u32::MAX; 4], [1, 2, 3, 4]), [0, 1, 2, 3]);
        let mut output = [9; 5];
        s.u32x4_store([1, 2, 3, 4], &mut output);
        assert_eq!(output, [1, 2, 3, 4, 9]);
        for len in 0..4 {
            assert!(catch_unwind(|| s.u32x4_load(&[0; 4][..len])).is_err());
            let mut output = [9; 4];
            assert!(
                catch_unwind(AssertUnwindSafe(
                    || s.u32x4_store([1; 4], &mut output[..len])
                ))
                .is_err()
            );
            assert_eq!(output, [9; 4]);
        }
        assert!(catch_unwind(|| s.u32x4_shuffle::<-1>([0; 4])).is_err());
        assert!(catch_unwind(|| s.u32x4_shuffle::<256>([0; 4])).is_err());
        assert!(catch_unwind(|| s.u32_ternary::<-1>([0; 16], [0; 16], [0; 16])).is_err());
        assert!(catch_unwind(|| s.u32_ternary::<256>([0; 16], [0; 16], [0; 16])).is_err());
        assert!(catch_unwind(|| s.u32_shuffle_groups::<-1>([0; 16], [0; 16])).is_err());
        assert!(catch_unwind(|| s.u32_shuffle_groups::<256>([0; 16], [0; 16])).is_err());
        let bytes = core::array::from_fn(|i| i as u8);
        for index in 0..=255u8 {
            let actual = s.u8_shuffle128(bytes, [index; 64]);
            assert_eq!(
                actual,
                core::array::from_fn(|i| if index & 128 != 0 {
                    0
                } else {
                    bytes[i / 16 * 16 + (index & 15) as usize]
                })
            );
        }
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

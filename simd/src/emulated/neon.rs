//! Emulation of the AArch64 NEON and SHA2 instruction profile.

use crate::{Neon, Operation, Simd};

/// Emulated NEON execution token with 16 byte, four u32, and two u64 lanes.
///
/// Executes the NEON operation path without requiring native hardware features.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmulatedNeon;

impl Simd for EmulatedNeon {
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
        operation.neon(self)
    }
}

impl Neon for EmulatedNeon {
    #[inline]
    fn sha256_h(self, abcd: Self::U32x4, efgh: Self::U32x4, wk: Self::U32x4) -> Self::U32x4 {
        let state = rounds(abcd, efgh, wk);
        [state[0], state[1], state[2], state[3]]
    }

    #[inline]
    fn sha256_h2(self, efgh: Self::U32x4, abcd: Self::U32x4, wk: Self::U32x4) -> Self::U32x4 {
        let state = rounds(abcd, efgh, wk);
        [state[4], state[5], state[6], state[7]]
    }

    #[inline]
    fn sha256_su0(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4 {
        let next = [a[1], a[2], a[3], b[0]];
        core::array::from_fn(|i| a[i].wrapping_add(sigma0(next[i])))
    }

    #[inline]
    fn sha256_su1(self, a: Self::U32x4, b: Self::U32x4, c: Self::U32x4) -> Self::U32x4 {
        let mut result = [0u32; 4];
        let next = [b[1], b[2], b[3], c[0]];
        for i in 0..4 {
            let previous = if i < 2 { c[i + 2] } else { result[i - 2] };
            result[i] = a[i].wrapping_add(next[i]).wrapping_add(sigma1(previous));
        }
        result
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
    use super::{super::test_utils, EmulatedNeon};

    #[test]
    fn common_contracts() {
        test_utils::common(EmulatedNeon);
        test_utils::basic_common(EmulatedNeon);
    }

    #[test]
    fn profile_contracts() {
        test_utils::neon(EmulatedNeon);
        test_utils::widening(EmulatedNeon);
    }
}

#[inline]
const fn sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline]
const fn sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

#[inline]
fn rounds(abcd: [u32; 4], efgh: [u32; 4], wk: [u32; 4]) -> [u32; 8] {
    let [mut a, mut b, mut c, mut d] = abcd;
    let [mut e, mut f, mut g, mut h] = efgh;
    for word in wk {
        let t1 = h
            .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
            .wrapping_add((e & f) ^ (!e & g))
            .wrapping_add(word);
        let t2 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
            .wrapping_add((a & b) ^ (a & c) ^ (b & c));
        (a, b, c, d, e, f, g, h) = (t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g);
    }
    [a, b, c, d, e, f, g, h]
}

#[cfg(test)]
mod sha_tests {
    use super::*;

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

    // Independently expands all 64 schedule words and updates one round at a time.
    fn oracle(mut state: [u32; 8], block: [u32; 16]) -> [u32; 8] {
        let initial = state;
        let mut w = [0u32; 64];
        w[..16].copy_from_slice(&block);
        for t in 16..64 {
            let x = w[t - 15];
            let y = w[t - 2];
            w[t] = w[t - 16]
                .wrapping_add(x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3))
                .wrapping_add(w[t - 7])
                .wrapping_add(y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10));
        }
        for t in 0..64 {
            let [a, b, c, d, e, f, g, h] = state;
            let choice = (e & f) | (!e & g);
            let majority = (a & b) | ((a | b) & c);
            let first = h
                .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
                .wrapping_add(choice)
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let second = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
                .wrapping_add(majority);
            state = [
                first.wrapping_add(second),
                a,
                b,
                c,
                d.wrapping_add(first),
                e,
                f,
                g,
            ];
        }
        core::array::from_fn(|i| initial[i].wrapping_add(state[i]))
    }

    fn compression<S: Neon>(simd: S, state: [u32; 8], block: [u32; 16]) -> [u32; 8] {
        let mut schedule = [simd.u32x4_load(&[0; 4]); 16];
        for i in 0..4 {
            schedule[i] = simd.u32x4_load(&block[4 * i..]);
        }
        for i in 4..16 {
            schedule[i] = simd.sha256_su1(
                simd.sha256_su0(schedule[i - 4], schedule[i - 3]),
                schedule[i - 2],
                schedule[i - 1],
            );
        }
        let mut abcd = simd.u32x4_load(&state);
        let mut efgh = simd.u32x4_load(&state[4..]);
        for i in 0..16 {
            let wk = simd.u32x4_add(schedule[i], simd.u32x4_load(&K[4 * i..]));
            let next = simd.sha256_h(abcd, efgh, wk);
            efgh = simd.sha256_h2(efgh, abcd, wk);
            abcd = next;
        }
        let mut result = [0; 8];
        simd.u32x4_store(simd.u32x4_add(abcd, simd.u32x4_load(&state)), &mut result);
        simd.u32x4_store(
            simd.u32x4_add(efgh, simd.u32x4_load(&state[4..])),
            &mut result[4..],
        );
        result
    }

    #[test]
    fn test_sha256_compression_oracle() {
        let simd = EmulatedNeon;
        for seed in [0u32, 1, 0x8000_0000, u32::MAX, 0x1234_5678] {
            let state =
                core::array::from_fn(|i| seed.wrapping_add((i as u32).wrapping_mul(0x9e37_79b9)));
            for word in [0, 1, u32::MAX, 0x8000_0000, 0xdead_beef] {
                let block =
                    core::array::from_fn(|i| word.wrapping_add((i as u32).wrapping_mul(seed)));
                assert_eq!(compression(simd, state, block), oracle(state, block));
                assert_eq!(
                    compression(crate::emulated::EmulatedArmV9, state, block),
                    oracle(state, block)
                );
            }
        }
        let initial = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let mut empty = [0; 16];
        empty[0] = 0x8000_0000;
        assert_eq!(
            compression(simd, initial, empty),
            [
                0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b,
                0x7852b855
            ]
        );
    }

    #[test]
    fn test_sha2_execution_path() {
        struct Path;
        impl<S: Simd> Operation<S> for Path {
            type Output = bool;
            fn portable(self, _: S) -> bool {
                false
            }
            fn neon(self, _: S) -> bool
            where
                S: Neon,
            {
                true
            }
        }
        assert!(EmulatedNeon.execute(Path));
    }
}

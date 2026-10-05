//! Array-backed execution tokens that run every instruction profile on any host.
//!
//! These tokens select their corresponding operation paths without using native SIMD
//! instructions. Vectors preserve lane order and wrapping arithmetic at each profile's
//! width.
//!
//! # Examples
//!
//! ```
//! use commonware_simd::{emulated::EmulatedIceLake, Simd};
//!
//! let s = EmulatedIceLake;
//! let sum = s.u64_add(s.u64_splat(u64::MAX), s.u64_splat(1));
//! let mut output = [0; 8];
//! s.u64_store(sum, &mut output);
//! assert_eq!(output, [0; 8]);
//! ```

mod arm_v9;
mod ice_lake;
mod neon;
mod scalar;

pub use arm_v9::EmulatedArmV9;
pub use ice_lake::EmulatedIceLake;
pub use neon::EmulatedNeon;
pub use scalar::EmulatedScalar;

#[cfg(test)]
mod test_utils {
    //! Shared scalar oracles for emulator unit tests.

    use crate::{Neon, Simd};
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        vec,
        vec::Vec,
    };

    fn bytes<S: Simd>(s: S, v: S::U8) -> Vec<u8> {
        let mut out = vec![0xa5; S::U8_LANES + 1];
        s.u8_store(v, &mut out);
        assert_eq!(out.pop(), Some(0xa5));
        out
    }
    pub fn words<S: Simd>(s: S, v: S::U32) -> Vec<u32> {
        let mut out = vec![0xa5; S::U32_LANES + 1];
        s.u32_store(v, &mut out);
        assert_eq!(out.pop(), Some(0xa5));
        out
    }
    fn longs<S: Simd>(s: S, v: S::U64) -> Vec<u64> {
        let mut out = vec![0xa5; S::U64_LANES + 1];
        s.u64_store(v, &mut out);
        assert_eq!(out.pop(), Some(0xa5));
        out
    }

    pub fn common<S: Simd>(s: S) {
        let a: Vec<u8> = (0..S::U8_LANES)
            .map(|i| (i as u8).wrapping_mul(73).wrapping_add(0x81))
            .collect();
        let b: Vec<u8> = a.iter().map(|v| v.rotate_left(3) ^ 0xa6).collect();
        let av = s.u8_load(&a);
        let bv = s.u8_load(&b);
        for len in 0..=S::U8_LANES {
            let mut expected = vec![0; S::U8_LANES];
            expected[..len].copy_from_slice(&a[..len]);
            assert_eq!(bytes(s, s.u8_load_partial(&a[..len])), expected);
            let mut out = vec![0xa5; S::U8_LANES + 2];
            s.u8_store_partial(av, &mut out[1..len + 1]);
            assert_eq!(&out[1..len + 1], &a[..len]);
            assert_eq!(out[0], 0xa5);
            assert!(out[len + 1..].iter().all(|v| *v == 0xa5));
            assert_eq!(
                s.u8_xor_fold(s.u8_load_partial(&a[..len])),
                a[..len].iter().fold(0, |acc, v| acc ^ v)
            );
        }
        for len in [S::U8_LANES + 1, S::U8_LANES + 17] {
            let mut out = vec![0xa5; len];
            assert!(catch_unwind(AssertUnwindSafe(|| s.u8_load_partial(&out))).is_err());
            assert!(catch_unwind(AssertUnwindSafe(|| s.u8_store_partial(av, &mut out))).is_err());
            assert_eq!(out, vec![0xa5; len]);
        }
        assert_eq!(
            bytes(s, s.u8_and(av, bv)),
            a.iter().zip(&b).map(|(x, y)| x & y).collect::<Vec<_>>()
        );
        fn byte_shift<S: Simd, const N: u32>(s: S, a: &[u8]) {
            assert_eq!(
                bytes(s, s.u8_shl::<N>(s.u8_load(a))),
                a.iter().map(|x| x << N).collect::<Vec<_>>()
            );
            assert_eq!(
                bytes(s, s.u8_shr::<N>(s.u8_load(a))),
                a.iter().map(|x| x >> N).collect::<Vec<_>>()
            );
        }
        macro_rules! byte_shifts { ($($n:literal),*) => { $(byte_shift::<S,$n>(s,&a);)* }; }
        byte_shifts!(0, 1, 2, 3, 4, 5, 6, 7);
        assert!(catch_unwind(AssertUnwindSafe(|| s.u8_shl::<8>(av))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| s.u8_shr::<8>(av))).is_err());

        let a: Vec<u32> = (0..S::U32_LANES)
            .map(|i| {
                0xfedc_ba98u32
                    .rotate_left(i as u32)
                    .wrapping_add(i as u32 * 137)
            })
            .collect();
        let b: Vec<u32> = (0..S::U32_LANES)
            .map(|i| 0x1357_2468u32.wrapping_mul(i as u32 + 1))
            .collect();
        let mask: Vec<u32> = (0..S::U32_LANES)
            .map(|i| [0, u32::MAX, 0xa53c_7e81, 0x8000_0001][i % 4])
            .collect();
        let av = s.u32_load(&a);
        let bv = s.u32_load(&b);
        for (x, y) in [(0, 1), (u32::MAX, 1), (0, u32::MAX)] {
            assert_eq!(
                words(s, s.u32_sub(s.u32_splat(x), s.u32_splat(y))),
                vec![x.wrapping_sub(y); S::U32_LANES]
            );
        }
        for (actual, expected) in [
            (
                s.u32_sub(av, bv),
                a.iter()
                    .zip(&b)
                    .map(|(x, y)| x.wrapping_sub(*y))
                    .collect::<Vec<_>>(),
            ),
            (
                s.u32_and(av, bv),
                a.iter().zip(&b).map(|(x, y)| x & y).collect(),
            ),
            (
                s.u32_or(av, bv),
                a.iter().zip(&b).map(|(x, y)| x | y).collect(),
            ),
            (
                s.u32_select(s.u32_load(&mask), av, bv),
                (0..a.len())
                    .map(|i| (mask[i] & a[i]) | (!mask[i] & b[i]))
                    .collect(),
            ),
        ] {
            assert_eq!(words(s, actual), expected);
        }
        macro_rules! word_shifts { ($($n:literal),*) => { $(
            assert_eq!(words(s,s.u32_shl::<$n>(av)),a.iter().map(|x| x << $n).collect::<Vec<_>>());
            assert_eq!(words(s,s.u32_shr::<$n>(av)),a.iter().map(|x| x >> $n).collect::<Vec<_>>());
        )* }; }
        word_shifts!(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31
        );
        assert!(catch_unwind(AssertUnwindSafe(|| s.u32_shl::<32>(av))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| s.u32_shr::<32>(av))).is_err());
        // Rotate every possible source into lane zero, crossing every group boundary.
        for source in 0..2 * S::U32_LANES {
            let mut idx: Vec<usize> = (0..S::U32_LANES)
                .map(|i| (source + i) % S::U32_LANES)
                .collect();
            idx.push(usize::MAX); // Inactive trailing indices are ignored.
            assert_eq!(
                words(s, s.u32_permute(av, &idx)),
                idx[..S::U32_LANES]
                    .iter()
                    .map(|i| a[*i])
                    .collect::<Vec<_>>()
            );
            let mut idx: Vec<usize> = (0..S::U32_LANES)
                .map(|i| (source + i) % (2 * S::U32_LANES))
                .collect();
            idx.push(usize::MAX);
            assert_eq!(
                words(s, s.u32_permute2(av, bv, &idx)),
                idx[..S::U32_LANES]
                    .iter()
                    .map(|i| if *i < a.len() { a[*i] } else { b[*i - a.len()] })
                    .collect::<Vec<_>>()
            );
        }
        for len in 0..S::U32_LANES {
            let idx = vec![0; len];
            assert!(catch_unwind(AssertUnwindSafe(|| s.u32_permute(av, &idx))).is_err());
            assert!(catch_unwind(AssertUnwindSafe(|| s.u32_permute2(av, bv, &idx))).is_err());
        }
        for lane in 0..S::U32_LANES {
            for invalid in [S::U32_LANES, usize::MAX] {
                let mut idx = vec![0; S::U32_LANES];
                idx[lane] = invalid;
                assert!(catch_unwind(AssertUnwindSafe(|| s.u32_permute(av, &idx))).is_err());
                idx[lane] = if invalid == usize::MAX {
                    invalid
                } else {
                    2 * S::U32_LANES
                };
                assert!(catch_unwind(AssertUnwindSafe(|| s.u32_permute2(av, bv, &idx))).is_err());
            }
        }
        assert_eq!(words(s, av), a);
        assert_eq!(words(s, bv), b);

        let a: Vec<u64> = (0..S::U64_LANES)
            .map(|i| 0xfedc_ba98_7654_3210u64.rotate_left(i as u32 * 7))
            .collect();
        let b: Vec<u64> = (0..S::U64_LANES)
            .map(|i| 0x1234_5678_9abc_def0u64.wrapping_mul(i as u64 + 1))
            .collect();
        let mask: Vec<u64> = (0..S::U64_LANES)
            .map(|i| 0x81a5_3c7e_0180_ff00u64.rotate_left(i as u32 * 13))
            .collect();
        let av = s.u64_load(&a);
        let bv = s.u64_load(&b);
        for len in 0..S::U64_LANES {
            let mut out = vec![0xa5; len];
            assert!(catch_unwind(AssertUnwindSafe(|| s.u64_load(&out))).is_err());
            assert!(catch_unwind(AssertUnwindSafe(|| s.u64_store(av, &mut out))).is_err());
            assert_eq!(out, vec![0xa5; len]);
        }
        for (x, y) in [(0, 1), (u64::MAX, 1), (0, u64::MAX)] {
            assert_eq!(
                longs(s, s.u64_sub(s.u64_splat(x), s.u64_splat(y))),
                vec![x.wrapping_sub(y); S::U64_LANES]
            );
        }
        assert_eq!(
            longs(s, s.u64_sub(av, bv)),
            a.iter()
                .zip(&b)
                .map(|(x, y)| x.wrapping_sub(*y))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            longs(s, s.u64_xor(av, bv)),
            a.iter().zip(&b).map(|(x, y)| x ^ y).collect::<Vec<_>>()
        );
        assert_eq!(
            longs(s, s.u64_select(s.u64_load(&mask), av, bv)),
            (0..a.len())
                .map(|i| (mask[i] & a[i]) | (!mask[i] & b[i]))
                .collect::<Vec<_>>()
        );
        macro_rules! lanes { ($($n:literal),*) => { $(
            if $n < S::U64_LANES {
                assert_eq!(s.u64_extract::<$n>(av),a[$n]);
                let mut expected=a.clone(); expected[$n]=0x0123_4567_89ab_cdef;
                assert_eq!(longs(s,s.u64_insert::<$n>(av,expected[$n])),expected);
            } else {
                assert!(catch_unwind(AssertUnwindSafe(|| s.u64_extract::<$n>(av))).is_err());
                assert!(catch_unwind(AssertUnwindSafe(|| s.u64_insert::<$n>(av,0))).is_err());
                assert_eq!(longs(s,av),a);
            }
        )* }; }
        lanes!(0, 1, 2, 3, 4, 5, 6, 7, 8, 64);
    }

    pub fn basic_common<S: Simd>(s: S) {
        let a: Vec<u64> = (0..S::U64_LANES).map(|i| u64::MAX >> i).collect();
        let b: Vec<u64> = (0..S::U64_LANES).map(|i| 1u64 << i).collect();
        let av = s.u64_load(&a);
        let bv = s.u64_load(&b);
        let cases = [
            (
                s.u64_and(av, bv),
                a.iter().zip(&b).map(|(a, b)| a & b).collect(),
            ),
            (
                s.u64_or(av, bv),
                a.iter().zip(&b).map(|(a, b)| a | b).collect(),
            ),
            (s.u64_shl::<0>(av), a.clone()),
            (s.u64_shl::<63>(av), a.iter().map(|a| a << 63).collect()),
            (s.u64_shr::<0>(av), a.clone()),
            (s.u64_shr::<63>(av), a.iter().map(|a| a >> 63).collect()),
        ];
        for (actual, expected) in cases {
            let mut output = vec![42; S::U64_LANES + 1];
            s.u64_store(actual, &mut output);
            assert_eq!(&output[..S::U64_LANES], expected);
            assert_eq!(output[S::U64_LANES], 42);
        }

        let words: Vec<u32> = (0..S::U32_LANES)
            .map(|i| u32::MAX.rotate_right(i as u32) ^ (i as u32))
            .collect();
        let v = s.u32_load(&words);
        let mut output = vec![42; S::U32_LANES + 1];
        for (actual, expected) in [
            (
                s.u32_add(v, s.u32_splat(1)),
                words.iter().map(|v| v.wrapping_add(1)).collect::<Vec<_>>(),
            ),
            (
                s.u32_xor(v, s.u32_splat(0xdeadbeef)),
                words.iter().map(|v| v ^ 0xdeadbeef).collect(),
            ),
            (s.u32_rotate_right::<0>(v), words.clone()),
            (
                s.u32_rotate_right::<31>(v),
                words.iter().map(|v| v.rotate_right(31)).collect(),
            ),
        ] {
            s.u32_store(actual, &mut output);
            assert_eq!(&output[..S::U32_LANES], expected);
            assert_eq!(output[S::U32_LANES], 42);
        }
        let bytes: Vec<u8> = (0..S::U8_LANES).map(|i| i as u8).collect();
        let mut output = vec![42; S::U8_LANES + 1];
        s.u8_store(s.u8_xor(s.u8_load(&bytes), s.u8_splat(255)), &mut output);
        assert_eq!(
            &output[..S::U8_LANES],
            bytes.iter().map(|v| !v).collect::<Vec<_>>()
        );
        assert_eq!(output[S::U8_LANES], 42);

        for len in 0..S::U8_LANES {
            let mut output = vec![42; len];
            assert!(catch_unwind(AssertUnwindSafe(|| s.u8_load(&output))).is_err());
            assert!(
                catch_unwind(AssertUnwindSafe(|| s.u8_store(s.u8_splat(0), &mut output))).is_err()
            );
            assert_eq!(output, vec![42; len]);
        }
        for len in 0..S::U32_LANES {
            let mut output = vec![42; len];
            assert!(catch_unwind(AssertUnwindSafe(|| s.u32_load(&output))).is_err());
            assert!(
                catch_unwind(AssertUnwindSafe(|| s.u32_store(s.u32_splat(0), &mut output)))
                    .is_err()
            );
            assert_eq!(output, vec![42; len]);
        }
    }

    fn polynomial(a: u8, b: u8) -> u16 {
        let mut product = 0;
        for bit in 0..8 {
            if b & (1 << bit) != 0 {
                product ^= (a as u16) << bit;
            }
        }
        product
    }
    // Observe both bytes of U16 without depending on its backend representation.
    fn halves<S: Neon>(s: S, low: S::U16, high: S::U16) -> Vec<u16> {
        let lo = bytes(s, s.u16_narrow_pair(low, high));
        let hi = bytes(
            s,
            s.u16_narrow_pair(s.u16_shr::<8>(low), s.u16_shr::<8>(high)),
        );
        lo.into_iter()
            .zip(hi)
            .map(|(l, h)| l as u16 | ((h as u16) << 8))
            .collect()
    }
    pub fn neon<S: Neon>(s: S) {
        let table: Vec<u8> = (0..16).map(|i| 0x83u8.wrapping_add(i * 7)).collect();
        for base in (0..256).step_by(16) {
            let idx: Vec<u8> = (base..base + 16).map(|i| i as u8).collect();
            assert_eq!(
                bytes(s, s.u8_table_lookup(s.u8_load(&table), s.u8_load(&idx))),
                idx.iter()
                    .map(|i| table.get(*i as usize).copied().unwrap_or(0))
                    .collect::<Vec<_>>()
            );
        }
        // Every byte pair appears in every lane, including the high half.
        for a in 0..=255u8 {
            for base in (0..256).step_by(16) {
                let aa: Vec<u8> = (0..16).map(|i| a.wrapping_add(i as u8 * 13)).collect();
                let bb: Vec<u8> = (0..16).map(|i| (base + i) as u8).collect();
                let av = s.u8_load(&aa);
                let bv = s.u8_load(&bb);
                let lo = s.u8_clmul_lo(av, bv);
                let hi = s.u8_clmul_hi(av, bv);
                let expected: Vec<u16> = aa
                    .iter()
                    .zip(&bb)
                    .map(|(a, b)| polynomial(*a, *b))
                    .collect();
                assert_eq!(halves(s, lo, hi), expected);
                assert_eq!(
                    bytes(s, s.u16_narrow_pair(lo, hi)),
                    expected.iter().map(|x| *x as u8).collect::<Vec<_>>()
                );
                assert_eq!(
                    halves(s, s.u16_xor(lo, hi), s.u16_xor(hi, lo)),
                    (0..16)
                        .map(|i| expected[i % 8] ^ expected[8 + i % 8])
                        .collect::<Vec<_>>()
                );
                macro_rules! half_shifts { ($($n:literal),*) => { $(
                assert_eq!(halves(s,s.u16_shl::<$n>(lo),s.u16_shl::<$n>(hi)),expected.iter().map(|x| x << $n).collect::<Vec<_>>());
                assert_eq!(halves(s,s.u16_shr::<$n>(lo),s.u16_shr::<$n>(hi)),expected.iter().map(|x| x >> $n).collect::<Vec<_>>());
            )* }; }
                half_shifts!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            }
        }
        let v = s.u8_clmul_lo(s.u8_splat(255), s.u8_splat(255));
        let before = halves(s, v, v);
        assert!(catch_unwind(AssertUnwindSafe(|| s.u16_shl::<16>(v))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| s.u16_shr::<16>(v))).is_err());
        assert_eq!(halves(s, v, v), before);
        for a in [0, 1, 0x8000_0000, u32::MAX] {
            for b in [0, 1, 0x89ab_cdef, u32::MAX] {
                let acc = [u64::MAX, 0x1234_5678_9abc_def0];
                let aa = [a as u64, a.wrapping_add(17) as u64];
                let bb = [b as u64, b.wrapping_add(31) as u64];
                assert_eq!(
                    longs(
                        s,
                        s.u32_widen_madd(
                            s.u64_load(&acc),
                            s.u64_narrow(s.u64_load(&aa)),
                            s.u64_narrow(s.u64_load(&bb))
                        )
                    ),
                    (0..2)
                        .map(|i| acc[i].wrapping_add(aa[i] * bb[i]))
                        .collect::<Vec<_>>()
                );
            }
        }
    }

    pub fn widening<S: Neon>(s: S) {
        let input = [u64::MAX, 0x1234_5678_9abc_def0];
        let a = s.u64_narrow(s.u64_load(&input));
        let mut output = [0; 2];
        s.u64_store(s.u32_widen_mul(a, s.u32_half_splat(u32::MAX)), &mut output);
        assert_eq!(output, input.map(|v| (v as u32 as u64) * u32::MAX as u64));
        s.u64_store(
            s.u32_widen_mul(s.u32_half_add(a, s.u32_half_splat(1)), s.u32_half_splat(1)),
            &mut output,
        );
        assert_eq!(output, input.map(|v| (v as u32).wrapping_add(1) as u64));
        s.u64_store(
            s.u32_widen_mul(s.u32_half_shl::<31>(a), s.u32_half_splat(1)),
            &mut output,
        );
        assert_eq!(output, input.map(|v| ((v as u32) << 31) as u64));
    }
}

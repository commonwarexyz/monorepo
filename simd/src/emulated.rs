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
//! let simd = EmulatedIceLake;
//! let sum = simd.u64_add(simd.u64_splat(u64::MAX), simd.u64_splat(1));
//! let mut output = [0; 8];
//! simd.u64_store(sum, &mut output);
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

    fn bytes<S: Simd>(simd: S, v: S::U8) -> Vec<u8> {
        let mut out = vec![0xa5; S::U8_LANES + 1];
        simd.u8_store(v, &mut out);
        assert_eq!(out.pop(), Some(0xa5));
        out
    }
    pub fn words<S: Simd>(simd: S, v: S::U32) -> Vec<u32> {
        let mut out = vec![0xa5; S::U32_LANES + 1];
        simd.u32_store(v, &mut out);
        assert_eq!(out.pop(), Some(0xa5));
        out
    }
    fn longs<S: Simd>(simd: S, v: S::U64) -> Vec<u64> {
        let mut out = vec![0xa5; S::U64_LANES + 1];
        simd.u64_store(v, &mut out);
        assert_eq!(out.pop(), Some(0xa5));
        out
    }

    pub fn common<S: Simd>(simd: S) {
        let a: Vec<u8> = (0..S::U8_LANES)
            .map(|i| (i as u8).wrapping_mul(73).wrapping_add(0x81))
            .collect();
        let b: Vec<u8> = a.iter().map(|v| v.rotate_left(3) ^ 0xa6).collect();
        let av = simd.u8_load(&a);
        let bv = simd.u8_load(&b);
        for len in 0..=S::U8_LANES {
            let mut expected = vec![0; S::U8_LANES];
            expected[..len].copy_from_slice(&a[..len]);
            assert_eq!(bytes(simd, simd.u8_load_partial(&a[..len])), expected);
            let mut out = vec![0xa5; S::U8_LANES + 2];
            simd.u8_store_partial(av, &mut out[1..len + 1]);
            assert_eq!(&out[1..len + 1], &a[..len]);
            assert_eq!(out[0], 0xa5);
            assert!(out[len + 1..].iter().all(|v| *v == 0xa5));
            assert_eq!(
                simd.u8_xor_fold(simd.u8_load_partial(&a[..len])),
                a[..len].iter().fold(0, |acc, v| acc ^ v)
            );
        }
        for len in [S::U8_LANES + 1, S::U8_LANES + 17] {
            let mut out = vec![0xa5; len];
            assert!(catch_unwind(AssertUnwindSafe(|| simd.u8_load_partial(&out))).is_err());
            assert!(
                catch_unwind(AssertUnwindSafe(|| simd.u8_store_partial(av, &mut out))).is_err()
            );
            assert_eq!(out, vec![0xa5; len]);
        }
        assert_eq!(
            bytes(simd, simd.u8_and(av, bv)),
            a.iter().zip(&b).map(|(x, y)| x & y).collect::<Vec<_>>()
        );
        fn byte_shift<S: Simd, const N: u32>(simd: S, a: &[u8]) {
            assert_eq!(
                bytes(simd, simd.u8_shl::<N>(simd.u8_load(a))),
                a.iter().map(|x| x << N).collect::<Vec<_>>()
            );
            assert_eq!(
                bytes(simd, simd.u8_shr::<N>(simd.u8_load(a))),
                a.iter().map(|x| x >> N).collect::<Vec<_>>()
            );
        }
        macro_rules! byte_shifts { ($($n:literal),*) => { $(byte_shift::<S,$n>(simd,&a);)* }; }
        byte_shifts!(0, 1, 2, 3, 4, 5, 6, 7);
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u8_shl::<8>(av))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u8_shr::<8>(av))).is_err());

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
        let av = simd.u32_load(&a);
        let bv = simd.u32_load(&b);
        for (x, y) in [(0, 1), (u32::MAX, 1), (0, u32::MAX)] {
            assert_eq!(
                words(simd, simd.u32_sub(simd.u32_splat(x), simd.u32_splat(y))),
                vec![x.wrapping_sub(y); S::U32_LANES]
            );
        }
        for (actual, expected) in [
            (
                simd.u32_sub(av, bv),
                a.iter()
                    .zip(&b)
                    .map(|(x, y)| x.wrapping_sub(*y))
                    .collect::<Vec<_>>(),
            ),
            (
                simd.u32_and(av, bv),
                a.iter().zip(&b).map(|(x, y)| x & y).collect(),
            ),
            (
                simd.u32_or(av, bv),
                a.iter().zip(&b).map(|(x, y)| x | y).collect(),
            ),
            (
                simd.u32_select(simd.u32_load(&mask), av, bv),
                (0..a.len())
                    .map(|i| (mask[i] & a[i]) | (!mask[i] & b[i]))
                    .collect(),
            ),
        ] {
            assert_eq!(words(simd, actual), expected);
        }
        macro_rules! word_shifts { ($($n:literal),*) => { $(
            assert_eq!(words(simd,simd.u32_shl::<$n>(av)),a.iter().map(|x| x << $n).collect::<Vec<_>>());
            assert_eq!(words(simd,simd.u32_shr::<$n>(av)),a.iter().map(|x| x >> $n).collect::<Vec<_>>());
        )* }; }
        word_shifts!(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31
        );
        macro_rules! word_rotations { ($($n:literal),*) => { $(
            assert_eq!(words(simd,simd.u32_rotate_right::<$n>(av)),a.iter().map(|x| x.rotate_right($n)).collect::<Vec<_>>());
        )* }; }
        word_rotations!(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31
        );
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u32_rotate_right::<32>(av))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u32_shl::<32>(av))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u32_shr::<32>(av))).is_err());
        // Rotate every possible source into lane zero, crossing every group boundary.
        for source in 0..2 * S::U32_LANES {
            let mut idx: Vec<usize> = (0..S::U32_LANES)
                .map(|i| (source + i) % S::U32_LANES)
                .collect();
            idx.push(usize::MAX); // Inactive trailing indices are ignored.
            assert_eq!(
                words(simd, simd.u32_permute(av, &idx)),
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
                words(simd, simd.u32_permute2(av, bv, &idx)),
                idx[..S::U32_LANES]
                    .iter()
                    .map(|i| if *i < a.len() { a[*i] } else { b[*i - a.len()] })
                    .collect::<Vec<_>>()
            );
        }
        for len in 0..S::U32_LANES {
            let idx = vec![0; len];
            assert!(catch_unwind(AssertUnwindSafe(|| simd.u32_permute(av, &idx))).is_err());
            assert!(catch_unwind(AssertUnwindSafe(|| simd.u32_permute2(av, bv, &idx))).is_err());
        }
        for lane in 0..S::U32_LANES {
            for invalid in [S::U32_LANES, usize::MAX] {
                let mut idx = vec![0; S::U32_LANES];
                idx[lane] = invalid;
                assert!(catch_unwind(AssertUnwindSafe(|| simd.u32_permute(av, &idx))).is_err());
                idx[lane] = if invalid == usize::MAX {
                    invalid
                } else {
                    2 * S::U32_LANES
                };
                assert!(
                    catch_unwind(AssertUnwindSafe(|| simd.u32_permute2(av, bv, &idx))).is_err()
                );
            }
        }
        assert_eq!(words(simd, av), a);
        assert_eq!(words(simd, bv), b);

        let a: Vec<u64> = (0..S::U64_LANES)
            .map(|i| 0xfedc_ba98_7654_3210u64.rotate_left(i as u32 * 7))
            .collect();
        let b: Vec<u64> = (0..S::U64_LANES)
            .map(|i| 0x1234_5678_9abc_def0u64.wrapping_mul(i as u64 + 1))
            .collect();
        let mask: Vec<u64> = (0..S::U64_LANES)
            .map(|i| 0x81a5_3c7e_0180_ff00u64.rotate_left(i as u32 * 13))
            .collect();
        let av = simd.u64_load(&a);
        let bv = simd.u64_load(&b);
        macro_rules! long_shifts { ($($n:literal),*) => { $(
            assert_eq!(longs(simd,simd.u64_shl::<$n>(av)),a.iter().map(|x| x << $n).collect::<Vec<_>>());
            assert_eq!(longs(simd,simd.u64_shr::<$n>(av)),a.iter().map(|x| x >> $n).collect::<Vec<_>>());
        )* }; }
        long_shifts!(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63
        );
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u64_shl::<64>(av))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u64_shr::<64>(av))).is_err());
        assert_eq!(
            longs(simd, simd.u64_add(av, bv)),
            a.iter()
                .zip(&b)
                .map(|(x, y)| x.wrapping_add(*y))
                .collect::<Vec<_>>()
        );
        let boundaries = [
            0,
            1,
            u64::MAX - 1,
            u64::MAX,
            (1 << 32) - 1,
            1 << 32,
            (1 << 63) - 1,
            1 << 63,
        ];
        for x in boundaries {
            for y in boundaries {
                assert_eq!(
                    longs(simd, simd.u64_add(simd.u64_splat(x), simd.u64_splat(y))),
                    vec![x.wrapping_add(y); S::U64_LANES]
                );
            }
        }
        // Exercise carry propagation through every bit in every lane.
        for bits in 1..=64 {
            let x = u64::MAX >> (64 - bits);
            assert_eq!(
                longs(simd, simd.u64_add(simd.u64_splat(x), simd.u64_splat(1))),
                vec![x.wrapping_add(1); S::U64_LANES]
            );
        }
        // Distinct operands per lane expose accidental carries between lanes.
        for seed in 0..256u64 {
            let a: Vec<u64> = (0..S::U64_LANES)
                .map(|i| {
                    seed.wrapping_add(i as u64)
                        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                        .rotate_left(i as u32 * 7)
                })
                .collect();
            let b: Vec<u64> = (0..S::U64_LANES)
                .map(|i| {
                    seed.wrapping_mul(0xd1b5_4a32_d192_ed03)
                        .wrapping_add(i as u64)
                        .rotate_right(i as u32 * 13)
                })
                .collect();
            assert_eq!(
                longs(simd, simd.u64_add(simd.u64_load(&a), simd.u64_load(&b))),
                a.iter()
                    .zip(&b)
                    .map(|(x, y)| x.wrapping_add(*y))
                    .collect::<Vec<_>>()
            );
        }
        for len in 0..S::U64_LANES {
            let mut out = vec![0xa5; len];
            assert!(catch_unwind(AssertUnwindSafe(|| simd.u64_load(&out))).is_err());
            assert!(catch_unwind(AssertUnwindSafe(|| simd.u64_store(av, &mut out))).is_err());
            assert_eq!(out, vec![0xa5; len]);
        }
        for (x, y) in [(0, 1), (u64::MAX, 1), (0, u64::MAX)] {
            assert_eq!(
                longs(simd, simd.u64_sub(simd.u64_splat(x), simd.u64_splat(y))),
                vec![x.wrapping_sub(y); S::U64_LANES]
            );
        }
        assert_eq!(
            longs(simd, simd.u64_sub(av, bv)),
            a.iter()
                .zip(&b)
                .map(|(x, y)| x.wrapping_sub(*y))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            longs(simd, simd.u64_xor(av, bv)),
            a.iter().zip(&b).map(|(x, y)| x ^ y).collect::<Vec<_>>()
        );
        assert_eq!(
            longs(simd, simd.u64_select(simd.u64_load(&mask), av, bv)),
            (0..a.len())
                .map(|i| (mask[i] & a[i]) | (!mask[i] & b[i]))
                .collect::<Vec<_>>()
        );
        macro_rules! lanes { ($($n:literal),*) => { $(
            if $n < S::U64_LANES {
                assert_eq!(simd.u64_extract::<$n>(av),a[$n]);
                let mut expected=a.clone(); expected[$n]=0x0123_4567_89ab_cdef;
                assert_eq!(longs(simd,simd.u64_insert::<$n>(av,expected[$n])),expected);
            } else {
                assert!(catch_unwind(AssertUnwindSafe(|| simd.u64_extract::<$n>(av))).is_err());
                assert!(catch_unwind(AssertUnwindSafe(|| simd.u64_insert::<$n>(av,0))).is_err());
                assert_eq!(longs(simd,av),a);
            }
        )* }; }
        lanes!(0, 1, 2, 3, 4, 5, 6, 7, 8, 64);
    }

    pub fn basic_common<S: Simd>(simd: S) {
        let a: Vec<u64> = (0..S::U64_LANES).map(|i| u64::MAX >> i).collect();
        let b: Vec<u64> = (0..S::U64_LANES).map(|i| 1u64 << i).collect();
        let av = simd.u64_load(&a);
        let bv = simd.u64_load(&b);
        let cases = [
            (
                simd.u64_and(av, bv),
                a.iter().zip(&b).map(|(a, b)| a & b).collect(),
            ),
            (
                simd.u64_or(av, bv),
                a.iter().zip(&b).map(|(a, b)| a | b).collect(),
            ),
            (simd.u64_shl::<0>(av), a.clone()),
            (simd.u64_shl::<63>(av), a.iter().map(|a| a << 63).collect()),
            (simd.u64_shr::<0>(av), a.clone()),
            (simd.u64_shr::<63>(av), a.iter().map(|a| a >> 63).collect()),
        ];
        for (actual, expected) in cases {
            let mut output = vec![42; S::U64_LANES + 1];
            simd.u64_store(actual, &mut output);
            assert_eq!(&output[..S::U64_LANES], expected);
            assert_eq!(output[S::U64_LANES], 42);
        }

        let words: Vec<u32> = (0..S::U32_LANES)
            .map(|i| u32::MAX.rotate_right(i as u32) ^ (i as u32))
            .collect();
        let v = simd.u32_load(&words);
        let mut output = vec![42; S::U32_LANES + 1];
        for (actual, expected) in [
            (
                simd.u32_add(v, simd.u32_splat(1)),
                words.iter().map(|v| v.wrapping_add(1)).collect::<Vec<_>>(),
            ),
            (
                simd.u32_xor(v, simd.u32_splat(0xdeadbeef)),
                words.iter().map(|v| v ^ 0xdeadbeef).collect(),
            ),
            (simd.u32_rotate_right::<0>(v), words.clone()),
            (
                simd.u32_rotate_right::<31>(v),
                words.iter().map(|v| v.rotate_right(31)).collect(),
            ),
        ] {
            simd.u32_store(actual, &mut output);
            assert_eq!(&output[..S::U32_LANES], expected);
            assert_eq!(output[S::U32_LANES], 42);
        }
        let bytes: Vec<u8> = (0..S::U8_LANES).map(|i| i as u8).collect();
        let mut output = vec![42; S::U8_LANES + 1];
        simd.u8_store(
            simd.u8_xor(simd.u8_load(&bytes), simd.u8_splat(255)),
            &mut output,
        );
        assert_eq!(
            &output[..S::U8_LANES],
            bytes.iter().map(|v| !v).collect::<Vec<_>>()
        );
        assert_eq!(output[S::U8_LANES], 42);

        for len in 0..S::U8_LANES {
            let mut output = vec![42; len];
            assert!(catch_unwind(AssertUnwindSafe(|| simd.u8_load(&output))).is_err());
            assert!(
                catch_unwind(AssertUnwindSafe(
                    || simd.u8_store(simd.u8_splat(0), &mut output)
                ))
                .is_err()
            );
            assert_eq!(output, vec![42; len]);
        }
        for len in 0..S::U32_LANES {
            let mut output = vec![42; len];
            assert!(catch_unwind(AssertUnwindSafe(|| simd.u32_load(&output))).is_err());
            assert!(
                catch_unwind(AssertUnwindSafe(
                    || simd.u32_store(simd.u32_splat(0), &mut output)
                ))
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
    fn halves<S: Neon>(simd: S, low: S::U16, high: S::U16) -> Vec<u16> {
        let lo = bytes(simd, simd.u16_narrow_pair(low, high));
        let hi = bytes(
            simd,
            simd.u16_narrow_pair(simd.u16_shr::<8>(low), simd.u16_shr::<8>(high)),
        );
        lo.into_iter()
            .zip(hi)
            .map(|(l, h)| l as u16 | ((h as u16) << 8))
            .collect()
    }
    pub fn neon<S: Neon>(simd: S) {
        let table: Vec<u8> = (0..16).map(|i| 0x83u8.wrapping_add(i * 7)).collect();
        for base in (0..256).step_by(16) {
            let idx: Vec<u8> = (base..base + 16).map(|i| i as u8).collect();
            assert_eq!(
                bytes(
                    simd,
                    simd.u8_table_lookup(simd.u8_load(&table), simd.u8_load(&idx))
                ),
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
                let av = simd.u8_load(&aa);
                let bv = simd.u8_load(&bb);
                let lo = simd.u8_clmul_lo(av, bv);
                let hi = simd.u8_clmul_hi(av, bv);
                let expected: Vec<u16> = aa
                    .iter()
                    .zip(&bb)
                    .map(|(a, b)| polynomial(*a, *b))
                    .collect();
                assert_eq!(halves(simd, lo, hi), expected);
                assert_eq!(
                    bytes(simd, simd.u16_narrow_pair(lo, hi)),
                    expected.iter().map(|x| *x as u8).collect::<Vec<_>>()
                );
                assert_eq!(
                    halves(simd, simd.u16_xor(lo, hi), simd.u16_xor(hi, lo)),
                    (0..16)
                        .map(|i| expected[i % 8] ^ expected[8 + i % 8])
                        .collect::<Vec<_>>()
                );
                macro_rules! half_shifts { ($($n:literal),*) => { $(
                assert_eq!(halves(simd,simd.u16_shl::<$n>(lo),simd.u16_shl::<$n>(hi)),expected.iter().map(|x| x << $n).collect::<Vec<_>>());
                assert_eq!(halves(simd,simd.u16_shr::<$n>(lo),simd.u16_shr::<$n>(hi)),expected.iter().map(|x| x >> $n).collect::<Vec<_>>());
            )* }; }
                half_shifts!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            }
        }
        let v = simd.u8_clmul_lo(simd.u8_splat(255), simd.u8_splat(255));
        let before = halves(simd, v, v);
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u16_shl::<16>(v))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u16_shr::<16>(v))).is_err());
        assert_eq!(halves(simd, v, v), before);
        for a in [0, 1, 0x8000_0000, u32::MAX] {
            for b in [0, 1, 0x89ab_cdef, u32::MAX] {
                let acc = [u64::MAX, 0x1234_5678_9abc_def0];
                let aa = [a as u64, a.wrapping_add(17) as u64];
                let bb = [b as u64, b.wrapping_add(31) as u64];
                assert_eq!(
                    longs(
                        simd,
                        simd.u32_widen_madd(
                            simd.u64_load(&acc),
                            simd.u64_narrow(simd.u64_load(&aa)),
                            simd.u64_narrow(simd.u64_load(&bb))
                        )
                    ),
                    (0..2)
                        .map(|i| acc[i].wrapping_add(aa[i] * bb[i]))
                        .collect::<Vec<_>>()
                );
            }
        }
    }

    pub fn widening<S: Neon>(simd: S) {
        let input = [u64::MAX, 0x1234_5678_9abc_def0];
        let a = simd.u64_narrow(simd.u64_load(&input));
        let mut output = [0; 2];
        simd.u64_store(
            simd.u32_widen_mul(a, simd.u32_half_splat(u32::MAX)),
            &mut output,
        );
        assert_eq!(output, input.map(|v| (v as u32 as u64) * u32::MAX as u64));
        simd.u64_store(
            simd.u32_widen_mul(
                simd.u32_half_add(a, simd.u32_half_splat(1)),
                simd.u32_half_splat(1),
            ),
            &mut output,
        );
        assert_eq!(output, input.map(|v| (v as u32).wrapping_add(1) as u64));
        simd.u64_store(
            simd.u32_widen_mul(simd.u32_half_shl::<31>(a), simd.u32_half_splat(1)),
            &mut output,
        );
        assert_eq!(output, input.map(|v| ((v as u32) << 31) as u64));
    }
}

#[cfg(test)]
mod fixed4_tests {
    use super::{EmulatedArmV9, EmulatedIceLake, EmulatedNeon, EmulatedScalar};
    use crate::Simd;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn words<S: Simd>(simd: S, value: S::U32x4) -> [u32; 4] {
        let mut output = [0xa5; 5];
        simd.u32x4_store(value, &mut output);
        assert_eq!(output[4], 0xa5);
        output[..4].try_into().unwrap()
    }

    fn contracts<S: Simd>(simd: S) {
        let a = [0x01234567, 0x89abcdef, u32::MAX, 0x80000000];
        let b = [0xfedcba98, 0x76543210, 1, 0x80000000];
        let av = simd.u32x4_load(&a);
        let bv = simd.u32x4_load(&b);
        assert_eq!(words(simd, av), a);
        assert_eq!(
            words(simd, simd.u32x4_add(av, bv)),
            [u32::MAX, u32::MAX, 0, 0]
        );
        let joined = [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]];
        macro_rules! aligns { ($($n:literal),*) => { $(
            assert_eq!(words(simd, simd.u32x4_align::<$n>(av, bv)), joined[$n..$n+4]);
        )* }; }
        aligns!(0, 1, 2, 3, 4);
        macro_rules! blends { ($($mask:literal),*) => { $(
            let mut expected = a;
            for (i, word) in expected.iter_mut().enumerate() {
                if ($mask / (1 << i)) % 2 == 1 { *word = b[i]; }
            }
            assert_eq!(words(simd, simd.u32x4_blend::<$mask>(av, bv)), expected);
        )* }; }
        blends!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        macro_rules! shuffles { ($($mask:literal),*) => { $(
            let mut selectors = $mask;
            let mut expected = [0; 4];
            for word in &mut expected { *word = a[selectors % 4]; selectors /= 4; }
            assert_eq!(words(simd, simd.u32x4_shuffle::<$mask>(av)), expected);
        )* }; }
        shuffles!(
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
        for offset in 0..=16 {
            let input: [u8; 49] =
                core::array::from_fn(|i| (i as u8).wrapping_mul(73).wrapping_add(11));
            // Decode by positional accumulation, independently of backend endian conversion.
            let mut expected = [0u32; 4];
            for (i, byte) in input[offset..offset + 16].iter().enumerate() {
                expected[i / 4] = expected[i / 4] * 256 + u32::from(*byte);
            }
            let loaded = simd.u32x4_load_be(&input[offset..]);
            assert_eq!(words(simd, loaded), expected);
            assert_eq!(
                words(simd, simd.u32x4_load_be(&input[offset..offset + 16])),
                expected
            );
            assert_eq!(
                words(simd, simd.u32x4_load_be2(&input[offset..offset + 8])),
                [expected[0], expected[1], 0, 0]
            );
            assert_eq!(
                words(simd, simd.u32x4_load_be2(&input[offset..])),
                [expected[0], expected[1], 0, 0]
            );
            let mut output = [0xa5; 49];
            simd.u32x4_store_be(loaded, &mut output[offset..]);
            assert_eq!(&output[offset..offset + 16], &input[offset..offset + 16]);
            assert!(
                output[..offset]
                    .iter()
                    .chain(&output[offset + 16..])
                    .all(|b| *b == 0xa5)
            );
        }
        for len in 0..16 {
            let mut output = [0xa5; 16];
            assert!(catch_unwind(AssertUnwindSafe(|| simd.u32x4_load_be(&output[..len]))).is_err());
            assert!(
                catch_unwind(AssertUnwindSafe(
                    || simd.u32x4_store_be(av, &mut output[..len])
                ))
                .is_err()
            );
            assert_eq!(output, [0xa5; 16]);
            if len < 8 {
                assert!(
                    catch_unwind(AssertUnwindSafe(|| simd.u32x4_load_be2(&output[..len]))).is_err()
                );
            }
        }
        for len in 0..4 {
            let mut output = [0xa5; 4];
            assert!(catch_unwind(AssertUnwindSafe(|| simd.u32x4_load(&output[..len]))).is_err());
            assert!(
                catch_unwind(AssertUnwindSafe(|| simd.u32x4_store(av, &mut output[..len])))
                    .is_err()
            );
            assert_eq!(output, [0xa5; 4]);
        }
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u32x4_align::<-1>(av, bv))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u32x4_align::<5>(av, bv))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u32x4_blend::<-1>(av, bv))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u32x4_blend::<16>(av, bv))).is_err());
    }

    #[test]
    fn emulated_fixed4_contracts() {
        contracts(EmulatedScalar);
        contracts(EmulatedIceLake);
        contracts(EmulatedNeon);
        contracts(EmulatedArmV9);
    }

    fn native_consistency<S: Simd>(native: S) {
        let emulated = EmulatedScalar;
        for seed in 0..128u32 {
            let a: [u32; 4] = core::array::from_fn(|i| {
                seed.wrapping_mul(0x9e3779b9).rotate_left(7 * i as u32) ^ (u32::MAX >> i)
            });
            let b = a.map(|word| word.rotate_right(13).wrapping_add(0x13579bdf));
            let av = native.u32x4_load(&a);
            let bv = native.u32x4_load(&b);
            assert_eq!(
                words(native, native.u32x4_add(av, bv)),
                emulated.u32x4_add(a, b)
            );
            macro_rules! align { ($($n:literal),*) => { $(
                assert_eq!(words(native, native.u32x4_align::<$n>(av,bv)), emulated.u32x4_align::<$n>(a,b));
            )* }; }
            align!(0, 1, 2, 3, 4);
            macro_rules! blend { ($($mask:literal),*) => { $(
                assert_eq!(words(native,native.u32x4_blend::<$mask>(av,bv)),emulated.u32x4_blend::<$mask>(a,b));
            )* }; }
            blend!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            macro_rules! shuffle { ($($mask:literal),*) => { $(
                assert_eq!(words(native,native.u32x4_shuffle::<$mask>(av)),emulated.u32x4_shuffle::<$mask>(a));
            )* }; }
            shuffle!(0x00, 0x1b, 0x4e, 0xb1, 0xff);
            let bytes: [u8; 33] =
                core::array::from_fn(|i| (seed as u8).wrapping_add(i as u8).wrapping_mul(73));
            let input = &bytes[(seed as usize % 17)..];
            assert_eq!(
                words(native, native.u32x4_load_be(input)),
                emulated.u32x4_load_be(input)
            );
            assert_eq!(
                words(native, native.u32x4_load_be2(input)),
                emulated.u32x4_load_be2(input)
            );
            let mut actual = [0xa5; 17];
            let mut expected = actual;
            native.u32x4_store_be(av, &mut actual[1..]);
            emulated.u32x4_store_be(a, &mut expected[1..]);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn native_fixed4_contracts() {
        #[cfg(target_arch = "aarch64")]
        {
            if let Some(simd) = crate::native::NativeNeon::new() {
                contracts(simd);
                native_consistency(simd);
            }
            if let Some(simd) = crate::native::NativeArmV9::new() {
                contracts(simd);
                native_consistency(simd);
            }
        }
        #[cfg(target_arch = "x86_64")]
        if let Some(simd) = crate::native::NativeIceLake::new() {
            contracts(simd);
            native_consistency(simd);
        }
    }
}

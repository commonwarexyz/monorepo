// Portions adapted from blst 0.3.16, blst/src/multi_scalar.c and ec_mult.h.
// Copyright Supranational LLC
// SPDX-License-Identifier: Apache-2.0

//! Public-scalar recoding for shared-window and bucketed multiplication.

use super::Scalar;
use alloc::vec::Vec;

pub(super) trait Point<C>: Copy {
    fn add(&self, other: &Self, context: &C) -> Self;
    fn double(&self, context: &C) -> Self;
    fn neg(&self, context: &C) -> Self;
}

pub(super) struct Term<P> {
    pub point: P,
    pub scalar: EncodedScalar,
}

#[derive(Clone, Copy)]
pub(in crate::bls12381) struct EncodedScalar([u8; 32]);

impl EncodedScalar {
    pub fn new(scalar: &Scalar) -> Self {
        let mut bytes = scalar.to_bytes();
        bytes.reverse();
        Self(bytes)
    }

    pub fn from_batch_be_bytes(bytes: &[u8; 16]) -> Self {
        let mut encoded = [0; 32];
        encoded[..16].copy_from_slice(bytes);
        encoded[..16].reverse();
        Self(encoded)
    }

    pub fn bits(&self) -> usize {
        self.0
            .iter()
            .rposition(|&byte| byte != 0)
            .map_or(0, |i| i * 8 + 8 - self.0[i].leading_zeros() as usize)
    }

    // Adjacent Booth windows share one bit. The bottom window supplies a zero
    // below bit zero, and an extra top window absorbs a carry beyond the input.
    #[inline(always)]
    pub fn digit(&self, window: usize, width: usize) -> i32 {
        let bit = window * width;
        let start = bit.saturating_sub(1);
        let mut value = 0u32;
        for (i, &byte) in self.0.iter().skip(start / 8).take(3).enumerate() {
            value |= (byte as u32) << (8 * i);
        }
        value >>= start % 8;
        if bit == 0 {
            value <<= 1;
        }
        value &= (1 << (width + 1)) - 1;
        ((value + 1) >> 1) as i32 - ((value >> width) << width) as i32
    }
}

// blst uses an eight-point table below 32 terms, then picks bucket widths from
// the input count. The cap bounds bucket storage and limits Booth extraction to
// three bytes, including an overlapping bit at any byte offset.
pub(super) fn window_width(points: usize) -> usize {
    if points < 32 {
        return 4;
    }
    let bits = points.ilog2() as usize;
    let width = if bits > 12 {
        bits - 3
    } else if bits > 8 {
        bits - 2
    } else {
        bits - 1
    };
    width.min(16)
}

#[inline(always)]
pub(super) fn precompute_window<P: Point<C>, C, const N: usize>(
    point: &P,
    table: &mut [P; N],
    context: &C,
) {
    const { assert!(N >= 2 && N.is_power_of_two()) };
    table[0] = *point;
    table[1] = point.double(context);
    for i in 1..N / 2 {
        table[2 * i] = table[i].add(&table[i - 1], context);
        table[2 * i + 1] = table[i].double(context);
    }
}

// Scalar preparation and point import expand in the selected worker. Zero
// coefficients are filtered before point import, and retained terms set the width.
macro_rules! prepare_terms {
    ($points:expr, $scalars:expr, $scalar:ident => $encode:expr, $point:ident => $import:expr) => {{
        let points = $points;
        let scalars = $scalars;
        let mut terms = alloc::vec::Vec::with_capacity(points.len());
        let mut bits = 0;
        for ($point, $scalar) in points.iter().zip(scalars) {
            let scalar = $encode;
            let scalar_bits = scalar.bits();
            if scalar_bits == 0 {
                continue;
            }
            bits = bits.max(scalar_bits);
            terms.push($crate::bls12381::group::msm::Term {
                point: $import,
                scalar,
            });
        }
        (terms, bits)
    }};
}
pub(super) use prepare_terms;

#[inline(always)]
pub(super) fn compute<P: Point<C>, C>(
    terms: Vec<Term<P>>,
    bits: usize,
    context: &C,
    identity: P,
) -> P {
    if terms.is_empty() {
        return identity;
    }

    let width = window_width(terms.len());
    let windows = bits / width + 1;
    let mut result = identity;
    if terms.len() < 32 {
        let mut tables = Vec::with_capacity(terms.len());
        for term in &terms {
            let mut table = [identity; 8];
            precompute_window(&term.point, &mut table, context);
            tables.push(table);
        }
        for window in (0..windows).rev() {
            if window != windows - 1 {
                for _ in 0..width {
                    result = result.double(context);
                }
            }
            for (term, table) in terms.iter().zip(&tables) {
                let digit = term.scalar.digit(window, width);
                if digit != 0 {
                    let mut point = table[digit.unsigned_abs() as usize - 1];
                    if digit < 0 {
                        point = point.neg(context);
                    }
                    result = result.add(&point, context);
                }
            }
        }
    } else {
        let mut buckets = alloc::vec![identity; 1 << (width - 1)];
        for window in (0..windows).rev() {
            if window != windows - 1 {
                for _ in 0..width {
                    result = result.double(context);
                }
            }
            let mut used = 0;
            for term in &terms {
                let digit = term.scalar.digit(window, width);
                if digit != 0 {
                    let magnitude = digit.unsigned_abs() as usize;
                    used = used.max(magnitude);
                    let point = if digit < 0 {
                        term.point.neg(context)
                    } else {
                        term.point
                    };
                    let bucket = &mut buckets[magnitude - 1];
                    *bucket = bucket.add(&point, context);
                }
            }
            let mut sum = identity;
            for bucket in buckets[..used].iter_mut().rev() {
                sum = sum.add(bucket, context);
                result = result.add(&sum, context);
                *bucket = identity;
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::{BigInt, Sign};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct AdditivePoint(i64);

    #[derive(Debug, Default)]
    struct AdditiveContext {
        adds: core::cell::Cell<usize>,
        doubles: core::cell::Cell<usize>,
        negations: core::cell::Cell<usize>,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct Trace {
        adds: usize,
        doubles: usize,
        negations: usize,
    }

    impl AdditiveContext {
        fn trace(&self) -> Trace {
            Trace {
                adds: self.adds.get(),
                doubles: self.doubles.get(),
                negations: self.negations.get(),
            }
        }
    }

    impl Point<AdditiveContext> for AdditivePoint {
        fn add(&self, other: &Self, context: &AdditiveContext) -> Self {
            context.adds.set(context.adds.get() + 1);
            Self(self.0 + other.0)
        }

        fn double(&self, context: &AdditiveContext) -> Self {
            context.doubles.set(context.doubles.get() + 1);
            Self(self.0 * 2)
        }

        fn neg(&self, context: &AdditiveContext) -> Self {
            context.negations.set(context.negations.get() + 1);
            Self(-self.0)
        }
    }

    #[derive(Clone, Copy)]
    struct InputPoint {
        position: usize,
        value: i64,
    }

    #[test]
    fn compute_filters_zero_before_import_and_uses_retained_cardinality() {
        type Outcome = (AdditivePoint, alloc::vec::Vec<(usize, i64)>, Trace);

        fn run<S>(
            points: &[InputPoint],
            scalars: &[S],
            weights: &[u64],
            encode: impl Fn(&S) -> EncodedScalar,
        ) -> Outcome {
            let expected_imports: alloc::vec::Vec<_> = points
                .iter()
                .zip(weights)
                .filter_map(|(point, &weight)| {
                    (weight != 0).then_some((point.position, point.value))
                })
                .collect();
            let mut imports = alloc::vec::Vec::new();
            let context = AdditiveContext::default();
            let (terms, bits) = prepare_terms!(
                points,
                scalars,
                scalar => encode(scalar),
                point => {
                    imports.push((point.position, point.value));
                    AdditivePoint(point.value)
                }
            );
            let result = compute(terms, bits, &context, AdditivePoint(0));

            assert_eq!(imports, expected_imports);
            assert!(imports.iter().all(|&(position, _)| weights[position] != 0));
            let expected = points
                .iter()
                .zip(weights)
                .map(|(point, &weight)| point.value * weight as i64)
                .sum();
            assert_eq!(result, AdditivePoint(expected));
            (result, imports, context.trace())
        }

        fn run_both(points: &[InputPoint], weights: &[u64]) -> [Outcome; 2] {
            let scalars: alloc::vec::Vec<_> =
                weights.iter().copied().map(Scalar::from_u64).collect();
            let encoded: alloc::vec::Vec<_> = weights
                .iter()
                .map(|&weight| EncodedScalar::from_batch_be_bytes(&(weight as u128).to_be_bytes()))
                .collect();
            [
                run(points, &scalars, weights, EncodedScalar::new),
                run(points, &encoded, weights, |scalar| *scalar),
            ]
        }

        let mut values = alloc::vec![[0; 16], [0xff; 16], core::array::from_fn(|i| i as u8)];
        for bit in 0..128 {
            let mut bytes = [0; 16];
            bytes[15 - bit / 8] = 1 << (bit % 8);
            values.push(bytes);
        }
        for bytes in values {
            let mut canonical = [0; 32];
            canonical[16..].copy_from_slice(&bytes);
            let scalar = Scalar::from_bytes(&canonical).unwrap();
            assert_eq!(
                EncodedScalar::from_batch_be_bytes(&bytes).0,
                EncodedScalar::new(&scalar).0,
            );
        }

        const TOTAL: usize = 67;
        for retained in [31, 32] {
            let terms: alloc::vec::Vec<_> = (0..retained)
                .map(|ordinal| (ordinal as i64 + 1, (ordinal % 15 + 1) as u64))
                .collect();
            let compact_points: alloc::vec::Vec<_> = terms
                .iter()
                .enumerate()
                .map(|(position, &(value, _))| InputPoint { position, value })
                .collect();
            let compact_weights: alloc::vec::Vec<_> =
                terms.iter().map(|&(_, weight)| weight).collect();

            let mut padded_points: alloc::vec::Vec<_> = (0..TOTAL)
                .map(|position| InputPoint {
                    position,
                    value: -(position as i64) - 1,
                })
                .collect();
            let mut padded_weights = [0; TOTAL];
            for (ordinal, &(value, weight)) in terms.iter().enumerate() {
                let position = ordinal * 2 + 1;
                padded_points[position].value = value;
                padded_weights[position] = weight;
            }

            let compact = run_both(&compact_points, &compact_weights);
            let padded = run_both(&padded_points, &padded_weights);
            assert_eq!(compact[0], compact[1]);
            assert_eq!(padded[0], padded[1]);
            for (
                (compact_result, compact_imports, compact_trace),
                (padded_result, padded_imports, padded_trace),
            ) in compact.into_iter().zip(padded)
            {
                assert_eq!(compact_result, padded_result);
                assert_eq!(compact_imports.len(), retained);
                assert_eq!(padded_imports.len(), retained);
                assert_eq!(compact_trace, padded_trace);
                assert!(compact_trace.negations > 0);
            }
        }

        let points: alloc::vec::Vec<_> = (0..TOTAL)
            .map(|position| InputPoint {
                position,
                value: position as i64 + 1,
            })
            .collect();
        for (result, imports, trace) in run_both(&points, &[0; TOTAL]) {
            assert_eq!(result, AdditivePoint(0));
            assert!(imports.is_empty());
            assert_eq!(trace, AdditiveContext::default().trace());
        }

        let point = [InputPoint {
            position: 0,
            value: -7,
        }];
        let outcomes = run_both(&point, &[9]);
        assert_eq!(outcomes[0], outcomes[1]);
        for (result, imports, _) in outcomes {
            assert_eq!(result, AdditivePoint(-63));
            assert_eq!(imports, alloc::vec![(0, -7)]);
        }
    }

    #[cfg(not(miri))]
    #[test]
    fn compute_wide_windows_reuses_largest_bucket() {
        let count = 1 << 19;
        assert_eq!(window_width(count), 16);
        let weight = 0x7fff8000u64;
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&weight.to_le_bytes());
        let scalar = EncodedScalar(bytes);
        let terms = (0..count)
            .map(|_| Term {
                point: AdditivePoint(1),
                scalar,
            })
            .collect();
        let result = compute(
            terms,
            scalar.bits(),
            &AdditiveContext::default(),
            AdditivePoint(0),
        );
        assert_eq!(result, AdditivePoint(count as i64 * weight as i64));
    }

    #[test]
    fn booth_width_15_negative_digit_does_not_overflow() {
        let mut bytes = [0; 32];
        bytes[1] = 0x40;
        let scalar = EncodedScalar(bytes);
        let digits = [
            i128::from(scalar.digit(0, 15)),
            i128::from(scalar.digit(1, 15)),
        ];
        assert_eq!(digits, [-16384i128, 1]);
        let reconstructed = (digits[1] << 15) + digits[0];
        assert_eq!(reconstructed, 1i128 << 14);
    }

    #[test]
    fn booth_width_16_preserves_positive_extreme() {
        let mut bytes = [0; 32];
        bytes[..4].copy_from_slice(&0x7fff8000u32.to_le_bytes());
        let scalar = EncodedScalar(bytes);
        let digits = [
            i128::from(scalar.digit(0, 16)),
            i128::from(scalar.digit(1, 16)),
        ];
        assert_eq!(digits, [-32768i128, 32768i128]);
        let reconstructed = (digits[1] << 16) + digits[0];
        assert_eq!(reconstructed, 0x7fff8000i128);

        let full = EncodedScalar([0xff; 32]);
        assert_eq!(i128::from(full.digit(0, 16)), -1);
        assert_eq!(i128::from(full.digit(16, 16)), 1);
    }

    #[test]
    fn booth_windows_reconstruct_integer() {
        let mut values = alloc::vec![[0; 32], [0xff; 32], [0x55; 32], [0xaa; 32]];
        for bit in 0..256 {
            let mut value = [0; 32];
            value[bit / 8] = 1 << (bit % 8);
            values.push(value);
            if bit != 0 {
                let value = (BigInt::from_bytes_le(Sign::Plus, &value) - 1u8)
                    .to_bytes_le()
                    .1;
                let mut bytes = [0; 32];
                bytes[..value.len()].copy_from_slice(&value);
                values.push(bytes);
            }
        }
        for value in values {
            let scalar = EncodedScalar(value);
            for width in 4..=16 {
                let mut result = BigInt::from(0);
                for window in (0..scalar.bits() / width + 1).rev() {
                    let digit = scalar.digit(window, width);
                    assert!(digit.unsigned_abs() as usize <= 1 << (width - 1));
                    result = (result << width) + digit;
                }
                assert_eq!(result, BigInt::from_bytes_le(Sign::Plus, &value));
            }
        }
        assert_eq!(window_width(100_000), 13);
        assert_eq!(window_width(1_000_000), 16);
        assert_eq!(window_width(usize::MAX), 16);
    }
}

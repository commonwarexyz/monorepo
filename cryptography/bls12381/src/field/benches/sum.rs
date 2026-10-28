//! Sums of G1 points, as a representative formula for comparing radices.
//!
//! Each lane sums every eighth point with complete projective additions, leaving eight partial
//! sums; combining them is the same small cost in every representation.

use super::utils::{IDENTITY, LANES, points};
use commonware_cryptography_bls12381::field::{
    curve::{Coordinates, Limbs, Point},
    fp::unsat49::Unsat49,
};
use commonware_simd::{Operation, Simd, dispatch};
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

/// `3b = 12` as a big-endian integer.
const B3: [u8; 48] = {
    let mut bytes = [0; 48];
    bytes[47] = 12;
    bytes
};

/// Sums points loaded from bytes, converting each addend.
struct SumBytes<'a, const BITS: u32>(&'a [Coordinates]);

impl<S: Simd, const BITS: u32> Operation<S> for SumBytes<'_, BITS> {
    type Output = [Coordinates; LANES];

    fn portable(self, simd: S) -> [Coordinates; LANES] {
        let mut output = [IDENTITY; LANES];
        simd.execute(
            #[inline(always)]
            |simd: S| {
                let b3 = Unsat49::<S, BITS>::splat(simd, &B3);
                let rounds = self.0.len() / LANES;
                for start in (0..LANES).step_by(S::U64_LANES) {
                    let mut sum = Point::<S, BITS>::load(simd, &self.0[start..], &IDENTITY);
                    for round in 1..rounds {
                        let base = round * LANES + start;
                        let points = &self.0[base..base + S::U64_LANES];
                        sum = sum.add(simd, Point::load(simd, points, &IDENTITY), b3);
                    }
                    sum.store(simd, &mut output[start..]);
                }
            },
        );
        output
    }
}

/// Converts points into per-lane limbs, one entry per round and lane chunk.
struct Prepare<'a, const BITS: u32>(&'a [Coordinates]);

impl<S: Simd, const BITS: u32> Operation<S> for Prepare<'_, BITS> {
    type Output = Vec<Limbs>;

    fn portable(self, simd: S) -> Vec<Limbs> {
        let mut output = Vec::new();
        for round in 0..self.0.len() / LANES {
            for start in (0..LANES).step_by(S::U64_LANES) {
                let base = round * LANES + start;
                let points = &self.0[base..base + S::U64_LANES];
                output.push(Point::<S, BITS>::load(simd, points, &IDENTITY).to_limbs(simd));
            }
        }
        output
    }
}

/// Sums points already in this representation's limb form.
struct SumLimbs<'a, const BITS: u32>(&'a [Limbs]);

impl<S: Simd, const BITS: u32> Operation<S> for SumLimbs<'_, BITS> {
    type Output = [Coordinates; LANES];

    fn portable(self, simd: S) -> [Coordinates; LANES] {
        let mut output = [IDENTITY; LANES];
        simd.execute(
            #[inline(always)]
            |simd: S| {
                let b3 = Unsat49::<S, BITS>::splat(simd, &B3);
                let chunks = LANES / S::U64_LANES;
                let rounds = self.0.len() / chunks;
                for (chunk, start) in (0..LANES).step_by(S::U64_LANES).enumerate() {
                    let mut sum = Point::<S, BITS>::from_limbs(simd, &self.0[chunk]);
                    for round in 1..rounds {
                        let addend = Point::from_limbs(simd, &self.0[round * chunks + chunk]);
                        sum = sum.add(simd, addend, b3);
                    }
                    sum.store(simd, &mut output[start..]);
                }
            },
        );
        output
    }
}

fn bench_sum(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for n in [128, 1024] {
        let (coordinates, blst_points) = points(n);
        group.throughput(Throughput::Elements(n as u64));
        macro_rules! radix {
            ($($bits:literal),*) => {$(
                let name = format!("repr=unsat49 radix={} input=bytes n={n}", $bits);
                group.bench_function(name, |b| {
                    b.iter(|| black_box(dispatch(SumBytes::<$bits>(black_box(&coordinates)))));
                });
                let limbs = dispatch(Prepare::<$bits>(&coordinates));
                let name = format!("repr=unsat49 radix={} input=limbs n={n}", $bits);
                group.bench_function(name, |b| {
                    b.iter(|| black_box(dispatch(SumLimbs::<$bits>(black_box(&limbs)))));
                });
            )*};
        }
        radix!(52, 51, 50, 49);
        group.bench_function(format!("repr=blst n={n}"), |b| {
            b.iter(|| {
                let mut acc = blst::blst_p1::default();
                for point in &blst_points {
                    // SAFETY: valid pointers to point structures.
                    unsafe { blst::blst_p1_add_or_double(&mut acc, &acc, point) };
                }
                black_box(acc)
            });
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_sum
}

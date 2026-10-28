//! Throughput of converting elements into and out of lanes.

use super::utils::elements;
use commonware_cryptography_bls12381::field::fp::{BYTES, unsat49::Unsat49};
use commonware_simd::{Operation, Simd, dispatch};
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

/// Elements converted per iteration.
const COUNT: usize = 1024;

/// Loads every element into lanes and stores it back.
struct RoundTrip<'a>(&'a [[u8; BYTES]]);

impl<S: Simd> Operation<S> for RoundTrip<'_> {
    type Output = Vec<[u8; BYTES]>;

    fn portable(self, simd: S) -> Vec<[u8; BYTES]> {
        let mut output = vec![[0; BYTES]; self.0.len()];
        simd.execute(
            #[inline(always)]
            |simd: S| {
                for start in (0..self.0.len()).step_by(S::U64_LANES) {
                    Unsat49::<S>::load(simd, &self.0[start..], &[0; BYTES])
                        .store(simd, &mut output[start..]);
                }
            },
        );
        output
    }
}

fn bench_convert(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    let inputs = elements(COUNT);
    group.throughput(Throughput::Elements(COUNT as u64));
    group.bench_function("repr=unsat49", |b| {
        b.iter(|| black_box(dispatch(RoundTrip(black_box(&inputs)))));
    });
    group.finish();
}

criterion_group!(benches, bench_convert);

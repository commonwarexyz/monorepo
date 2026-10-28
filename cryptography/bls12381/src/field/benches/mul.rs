//! Throughput of lane multiplications.

use super::utils::{LANES, ONE, elements};
use commonware_cryptography_bls12381::field::fp::{BYTES, unsat49::Unsat49};
use commonware_simd::{Operation, Simd, dispatch};
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

/// Independent multiplication chains per lane, so consecutive products can overlap.
const CHAINS: usize = 4;

/// Multiplications in each chain.
const ROUNDS: usize = 64;

/// Multiplies each of `CHAINS` accumulators by a factor `ROUNDS` times, per lane.
struct Chains<'a>(&'a [[u8; BYTES]]);

impl<S: Simd> Operation<S> for Chains<'_> {
    type Output = [[u8; BYTES]; LANES];

    fn portable(self, simd: S) -> [[u8; BYTES]; LANES] {
        let mut output = [[0; BYTES]; LANES];
        simd.execute(
            #[inline(always)]
            |simd: S| {
                for start in (0..LANES).step_by(S::U64_LANES) {
                    let factor = Unsat49::<S>::load(simd, &self.0[start..], &ONE);
                    let mut chains = [factor; CHAINS];
                    for (i, chain) in chains.iter_mut().enumerate() {
                        *chain = Unsat49::load(simd, &self.0[LANES * (i + 1) + start..], &ONE);
                    }
                    for _ in 0..ROUNDS {
                        for chain in &mut chains {
                            *chain = chain.mul(simd, factor);
                        }
                    }
                    let mut sum = chains[0];
                    for chain in &chains[1..] {
                        sum = sum.add(simd, *chain);
                    }
                    sum.store(simd, &mut output[start..]);
                }
            },
        );
        output
    }
}

fn bench_mul(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    let inputs = elements(LANES * (CHAINS + 1));
    group.throughput(Throughput::Elements((LANES * CHAINS * ROUNDS) as u64));
    group.bench_function("repr=unsat49", |b| {
        b.iter(|| black_box(dispatch(Chains(black_box(&inputs)))));
    });
    group.finish();
}

criterion_group!(benches, bench_mul);

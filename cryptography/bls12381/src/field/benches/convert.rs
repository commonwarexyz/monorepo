//! Throughput of converting elements into and out of lanes in each radix.

use super::utils::{LANES, elements};
use commonware_cryptography_bls12381::{field::fp::unsat49::Unsat49, fp::Fp};
use commonware_simd::{Operation, Simd, dispatch};
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

/// Elements converted per iteration.
const COUNT: usize = 1024;

/// The conversion to measure.
#[derive(Clone, Copy)]
enum Mode {
    /// Load with a multiplication, then store.
    Load,
    /// Load by shifting, then store.
    Shifted,
}

/// Loads every element into lanes and stores it back.
struct RoundTrip<'a, const BITS: u32> {
    elements: &'a [Fp],
    mode: Mode,
}

impl<S: Simd, const BITS: u32> Operation<S> for RoundTrip<'_, BITS> {
    type Output = Vec<Fp>;

    fn portable(self, simd: S) -> Vec<Fp> {
        let mut output = vec![Fp::ZERO; self.elements.len()];
        simd.execute(
            #[inline(always)]
            |simd: S| {
                for start in (0..self.elements.len()).step_by(S::U64_LANES) {
                    let input = &self.elements[start..];
                    let value = match self.mode {
                        Mode::Load => Unsat49::<S, BITS>::load(simd, input, Fp::ZERO),
                        Mode::Shifted => Unsat49::<S, BITS>::load_shifted(simd, input, Fp::ZERO),
                    };
                    value.store(simd, &mut output[start..]);
                }
            },
        );
        output
    }
}

fn bench_convert(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    let inputs = elements(COUNT);
    assert_eq!(COUNT % LANES, 0);
    group.throughput(Throughput::Elements(COUNT as u64));
    macro_rules! radix {
        ($($bits:literal),*) => {$(
            for (name, mode) in [("load", Mode::Load), ("shifted", Mode::Shifted)] {
                group.bench_function(format!("radix={} mode={name}", $bits), |b| {
                    b.iter(|| {
                        black_box(dispatch(RoundTrip::<$bits> {
                            elements: black_box(&inputs),
                            mode,
                        }))
                    });
                });
            }
        )*};
    }
    radix!(52, 49, 48);
    group.finish();
}

criterion_group!(benches, bench_convert);

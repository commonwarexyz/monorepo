//! Throughput of quadratic extension multiplications and squarings, compared with blst.

use super::utils::elements;
use commonware_cryptography_bls12381::core::field::{
    arithmetic::Field,
    fp::{self, rns::Rns, unsat28::Unsat28, unsat49::Unsat49},
    fp2::{BYTES, Fp2},
};
use commonware_simd::{Operation, Simd, dispatch};
use criterion::{BenchmarkGroup, Criterion, Throughput, criterion_group, measurement::WallTime};
use std::{hint::black_box, marker::PhantomData};

/// Elements in each chain step, a multiple of every representation's lane count.
const ELEMENTS: usize = 16;

/// Independent chains per lane, so consecutive operations can overlap.
const CHAINS: usize = 4;

/// Operations in each chain.
const ROUNDS: usize = 64;

/// Subtraction bias for squaring, covering the imaginary component of any chained result.
const SQUARE_BIAS: u64 = 128;

/// Positional bias for reducing products, covering the negative sums of any chained product.
const PRODUCT_BIAS: u64 = 64;

/// A base field representation, selecting its element type on every backend.
trait Representation {
    /// The representation's name in benchmark labels.
    const NAME: &'static str;

    /// Elements in this representation on backend `S`.
    type Field<S: Simd>: Field<S>;
}

macro_rules! representations {
    ($($marker:ident => $field:ident: $name:literal),*) => {$(
        struct $marker;

        impl Representation for $marker {
            const NAME: &'static str = $name;
            type Field<S: Simd> = $field<S>;
        }
    )*};
}

representations!(
    Radix28 => Unsat28: "unsat28",
    Radix49 => Unsat49: "unsat49",
    Residues => Rns: "rns"
);

/// The operation each chain repeats.
#[derive(Clone, Copy)]
enum Step {
    /// Multiplies the accumulator by a fixed factor.
    Mul,
    /// Squares the accumulator.
    Square,
}

/// One as an extension element.
const ONE: [u8; BYTES] = {
    let mut bytes = [0; BYTES];
    bytes[BYTES - 1] = 1;
    bytes
};

/// Repeats a step `ROUNDS` times on each of `CHAINS` accumulators, per lane.
struct Chains<'a, R>(Step, &'a [[u8; BYTES]], PhantomData<R>);

impl<S: Simd, R: Representation> Operation<S> for Chains<'_, R> {
    type Output = [[u8; BYTES]; ELEMENTS];

    fn portable(self, simd: S) -> [[u8; BYTES]; ELEMENTS] {
        let mut output = [[0; BYTES]; ELEMENTS];
        simd.execute(
            #[inline(always)]
            |simd: S| {
                for start in (0..ELEMENTS).step_by(R::Field::<S>::LANES) {
                    let factor = Fp2::<R::Field<S>>::load(simd, &self.1[start..], &ONE);
                    let mut chains = [factor; CHAINS];
                    for (i, chain) in chains.iter_mut().enumerate() {
                        *chain = Fp2::load(simd, &self.1[ELEMENTS * (i + 1) + start..], &ONE);
                    }
                    match self.0 {
                        Step::Mul => {
                            for _ in 0..ROUNDS {
                                for chain in &mut chains {
                                    *chain = chain.mul::<PRODUCT_BIAS, S>(simd, factor);
                                }
                            }
                        }
                        Step::Square => {
                            for _ in 0..ROUNDS {
                                for chain in &mut chains {
                                    *chain = chain.square::<SQUARE_BIAS, S>(simd);
                                }
                            }
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

/// Returns `count` deterministic extension elements with components below `2^380 < p`.
fn extension_elements(count: usize) -> Vec<[u8; BYTES]> {
    elements(2 * count)
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[c0, c1]| {
            let mut bytes = [0; BYTES];
            bytes[..fp::BYTES].copy_from_slice(c1);
            bytes[fp::BYTES..].copy_from_slice(c0);
            bytes
        })
        .collect()
}

/// Converts extension elements to blst's representation.
fn to_blst(elements: &[[u8; BYTES]]) -> Vec<blst::blst_fp2> {
    elements
        .iter()
        .map(|bytes| {
            let mut element = blst::blst_fp2::default();
            // SAFETY: each pointer references a valid field element and 48 readable bytes.
            unsafe {
                blst::blst_fp_from_bendian(&mut element.fp[1], bytes[..fp::BYTES].as_ptr());
                blst::blst_fp_from_bendian(&mut element.fp[0], bytes[fp::BYTES..].as_ptr());
            }
            element
        })
        .collect()
}

fn bench_chains(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    let inputs = extension_elements(ELEMENTS * (CHAINS + 1));
    let blst_inputs = to_blst(&inputs);
    group.throughput(Throughput::Elements((ELEMENTS * CHAINS * ROUNDS) as u64));
    for (step, name) in [(Step::Mul, "mul"), (Step::Square, "square")] {
        chain_representation::<Radix28>(&mut group, step, name, &inputs);
        chain_representation::<Radix49>(&mut group, step, name, &inputs);
        chain_representation::<Residues>(&mut group, step, name, &inputs);
        group.bench_function(format!("op={name} repr=blst"), |b| {
            b.iter(|| {
                let (factors, chains) = black_box(&blst_inputs).split_at(ELEMENTS);
                let mut chains: [blst::blst_fp2; ELEMENTS * CHAINS] =
                    chains.try_into().expect("chain inputs");
                for _ in 0..ROUNDS {
                    for (i, chain) in chains.iter_mut().enumerate() {
                        // SAFETY: valid pointers to field elements; blst allows aliasing the
                        // output with an input.
                        unsafe {
                            match step {
                                Step::Mul => {
                                    blst::blst_fp2_mul(chain, chain, &factors[i % ELEMENTS])
                                }
                                Step::Square => blst::blst_fp2_sqr(chain, chain),
                            }
                        }
                    }
                }
                black_box(chains)
            });
        });
    }
    group.finish();
}

fn chain_representation<R: Representation>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    step: Step,
    name: &str,
    inputs: &[[u8; BYTES]],
) {
    group.bench_function(format!("op={name} repr={}", R::NAME), |b| {
        b.iter(|| black_box(dispatch(Chains::<R>(step, black_box(inputs), PhantomData))));
    });
}

criterion_group!(benches, bench_chains);

//! Throughput of dodecic extension operations, compared with blst.

use super::utils::elements;
use commonware_cryptography_bls12381::core::field::{
    arithmetic::Field,
    fp::{self, rns::Rns, unsat28::Unsat28, unsat49::Unsat49},
    fp2::{self, Fp2},
    fp12::{BYTES, Fp12, ONE},
};
use commonware_simd::{Operation, Simd, dispatch};
use criterion::{BenchmarkGroup, Criterion, Throughput, criterion_group, measurement::WallTime};
use std::{hint::black_box, marker::PhantomData};

/// Elements in each chain step, a multiple of every representation's lane count.
const ELEMENTS: usize = 16;

/// Independent chains per lane, so consecutive operations can overlap.
const CHAINS: usize = 2;

/// A base field representation, selecting its element type on every backend.
trait Representation {
    /// The representation's name in benchmark labels.
    const NAME: &'static str;

    /// Elements in this representation on backend S.
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
    Mul,
    Square,
    CyclotomicSquare,
    Line,
    Frobenius,
    Invert,
}

impl Step {
    const fn name(self) -> &'static str {
        match self {
            Self::Mul => "mul",
            Self::Square => "square",
            Self::CyclotomicSquare => "cyclotomic_square",
            Self::Line => "mul_by_line",
            Self::Frobenius => "frobenius",
            Self::Invert => "invert",
        }
    }

    const fn rounds(self) -> usize {
        match self {
            Self::Invert => 2,
            _ => 16,
        }
    }
}

/// Repeats a step on each of CHAINS accumulators, per lane.
struct Chains<'a, R>(
    Step,
    &'a [[u8; BYTES]],
    &'a [[u8; fp2::BYTES]],
    PhantomData<R>,
);

impl<S: Simd, R: Representation> Operation<S> for Chains<'_, R> {
    type Output = [[u8; BYTES]; ELEMENTS];

    fn portable(self, simd: S) -> [[u8; BYTES]; ELEMENTS] {
        let Self(step, elements, line, _) = self;
        let mut output = [[0; BYTES]; ELEMENTS];
        simd.execute(|simd: S| {
            for start in (0..ELEMENTS).step_by(R::Field::<S>::LANES) {
                let factor = Fp12::<R::Field<S>>::load(simd, &elements[start..], &ONE);
                let line = [
                    Fp2::load(simd, &line[start..], &line[0]),
                    Fp2::load(simd, &line[ELEMENTS + start..], &line[0]),
                    Fp2::load(simd, &line[2 * ELEMENTS + start..], &line[0]),
                ];
                let mut chains = [factor; CHAINS];
                for (i, chain) in chains.iter_mut().enumerate() {
                    *chain = Fp12::load(simd, &elements[ELEMENTS * (i + 1) + start..], &ONE);
                }
                for _ in 0..step.rounds() {
                    for chain in &mut chains {
                        *chain = match step {
                            Step::Mul => chain.mul(simd, factor),
                            Step::Square => chain.square(simd),
                            Step::CyclotomicSquare => chain.cyclotomic_square(simd),
                            Step::Line => chain.mul_by_line(simd, line),
                            Step::Frobenius => chain.frobenius(simd),
                            Step::Invert => chain.invert(simd),
                        };
                    }
                }
                let mut product = chains[0];
                for chain in &chains[1..] {
                    product = product.mul(simd, *chain);
                }
                product.store(simd, &mut output[start..]);
            }
        });
        output
    }
}

/// Converts encodings to blst's representation.
fn to_blst(elements: &[[u8; BYTES]]) -> Vec<blst::blst_fp12> {
    elements
        .iter()
        .map(|bytes| {
            let mut value = blst::blst_fp12::default();
            let (chunks, _) = bytes.as_chunks::<{ fp::BYTES }>();
            for (k, chunk) in chunks.iter().enumerate() {
                let (fp6, fp2, fp) = (1 - k / 6, 2 - (k / 2) % 3, 1 - k % 2);
                // SAFETY: the pointers reference a valid field element and 48 readable bytes.
                unsafe {
                    blst::blst_fp_from_bendian(&mut value.fp6[fp6].fp2[fp2].fp[fp], chunk.as_ptr())
                };
            }
            value
        })
        .collect()
}

fn bench_fp12(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    let fps = elements(12 * ELEMENTS * (CHAINS + 1) + 6 * 3 * ELEMENTS);
    let (fps, line_fps) = fps.split_at(12 * ELEMENTS * (CHAINS + 1));
    let inputs: Vec<[u8; BYTES]> = fps
        .as_chunks::<12>()
        .0
        .iter()
        .map(|chunk| {
            let mut bytes = [0; BYTES];
            for (k, fp) in chunk.iter().enumerate() {
                bytes[k * fp::BYTES..(k + 1) * fp::BYTES].copy_from_slice(fp);
            }
            bytes
        })
        .collect();
    let line: Vec<[u8; fp2::BYTES]> = line_fps
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[c1, c0]| {
            let mut bytes = [0; fp2::BYTES];
            bytes[..fp::BYTES].copy_from_slice(c1);
            bytes[fp::BYTES..].copy_from_slice(c0);
            bytes
        })
        .collect();
    let blst_inputs = to_blst(&inputs);
    let blst_line = {
        let mut value = blst::blst_fp6::default();
        // SAFETY: the pointers reference valid field elements and 48 readable bytes.
        unsafe {
            for (k, fp) in line_fps[..6].iter().enumerate() {
                blst::blst_fp_from_bendian(&mut value.fp2[k / 2].fp[k % 2], fp.as_ptr());
            }
        }
        value
    };
    for step in [
        Step::Mul,
        Step::Square,
        Step::CyclotomicSquare,
        Step::Line,
        Step::Frobenius,
        Step::Invert,
    ] {
        let name = step.name();
        group.throughput(Throughput::Elements(
            (ELEMENTS * CHAINS * step.rounds()) as u64,
        ));
        representation::<Radix28>(&mut group, step, &inputs, &line);
        representation::<Radix49>(&mut group, step, &inputs, &line);
        representation::<Residues>(&mut group, step, &inputs, &line);
        group.bench_function(format!("op={name} repr=blst"), |b| {
            b.iter(|| {
                let (factors, chains) = black_box(&blst_inputs).split_at(ELEMENTS);
                let mut chains: [blst::blst_fp12; ELEMENTS * CHAINS] =
                    chains.try_into().expect("chain inputs");
                for _ in 0..step.rounds() {
                    for (i, chain) in chains.iter_mut().enumerate() {
                        // SAFETY: valid pointers to field elements; blst allows aliasing the
                        // output with an input.
                        unsafe {
                            match step {
                                Step::Mul => {
                                    blst::blst_fp12_mul(chain, chain, &factors[i % ELEMENTS])
                                }
                                Step::Square => blst::blst_fp12_sqr(chain, chain),
                                Step::CyclotomicSquare => {
                                    blst::blst_fp12_cyclotomic_sqr(chain, chain)
                                }
                                Step::Line => {
                                    blst::blst_fp12_mul_by_xy00z0(chain, chain, &blst_line)
                                }
                                Step::Frobenius => blst::blst_fp12_frobenius_map(chain, chain, 1),
                                Step::Invert => blst::blst_fp12_inverse(chain, chain),
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

fn representation<R: Representation>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    step: Step,
    inputs: &[[u8; BYTES]],
    line: &[[u8; fp2::BYTES]],
) {
    group.bench_function(format!("op={} repr={}", step.name(), R::NAME), |b| {
        b.iter(|| {
            black_box(dispatch(Chains::<R>(
                step,
                black_box(inputs),
                line,
                PhantomData,
            )))
        });
    });
}

criterion_group!(benches, bench_fp12);

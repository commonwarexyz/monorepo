use commonware_cryptography::{
    bls12381::primitives::group::{Scalar, G1},
    kzg::{commit, Ethereum},
};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::rngs::OsRng;
use std::hint::black_box;

const DEGREES: &[usize] = &[64, 256, 1024, 4096];

fn benchmark_commit(c: &mut Criterion) {
    let setup = Ethereum::new();
    let mut rng = OsRng;

    // Benchmark for different polynomial degrees
    for &degree in DEGREES {
        c.bench_function(&format!("{}/degree={degree}", module_path!()), |b| {
            b.iter_batched(
                || {
                    let mut coeffs = Vec::with_capacity(degree);
                    for _ in 0..degree {
                        coeffs.push(Scalar::from_rand(&mut rng));
                    }
                    coeffs
                },
                |coeffs| {
                    black_box(commit::<Ethereum, G1>(&coeffs, &setup).unwrap());
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, benchmark_commit);

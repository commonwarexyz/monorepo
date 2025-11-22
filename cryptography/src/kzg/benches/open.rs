use commonware_cryptography::{
    bls12381::primitives::group::{Scalar, G1},
    kzg::{open, setup::Ethereum},
};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::rngs::OsRng;
use std::hint::black_box;

const DEGREES: &[usize] = &[64, 256, 1024, 4096];

fn benchmark_open(c: &mut Criterion) {
    let setup = Ethereum::new();
    let mut rng = OsRng;

    for &degree in DEGREES {
        c.bench_function(&format!("{}/degree={degree}", module_path!()), |b| {
            b.iter_batched(
                || {
                    let mut coeffs = Vec::with_capacity(degree);
                    for _ in 0..degree {
                        coeffs.push(Scalar::from_rand(&mut rng));
                    }
                    let point = Scalar::from_rand(&mut rng);
                    (coeffs, point)
                },
                |(coeffs, point)| {
                    black_box(open::<Ethereum, G1>(&coeffs, &point, &setup).unwrap());
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, benchmark_open);

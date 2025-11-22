use commonware_cryptography::{
    bls12381::primitives::group::Scalar,
    kzg::{open, TrustedSetup},
};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::rngs::OsRng;

fn benchmark_open(c: &mut Criterion) {
    let setup = TrustedSetup::ethereum_kzg().unwrap();
    let mut rng = OsRng;

    for degree in [64, 256, 1024, 4096] {
        c.bench_function(&format!("kzg_open_degree_{degree}"), |b| {
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
                    open(&coeffs, &point, &setup).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, benchmark_open);

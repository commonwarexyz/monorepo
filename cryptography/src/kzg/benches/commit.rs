use commonware_cryptography::{
    bls12381::primitives::group::Scalar,
    kzg::{commit, TrustedSetup},
};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::rngs::OsRng;

fn benchmark_commit(c: &mut Criterion) {
    let setup = TrustedSetup::ethereum_kzg().unwrap();
    let mut rng = OsRng;

    // Benchmark for different polynomial degrees
    for degree in [64, 256, 1024, 4096] {
        c.bench_function(&format!("kzg_commit_degree_{degree}"), |b| {
            b.iter_batched(
                || {
                    let mut coeffs = Vec::with_capacity(degree);
                    for _ in 0..degree {
                        coeffs.push(Scalar::from_rand(&mut rng));
                    }
                    coeffs
                },
                |coeffs| {
                    commit(&coeffs, &setup).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, benchmark_commit);

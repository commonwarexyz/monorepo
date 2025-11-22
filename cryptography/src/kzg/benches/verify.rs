use commonware_cryptography::{
    bls12381::primitives::group::Scalar,
    kzg::{batch_verify, commit, open, verify, TrustedSetup},
};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::rngs::OsRng;

fn benchmark_verify(c: &mut Criterion) {
    let setup = TrustedSetup::ethereum_kzg().unwrap();
    let mut rng = OsRng;

    c.bench_function("kzg_verify", |b| {
        b.iter_batched(
            || {
                let degree = 64;
                let mut coeffs = Vec::with_capacity(degree);
                for _ in 0..degree {
                    coeffs.push(Scalar::from_rand(&mut rng));
                }
                let point = Scalar::from_rand(&mut rng);
                let commitment = commit(&coeffs, &setup).unwrap();
                let proof = open(&coeffs, &point, &setup).unwrap();
                (commitment, point, proof)
            },
            |(commitment, point, proof)| {
                verify(&commitment, &point, &proof, &setup).unwrap();
            },
            BatchSize::SmallInput,
        );
    });
}

fn benchmark_batch_verify(c: &mut Criterion) {
    let setup = TrustedSetup::ethereum_kzg().unwrap();
    let mut rng = OsRng;

    for size in [1, 10, 50, 100] {
        c.bench_function(&format!("kzg_batch_verify_{size}"), |b| {
            b.iter_batched(
                || {
                    let degree = 64;
                    let mut commitments = Vec::with_capacity(size);
                    let mut points = Vec::with_capacity(size);
                    let mut proofs = Vec::with_capacity(size);

                    for _ in 0..size {
                        let mut coeffs = Vec::with_capacity(degree);
                        for _ in 0..degree {
                            coeffs.push(Scalar::from_rand(&mut rng));
                        }
                        let point = Scalar::from_rand(&mut rng);
                        let commitment = commit(&coeffs, &setup).unwrap();
                        let proof = open(&coeffs, &point, &setup).unwrap();

                        commitments.push(commitment);
                        points.push(point);
                        proofs.push(proof);
                    }
                    (commitments, points, proofs)
                },
                |(commitments, points, proofs)| {
                    batch_verify(&commitments, &points, &proofs, &setup, &mut OsRng).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, benchmark_verify, benchmark_batch_verify);

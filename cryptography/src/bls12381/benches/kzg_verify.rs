use commonware_cryptography::{
    bls12381::{
        kzg::{batch_verify, commit, open, setup::Ethereum, verify},
        primitives::group::{Scalar, G1},
    },
};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::rngs::OsRng as rng;

const DEGREES: &[usize] = &[64, 256, 1024, 4096];
const BATCH_SIZES: &[usize] = &[1, 10, 50, 100];

fn benchmark_verify(c: &mut Criterion) {
    let setup = Ethereum::new();

    for &degree in DEGREES {
        c.bench_function(
            &format!("{}/mode=single degree={degree}", module_path!()),
            |b| {
                b.iter_batched(
                    || {
                        let mut coeffs = Vec::with_capacity(degree);
                        for _ in 0..degree {
                            coeffs.push(Scalar::from_rand(&mut rng));
                        }
                        let point = Scalar::from_rand(&mut rng);
                        let commitment: G1 = commit(&coeffs, &setup).unwrap();
                        let proof = open(&coeffs, &point, &setup).unwrap();
                        (commitment, point, proof)
                    },
                    |(commitment, point, proof)| {
                        verify(&commitment, &point, &proof, &setup).unwrap();
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

fn benchmark_batch_verify(c: &mut Criterion) {
    let setup = Ethereum::new();

    for &degree in DEGREES {
        for &size in BATCH_SIZES {
            c.bench_function(
                &format!("{}/mode=batch degree={degree} size={size}", module_path!()),
                |b| {
                    b.iter_batched(
                        || {
                            let mut commitments: Vec<G1> = Vec::with_capacity(size);
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
                            batch_verify(&commitments, &points, &proofs, &setup, &mut rng).unwrap();
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

criterion_group!(benches, benchmark_verify, benchmark_batch_verify);

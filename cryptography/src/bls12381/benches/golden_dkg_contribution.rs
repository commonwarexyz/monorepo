//! Benchmark for Golden DKG contribution generation.
//!
//! This measures the time to generate a single contribution (encrypted shares + DLEQ proofs).

use commonware_cryptography::bls12381::{
    golden::Contributor,
    primitives::{
        group::{Element, Scalar, G1},
        variant::MinPk,
    },
};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::hint::black_box;

// Configure contributors based on context
#[cfg(not(full_bench))]
const CONTRIBUTORS: &[usize] = &[5, 10, 20, 50];
#[cfg(full_bench)]
const CONTRIBUTORS: &[usize] = &[5, 10, 20, 50, 100, 250, 500];

fn create_participants(rng: &mut StdRng, n: usize) -> Vec<(Scalar, G1)> {
    (0..n)
        .map(|_| {
            let sk = Scalar::from_rand(rng);
            let mut pk = G1::one();
            pk.mul(&sk);
            (sk, pk)
        })
        .collect()
}

fn benchmark_golden_dkg_contribution(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    for &n in CONTRIBUTORS {
        let t = commonware_utils::quorum(n as u32);

        // Pre-create participants
        let participants = create_participants(&mut rng, n);
        let public_keys: Vec<G1> = participants.iter().map(|(_, pk)| *pk).collect();

        c.bench_function(
            &format!("{}/n={} t={}", module_path!(), n, t),
            |b| {
                b.iter_batched(
                    || {
                        // Setup: clone what we need
                        (public_keys.clone(), participants[0].0.clone())
                    },
                    |(pks, sk)| {
                        black_box(Contributor::<MinPk>::new(
                            &mut StdRng::seed_from_u64(42),
                            pks,
                            0,
                            &sk,
                            None,
                        ));
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_golden_dkg_contribution
}

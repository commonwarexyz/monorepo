//! Benchmark for Golden DKG share recovery (finalization).
//!
//! This measures the time for a participant to finalize and recover their share
//! after receiving all contributions.

use commonware_cryptography::bls12381::{
    golden::{Aggregator, Contributor},
    primitives::{
        group::{Element, Scalar, G1},
        variant::MinPk,
    },
};
use commonware_utils::quorum;
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

fn benchmark_golden_dkg_recovery(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    for &n in CONTRIBUTORS {
        let t = quorum(n as u32);

        c.bench_function(&format!("{}/n={} t={}", module_path!(), n, t), |b| {
            b.iter_batched(
                || {
                    // Setup: create participants and contributions
                    let participants = create_participants(&mut rng, n);
                    let public_keys: Vec<G1> = participants.iter().map(|(_, pk)| *pk).collect();

                    // Create aggregator and add contributions
                    let mut aggregator = Aggregator::<MinPk>::new(public_keys.clone(), t);

                    for (idx, (sk, _)) in participants.iter().enumerate().take(t as usize) {
                        let (_, contribution) = Contributor::<MinPk>::new(
                            &mut StdRng::seed_from_u64(idx as u64),
                            public_keys.clone(),
                            idx as u32,
                            sk,
                            None,
                        );
                        aggregator.add(idx as u32, contribution).unwrap();
                    }

                    (aggregator, participants[0].0.clone())
                },
                |(aggregator, sk)| {
                    black_box(aggregator.finalize(0, &sk).unwrap());
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_golden_dkg_recovery
}

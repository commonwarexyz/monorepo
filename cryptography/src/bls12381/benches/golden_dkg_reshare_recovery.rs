//! Benchmark for Golden DKG reshare recovery.
//!
//! This measures the time for a participant to finalize a reshare and recover
//! their new share after receiving all reshare contributions.

use commonware_cryptography::bls12381::{
    golden::{Aggregator, Contributor},
    primitives::{
        group::{Element, Scalar, Share, G1},
        poly,
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

/// Run initial DKG to get shares for resharing
fn run_initial_dkg(participants: &[(Scalar, G1)]) -> (poly::Public<MinPk>, Vec<Share>) {
    let n = participants.len();
    let t = quorum(n as u32);
    let public_keys: Vec<G1> = participants.iter().map(|(_, pk)| *pk).collect();

    // Create aggregator and add contributions
    let mut aggregator = Aggregator::<MinPk>::new(public_keys.clone(), t);

    for (idx, (sk, _)) in participants.iter().enumerate() {
        let (_, contribution) = Contributor::<MinPk>::new(
            &mut StdRng::seed_from_u64(idx as u64),
            public_keys.clone(),
            idx as u32,
            sk,
            None,
        );
        aggregator.add(idx as u32, contribution).unwrap();
    }

    // Finalize for all participants
    let mut shares = Vec::with_capacity(n);
    let mut public = None;

    for (idx, (sk, _)) in participants.iter().enumerate() {
        let output = aggregator.finalize(idx as u32, sk).unwrap();
        if public.is_none() {
            public = Some(output.public);
        }
        shares.push(output.share);
    }

    (public.unwrap(), shares)
}

fn benchmark_golden_dkg_reshare_recovery(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    for &n in CONTRIBUTORS {
        let t = quorum(n as u32);

        // Create participants and run initial DKG
        let participants = create_participants(&mut rng, n);
        let (previous_public, previous_shares) = run_initial_dkg(&participants);
        let public_keys: Vec<G1> = participants.iter().map(|(_, pk)| *pk).collect();

        c.bench_function(&format!("{}/n={} t={}", module_path!(), n, t), |b| {
            b.iter_batched(
                || {
                    // Setup: create reshare contributions
                    let mut aggregator = Aggregator::<MinPk>::new_reshare(
                        public_keys.clone(),
                        t,
                        previous_public.clone(),
                    );

                    for (idx, (sk, _)) in participants.iter().enumerate().take(t as usize) {
                        let (_, contribution) = Contributor::<MinPk>::new(
                            &mut StdRng::seed_from_u64(100 + idx as u64),
                            public_keys.clone(),
                            idx as u32,
                            sk,
                            Some(previous_shares[idx].clone()),
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
    targets = benchmark_golden_dkg_reshare_recovery
}

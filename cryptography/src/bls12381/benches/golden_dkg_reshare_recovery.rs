//! Benchmark for Golden DKG reshare recovery.
//!
//! This measures the time for a participant to finalize a reshare and recover
//! their new share after receiving all reshare contributions.

use commonware_cryptography::bls12381::{
    golden::{Aggregator, Contributor, IdentityKey, JubjubPoint},
    primitives::{
        group::Share,
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

fn create_identities(rng: &mut StdRng, n: usize) -> Vec<IdentityKey> {
    (0..n).map(|_| IdentityKey::generate(rng)).collect()
}

/// Run initial DKG to get shares for resharing
fn run_initial_dkg(identities: &[IdentityKey]) -> (poly::Public<MinPk>, Vec<Share>) {
    let n = identities.len();
    let t = quorum(n as u32);
    let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

    // Create aggregator and add contributions (use single thread for setup)
    let mut aggregator = Aggregator::<MinPk>::new(identity_keys.clone(), t, 1);

    for (idx, identity) in identities.iter().enumerate() {
        let (_, contribution) = Contributor::<MinPk>::new(
            &mut StdRng::seed_from_u64(idx as u64),
            identity_keys.clone(),
            idx as u32,
            identity,
            None,
        );
        aggregator.add(idx as u32, contribution).unwrap();
    }

    // Finalize for all participants
    let mut shares = Vec::with_capacity(n);
    let mut public = None;

    for (idx, identity) in identities.iter().enumerate() {
        let output = aggregator.finalize(idx as u32, identity).unwrap();
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
        let identities = create_identities(&mut rng, n);
        let (previous_public, previous_shares) = run_initial_dkg(&identities);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        for concurrency in [1, 8] {
            c.bench_function(
                &format!("{}/conc={} n={} t={}", module_path!(), concurrency, n, t),
                |b| {
                    b.iter_batched(
                        || {
                            // Setup: create reshare contributions
                            let mut aggregator = Aggregator::<MinPk>::new_reshare(
                                identity_keys.clone(),
                                t,
                                previous_public.clone(),
                                concurrency,
                            );

                            for (idx, identity) in identities.iter().enumerate().take(t as usize) {
                                let (_, contribution) = Contributor::<MinPk>::new(
                                    &mut StdRng::seed_from_u64(100 + idx as u64),
                                    identity_keys.clone(),
                                    idx as u32,
                                    identity,
                                    Some(previous_shares[idx].clone()),
                                );
                                aggregator.add(idx as u32, contribution).unwrap();
                            }

                            (aggregator, identities[0].clone())
                        },
                        |(aggregator, identity)| {
                            black_box(aggregator.finalize(0, &identity).unwrap());
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_golden_dkg_reshare_recovery
}

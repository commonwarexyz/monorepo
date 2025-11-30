//! Benchmark for Golden DKG share recovery (finalization).
//!
//! This measures the time for a participant to finalize and recover their share
//! after receiving all contributions.

use commonware_cryptography::bls12381::{
    golden::{Aggregator, Contributor, IdentityKey, JubjubPoint},
    primitives::variant::MinPk,
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

fn benchmark_golden_dkg_recovery(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    for &n in CONTRIBUTORS {
        let t = quorum(n as u32);

        for concurrency in [1, 8] {
            c.bench_function(
                &format!("{}/conc={} n={} t={}", module_path!(), concurrency, n, t),
                |b| {
                    b.iter_batched(
                        || {
                            // Setup: create participants and contributions
                            let identities = create_identities(&mut rng, n);
                            let identity_keys: Vec<JubjubPoint> =
                                identities.iter().map(|id| id.public).collect();

                            // Create aggregator and add contributions
                            let mut aggregator =
                                Aggregator::<MinPk>::new(identity_keys.clone(), t, concurrency);

                            for (idx, identity) in identities.iter().enumerate().take(t as usize) {
                                let (_, contribution) = Contributor::<MinPk>::new(
                                    &mut StdRng::seed_from_u64(idx as u64),
                                    identity_keys.clone(),
                                    idx as u32,
                                    identity,
                                    None,
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
    targets = benchmark_golden_dkg_recovery
}

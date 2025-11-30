//! Benchmark for Golden DKG contribution generation.
//!
//! This measures the time to generate a single contribution with batched proofs.

use commonware_cryptography::bls12381::{
    golden::{Contributor, IdentityKey, JubjubPoint},
    primitives::variant::MinPk,
};
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

fn benchmark_golden_dkg_contribution(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    for &n in CONTRIBUTORS {
        let t = commonware_utils::quorum(n as u32);

        // Pre-create participants
        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        c.bench_function(
            &format!("{}/n={} t={}", module_path!(), n, t),
            |b| {
                b.iter_batched(
                    || {
                        // Setup: clone what we need
                        (identity_keys.clone(), identities[0].clone())
                    },
                    |(pks, identity)| {
                        black_box(Contributor::<MinPk>::new(
                            &mut StdRng::seed_from_u64(42),
                            pks,
                            0,
                            &identity,
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

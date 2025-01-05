use commonware_cryptography::bls12381::dkg::{dealer, player};
use commonware_cryptography::Ed25519;
use commonware_cryptography::Scheme;
use commonware_utils::quorum;
use criterion::{criterion_group, BatchSize, Criterion};
use std::collections::HashMap;
use std::hint::black_box;

/// Concurrency isn't used in DKG recovery, so we set it to 1.
const CONCURRENCY: usize = 1;

fn benchmark_dkg_recovery(c: &mut Criterion) {
    for &n in &[5, 10, 20, 50, 100, 250, 500] {
        let t = quorum(n).unwrap();
        c.bench_function(&format!("{}/n={} t={}", module_path!(), n, t), |b| {
            b.iter_batched(
                || {
                    // Create contributors
                    let mut contributors = (0..n)
                        .map(|i| Ed25519::from_seed(i as u64).public_key())
                        .collect::<Vec<_>>();
                    contributors.sort();

                    // Create player
                    let me = contributors[0].clone();
                    let mut p0 = player::P0::new(
                        me.clone(),
                        None,
                        contributors.clone(),
                        contributors.clone(),
                        CONCURRENCY,
                    );

                    // Create commitments and send shares to player
                    let mut commitments = HashMap::new();
                    for (idx, dealer) in contributors.iter().take(t as usize).enumerate() {
                        let (_, commitment, shares) = dealer::P0::new(None, contributors.clone());
                        p0.share(dealer.clone(), commitment.clone(), shares[0])
                            .unwrap();
                        commitments.insert(idx as u32, commitment);
                    }
                    (p0, commitments)
                },
                |(player, commitments)| {
                    black_box(player.finalize(commitments, HashMap::new()).unwrap());
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_dkg_recovery
}

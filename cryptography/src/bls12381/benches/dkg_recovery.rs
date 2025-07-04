use commonware_cryptography::{
    bls12381::{
        dkg::{Dealer, Player},
        primitives::variant::MinSig,
    },
    ed25519, PrivateKeyExt as _, Signer as _,
};
use commonware_utils::quorum;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::{collections::HashMap, hint::black_box};

/// Concurrency isn't used in DKG recovery, so we set it to 1.
const CONCURRENCY: usize = 1;

fn benchmark_dkg_recovery(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    for &n in &[5, 10, 20, 50, 100, 250, 500] {
        let t = quorum(n);
        c.bench_function(&format!("{}/n={} t={}", module_path!(), n, t), |b| {
            b.iter_batched(
                || {
                    // Create contributors
                    let mut contributors = (0..n)
                        .map(|i| ed25519::PrivateKey::from_seed(i as u64).public_key())
                        .collect::<Vec<_>>();
                    contributors.sort();

                    // Create player
                    let me = contributors[0].clone();
                    let mut player = Player::<_, MinSig>::new(
                        me,
                        None,
                        contributors.clone(),
                        contributors.clone(),
                        CONCURRENCY,
                    );

                    // Create commitments and send shares to player
                    let mut commitments = HashMap::new();
                    for (idx, dealer) in contributors.iter().take(t as usize).enumerate() {
                        let (_, commitment, shares) =
                            Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());
                        player
                            .share(dealer.clone(), commitment.clone(), shares[0].clone())
                            .unwrap();
                        commitments.insert(idx as u32, commitment);
                    }
                    (player, commitments)
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

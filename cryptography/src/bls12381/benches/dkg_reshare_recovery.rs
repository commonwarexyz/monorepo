use commonware_cryptography::{
    bls12381::dkg::{Dealer, Player},
    Ed25519, Signer,
};
use commonware_utils::quorum;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::collections::HashMap;
use std::hint::black_box;

fn benchmark_dkg_reshare_recovery(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    for &n in &[5, 10, 20, 50, 100, 250, 500] {
        // Perform DKG
        //
        // We do this once outside of the benchmark to reduce the overhead
        // of each sample (which can be large as `n` grows).

        // Create contributors
        let mut contributors = (0..n)
            .map(|i| Ed25519::from_seed(i as u64).public_key())
            .collect::<Vec<_>>();
        contributors.sort();

        // Create players
        let mut players = Vec::with_capacity(n);
        for con in &contributors {
            let player = Player::new(
                con.clone(),
                None,
                contributors.clone(),
                contributors.clone(),
                1,
            );
            players.push(player);
        }

        // Create commitments and send shares to players
        let t = quorum(n as u32);
        let mut commitments = HashMap::new();
        for (dealer_idx, dealer) in contributors.iter().take(t as usize).enumerate() {
            let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());
            for (player_idx, player) in players.iter_mut().enumerate() {
                player
                    .share(
                        dealer.clone(),
                        commitment.clone(),
                        shares[player_idx].clone(),
                    )
                    .unwrap();
            }
            commitments.insert(dealer_idx as u32, commitment);
        }

        // Finalize players
        let mut outputs = Vec::new();
        for player in players {
            outputs.push(
                player
                    .finalize(commitments.clone(), HashMap::new())
                    .unwrap(),
            );
        }

        for &concurrency in &[1, 2, 4, 8] {
            c.bench_function(
                &format!("{}/conc={} n={} t={}", module_path!(), concurrency, n, t),
                |b| {
                    b.iter_batched(
                        || {
                            // Create player
                            let me = contributors[0].clone();
                            let mut player = Player::new(
                                me,
                                Some(outputs[0].public.clone()),
                                contributors.clone(),
                                contributors.clone(),
                                concurrency,
                            );

                            // Create commitments and send shares to player
                            let mut commitments = HashMap::new();
                            for (idx, dealer) in contributors.iter().take(t as usize).enumerate() {
                                let (_, commitment, shares) = Dealer::new(
                                    &mut rng,
                                    Some(outputs[idx].share.clone()),
                                    contributors.clone(),
                                );
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
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_dkg_reshare_recovery
}

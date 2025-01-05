use commonware_cryptography::{
    bls12381::dkg::{dealer, player},
    Ed25519, Scheme,
};
use commonware_utils::quorum;
use criterion::{criterion_group, BatchSize, Criterion};
use std::collections::HashMap;
use std::hint::black_box;

fn benchmark_dkg_reshare_recovery(c: &mut Criterion) {
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
            let p0 = player::P0::new(
                con.clone(),
                None,
                contributors.clone(),
                contributors.clone(),
                1,
            );
            players.push(p0);
        }

        // Create commitments and send shares to players
        let t = quorum(n as u32).unwrap();
        let mut commitments = HashMap::new();
        for (dealer_idx, dealer) in contributors.iter().take(t as usize).enumerate() {
            let (_, commitment, shares) = dealer::P0::new(None, contributors.clone());
            for (player_idx, player) in players.iter_mut().enumerate() {
                player
                    .share(dealer.clone(), commitment.clone(), shares[player_idx])
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
                            let mut p0 = player::P0::new(
                                me.clone(),
                                Some(outputs[0].public.clone()),
                                contributors.clone(),
                                contributors.clone(),
                                concurrency,
                            );

                            // Create commitments and send shares to player
                            let mut commitments = HashMap::new();
                            for (idx, dealer) in contributors.iter().take(t as usize).enumerate() {
                                let (_, commitment, shares) =
                                    dealer::P0::new(Some(outputs[idx].share), contributors.clone());
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

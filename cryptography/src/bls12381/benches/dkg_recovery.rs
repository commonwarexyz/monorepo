use commonware_cryptography::{
    bls12381::{
        dkg::{Dealer, Info, Player},
        primitives::variant::MinSig,
    },
    ed25519::PrivateKey,
    PrivateKeyExt as _, Signer as _,
};
use commonware_utils::{quorum, set::Ordered};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::{collections::BTreeMap, hint::black_box};

// Configure contributors based on context
#[cfg(not(full_bench))]
const CONTRIBUTORS: &[u32] = &[5, 10, 20, 50];
#[cfg(full_bench)]
const CONTRIBUTORS: &[u32] = &[5, 10, 20, 50, 100, 250, 500];
const CONCURRENCY: &[usize] = &[1, 4, 8];

fn benchmark_dkg_recovery(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    for &n in CONTRIBUTORS {
        let t = quorum(n);
        for &concurrency in CONCURRENCY {
            c.bench_function(
                &format!("{}/n={} t={} conc={}", module_path!(), n, t, concurrency),
                |b| {
                    b.iter_batched(
                        || {
                            let private_keys = (0..n)
                                .map(|i| PrivateKey::from_seed(i as u64))
                                .collect::<Vec<_>>();
                            let me = private_keys.first().unwrap().clone();
                            let me_pk = me.public_key();
                            let dealers =
                                Ordered::from_iter(private_keys.iter().map(|sk| sk.public_key()));
                            let players = dealers.clone();
                            let round_info = Info::new(0, None, dealers, players).unwrap();

                            // Create player state for every participant
                            let mut player_states = private_keys
                                .iter()
                                .map(|sk| {
                                    let pk = sk.public_key();
                                    (
                                        pk,
                                        Player::<MinSig, PrivateKey>::new(
                                            round_info.clone(),
                                            sk.clone(),
                                        )
                                        .unwrap(),
                                    )
                                })
                                .collect::<BTreeMap<_, _>>();
                            let mut me_player = player_states
                                .remove(&me_pk)
                                .expect("player set should contain me");

                            // Create commitments and send shares to player
                            let mut logs = BTreeMap::new();
                            for sk in private_keys {
                                let pk = sk.public_key();
                                let (mut dealer, pub_msg, priv_msgs) =
                                    Dealer::start(&mut rng, round_info.clone(), sk, None).unwrap();
                                for (target_pk, priv_msg) in priv_msgs {
                                    if target_pk == me_pk {
                                        let ack = me_player
                                            .dealer_message(pk.clone(), pub_msg.clone(), priv_msg)
                                            .unwrap();
                                        dealer.receive_player_ack(target_pk.clone(), ack).unwrap();
                                    } else if let Some(player) = player_states.get_mut(&target_pk) {
                                        if let Some(ack) = player.dealer_message(
                                            pk.clone(),
                                            pub_msg.clone(),
                                            priv_msg,
                                        ) {
                                            dealer
                                                .receive_player_ack(target_pk.clone(), ack)
                                                .unwrap();
                                        }
                                    }
                                }
                                let (checked_pk, log) =
                                    dealer.finalize().check(&round_info).unwrap();
                                logs.insert(checked_pk, log);
                            }
                            (me_player, logs)
                        },
                        |(player, logs)| {
                            black_box(player.finalize(logs, concurrency).unwrap());
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
    targets = benchmark_dkg_recovery
}

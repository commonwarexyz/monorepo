use commonware_cryptography::{
    bls12381::{
        dkg::{Dealer, Player, Info},
        primitives::variant::MinSig,
    },
    ed25519::PrivateKey,
    PrivateKeyExt as _, Signer as _,
};
use commonware_utils::{quorum, set::Ordered};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::{collections::BTreeMap, hint::black_box, iter};

// Configure contributors based on context
#[cfg(not(full_bench))]
const CONTRIBUTORS: &[u32] = &[5, 10, 20, 50];
#[cfg(full_bench)]
const CONTRIBUTORS: &[u32] = &[5, 10, 20, 50, 100, 250, 500];

fn benchmark_dkg_recovery(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    for &n in CONTRIBUTORS {
        let t = quorum(n);
        c.bench_function(&format!("{}/n={} t={}", module_path!(), n, t), |b| {
            b.iter_batched(
                || {
                    let mut private_keys = (0..n)
                        .map(|i| PrivateKey::from_seed(i as u64))
                        .collect::<Vec<_>>();
                    let me = private_keys.pop().unwrap();
                    let me_pk = me.public_key();
                    let dealers = private_keys
                        .iter()
                        .map(|sk| sk.public_key())
                        .collect::<Ordered<_>>();
                    let players = Ordered::from_iter(iter::once(me_pk.clone()));
                    let round_info = Info::new(0, None, dealers, players).unwrap();

                    // Create player
                    let mut player =
                        Player::<MinSig, PrivateKey>::new(round_info.clone(), me).unwrap();

                    // Create commitments and send shares to player
                    let mut logs = BTreeMap::new();
                    for sk in private_keys {
                        let pk = sk.public_key();
                        let (mut dealer, pub_msg, mut priv_msgs) =
                            Dealer::start(&mut rng, round_info.clone(), sk, None).unwrap();
                        let ack = player
                            .dealer_message(pk, pub_msg, priv_msgs.pop().unwrap().1)
                            .unwrap();
                        dealer.receive_player_ack(me_pk.clone(), ack).unwrap();
                        let (checked_pk, log) = dealer.finalize().check(&round_info).unwrap();
                        logs.insert(checked_pk, log);
                    }
                    (player, logs)
                },
                |(player, logs)| {
                    black_box(player.finalize(logs).unwrap());
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

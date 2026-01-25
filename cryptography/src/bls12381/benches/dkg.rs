use commonware_cryptography::{
    bls12381::{
        dkg::{deal, Dealer, DealerLog, Info, Player},
        primitives::variant::MinSig,
    },
    ed25519::{PrivateKey, PublicKey},
    Signer as _,
};
use commonware_math::algebra::Random;
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{ordered::Set, Faults, N3f1, NZUsize, TryCollect};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use rand_core::CryptoRngCore;
use std::{collections::BTreeMap, hint::black_box};

type V = MinSig;

struct Bench {
    info: Info<V, PublicKey>,
    me: PrivateKey,
    logs: BTreeMap<PublicKey, DealerLog<V, PublicKey>>,
}

impl Bench {
    fn new(mut rng: impl CryptoRngCore, reshare: bool, n: u32) -> Self {
        let private_keys = (0..n)
            .map(|_| PrivateKey::random(&mut rng))
            .collect::<Vec<_>>();
        let me = private_keys.first().unwrap().clone();
        let me_pk = me.public_key();
        let dealers = private_keys
            .iter()
            .map(|sk| sk.public_key())
            .try_collect::<Set<_>>()
            .unwrap();

        let (output, shares) = if reshare {
            let (o, s) =
                deal::<V, PublicKey, N3f1>(&mut rng, Default::default(), dealers.clone()).unwrap();
            (Some(o), Some(s))
        } else {
            (None, None)
        };
        let players = dealers.clone();
        let info = Info::new::<N3f1>(
            b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_DKG_BENCH",
            0,
            output,
            Default::default(),
            dealers,
            players,
        )
        .unwrap();

        // Create player state for every participant
        let mut player_states = private_keys
            .iter()
            .filter_map(|sk| {
                let pk = sk.public_key();
                if pk == me_pk {
                    return None;
                }
                Some((
                    pk,
                    Player::<MinSig, PrivateKey>::new(info.clone(), sk.clone()).unwrap(),
                ))
            })
            .collect::<BTreeMap<_, _>>();

        let mut logs = BTreeMap::new();
        for sk in private_keys {
            let pk = sk.public_key();
            let (mut dealer, pub_msg, priv_msgs) = Dealer::start::<N3f1>(
                &mut rng,
                info.clone(),
                sk,
                shares
                    .as_ref()
                    .and_then(|shares| shares.get_value(&pk).cloned()),
            )
            .unwrap();
            for (target_pk, priv_msg) in priv_msgs {
                // The only missing player should be ourselves.
                if let Some(player) = player_states.get_mut(&target_pk) {
                    if let Some(ack) =
                        player.dealer_message::<N3f1>(pk.clone(), pub_msg.clone(), priv_msg)
                    {
                        dealer.receive_player_ack(target_pk.clone(), ack).unwrap();
                    }
                }
            }
            logs.insert(pk, dealer.finalize::<N3f1>().check(&info).unwrap().1);
        }

        Self { info, me, logs }
    }

    fn pre_finalize(
        &self,
    ) -> (
        Player<V, PrivateKey>,
        BTreeMap<PublicKey, DealerLog<V, PublicKey>>,
    ) {
        (
            Player::<MinSig, PrivateKey>::new(self.info.clone(), self.me.clone()).unwrap(),
            self.logs.clone(),
        )
    }
}

// Configure contributors based on context
cfg_if::cfg_if! {
    if #[cfg(full_bench)] {
        const CONTRIBUTORS: &[u32] = &[5, 10, 20, 50, 100, 250, 500];
        const CONCURRENCY: &[usize] = &[1, 4, 8];
    } else {
        const CONTRIBUTORS: &[u32] = &[5, 10, 20, 50];
        const CONCURRENCY: &[usize] = &[1];
    }
}

fn bench_dkg(c: &mut Criterion, reshare: bool) {
    let suffix = if reshare {
        "_reshare_recovery"
    } else {
        "_recovery"
    };
    let mut rng = StdRng::seed_from_u64(0);
    for &n in CONTRIBUTORS {
        let t = N3f1::quorum(n);
        let bench = Bench::new(&mut rng, reshare, n);
        for &concurrency in CONCURRENCY {
            let strategy = Rayon::new(NZUsize!(concurrency)).unwrap();
            c.bench_function(
                &format!(
                    "{}{}/n={} t={} conc={}",
                    module_path!(),
                    suffix,
                    n,
                    t,
                    concurrency,
                ),
                |b| {
                    b.iter_batched(
                        || bench.pre_finalize(),
                        |(player, logs)| {
                            if concurrency > 1 {
                                black_box(player.finalize::<N3f1>(logs, &strategy).unwrap());
                            } else {
                                black_box(player.finalize::<N3f1>(logs, &Sequential).unwrap());
                            }
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

fn bench_dkg_recovery(c: &mut Criterion) {
    bench_dkg(c, false);
}

fn bench_dkg_reshare_recovery(c: &mut Criterion) {
    bench_dkg(c, true);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_dkg_recovery, bench_dkg_reshare_recovery
}

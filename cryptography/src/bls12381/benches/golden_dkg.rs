use commonware_cryptography::bls12381::{
    golden_dkg::{self, DealerLog, Info, Output, PrivateKey, PublicKey},
    primitives::group::Share,
};
use commonware_math::algebra::Random;
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{ordered::Set, Faults, N3f1, NZUsize, TryCollect};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use rand_core::CryptoRngCore;
use std::{collections::BTreeMap, hint::black_box};

/// Run a fresh honest DKG round, returning the output and per-key shares.
fn run_fresh(
    rng: &mut impl CryptoRngCore,
    keys: &[PrivateKey],
    dealers: &Set<PublicKey>,
    players: &Set<PublicKey>,
) -> (Output<PublicKey>, Vec<Share>) {
    let info = Info::new(0, None, dealers.clone(), players.clone());
    let mut logs = BTreeMap::new();
    for k in keys {
        let signed = golden_dkg::deal::<N3f1>(rng, &info, k, None).unwrap();
        let (pk, log) = signed.identify().unwrap();
        logs.insert(pk, log);
    }
    let sharing = golden_dkg::observe::<N3f1>(rng, &info, logs.clone(), &Sequential).unwrap();
    let mut shares = Vec::new();
    for k in keys {
        let (_, share) =
            golden_dkg::play::<N3f1>(rng, &info, logs.clone(), k, &Sequential).unwrap();
        shares.push(share);
    }
    let output = Output::new(*info.summary(), sharing, dealers.clone(), players.clone());
    (output, shares)
}

struct DealBench {
    info: Info,
    me: PrivateKey,
}

impl DealBench {
    fn new(rng: &mut impl CryptoRngCore, n: u32) -> Self {
        let keys: Vec<PrivateKey> = (0..n).map(|_| PrivateKey::random(&mut *rng)).collect();
        let me = keys[0].clone();
        let dealers: Set<PublicKey> = keys.iter().map(|k| k.public()).try_collect().unwrap();
        let players = dealers.clone();
        let info = Info::new(0, None, dealers, players);
        Self { info, me }
    }
}

struct PlayBench {
    info: Info,
    me: PrivateKey,
    logs: BTreeMap<PublicKey, DealerLog>,
}

impl PlayBench {
    fn new(rng: &mut impl CryptoRngCore, reshare: bool, n: u32) -> Self {
        let keys: Vec<PrivateKey> = (0..n).map(|_| PrivateKey::random(&mut *rng)).collect();
        let me = keys[0].clone();
        let dealers: Set<PublicKey> = keys.iter().map(|k| k.public()).try_collect().unwrap();
        let players = dealers.clone();

        let (previous, shares) = if reshare {
            let (output, shares) = run_fresh(rng, &keys, &dealers, &players);
            (Some(output), Some(shares))
        } else {
            (None, None)
        };

        let round = if reshare { 1 } else { 0 };
        let info = Info::new(round, previous, dealers, players);

        let mut logs = BTreeMap::new();
        for (i, k) in keys.iter().enumerate() {
            let share = shares.as_ref().map(|s| s[i].clone());
            let signed = golden_dkg::deal::<N3f1>(rng, &info, k, share).unwrap();
            let (pk, log) = signed.identify().unwrap();
            logs.insert(pk, log);
        }

        Self { info, me, logs }
    }
}

cfg_if::cfg_if! {
    if #[cfg(full_bench)] {
        const CONTRIBUTORS: &[u32] = &[5, 10, 20, 50, 100, 250, 500];
        const CONCURRENCY: &[usize] = &[1, 4, 8];
    } else {
        const CONTRIBUTORS: &[u32] = &[5, 10, 20, 50];
        const CONCURRENCY: &[usize] = &[1];
    }
}

fn bench_golden_dkg_deal(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    for &n in CONTRIBUTORS {
        let t = N3f1::quorum(n);
        let bench = DealBench::new(&mut rng, n);
        c.bench_function(&format!("{}_deal/n={} t={}", module_path!(), n, t), |b| {
            b.iter_batched(
                || {
                    (
                        bench.info.clone(),
                        bench.me.clone(),
                        StdRng::seed_from_u64(0),
                    )
                },
                |(info, me, mut rng)| {
                    black_box(golden_dkg::deal::<N3f1>(&mut rng, &info, &me, None).unwrap());
                },
                BatchSize::SmallInput,
            );
        });
    }
}

fn bench_play(c: &mut Criterion, reshare: bool) {
    let suffix = if reshare { "_reshare_play" } else { "_play" };
    let mut rng = StdRng::seed_from_u64(0);
    for &n in CONTRIBUTORS {
        let t = N3f1::quorum(n);
        let bench = PlayBench::new(&mut rng, reshare, n);
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
                        || {
                            (
                                bench.info.clone(),
                                bench.me.clone(),
                                bench.logs.clone(),
                                StdRng::seed_from_u64(0),
                            )
                        },
                        |(info, me, logs, mut rng)| {
                            if concurrency > 1 {
                                black_box(
                                    golden_dkg::play::<N3f1>(&mut rng, &info, logs, &me, &strategy)
                                        .unwrap(),
                                );
                            } else {
                                black_box(
                                    golden_dkg::play::<N3f1>(
                                        &mut rng,
                                        &info,
                                        logs,
                                        &me,
                                        &Sequential,
                                    )
                                    .unwrap(),
                                );
                            }
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

fn bench_golden_dkg_play(c: &mut Criterion) {
    bench_play(c, false);
}

fn bench_golden_dkg_reshare_play(c: &mut Criterion) {
    bench_play(c, true);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets =
        bench_golden_dkg_deal,
        bench_golden_dkg_play,
        bench_golden_dkg_reshare_play,
}

use commonware_cryptography::{
    bls12381::{
        dkg::deal,
        primitives::{self, sharing::Mode, variant::MinSig},
    },
    ed25519::PrivateKey,
    Signer,
};
use commonware_parallel::Sequential;
use commonware_utils::{Faults, N3f1, TryCollect};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::hint::black_box;

fn bench_threshold_recover(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    let namespace = b"benchmark";
    let msg = b"hello";
    for &n in &[5, 10, 20, 50, 100, 250, 500, 1000, 2000, 4000] {
        for mode in [Mode::NonZeroCounter, Mode::RootsOfUnity] {
            let t = N3f1::quorum(n);
            c.bench_function(
                &format!("{}/n={} t={} mode={:?}", module_path!(), n, t, mode),
                |b| {
                    b.iter_batched(
                        || {
                            let players = (0..n)
                                .map(|i| PrivateKey::from_seed(i as u64).public_key())
                                .try_collect()
                                .unwrap();
                            let (public, shares) = deal::<MinSig, _, N3f1>(&mut rng, mode, players)
                                .expect("deal should succeed");
                            (
                                public,
                                shares
                                    .values()
                                    .iter()
                                    .map(|s| {
                                        primitives::ops::threshold::sign_message::<MinSig>(
                                            s, namespace, msg,
                                        )
                                    })
                                    .collect::<Vec<_>>(),
                            )
                        },
                        |(public, partials)| {
                            black_box(
                                primitives::ops::threshold::recover::<MinSig, _, N3f1>(
                                    public.public(),
                                    &partials,
                                    &Sequential,
                                )
                                .unwrap(),
                            );
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

criterion_group!(benches, bench_threshold_recover);

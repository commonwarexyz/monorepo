use commonware_cryptography::{
    bls12381::{
        dkg::deal,
        primitives::{self, sharing::Mode, variant::MinSig},
    },
    ed25519::PrivateKey,
    Signer as _,
};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{Faults, N3f1, NZUsize, TryCollect};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::hint::black_box;

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::NonZeroCounter => "counter",
        Mode::RootsOfUnity => "roots",
    }
}

fn bench_threshold_batch_verify_same_message(c: &mut Criterion) {
    let namespace = b"benchmark";
    let msg = b"hello";
    for mode in [Mode::NonZeroCounter, Mode::RootsOfUnity] {
        for &n in &[5, 10, 20, 50, 100, 250, 500] {
            let t = N3f1::quorum(n);
            let f = n - t;
            for invalid in [0, f] {
                for concurrency in [1, 8] {
                    let strategy = Rayon::new(NZUsize!(concurrency)).unwrap();
                    c.bench_function(
                        &format!(
                            "{}/mode={} n={} t={} invalid={} conc={}",
                            module_path!(),
                            mode_name(mode),
                            n,
                            t,
                            invalid,
                            concurrency
                        ),
                        |b| {
                            b.iter_batched(
                                || {
                                    let mut rng = StdRng::seed_from_u64(0);
                                    let players = (0..n)
                                        .map(|i| PrivateKey::from_seed(i as u64).public_key())
                                        .try_collect()
                                        .unwrap();
                                    let (output, shares) =
                                        deal::<MinSig, _, N3f1>(&mut rng, mode, players)
                                            .expect("deal should succeed");
                                let signatures = shares
                                    .values()
                                    .iter()
                                    .enumerate()
                                    .map(|(idx, s)| {
                                        if idx < invalid as usize {
                                            primitives::ops::threshold::sign_message::<MinSig>(
                                                s, b"wrong", msg,
                                            )
                                        } else {
                                            primitives::ops::threshold::sign_message::<MinSig>(
                                                s, namespace, msg,
                                            )
                                        }
                                    })
                                    .collect::<Vec<_>>();
                                (rng, output.public().clone(), signatures)
                            },
                            |(mut rng, polynomial, mut signatures)| {
                                if invalid > 0 {
                                    signatures.shuffle(&mut rng);
                                }

                                let result = if concurrency > 1 {
                                    black_box(
                                        primitives::ops::threshold::batch_verify_same_message::<
                                            _,
                                            MinSig,
                                            _,
                                        >(
                                            &mut rng,
                                            &polynomial,
                                            namespace,
                                            msg,
                                            &signatures,
                                            &strategy,
                                        ),
                                    )
                                } else {
                                    black_box(
                                        primitives::ops::threshold::batch_verify_same_message::<
                                            _,
                                            MinSig,
                                            _,
                                        >(
                                            &mut rng,
                                            &polynomial,
                                            namespace,
                                            msg,
                                            &signatures,
                                            &Sequential,
                                        ),
                                    )
                                };
                                    if invalid == 0 {
                                        assert!(result.is_ok());
                                    } else {
                                        assert!(result.is_err());
                                    }
                                },
                                BatchSize::SmallInput,
                            );
                        },
                    );
                }
            }
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_threshold_batch_verify_same_message
}

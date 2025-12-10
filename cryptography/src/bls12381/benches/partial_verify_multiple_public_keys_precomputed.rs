use commonware_cryptography::{
    bls12381::{
        dkg::deal,
        primitives::{self, variant::MinSig},
    },
    ed25519::PrivateKey,
    PrivateKeyExt as _, Signer as _,
};
use commonware_utils::{quorum, TryCollect};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::hint::black_box;

fn benchmark_partial_verify_multiple_public_keys_precomputed(c: &mut Criterion) {
    let namespace = b"benchmark";
    let msg = b"hello";
    for &n in &[5, 10, 20, 50, 100, 250, 500] {
        let t = quorum(n);
        let f = n - t;
        for invalid in [0, f] {
            c.bench_function(
                &format!("{}/n={} t={} invalid={}", module_path!(), n, t, invalid),
                |b| {
                    b.iter_batched(
                        || {
                            let mut rng = StdRng::seed_from_u64(0);
                            let players = (0..n)
                                .map(|i| PrivateKey::from_seed(i as u64).public_key())
                                .try_collect()
                                .unwrap();
                            let (output, shares) =
                                deal::<MinSig, _>(&mut rng, players).expect("deal should succeed");
                            let polynomial = output.public().evaluate_all(n);
                            let signatures = shares
                                .values()
                                .iter()
                                .enumerate()
                                .map(|(idx, s)| {
                                    if idx < invalid as usize {
                                        primitives::ops::partial_sign_message::<MinSig>(
                                            s, None, msg,
                                        )
                                    } else {
                                        primitives::ops::partial_sign_message::<MinSig>(
                                            s,
                                            Some(namespace),
                                            msg,
                                        )
                                    }
                                })
                                .collect::<Vec<_>>();
                            (rng, polynomial, signatures)
                        },
                        |(mut rng, polynomial, mut signatures): (_, _, Vec<_>)| {
                            // Shuffle faults
                            if invalid > 0 {
                                signatures.shuffle(&mut rng);
                            }

                            // Verify
                            let result = black_box(
                                primitives::ops::partial_verify_multiple_public_keys_precomputed::<
                                    MinSig,
                                    _,
                                >(
                                    &polynomial, Some(namespace), msg, &signatures
                                ),
                            );
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

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_partial_verify_multiple_public_keys_precomputed
}

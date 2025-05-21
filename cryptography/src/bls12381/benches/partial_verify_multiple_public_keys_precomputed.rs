use commonware_cryptography::bls12381::{
    dkg,
    primitives::{self, variant::MinSig},
};
use commonware_utils::quorum;
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
                            let (polynomial, shares) =
                                dkg::ops::generate_shares::<_, MinSig>(&mut rng, None, n, t);
                            let keys = (0..n)
                                .map(|i| polynomial.evaluate(i).value)
                                .collect::<Vec<_>>();
                            let signatures = shares
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
                            (rng, keys, signatures)
                        },
                        |(mut rng, keys, mut signatures)| {
                            // Shuffle faults
                            if invalid > 0 {
                                signatures.shuffle(&mut rng);
                            }

                            // Prepare keys array
                            let mut ordered_keys = Vec::with_capacity(keys.len());
                            for signature in &signatures {
                                ordered_keys.push(keys[signature.index as usize]);
                            }

                            // Verify
                            let result = black_box(
                                primitives::ops::partial_verify_multiple_public_keys_precomputed::<
                                    MinSig,
                                    _,
                                >(
                                    &ordered_keys, Some(namespace), msg, &signatures
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

criterion_group!(
    benches,
    benchmark_partial_verify_multiple_public_keys_precomputed
);

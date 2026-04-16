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
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::hint::black_box;

fn bench_threshold_batch_verify_same_signer(c: &mut Criterion) {
    let namespace = b"benchmark";
    for mode in [Mode::NonZeroCounter, Mode::RootsOfUnity] {
        for &n in &[5, 10, 20, 50, 100, 250, 500] {
            let t = N3f1::quorum(n);
            for &msgs in &[10, 100] {
                for concurrency in [1, 8] {
                    let strategy = Rayon::new(NZUsize!(concurrency)).unwrap();
                    c.bench_function(
                        &format!(
                            "{}/n={} t={} msgs={} conc={} mode={:?}",
                            module_path!(),
                            n,
                            t,
                            msgs,
                            concurrency,
                            mode
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
                                    let signer = &shares.values()[0];
                                    let index = signer.index;
                                    let entries: Vec<_> = (0..msgs)
                                        .map(|_| {
                                            let mut msg = [0u8; 32];
                                            rng.fill(&mut msg);
                                            let sig =
                                                primitives::ops::threshold::sign_message::<MinSig>(
                                                    signer, namespace, &msg,
                                                );
                                            (namespace.to_vec(), msg.to_vec(), sig)
                                        })
                                        .collect();
                                    (rng, output.public().clone(), index, entries)
                                },
                                |(mut rng, polynomial, index, entries)| {
                                    let refs: Vec<_> = entries
                                        .iter()
                                        .map(|(ns, msg, sig)| {
                                            (ns.as_slice(), msg.as_slice(), sig.clone())
                                        })
                                        .collect();
                                    let result = if concurrency > 1 {
                                        black_box(
                                            primitives::ops::threshold::batch_verify_same_signer::<
                                                _,
                                                MinSig,
                                                _,
                                            >(
                                                &mut rng, &polynomial, index, &refs, &strategy
                                            ),
                                        )
                                    } else {
                                        black_box(
                                            primitives::ops::threshold::batch_verify_same_signer::<
                                                _,
                                                MinSig,
                                                _,
                                            >(
                                                &mut rng, &polynomial, index, &refs, &Sequential
                                            ),
                                        )
                                    };
                                    assert!(result.is_ok());
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
    targets = bench_threshold_batch_verify_same_signer
}

use commonware_cryptography::bls12381::primitives::{ops, variant::MinSig};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::NZUsize;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};

fn bench_batch_verify_same_signer(c: &mut Criterion) {
    let namespace = b"namespace";
    for n in [2, 10, 100, 1000, 10000].into_iter() {
        let mut msgs: Vec<[u8; 32]> = Vec::with_capacity(n);
        for _ in 0..n {
            let mut msg = [0u8; 32];
            thread_rng().fill(&mut msg);
            msgs.push(msg);
        }
        for concurrency in [1, 8] {
            let strategy = Rayon::new(NZUsize!(concurrency)).unwrap();
            c.bench_function(
                &format!("{}/conc={} msgs={}", module_path!(), concurrency, n),
                |b| {
                    b.iter_batched(
                        || {
                            let (private, public) = ops::keypair::<_, MinSig>(&mut thread_rng());
                            let entries: Vec<_> = msgs
                                .iter()
                                .map(|msg| {
                                    let sig = ops::sign_message::<MinSig>(&private, namespace, msg);
                                    (namespace.as_ref(), msg.as_ref(), sig)
                                })
                                .collect();
                            (public, entries)
                        },
                        |(public, entries)| {
                            if concurrency > 1 {
                                ops::batch::verify_same_signer::<_, MinSig, _>(
                                    &mut thread_rng(),
                                    &public,
                                    &entries,
                                    &strategy,
                                )
                                .unwrap();
                            } else {
                                ops::batch::verify_same_signer::<_, MinSig, _>(
                                    &mut thread_rng(),
                                    &public,
                                    &entries,
                                    &Sequential,
                                )
                                .unwrap();
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
    targets = bench_batch_verify_same_signer
}

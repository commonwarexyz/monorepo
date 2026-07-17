use commonware_cryptography::bls12381::primitives::{ops, variant::MinSig};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZUsize, test_rng};
use criterion::{BatchSize, Criterion, criterion_group};
use rand::RngExt as _;

fn bench_aggregate_verify_same_signer(c: &mut Criterion) {
    let mut rng = test_rng();
    let namespace = b"namespace";
    for n in [2, 10, 100, 1000, 10000].into_iter() {
        let mut msgs = Vec::with_capacity(n);
        for _ in 0..n {
            let mut msg = [0u8; 32];
            rng.fill(&mut msg);
            msgs.push(msg);
        }
        for concurrency in [1, 8].into_iter() {
            let rayon = (concurrency > 1).then(|| Rayon::new(NZUsize!(concurrency)).unwrap());
            c.bench_function(
                &format!("{}/conc={} msgs={}", module_path!(), concurrency, n),
                |b| {
                    b.iter_batched(
                        || {
                            let (private, public) = ops::keypair::<_, MinSig>(&mut rng);
                            let sigs: Vec<_> = msgs
                                .iter()
                                .map(|msg| ops::sign_message::<MinSig>(&private, namespace, msg))
                                .collect();
                            let agg_sig = ops::aggregate::combine_signatures::<MinSig, _>(&sigs);
                            let messages: Vec<_> = msgs
                                .iter()
                                .map(|msg| (namespace.as_ref(), msg.as_ref()))
                                .collect();
                            (public, messages, agg_sig)
                        },
                        |(public, messages, agg_sig)| {
                            #[allow(clippy::option_if_let_else)]
                            let combined_msg = if let Some(rayon) = rayon.as_ref() {
                                ops::aggregate::combine_messages::<MinSig, _>(&messages, rayon)
                            } else {
                                ops::aggregate::combine_messages::<MinSig, _>(
                                    &messages,
                                    &Sequential,
                                )
                            };
                            ops::aggregate::verify_same_signer::<MinSig>(
                                &public,
                                &combined_msg,
                                &agg_sig,
                            )
                            .unwrap();
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
    targets = bench_aggregate_verify_same_signer
}

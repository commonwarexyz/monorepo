use commonware_cryptography::bls12381::primitives::{ops, variant::MinSig};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};

fn benchmark_aggregate_verify_messages(c: &mut Criterion) {
    let namespace = b"namespace";
    for n in [2, 10, 100, 1000, 10000].into_iter() {
        let mut msgs = Vec::with_capacity(n);
        for _ in 0..n {
            let mut msg = [0u8; 32];
            thread_rng().fill(&mut msg);
            msgs.push(msg);
        }
        for concurrency in [1, 8].into_iter() {
            c.bench_function(
                &format!("{}/conc={} msgs={}", module_path!(), concurrency, n),
                |b| {
                    b.iter_batched(
                        || {
                            let (private, public) = ops::keypair::<_, MinSig>(&mut thread_rng());
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
                            let combined_msg = ops::aggregate::combine_messages::<MinSig, _>(
                                &messages,
                                concurrency,
                            );
                            ops::aggregate::verify_messages::<MinSig>(
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
    targets = benchmark_aggregate_verify_messages
}

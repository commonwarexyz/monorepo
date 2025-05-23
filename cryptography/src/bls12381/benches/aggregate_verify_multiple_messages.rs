use commonware_cryptography::bls12381::primitives::{ops, variant::MinSig};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};

fn benchmark_aggregate_verify_multiple_messages(c: &mut Criterion) {
    let namespace = b"namespace";
    for n in [2, 10, 100, 1000, 10000, 50000].into_iter() {
        let mut msgs = Vec::with_capacity(n);
        for _ in 0..n {
            let mut msg = [0u8; 32];
            thread_rng().fill(&mut msg);
            msgs.push(msg);
        }
        let msgs = msgs
            .iter()
            .map(|msg| (Some(&namespace[..]), msg.as_ref()))
            .collect::<Vec<_>>();
        for concurrency in [1, 2, 4, 8].into_iter() {
            c.bench_function(
                &format!("{}/conc={} msgs={}", module_path!(), concurrency, n,),
                |b| {
                    b.iter_batched(
                        || {
                            let (private, public) = ops::keypair::<_, MinSig>(&mut thread_rng());
                            let mut signatures = Vec::with_capacity(n);
                            for (namespace, msg) in msgs.iter() {
                                let signature =
                                    ops::sign_message::<MinSig>(&private, *namespace, msg);
                                signatures.push(signature);
                            }
                            (public, ops::aggregate_signatures::<MinSig, _>(&signatures))
                        },
                        |(public, signature)| {
                            ops::aggregate_verify_multiple_messages::<MinSig, _>(
                                &public,
                                &msgs,
                                &signature,
                                concurrency,
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
    targets = benchmark_aggregate_verify_multiple_messages
}

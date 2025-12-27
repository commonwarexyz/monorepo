use commonware_cryptography::bls12381::primitives::{ops, variant::MinSig};
use commonware_parallel::{Parallel, Sequential};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};
use rayon::ThreadPoolBuilder;
use std::sync::Arc;

fn benchmark_aggregate_verify_multiple_messages(c: &mut Criterion) {
    let namespace = b"namespace";
    for n in [2, 10, 100, 1000, 10000].into_iter() {
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
        for concurrency in [1, 8].into_iter() {
            let pool = Arc::new(
                ThreadPoolBuilder::new()
                    .num_threads(concurrency)
                    .build()
                    .unwrap(),
            );
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
                            if concurrency > 1 {
                                ops::aggregate_verify_multiple_messages::<MinSig, _, _>(
                                    &public,
                                    &msgs,
                                    &signature,
                                    &Parallel::new(pool.clone()),
                                )
                                .unwrap();
                            } else {
                                ops::aggregate_verify_multiple_messages::<MinSig, _, _>(
                                    &public,
                                    &msgs,
                                    &signature,
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
    targets = benchmark_aggregate_verify_multiple_messages
}

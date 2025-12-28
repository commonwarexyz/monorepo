use commonware_cryptography::bls12381::primitives::{ops, variant::MinSig};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};

fn benchmark_verify_multiple_messages(c: &mut Criterion) {
    let namespace = b"namespace";
    for n in [2, 10, 100, 1000, 10000].into_iter() {
        let mut msgs: Vec<[u8; 32]> = Vec::with_capacity(n);
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
                            let entries: Vec<_> = msgs
                                .iter()
                                .map(|msg| {
                                    let ns: Option<&[u8]> = Some(&namespace[..]);
                                    let sig = ops::sign_message::<MinSig>(&private, ns, msg);
                                    (ns, msg.as_ref(), sig)
                                })
                                .collect();
                            (public, entries)
                        },
                        |(public, entries)| {
                            ops::verify_multiple_messages::<_, MinSig, _>(
                                &mut thread_rng(),
                                &public,
                                &entries,
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
    targets = benchmark_verify_multiple_messages
}

use commonware_cryptography::bls12381::primitives::{ops, variant::MinSig};
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_utils::NZUsize;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};

fn bench_with_strategy<S: Strategy>(
    c: &mut Criterion,
    name: &str,
    strategy: &S,
    n: usize,
    msgs: &[[u8; 32]],
) {
    let namespace = b"namespace";
    c.bench_function(
        &format!("{}/strategy={} msgs={}", module_path!(), name, n),
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
                    let combined_msg =
                        ops::aggregate::combine_messages::<MinSig, _>(&messages, strategy);
                    ops::aggregate::verify_same_signer::<MinSig>(&public, &combined_msg, &agg_sig)
                        .unwrap();
                },
                BatchSize::SmallInput,
            );
        },
    );
}

fn benchmark_aggregate_verify_same_signer(c: &mut Criterion) {
    for n in [2, 10, 100, 1000, 10000].into_iter() {
        let mut msgs = Vec::with_capacity(n);
        for _ in 0..n {
            let mut msg = [0u8; 32];
            thread_rng().fill(&mut msg);
            msgs.push(msg);
        }

        bench_with_strategy(c, "seq", &Sequential, n, &msgs);
        let parallel = Rayon::new(NZUsize!(8)).unwrap();
        bench_with_strategy(c, "par", &parallel, n, &msgs);
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_aggregate_verify_same_signer
}

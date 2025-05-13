use commonware_cryptography::bls12381::primitives::{ops, variant::MinSig};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};

fn benchmark_aggregate_verify_multiple_public_keys(c: &mut Criterion) {
    let namespace = b"namespace";
    let mut msg = [0u8; 32];
    thread_rng().fill(&mut msg);
    for n in [10, 100, 1000, 10000].into_iter() {
        c.bench_function(&format!("{}/pks={}", module_path!(), n), |b| {
            b.iter_batched(
                || {
                    let mut public_keys = Vec::with_capacity(n);
                    let mut signatures = Vec::with_capacity(n);
                    for _ in 0..n {
                        let (private, public) = ops::keypair::<_, MinSig>(&mut thread_rng());
                        let signature =
                            ops::sign_message::<MinSig>(&private, Some(namespace), &msg);
                        public_keys.push(public);
                        signatures.push(signature);
                    }
                    (
                        public_keys,
                        ops::aggregate_signatures::<MinSig, _>(&signatures),
                    )
                },
                |(public_keys, signature)| {
                    ops::aggregate_verify_multiple_public_keys::<MinSig, _>(
                        &public_keys,
                        Some(namespace),
                        &msg,
                        &signature,
                    )
                    .unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_aggregate_verify_multiple_public_keys
}

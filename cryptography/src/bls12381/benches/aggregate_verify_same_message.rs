use commonware_cryptography::bls12381::primitives::{ops, variant::MinSig};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};

fn bench_aggregate_verify_same_message(c: &mut Criterion) {
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
                        let signature = ops::sign_message::<MinSig>(&private, namespace, &msg);
                        public_keys.push(public);
                        signatures.push(signature);
                    }
                    (
                        public_keys,
                        ops::aggregate::combine_signatures::<MinSig, _>(&signatures),
                    )
                },
                |(public_keys, signature)| {
                    let public = ops::aggregate::combine_public_keys::<MinSig, _>(&public_keys);
                    ops::aggregate::verify_same_message::<MinSig>(
                        &public, namespace, &msg, &signature,
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
    targets = bench_aggregate_verify_same_message
}

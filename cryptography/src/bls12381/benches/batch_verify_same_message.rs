use commonware_cryptography::bls12381::primitives::{
    self, ops,
    variant::{MinSig, Variant},
};
use commonware_parallel::Sequential;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::hint::black_box;

fn benchmark_batch_verify_same_message(c: &mut Criterion) {
    let namespace = b"benchmark";
    let msg = b"hello";

    for n in [10, 50, 100, 200] {
        c.bench_function(&format!("{}/n={}", module_path!(), n), |b| {
            b.iter_batched(
                || {
                    let mut rng = StdRng::seed_from_u64(0);
                    let mut publics = Vec::with_capacity(n);
                    let mut signatures = Vec::with_capacity(n);

                    for _ in 0..n {
                        let (private, public) = ops::keypair::<_, MinSig>(&mut rng);
                        let sig = ops::sign_message::<MinSig>(&private, namespace, msg);
                        publics.push(public);
                        signatures.push(sig);
                    }

                    let hm = primitives::ops::hash_with_namespace::<MinSig>(
                        MinSig::MESSAGE,
                        namespace,
                        msg,
                    );
                    let hms = vec![hm; n];

                    (rng, publics, hms, signatures)
                },
                |(mut rng, publics, hms, signatures)| {
                    black_box(
                        MinSig::batch_verify(&mut rng, &publics, &hms, &signatures, &Sequential)
                            .unwrap(),
                    );
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_batch_verify_same_message
}

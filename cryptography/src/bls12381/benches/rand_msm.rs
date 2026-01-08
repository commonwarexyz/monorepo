use commonware_cryptography::bls12381::primitives::{
    self,
    group::{Scalar, G1, G2},
    variant::{MinSig, Variant},
};
use commonware_parallel::Sequential;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::hint::black_box;

fn benchmark_rand_msm(c: &mut Criterion) {
    let namespace = b"ns";
    let msg = b"msg";

    for n in [10, 50, 100, 200] {
        c.bench_function(&format!("{}/n={}", module_path!(), n), |b| {
            b.iter_batched(
                || {
                    let mut rng = StdRng::seed_from_u64(0);
                    let hm = primitives::ops::hash_with_namespace::<MinSig>(
                        MinSig::MESSAGE,
                        namespace,
                        msg,
                    );
                    let (publics, sigs): (Vec<G2>, Vec<G1>) = (0..n)
                        .map(|_| {
                            let (private, public) = primitives::ops::keypair::<_, MinSig>(&mut rng);
                            let sig =
                                primitives::ops::sign_message::<MinSig>(&private, namespace, msg);
                            (public, sig)
                        })
                        .unzip();
                    let scalars: Vec<Scalar> =
                        (0..n).map(|_| Scalar::random_batch(&mut rng)).collect();
                    (publics, hm, sigs, scalars)
                },
                |(publics, hm, sigs, scalars)| {
                    black_box(MinSig::verify_same_message_msm(
                        &publics,
                        &hm,
                        &sigs,
                        &scalars,
                        &Sequential,
                    ))
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_rand_msm
}

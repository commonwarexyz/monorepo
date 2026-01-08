use commonware_cryptography::bls12381::primitives::{
    self,
    group::{G1, G2},
    variant::{MinSig, Variant},
};
use commonware_math::algebra::Space;
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
                    (StdRng::seed_from_u64(0), publics, hm, sigs)
                },
                |(mut rng, publics, hm, sigs)| {
                    let (pk_agg, scalars) = G2::rand_msm(&mut rng, &publics, &Sequential);
                    let sig_agg = G1::msm(&sigs, &scalars, &Sequential);
                    black_box(MinSig::verify(&pk_agg, &hm, &sig_agg))
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

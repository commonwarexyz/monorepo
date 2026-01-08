use commonware_cryptography::bls12381::primitives::{
    self,
    variant::{MinSig, Variant},
};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::hint::black_box;

fn benchmark_pairing_verify(c: &mut Criterion) {
    c.bench_function(module_path!(), |b| {
        b.iter_batched(
            || {
                let mut rng = StdRng::seed_from_u64(0);
                let (private, public) = primitives::ops::keypair::<_, MinSig>(&mut rng);
                let sig = primitives::ops::sign_message::<MinSig>(&private, b"ns", b"msg");
                let hm =
                    primitives::ops::hash_with_namespace::<MinSig>(MinSig::MESSAGE, b"ns", b"msg");
                (public, hm, sig)
            },
            |(public, hm, sig)| {
                black_box(MinSig::verify)(&public, &hm, &sig).unwrap();
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_pairing_verify
}

use commonware_cryptography::bls12381::primitives::{
    self,
    group::{Scalar, G1, G2},
    variant::{MinSig, Variant},
};
use commonware_math::algebra::{CryptoGroup, Random, Space};
use commonware_parallel::Sequential;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::hint::black_box;

fn benchmark_components(c: &mut Criterion) {
    let n = 100;

    // Benchmark scalar generation
    c.bench_function("bls12381::components/scalar_gen_100", |b| {
        b.iter_batched(
            || StdRng::seed_from_u64(0),
            |mut rng| {
                let scalars: Vec<Scalar> =
                    black_box((0..n).map(|_| Scalar::random(&mut rng)).collect());
                scalars
            },
            BatchSize::SmallInput,
        );
    });

    // Benchmark batch_to_affine for G1 (signatures for MinSig)
    c.bench_function("bls12381::components/batch_to_affine_g1_100", |b| {
        b.iter_batched(
            || {
                let mut rng = StdRng::seed_from_u64(0);
                (0..n)
                    .map(|_| G1::generator() * &Scalar::random(&mut rng))
                    .collect::<Vec<_>>()
            },
            |points| black_box(G1::batch_to_affine(&points)),
            BatchSize::SmallInput,
        );
    });

    // Benchmark batch_to_affine for G2 (public keys for MinSig)
    c.bench_function("bls12381::components/batch_to_affine_g2_100", |b| {
        b.iter_batched(
            || {
                let mut rng = StdRng::seed_from_u64(0);
                (0..n)
                    .map(|_| G2::generator() * &Scalar::random(&mut rng))
                    .collect::<Vec<_>>()
            },
            |points| black_box(G2::batch_to_affine(&points)),
            BatchSize::SmallInput,
        );
    });

    // Benchmark MSM for G1 (100 points)
    c.bench_function("bls12381::components/msm_g1_100", |b| {
        b.iter_batched(
            || {
                let mut rng = StdRng::seed_from_u64(0);
                let points: Vec<G1> = (0..n)
                    .map(|_| G1::generator() * &Scalar::random(&mut rng))
                    .collect();
                let scalars: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
                (points, scalars)
            },
            |(points, scalars)| black_box(G1::msm(&points, &scalars, &Sequential)),
            BatchSize::SmallInput,
        );
    });

    // Benchmark MSM for G2 (100 points)
    c.bench_function("bls12381::components/msm_g2_100", |b| {
        b.iter_batched(
            || {
                let mut rng = StdRng::seed_from_u64(0);
                let points: Vec<G2> = (0..n)
                    .map(|_| G2::generator() * &Scalar::random(&mut rng))
                    .collect();
                let scalars: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
                (points, scalars)
            },
            |(points, scalars)| black_box(G2::msm(&points, &scalars, &Sequential)),
            BatchSize::SmallInput,
        );
    });

    // Benchmark msm_affine for G1 (100 points)
    c.bench_function("bls12381::components/msm_affine_g1_100", |b| {
        b.iter_batched(
            || {
                let mut rng = StdRng::seed_from_u64(0);
                let points: Vec<G1> = (0..n)
                    .map(|_| G1::generator() * &Scalar::random(&mut rng))
                    .collect();
                let affine = G1::batch_to_affine(&points);
                let scalars: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
                (affine, scalars)
            },
            |(affine, scalars)| black_box(G1::msm_affine(&affine, &scalars)),
            BatchSize::SmallInput,
        );
    });

    // Benchmark msm_affine for G2 (100 points)
    c.bench_function("bls12381::components/msm_affine_g2_100", |b| {
        b.iter_batched(
            || {
                let mut rng = StdRng::seed_from_u64(0);
                let points: Vec<G2> = (0..n)
                    .map(|_| G2::generator() * &Scalar::random(&mut rng))
                    .collect();
                let affine = G2::batch_to_affine(&points);
                let scalars: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
                (affine, scalars)
            },
            |(affine, scalars)| black_box(G2::msm_affine(&affine, &scalars)),
            BatchSize::SmallInput,
        );
    });

    // Benchmark single pairing verification
    c.bench_function("bls12381::components/pairing_verify", |b| {
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

    // Benchmark full verify_same_message_msm for comparison
    c.bench_function("bls12381::components/verify_same_message_msm_100", |b| {
        b.iter_batched(
            || {
                let mut rng = StdRng::seed_from_u64(0);
                let namespace = b"ns";
                let msg = b"msg";
                let hm =
                    primitives::ops::hash_with_namespace::<MinSig>(MinSig::MESSAGE, namespace, msg);
                let (publics, sigs): (Vec<G2>, Vec<G1>) = (0..n)
                    .map(|_| {
                        let (private, public) = primitives::ops::keypair::<_, MinSig>(&mut rng);
                        let sig = primitives::ops::sign_message::<MinSig>(&private, namespace, msg);
                        (public, sig)
                    })
                    .unzip();
                let scalars: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
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

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_components
}

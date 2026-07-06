use commonware_cryptography::{
    bls12381::primitives::group::{Scalar, G1},
    transcript::Transcript,
    zk::bulletproofs::ipa::{self, Proof, Setup, Witness},
};
use commonware_math::algebra::{CryptoGroup, Random};
use commonware_parallel::{Rayon, Sequential};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::{hint::black_box, num::NonZeroUsize};

fn make_setup(len: usize) -> Setup<G1> {
    let generators: Vec<_> = (0..(2 * len + 1))
        .map(|i| G1::generator() * &Scalar::from(i as u64 + 1))
        .collect();
    Setup::new(
        generators[0],
        generators[1..]
            .chunks_exact(2)
            .map(|chunk| (chunk[0], chunk[1])),
    )
}

fn make_elements(rng: &mut StdRng, len: usize) -> Vec<(Scalar, Scalar)> {
    let mut elements = Vec::with_capacity(len);
    for _ in 0..len {
        elements.push((Scalar::random(&mut *rng), Scalar::random(&mut *rng)));
    }
    elements
}

fn make_proof(setup: &Setup<G1>, len: usize) -> (ipa::Claim<Scalar, G1>, Proof<Scalar, G1>) {
    let mut rng = StdRng::seed_from_u64(0);
    let y = Scalar::random(&mut rng);
    let (witness, claim) =
        Witness::new_with_claim(setup, y, make_elements(&mut rng, len)).expect("valid witness");
    let mut transcript = Transcript::new(b"ipa-bench");
    transcript.commit(&b"context"[..]);
    let proof = ipa::prove(&mut transcript, setup, &claim, witness, &Sequential)
        .expect("proof should succeed");
    (claim, proof)
}

fn bench_prove(c: &mut Criterion) {
    let par = Rayon::new(NonZeroUsize::new(8).unwrap()).unwrap();

    for len in [8usize, 16, 32, 64, 128] {
        let setup = make_setup(len);
        c.bench_function(&format!("{}::prove/n={len} conc=1", module_path!()), |b| {
            b.iter_batched(
                || {
                    let mut rng = StdRng::seed_from_u64(0);
                    let y = Scalar::random(&mut rng);
                    let elements = make_elements(&mut rng, len);
                    let (witness, claim) =
                        Witness::new_with_claim(&setup, y, elements).expect("valid witness");
                    (claim, witness)
                },
                |(claim, witness)| {
                    let mut transcript = Transcript::new(b"ipa-bench");
                    transcript.commit(&b"context"[..]);
                    black_box(ipa::prove(
                        &mut transcript,
                        &setup,
                        &claim,
                        witness,
                        &Sequential,
                    ));
                },
                BatchSize::SmallInput,
            );
        });

        c.bench_function(&format!("{}::prove/n={len} conc=8", module_path!()), |b| {
            b.iter_batched(
                || {
                    let mut rng = StdRng::seed_from_u64(0);
                    let y = Scalar::random(&mut rng);
                    let elements = make_elements(&mut rng, len);
                    let (witness, claim) =
                        Witness::new_with_claim(&setup, y, elements).expect("valid witness");
                    (claim, witness)
                },
                |(claim, witness)| {
                    let mut transcript = Transcript::new(b"ipa-bench");
                    transcript.commit(&b"context"[..]);
                    black_box(ipa::prove(&mut transcript, &setup, &claim, witness, &par));
                },
                BatchSize::SmallInput,
            );
        });
    }
}

fn bench_verify(c: &mut Criterion) {
    let par = Rayon::new(NonZeroUsize::new(8).unwrap()).unwrap();

    for len in [8usize, 16, 32, 64, 128] {
        let setup = make_setup(len);
        c.bench_function(&format!("{}::verify/n={len} conc=1", module_path!()), |b| {
            b.iter_batched(
                || make_proof(&setup, len),
                |(claim, proof)| {
                    let mut transcript = Transcript::new(b"ipa-bench");
                    transcript.commit(&b"context"[..]);
                    black_box(setup.eval(
                        |vs| ipa::verify(&mut transcript, vs, &claim, proof),
                        &Sequential,
                    ));
                },
                BatchSize::SmallInput,
            );
        });

        c.bench_function(&format!("{}::verify/n={len} conc=8", module_path!()), |b| {
            b.iter_batched(
                || make_proof(&setup, len),
                |(claim, proof)| {
                    let mut transcript = Transcript::new(b"ipa-bench");
                    transcript.commit(&b"context"[..]);
                    black_box(
                        setup.eval(|vs| ipa::verify(&mut transcript, vs, &claim, proof), &par),
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
    targets = bench_prove, bench_verify
}

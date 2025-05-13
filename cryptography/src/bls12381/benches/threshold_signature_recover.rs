use commonware_cryptography::bls12381::{
    dkg,
    primitives::{self, variant::MinSig},
};
use commonware_utils::quorum;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::hint::black_box;

fn benchmark_threshold_signature_recover(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    let namespace = b"benchmark";
    let msg = b"hello";
    for &n in &[5, 10, 20, 50, 100, 250, 500] {
        let t = quorum(n);
        c.bench_function(&format!("{}/n={} t={}", module_path!(), n, t), |b| {
            b.iter_batched(
                || {
                    let (_, shares) = dkg::ops::generate_shares::<_, MinSig>(&mut rng, None, n, t);
                    shares
                        .iter()
                        .map(|s| {
                            primitives::ops::partial_sign_message::<MinSig>(s, Some(namespace), msg)
                        })
                        .collect::<Vec<_>>()
                },
                |partials| {
                    black_box(
                        primitives::ops::threshold_signature_recover::<MinSig, _>(t, &partials)
                            .unwrap(),
                    );
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, benchmark_threshold_signature_recover);

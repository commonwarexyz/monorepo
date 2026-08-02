use super::common::{Fixture, PARTICIPANTS, rayon};
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
};
use commonware_parallel::Sequential;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn register<V: Variant>(c: &mut Criterion, variant: &str) {
    let fixture = Fixture::<V>::new();
    let (vqc, lqc) = fixture.certificates();
    let rayon = rayon();

    for (strategy, parallel) in [("sequential", false), ("rayon", true)] {
        c.bench_function(
            &format!(
                "{}/variant={} certificate=vqc n={} strategy={}",
                module_path!(),
                variant,
                PARTICIPANTS,
                strategy,
            ),
            |b| {
                b.iter(|| {
                    let verified = if parallel {
                        fixture.verifier.verify_vqc::<Sha256, _>(&vqc, &rayon)
                    } else {
                        fixture.verifier.verify_vqc::<Sha256, _>(&vqc, &Sequential)
                    };
                    black_box(verified.unwrap())
                });
            },
        );
        c.bench_function(
            &format!(
                "{}/variant={} certificate=lqc n={} strategy={}",
                module_path!(),
                variant,
                PARTICIPANTS,
                strategy,
            ),
            |b| {
                b.iter(|| {
                    let verified = if parallel {
                        fixture.verifier.verify_lqc::<Sha256, _>(&lqc, &rayon)
                    } else {
                        fixture.verifier.verify_lqc::<Sha256, _>(&lqc, &Sequential)
                    };
                    black_box(verified.unwrap())
                });
            },
        );
    }
}

fn bench_aggregate(c: &mut Criterion) {
    register::<MinPk>(c, "minpk");
    register::<MinSig>(c, "minsig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_aggregate
}

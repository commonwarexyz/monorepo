use super::common::{Fixture, PARTICIPANTS, rayon};
use commonware_consensus::multimmit::scheme::Unverified;
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
};
use commonware_parallel::Sequential;
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn register<V: Variant>(c: &mut Criterion, variant: &str) {
    let fixture = Fixture::<V>::new();
    let blocks = fixture.ordinary_blocks();
    let artifacts = blocks
        .iter()
        .map(Unverified::TransactionBlock)
        .collect::<Vec<_>>();
    let rayon = rayon();

    for (strategy, parallel) in [("sequential", false), ("rayon", true)] {
        c.bench_function(
            &format!(
                "{}/variant={} n={} strategy={}",
                module_path!(),
                variant,
                PARTICIPANTS,
                strategy,
            ),
            |b| {
                b.iter(|| {
                    let verdicts = if parallel {
                        fixture.verifier.verify_artifacts::<_, Sha256, _>(
                            &mut test_rng(),
                            &artifacts,
                            &rayon,
                        )
                    } else {
                        fixture.verifier.verify_artifacts::<_, Sha256, _>(
                            &mut test_rng(),
                            &artifacts,
                            &Sequential,
                        )
                    };
                    black_box(verdicts)
                });
            },
        );
    }
}

fn bench_ordinary(c: &mut Criterion) {
    register::<MinPk>(c, "minpk");
    register::<MinSig>(c, "minsig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_ordinary
}

use super::admission_fixtures::{FAULTS, QUORUM, VALIDATORS, certificate_fixture};
use commonware_parallel::Sequential;
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_verify_certificate(c: &mut Criterion) {
    let fixture = certificate_fixture();
    let mut rng = test_rng();
    c.bench_function(
        &format!("{}/n={VALIDATORS} f={FAULTS} q={QUORUM}", module_path!()),
        |b| {
            b.iter(|| {
                let verified = fixture.verifier.verify_exact(
                    black_box(&mut rng),
                    black_box(&fixture.header),
                    black_box(&fixture.certificate),
                    &Sequential,
                );
                assert!(verified, "benchmark certificate remains valid");
                black_box(verified)
            });
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_verify_certificate,
}

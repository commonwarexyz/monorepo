use super::admission_fixtures::{FAULTS, QUORUM, VALIDATORS, certificate_fixture};
use criterion::{BatchSize, Criterion, criterion_group};
use std::hint::black_box;

fn bench_assemble_certificate(c: &mut Criterion) {
    let fixture = certificate_fixture();
    c.bench_function(
        &format!("{}/n={VALIDATORS} f={FAULTS} q={QUORUM}", module_path!()),
        |b| {
            b.iter_batched(
                || fixture.attestations.clone(),
                |attestations| {
                    black_box(
                        fixture
                            .assembler
                            .assemble_exact(black_box(attestations))
                            .expect("benchmark attestations form an exact certificate"),
                    )
                },
                BatchSize::SmallInput,
            );
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_assemble_certificate,
}

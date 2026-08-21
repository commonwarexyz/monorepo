use super::fixtures::{SPARSE_PROFILES, sparse_fixture};
use commonware_clearing::bajillion::commitment::VectorKind;
use commonware_cryptography::Sha256;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_verify_sparse_update(c: &mut Criterion) {
    for &(registry, changed) in SPARSE_PROFILES {
        let fixture = sparse_fixture(registry, changed);
        c.bench_function(
            &format!(
                "{}/registry={registry} changed={changed} value_size=64",
                module_path!()
            ),
            |b| {
                b.iter(|| {
                    black_box(&fixture.update)
                        .verify::<Sha256, _, _>(
                            VectorKind::State,
                            black_box(&fixture.opening_root),
                            black_box(&fixture.closing_root),
                            black_box(&fixture.opening_values),
                            black_box(&fixture.closing_values),
                        )
                        .expect("benchmark sparse update is valid");
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_verify_sparse_update,
}

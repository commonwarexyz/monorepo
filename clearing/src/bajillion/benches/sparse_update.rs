use super::fixtures::{SPARSE_PROFILES, sparse_fixture};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_sparse_update(c: &mut Criterion) {
    for &(registry, changed) in SPARSE_PROFILES {
        let fixture = sparse_fixture(registry, changed);
        c.bench_function(
            &format!(
                "{}/registry={registry} changed={changed} value_size=64",
                module_path!()
            ),
            |b| {
                b.iter(|| {
                    black_box(
                        black_box(&fixture.tree)
                            .sparse_update(black_box(&fixture.positions))
                            .expect("benchmark sparse positions are valid"),
                    )
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_sparse_update,
}

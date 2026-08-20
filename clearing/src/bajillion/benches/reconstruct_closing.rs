use super::fixtures::{SPARSE_PROFILES, sparse_fixture};
use commonware_cryptography::Sha256;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_reconstruct_closing(c: &mut Criterion) {
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
                        black_box(&fixture.update)
                            .reconstruct_closing::<Sha256, _>(black_box(&fixture.closing_values))
                            .expect("benchmark closing values are valid"),
                    )
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_reconstruct_closing,
}

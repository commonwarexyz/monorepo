use super::range_update_fixtures::{Fixture, UPDATE_PROFILES, WORKERS, strategy};
use commonware_cryptography::Sha256;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_update(c: &mut Criterion) {
    let strategy = strategy();
    for &profile in UPDATE_PROFILES {
        let fixture = Fixture::new(profile);
        c.bench_function(
            &format!(
                "{}/shape={} n={} changes={} workers={WORKERS}",
                module_path!(),
                profile.shape,
                profile.leaves,
                profile.changes,
            ),
            |b| {
                b.iter(|| {
                    let update = fixture
                        .tree
                        .update_with_strategy::<Sha256>(
                            black_box(&fixture.changes),
                            black_box(&strategy),
                        )
                        .expect("benchmark update is valid");
                    black_box(update)
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_update,
}

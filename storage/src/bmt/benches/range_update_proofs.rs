use super::range_update_fixtures::{Fixture, RANGE_PROFILES, WORKERS, strategy};
use commonware_cryptography::Sha256;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_range_update_proofs(c: &mut Criterion) {
    let strategy = strategy();
    for &profile in RANGE_PROFILES {
        let fixture = Fixture::new(profile);
        let update = fixture
            .tree
            .update_with_strategy::<Sha256>(&fixture.changes, &strategy)
            .expect("benchmark update is valid");
        c.bench_function(
            &format!(
                "{}/shape={} n={} changes={} ranges={} workers={WORKERS}",
                module_path!(),
                profile.shape,
                profile.leaves,
                profile.changes,
                profile.ranges,
            ),
            |b| {
                b.iter(|| {
                    let proofs = fixture
                        .tree
                        .range_update_proofs_with_strategy(
                            black_box(&update),
                            black_box(&fixture.boundaries),
                            black_box(&strategy),
                        )
                        .expect("benchmark boundaries are valid");
                    black_box(proofs)
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_range_update_proofs,
}

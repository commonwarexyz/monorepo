use super::range_update_fixtures::{Fixture, RANGE_PROFILES, strategy};
use commonware_cryptography::Sha256;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_verify_range_update(c: &mut Criterion) {
    let strategy = strategy();
    for &profile in RANGE_PROFILES {
        let fixture = Fixture::new(profile);
        let opening_root = fixture.tree.root();
        let update = fixture
            .tree
            .update_with_strategy::<Sha256>(&fixture.changes, &strategy)
            .expect("benchmark update is valid");
        let closing_root = update.root();
        let proofs = fixture
            .tree
            .range_update_proofs_with_strategy(&update, &fixture.boundaries, &strategy)
            .expect("benchmark boundaries are valid");
        assert_eq!(proofs.len(), fixture.disclosures.len());

        c.bench_function(
            &format!(
                "{}/shape={} n={} changes={} ranges={}",
                module_path!(),
                profile.shape,
                profile.leaves,
                profile.changes,
                profile.ranges,
            ),
            |b| {
                b.iter(|| {
                    for (proof, disclosure) in proofs.iter().zip(&fixture.disclosures) {
                        black_box(proof)
                            .verify::<Sha256>(
                                disclosure.range.clone(),
                                black_box(&disclosure.positions),
                                black_box(&disclosure.opening),
                                black_box(&disclosure.closing),
                                black_box(&opening_root),
                                black_box(&closing_root),
                            )
                            .expect("benchmark proof verifies");
                    }
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_verify_range_update,
}

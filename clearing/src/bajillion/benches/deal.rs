use super::fixtures::{
    WORKERS, active_close_fixture, profile_key, selected_active_profiles, strategy,
};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_deal(c: &mut Criterion) {
    for (_, profile) in selected_active_profiles() {
        let fixture = active_close_fixture(profile);
        c.bench_function(
            &format!(
                "{}/{} E={} workers={WORKERS}",
                module_path!(),
                profile_key(profile),
                profile.edges(),
            ),
            |b| {
                b.iter(|| {
                    black_box(
                        fixture
                            .prepared
                            .assemble_slices(&fixture.cache, strategy())
                            .expect("benchmark dealing is valid"),
                    )
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_deal,
}

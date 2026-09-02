use super::{
    admission_fixtures::{VALIDATORS, Validators},
    fixtures::{
        WORKERS, active_close_fixture_with_assignment, profile_key, selected_active_profiles,
        strategy,
    },
};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

/// Deals every distinct span the committee is assigned: the operator's assembly cost per
/// close, since each validator's dealing is one proof slice per span.
fn bench_deal(c: &mut Criterion) {
    let validators = Validators::new();
    for (_, profile) in selected_active_profiles() {
        let fixture = active_close_fixture_with_assignment(profile, validators.assignment());
        let spans = validators.distinct_spans(fixture.context.assignment());
        c.bench_function(
            &format!(
                "{}/{} E={} n={VALIDATORS} spans={} workers={WORKERS}",
                module_path!(),
                profile_key(profile),
                profile.edges(),
                spans.len(),
            ),
            |b| {
                b.iter(|| {
                    black_box(
                        fixture
                            .prepared
                            .assemble_slices(&fixture.cache, &spans, strategy())
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

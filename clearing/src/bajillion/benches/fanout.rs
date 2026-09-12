use super::{
    admission_fixtures::VALIDATORS,
    fixtures::{active_close_fixture, profile_key, selected_active_profiles},
};
use commonware_runtime::Runner as _;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_fanout(c: &mut Criterion) {
    for (_, profile) in selected_active_profiles() {
        let encoded = super::fixtures::runner().start(|runtime| async move {
            active_close_fixture(runtime, profile)
                .await
                .prepared
                .encoded()
                .clone()
        });
        c.bench_function(
            &format!(
                "{}/{} validators={VALIDATORS}",
                module_path!(),
                profile_key(profile)
            ),
            |b| {
                b.iter(|| black_box((0..VALIDATORS).map(|_| encoded.clone()).collect::<Vec<_>>()));
            },
        );
    }
}
criterion_group! {name = benches; config = Criterion::default().sample_size(10); targets = bench_fanout,}

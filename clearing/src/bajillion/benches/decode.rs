use super::fixtures::{active_close_fixture, profile_key, selected_active_profiles};
use commonware_clearing::bajillion::posted;
use commonware_runtime::Runner as _;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_decode(c: &mut Criterion) {
    for (_, profile) in selected_active_profiles() {
        let (context, encoded) = super::fixtures::runner().start(|runtime| async move {
            let fixture = active_close_fixture(runtime, profile).await;
            (fixture.context, fixture.prepared.encoded().clone())
        });
        c.bench_function(
            &format!(
                "{}/{} E={}",
                module_path!(),
                profile_key(profile),
                profile.edges()
            ),
            |b| {
                b.iter(|| {
                    black_box(
                        posted::decode(encoded.clone(), &context).expect("bounded dealing decode"),
                    )
                });
            },
        );
    }
}
criterion_group! {name = benches; config = Criterion::default().sample_size(10); targets = bench_decode,}

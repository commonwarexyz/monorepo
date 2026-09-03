use super::fixtures::{
    active_close_fixture, kind_label, profile_key, proven_challenges, selected_active_profiles,
};
use commonware_clearing::bajillion::challenge::adjudicate;
use commonware_codec::EncodeSize;
use commonware_cryptography::Sha256;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_adjudicate(c: &mut Criterion) {
    for (_, profile) in selected_active_profiles() {
        let fixture = active_close_fixture(profile);
        let close = fixture.prepared.close();
        for (kind, challenge) in proven_challenges(&fixture) {
            eprintln!(
                "clearing challenge bytes: {} kind={} bytes={}",
                profile_key(profile),
                kind_label(kind),
                challenge.encode_size(),
            );
            c.bench_function(
                &format!(
                    "{}/{} kind={}",
                    module_path!(),
                    profile_key(profile),
                    kind_label(kind)
                ),
                |b| {
                    b.iter(|| {
                        black_box(
                            adjudicate::<Sha256, _, _>(
                                black_box(&fixture.context),
                                black_box(&close.header),
                                black_box(&close.roots),
                                black_box(&challenge),
                            )
                            .expect("benchmark challenge is valid"),
                        )
                    });
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_adjudicate,
}

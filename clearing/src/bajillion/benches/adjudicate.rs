use super::fixtures::{
    active_close_fixture, kind_label, profile_key, proven_challenges, selected_active_profiles,
};
use commonware_clearing::bajillion::challenge::{adjudicate, decode_bounded};
use commonware_codec::{Encode, EncodeSize};
use commonware_cryptography::Sha256;
use commonware_runtime::Runner as _;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench_adjudicate(c: &mut Criterion) {
    for (_, profile) in selected_active_profiles() {
        let (context, header, roots, amounts, challenges) =
            super::fixtures::runner().start(|runtime| async move {
                let fixture = active_close_fixture(runtime, profile).await;
                let close = fixture.prepared.close();
                (
                    fixture.context.clone(),
                    close.header,
                    close.roots,
                    close.amounts,
                    proven_challenges(&fixture),
                )
            });
        for (kind, challenge) in challenges {
            let encoded = challenge.encode();
            assert_eq!(encoded.len(), challenge.encode_size());
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
                        let challenge = decode_bounded(encoded.as_ref(), encoded.len())
                            .expect("bounded challenge decode");
                        black_box(
                            adjudicate::<Sha256, _, _>(
                                black_box(&context),
                                black_box(&header),
                                black_box(&roots),
                                black_box(&amounts),
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

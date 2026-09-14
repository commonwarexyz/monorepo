use super::fixtures::{active_close_fixture, profile_key, selected_active_profiles};
use commonware_clearing::bajillion::transition::prepare_dealing;
use commonware_cryptography::Sha256;
use commonware_runtime::Runner as _;
use criterion::{Criterion, criterion_group};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

fn bench_prepare(c: &mut Criterion) {
    for (_, profile) in selected_active_profiles() {
        c.bench_function(
            &format!(
                "{}/{} E={}",
                module_path!(),
                profile_key(profile),
                profile.edges()
            ),
            |b| {
                b.iter_custom(|iterations| {
                    super::fixtures::runner().start(|runtime| async move {
                        let fixture = active_close_fixture(runtime, profile).await;
                        let mut elapsed = Duration::ZERO;
                        for _ in 0..iterations {
                            let start = Instant::now();
                            let prepared = prepare_dealing::<Sha256, _, _>(
                                fixture.context.epoch_context(),
                                &fixture.deposits,
                                &fixture.withdrawals,
                                fixture.terminals.clone(),
                            )
                            .expect("prepare dealing");
                            elapsed += start.elapsed();
                            assert_eq!(prepared.encoded(), fixture.prepared.encoded());
                            black_box(prepared);
                        }
                        elapsed
                    })
                });
            },
        );
    }
}
criterion_group! {name = benches; config = Criterion::default().sample_size(10); targets = bench_prepare,}

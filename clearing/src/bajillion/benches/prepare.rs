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
        let (context, deposits, withdrawals, terminals, expected) = super::fixtures::runner()
            .start(|runtime| async move {
                let fixture = active_close_fixture(runtime, profile).await;
                (
                    fixture.context,
                    fixture.deposits,
                    fixture.withdrawals,
                    fixture.terminals,
                    fixture.prepared.encoded().clone(),
                )
            });
        c.bench_function(
            &format!(
                "{}/{} E={}",
                module_path!(),
                profile_key(profile),
                profile.edges()
            ),
            |b| {
                b.iter_custom(|iterations| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iterations {
                        let terminals = terminals.clone();
                        let start = Instant::now();
                        let prepared = prepare_dealing::<Sha256, _, _>(
                            context.epoch_context(),
                            &deposits,
                            &withdrawals,
                            terminals,
                        )
                        .expect("prepare dealing");
                        elapsed += start.elapsed();
                        assert_eq!(prepared.encoded(), &expected);
                        black_box(prepared);
                    }
                    elapsed
                });
            },
        );
    }
}
criterion_group! {name = benches; config = Criterion::default().sample_size(10); targets = bench_prepare,}

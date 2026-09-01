use super::fixtures::{
    WORKERS, active_close_fixture, profile_key, selected_active_profiles, strategy,
};
use commonware_clearing::bajillion::transition::prepare_close_with_strategy;
use commonware_cryptography::Sha256;
use criterion::{BatchSize, Criterion, criterion_group};
use std::hint::black_box;

fn bench_prepare(c: &mut Criterion) {
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
                b.iter_batched(
                    || {
                        (
                            fixture.rows.clone(),
                            fixture.out_vectors.clone(),
                            fixture.transpose.clone(),
                        )
                    },
                    |(rows, out_vectors, transpose)| {
                        black_box(
                            prepare_close_with_strategy::<Sha256, _, _>(
                                &fixture.cache,
                                &fixture.context,
                                &fixture.deposits,
                                &fixture.withdrawals,
                                rows,
                                out_vectors,
                                &fixture.out_partials,
                                &fixture.operator_signatures,
                                transpose,
                                strategy(),
                            )
                            .expect("benchmark preparation is valid"),
                        )
                    },
                    BatchSize::PerIteration,
                );
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_prepare,
}

use super::fixtures::challenge_fixture;
use commonware_clearing::bajillion::challenge::adjudicate;
use commonware_cryptography::Sha256;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

const REGISTRY: usize = 1_024;
const CHANGE_ROWS: usize = 129;
const RECEIVE_SHARDS: usize = 16;

fn bench_adjudicate(c: &mut Criterion) {
    let fixture = challenge_fixture(REGISTRY, CHANGE_ROWS, RECEIVE_SHARDS);
    c.bench_function(
        &format!(
            "{}/kind=higher_shard_tip change_rows={CHANGE_ROWS} receive_shards={RECEIVE_SHARDS}",
            module_path!()
        ),
        |b| {
            b.iter(|| {
                black_box(
                    adjudicate::<Sha256, _>(
                        black_box(&fixture.context),
                        black_box(&fixture.header),
                        black_box(&fixture.roots),
                        fixture.context.challenge_deadline(),
                        black_box(&fixture.challenge),
                    )
                    .expect("benchmark challenge is valid"),
                )
            });
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_adjudicate,
}

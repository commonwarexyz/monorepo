use super::fixtures::{batched_challenge, challenge_fixture};
use commonware_clearing::bajillion::challenge::adjudicate;
use commonware_cryptography::Sha256;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

const LIVE_ACCOUNTS: usize = 1_024;
const CHANGE_ROWS: usize = 129;
const RECEIVE_SHARDS: usize = 16;
const BATCH_ENTRIES: [usize; 3] = [1, 16, 256];

fn bench_adjudicate(c: &mut Criterion) {
    let fixture = challenge_fixture(LIVE_ACCOUNTS, CHANGE_ROWS, RECEIVE_SHARDS);
    for entries in BATCH_ENTRIES {
        let challenge = if entries == 1 {
            fixture.challenge.clone()
        } else {
            batched_challenge(&fixture, entries)
        };
        c.bench_function(
            &format!(
                "{}/kind=higher_shard_tip change_rows={CHANGE_ROWS} receive_shards={RECEIVE_SHARDS} entries={entries}",
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
                            black_box(&challenge),
                        )
                        .expect("benchmark challenge is valid"),
                    )
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_adjudicate,
}

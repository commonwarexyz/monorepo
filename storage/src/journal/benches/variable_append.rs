//! Single-item variable-journal append cost with buffered and durable workloads.

use crate::{PAGE_SIZE, REPLAY_BUFFER, WRITE_BUFFER};
use commonware_runtime::{
    Supervisor as _,
    benchmarks::{context, tokio},
    buffer::paged::CacheRef,
};
use commonware_storage::journal::contiguous::variable::{Config, Journal};
use commonware_utils::{NZU64, NZUsize, sequence::FixedBytes};
use criterion::{Criterion, criterion_group};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

fn bench_case<const SIZE: usize>(
    c: &mut Criterion,
    items: usize,
    compression: Option<u8>,
    commit_every: usize,
) {
    let runner = tokio::Runner::default();
    let level = compression.map_or("none".into(), |level| level.to_string());
    c.bench_function(
        &format!(
            "{}/items={items} size={SIZE} compression={level} commit_every={commit_every}",
            module_path!()
        ),
        |b| {
            b.to_async(&runner).iter_custom(|iters| async move {
                let ctx = context::get::<commonware_runtime::tokio::Context>();
                let cache = CacheRef::from_pooler(&ctx, PAGE_SIZE, NZUsize!(32));
                let item = FixedBytes::new([0xAB; SIZE]);
                let mut elapsed = Duration::ZERO;
                for _ in 0..iters {
                    let mut journal = Journal::init(
                        ctx.child("storage"),
                        Config {
                            partition: "variable_append".into(),
                            items_per_section: NZU64!(1_000_000),
                            compression,
                            codec_config: (),
                            page_cache: cache.clone(),
                            write_buffer: WRITE_BUFFER,
                            replay_buffer: REPLAY_BUFFER,
                        },
                    )
                    .await
                    .unwrap();
                    // Append one item first, so the write buffers' initial allocation isn't
                    // timed. Durable cases also commit it, so timing starts with nothing pending.
                    (journal, _) = journal.append(&item).await.unwrap();
                    if commit_every != 0 {
                        journal = journal.commit().await.unwrap();
                    }

                    let start = Instant::now();
                    for index in 1..=items {
                        (journal, _) = journal.append(black_box(&item)).await.unwrap();
                        if commit_every != 0 && index.is_multiple_of(commit_every) {
                            journal = journal.commit().await.unwrap();
                        }
                    }
                    black_box(&journal);
                    elapsed += start.elapsed();
                    journal.destroy().await.unwrap();
                }
                elapsed
            });
        },
    );
}

fn bench_size<const SIZE: usize>(c: &mut Criterion) {
    // 320 KiB fits in the 1 MiB write buffer, so nothing is written to disk and only CPU cost
    // is timed.
    bench_case::<SIZE>(c, 320 * 1024 / SIZE, None, 0);
    // 4 MiB fills the write buffer several times, then commits once at the end.
    let items = 4 * 1024 * 1024 / SIZE;
    bench_case::<SIZE>(c, items, None, items);
}

fn bench(c: &mut Criterion) {
    bench_size::<32>(c);
    bench_size::<256>(c);
    bench_size::<4_096>(c);
    // Compressed appends, which take the batch path.
    bench_case::<32>(c, 320 * 1024 / 32, Some(3), 0);
    // Frequent commits, where fsync dominates the per-item cost.
    bench_case::<32>(c, 64, None, 1);
    bench_case::<32>(c, 1_024, None, 64);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30);
    targets = bench
}

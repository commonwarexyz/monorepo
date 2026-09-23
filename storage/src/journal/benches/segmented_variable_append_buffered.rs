//! Segmented variable-journal append CPU cost while every record fits in the write buffer.

use crate::{PAGE_SIZE, WRITE_BUFFER};
use commonware_runtime::{
    Supervisor as _,
    benchmarks::{context, tokio},
    buffer::paged::CacheRef,
};
use commonware_storage::journal::segmented::variable::{Config, Journal};
use commonware_utils::{NZUsize, sequence::FixedBytes};
use criterion::{Criterion, criterion_group};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

fn bench_size<const SIZE: usize>(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    let items = 320 * 1024 / SIZE;
    c.bench_function(
        &format!("{}/items={items} size={SIZE}", module_path!()),
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
                            partition: "segmented_variable_append_buffered".into(),
                            compression: None,
                            codec_config: (),
                            page_cache: cache.clone(),
                            write_buffer: WRITE_BUFFER,
                        },
                    )
                    .await
                    .unwrap();

                    // Warm the tip allocation outside the timed region. Neither these appends
                    // nor the timed appends fill the tip.
                    (journal, _, _) = journal.append(0, &item).await.unwrap();
                    let start = Instant::now();
                    for _ in 0..items {
                        (journal, _, _) = journal.append(0, black_box(&item)).await.unwrap();
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

fn bench(c: &mut Criterion) {
    bench_size::<32>(c);
    bench_size::<256>(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench
}

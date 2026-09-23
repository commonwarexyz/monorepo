//! Contiguous variable-journal reads of compressed items.

use crate::{PAGE_CACHE_SIZE, PAGE_SIZE, REPLAY_BUFFER, WRITE_BUFFER};
use commonware_runtime::{
    ReadOptions, Supervisor as _,
    benchmarks::{context, tokio},
    buffer::paged::CacheRef,
};
use commonware_storage::journal::contiguous::{
    Contiguous as _,
    variable::{Config, Journal},
};
use commonware_utils::{NZU64, NZUsize, sequence::FixedBytes};
use criterion::{Criterion, criterion_group};
use futures::{StreamExt, pin_mut};
use std::{hint::black_box, time::Instant};

/// Number of items in the journal.
const ITEMS: u64 = 10_000;

fn bench_size<const SIZE: usize>(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    for mode in ["read_many", "replay"] {
        c.bench_function(
            &format!("{}/mode={mode} items={ITEMS} size={SIZE}", module_path!()),
            |b| {
                b.to_async(&runner).iter_custom(|iters| async move {
                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                    let mut journal = Journal::init(
                        ctx.child("storage"),
                        Config {
                            partition: "variable_read_compressed".into(),
                            items_per_section: NZU64!(1_000_000),
                            compression: Some(3),
                            codec_config: (),
                            page_cache: CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
                            write_buffer: WRITE_BUFFER,
                            replay_buffer: REPLAY_BUFFER,
                        },
                    )
                    .await
                    .unwrap();

                    // Items differ only in a counter prefix, so each compresses well.
                    for i in 0..ITEMS {
                        let mut bytes = [0xAB; SIZE];
                        bytes[..8].copy_from_slice(&i.to_be_bytes());
                        (journal, _) = journal.append(&FixedBytes::new(bytes)).await.unwrap();
                    }
                    let journal = journal.sync().await.unwrap();
                    let positions: Vec<u64> = (0..ITEMS).collect();

                    let (journal, reader) = journal.snapshot().await.unwrap();
                    let start = Instant::now();
                    for _ in 0..iters {
                        match mode {
                            "read_many" => {
                                black_box(reader.read_many(&positions).await.unwrap());
                            }
                            "replay" => {
                                let stream = reader
                                    .replay(0, NZUsize!(65_536), ReadOptions::default())
                                    .await
                                    .unwrap();
                                pin_mut!(stream);
                                while let Some(item) = stream.next().await {
                                    black_box(item.unwrap());
                                }
                            }
                            _ => unreachable!(),
                        }
                    }
                    let elapsed = start.elapsed();
                    drop(reader);
                    journal.destroy().await.unwrap();
                    elapsed
                });
            },
        );
    }
}

fn bench(c: &mut Criterion) {
    bench_size::<64>(c);
    bench_size::<1024>(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench
}

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
use commonware_utils::{NZU64, NZUsize, sequence::FixedBytes, test_rng};
use criterion::{Criterion, criterion_group};
use futures::{StreamExt, pin_mut};
use rand::{Rng as _, RngExt as _};
use std::{hint::black_box, time::Instant};

/// Value of items_per_section to use in the journal config.
const ITEMS_PER_SECTION: u64 = 1_000;

fn bench_size<const SIZE: usize>(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    let items = (16 * 1024 * 1024 / SIZE).min(10_000) as u64;
    for random in [false, true] {
        for mode in ["read_many", "read_uncached", "replay"] {
            c.bench_function(
                &format!(
                    "{}/mode={mode} items={items} size={SIZE} random={random}",
                    module_path!()
                ),
                |b| {
                    b.to_async(&runner).iter_custom(|iters| async move {
                        let ctx = context::get::<commonware_runtime::tokio::Context>();

                        // A two-page cache makes random reads miss and read frames from blobs.
                        let cache_pages = if mode == "read_uncached" {
                            NZUsize!(2)
                        } else {
                            PAGE_CACHE_SIZE
                        };
                        let mut journal = Journal::init(
                            ctx.child("storage"),
                            Config {
                                partition: "variable_read_compressed".into(),
                                items_per_section: NZU64!(ITEMS_PER_SECTION),
                                compression: Some(3),
                                codec_config: (),
                                page_cache: CacheRef::from_pooler(&ctx, PAGE_SIZE, cache_pages),
                                write_buffer: WRITE_BUFFER,
                                replay_buffer: REPLAY_BUFFER,
                            },
                        )
                        .await
                        .unwrap();

                        // Use the same items and read positions in every sample. Random items do
                        // not compress; the others differ only in a counter prefix.
                        let mut rng = test_rng();
                        for i in 0..items {
                            let mut bytes = [0xAB; SIZE];
                            if random {
                                rng.fill_bytes(&mut bytes);
                            } else {
                                bytes[..8].copy_from_slice(&i.to_be_bytes());
                            }
                            (journal, _) = journal.append(&FixedBytes::new(bytes)).await.unwrap();
                        }
                        let journal = journal.sync().await.unwrap();
                        let all: Vec<u64> = (0..items).collect();
                        let sampled: Vec<u64> =
                            (0..items).map(|_| rng.random_range(0..items)).collect();

                        let (journal, reader) = journal.snapshot().await.unwrap();
                        let start = Instant::now();
                        for _ in 0..iters {
                            match mode {
                                "read_many" => {
                                    black_box(reader.read_many(&all).await.unwrap());
                                }
                                "read_uncached" => {
                                    for &pos in &sampled {
                                        black_box(reader.read(pos).await.unwrap());
                                    }
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
}

fn bench(c: &mut Criterion) {
    bench_size::<64>(c);
    bench_size::<1024>(c);
    bench_size::<16384>(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench
}

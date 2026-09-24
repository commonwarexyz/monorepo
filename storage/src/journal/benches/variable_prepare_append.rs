//! Variable-journal batch preparation across record sizes and compressibility.

use crate::{PAGE_SIZE, REPLAY_BUFFER, WRITE_BUFFER};
use commonware_runtime::{
    Supervisor as _,
    benchmarks::{context, tokio},
    buffer::paged::CacheRef,
};
use commonware_storage::journal::contiguous::{
    Many,
    variable::{Config, Journal},
};
use commonware_utils::{NZU64, NZUsize, sequence::FixedBytes, test_rng};
use criterion::{Criterion, criterion_group};
use rand::Rng as _;
use std::{hint::black_box, time::Instant};

fn bench_size<const SIZE: usize>(c: &mut Criterion) {
    let runner = tokio::Runner::default();

    // Cap input payloads at 32 MiB: the full 32,768-item sweep with 1 MiB records would
    // otherwise allocate 32 GiB.
    let max_items = 32_768.min(32 * 1024 * 1024 / SIZE);

    // Repeated bytes with distinct item prefixes provide highly compressible records.
    // Random bytes exercise inputs with little opportunity for compression.
    for random in [false, true] {
        let mut rng = test_rng();
        let values: Vec<_> = (0..max_items as u64)
            .map(|i| {
                let mut bytes = [0xAB; SIZE];
                if random {
                    rng.fill_bytes(&mut bytes);
                } else {
                    bytes[..8].copy_from_slice(&i.to_be_bytes());
                }
                FixedBytes::new(bytes)
            })
            .collect();

        for items in [1, 32, 256, 1_024, 32_768] {
            if items > max_items {
                continue;
            }

            let values = &values[..items];
            for compression in [None, Some(3)] {
                // Fixed-size encoding copies the same number of bytes for either input pattern,
                // so one uncompressed baseline covers both.
                if compression.is_none() && random {
                    continue;
                }

                let level = compression.map_or("none".into(), |level| level.to_string());
                c.bench_function(
                    &format!(
                        "{}/items={items} size={SIZE} compression={level} random={random}",
                        module_path!()
                    ),
                    |b| {
                        b.to_async(&runner).iter_custom(|iters| async move {
                            let ctx = context::get::<commonware_runtime::tokio::Context>();
                            let journal = Journal::init(
                                ctx.child("storage"),
                                Config {
                                    partition: "variable_prepare_append".into(),
                                    items_per_section: NZU64!(1_000_000),
                                    compression,
                                    codec_config: (),
                                    page_cache: CacheRef::from_pooler(
                                        &ctx,
                                        PAGE_SIZE,
                                        NZUsize!(32),
                                    ),
                                    write_buffer: WRITE_BUFFER,
                                    replay_buffer: REPLAY_BUFFER,
                                },
                            )
                            .await
                            .unwrap();

                            // Include frame encoding, optional compression, compaction, and dropping
                            // each batch.
                            let start = Instant::now();
                            for _ in 0..iters {
                                black_box(journal.prepare_append(Many::Flat(black_box(values))))
                                    .unwrap();
                            }
                            let elapsed = start.elapsed();

                            journal.destroy().await.unwrap();
                            elapsed
                        });
                    },
                );
            }
        }
    }
}

fn bench(c: &mut Criterion) {
    bench_size::<64>(c);
    bench_size::<1024>(c);
    bench_size::<{ 1024 * 1024 }>(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench
}

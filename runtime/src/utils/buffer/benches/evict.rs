//! Benchmark dropping the last handle of a blob whose pages fill the page cache, and filling the
//! cache again with the pages of another blob.

use super::create_append;
use commonware_runtime::{Runner, Storage, buffer::paged::CacheRef, deterministic};
use commonware_utils::{NZU16, NZUsize, Widen};
use criterion::Criterion;
use std::{
    num::NonZeroU16,
    time::{Duration, Instant},
};

/// Removing a page costs the same at any page size, so small pages make filling the cache cheap.
const PAGE_SIZE: NonZeroU16 = NZU16!(64);

/// The slots of a 6 GiB cache of 4 KiB pages.
const LARGE: usize = 6 * 1024 * 1024 * 1024 / 4096;

pub fn bench(c: &mut Criterion) {
    let page_size: usize = PAGE_SIZE.widen();
    for pages in [1usize << 12, 1 << 16, LARGE] {
        for refill in [false, true] {
            let op = if refill { "refill" } else { "drop" };
            c.bench_function(&format!("{}/op={op} pages={pages}", module_path!()), |b| {
                b.iter_custom(|iters| {
                    deterministic::Runner::default().start(|ctx| async move {
                        let cache_ref = CacheRef::new(PAGE_SIZE, NZUsize!(pages));
                        let data = vec![0xABu8; page_size * pages];
                        let mut elapsed = Duration::ZERO;
                        for i in 0..iters {
                            // Fill the cache with one blob's pages outside the timed operations.
                            let name = format!("evict_{i}").into_bytes();
                            let mut writer = create_append(&ctx, &name, cache_ref.clone()).await;
                            (writer, _) = writer.append(&data).await.unwrap();
                            writer = writer.sync().await.unwrap();

                            let start = Instant::now();
                            drop(writer);
                            let dropped = start.elapsed();
                            ctx.remove("bench_partition", Some(&name)).await.unwrap();
                            if !refill {
                                elapsed += dropped;
                                continue;
                            }

                            // Every page the next blob caches needs a slot the dropped blob held.
                            let mut writer = create_append(&ctx, &name, cache_ref.clone()).await;
                            let start = Instant::now();
                            (writer, _) = writer.append(&data).await.unwrap();
                            writer = writer.sync().await.unwrap();
                            elapsed += start.elapsed();
                            drop(writer);
                            ctx.remove("bench_partition", Some(&name)).await.unwrap();
                        }
                        elapsed
                    })
                });
            });
        }
    }
}

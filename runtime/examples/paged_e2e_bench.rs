//! BENCH-ONLY (do not commit): end-to-end A/B through the paged writer.
//!
//! Usage: paged_e2e_bench <storage_dir> <per_sync> <syncs> <record_bytes> <write_buffer>

use commonware_runtime::{
    Runner as _, Storage,
    buffer::paged::{CacheRef, Writer, page_size},
    tokio,
};
use commonware_utils::NZUsize;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = args[1].clone();
    let per_sync: usize = args[2].parse().unwrap();
    let syncs: usize = args[3].parse().unwrap();
    let record: usize = args[4].parse().unwrap();
    let write_buffer: usize = args[5].parse().unwrap();

    let cfg = tokio::Config::new().with_storage_directory(dir);
    tokio::Runner::new(cfg).start(|ctx| async move {
        let cache = CacheRef::from_pooler(&ctx, page_size(4096), NZUsize!(10_000));
        let (blob, size) = ctx.open("ablate", b"journal").await.unwrap();
        let mut writer = Writer::new(blob, size, write_buffer, cache).await.unwrap();
        let data = vec![0xABu8; record];

        // Warmup.
        for _ in 0..64.min(syncs) {
            for _ in 0..per_sync {
                writer.append(&data).await.unwrap();
            }
            writer.sync().await.unwrap();
        }

        let mut lat = Vec::with_capacity(syncs);
        let start = Instant::now();
        for _ in 0..syncs {
            for _ in 0..per_sync {
                writer.append(&data).await.unwrap();
            }
            let s = Instant::now();
            writer.sync().await.unwrap();
            lat.push(s.elapsed().as_secs_f64());
        }
        let total = start.elapsed().as_secs_f64();

        lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "per_sync={per_sync} rec={record} buf={write_buffer} syncs={syncs} \
             total={total:.3}s syncs_per_s={:.0} sync_p50={:.1}us p99={:.1}us",
            syncs as f64 / total,
            lat[lat.len() / 2] * 1e6,
            lat[(lat.len() as f64 * 0.99) as usize] * 1e6,
        );
    });
}

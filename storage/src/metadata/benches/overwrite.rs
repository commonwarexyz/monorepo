//! Steady-state cost of persisting equal-size updates, which overwrite the store in place.

use commonware_runtime::{
    Supervisor as _,
    benchmarks::{context, tokio},
};
use commonware_storage::metadata::{Config, Metadata};
use commonware_utils::sequence::FixedBytes;
use criterion::{Criterion, criterion_group};
use std::time::{Duration, Instant};

fn bench_case<const SIZE: usize>(c: &mut Criterion, keys: u64, modified: u64, pipelined: bool) {
    let runner = tokio::Runner::default();
    c.bench_function(
        &format!(
            "{}/keys={keys} size={SIZE} modified={modified} pipelined={pipelined}",
            module_path!()
        ),
        |b| {
            b.to_async(&runner).iter_custom(|iters| async move {
                let ctx = context::get::<commonware_runtime::tokio::Context>();
                let mut metadata = Metadata::<_, u64, FixedBytes<SIZE>>::init(
                    ctx.child("storage"),
                    Config {
                        partition: "metadata_overwrite".into(),
                        codec_config: (),
                    },
                )
                .await
                .unwrap();
                for key in 0..keys {
                    metadata.put(key, FixedBytes::new([0; SIZE]));
                }
                // Populate both metadata copies before timing equal-size updates.
                metadata = metadata.sync().await.unwrap();
                metadata = metadata.sync().await.unwrap();

                let mut elapsed = Duration::ZERO;
                for iteration in 0..iters {
                    let value = FixedBytes::new([(iteration % 251 + 1) as u8; SIZE]);
                    for key in 0..modified {
                        metadata.put(key, value.clone());
                    }
                    // Pipelined runs await the handle, so both modes time completion, not submission.
                    let start = Instant::now();
                    if pipelined {
                        let (next, handle) = metadata.start_sync().await.unwrap();
                        metadata = next;
                        handle.await.unwrap();
                    } else {
                        metadata = metadata.sync().await.unwrap();
                    }
                    elapsed += start.elapsed();
                }
                metadata.destroy().await.unwrap();
                elapsed
            });
        },
    );
}

fn bench_overwrite(c: &mut Criterion) {
    // Cases with fewer than 256 keys encode to at most 4 KiB and are written whole. 255 keys
    // (4,092 bytes) is the largest such store, and 256 keys (4,108 bytes) is just above the limit.
    bench_case::<8>(c, 1, 1, false);
    bench_case::<8>(c, 3, 1, false);
    bench_case::<8>(c, 3, 3, false);
    bench_case::<8>(c, 128, 1, false);
    bench_case::<8>(c, 128, 128, false);
    bench_case::<8>(c, 255, 1, false);
    bench_case::<8>(c, 255, 1, true);
    bench_case::<8>(c, 256, 1, false);
    bench_case::<8>(c, 1_024, 1, false);
    bench_case::<8>(c, 1_024, 128, false);
    bench_case::<2_048>(c, 1, 1, false);
    bench_case::<8>(c, 3, 1, true);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30);
    targets = bench_overwrite
}

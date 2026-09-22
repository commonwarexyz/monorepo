//! Merkle digest lookup cost with persisted nodes or operation-backed reconstruction.
//!
//! Setup and startup replay are excluded. `cache=disabled` measures repeated reconstruction;
//! `cache=warm` primes the requested lower subtree. The runtime's page cache remains enabled
//! in every case, so these measurements are not cold-device latency claims.

use commonware_codec::Encode;
use commonware_cryptography::Sha256;
use commonware_parallel::Sequential;
use commonware_runtime::{
    Supervisor as _,
    benchmarks::{context, tokio},
    buffer::paged::CacheRef,
    tokio::{Config, Context},
};
use commonware_storage::{
    journal::{authenticated, contiguous::variable},
    merkle::{Family, Location, full, mmb, mmr, storage::Storage as _},
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use criterion::{Criterion, criterion_group};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

const OPERATIONS: u64 = 4096;

async fn run<F: Family>(
    context: Context,
    iters: u64,
    bytes: usize,
    height: u32,
    backend: &str,
) -> Duration {
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    let page_cache = CacheRef::from_pooler(&context, NZU16!(4096), NZUsize!(512));
    let item = vec![7u8; bytes];
    let position = F::subtree_root_position(Location::new(0), height);
    let mut total = Duration::ZERO;
    if backend == "persisted" {
        let mut tree = full::Merkle::<F, _, _, _>::init(
            context.child("nodes"),
            &hasher,
            full::Config {
                journal_partition: "digest-read-nodes".into(),
                metadata_partition: "digest-read-node-metadata".into(),
                items_per_blob: NZU64!(4096),
                write_buffer: NZUsize!(1 << 16),
                replay_buffer: NZUsize!(1 << 16),
                strategy: Sequential,
                page_cache,
            },
        )
        .await
        .unwrap();
        let encoded = item.encode();
        let mut batch = tree.new_batch();
        for _ in 0..OPERATIONS {
            batch = batch.add(&hasher, &encoded);
        }
        let batch = tree.with_mem(|mem| batch.merkleize(mem, &hasher));
        tree = tree.apply_batch(&batch).unwrap().sync().await.unwrap();
        black_box(tree.get_node(position).await.unwrap());
        for _ in 0..iters {
            let start = Instant::now();
            black_box(tree.get_node(position).await.unwrap());
            total += start.elapsed();
        }
        tree.destroy().await.unwrap();
    } else {
        let config = authenticated::Config {
            metadata_partition: "digest-read-frontier".into(),
            cache: authenticated::CacheConfig {
                resident_height: 5,
                lower_cache_bytes: if backend == "warm" { 8 << 20 } else { 0 },
            },
            replay_buffer: NZUsize!(1 << 16),
            strategy: Sequential,
        };
        let raw_config = variable::Config {
            partition: "digest-read-operations".into(),
            items_per_section: NZU64!(4096),
            compression: None,
            codec_config: ((0..=bytes).into(), ()),
            page_cache,
            write_buffer: NZUsize!(1 << 16),
            replay_buffer: NZUsize!(1 << 16),
        };
        let mut journal =
            authenticated::Journal::<F, _, variable::Journal<_, Vec<u8>>, Sha256, _>::new(
                context.child("operations"),
                config,
                raw_config,
                |_| true,
                hasher.root_bagging(),
            )
            .await
            .unwrap();
        for i in 0..OPERATIONS {
            (journal, _) = journal.append(&item).await.unwrap();
            if i % 256 == 255 {
                journal = journal.commit().await.unwrap();
            }
        }
        journal = journal.sync().await.unwrap();
        black_box(journal.get_node(position).await.unwrap());
        for _ in 0..iters {
            let start = Instant::now();
            black_box(journal.get_node(position).await.unwrap());
            total += start.elapsed();
        }
        journal.destroy().await.unwrap();
    }
    total
}

fn bench_family<F: Family>(c: &mut Criterion, family: &str) {
    let runner = tokio::Runner::new(Config::default());
    for bytes in [64, 4096] {
        for height in [4, 5] {
            for backend in ["persisted", "disabled", "warm"] {
                c.bench_function(
                    &format!(
                        "{}/family={family} bytes={bytes} height={height} cache={backend}",
                        module_path!()
                    ),
                    |b| {
                        b.to_async(&runner).iter_custom(|iters| {
                            run::<F>(context::get::<Context>(), iters, bytes, height, backend)
                        });
                    },
                );
            }
        }
    }
}

fn bench_digest_reads(c: &mut Criterion) {
    bench_family::<mmr::Family>(c, "mmr");
    bench_family::<mmb::Family>(c, "mmb");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_digest_reads,
}

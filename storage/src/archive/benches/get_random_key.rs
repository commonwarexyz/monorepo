//! Random key-lookup benchmark for `Archive`.

use commonware_runtime::benchmarks::{context, tokio};
use criterion::{black_box, criterion_group, Criterion};
use futures::future::try_join_all;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use std::time::{Duration, Instant};

mod util;
use util::*;

/// How many items we pre-load into the archive.
const ITEMS_WRITTEN: u64 = 1_000_000;

/// Populate the archive and return the corresponding Vec<Key>
async fn load_archive(ctx: commonware_runtime::tokio::Context) -> (Archive, Vec<Key>)
where
    Archive: commonware_storage::archive::ArchiveTrait,
{
    let mut archive = get_archive(ctx, None).await;
    let mut rng = StdRng::seed_from_u64(0);
    let mut keys = Vec::with_capacity(ITEMS_WRITTEN as usize);

    let mut key_buf = [0u8; 64];
    let mut val_buf = [0u8; 32];

    for idx in 0..ITEMS_WRITTEN {
        rng.fill_bytes(&mut key_buf);
        rng.fill_bytes(&mut val_buf);
        let key = Key::new(key_buf);
        archive
            .put(idx, key.clone(), Val::new(val_buf))
            .await
            .unwrap();
        keys.push(key);
    }
    archive.sync().await.unwrap();
    (archive, keys)
}

async fn read_random_serial(archive: &Archive, keys: &[Key], reads: usize)
where
    Archive: commonware_storage::archive::ArchiveTrait,
{
    let mut rng = StdRng::seed_from_u64(42);
    for _ in 0..reads {
        let k = &keys[rng.gen_range(0..ITEMS_WRITTEN as usize)];
        black_box(
            archive
                .get(util::Identifier::Key(k))
                .await
                .unwrap()
                .unwrap(),
        );
    }
}

async fn read_random_concurrent(archive: &Archive, keys: &[Key], reads: usize)
where
    Archive: commonware_storage::archive::ArchiveTrait,
{
    let mut rng = StdRng::seed_from_u64(42);
    let mut futs = Vec::with_capacity(reads);
    for _ in 0..reads {
        let k = keys[rng.gen_range(0..ITEMS_WRITTEN as usize)].clone();
        futs.push(archive.get(util::Identifier::Key(&k)));
    }
    let res = try_join_all(futs).await.unwrap();
    black_box(res);
}

fn bench_archive_get_random_key(c: &mut Criterion) {
    // Build the big archive once
    let build = commonware_runtime::tokio::Runner::default();
    build.start(|ctx| async move {
        let (a, _) = load_archive(ctx).await;
        a.close().await.unwrap();
    });

    let runner = tokio::Runner::default();
    for mode in ["serial", "concurrent"] {
        for reads in [1_000, 10_000, 100_000] {
            let lbl = format!("{}/mode={} reads={}", module_path!(), mode, reads);
            c.bench_function(&lbl, |b| {
                b.to_async(&runner).iter_custom(move |iters| async move {
                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                    let (archive, keys) = load_archive(ctx).await; // load fresh each iter
                    let mut total = Duration::ZERO;

                    for _ in 0..iters {
                        let start = Instant::now();
                        match mode {
                            "serial" => read_random_serial(&archive, &keys, reads).await,
                            "concurrent" => read_random_concurrent(&archive, &keys, reads).await,
                            _ => unreachable!(),
                        }
                        total += start.elapsed();
                    }
                    archive.destroy().await.unwrap();
                    total
                });
            });
        }
    }

    // Tear down
    let cleaner = commonware_runtime::tokio::Runner::default();
    cleaner.start(|ctx| async move {
        let a = get_archive(ctx, None).await;
        a.destroy().await.unwrap();
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_archive_get_random_key
}

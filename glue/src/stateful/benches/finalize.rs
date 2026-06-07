use commonware_cryptography::{sha256::Digest, Hasher as _, Sha256};
use commonware_glue::stateful::db::{DatabaseSet, ManagedDb, Unmerkleized as _};
use commonware_parallel::Rayon;
use commonware_runtime::{
    benchmarks::{context, tokio},
    buffer::paged::CacheRef,
    tokio::{Config, Context},
    Handle, Spawner, Supervisor as _, ThreadPooler,
};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig,
    merkle::{full::Config as MerkleConfig, mmb, Family, Location},
    qmdb::keyless::fixed::{Config as KeylessConfig, Db},
};
use commonware_utils::{sync::AsyncRwLock, NZUsize, NZU16, NZU64};
use criterion::{criterion_group, Criterion};
use futures::FutureExt as _;
use std::{
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::{Duration, Instant},
};

const PAGE_SIZE: NonZeroU16 = NZU16!(16_384);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(512);
const THREADS: NonZeroUsize = NZUsize!(8);
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(50_000);
const BATCHES: u64 = 100;
const APPENDS_PER_BATCH: u64 = 256;
const PRUNE_EVERY: u64 = 25;
const PRUNE_BOUNDARIES: u64 = BATCHES / PRUNE_EVERY;
const WRITE_BUFFER_SIZE: NonZeroUsize = NZUsize!(2 * 1024 * 1024);

type BenchDb<F> = Db<F, Context, Digest, Sha256, Rayon>;

fn value(batch: u64, append: u64) -> Digest {
    Sha256::hash(&[batch.to_be_bytes(), append.to_be_bytes()].concat())
}

fn db_config(ctx: &Context, suffix: &str) -> KeylessConfig<Rayon> {
    let page_cache = CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    KeylessConfig {
        merkle: MerkleConfig {
            journal_partition: format!("merkle-journal-{suffix}"),
            metadata_partition: format!("merkle-metadata-{suffix}"),
            items_per_blob: ITEMS_PER_BLOB,
            write_buffer: WRITE_BUFFER_SIZE,
            strategy: ctx.create_strategy(THREADS).unwrap(),
            page_cache: page_cache.clone(),
        },
        log: JournalConfig {
            partition: format!("log-journal-{suffix}"),
            items_per_blob: ITEMS_PER_BLOB,
            page_cache,
            write_buffer: WRITE_BUFFER_SIZE,
        },
    }
}

async fn open_db<F: Family>(ctx: &Context, suffix: &str) -> BenchDb<F> {
    BenchDb::<F>::init(ctx.child("storage"), db_config(ctx, suffix))
        .await
        .unwrap()
}

async fn bench_managed_finalize<F: Family>(ctx: &Context) -> Duration {
    let db = open_db::<F>(ctx, "managed-finalize").await;
    let db = Arc::new(AsyncRwLock::new(db));
    let mut elapsed = Duration::ZERO;

    for batch_idx in 0..BATCHES {
        let mut batch = <BenchDb<F> as ManagedDb<Context>>::new_batch(&db).await;
        for append_idx in 0..APPENDS_PER_BATCH {
            batch = batch.append(value(batch_idx, append_idx));
        }
        let merkleized = batch.merkleize().await.unwrap();

        let start = Instant::now();
        {
            let mut guard = db.write().await;
            <BenchDb<F> as ManagedDb<Context>>::finalize(&mut *guard, merkleized)
                .await
                .unwrap();
        }
        elapsed += start.elapsed();
    }

    let db = Arc::try_unwrap(db)
        .ok()
        .expect("benchmark should hold the only db reference")
        .into_inner();
    db.destroy().await.unwrap();
    elapsed
}

async fn bench_apply_then_commit<F: Family>(ctx: &Context) -> Duration {
    let mut db = open_db::<F>(ctx, "apply-commit").await;
    let mut elapsed = Duration::ZERO;

    for batch_idx in 0..BATCHES {
        let mut batch = db.new_batch();
        for append_idx in 0..APPENDS_PER_BATCH {
            batch = batch.append(value(batch_idx, append_idx));
        }
        let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc());

        let start = Instant::now();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        elapsed += start.elapsed();
    }

    db.destroy().await.unwrap();
    elapsed
}

fn spawn_background_preflush<F>(
    ctx: &Context,
    db: Arc<AsyncRwLock<BenchDb<F>>>,
    target: <Arc<AsyncRwLock<BenchDb<F>>> as DatabaseSet<Context>>::SyncTargets,
) -> Handle<()>
where
    F: Family + 'static,
    <Arc<AsyncRwLock<BenchDb<F>>> as DatabaseSet<Context>>::SyncTargets: Send + 'static,
{
    ctx.child("background_preflush").spawn(|_| async move {
        <Arc<AsyncRwLock<BenchDb<F>>> as DatabaseSet<Context>>::preflush_to(&db, &target).await;
    })
}

async fn await_background_preflush(sync: &mut Option<Handle<()>>) {
    if let Some(handle) = sync.take() {
        handle
            .await
            .expect("background preflush task should complete");
    }
}

fn clear_finished_background_preflush(sync: &mut Option<Handle<()>>) {
    let Some(handle) = sync.as_mut() else {
        return;
    };
    let Some(result) = handle.now_or_never() else {
        return;
    };
    result.expect("background preflush task should complete");
    *sync = None;
}

async fn bench_managed_pipeline<F: Family>(ctx: &Context) -> Duration {
    let db = open_db::<F>(ctx, "managed-pipeline").await;
    let db = Arc::new(AsyncRwLock::new(db));
    let mut elapsed = Duration::ZERO;
    let mut next_loc = 1;

    for batch_idx in 0..BATCHES {
        let mut batch = <BenchDb<F> as ManagedDb<Context>>::new_batch(&db)
            .await
            .with_inactivity_floor(Location::new(next_loc));
        for append_idx in 0..APPENDS_PER_BATCH {
            batch = batch.append(value(batch_idx, append_idx));
        }
        let merkleized = batch.merkleize().await.unwrap();

        let start = Instant::now();
        {
            let mut guard = db.write().await;
            <BenchDb<F> as ManagedDb<Context>>::finalize(&mut *guard, merkleized)
                .await
                .unwrap();
        }
        elapsed += start.elapsed();
        next_loc += APPENDS_PER_BATCH + 1;

        if (batch_idx + 1) % PRUNE_EVERY == 0 {
            let start = Instant::now();
            {
                let mut guard = db.write().await;
                let target = <BenchDb<F> as ManagedDb<Context>>::sync_target(&*guard).await;
                <BenchDb<F> as ManagedDb<Context>>::prune(&mut *guard, &target)
                    .await
                    .unwrap();
            }
            elapsed += start.elapsed();
        }
    }

    let db = Arc::try_unwrap(db)
        .ok()
        .expect("benchmark should hold the only db reference")
        .into_inner();
    db.destroy().await.unwrap();
    elapsed
}

async fn bench_managed_preflushed_pipeline<F: Family + 'static>(ctx: &Context) -> Duration {
    let db = open_db::<F>(ctx, "managed-preflushed-pipeline").await;
    let db = Arc::new(AsyncRwLock::new(db));
    let mut elapsed = Duration::ZERO;
    let mut next_loc = 1;
    let mut background_preflush = None;

    for batch_idx in 0..BATCHES {
        let mut batch = <BenchDb<F> as ManagedDb<Context>>::new_batch(&db)
            .await
            .with_inactivity_floor(Location::new(next_loc));
        for append_idx in 0..APPENDS_PER_BATCH {
            batch = batch.append(value(batch_idx, append_idx));
        }
        let merkleized = batch.merkleize().await.unwrap();

        clear_finished_background_preflush(&mut background_preflush);
        let start = Instant::now();
        {
            let mut guard = db.write().await;
            <BenchDb<F> as ManagedDb<Context>>::finalize(&mut *guard, merkleized)
                .await
                .unwrap();
        }
        if background_preflush.is_none() {
            let target = {
                let guard = db.read().await;
                <BenchDb<F> as ManagedDb<Context>>::sync_target(&*guard).await
            };
            background_preflush = Some(spawn_background_preflush(ctx, db.clone(), target));
        }
        elapsed += start.elapsed();
        next_loc += APPENDS_PER_BATCH + 1;

        if (batch_idx + 1) % PRUNE_EVERY == 0 {
            let target = {
                let guard = db.read().await;
                <BenchDb<F> as ManagedDb<Context>>::sync_target(&*guard).await
            };
            let start = Instant::now();
            {
                let mut guard = db.write().await;
                <BenchDb<F> as ManagedDb<Context>>::prune(&mut *guard, &target)
                    .await
                    .unwrap();
            }
            elapsed += start.elapsed();
        }
    }
    await_background_preflush(&mut background_preflush).await;

    let db = Arc::try_unwrap(db)
        .ok()
        .expect("benchmark should hold the only db reference")
        .into_inner();
    db.destroy().await.unwrap();
    elapsed
}

async fn bench_apply_commit_pipeline<F: Family>(ctx: &Context) -> Duration {
    let mut db = open_db::<F>(ctx, "apply-commit-pipeline").await;
    let mut elapsed = Duration::ZERO;
    let mut next_loc = 1;

    for batch_idx in 0..BATCHES {
        let mut batch = db.new_batch();
        for append_idx in 0..APPENDS_PER_BATCH {
            batch = batch.append(value(batch_idx, append_idx));
        }
        let merkleized = batch.merkleize(&db, None, Location::new(next_loc));

        let start = Instant::now();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        elapsed += start.elapsed();
        next_loc += APPENDS_PER_BATCH + 1;

        if (batch_idx + 1) % PRUNE_EVERY == 0 {
            let start = Instant::now();
            db.prune_and_sync(db.sync_boundary()).await.unwrap();
            elapsed += start.elapsed();
        }
    }

    db.destroy().await.unwrap();
    elapsed
}

async fn bench_managed_boundary_stall<F: Family>(ctx: &Context) -> Duration {
    let db = open_db::<F>(ctx, "managed-boundary-stall").await;
    let db = Arc::new(AsyncRwLock::new(db));
    let mut max_boundary = Duration::ZERO;
    let mut next_loc = 1;

    for batch_idx in 0..BATCHES {
        let mut batch = <BenchDb<F> as ManagedDb<Context>>::new_batch(&db)
            .await
            .with_inactivity_floor(Location::new(next_loc));
        for append_idx in 0..APPENDS_PER_BATCH {
            batch = batch.append(value(batch_idx, append_idx));
        }
        let merkleized = batch.merkleize().await.unwrap();

        {
            let mut guard = db.write().await;
            <BenchDb<F> as ManagedDb<Context>>::finalize(&mut *guard, merkleized)
                .await
                .unwrap();
        }
        next_loc += APPENDS_PER_BATCH + 1;

        if (batch_idx + 1) % PRUNE_EVERY == 0 {
            let target = {
                let guard = db.read().await;
                <BenchDb<F> as ManagedDb<Context>>::sync_target(&*guard).await
            };
            let start = Instant::now();
            {
                let mut guard = db.write().await;
                <BenchDb<F> as ManagedDb<Context>>::prune(&mut *guard, &target)
                    .await
                    .unwrap();
            }
            max_boundary = max_boundary.max(start.elapsed());
        }
    }

    let db = Arc::try_unwrap(db)
        .ok()
        .expect("benchmark should hold the only db reference")
        .into_inner();
    db.destroy().await.unwrap();
    max_boundary
}

async fn bench_apply_commit_boundary_stall<F: Family>(ctx: &Context) -> Duration {
    let mut db = open_db::<F>(ctx, "apply-commit-boundary-stall").await;
    let mut max_boundary = Duration::ZERO;
    let mut next_loc = 1;

    for batch_idx in 0..BATCHES {
        let mut batch = db.new_batch();
        for append_idx in 0..APPENDS_PER_BATCH {
            batch = batch.append(value(batch_idx, append_idx));
        }
        let merkleized = batch.merkleize(&db, None, Location::new(next_loc));

        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        next_loc += APPENDS_PER_BATCH + 1;

        if (batch_idx + 1) % PRUNE_EVERY == 0 {
            let start = Instant::now();
            db.prune_and_sync(db.sync_boundary()).await.unwrap();
            max_boundary = max_boundary.max(start.elapsed());
        }
    }

    db.destroy().await.unwrap();
    max_boundary
}

async fn bench_managed_preflushed_boundary_stall<F: Family + 'static>(ctx: &Context) -> Duration {
    let db = open_db::<F>(ctx, "managed-preflushed-boundary-stall").await;
    let db = Arc::new(AsyncRwLock::new(db));
    let mut max_boundary = Duration::ZERO;
    let mut next_loc = 1;
    let mut background_preflush = None;

    for batch_idx in 0..BATCHES {
        let mut batch = <BenchDb<F> as ManagedDb<Context>>::new_batch(&db)
            .await
            .with_inactivity_floor(Location::new(next_loc));
        for append_idx in 0..APPENDS_PER_BATCH {
            batch = batch.append(value(batch_idx, append_idx));
        }
        let merkleized = batch.merkleize().await.unwrap();

        clear_finished_background_preflush(&mut background_preflush);
        {
            let mut guard = db.write().await;
            <BenchDb<F> as ManagedDb<Context>>::finalize(&mut *guard, merkleized)
                .await
                .unwrap();
        }
        if background_preflush.is_none() {
            let target = {
                let guard = db.read().await;
                <BenchDb<F> as ManagedDb<Context>>::sync_target(&*guard).await
            };
            background_preflush = Some(spawn_background_preflush(ctx, db.clone(), target));
        }
        next_loc += APPENDS_PER_BATCH + 1;

        if (batch_idx + 1) % PRUNE_EVERY == 0 {
            let target = {
                let guard = db.read().await;
                <BenchDb<F> as ManagedDb<Context>>::sync_target(&*guard).await
            };
            let start = Instant::now();
            {
                let mut guard = db.write().await;
                <BenchDb<F> as ManagedDb<Context>>::prune(&mut *guard, &target)
                    .await
                    .unwrap();
            }
            max_boundary = max_boundary.max(start.elapsed());
        }
    }
    await_background_preflush(&mut background_preflush).await;

    let db = Arc::try_unwrap(db)
        .ok()
        .expect("benchmark should hold the only db reference")
        .into_inner();
    db.destroy().await.unwrap();
    max_boundary
}

fn bench_finalize(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());

    c.bench_function(
        &format!(
            "{}/case=managed_finalize variant=keyless::fixed::mmb batches={BATCHES} appends={APPENDS_PER_BATCH}",
            module_path!(),
        ),
        |b| {
            b.to_async(&runner).iter_custom(|iters| async move {
                let ctx = context::get::<Context>();
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    total += bench_managed_finalize::<mmb::Family>(&ctx).await;
                }
                total
            });
        },
    );

    c.bench_function(
        &format!(
            "{}/case=apply_commit variant=keyless::fixed::mmb batches={BATCHES} appends={APPENDS_PER_BATCH}",
            module_path!(),
        ),
        |b| {
            b.to_async(&runner).iter_custom(|iters| async move {
                let ctx = context::get::<Context>();
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    total += bench_apply_then_commit::<mmb::Family>(&ctx).await;
                }
                total
            });
        },
    );

    c.bench_function(
        &format!(
            "{}/case=managed_pipeline variant=keyless::fixed::mmb batches={BATCHES} appends={APPENDS_PER_BATCH} prune_every={PRUNE_EVERY} prune_boundaries={PRUNE_BOUNDARIES}",
            module_path!(),
        ),
        |b| {
            b.to_async(&runner).iter_custom(|iters| async move {
                let ctx = context::get::<Context>();
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    total += bench_managed_pipeline::<mmb::Family>(&ctx).await;
                }
                total
            });
        },
    );

    c.bench_function(
        &format!(
            "{}/case=managed_preflush_pipeline variant=keyless::fixed::mmb preflush=sync_start_to cancel=none batches={BATCHES} appends={APPENDS_PER_BATCH} prune_every={PRUNE_EVERY} prune_boundaries={PRUNE_BOUNDARIES}",
            module_path!(),
        ),
        |b| {
            b.to_async(&runner).iter_custom(|iters| async move {
                let ctx = context::get::<Context>();
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    total += bench_managed_preflushed_pipeline::<mmb::Family>(&ctx).await;
                }
                total
            });
        },
    );

    c.bench_function(
        &format!(
            "{}/case=apply_commit_pipeline variant=keyless::fixed::mmb batches={BATCHES} appends={APPENDS_PER_BATCH} prune_every={PRUNE_EVERY} prune_boundaries={PRUNE_BOUNDARIES}",
            module_path!(),
        ),
        |b| {
            b.to_async(&runner).iter_custom(|iters| async move {
                let ctx = context::get::<Context>();
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    total += bench_apply_commit_pipeline::<mmb::Family>(&ctx).await;
                }
                total
            });
        },
    );

    c.bench_function(
        &format!(
            "{}/case=managed_prune_boundary variant=keyless::fixed::mmb metric=max_boundary batches={BATCHES} appends={APPENDS_PER_BATCH} prune_every={PRUNE_EVERY} prune_boundaries={PRUNE_BOUNDARIES}",
            module_path!(),
        ),
        |b| {
            b.to_async(&runner).iter_custom(|iters| async move {
                let ctx = context::get::<Context>();
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    total += bench_managed_boundary_stall::<mmb::Family>(&ctx).await;
                }
                total
            });
        },
    );

    c.bench_function(
        &format!(
            "{}/case=apply_commit_prune_boundary variant=keyless::fixed::mmb metric=max_boundary batches={BATCHES} appends={APPENDS_PER_BATCH} prune_every={PRUNE_EVERY} prune_boundaries={PRUNE_BOUNDARIES}",
            module_path!(),
        ),
        |b| {
            b.to_async(&runner).iter_custom(|iters| async move {
                let ctx = context::get::<Context>();
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    total += bench_apply_commit_boundary_stall::<mmb::Family>(&ctx).await;
                }
                total
            });
        },
    );

    c.bench_function(
        &format!(
            "{}/case=managed_preflush_prune_boundary variant=keyless::fixed::mmb preflush=sync_start_to cancel=none metric=max_boundary batches={BATCHES} appends={APPENDS_PER_BATCH} prune_every={PRUNE_EVERY} prune_boundaries={PRUNE_BOUNDARIES}",
            module_path!(),
        ),
        |b| {
            b.to_async(&runner).iter_custom(|iters| async move {
                let ctx = context::get::<Context>();
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    total += bench_managed_preflushed_boundary_stall::<mmb::Family>(&ctx).await;
                }
                total
            });
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_finalize,
}

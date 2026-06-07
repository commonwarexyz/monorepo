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
    env,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::{Duration, Instant},
};

const PAGE_SIZE: NonZeroU16 = NZU16!(16_384);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(512);
const THREADS: NonZeroUsize = NZUsize!(8);
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(50_000);
const DEFAULT_BATCHES: u64 = 100;
const DEFAULT_APPENDS_PER_BATCH: u64 = 256;
const DEFAULT_PRUNE_EVERY: u64 = 25;
const WRITE_BUFFER_SIZE: NonZeroUsize = NZUsize!(2 * 1024 * 1024);
const ENV_BATCHES: &str = "COMMONWARE_GLUE_FINALIZE_BENCH_BATCHES";
const ENV_APPENDS_PER_BATCH: &str = "COMMONWARE_GLUE_FINALIZE_BENCH_APPENDS_PER_BATCH";
const ENV_PRUNE_EVERY: &str = "COMMONWARE_GLUE_FINALIZE_BENCH_PRUNE_EVERY";

type BenchDb<F> = Db<F, Context, Digest, Sha256, Rayon>;

#[derive(Clone, Copy)]
struct Workload {
    batches: u64,
    appends_per_batch: u64,
    prune_every: u64,
}

impl Workload {
    fn from_env() -> Self {
        Self {
            batches: env_u64(ENV_BATCHES, DEFAULT_BATCHES),
            appends_per_batch: env_u64(ENV_APPENDS_PER_BATCH, DEFAULT_APPENDS_PER_BATCH),
            prune_every: env_u64(ENV_PRUNE_EVERY, DEFAULT_PRUNE_EVERY),
        }
    }

    fn name(self, case: &str, extra: &str) -> String {
        let prefix = if extra.is_empty() {
            String::new()
        } else {
            format!(" {extra}")
        };
        format!(
            "{}/case={case} v=kfix{prefix} blocks={} keys={} prune={}",
            module_path!(),
            self.batches,
            self.appends_per_batch,
            self.prune_every,
        )
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    match env::var(name) {
        Ok(value) => {
            let parsed = value
                .parse()
                .unwrap_or_else(|_| panic!("{name} must be a positive integer"));
            assert!(parsed > 0, "{name} must be non-zero");
            parsed
        }
        Err(env::VarError::NotPresent) => default,
        Err(error) => panic!("failed to read {name}: {error}"),
    }
}

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

async fn bench_managed_finalize<F: Family>(ctx: &Context, workload: Workload) -> Duration {
    let db = open_db::<F>(ctx, "managed-finalize").await;
    let db = Arc::new(AsyncRwLock::new(db));
    let mut elapsed = Duration::ZERO;

    for batch_idx in 0..workload.batches {
        let mut batch = <BenchDb<F> as ManagedDb<Context>>::new_batch(&db).await;
        for append_idx in 0..workload.appends_per_batch {
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

async fn bench_apply_then_commit<F: Family>(ctx: &Context, workload: Workload) -> Duration {
    let mut db = open_db::<F>(ctx, "apply-commit").await;
    let mut elapsed = Duration::ZERO;

    for batch_idx in 0..workload.batches {
        let mut batch = db.new_batch();
        for append_idx in 0..workload.appends_per_batch {
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

async fn bench_apply_only<F: Family>(ctx: &Context, workload: Workload) -> Duration {
    let mut db = open_db::<F>(ctx, "apply-only").await;
    let mut elapsed = Duration::ZERO;

    for batch_idx in 0..workload.batches {
        let mut batch = db.new_batch();
        for append_idx in 0..workload.appends_per_batch {
            batch = batch.append(value(batch_idx, append_idx));
        }
        let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc());

        let start = Instant::now();
        db.apply_batch(merkleized).await.unwrap();
        elapsed += start.elapsed();
    }

    db.destroy().await.unwrap();
    elapsed
}

async fn bench_write_pending_only<F: Family>(ctx: &Context, workload: Workload) -> Duration {
    let mut db = open_db::<F>(ctx, "write-pending-only").await;
    let mut elapsed = Duration::ZERO;

    for batch_idx in 0..workload.batches {
        let mut batch = db.new_batch();
        for append_idx in 0..workload.appends_per_batch {
            batch = batch.append(value(batch_idx, append_idx));
        }
        let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc());
        db.apply_batch(merkleized).await.unwrap();

        let start = Instant::now();
        db.write_pending().await.unwrap();
        elapsed += start.elapsed();
    }

    db.destroy().await.unwrap();
    elapsed
}

async fn bench_commit_only<F: Family>(ctx: &Context, workload: Workload) -> Duration {
    let mut db = open_db::<F>(ctx, "commit-only").await;
    let mut elapsed = Duration::ZERO;

    for batch_idx in 0..workload.batches {
        let mut batch = db.new_batch();
        for append_idx in 0..workload.appends_per_batch {
            batch = batch.append(value(batch_idx, append_idx));
        }
        let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc());
        db.apply_batch(merkleized).await.unwrap();

        let start = Instant::now();
        db.commit().await.unwrap();
        elapsed += start.elapsed();
    }

    db.destroy().await.unwrap();
    elapsed
}

async fn bench_sync_start_pending_only<F: Family>(ctx: &Context, workload: Workload) -> Duration {
    let mut db = open_db::<F>(ctx, "sync-start-pending-only").await;
    let mut elapsed = Duration::ZERO;

    for batch_idx in 0..workload.batches {
        let mut batch = db.new_batch();
        for append_idx in 0..workload.appends_per_batch {
            batch = batch.append(value(batch_idx, append_idx));
        }
        let merkleized = batch.merkleize(&db, None, db.inactivity_floor_loc());
        db.apply_batch(merkleized).await.unwrap();

        let start = Instant::now();
        db.sync_start_pending().await.unwrap();
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

async fn bench_managed_pipeline<F: Family>(ctx: &Context, workload: Workload) -> Duration {
    let db = open_db::<F>(ctx, "managed-pipeline").await;
    let db = Arc::new(AsyncRwLock::new(db));
    let mut elapsed = Duration::ZERO;
    let mut next_loc = 1;

    for batch_idx in 0..workload.batches {
        let mut batch = <BenchDb<F> as ManagedDb<Context>>::new_batch(&db)
            .await
            .with_inactivity_floor(Location::new(next_loc));
        for append_idx in 0..workload.appends_per_batch {
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
        next_loc += workload.appends_per_batch + 1;

        if (batch_idx + 1) % workload.prune_every == 0 {
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

async fn bench_managed_preflushed_pipeline<F: Family + 'static>(
    ctx: &Context,
    workload: Workload,
) -> Duration {
    let db = open_db::<F>(ctx, "managed-preflushed-pipeline").await;
    let db = Arc::new(AsyncRwLock::new(db));
    let mut elapsed = Duration::ZERO;
    let mut next_loc = 1;
    let mut background_preflush = None;

    for batch_idx in 0..workload.batches {
        let mut batch = <BenchDb<F> as ManagedDb<Context>>::new_batch(&db)
            .await
            .with_inactivity_floor(Location::new(next_loc));
        for append_idx in 0..workload.appends_per_batch {
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
        next_loc += workload.appends_per_batch + 1;

        if (batch_idx + 1) % workload.prune_every == 0 {
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

async fn bench_apply_commit_pipeline<F: Family>(ctx: &Context, workload: Workload) -> Duration {
    let mut db = open_db::<F>(ctx, "apply-commit-pipeline").await;
    let mut elapsed = Duration::ZERO;
    let mut next_loc = 1;

    for batch_idx in 0..workload.batches {
        let mut batch = db.new_batch();
        for append_idx in 0..workload.appends_per_batch {
            batch = batch.append(value(batch_idx, append_idx));
        }
        let merkleized = batch.merkleize(&db, None, Location::new(next_loc));

        let start = Instant::now();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        elapsed += start.elapsed();
        next_loc += workload.appends_per_batch + 1;

        if (batch_idx + 1) % workload.prune_every == 0 {
            let start = Instant::now();
            db.prune_and_sync(db.sync_boundary()).await.unwrap();
            elapsed += start.elapsed();
        }
    }

    db.destroy().await.unwrap();
    elapsed
}

async fn bench_managed_boundary_stall<F: Family>(ctx: &Context, workload: Workload) -> Duration {
    let db = open_db::<F>(ctx, "managed-boundary-stall").await;
    let db = Arc::new(AsyncRwLock::new(db));
    let mut max_boundary = Duration::ZERO;
    let mut next_loc = 1;

    for batch_idx in 0..workload.batches {
        let mut batch = <BenchDb<F> as ManagedDb<Context>>::new_batch(&db)
            .await
            .with_inactivity_floor(Location::new(next_loc));
        for append_idx in 0..workload.appends_per_batch {
            batch = batch.append(value(batch_idx, append_idx));
        }
        let merkleized = batch.merkleize().await.unwrap();

        {
            let mut guard = db.write().await;
            <BenchDb<F> as ManagedDb<Context>>::finalize(&mut *guard, merkleized)
                .await
                .unwrap();
        }
        next_loc += workload.appends_per_batch + 1;

        if (batch_idx + 1) % workload.prune_every == 0 {
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

async fn bench_apply_commit_boundary_stall<F: Family>(
    ctx: &Context,
    workload: Workload,
) -> Duration {
    let mut db = open_db::<F>(ctx, "apply-commit-boundary-stall").await;
    let mut max_boundary = Duration::ZERO;
    let mut next_loc = 1;

    for batch_idx in 0..workload.batches {
        let mut batch = db.new_batch();
        for append_idx in 0..workload.appends_per_batch {
            batch = batch.append(value(batch_idx, append_idx));
        }
        let merkleized = batch.merkleize(&db, None, Location::new(next_loc));

        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        next_loc += workload.appends_per_batch + 1;

        if (batch_idx + 1) % workload.prune_every == 0 {
            let start = Instant::now();
            db.prune_and_sync(db.sync_boundary()).await.unwrap();
            max_boundary = max_boundary.max(start.elapsed());
        }
    }

    db.destroy().await.unwrap();
    max_boundary
}

async fn bench_managed_preflushed_boundary_stall<F: Family + 'static>(
    ctx: &Context,
    workload: Workload,
) -> Duration {
    let db = open_db::<F>(ctx, "managed-preflushed-boundary-stall").await;
    let db = Arc::new(AsyncRwLock::new(db));
    let mut max_boundary = Duration::ZERO;
    let mut next_loc = 1;
    let mut background_preflush = None;

    for batch_idx in 0..workload.batches {
        let mut batch = <BenchDb<F> as ManagedDb<Context>>::new_batch(&db)
            .await
            .with_inactivity_floor(Location::new(next_loc));
        for append_idx in 0..workload.appends_per_batch {
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
        next_loc += workload.appends_per_batch + 1;

        if (batch_idx + 1) % workload.prune_every == 0 {
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
    let workload = Workload::from_env();

    c.bench_function(&workload.name("mf", ""), |b| {
        b.to_async(&runner).iter_custom(|iters| async move {
            let ctx = context::get::<Context>();
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += bench_managed_finalize::<mmb::Family>(&ctx, workload).await;
            }
            total
        });
    });

    c.bench_function(&workload.name("ac", ""), |b| {
        b.to_async(&runner).iter_custom(|iters| async move {
            let ctx = context::get::<Context>();
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += bench_apply_then_commit::<mmb::Family>(&ctx, workload).await;
            }
            total
        });
    });

    c.bench_function(&workload.name("apply", ""), |b| {
        b.to_async(&runner).iter_custom(|iters| async move {
            let ctx = context::get::<Context>();
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += bench_apply_only::<mmb::Family>(&ctx, workload).await;
            }
            total
        });
    });

    c.bench_function(&workload.name("write", ""), |b| {
        b.to_async(&runner).iter_custom(|iters| async move {
            let ctx = context::get::<Context>();
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += bench_write_pending_only::<mmb::Family>(&ctx, workload).await;
            }
            total
        });
    });

    c.bench_function(&workload.name("commit", ""), |b| {
        b.to_async(&runner).iter_custom(|iters| async move {
            let ctx = context::get::<Context>();
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += bench_commit_only::<mmb::Family>(&ctx, workload).await;
            }
            total
        });
    });

    c.bench_function(&workload.name("start", "sync=start"), |b| {
        b.to_async(&runner).iter_custom(|iters| async move {
            let ctx = context::get::<Context>();
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += bench_sync_start_pending_only::<mmb::Family>(&ctx, workload).await;
            }
            total
        });
    });

    c.bench_function(&workload.name("mpipe", ""), |b| {
        b.to_async(&runner).iter_custom(|iters| async move {
            let ctx = context::get::<Context>();
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += bench_managed_pipeline::<mmb::Family>(&ctx, workload).await;
            }
            total
        });
    });

    c.bench_function(&workload.name("pfpipe", "pf=start"), |b| {
        b.to_async(&runner).iter_custom(|iters| async move {
            let ctx = context::get::<Context>();
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += bench_managed_preflushed_pipeline::<mmb::Family>(&ctx, workload).await;
            }
            total
        });
    });

    c.bench_function(&workload.name("acpipe", ""), |b| {
        b.to_async(&runner).iter_custom(|iters| async move {
            let ctx = context::get::<Context>();
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += bench_apply_commit_pipeline::<mmb::Family>(&ctx, workload).await;
            }
            total
        });
    });

    c.bench_function(&workload.name("mbound", "metric=max"), |b| {
        b.to_async(&runner).iter_custom(|iters| async move {
            let ctx = context::get::<Context>();
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += bench_managed_boundary_stall::<mmb::Family>(&ctx, workload).await;
            }
            total
        });
    });

    c.bench_function(&workload.name("acbound", "metric=max"), |b| {
        b.to_async(&runner).iter_custom(|iters| async move {
            let ctx = context::get::<Context>();
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += bench_apply_commit_boundary_stall::<mmb::Family>(&ctx, workload).await;
            }
            total
        });
    });

    c.bench_function(&workload.name("pfbound", "pf=start metric=max"), |b| {
        b.to_async(&runner).iter_custom(|iters| async move {
            let ctx = context::get::<Context>();
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total +=
                    bench_managed_preflushed_boundary_stall::<mmb::Family>(&ctx, workload).await;
            }
            total
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_finalize,
}

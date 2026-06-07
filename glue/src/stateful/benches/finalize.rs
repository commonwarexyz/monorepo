use commonware_cryptography::{sha256::Digest, Hasher as _, Sha256};
use commonware_glue::stateful::db::{ManagedDb, Unmerkleized as _};
use commonware_parallel::Rayon;
use commonware_runtime::{
    benchmarks::{context, tokio},
    buffer::paged::CacheRef,
    tokio::{Config, Context},
    Supervisor as _, ThreadPooler,
};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig,
    merkle::{full::Config as MerkleConfig, mmb, Family},
    qmdb::any::{unordered::fixed::Db, FixedConfig as AnyConfig},
    translator::EightCap,
};
use commonware_utils::{sync::AsyncRwLock, NZUsize, NZU16, NZU64};
use criterion::{criterion_group, Criterion};
use std::{
    env,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::{Duration, Instant},
};

const PAGE_SIZE: NonZeroU16 = NZU16!(16_384);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(512);
const THREADS: NonZeroUsize = NZUsize!(8);
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(2_000_000);
const DEFAULT_BLOCKS: u64 = 100;
const DEFAULT_APPENDS_PER_BLOCK: u64 = 100_000;
const WRITE_BUFFER_SIZE: NonZeroUsize = NZUsize!(8 * 1024 * 1024);
const ENV_BLOCKS: &str = "COMMONWARE_GLUE_FINALIZE_BENCH_BATCHES";
const ENV_APPENDS_PER_BLOCK: &str = "COMMONWARE_GLUE_FINALIZE_BENCH_APPENDS_PER_BATCH";
const ENV_WRITE_BUFFER_SIZE: &str = "COMMONWARE_GLUE_FINALIZE_BENCH_WRITE_BUFFER_SIZE";

type BenchDb<F> = Db<F, Context, Digest, Digest, Sha256, EightCap, Rayon>;

#[derive(Clone, Copy)]
struct Workload {
    blocks: u64,
    appends_per_block: u64,
    write_buffer: NonZeroUsize,
}

impl Workload {
    fn from_env() -> Self {
        Self {
            blocks: env_u64(ENV_BLOCKS, DEFAULT_BLOCKS),
            appends_per_block: env_u64(ENV_APPENDS_PER_BLOCK, DEFAULT_APPENDS_PER_BLOCK),
            write_buffer: env_nonzero_usize(ENV_WRITE_BUFFER_SIZE, WRITE_BUFFER_SIZE),
        }
    }

    fn name(self, metric: &str) -> String {
        format!(
            "{}/v=any-fixed metric={metric} blocks={} keys={} buf={}",
            module_path!(),
            self.blocks,
            self.appends_per_block,
            self.write_buffer,
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

fn digest(domain: u8, block: u64, append: u64) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(&[domain]);
    hasher.update(&block.to_be_bytes());
    hasher.update(&append.to_be_bytes());
    hasher.finalize()
}

fn key(block: u64, append: u64) -> Digest {
    digest(b'k', block, append)
}

fn value(block: u64, append: u64) -> Digest {
    digest(b'v', block, append)
}

fn env_nonzero_usize(name: &str, default: NonZeroUsize) -> NonZeroUsize {
    match env::var(name) {
        Ok(value) => {
            let parsed = value
                .parse()
                .unwrap_or_else(|_| panic!("{name} must be a positive integer"));
            NonZeroUsize::new(parsed).unwrap_or_else(|| panic!("{name} must be non-zero"))
        }
        Err(env::VarError::NotPresent) => default,
        Err(error) => panic!("failed to read {name}: {error}"),
    }
}

fn db_config(
    ctx: &Context,
    suffix: &str,
    write_buffer: NonZeroUsize,
) -> AnyConfig<EightCap, Rayon> {
    let page_cache = CacheRef::from_pooler(ctx, PAGE_SIZE, PAGE_CACHE_SIZE);
    AnyConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("merkle-journal-{suffix}"),
            metadata_partition: format!("merkle-metadata-{suffix}"),
            items_per_blob: ITEMS_PER_BLOB,
            write_buffer,
            strategy: ctx.create_strategy(THREADS).unwrap(),
            page_cache: page_cache.clone(),
        },
        journal_config: JournalConfig {
            partition: format!("log-journal-{suffix}"),
            items_per_blob: ITEMS_PER_BLOB,
            page_cache,
            write_buffer,
        },
        translator: EightCap,
    }
}

async fn open_db<F: Family>(ctx: &Context, suffix: &str, workload: Workload) -> BenchDb<F> {
    BenchDb::<F>::init(
        ctx.child("storage"),
        db_config(ctx, suffix, workload.write_buffer),
    )
    .await
    .unwrap()
}

async fn bench_finalize_loop<F: Family + 'static>(ctx: &Context, workload: Workload) -> Duration {
    let db = open_db::<F>(ctx, "finalize-loop", workload).await;
    let db = Arc::new(AsyncRwLock::new(db));
    let start = Instant::now();

    for block_idx in 0..workload.blocks {
        let mut batch = <BenchDb<F> as ManagedDb<Context>>::new_batch(&db).await;
        for append_idx in 0..workload.appends_per_block {
            batch = batch.write(
                key(block_idx, append_idx),
                Some(value(block_idx, append_idx)),
            );
        }
        let merkleized = batch.merkleize().await.unwrap();

        {
            let mut guard = db.write().await;
            <BenchDb<F> as ManagedDb<Context>>::finalize(&mut *guard, merkleized)
                .await
                .unwrap();
        }
    }
    let elapsed = start.elapsed();

    let db = Arc::try_unwrap(db)
        .ok()
        .expect("benchmark should hold the only db reference")
        .into_inner();
    db.destroy().await.unwrap();
    elapsed
}

fn bench_finalize(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    let workload = Workload::from_env();

    c.bench_function(&workload.name("total"), |b| {
        b.to_async(&runner).iter_custom(|iters| async move {
            let ctx = context::get::<Context>();
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                total += bench_finalize_loop::<mmb::Family>(&ctx, workload).await;
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

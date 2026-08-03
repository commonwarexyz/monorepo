use commonware_runtime::{
    Supervisor as _,
    benchmarks::{context, tokio},
    buffer::paged::{CacheRef, atomic_page_size, page_size},
    tokio::Context,
};
use commonware_storage::journal::contiguous::{
    Many, Mutable,
    fixed::{Config as OrdinaryConfig, Journal as OrdinaryJournal},
    v2::{
        MutableV2,
        fixed::{Config as AtomicConfig, Journal as AtomicJournal},
    },
};
use commonware_utils::{NZU64, NZUsize, sequence::FixedBytes};
use criterion::{BenchmarkGroup, Criterion, Throughput, criterion_group, measurement::WallTime};
use std::{
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

const PARTITION: &str = "_COMMONWARE_STORAGE_JOURNAL_FIXED_APPEND_PAIRED";
const ITEMS: u64 = 100_000;
const ITEM_SIZE: usize = 32;
const STEADY_ITEMS_PER_BLOB: NonZeroU64 = NZU64!(1_000_000);
const ROLLOVER_ITEMS_PER_BLOB: NonZeroU64 = NZU64!(100_000);
const PHYSICAL_PAGE_SIZE: u32 = 8_192;
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10_000);
const BATCH_SIZES: [usize; 3] = [1_000, 10_000, 100_000];
const WRITE_BUFFER: NonZeroUsize = NZUsize!(1_024 * 1_024);
static NEXT_ORDER: AtomicU64 = AtomicU64::new(0);

type Item = FixedBytes<ITEM_SIZE>;

#[derive(Clone, Copy)]
enum Target {
    Plain,
    Uno,
}

trait BenchmarkJournal: Sized {
    fn append_batch(self, items: &[Item]) -> impl Future<Output = Self> + Send;
    fn publish(self) -> impl Future<Output = Self> + Send;
    fn destroy(self) -> impl Future<Output = ()> + Send;
}

impl BenchmarkJournal for OrdinaryJournal<Context, Item> {
    async fn append_batch(self, items: &[Item]) -> Self {
        Mutable::append_many(self, Many::Flat(items))
            .await
            .expect("failed to append fixed items")
            .0
    }

    async fn publish(self) -> Self {
        Mutable::commit(self)
            .await
            .expect("failed to publish journal")
    }

    async fn destroy(self) {
        Mutable::destroy(self)
            .await
            .expect("failed to destroy journal");
    }
}

impl BenchmarkJournal for AtomicJournal<Context, Item> {
    async fn append_batch(self, items: &[Item]) -> Self {
        MutableV2::append_many(self, Many::Flat(items))
            .await
            .expect("failed to append fixed items")
            .0
    }

    async fn publish(self) -> Self {
        MutableV2::sync(self)
            .await
            .expect("failed to publish journal")
    }

    async fn destroy(self) {
        MutableV2::destroy(self)
            .await
            .expect("failed to destroy journal");
    }
}

async fn append_and_publish<J>(mut journal: J, items: &[Item], batch_size: usize) -> J
where
    J: BenchmarkJournal,
{
    for batch in items.chunks(batch_size) {
        journal = journal.append_batch(batch).await;
        journal = journal.publish().await;
    }
    journal
}

async fn ordinary_journal(
    context: Context,
    items_per_blob: NonZeroU64,
) -> OrdinaryJournal<Context, Item> {
    let config = OrdinaryConfig {
        partition: PARTITION.into(),
        items_per_blob,
        write_buffer: WRITE_BUFFER,
        page_cache: CacheRef::from_pooler(&context, page_size(PHYSICAL_PAGE_SIZE), PAGE_CACHE_SIZE),
    };
    OrdinaryJournal::init(context, config)
        .await
        .expect("failed to initialize ordinary journal")
}

async fn atomic_journal(
    context: Context,
    items_per_blob: NonZeroU64,
) -> AtomicJournal<Context, Item> {
    let config = AtomicConfig {
        partition: PARTITION.into(),
        items_per_blob,
        page_size: atomic_page_size(PHYSICAL_PAGE_SIZE),
    };
    AtomicJournal::init(context, config)
        .await
        .expect("failed to initialize V2 atomic journal")
}

async fn measure_paired(
    context: Context,
    iterations: u64,
    target: Target,
    batch_size: usize,
    items_per_blob: NonZeroU64,
) -> Duration {
    let items = vec![Item::new([0xA5; ITEM_SIZE]); ITEMS as usize];
    let mut duration = Duration::ZERO;
    for _ in 0..iterations {
        let plain = ordinary_journal(context.child("plain"), items_per_blob).await;
        let uno = atomic_journal(context.child("uno"), items_per_blob).await;
        let plain_first = NEXT_ORDER.fetch_add(1, Ordering::Relaxed).is_multiple_of(2);

        let (plain, plain_duration, uno, uno_duration) = if plain_first {
            let start = Instant::now();
            let plain = append_and_publish(plain, &items, batch_size).await;
            let plain_duration = start.elapsed();
            let start = Instant::now();
            let uno = append_and_publish(uno, &items, batch_size).await;
            (plain, plain_duration, uno, start.elapsed())
        } else {
            let start = Instant::now();
            let uno = append_and_publish(uno, &items, batch_size).await;
            let uno_duration = start.elapsed();
            let start = Instant::now();
            let plain = append_and_publish(plain, &items, batch_size).await;
            (plain, start.elapsed(), uno, uno_duration)
        };
        duration += match target {
            Target::Plain => plain_duration,
            Target::Uno => uno_duration,
        };

        BenchmarkJournal::destroy(plain).await;
        BenchmarkJournal::destroy(uno).await;
    }
    duration
}

fn parameters(
    implementation: &str,
    publication: &str,
    batch_size: usize,
    items_per_blob: NonZeroU64,
) -> String {
    format!(
        "impl={implementation} pub={publication} batch={batch_size} section={}",
        items_per_blob.get(),
    )
}

fn register_case(
    group: &mut BenchmarkGroup<'_, WallTime>,
    runner: &tokio::Runner,
    batch_size: usize,
    items_per_blob: NonZeroU64,
) {
    group.bench_function(
        parameters("plain", "commit", batch_size, items_per_blob),
        |b| {
            b.to_async(runner).iter_custom(|iters| {
                measure_paired(
                    context::get::<Context>(),
                    iters,
                    Target::Plain,
                    batch_size,
                    items_per_blob,
                )
            });
        },
    );

    group.bench_function(parameters("uno", "sync", batch_size, items_per_blob), |b| {
        b.to_async(runner).iter_custom(|iters| {
            measure_paired(
                context::get::<Context>(),
                iters,
                Target::Uno,
                batch_size,
                items_per_blob,
            )
        });
    });
}

fn configure(group: &mut BenchmarkGroup<'_, WallTime>) {
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(10));
    group.throughput(Throughput::Elements(ITEMS));
}

fn bench_fixed_append_paired(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    let mut steady = c.benchmark_group(format!("{}::steady", module_path!()));
    configure(&mut steady);
    for batch_size in BATCH_SIZES {
        register_case(&mut steady, &runner, batch_size, STEADY_ITEMS_PER_BLOB);
    }
    steady.finish();

    let mut rollover = c.benchmark_group(format!("{}::rollover", module_path!()));
    configure(&mut rollover);
    register_case(
        &mut rollover,
        &runner,
        BATCH_SIZES[2],
        ROLLOVER_ITEMS_PER_BLOB,
    );
    rollover.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_fixed_append_paired
}

//! Production-shaped Constantinople state benchmark.
//!
//! Advances a fully seeded database with unique, consecutive ring-account updates. Each timed
//! leaf is applied and non-durably flushed, including any requested pending ancestors. The harness
//! validates staged values, applied operation bounds, root, inactivity/sync boundary, and final
//! readback. It runs on the tokio runtime with EightCap, matching the production validator shape,
//! against the
//! unordered or ordered fixed `any`/`current` DBs over `mmb`, plus the production `any`/`mmr`
//! state shape. Per-iteration output splits staged load, merkleization, and apply/flush, and prints
//! the applied root as a cross-binary parity check.
//!
//! Usage:
//!   cargo bench -p commonware-storage --bench constantinople -- <db> [depth] [iters] [keys] [reads] [read_chunks] [updates] [threads] [page_cache] [warmup]
//!
//! - db: one of "any::unordered::fixed::mmb", "any::unordered::fixed::mmr",
//!   "any::ordered::fixed::mmb",
//!   "any::unordered::variable::mmb", "current::unordered::fixed::mmb", or
//!   "current::ordered::fixed::mmb", matching the qmdb criterion bench variant names
//!   (required; without it the harness no-ops so blanket `cargo bench --benches`
//!   invocations skip it)
//! - depth: number of pending ancestor batches under the timed batch
//! - iters: timed iterations (default 15)
//! - keys: total seeded keys (default 1,000,000)
//! - reads: unique consecutive ring keys loaded per batch (default 32,768)
//! - read_chunks: split reads into `stage` + `expand` chunks (default 1)
//! - updates: leading loaded keys written per batch (default 32,768); set reads and updates to
//!   170,001 to model the accounts touched by 170,000 consecutive transfers
//! - threads: strategy pool threads (default 8)
//! - page_cache: page cache capacity in 4096-byte pages (default 131,072 = 512MiB, enough
//!   to hold the default working set; shrink it to measure miss-heavy regimes)
//! - warmup: untimed full-pipeline iterations before sampling (default 3)

use commonware_cryptography::{DigestOf, Hasher as _, Sha256};
use commonware_parallel::Rayon;
use commonware_runtime::{
    Runner as _, Strategizer as _, Supervisor as _,
    buffer::paged::CacheRef,
    tokio::{Config as RConfig, Context, Runner},
};
use commonware_storage::{
    journal::contiguous::{fixed::Config as FConfig, variable::Config as VConfig},
    merkle::{full, mmb, mmr},
    qmdb::{any::FixedConfig, current::FixedConfig as CurrentFixedConfig},
    translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, TestRng};
use rand::Rng;
use std::{
    fmt::Display,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    str::FromStr,
    time::Instant,
};

type Digest = DigestOf<Sha256>;
const CHUNK_SIZE: usize = 32;
type AnyDb = commonware_storage::qmdb::any::unordered::fixed::Db<
    mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
type AnyMerkleized = std::sync::Arc<
    commonware_storage::qmdb::any::batch::MerkleizedBatch<
        mmb::Family,
        Digest,
        commonware_storage::qmdb::any::unordered::fixed::Update<Digest, Digest>,
        Rayon,
    >,
>;
type AnyMmrDb = commonware_storage::qmdb::any::unordered::fixed::Db<
    mmr::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
type AnyMmrMerkleized = std::sync::Arc<
    commonware_storage::qmdb::any::batch::MerkleizedBatch<
        mmr::Family,
        Digest,
        commonware_storage::qmdb::any::unordered::fixed::Update<Digest, Digest>,
        Rayon,
    >,
>;
type CurrentDb = commonware_storage::qmdb::current::unordered::fixed::Db<
    mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
    Rayon,
>;
type CurrentMerkleized = std::sync::Arc<
    commonware_storage::qmdb::current::batch::MerkleizedBatch<
        mmb::Family,
        Digest,
        commonware_storage::qmdb::any::unordered::fixed::Update<Digest, Digest>,
        CHUNK_SIZE,
        Rayon,
    >,
>;
type AnyOrderedDb = commonware_storage::qmdb::any::ordered::fixed::Db<
    mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
type AnyOrderedMerkleized = std::sync::Arc<
    commonware_storage::qmdb::any::batch::MerkleizedBatch<
        mmb::Family,
        Digest,
        commonware_storage::qmdb::any::ordered::fixed::Update<Digest, Digest>,
        Rayon,
    >,
>;
type CurrentOrderedDb = commonware_storage::qmdb::current::ordered::fixed::Db<
    mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    CHUNK_SIZE,
    Rayon,
>;
type CurrentOrderedMerkleized = std::sync::Arc<
    commonware_storage::qmdb::current::batch::MerkleizedBatch<
        mmb::Family,
        Digest,
        commonware_storage::qmdb::any::ordered::fixed::Update<Digest, Digest>,
        CHUNK_SIZE,
        Rayon,
    >,
>;

type AnyVarDb = commonware_storage::qmdb::any::unordered::variable::Db<
    mmb::Family,
    Context,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;
type AnyVarMerkleized = std::sync::Arc<
    commonware_storage::qmdb::any::batch::MerkleizedBatch<
        mmb::Family,
        Digest,
        commonware_storage::qmdb::any::unordered::variable::Update<Digest, Digest>,
        Rayon,
    >,
>;

const PAGE_SIZE: NonZeroU16 = NZU16!(4096);
const PAGE_CACHE_PAGES: NonZeroUsize = NZUsize!(131_072);
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(10_000_000);
const WRITE_BUFFER: NonZeroUsize = NZUsize!(2 * 1024 * 1024);
const CHURN_BATCHES: u64 = 4;

struct Args {
    depth: u8,
    iters: usize,
    warmup: usize,
    num_keys: u64,
    num_updates: u64,
    num_reads: u64,
    read_chunks: usize,
}

#[derive(Clone)]
struct Mutation {
    index: usize,
    key: Digest,
    value: Digest,
}

#[derive(Clone, Copy)]
struct Timing {
    load_ms: f64,
    merkleize_ms: f64,
    apply_flush_ms: f64,
}

impl Timing {
    fn cycle_ms(self) -> f64 {
        self.load_ms + self.merkleize_ms + self.apply_flush_ms
    }
}

fn key(i: u64) -> Digest {
    Sha256::hash(&[&i.to_le_bytes()])
}

fn positional<T>(raw: &[String], index: usize, name: &str, default: T) -> T
where
    T: FromStr,
    T::Err: Display,
{
    raw.get(index).map_or(default, |value| {
        value
            .parse()
            .unwrap_or_else(|error| panic!("invalid {name} value {value:?}: {error}"))
    })
}

fn ring_mutations(rng: &mut TestRng, cursor: &mut u64, count: u64, num_keys: u64) -> Vec<Mutation> {
    let mutations = (0..count)
        .map(|offset| {
            let index = (*cursor + offset) % num_keys;
            Mutation {
                index: usize::try_from(index).expect("account index must fit usize"),
                key: key(index),
                value: Sha256::hash(&[&rng.next_u32().to_le_bytes()]),
            }
        })
        .collect();

    // Consecutive transfers touch one more account than they contain. Advancing by `count - 1`
    // makes the last recipient of one block the first sender of the next.
    *cursor = (*cursor + count.saturating_sub(1)) % num_keys;
    mutations
}

fn percentile(mut samples: Vec<f64>, q: f64) -> f64 {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[((samples.len() - 1) as f64 * q) as usize]
}

fn mean(samples: impl Iterator<Item = f64>, len: usize) -> f64 {
    samples.sum::<f64>() / len as f64
}

fn report(db: &str, args: &Args, timings: &[Timing]) {
    let cycles: Vec<_> = timings.iter().map(|timing| timing.cycle_ms()).collect();
    let build: Vec<_> = timings
        .iter()
        .map(|timing| timing.load_ms + timing.merkleize_ms)
        .collect();
    let applies: Vec<_> = timings.iter().map(|timing| timing.apply_flush_ms).collect();
    println!(
        "RESULT db={db} depth={} reads={} read_chunks={} updates={} cycle_p10={:.2} cycle_p50={:.2} cycle_mean={:.2} build_p50={:.2} apply_flush_p50={:.2}",
        args.depth,
        args.num_reads,
        args.read_chunks,
        args.num_updates,
        percentile(cycles.clone(), 0.1),
        percentile(cycles.to_vec(), 0.5),
        mean(cycles.into_iter(), timings.len()),
        percentile(build, 0.5),
        percentile(applies, 0.5),
    );
}

macro_rules! expected_boundary {
    (any, $batch:expr) => {
        $batch.bounds().inactivity_floor
    };
    (current, $batch:expr) => {
        $batch.sync_boundary()
    };
}

// One macro body for both db types: their batch APIs match but share no trait, and a bench does
// not warrant inventing one.
macro_rules! run_pipeline {
    ($db:ident, $args:ident, $label:literal, $merkleized:ty, $kind:ident) => {{
        let args = $args;
        let mut db = $db;

        // Seed all keys in one committed batch.
        let seed_start = Instant::now();
        let mut rng = TestRng::new(42);
        let mut batch = db.new_batch();
        let mut expected_values = Vec::with_capacity(
            usize::try_from(args.num_keys).expect("key count must fit usize"),
        );
        for i in 0..args.num_keys {
            let value = Sha256::hash(&[&rng.next_u32().to_le_bytes()]);
            expected_values.push(value);
            batch = batch.write(key(i), Some(value));
        }
        let merkleized = batch.merkleize(&db, None).await.unwrap();
        let (next_db, _) = db.apply_batch(merkleized).await.unwrap();
        db = next_db.commit().await.unwrap();

        // Churn: overwrite batches so inactive ops accumulate above the floor.
        let mut cursor = 0;
        for _ in 0..CHURN_BATCHES {
            let mut batch = db.new_batch();
            let mutations =
                ring_mutations(&mut rng, &mut cursor, args.num_updates, args.num_keys);
            for mutation in &mutations {
                batch = batch.write(mutation.key, Some(mutation.value));
            }
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            (db, _) = db.apply_batch(merkleized).await.unwrap();
            for mutation in mutations {
                expected_values[mutation.index] = mutation.value;
            }
        }
        db = db.commit().await.unwrap();
        db = db.sync().await.unwrap();
        eprintln!("seed+churn done in {:?}", seed_start.elapsed());

        let mut rng = TestRng::new(99);
        let mut timings = Vec::with_capacity(args.iters);
        let mut final_readback_indices = Vec::new();
        let samples = args
            .warmup
            .checked_add(args.iters)
            .expect("warmup plus iterations must fit usize");
        for sample in 0..samples {
            let capture_readback = sample == samples - 1;

            // Build pending ancestors outside the timed leaf. Keep the whole chain alive through
            // apply because parent links are weak while descendant apply owns the raw diffs.
            let mut chain: Vec<$merkleized> = Vec::with_capacity(args.depth as usize);
            for _ in 0..args.depth {
                let mut b = chain
                    .last()
                    .map_or_else(|| db.new_batch(), |p| p.new_batch::<Sha256>());
                let mutations =
                    ring_mutations(&mut rng, &mut cursor, args.num_updates, args.num_keys);
                if capture_readback {
                    final_readback_indices.extend(
                        mutations
                            .iter()
                            .map(|mutation| mutation.index),
                    );
                }
                for mutation in &mutations {
                    b = b.write(mutation.key, Some(mutation.value));
                }
                chain.push(b.merkleize(&db, None).await.unwrap());
                for mutation in mutations {
                    expected_values[mutation.index] = mutation.value;
                }
            }

            let reads = ring_mutations(&mut rng, &mut cursor, args.num_reads, args.num_keys);
            if capture_readback {
                final_readback_indices.extend(reads.iter().map(|mutation| mutation.index));
            }
            let keys: Vec<&Digest> = reads.iter().map(|mutation| &mutation.key).collect();
            let updates: Vec<_> = reads
                .iter()
                .take(args.num_updates as usize)
                .enumerate()
                .map(|(index, mutation)| (index, Some(mutation.value)))
                .collect();
            let new_batch = || {
                chain
                    .last()
                    .map_or_else(|| db.new_batch(), |p| p.new_batch::<Sha256>())
            };

            // The staged batch consumes `(read_index, value)` updates after the caller computes
            // them. Correctness checks run after all measured storage phases so their cache walk
            // cannot alter merkleization or apply/flush timing.
            let load_start = Instant::now();
            let b = new_batch();
            let read_chunks = args.read_chunks.min(keys.len()).max(1);
            let chunk_len = keys.len().div_ceil(read_chunks);
            let mut chunks = keys.chunks(chunk_len);
            let first = chunks.next().expect("reads must be non-empty");
            let (mut values, mut staged) = b.stage(first, &db).await.unwrap();
            for chunk in chunks {
                let (_, more, next) = staged.expand(chunk, &db).await.unwrap();
                values.extend(more);
                staged = next;
            }
            let load = load_start.elapsed();

            let merkleize_start = Instant::now();
            let merkleized = staged
                .merkleize(updates, Vec::new(), None, &db)
                .await
                .unwrap();
            let merkleize = merkleize_start.elapsed();
            let root = merkleized.root();
            let expected_start = merkleized.bounds().db.size;
            let expected_end = merkleized.bounds().tip.size;
            let expected_boundary = expected_boundary!($kind, merkleized);

            let apply_start = Instant::now();
            let (next_db, applied) = db.apply_batch(merkleized).await.unwrap();
            db = next_db.flush().await.unwrap();
            let apply_flush = apply_start.elapsed();
            drop(chain);

            for (value, mutation) in values.iter().zip(&reads) {
                assert_eq!(
                    value.as_ref(),
                    Some(&expected_values[mutation.index]),
                    "staged value diverged for account {}",
                    mutation.index,
                );
            }
            assert_eq!(applied, expected_start..expected_end);
            assert_eq!(db.bounds().end, expected_end);
            assert_eq!(db.root(), root);
            assert_eq!(db.sync_boundary(), expected_boundary);
            for mutation in reads.iter().take(args.num_updates as usize) {
                expected_values[mutation.index] = mutation.value;
            }

            if sample < args.warmup {
                continue;
            }
            let iter = sample - args.warmup;
            let timing = Timing {
                load_ms: load.as_secs_f64() * 1000.0,
                merkleize_ms: merkleize.as_secs_f64() * 1000.0,
                apply_flush_ms: apply_flush.as_secs_f64() * 1000.0,
            };
            println!(
                "iter={iter} cycle={:.2} build={:.2} load={:.2} merkleize={:.2} apply_flush={:.2} root={root} boundary={expected_boundary}",
                timing.cycle_ms(),
                timing.load_ms + timing.merkleize_ms,
                timing.load_ms,
                timing.merkleize_ms,
                timing.apply_flush_ms,
            );
            timings.push(timing);
        }

        // Read back every account touched by the final pending chain. Leaf-only verification can
        // miss an apply-index error on a key written exclusively by an ancestor.
        final_readback_indices.sort_unstable();
        final_readback_indices.dedup();
        let final_keys: Vec<_> = final_readback_indices
            .iter()
            .map(|index| {
                key(u64::try_from(*index).expect("account index must fit u64"))
            })
            .collect();
        let final_key_refs: Vec<_> = final_keys.iter().collect();
        let actual = db.get_many(&final_key_refs).await.unwrap();
        for (value, index) in actual.iter().zip(&final_readback_indices) {
            assert_eq!(
                value.as_ref(),
                Some(&expected_values[*index]),
                "final readback diverged for account {index}",
            );
        }
        db = db.sync().await.unwrap();
        report($label, &args, &timings);
        db.destroy().await.unwrap();
    }};
}

fn main() {
    let raw: Vec<String> = std::env::args().filter(|a| a != "--bench").collect();
    // Run only when explicitly given a db argument. Blanket harness invocations (no positional
    // args, or libtest flags like `--list` or `--output-format bencher` from the benchmark CI)
    // must no-op so `cargo bench --benches` does not seed a million keys or panic on the flags.
    let Some(db_kind) = raw.get(1).cloned() else {
        return;
    };
    if !matches!(
        db_kind.as_str(),
        "any::unordered::fixed::mmb"
            | "any::unordered::fixed::mmr"
            | "any::ordered::fixed::mmb"
            | "any::unordered::variable::mmb"
            | "current::unordered::fixed::mmb"
            | "current::ordered::fixed::mmb"
    ) {
        return;
    }
    let args = Args {
        depth: positional(&raw, 2, "depth", 0),
        iters: positional(&raw, 3, "iters", 15),
        num_keys: positional(&raw, 4, "keys", 1_000_000),
        num_reads: positional(&raw, 5, "reads", 32_768),
        read_chunks: positional(&raw, 6, "read_chunks", 1),
        num_updates: positional(&raw, 7, "updates", 32_768),
        warmup: positional(&raw, 10, "warmup", 3),
    };
    let threads = positional(&raw, 8, "threads", NZUsize!(8));
    let page_cache = positional(&raw, 9, "page_cache", PAGE_CACHE_PAGES);
    assert!(
        args.iters > 0
            && args.num_keys > 0
            && args.num_updates > 0
            && args.num_reads >= args.num_updates
            && args.num_keys >= args.num_reads,
        "iters, keys, and updates must be non-zero, and updates <= reads <= keys"
    );
    assert!(
        args.read_chunks > 0 && args.warmup > 0,
        "read_chunks and warmup must be non-zero"
    );

    eprintln!(
        "constantinople db={db_kind} depth={} warmup={} iters={} keys={} reads={} read_chunks={} updates={} threads={threads} page_cache={page_cache}",
        args.depth,
        args.warmup,
        args.iters,
        args.num_keys,
        args.num_reads,
        args.read_chunks,
        args.num_updates
    );

    Runner::new(RConfig::default()).start(|ctx| async move {
        let pc = CacheRef::from_pooler(&ctx, PAGE_SIZE, page_cache);
        let pc_var = pc.clone();
        let merkle_config = full::Config {
            journal_partition: "constantinople-merkle-journal".into(),
            metadata_partition: "constantinople-merkle-metadata".into(),
            items_per_blob: ITEMS_PER_BLOB,
            write_buffer: WRITE_BUFFER,
            strategy: ctx.strategy(threads),
            page_cache: pc.clone(),
        };
        let journal_config = FConfig {
            partition: "constantinople-log".into(),
            items_per_blob: ITEMS_PER_BLOB,
            page_cache: pc,
            write_buffer: WRITE_BUFFER,
        };
        match db_kind.as_str() {
            "any::unordered::fixed::mmr" => {
                let cfg = FixedConfig {
                    merkle_config,
                    journal_config,
                    translator: EightCap,
                    init_cache_size: Some(NZUsize!(1 << 18)),
                    init_buffer: NZUsize!(1 << 21),
                    init_concurrency: (),
                };
                let db = AnyMmrDb::init(ctx.child("db"), cfg).await.unwrap();
                run_pipeline!(
                    db,
                    args,
                    "any::unordered::fixed::mmr",
                    AnyMmrMerkleized,
                    any
                )
            }
            "current::unordered::fixed::mmb" => {
                let cfg = CurrentFixedConfig {
                    merkle_config,
                    journal_config,
                    grafted_metadata_partition: "constantinople-grafted-metadata".into(),
                    translator: EightCap,
                    init_cache_size: Some(NZUsize!(1 << 18)),
                    init_buffer: NZUsize!(1 << 21),
                    init_concurrency: (),
                };
                let db = CurrentDb::init(ctx.child("db"), cfg).await.unwrap();
                run_pipeline!(
                    db,
                    args,
                    "current::unordered::fixed::mmb",
                    CurrentMerkleized,
                    current
                )
            }
            "current::ordered::fixed::mmb" => {
                let cfg = CurrentFixedConfig {
                    merkle_config,
                    journal_config,
                    grafted_metadata_partition: "constantinople-grafted-metadata".into(),
                    translator: EightCap,
                    init_cache_size: Some(NZUsize!(1 << 18)),
                    init_buffer: NZUsize!(1 << 21),
                    init_concurrency: (),
                };
                let db = CurrentOrderedDb::init(ctx.child("db"), cfg).await.unwrap();
                run_pipeline!(
                    db,
                    args,
                    "current::ordered::fixed::mmb",
                    CurrentOrderedMerkleized,
                    current
                )
            }
            "any::ordered::fixed::mmb" => {
                let cfg = FixedConfig {
                    merkle_config,
                    journal_config,
                    translator: EightCap,
                    init_cache_size: Some(NZUsize!(1 << 18)),
                    init_buffer: NZUsize!(1 << 21),
                    init_concurrency: (),
                };
                let db = AnyOrderedDb::init(ctx.child("db"), cfg).await.unwrap();
                run_pipeline!(
                    db,
                    args,
                    "any::ordered::fixed::mmb",
                    AnyOrderedMerkleized,
                    any
                )
            }
            "any::unordered::variable::mmb" => {
                let cfg = commonware_storage::qmdb::any::VariableConfig {
                    merkle_config,
                    journal_config: VConfig {
                        partition: "constantinople-var-log".into(),
                        items_per_section: ITEMS_PER_BLOB,
                        compression: None,
                        codec_config: ((), ()),
                        page_cache: pc_var,
                        write_buffer: WRITE_BUFFER,
                    },
                    translator: EightCap,
                    init_cache_size: Some(NZUsize!(1 << 18)),
                    init_buffer: NZUsize!(1 << 21),
                    init_concurrency: (),
                };
                let db = AnyVarDb::init(ctx.child("db"), cfg).await.unwrap();
                run_pipeline!(
                    db,
                    args,
                    "any::unordered::variable::mmb",
                    AnyVarMerkleized,
                    any
                )
            }
            _ => {
                let cfg = FixedConfig {
                    merkle_config,
                    journal_config,
                    translator: EightCap,
                    init_cache_size: Some(NZUsize!(1 << 18)),
                    init_buffer: NZUsize!(1 << 21),
                    init_concurrency: (),
                };
                let db = AnyDb::init(ctx.child("db"), cfg).await.unwrap();
                run_pipeline!(db, args, "any::unordered::fixed::mmb", AnyMerkleized, any)
            }
        }
    });
}

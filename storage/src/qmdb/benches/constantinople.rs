//! Constantinople-shape harness: load+write+merkleize at 32k updates / 1M keys.
//!
//! Times the full per-block state pipeline (get_many load, batch writes, merkleize, root) on the
//! tokio runtime with EightCap, matching the production validator shape. Runs against the
//! unordered or ordered fixed `any`/`current` DBs over `mmb`. Prints per-iteration latency with
//! a load/write/merkleize phase split and the speculative root (a cross-binary parity check:
//! any optimization must reproduce identical roots).
//!
//! Usage:
//!   cargo bench -p commonware-storage --bench constantinople -- <db> [depth] [iters] [keys] [updates] [threads]
//!
//! - db: one of "any::unordered::fixed::mmb", "any::ordered::fixed::mmb",
//!   "any::unordered::variable::mmb", "current::unordered::fixed::mmb", or
//!   "current::ordered::fixed::mmb", matching the qmdb criterion bench variant names
//!   (required; without it the harness no-ops so blanket `cargo bench --benches`
//!   invocations skip it)
//! - depth: number of pending ancestor batches under the timed batch
//! - iters: timed iterations (default 15)
//! - keys: total seeded keys (default 1,000,000)
//! - updates: keys written per batch (default 32,768)
//! - threads: strategy pool threads (default 8)

use commonware_cryptography::{Hasher, Sha256};
use commonware_parallel::Rayon;
use commonware_runtime::{
    buffer::paged::CacheRef,
    tokio::{Config as RConfig, Context, Runner},
    Runner as _, Supervisor as _, ThreadPooler as _,
};
use commonware_storage::{
    journal::contiguous::{fixed::Config as FConfig, variable::Config as VConfig},
    merkle::{full, mmb},
    qmdb::{any::FixedConfig, current::FixedConfig as CurrentFixedConfig},
    translator::EightCap,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{
    hint::black_box,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    time::Instant,
};

type Digest = <Sha256 as Hasher>::Digest;
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
    num_keys: u64,
    num_updates: u64,
}

fn key(i: u64) -> Digest {
    Sha256::hash(&i.to_be_bytes())
}

fn gen_muts(rng: &mut StdRng, num_updates: u64, num_keys: u64) -> Vec<(Digest, Digest)> {
    (0..num_updates)
        .map(|_| {
            let idx = rng.next_u64() % num_keys;
            (key(idx), Sha256::hash(&rng.next_u32().to_be_bytes()))
        })
        .collect()
}

fn report(db: &str, depth: u8, mut times_ms: Vec<f64>) {
    times_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p = |q: f64| times_ms[((times_ms.len() - 1) as f64 * q) as usize];
    let mean: f64 = times_ms.iter().sum::<f64>() / times_ms.len() as f64;
    println!(
        "RESULT db={db} depth={depth} p10={:.2} p50={:.2} mean={:.2} max={:.2}",
        p(0.1),
        p(0.5),
        mean,
        times_ms[times_ms.len() - 1]
    );
}

// One macro body for both db types: their batch APIs match but share no trait, and a bench does
// not warrant inventing one.
macro_rules! run_pipeline {
    ($db:ident, $args:ident, $label:literal, $merkleized:ty) => {{
        let args = $args;
        let mut db = $db;

        // Seed all keys in one committed batch.
        let seed_start = Instant::now();
        let mut rng = StdRng::seed_from_u64(42);
        let mut batch = db.new_batch();
        for i in 0..args.num_keys {
            batch = batch.write(key(i), Some(Sha256::hash(&rng.next_u32().to_be_bytes())));
        }
        let merkleized = batch.merkleize(&db, None).await.unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();

        // Churn: overwrite batches so inactive ops accumulate above the floor.
        for _ in 0..CHURN_BATCHES {
            let mut batch = db.new_batch();
            for (k, v) in gen_muts(&mut rng, args.num_updates, args.num_keys) {
                batch = batch.write(k, Some(v));
            }
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
        }
        db.commit().await.unwrap();
        db.sync().await.unwrap();
        eprintln!("seed+churn done in {:?}", seed_start.elapsed());

        let mut rng = StdRng::seed_from_u64(99);
        let mut times_ms: Vec<f64> = Vec::with_capacity(args.iters);
        for iter in 0..args.iters {
            // Pending ancestors are rebuilt per iteration and never applied (untimed). The
            // whole chain is held alive: dropping an uncommitted ancestor before merkleize
            // loses its diff (the parent link is a Weak ref).
            let mut chain: Vec<$merkleized> = Vec::with_capacity(args.depth as usize);
            for _ in 0..args.depth {
                let mut b = chain
                    .last()
                    .map_or_else(|| db.new_batch(), |p| p.new_batch::<Sha256>());
                for (k, v) in gen_muts(&mut rng, args.num_updates, args.num_keys) {
                    b = b.write(k, Some(v));
                }
                chain.push(b.merkleize(&db, None).await.unwrap());
            }

            let muts = gen_muts(&mut rng, args.num_updates, args.num_keys);
            let keys: Vec<&Digest> = muts.iter().map(|(k, _)| k).collect();
            let updates: Vec<_> = muts
                .iter()
                .enumerate()
                .map(|(idx, (_, v))| (idx, *v))
                .collect();
            let new_batch = || {
                chain
                    .last()
                    .map_or_else(|| db.new_batch(), |p| p.new_batch::<Sha256>())
            };

            // Timed: load all touched keys, write the selected keys, merkleize, read root. The
            // load returns a staged batch that consumes `(read_index, value)` pairs after the
            // caller has computed them.
            let start = Instant::now();
            let b = new_batch();
            let (values, staged) = b.get_many_staged(&keys, &db).await.unwrap();
            black_box(&values);
            let t_load = start.elapsed();
            let b = staged.set(&[], &updates);
            let t_write = start.elapsed();
            let merkleized = b.merkleize(&db, None).await.unwrap();
            let root = merkleized.root();
            let elapsed = start.elapsed();

            times_ms.push(elapsed.as_secs_f64() * 1000.0);
            println!(
                "iter={iter} ms={:.2} load={:.2} write={:.2} merk={:.2} root={root}",
                times_ms[iter],
                t_load.as_secs_f64() * 1000.0,
                (t_write - t_load).as_secs_f64() * 1000.0,
                (elapsed - t_write).as_secs_f64() * 1000.0
            );
        }

        report($label, args.depth, times_ms);
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
    if db_kind.starts_with("--") {
        return;
    }
    let args = Args {
        depth: raw.get(2).and_then(|s| s.parse().ok()).unwrap_or(0),
        iters: raw.get(3).and_then(|s| s.parse().ok()).unwrap_or(15),
        num_keys: raw.get(4).and_then(|s| s.parse().ok()).unwrap_or(1_000_000),
        num_updates: raw.get(5).and_then(|s| s.parse().ok()).unwrap_or(32_768),
    };
    let threads: NonZeroUsize = raw
        .get(6)
        .and_then(|s| s.parse().ok())
        .unwrap_or(NZUsize!(8));
    assert!(
        matches!(
            db_kind.as_str(),
            "any::unordered::fixed::mmb"
                | "any::ordered::fixed::mmb"
                | "any::unordered::variable::mmb"
                | "current::unordered::fixed::mmb"
                | "current::ordered::fixed::mmb"
        ),
        "db: any::unordered::fixed::mmb|any::ordered::fixed::mmb|any::unordered::variable::mmb|current::unordered::fixed::mmb|current::ordered::fixed::mmb"
    );
    assert!(
        args.iters > 0 && args.num_keys > 0 && args.num_updates > 0,
        "iters, keys, and updates must be non-zero"
    );

    eprintln!(
        "constantinople db={db_kind} depth={} iters={} keys={} updates={} threads={threads}",
        args.depth, args.iters, args.num_keys, args.num_updates
    );

    Runner::new(RConfig::default()).start(|ctx| async move {
        let pc = CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_PAGES);
        let pc_var = pc.clone();
        let merkle_config = full::Config {
            journal_partition: "constantinople-merkle-journal".into(),
            metadata_partition: "constantinople-merkle-metadata".into(),
            items_per_blob: ITEMS_PER_BLOB,
            write_buffer: WRITE_BUFFER,
            strategy: ctx.create_strategy(threads).unwrap(),
            page_cache: pc.clone(),
        };
        let journal_config = FConfig {
            partition: "constantinople-log".into(),
            items_per_blob: ITEMS_PER_BLOB,
            page_cache: pc,
            write_buffer: WRITE_BUFFER,
        };
        match db_kind.as_str() {
            "current::unordered::fixed::mmb" => {
                let cfg = CurrentFixedConfig {
                    merkle_config,
                    journal_config,
                    grafted_metadata_partition: "constantinople-grafted-metadata".into(),
                    translator: EightCap,
                    init_cache_size: Some(NZUsize!(1 << 18)),
                };
                let db = CurrentDb::init(ctx.child("db"), cfg).await.unwrap();
                run_pipeline!(
                    db,
                    args,
                    "current::unordered::fixed::mmb",
                    CurrentMerkleized
                )
            }
            "current::ordered::fixed::mmb" => {
                let cfg = CurrentFixedConfig {
                    merkle_config,
                    journal_config,
                    grafted_metadata_partition: "constantinople-grafted-metadata".into(),
                    translator: EightCap,
                    init_cache_size: Some(NZUsize!(1 << 18)),
                };
                let db = CurrentOrderedDb::init(ctx.child("db"), cfg).await.unwrap();
                run_pipeline!(
                    db,
                    args,
                    "current::ordered::fixed::mmb",
                    CurrentOrderedMerkleized
                )
            }
            "any::ordered::fixed::mmb" => {
                let cfg = FixedConfig {
                    merkle_config,
                    journal_config,
                    translator: EightCap,
                    init_cache_size: Some(NZUsize!(1 << 18)),
                };
                let db = AnyOrderedDb::init(ctx.child("db"), cfg).await.unwrap();
                run_pipeline!(db, args, "any::ordered::fixed::mmb", AnyOrderedMerkleized)
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
                };
                let db = AnyVarDb::init(ctx.child("db"), cfg).await.unwrap();
                run_pipeline!(db, args, "any::unordered::variable::mmb", AnyVarMerkleized)
            }
            _ => {
                let cfg = FixedConfig {
                    merkle_config,
                    journal_config,
                    translator: EightCap,
                    init_cache_size: Some(NZUsize!(1 << 18)),
                };
                let db = AnyDb::init(ctx.child("db"), cfg).await.unwrap();
                run_pipeline!(db, args, "any::unordered::fixed::mmb", AnyMerkleized)
            }
        }
    });
}

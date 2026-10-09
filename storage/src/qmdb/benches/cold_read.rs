//! Cold random-read harness for QMDB: seeds a large unordered fixed-value `any` DB on the tokio
//! runtime, then times batches of random keys, reporting device statistics from /proc/diskstats
//! alongside each batch (Linux; zeros elsewhere). Pages a batch reads stay in the page cache, so
//! until the cache fills a later batch of the same run finds about
//! `batch * iteration / log pages` of its keys resident; size `keys` so this stays small.
//!
//! Usage:
//!   cargo bench -p commonware-storage --bench cold_read -- key=value ...
//!
//! Without a `phase` argument the harness no-ops, so blanket `cargo bench` invocations (with no
//! arguments, libtest or Criterion flags, or a benchmark name filter) skip it; with one, every
//! argument must be one of the `key=value` options below. Seed once with `phase=seed`, drop the
//! OS page cache, then run `phase=read` variants against the same directory. Always pass the
//! `page` and `logical` the DB was seeded with: reopening it with another page size truncates
//! it. The stage and pipeline modes commit to the DB.
//!
//! - dir: storage directory (default /tmp/qmdb-cold)
//! - keys: seeded keys (default 10,000,000); seed: keys per seeding batch (default 1,000,000)
//! - phase (required): seed, read, both, or blob (raw blob reads of the first log blob through
//!   the runtime, no QMDB or page cache; modes blob_read_at and blob_read_many)
//! - batch: random keys per timed batch (default 1500); iters: timed batches (default 20)
//! - mode: get_many (default), chunked (up to 8 concurrent get_many), get_concurrent (one `get`
//!   per key, joined), get_serial (one `get` at a time), stage (stage, merkleize, apply, commit),
//!   pipeline (prefetch the next batch with get_many while staging this one, then commit),
//!   or sustained (keep `depth` independent get_many batches in flight for 2 x iters batches
//!   and report the whole run: the steady-state device throughput a pipelined caller sees)
//! - page: physical page size, a power of two (default 4096); logical: logical page size
//!   override for unaligned layouts; cache: page cache capacity in pages (default 65,536)
//! - blob: items per blob (default 10,000,000); threads: strategy pool threads (default 8)
//! - workers, blocking: tokio worker and blocking threads (defaults 8 and 512)
//! - disk: /proc/diskstats device name (default nvme1n1); rseed: key sampling seed
//! - depth: batches in flight for the sustained mode (default 2)

use commonware_cryptography::{DigestOf, Hasher as _, Sha256};
use commonware_parallel::Rayon;
use commonware_runtime::{
    Blob as _, ReadOptions, Runner as _, Spawner, Strategizer,
    buffer::paged::{self, CacheRef},
    tokio::{Config as RConfig, Runner},
};
use commonware_storage::{
    Context as Ctx,
    journal::contiguous::fixed::Config as FConfig,
    merkle::{full, mmb},
    qmdb::{any::FixedConfig, floor::Proportional},
    translator::EightCap,
};
use commonware_utils::{NZU64, NZUsize, TestRng};
use futures::{StreamExt as _, future::try_join_all, join, stream::FuturesUnordered};
use rand::{Rng as _, RngExt as _};
use std::{collections::HashMap, hint::black_box, num::NonZeroUsize, time::Instant};

type Digest = DigestOf<Sha256>;
type AnyDb<E> = commonware_storage::qmdb::any::unordered::fixed::Db<
    mmb::Family,
    E,
    Digest,
    Digest,
    Sha256,
    EightCap,
    Rayon,
>;

const WRITE_BUFFER: NonZeroUsize = NZUsize!(2 * 1024 * 1024);
const REPLAY_BUFFER: NonZeroUsize = NZUsize!(2 * 1024 * 1024);

/// Options `main` accepts as `key=value` arguments (see the module docs).
const OPTIONS: [&str; 17] = [
    "dir", "keys", "batch", "iters", "page", "cache", "blob", "workers", "blocking", "mode",
    "disk", "seed", "phase", "threads", "rseed", "logical", "depth",
];

#[derive(Clone)]
struct Args {
    dir: String,
    keys: u64,
    batch: usize,
    iters: usize,
    page: u32,
    cache: usize,
    blob: u64,
    workers: usize,
    blocking: usize,
    mode: String,
    disk: String,
    seed: u64,
    phase: String,
    threads: usize,
    rseed: u64,
    logical: Option<u16>,
    depth: usize,
}

fn key(i: u64) -> Digest {
    Sha256::hash(&[&i.to_be_bytes()])
}

#[derive(Clone, Copy, Default, Debug)]
struct DiskStats {
    reads: u64,
    sectors: u64,
    read_ms: u64,
    io_ms: u64,
    weighted_ms: u64,
}

fn diskstats(disk: &str) -> DiskStats {
    let Ok(s) = std::fs::read_to_string("/proc/diskstats") else {
        return DiskStats::default();
    };
    for line in s.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() > 13 && f[2] == disk {
            return DiskStats {
                reads: f[3].parse().unwrap_or(0),
                sectors: f[5].parse().unwrap_or(0),
                read_ms: f[6].parse().unwrap_or(0),
                io_ms: f[12].parse().unwrap_or(0),
                weighted_ms: f[13].parse().unwrap_or(0),
            };
        }
    }
    DiskStats::default()
}

fn disk_delta(label: &str, before: DiskStats, after: DiskStats, elapsed_ms: f64) -> String {
    let reads = after.reads - before.reads;
    let sectors = after.sectors - before.sectors;
    let read_ms = after.read_ms - before.read_ms;
    let io_ms = after.io_ms - before.io_ms;
    let weighted = after.weighted_ms - before.weighted_ms;
    format!(
        "{label}: dev_reads={reads} kb={} avg_lat_ms={:.3} util={:.0}% avg_qd={:.1} iops={:.0}",
        sectors / 2,
        if reads > 0 {
            read_ms as f64 / reads as f64
        } else {
            0.0
        },
        if elapsed_ms > 0.0 {
            100.0 * io_ms as f64 / elapsed_ms
        } else {
            0.0
        },
        if elapsed_ms > 0.0 {
            weighted as f64 / elapsed_ms
        } else {
            0.0
        },
        if elapsed_ms > 0.0 {
            reads as f64 * 1000.0 / elapsed_ms
        } else {
            0.0
        },
    )
}

fn config<E: Strategizer + commonware_runtime::BufferPooler>(
    ctx: &E,
    args: &Args,
) -> FixedConfig<EightCap, Rayon> {
    let page_size = args.logical.map_or(paged::page_size(args.page), |l| {
        std::num::NonZeroU16::new(l).unwrap()
    });
    let page_cache = CacheRef::from_pooler(ctx, page_size, NZUsize!(args.cache));
    FixedConfig {
        merkle_config: full::Config {
            journal_partition: "cold-merkle".into(),
            metadata_partition: "cold-merkle-meta".into(),
            items_per_blob: NZU64!(args.blob),
            write_buffer: WRITE_BUFFER,
            replay_buffer: REPLAY_BUFFER,
            strategy: ctx.strategy(NZUsize!(args.threads)),
            page_cache: page_cache.clone(),
        },
        journal_config: FConfig {
            partition: "cold-log".into(),
            items_per_blob: NZU64!(args.blob),
            page_cache,
            write_buffer: WRITE_BUFFER,
            replay_buffer: REPLAY_BUFFER,
        },
        translator: EightCap,
        init_cache: Some(NZUsize!(1 << 20)),
        init_buffer: NZUsize!(1 << 22),
        init_concurrency: (),
    }
}

async fn seed<E: Ctx + Spawner>(mut db: AnyDb<E>, args: &Args) -> AnyDb<E> {
    let start = Instant::now();
    let mut rng = TestRng::new(42);
    if *db.bounds().end > 1 {
        eprintln!(
            "db already seeded (bounds={:?}); skipping seed",
            db.bounds()
        );
        return db;
    }
    let mut i = 0u64;
    while i < args.keys {
        let end = (i + args.seed).min(args.keys);
        let mut batch = db.new_batch();
        for k in i..end {
            batch = batch.write(key(k), Some(Sha256::hash(&[&rng.next_u32().to_be_bytes()])));
        }
        let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
        let (next, _) = db.apply_batch(merkleized).await.unwrap();
        db = next.commit().await.unwrap();
        i = end;
        if (i / args.seed).is_multiple_of(10) {
            eprintln!("seeded {i} keys in {:?}", start.elapsed());
        }
    }
    let db = db.sync().await.unwrap();
    eprintln!("seed done: {} keys in {:?}", args.keys, start.elapsed());
    db
}

fn percentile(v: &mut [f64], q: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() - 1) as f64 * q) as usize]
}

async fn read_phase<E: Ctx + Spawner>(mut db: AnyDb<E>, args: &Args) -> AnyDb<E> {
    let mut rng = TestRng::new(args.rseed);
    let mut times = Vec::new();
    // Pre-generate every batch's keys so a pipeline iteration can prefetch the next batch.
    let batches: Vec<Vec<Digest>> = (0..args.iters + 1)
        .map(|_| {
            let mut keys: Vec<Digest> = (0..args.batch)
                .map(|_| key(rng.random_range(0..args.keys)))
                .collect();
            keys.sort();
            keys.dedup();
            keys
        })
        .collect();
    for iter in 0..args.iters {
        let keys = &batches[iter];
        let refs: Vec<&Digest> = keys.iter().collect();
        let before = diskstats(&args.disk);
        let start = Instant::now();
        let mut detail = String::new();
        match args.mode.as_str() {
            "get_many" => {
                let values = db.get_many(&refs).await.unwrap();
                assert!(values.iter().all(|v| v.is_some()));
                black_box(values);
            }
            "get_serial" => {
                for k in &refs {
                    let value = db.get(k).await.unwrap();
                    assert!(value.is_some());
                    black_box(value);
                }
            }
            "get_concurrent" => {
                let values = try_join_all(refs.iter().map(|k| db.get(k))).await.unwrap();
                assert!(values.iter().all(|value| value.is_some()));
                black_box(values);
            }
            "chunked" => {
                let chunk = refs.len().div_ceil(8).max(1);
                let values = try_join_all(refs.chunks(chunk).map(|c| db.get_many(c)))
                    .await
                    .unwrap();
                assert!(values.iter().flatten().all(|value| value.is_some()));
                black_box(values);
            }
            "stage" => {
                let (values, staged) = db.new_batch().stage(&refs, &db).await.unwrap();
                assert!(values.iter().all(|value| value.is_some()));
                black_box(&values);
                let t_stage = start.elapsed();
                let updates: Vec<(usize, Option<Digest>)> = (0..refs.len())
                    .map(|i| {
                        let v = (iter as u64) * 1_000_000 + i as u64;
                        (i, Some(Sha256::hash(&[&v.to_be_bytes()])))
                    })
                    .collect();
                let merkleized = staged
                    .merkleize(updates, Vec::new(), None, &db, &mut Proportional)
                    .await
                    .unwrap();
                let t_merk = start.elapsed();
                let (next, _) = db.apply_batch(merkleized).await.unwrap();
                db = next.commit().await.unwrap();
                let t_commit = start.elapsed();
                detail = format!(
                    " stage={:.2} merkleize={:.2} apply+commit={:.2}",
                    t_stage.as_secs_f64() * 1000.0,
                    (t_merk - t_stage).as_secs_f64() * 1000.0,
                    (t_commit - t_merk).as_secs_f64() * 1000.0
                );
            }
            "pipeline" => {
                // Prefetch the next batch's keys (as an app would, given the key list ahead of
                // execution) while staging this batch, which was prefetched one iteration ago.
                let next_refs: Vec<&Digest> = batches[iter + 1].iter().collect();
                let prefetch = async {
                    if iter + 1 < args.iters {
                        let t = Instant::now();
                        let v = db.get_many(&next_refs).await.unwrap();
                        assert!(v.iter().all(|value| value.is_some()));
                        black_box(v);
                        t.elapsed()
                    } else {
                        std::time::Duration::ZERO
                    }
                };
                let stage = async {
                    let t = Instant::now();
                    let out = db.new_batch().stage(&refs, &db).await.unwrap();
                    (out, t.elapsed())
                };
                let (t_prefetch, ((values, staged), t_stage)) = join!(prefetch, stage);
                assert!(values.iter().all(|value| value.is_some()));
                black_box(&values);
                let updates: Vec<(usize, Option<Digest>)> = (0..refs.len())
                    .map(|i| {
                        let v = (iter as u64) * 1_000_000 + i as u64;
                        (i, Some(Sha256::hash(&[&v.to_be_bytes()])))
                    })
                    .collect();
                let t0 = Instant::now();
                let merkleized = staged
                    .merkleize(updates, Vec::new(), None, &db, &mut Proportional)
                    .await
                    .unwrap();
                let t_merk = t0.elapsed();
                let (next, _) = db.apply_batch(merkleized).await.unwrap();
                db = next.commit().await.unwrap();
                let t_commit = t0.elapsed();
                detail = format!(
                    " prefetch_next={:.2} stage={:.2} merkleize={:.2} apply+commit={:.2}",
                    t_prefetch.as_secs_f64() * 1000.0,
                    t_stage.as_secs_f64() * 1000.0,
                    t_merk.as_secs_f64() * 1000.0,
                    (t_commit - t_merk).as_secs_f64() * 1000.0
                );
            }
            "sustained" => {
                // Keep `depth` independent batches in flight for the whole run, refilling as each
                // completes, as a pipelined application does; one iteration covers all batches.
                let depth = args.depth;
                let total = args.iters * 2;
                let mut rng2 = TestRng::new(args.rseed.wrapping_add(99));
                let pool: Vec<Vec<Digest>> = (0..total)
                    .map(|_| {
                        let mut keys: Vec<Digest> = (0..args.batch)
                            .map(|_| key(rng2.random_range(0..args.keys)))
                            .collect();
                        keys.sort();
                        keys.dedup();
                        keys
                    })
                    .collect();
                let pool = &pool;
                let db_ref = &db;
                let read_batch = move |i: usize| async move {
                    let refs: Vec<&Digest> = pool[i].iter().collect();
                    let values = db_ref.get_many(&refs).await.unwrap();
                    assert!(values.iter().all(|value| value.is_some()));
                    values.len()
                };
                let mut next = 0;
                let mut inflight = FuturesUnordered::new();
                while inflight.len() < depth && next < total {
                    inflight.push(read_batch(next));
                    next += 1;
                }

                // Time the run from its first read; generating the key pool above is setup.
                let before = diskstats(&args.disk);
                let start = Instant::now();
                let mut done = 0;
                while let Some(n) = inflight.next().await {
                    black_box(n);
                    done += 1;
                    if next < total {
                        inflight.push(read_batch(next));
                        next += 1;
                    }
                }
                detail = format!(
                    " depth={depth} batches={done} ms_per_batch={:.2}",
                    start.elapsed().as_secs_f64() * 1000.0 / done as f64
                );
                drop(inflight);
                // One sustained run is the whole measurement.
                let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                let after = diskstats(&args.disk);
                println!(
                    "sustained: {detail} | total_ms={elapsed:.1} | {}",
                    disk_delta("disk", before, after, elapsed)
                );
                return db;
            }
            other => panic!("unknown mode {other}"),
        }
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        let after = diskstats(&args.disk);
        times.push(elapsed);
        println!(
            "iter={iter} keys={} ms={elapsed:.2}{detail} | {}",
            refs.len(),
            disk_delta("disk", before, after, elapsed)
        );
    }
    let mut t = times.clone();
    println!(
        "RESULT mode={} keys={} batch={} page={} cache={} blob={} workers={} blocking={} p50={:.2} mean={:.2} min={:.2} max={:.2}",
        args.mode,
        args.keys,
        args.batch,
        args.page,
        args.cache,
        args.blob,
        args.workers,
        args.blocking,
        percentile(&mut t, 0.5),
        times.iter().sum::<f64>() / times.len() as f64,
        percentile(&mut t, 0.0),
        percentile(&mut t, 1.0),
    );
    db
}

fn main() {
    let raw: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| a != "--bench")
        .collect();
    if !raw.iter().any(|a| a.starts_with("phase=")) {
        return;
    }
    let kv: HashMap<String, String> = raw
        .iter()
        .map(|a| {
            let (k, v) = a
                .split_once('=')
                .unwrap_or_else(|| panic!("expected key=value, got {a}"));
            assert!(OPTIONS.contains(&k), "unknown option {k}");
            (k.to_string(), v.to_string())
        })
        .collect();
    let get = |k: &str, d: &str| kv.get(k).cloned().unwrap_or_else(|| d.to_string());
    let args = Args {
        dir: get("dir", "/tmp/qmdb-cold"),
        keys: get("keys", "10000000").parse().unwrap(),
        batch: get("batch", "1500").parse().unwrap(),
        iters: get("iters", "20").parse().unwrap(),
        page: get("page", "4096").parse().unwrap(),
        cache: get("cache", "65536").parse().unwrap(),
        blob: get("blob", "10000000").parse().unwrap(),
        workers: get("workers", "8").parse().unwrap(),
        blocking: get("blocking", "512").parse().unwrap(),
        mode: get("mode", "get_many"),
        disk: get("disk", "nvme1n1"),
        seed: get("seed", "1000000").parse().unwrap(),
        phase: kv["phase"].clone(),
        threads: get("threads", "8").parse().unwrap(),
        rseed: get("rseed", "1234").parse().unwrap(),
        logical: kv.get("logical").map(|v| v.parse().unwrap()),
        depth: get("depth", "2").parse().unwrap(),
    };
    assert!(
        ["seed", "read", "both", "blob"].contains(&args.phase.as_str()),
        "unknown phase {}",
        args.phase
    );
    eprintln!(
        "cold_read args: dir={} keys={} batch={} iters={} page={} cache={} blob={} workers={} blocking={} mode={} disk={} phase={}",
        args.dir,
        args.keys,
        args.batch,
        args.iters,
        args.page,
        args.cache,
        args.blob,
        args.workers,
        args.blocking,
        args.mode,
        args.disk,
        args.phase
    );
    let cfg = RConfig::default()
        .with_worker_threads(args.workers)
        .with_max_blocking_threads(args.blocking)
        .with_storage_directory(args.dir.clone());
    Runner::new(cfg).start(|ctx| run(ctx, args));
}

/// Raw blob reads through the runtime's storage, bypassing QMDB and the page cache: `batch`
/// random 4 KiB physical pages of the log's first data blob per iteration, issued either as
/// concurrent `read_at` calls (one blocking task per read on tokio) or as one `read_many`.
async fn blob_phase<E: Ctx>(ctx: &E, args: &Args) {
    let (blob, size) = ctx
        .open("cold-log-blobs", &0u64.to_be_bytes())
        .await
        .expect("open first log blob");
    let pages = size / 4096;
    eprintln!("blob phase: blob size {size} ({pages} pages)");
    let blob = std::sync::Arc::new(blob);
    let mut rng = TestRng::new(args.rseed);
    let mut times = Vec::new();
    for iter in 0..args.iters {
        let mut offsets: Vec<u64> = (0..args.batch)
            .map(|_| rng.random_range(0..pages) * 4096)
            .collect();
        offsets.sort_unstable();
        offsets.dedup();
        let before = diskstats(&args.disk);
        let start = Instant::now();
        match args.mode.as_str() {
            "blob_read_at" => {
                let mut reads: FuturesUnordered<_> = offsets
                    .iter()
                    .map(|&offset| blob.read_at(offset, 4096, ReadOptions::DONT_CACHE))
                    .collect();
                while let Some(read) = reads.next().await {
                    black_box(read.unwrap());
                }
            }
            "blob_read_many" => {
                let ranges: Vec<(u64, usize)> = offsets.iter().map(|&o| (o, 4096)).collect();
                let mut count = 0;
                let mut reads = std::pin::pin!(blob.read_many(&ranges, ReadOptions::DONT_CACHE));
                while let Some(read) = reads.next().await {
                    black_box(read.unwrap());
                    count += 1;
                }
                assert_eq!(count, ranges.len());
            }
            other => panic!("unknown blob mode {other}"),
        }
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        let after = diskstats(&args.disk);
        times.push(elapsed);
        println!(
            "iter={iter} reads={} ms={elapsed:.2} | {}",
            offsets.len(),
            disk_delta("disk", before, after, elapsed)
        );
    }
    let mut t = times.clone();
    println!(
        "RESULT mode={} batch={} p50={:.2} mean={:.2} min={:.2} max={:.2}",
        args.mode,
        args.batch,
        percentile(&mut t, 0.5),
        times.iter().sum::<f64>() / times.len() as f64,
        percentile(&mut t, 0.0),
        percentile(&mut t, 1.0),
    );
}

async fn run<E: Ctx + Strategizer>(ctx: E, args: Args) {
    if args.phase == "blob" {
        blob_phase(&ctx, &args).await;
        return;
    }
    {
        let start = Instant::now();
        let db = AnyDb::<E>::init(ctx.child("db"), config(&ctx, &args), None)
            .await
            .unwrap();
        eprintln!("init: {:?} bounds={:?}", start.elapsed(), db.bounds());
        if *db.bounds().end > 1 || args.phase == "read" {
            // Sequential seeding commits a prefix of the keyspace before any timed updates.
            let last = args.keys.checked_sub(1).expect("keys must be positive");
            assert!(
                db.get(&key(last)).await.unwrap().is_some(),
                "database seed is incomplete; seed a fresh directory"
            );
        }
        let db = if args.phase != "read" {
            seed(db, &args).await
        } else {
            db
        };
        let db = if args.phase != "seed" {
            read_phase(db, &args).await
        } else {
            db
        };
        drop(db);
    }
}

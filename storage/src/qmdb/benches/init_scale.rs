//! Standalone, opt-in large-scale measurement of two QMDB operations at multi-GB scale: building a
//! database (`generate`) and reopening it, i.e. rebuilding the snapshot (`bench`), with the
//! init-time `(location -> key)` cache off vs on.
//!
//! The criterion init benchmark ([init](super::init)) can't reach these sizes: it resamples, and the
//! database is multi-GB. This binary instead builds a *real* on-disk database once and then times a
//! *real* reopen ([`Db::init`], i.e. `build_snapshot_from_log`) at several cache sizes, so the
//! cache's effect on the redundant collision-resolution log reads shows at scale.
//!
//! Generation and benchmarking are split so the (multi-minute, multi-GB) database is built once and
//! reused across many reopen runs -- but generation is itself an interesting benchmark: building a
//! database of this size is a large-scale seed/churn/commit workload, and `generate` reports its
//! elapsed build time. A folder names the database's on-disk location:
//!
//! ```text
//! cargo bench -p commonware-storage --bench init_scale --features test-traits -- generate /tmp/db 50000000 250000000
//! cargo bench -p commonware-storage --bench init_scale --features test-traits -- bench    /tmp/db
//! cargo bench -p commonware-storage --bench init_scale --features test-traits -- destroy  /tmp/db
//! ```
//!
//! `generate` applies `num_updates` random updates (~1 in `DELETE_FREQUENCY` are deletes) over a
//! `keyspace`-key index space, sampling each key uniformly or via Zipf -- there is no separate seed
//! phase, so the populated set fills organically as keys are sampled. The optional `zipf_exponent`
//! arg selects the distribution -- omitted is the default Zipf (`KEY_ZIPF_EXPONENT`), `0` is uniform
//! -- so a uniform and a skewed database differ only in that distribution. It then prunes and syncs,
//! reporting the total build time.
//!
//! `bench` reopens it (read-only) and reports init time two ways: a cache sweep (off / a quarter of
//! the replay region / the whole region) on the serial path, then a parallelism sweep (1/2/4/8/auto
//! workers) at a full-coverage cache, isolating the parallel-build speedup from the cache effect. It
//! also reports the replay-region size `R`, and uses the P=3 partitioned ordered index (the inline-SoA
//! config for large key sets) so the parallel `build_snapshot` override is exercised; `flat` reopens
//! with the non-partitioned index (serial) as a regression check.
//!
//! `bench`/`parallel` warm the OS file cache by reopening repeatedly in one process, so their numbers
//! are warm-cache. For the realistic cold-cache case (init at process start), use `one`, which does
//! exactly one reopen per process so an external driver can drop the OS cache (`sudo purge` on macOS)
//! before each datapoint:
//!
//! ```text
//! cargo bench -p commonware-storage --bench init_scale --features test-traits -- one /tmp/db <cache> <parallelism>
//! ```

#[allow(dead_code, unused_imports, unused_macros)]
#[path = "common.rs"]
mod common;

use common::{any_fix_cfg_with, gen_random_kv, make_fixed_value, AnyOFixDb, AnyOFixP3Db};
use commonware_runtime::{
    tokio::{Config, Runner},
    Runner as _, Supervisor as _,
};
use commonware_storage::{merkle::mmr::Family as Mmr, qmdb::any::traits::DbAny as _};
use commonware_utils::{NZUsize, NZU64};
use std::{
    io::Write as _,
    num::{NonZeroU64, NonZeroUsize},
    time::{Duration, Instant},
};

/// Items per blob for the generated database. Much larger than the shared bench default (50k) so a
/// multi-GB database is split across far fewer blob files, which keeps the partition-directory scan
/// on reopen cheap. Note this only reduces the file count, not the on-disk byte growth.
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(1_000_000);

/// Page cache size, realistic for a multi-GB database rather than the shared bench default of 8 MB
/// (512 pages). Both `generate` and `bench` use it, so the init-cache benefit is measured on top of
/// a realistic page cache instead of an unrealistically tiny one. 65536 * 16 KiB = 1 GiB.
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(65536);

/// Commit (and prune-eligible) cadence during population.
const COMMIT_FREQUENCY: u32 = 10_000;

/// Prune to the inactivity floor every this many commits during population, so the on-disk log stays
/// bounded to roughly the active region instead of accumulating every re-appended operation until
/// the end. At `COMMIT_FREQUENCY` this is ~1 prune per `COMMIT_FREQUENCY * PRUNE_FREQUENCY` ops.
const PRUNE_FREQUENCY: u32 = 100;

/// Zipf exponent for update/delete key selection: churn follows a power law (a hot subset of keys is
/// updated far more than the long tail) rather than uniform, which is more representative of real
/// workloads. Higher = more skew; ~1.0 is classic Zipf (near YCSB's 0.99).
const KEY_ZIPF_EXPONENT: f64 = 1.0;

/// Worker counts to sweep when timing the parallel snapshot build. `1` is the serial path (the
/// in-override fast path that calls `build_snapshot_from_log` directly); higher values fan out across
/// that many async worker tasks. `0` (auto, from the runtime's parallelism) is reported separately.
const PARALLELISM: [usize; 4] = [1, 2, 4, 8];

fn usage() {
    eprintln!(
        "usage:\n  generate <folder> <keyspace> <num_updates> [zipf_exponent]   build a database (omit exponent => zipf 1.0; 0 => uniform)\n  bench     <folder>                     reopen + time init: cache sweep then parallelism sweep\n  parallel  <folder>                     reopen + time init: parallelism sweep only (cache=R)\n  one       <folder> <cache> <workers>   reopen + time a single init (for cold-cache drivers)\n  flat      <folder>                     reopen with the flat index, serial, cache off/R (regression check)\n  destroy   <folder>                     delete the database"
    );
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match argv.first().map(String::as_str) {
        Some("generate") => match (
            argv.get(1),
            argv.get(2).and_then(|a| a.parse().ok()),
            argv.get(3).and_then(|a| a.parse().ok()),
        ) {
            (Some(folder), Some(keyspace), Some(num_updates)) => {
                // Optional zipf exponent (5th arg): omitted => default skew (KEY_ZIPF_EXPONENT);
                // `0` => uniform sampling (`None`).
                let zipf_exponent = match argv.get(4).map(|a| a.parse::<f64>()) {
                    None => Some(KEY_ZIPF_EXPONENT),
                    Some(Ok(e)) if e > 0.0 => Some(e),
                    Some(Ok(_)) => None,
                    Some(Err(_)) => {
                        usage();
                        return;
                    }
                };
                generate(folder, keyspace, num_updates, zipf_exponent)
            }
            _ => usage(),
        },
        Some("bench") => match argv.get(1) {
            Some(folder) => bench(folder),
            None => usage(),
        },
        Some("parallel") => match argv.get(1) {
            Some(folder) => bench_parallel(folder),
            None => usage(),
        },
        Some("one") => match (
            argv.get(1),
            argv.get(2).and_then(|a| a.parse().ok()),
            argv.get(3).and_then(|a| a.parse().ok()),
        ) {
            (Some(folder), Some(cache), Some(parallelism)) => bench_one(folder, cache, parallelism),
            _ => usage(),
        },
        Some("flat") => match argv.get(1) {
            Some(folder) => bench_flat(folder),
            None => usage(),
        },
        Some("destroy") => match argv.get(1) {
            Some(folder) => destroy(folder),
            None => usage(),
        },
        _ => usage(),
    }
}

/// Build a database at `folder` by applying `num_updates` random updates over a `keyspace`-key index
/// space, leaving it on disk for later `bench` runs. Reports the elapsed build time -- a large-scale
/// churn/commit benchmark in its own right, not just setup for the reopen measurement.
///
/// `zipf_exponent` sets the key distribution: `None` is uniform, `Some(e)` is Zipf with exponent `e`.
/// The populated set fills organically as updates sample the keyspace (no separate seed phase).
fn generate(folder: &str, keyspace: u64, num_updates: u64, zipf_exponent: Option<f64>) {
    if keyspace == 0 {
        eprintln!("keyspace must be > 0");
        return;
    }
    if db_dir_nonempty(folder) {
        eprintln!("{folder} already contains data; `destroy` it first or pick a new folder");
        return;
    }
    let cfg = Config::default().with_storage_directory(folder);
    let elapsed = Runner::new(cfg).start(|ctx| async move {
        // Generate with the flat index: it is much faster to build than P=3 at this keyspace (P=3 is
        // ~3 keys/partition here, so its merkleize floor-scan crawls), and the on-disk log is
        // P-agnostic, so `bench`/`parallel`/`one` still reopen it as P=3 to exercise the parallel build.
        let mut db = AnyOFixDb::<Mmr>::init(
            ctx.child("storage"),
            any_fix_cfg_with(&ctx, ITEMS_PER_BLOB, PAGE_CACHE_SIZE),
        )
        .await
        .unwrap();
        // Time the build itself (updates + prune + sync); opening the empty db above is cheap.
        let start = Instant::now();
        gen_random_kv::<Mmr, _>(
            &mut db,
            0, // num_elements: no seed phase; the keyspace fills organically as updates sample it
            num_updates,
            Some(COMMIT_FREQUENCY),
            None, // seed_batch
            Some(PRUNE_FREQUENCY),
            zipf_exponent,
            Some(keyspace),
            make_fixed_value,
        )
        .await;
        db.prune(db.sync_boundary()).await.unwrap();
        db.sync().await.unwrap();
        start.elapsed()
    });
    println!("generated {num_updates} updates over keyspace {keyspace} at {folder} in {elapsed:?}");
}

/// Reopen the database at `folder` (read-only) and time `init`. First sweeps the init cache (off, a
/// quarter of the replay region, and the whole region) at the serial worker count, then sweeps the
/// parallel worker count at a full-coverage cache so the parallel-build speedup is isolated from the
/// cache effect.
fn bench(folder: &str) {
    if !db_dir_nonempty(folder) {
        eprintln!(
            "no database at {folder}; run `generate {folder} <keyspace> <num_updates>` first"
        );
        return;
    }
    let cfg = Config::default().with_storage_directory(folder);

    // No-cache, serial baseline; also learn the replay region R (ops above the inactivity floor) --
    // what the location cache must cover to avoid eviction (a key-cache would need only the key count).
    let (baseline, region) = time_init(&cfg, None, 1);
    if region == 0 {
        eprintln!(
            "database at {folder} is empty; run `generate {folder} <keyspace> <num_updates>` first"
        );
        return;
    }
    println!("init_scale: {folder}  (any::ordered::fixed::p3::mmr)");
    println!("  replay region R = {region} ops");
    println!("  cache sweep (serial, parallelism=1):");
    println!("    cache=off          : {baseline:?}");
    let _ = std::io::stdout().flush();
    for cache_size in [
        NonZeroUsize::new((region / 4) as usize),
        NonZeroUsize::new(region as usize),
    ] {
        let (elapsed, _) = time_init(&cfg, cache_size, 1);
        println!("    cache={cache_size:?}: {elapsed:?}");
        let _ = std::io::stdout().flush();
    }

    // Parallelism sweep at a full-coverage cache (so per-worker cache misses don't dominate).
    println!("  parallelism sweep (cache=R):");
    for parallelism in PARALLELISM {
        let (elapsed, _) = time_init(&cfg, NonZeroUsize::new(region as usize), parallelism);
        println!("    parallelism={parallelism:>2}     : {elapsed:?}");
        let _ = std::io::stdout().flush();
    }
    // Auto worker count (derived from the runtime's available parallelism).
    let (elapsed, _) = time_init(&cfg, NonZeroUsize::new(region as usize), 0);
    println!("    parallelism=auto   : {elapsed:?}");
    let _ = std::io::stdout().flush();
}

/// Reopen the database at `folder` (read-only) and time only the parallelism sweep at a
/// full-coverage cache. The single serial `cache=0` init that learns `R` is not parallelism-sensitive,
/// so this keeps the contention-sensitive measurements (the worker-count sweep) to a short window --
/// useful when the machine must be kept quiet only for those runs.
fn bench_parallel(folder: &str) {
    let cfg = Config::default().with_storage_directory(folder);

    // Serial, cache-off init just to learn the replay region R (so the sweep can size cache=R).
    let (_, region) = time_init(&cfg, None, 1);
    if region == 0 {
        eprintln!("no database at {folder}; run `generate {folder} <elements>` first");
        return;
    }
    println!("init_scale (parallel-only): {folder}  (any::ordered::fixed::p3::mmr)");
    println!("  replay region R = {region} ops");
    println!("  parallelism sweep (cache=R):");
    let _ = std::io::stdout().flush();
    for parallelism in PARALLELISM {
        let (elapsed, _) = time_init(&cfg, NonZeroUsize::new(region as usize), parallelism);
        println!("    parallelism={parallelism:>2}     : {elapsed:?}");
        let _ = std::io::stdout().flush();
    }
    let (elapsed, _) = time_init(&cfg, NonZeroUsize::new(region as usize), 0);
    println!("    parallelism=auto   : {elapsed:?}");
    let _ = std::io::stdout().flush();
}

/// Time exactly one `init` at the given cache size and worker count, printing a parseable result
/// line plus the replay region `R`. Nothing in the process warms the OS file cache beforehand, so an
/// external driver can `purge` between invocations to measure cold-cache init.
fn bench_one(folder: &str, cache_size: usize, parallelism: usize) {
    let cfg = Config::default().with_storage_directory(folder);
    let (elapsed, region) = time_init(&cfg, NonZeroUsize::new(cache_size), parallelism);
    if region == 0 {
        eprintln!("no database at {folder}; run `generate {folder} <elements>` first");
        return;
    }
    println!("parallelism={parallelism} cache={cache_size} region={region} time={elapsed:?}");
}

/// Reopen the database at `folder` with the **flat** (non-partitioned) ordered index, serially, at
/// cache off and cache=R. This is the serial-path regression check: the flat index uses the unchanged
/// `build_snapshot_from_log` (via the default `SnapshotBuild`), so its time should match the pre-rework
/// (#4098) flat-index serial init -- isolating any overhead the parallel-init machinery added to the
/// serial path from the P=3 config change.
fn bench_flat(folder: &str) {
    let cfg = Config::default().with_storage_directory(folder);
    let (cold, region) = time_init_flat(&cfg, 0);
    if region == 0 {
        eprintln!("no database at {folder}; run `generate {folder} <elements>` first");
        return;
    }
    let (warm, _) = time_init_flat(&cfg, region as usize);
    println!("flat (any::ordered::fixed::mmr) {folder}  R={region}");
    println!("  serial cache=0 : {cold:?}");
    println!("  serial cache=R : {warm:?}");
}

/// Time one serial `init` of the **flat** ordered DB at the given cache size.
fn time_init_flat(cfg: &Config, cache_size: usize) -> (Duration, u64) {
    Runner::new(cfg.clone()).start(|ctx| async move {
        let mut config = any_fix_cfg_with(&ctx, ITEMS_PER_BLOB, PAGE_CACHE_SIZE);
        config.init_cache_size = NonZeroUsize::new(cache_size);
        let start = Instant::now();
        let db = AnyOFixDb::<Mmr>::init(ctx.child("storage"), config)
            .await
            .unwrap();
        let elapsed = start.elapsed();
        let end: u64 = *db.bounds().end;
        let floor: u64 = *db.inactivity_floor_loc().await;
        (elapsed, end.saturating_sub(floor))
    })
}

/// Delete the database at `folder`.
fn destroy(folder: &str) {
    match std::fs::remove_dir_all(folder) {
        Ok(()) => println!("destroyed {folder}"),
        Err(e) => eprintln!("failed to destroy {folder}: {e}"),
    }
}

/// Time a single `init` of the database at `cfg`'s folder with the given cache size and worker count,
/// returning the elapsed time and the replay-region size (`0` if the database is empty/absent).
fn time_init(
    cfg: &Config,
    cache_size: Option<NonZeroUsize>,
    parallelism: usize,
) -> (Duration, u64) {
    Runner::new(cfg.clone()).start(|ctx| async move {
        let mut config = any_fix_cfg_with(&ctx, ITEMS_PER_BLOB, PAGE_CACHE_SIZE);
        config.init_cache_size = cache_size;
        config.init_parallelism = parallelism;
        let start = Instant::now();
        let db = AnyOFixP3Db::<Mmr>::init(ctx.child("storage"), config)
            .await
            .unwrap();
        let elapsed = start.elapsed();
        let end: u64 = *db.bounds().end;
        let floor: u64 = *db.inactivity_floor_loc().await;
        (elapsed, end.saturating_sub(floor))
    })
}

/// Whether `folder` exists and contains any entries (used to avoid silently appending to an existing
/// database during `generate`).
fn db_dir_nonempty(folder: &str) -> bool {
    std::fs::read_dir(folder)
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false)
}

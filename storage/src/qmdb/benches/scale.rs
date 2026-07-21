//! Standalone, opt-in large-scale measurement of QMDB operations at multi-GB scale: building a
//! database (`generate`), reopening it, i.e. rebuilding the snapshot (`init`), at a chosen
//! init-time `(location -> key)` cache size and build concurrency, and random point reads against
//! it (`get`/`get_many`).
//!
//! The criterion init benchmark ([init](super::init)) can't reach these sizes: it resamples, and the
//! database is multi-GB. This binary instead builds a *real* on-disk database once and then times a
//! *real* reopen ([`Db::init`]) and *real* reads, so the cache's effect on the redundant
//! collision-resolution log reads, the parallel build's speedup, and cold read latency all show at
//! scale.
//!
//! Generation and benchmarking are split so the (multi-minute, multi-GB) database is built once and
//! reused across many runs -- but generation is itself an interesting benchmark: building a database
//! of this size is a large-scale seed/churn/commit workload, and `generate` reports its elapsed
//! build time. A folder names the database's on-disk location:
//!
//! ```text
//! cargo bench -p commonware-storage --bench scale --features test-traits -- generate /tmp/db <keyspace> <num_updates> [zipf_exponent] [ordered|unordered]
//! cargo bench -p commonware-storage --bench scale --features test-traits -- init     /tmp/db <cache> <concurrency> [ordered|unordered]
//! cargo bench -p commonware-storage --bench scale --features test-traits -- get      /tmp/db <keyspace> <num_gets> <concurrency>[,<concurrency>...] [ordered|unordered] [cache_pages]
//! cargo bench -p commonware-storage --bench scale --features test-traits -- get_many /tmp/db <keyspace> <num_gets> <concurrency>[,<concurrency>...] <batch> [ordered|unordered] [cache_pages]
//! cargo bench -p commonware-storage --bench scale --features test-traits -- destroy  /tmp/db
//! ```
//!
//! `generate` applies `num_updates` random updates (~1 in `DELETE_FREQUENCY` are deletes) over a
//! `keyspace`-key index space, sampling each key uniformly or via Zipf -- there is no separate seed
//! phase, so the populated set fills organically as keys are sampled. The optional `zipf_exponent`
//! arg selects the distribution -- omitted is the default Zipf (`KEY_ZIPF_EXPONENT`), `0` is uniform
//! -- so a uniform and a skewed database differ only in that distribution. It then prunes and syncs,
//! reporting the total build time.
//!
//! `init` reopens it (read-only) and times one `init` at the given init cache size (`cache` entries,
//! `0` = off) and `concurrency` (`1` = serial, `N` = N total build tasks, so N-1 workers alongside
//! the init task). It reports the replay-region size `R` (so a full-coverage cache is `cache = R`)
//! and the elapsed time. Sweep cache/concurrency by driving the command from a shell loop.
//!
//! `get` times random point reads through the full stack (index lookup, page cache, blob read): it
//! opens the database (untimed), then for each entry in the comma-separated concurrency list drops
//! the OS page cache in-process and runs a cold pass of `num_gets` uniform-random gets across that
//! many spawned reader tasks, followed by a warm pass over the same keys as a control. `get_many` is
//! identical except each reader issues its gets in `batch`-key `get_many` calls, exercising the
//! batched read path the commit path uses. Keys are sampled the same way `generate` derives them
//! (`Sha256(index)` over the keyspace), so nearly all gets hit a live key. By default these modes
//! use a minimal 64-page cache, which uniform-random reads at this scale virtually never hit, so
//! reads reach the storage layer. Pass a larger `cache_pages` to measure through an in-process
//! cache of that many pages instead.
//!
//! The optional index flavor (default `ordered`) selects the snapshot index: `ordered` is the P=3
//! partitioned ordered index (the inline-SoA config for large key sets), `unordered` the P=2
//! (65,536 partition) hash index. Bench a database with the flavor it was generated with, since the
//! two db variants write different operation logs.
//!
//! Each invocation does exactly one reopen, so `init` numbers are warm only if the OS file cache is
//! already warm. For the realistic cold-cache case (init at process start), have the driver drop the
//! OS cache (`sudo purge` on macOS) between invocations.

#[allow(dead_code, unused_imports, unused_macros)]
#[path = "common.rs"]
mod common;

use common::{
    AnyOFixP3Db, AnyUFixP64kDb, Digest, any_fix_cfg_full, gen_random_kv, make_fixed_value,
};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_runtime::{
    Runner as _, Spawner as _, Supervisor as _,
    tokio::{Config, Context, Runner},
};
use commonware_storage::{merkle::mmr::Family as Mmr, qmdb::any::traits::DbAny};
use commonware_utils::{NZU64, NZUsize};
use rand::{RngExt as _, SeedableRng as _, rngs::StdRng};
use std::{
    io::Write as _,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::{Duration, Instant},
};

/// Items per blob for the generated database. Much larger than the shared bench default (50k) so a
/// multi-GB database is split across far fewer blob files, which keeps the partition-directory scan
/// on reopen cheap. Note this only reduces the file count, not the on-disk byte growth.
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(1_000_000);

/// Page cache size, realistic for a multi-GB database rather than the shared bench default of 8 MB
/// (512 pages). `generate` and `init` use it, so the init-cache benefit is measured on top of a
/// realistic page cache instead of an unrealistically tiny one. 65536 * 16 KiB = 1 GiB.
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(65536);

/// Page cache size for the get modes when `cache_pages` is not given: small enough that
/// uniform-random reads at benchmark scale virtually never hit it, so cold reads reach the
/// storage layer through the same cache path production runs.
const MIN_PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(64);

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

/// The snapshot index flavor a database is generated and benched with (see the module docs).
#[derive(Clone, Copy)]
enum IndexKind {
    /// The P=3 partitioned ordered index.
    Ordered,
    /// The P=2 (65,536 partition) unordered hash index.
    Unordered,
}

impl IndexKind {
    /// Parse an index-flavor CLI argument. `None` is a parse failure.
    fn parse(arg: &str) -> Option<Self> {
        match arg {
            "ordered" => Some(Self::Ordered),
            "unordered" => Some(Self::Unordered),
            _ => None,
        }
    }

    /// The flavor's report label (the db type alias it selects).
    const fn label(self) -> &'static str {
        match self {
            Self::Ordered => "any::ordered::fixed::p3::mmr",
            Self::Unordered => "any::unordered::fixed::p64k::mmr",
        }
    }
}

/// Parse a `concurrency` CLI argument into a snapshot-build concurrency (`1` = serial on the
/// init task, `n` = `n - 1` worker tasks in addition to it). `None` is a parse failure.
fn parse_concurrency(arg: &str) -> Option<NonZeroUsize> {
    arg.parse::<usize>().ok().and_then(NonZeroUsize::new)
}

fn usage() {
    eprintln!(
        "usage:\n  generate <folder> <keyspace> <num_updates> [zipf_exponent] [ordered|unordered]   build a database (omit exponent => zipf 1.0; 0 => uniform)\n  init     <folder> <cache> <concurrency> [ordered|unordered]   reopen + time one init (cache=entries, 0=off; concurrency=1 serial / N total build tasks)\n  get      <folder> <keyspace> <num_gets> <concurrency>[,...] [ordered|unordered] [cache_pages]   time random point reads (per concurrency: cold after an OS cache drop, then warm; cache_pages = in-process page cache pages, omitted = minimal 64)\n  get_many <folder> <keyspace> <num_gets> <concurrency>[,...] <batch> [ordered|unordered] [cache_pages]   like get, but each reader issues gets in `batch`-key get_many calls\n  destroy  <folder>                          delete the database"
    );
}

fn main() {
    // `cargo bench` appends a trailing `--bench` arg even for harness=false binaries; drop it so
    // trailing optional args parse.
    let argv: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| a != "--bench")
        .collect();
    match argv.first().map(String::as_str) {
        Some("generate") => match (
            argv.get(1),
            argv.get(2).and_then(|a| a.parse().ok()),
            argv.get(3).and_then(|a| a.parse().ok()),
        ) {
            (Some(folder), Some(keyspace), Some(num_updates)) => {
                // Optional trailing args, in either order: an index flavor (default ordered) and
                // a zipf exponent -- omitted => default skew (KEY_ZIPF_EXPONENT); `0` => uniform
                // sampling (`None`).
                let mut zipf_exponent = Some(KEY_ZIPF_EXPONENT);
                let mut index = IndexKind::Ordered;
                for arg in &argv[4..] {
                    if let Some(kind) = IndexKind::parse(arg) {
                        index = kind;
                    } else if let Ok(e) = arg.parse::<f64>() {
                        zipf_exponent = (e > 0.0).then_some(e);
                    } else {
                        usage();
                        return;
                    }
                }
                generate(folder, keyspace, num_updates, zipf_exponent, index)
            }
            _ => usage(),
        },
        Some("init") => match (
            argv.get(1),
            argv.get(2).and_then(|a| a.parse().ok()),
            argv.get(3).and_then(|a| parse_concurrency(a)),
            argv.get(4)
                .map_or(Some(IndexKind::Ordered), |a| IndexKind::parse(a)),
        ) {
            (Some(folder), Some(cache), Some(concurrency), Some(index)) => {
                init(folder, cache, concurrency, index)
            }
            _ => usage(),
        },
        Some(mode @ ("get" | "get_many")) => match (
            argv.get(1),
            argv.get(2).and_then(|a| a.parse::<u64>().ok()),
            argv.get(3).and_then(|a| a.parse::<u64>().ok()),
            argv.get(4).map(|a| {
                a.split(',')
                    .map(|c| c.parse::<u64>().ok().filter(|c| *c > 0))
                    .collect::<Option<Vec<u64>>>()
            }),
        ) {
            (Some(folder), Some(keyspace), Some(num_gets), Some(Some(concurrencies))) => {
                // `get_many` takes the batch size as its fifth arg; later options shift right.
                let (batch, opts_at) = if mode == "get_many" {
                    match argv
                        .get(5)
                        .and_then(|a| a.parse::<u64>().ok())
                        .and_then(NonZeroU64::new)
                    {
                        Some(batch) => (Some(batch), 6),
                        None => {
                            usage();
                            return;
                        }
                    }
                } else {
                    (None, 5)
                };
                // Trailing options in either order: an index flavor (default ordered) and an
                // in-process page cache size (omitted = a minimal cache, so reads reach
                // storage).
                let mut index = IndexKind::Ordered;
                let mut cache_pages = None;
                for arg in &argv[opts_at.min(argv.len())..] {
                    if let Some(kind) = IndexKind::parse(arg) {
                        index = kind;
                    } else if let Some(n) = arg.parse::<usize>().ok().and_then(NonZeroUsize::new) {
                        cache_pages = Some(n);
                    } else {
                        usage();
                        return;
                    }
                }
                get_bench(
                    folder,
                    keyspace,
                    num_gets,
                    concurrencies,
                    batch,
                    cache_pages,
                    index,
                )
            }
            _ => usage(),
        },
        Some("destroy") => match argv.get(1) {
            Some(folder) => destroy(folder),
            None => usage(),
        },
        _ => usage(),
    }
}

/// Build a database at `folder` by applying `num_updates` random updates over a `keyspace`-key index
/// space, leaving it on disk for later runs. Reports the elapsed build time -- a large-scale
/// churn/commit benchmark in its own right, not just setup for the reopen measurement.
///
/// `zipf_exponent` sets the key distribution: `None` is uniform, `Some(e)` is Zipf with exponent `e`.
/// The populated set fills organically as updates sample the keyspace (no separate seed phase).
fn generate(
    folder: &str,
    keyspace: u64,
    num_updates: u64,
    zipf_exponent: Option<f64>,
    index: IndexKind,
) {
    if keyspace == 0 {
        eprintln!("keyspace must be > 0");
        return;
    }
    if db_dir_nonempty(folder) {
        eprintln!("{folder} already contains data; `destroy` it first or pick a new folder");
        return;
    }

    /// Time the build itself (updates + prune + sync). Opening the empty db is done by the
    /// caller and is cheap.
    #[commonware_macros::boxed]
    async fn populate<M: DbAny<Mmr, Key = Digest, Value = Digest>>(
        db: M,
        keyspace: u64,
        num_updates: u64,
        zipf_exponent: Option<f64>,
    ) -> Duration {
        let start = Instant::now();
        let db = gen_random_kv::<Mmr, _>(
            db,
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
        let boundary = db.sync_boundary();
        let db = db.prune(boundary).await.unwrap();
        let _db = db.sync().await.unwrap();
        start.elapsed()
    }

    let cfg = Config::default().with_storage_directory(folder);
    let elapsed = Runner::new(cfg).start(|ctx| async move {
        // Generate with the same index flavor the bench reopens with (concurrency 1: generation
        // opens an empty db, so there is nothing to build in parallel).
        let config = any_fix_cfg_full(&ctx, ITEMS_PER_BLOB, PAGE_CACHE_SIZE, NZUsize!(1));
        match index {
            IndexKind::Ordered => {
                let db = AnyOFixP3Db::<Mmr>::init(ctx.child("storage"), config)
                    .await
                    .unwrap();
                populate(db, keyspace, num_updates, zipf_exponent).await
            }
            IndexKind::Unordered => {
                let db = AnyUFixP64kDb::<Mmr>::init(ctx.child("storage"), config)
                    .await
                    .unwrap();
                populate(db, keyspace, num_updates, zipf_exponent).await
            }
        }
    });
    println!("generated {num_updates} updates over keyspace {keyspace} at {folder} in {elapsed:?}");
}

/// Reopen the database at `folder` (read-only) and time one `init` of the selected index flavor
/// at the given init cache size (`cache` entries; `0` = off) and worker count. Reports the
/// replay-region size `R` (a full-coverage cache is `cache = R`) and the elapsed time.
fn init(folder: &str, cache: usize, concurrency: NonZeroUsize, index: IndexKind) {
    if !db_dir_nonempty(folder) {
        eprintln!(
            "no database at {folder}; run `generate {folder} <keyspace> <num_updates>` first"
        );
        return;
    }
    let cfg = Config::default().with_storage_directory(folder);
    let (elapsed, region) = time_init(&cfg, NonZeroUsize::new(cache), concurrency, index);
    if region == 0 {
        eprintln!(
            "database at {folder} is empty; run `generate {folder} <keyspace> <num_updates>` first"
        );
        return;
    }
    let label = index.label();
    println!(
        "init ({label}) {folder} cache={cache} concurrency={concurrency} region={region} time={elapsed:?}"
    );
}

/// Time random point reads against the database at `folder`: open it (untimed), then for each
/// reader count drop the OS page cache and run a cold pass of `num_gets` gets, followed by a warm
/// pass over the same keys as a control. With `batch`, each reader issues its gets in `batch`-key
/// `get_many` calls.
#[allow(clippy::too_many_arguments)]
fn get_bench(
    folder: &str,
    keyspace: u64,
    num_gets: u64,
    concurrencies: Vec<u64>,
    batch: Option<NonZeroU64>,
    cache_pages: Option<NonZeroUsize>,
    index: IndexKind,
) {
    if keyspace == 0 || num_gets == 0 {
        usage();
        return;
    }
    if !db_dir_nonempty(folder) {
        eprintln!(
            "no database at {folder}; run `generate {folder} <keyspace> <num_updates>` first"
        );
        return;
    }
    let cfg = Config::default().with_storage_directory(folder);
    Runner::new(cfg).start(|ctx| async move {
        // A minimal page cache by default: uniform-random reads at benchmark scale virtually
        // never hit it, so the cold pass measures the storage layer through the same cache path
        // production runs.
        let cache_pages = cache_pages.unwrap_or(MIN_PAGE_CACHE_SIZE);
        let cache_mode = format!("{cache_pages} pages");
        let config = any_fix_cfg_full(&ctx, ITEMS_PER_BLOB, cache_pages, NZUsize!(1));

        let batch_mode = batch.map_or_else(|| "point".to_string(), |b| format!("get_many x{b}"));
        println!(
            "get ({}) {folder}  page cache {cache_mode}, keyspace {keyspace}, reads {batch_mode}",
            index.label()
        );
        let _ = std::io::stdout().flush();

        let open_start = Instant::now();
        match index {
            IndexKind::Ordered => {
                let db = Arc::new(
                    AnyOFixP3Db::<Mmr>::init(ctx.child("db"), config)
                        .await
                        .unwrap(),
                );
                run_reads(
                    &ctx,
                    db,
                    open_start.elapsed(),
                    keyspace,
                    num_gets,
                    &concurrencies,
                    batch,
                )
                .await;
            }
            IndexKind::Unordered => {
                let db = Arc::new(
                    AnyUFixP64kDb::<Mmr>::init(ctx.child("db"), config)
                        .await
                        .unwrap(),
                );
                run_reads(
                    &ctx,
                    db,
                    open_start.elapsed(),
                    keyspace,
                    num_gets,
                    &concurrencies,
                    batch,
                )
                .await;
            }
        }
    });
}

/// Run the cold/warm read passes for each reader count against an opened database.
async fn run_reads<D: DbAny<Mmr, Key = Digest> + Send + Sync + 'static>(
    ctx: &Context,
    db: Arc<D>,
    opened: Duration,
    keyspace: u64,
    num_gets: u64,
    concurrencies: &[u64],
    batch: Option<NonZeroU64>,
) {
    println!("  open (untimed phase): {opened:?}");
    let _ = std::io::stdout().flush();
    for &concurrency in concurrencies {
        if concurrency > num_gets {
            eprintln!("  skipping readers={concurrency}: more readers than gets");
            continue;
        }
        if !drop_os_caches() {
            eprintln!(
                "  warning: OS cache drop failed (needs passwordless sudo); cold pass is not cold"
            );
        }
        for pass in ["cold", "warm"] {
            let (elapsed, total, found) =
                run_gets(ctx, db.clone(), keyspace, num_gets, concurrency, batch).await;
            let us = elapsed.as_secs_f64() * 1e6 / total as f64;
            let rate = total as f64 / elapsed.as_secs_f64();
            println!(
                "  {pass}[readers={concurrency}]: {total} gets ({found} found) in {elapsed:?}  ({us:.1} us/get, {rate:.0} gets/s)"
            );
            let _ = std::io::stdout().flush();
        }
    }
}

/// Run one pass of uniform-random gets: `num_gets` gets split across `concurrency` spawned reader
/// tasks (the first `num_gets % concurrency` readers take one extra), each consuming its own
/// deterministic key stream (so a repeat pass replays the same keys). With a `batch` size, each
/// reader issues its gets in `batch`-key `get_many` calls instead of point gets. Returns the
/// elapsed time, the number of gets issued, and how many found a value.
async fn run_gets<D: DbAny<Mmr, Key = Digest> + Send + Sync + 'static>(
    ctx: &Context,
    db: Arc<D>,
    keyspace: u64,
    num_gets: u64,
    concurrency: u64,
    batch: Option<NonZeroU64>,
) -> (Duration, u64, u64) {
    let per_reader = num_gets / concurrency;
    let remainder = num_gets % concurrency;
    let start = Instant::now();
    let readers: Vec<_> = (0..concurrency)
        .map(|reader| {
            let gets = per_reader + u64::from(reader < remainder);
            let db = db.clone();
            ctx.child("reader").spawn(move |_| async move {
                let mut rng = StdRng::seed_from_u64(reader);
                let mut found = 0u64;
                match batch {
                    None => {
                        for _ in 0..gets {
                            let index = rng.random_range(0..keyspace);
                            let key = Sha256::hash(&index.to_be_bytes());
                            if db.get(&key).await.unwrap().is_some() {
                                found += 1;
                            }
                        }
                    }
                    Some(batch) => {
                        let mut remaining = gets;
                        while remaining > 0 {
                            let n = remaining.min(batch.get());
                            let keys: Vec<_> = (0..n)
                                .map(|_| {
                                    let index = rng.random_range(0..keyspace);
                                    Sha256::hash(&index.to_be_bytes())
                                })
                                .collect();
                            let refs: Vec<_> = keys.iter().collect();
                            let values = db.get_many(&refs).await.unwrap();
                            found += values.iter().flatten().count() as u64;
                            remaining -= n;
                        }
                    }
                }
                found
            })
        })
        .collect();
    let mut found = 0u64;
    for reader in readers {
        found += reader.await.unwrap();
    }
    (start.elapsed(), num_gets, found)
}

/// Drop the OS page cache (requires passwordless sudo), returning whether it succeeded.
fn drop_os_caches() -> bool {
    #[cfg(target_os = "linux")]
    let status = std::process::Command::new("sh")
        .args([
            "-c",
            "sync && echo 3 | sudo -n tee /proc/sys/vm/drop_caches > /dev/null",
        ])
        .status();
    #[cfg(target_os = "macos")]
    let status = std::process::Command::new("sudo")
        .args(["-n", "purge"])
        .status();
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let status = std::io::Result::<std::process::ExitStatus>::Err(std::io::Error::other(
        "unsupported platform",
    ));
    matches!(status, Ok(s) if s.success())
}

/// Delete the database at `folder`.
fn destroy(folder: &str) {
    match std::fs::remove_dir_all(folder) {
        Ok(()) => println!("destroyed {folder}"),
        Err(e) => eprintln!("failed to destroy {folder}: {e}"),
    }
}

/// Time a single `init` of the database at `cfg`'s folder with the given cache size, worker
/// count, and index flavor, returning the elapsed time and the replay-region size (`0` if the
/// database is empty/absent).
fn time_init(
    cfg: &Config,
    cache_size: Option<NonZeroUsize>,
    concurrency: NonZeroUsize,
    index: IndexKind,
) -> (Duration, u64) {
    /// The elapsed time since `start` and the db's replay-region size.
    fn measure<M: DbAny<Mmr, Key = Digest, Value = Digest>>(
        db: &M,
        start: Instant,
    ) -> (Duration, u64) {
        let elapsed = start.elapsed();
        let end: u64 = *db.bounds().end;
        let floor: u64 = *db.inactivity_floor_loc();
        (elapsed, end.saturating_sub(floor))
    }

    Runner::new(cfg.clone()).start(|ctx| async move {
        let mut config = any_fix_cfg_full(&ctx, ITEMS_PER_BLOB, PAGE_CACHE_SIZE, concurrency);
        config.init_cache_size = cache_size;
        let start = Instant::now();
        match index {
            IndexKind::Ordered => {
                let db = AnyOFixP3Db::<Mmr>::init(ctx.child("storage"), config)
                    .await
                    .unwrap();
                measure(&db, start)
            }
            IndexKind::Unordered => {
                let db = AnyUFixP64kDb::<Mmr>::init(ctx.child("storage"), config)
                    .await
                    .unwrap();
                measure(&db, start)
            }
        }
    })
}

/// Whether `folder` exists and contains any entries (used to avoid silently appending to an existing
/// database during `generate`).
fn db_dir_nonempty(folder: &str) -> bool {
    std::fs::read_dir(folder)
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false)
}

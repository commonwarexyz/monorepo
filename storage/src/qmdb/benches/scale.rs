//! Standalone, opt-in large-scale measurement of QMDB operations at multi-GB scale: building a
//! database (`generate`), reopening it, i.e. rebuilding the snapshot (`init`, with the init-time
//! `(location -> key)` cache off vs on), and random point reads against it (`get`).
//!
//! The criterion init benchmark ([init](super::init)) can't reach these sizes: it resamples, and
//! the database is multi-GB. This binary instead builds a *real* on-disk database once and then
//! times a *real* reopen ([`Db::init`], i.e. `build_snapshot_from_log`) at several cache sizes, so
//! the cache's effect on the redundant collision-resolution log reads shows at scale.
//!
//! Generation and benchmarking are split so the (multi-minute, multi-GB) database is built once and
//! reused across many reopen runs -- but generation is itself an interesting benchmark: building a
//! database of this size is a large-scale seed/churn/commit workload, and `generate` reports its
//! elapsed build time. A folder names the database's on-disk location:
//!
//! ```text
//! cargo bench -p commonware-storage --bench scale --features test-traits -- generate /tmp/db 50000000 250000000 [zipf_exponent] [page_size]
//! cargo bench -p commonware-storage --bench scale --features test-traits -- init     /tmp/db [page_size]
//! cargo bench -p commonware-storage --bench scale --features test-traits -- get      /tmp/db 50000000 100000 1,8,32 [page_size]
//! cargo bench -p commonware-storage --bench scale --features test-traits -- destroy  /tmp/db
//! ```
//!
//! `generate` applies `num_updates` random updates (~1 in `DELETE_FREQUENCY` are deletes) over a
//! `keyspace`-key index space, sampling each key uniformly or via Zipf -- there is no separate seed
//! phase, so the populated set fills organically as keys are sampled. The optional `zipf_exponent`
//! arg selects the distribution -- omitted is the default Zipf (`KEY_ZIPF_EXPONENT`), `0` is
//! uniform -- so a uniform and a skewed database differ only in that distribution. It then prunes
//! and syncs, reporting the total build time. `init` reopens it (read-only) at cache off / a
//! quarter of the replay region / the whole replay region, reporting each init time plus the
//! replay-region size `R` (what the cache must cover to avoid eviction).
//!
//! The optional `page_size` arg (logical bytes; default 16384) selects the page geometry; a
//! database must be reopened (`init`) with the page size it was generated with. Physical pages are
//! 12 bytes larger than logical ones (the per-page CRC record), so e.g. logical 16372 produces
//! 16384-byte physical pages.
//!
//! `get` times random point reads through the full stack (index lookup, page cache, blob read): it
//! opens the database (untimed), then for each entry in the comma-separated concurrency list drops
//! the OS page cache in-process (init's replay warms it) and runs a cold pass of `num_gets`
//! uniform-random gets across that many spawned reader tasks, followed by a warm pass over the same
//! keys as a control. Keys are sampled the same way `generate` derives them (`Sha256(index)` over
//! the keyspace), so nearly all gets hit a live key. By default this mode uses `NoCache` (no
//! in-process caching) so reads always reach the storage layer; pass a non-zero `cache_pages` to
//! measure through an in-process cache of that many pages instead.

#[allow(dead_code, unused_imports, unused_macros)]
#[path = "common.rs"]
mod common;

use common::{any_fix_cfg_with, gen_random_kv, make_fixed_value, AnyOFixDb, PAGE_SIZE};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_runtime::{
    buffer::paged::{CacheRef, PageCache},
    tokio::{Config, Context, Runner},
    Runner as _, Spawner as _, Supervisor as _,
};
use commonware_storage::{merkle::mmr::Family as Mmr, qmdb::any::traits::DbAny as _};
use commonware_utils::{NZUsize, NZU64};
use rand::{rngs::StdRng, RngCore as _, SeedableRng as _};
use std::{
    io::Write as _,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::{Duration, Instant},
};

/// Items per blob for the generated database. Large enough so that a multi-GB database isn't split
/// across too many files.
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(1_000_000);

/// Page cache size. 65536 * 16 KiB = 1 GiB.
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(65536);

/// Commit (and prune-eligible) cadence during population.
const COMMIT_FREQUENCY: u32 = 10_000;

/// Prune to the inactivity floor every this many commits during population, so the on-disk log
/// stays bounded to roughly the active region instead of accumulating every re-appended operation
/// until the end. At `COMMIT_FREQUENCY` this is ~1 prune per `COMMIT_FREQUENCY * PRUNE_FREQUENCY`
/// ops.
const PRUNE_FREQUENCY: u32 = 100;

/// Zipf exponent for update/delete key selection: churn follows a power law (a hot subset of keys
/// is updated far more than the long tail) rather than uniform, which is more representative of
/// real workloads. Higher = more skew; ~1.0 is classic Zipf.
const KEY_ZIPF_EXPONENT: f64 = 1.0;

fn usage() {
    eprintln!(
        "usage:\n  generate <folder> <keyspace> <num_updates> [zipf_exponent] [page_size]   build a database (omit exponent => zipf 1.0; 0 => uniform; page_size = logical bytes, default 16384)\n  init     <folder> [page_size]  reopen + time init at cache off / R/4 / R (page_size must match generate)\n  get      <folder> <keyspace> <num_gets> <concurrency>[,<concurrency>...] [page_size] [cache_pages]   time random point reads (per concurrency: cold after an OS cache drop, then warm; cache_pages = in-process page cache pages, 0/omitted = no caching)\n  destroy  <folder>              delete the database"
    );
}

fn main() {
    // `cargo bench` appends a trailing `--bench` arg even for harness=false binaries; drop it so
    // trailing optional args (zipf_exponent, page_size) parse.
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
                // Optional zipf exponent (5th arg): omitted => default skew (KEY_ZIPF_EXPONENT);
                // `0` => uniform sampling (`None`). Implausible exponents are rejected so a
                // page size mistakenly passed in this position errors instead of silently
                // building a database with the wrong key distribution.
                let zipf_exponent = match argv.get(4).map(|a| a.parse::<f64>()) {
                    None => Some(KEY_ZIPF_EXPONENT),
                    Some(Ok(0.0)) => None,
                    Some(Ok(e)) if e > 0.0 && e <= 8.0 => Some(e),
                    _ => {
                        usage();
                        return;
                    }
                };
                let Some(page_size) = parse_page_size(argv.get(5)) else {
                    usage();
                    return;
                };
                generate(folder, keyspace, num_updates, zipf_exponent, page_size)
            }
            _ => usage(),
        },
        Some("init") => match argv.get(1) {
            Some(folder) => {
                let Some(page_size) = parse_page_size(argv.get(2)) else {
                    usage();
                    return;
                };
                init(folder, page_size)
            }
            None => usage(),
        },
        Some("get") => match (
            argv.get(1),
            argv.get(2).and_then(|a| a.parse().ok()),
            argv.get(3).and_then(|a| a.parse().ok()),
            argv.get(4).map(|a| {
                a.split(',')
                    .map(|c| c.parse::<u64>().ok().filter(|c| *c > 0))
                    .collect::<Option<Vec<u64>>>()
            }),
        ) {
            (Some(folder), Some(keyspace), Some(num_gets), Some(Some(concurrencies))) => {
                let Some(page_size) = parse_page_size(argv.get(5)) else {
                    usage();
                    return;
                };
                // Optional in-process page cache size (7th arg): omitted or `0` selects
                // `NoCache`, so reads always reach the storage layer.
                let cache_pages = match argv.get(6).map(|a| a.parse::<usize>()) {
                    None => None,
                    Some(Ok(n)) => NonZeroUsize::new(n),
                    Some(Err(_)) => {
                        usage();
                        return;
                    }
                };
                get_bench(
                    folder,
                    keyspace,
                    num_gets,
                    concurrencies,
                    page_size,
                    cache_pages,
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

/// Parse an optional logical page-size argument, defaulting to [PAGE_SIZE].
fn parse_page_size(arg: Option<&String>) -> Option<NonZeroU16> {
    arg.map_or(Some(PAGE_SIZE), |a| {
        a.parse::<u16>().ok().and_then(NonZeroU16::new)
    })
}

/// Build a database at `folder` by applying `num_updates` random updates over a `keyspace`-key index
/// space, leaving it on disk for later `init` runs. Reports the elapsed build time -- a large-scale
/// churn/commit benchmark in its own right, not just setup for the reopen measurement.
///
/// `zipf_exponent` sets the key distribution: `None` is uniform, `Some(e)` is Zipf with exponent `e`.
/// The populated set fills organically as updates sample the keyspace (no separate seed phase).
fn generate(
    folder: &str,
    keyspace: u64,
    num_updates: u64,
    zipf_exponent: Option<f64>,
    page_size: NonZeroU16,
) {
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
        let mut db = AnyOFixDb::<Mmr>::init(
            ctx.child("storage"),
            any_fix_cfg_with(
                &ctx,
                ITEMS_PER_BLOB,
                CacheRef::from_pooler(&ctx, page_size, PAGE_CACHE_SIZE),
            ),
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

/// Reopen the database at `folder` (read-only) and time `init` at three cache regimes: off, a
/// quarter of the replay region (fills + evicts), and the whole replay region (no eviction).
fn init(folder: &str, page_size: NonZeroU16) {
    if !db_dir_nonempty(folder) {
        eprintln!(
            "no database at {folder}; run `generate {folder} <keyspace> <num_updates>` first"
        );
        return;
    }
    let cfg = Config::default().with_storage_directory(folder);

    // No-cache baseline; also learn the replay region R (ops above the inactivity floor) -- what
    // the location cache must cover to avoid eviction (a key-cache would need only the key count).
    let (baseline, region) = time_init(&cfg, None, page_size);
    if region == 0 {
        eprintln!(
            "database at {folder} is empty; run `generate {folder} <keyspace> <num_updates>` first"
        );
        return;
    }
    println!("scale: {folder}  (any::ordered::fixed::mmr, logical page size {page_size})");
    println!("  replay region R = {region} ops");
    println!("  cache=off          : {baseline:?}");
    let _ = std::io::stdout().flush();

    for cache_size in [
        NonZeroUsize::new((region / 4) as usize),
        NonZeroUsize::new(region as usize),
    ] {
        let (elapsed, _) = time_init(&cfg, cache_size, page_size);
        println!("  cache={cache_size:?}: {elapsed:?}");
        let _ = std::io::stdout().flush();
    }
}

/// Time random point reads against the database at `folder`: open it (untimed), drop the OS page
/// cache, then run a cold pass of `num_gets` gets with `concurrency` readers in flight, followed
/// by a warm pass over the same keys as a control.
fn get_bench(
    folder: &str,
    keyspace: u64,
    num_gets: u64,
    concurrencies: Vec<u64>,
    page_size: NonZeroU16,
    cache_pages: Option<NonZeroUsize>,
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
    // `NoCache` by default so point reads reach the storage layer instead of the in-process
    // cache, which is what the cold-read measurement is about. The cache implementation is a
    // type parameter, so each choice instantiates its own database type.
    match cache_pages {
        None => run_get_bench(
            folder,
            keyspace,
            num_gets,
            concurrencies,
            page_size,
            move |ctx: &Context| CacheRef::no_cache_from_pooler(ctx, page_size),
            "none".to_string(),
        ),
        Some(pages) => run_get_bench(
            folder,
            keyspace,
            num_gets,
            concurrencies,
            page_size,
            move |ctx: &Context| CacheRef::from_pooler(ctx, page_size, pages),
            format!("{pages} pages"),
        ),
    }
}

/// [get_bench], instantiated for one [PageCache] implementation.
#[allow(clippy::too_many_arguments)]
fn run_get_bench<P: PageCache>(
    folder: &str,
    keyspace: u64,
    num_gets: u64,
    concurrencies: Vec<u64>,
    page_size: NonZeroU16,
    make_cache: impl FnOnce(&Context) -> CacheRef<P> + Send + 'static,
    cache_mode: String,
) {
    let cfg = Config::default().with_storage_directory(folder);
    Runner::new(cfg).start(|ctx| async move {
        let config = any_fix_cfg_with(&ctx, ITEMS_PER_BLOB, make_cache(&ctx));
        let open_start = Instant::now();
        let db = AnyOFixDb::<Mmr, P>::init(ctx.child("storage"), config)
            .await
            .unwrap();
        let opened = open_start.elapsed();
        println!(
            "get_scale: {folder}  (logical page size {page_size}, page cache {cache_mode}, keyspace {keyspace})"
        );
        println!("  open (untimed phase): {opened:?}");
        let _ = std::io::stdout().flush();

        let db = Arc::new(db);
        for concurrency in concurrencies {
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
                    run_gets(&ctx, db.clone(), keyspace, num_gets, concurrency).await;
                let us = elapsed.as_secs_f64() * 1e6 / total as f64;
                let rate = total as f64 / elapsed.as_secs_f64();
                println!(
                    "  {pass}[readers={concurrency}]: {total} gets ({found} found) in {elapsed:?}  ({us:.1} us/get, {rate:.0} gets/s)"
                );
                let _ = std::io::stdout().flush();
            }
        }
    });
}

/// Run one pass of uniform-random gets: `num_gets` gets split across `concurrency` spawned
/// reader tasks (the first `num_gets % concurrency` readers take one extra), each consuming its
/// own deterministic key stream (so a repeat pass replays the same keys). Returns the elapsed
/// time, the number of gets issued, and how many found a value.
async fn run_gets<P: PageCache>(
    ctx: &Context,
    db: Arc<AnyOFixDb<Mmr, P>>,
    keyspace: u64,
    num_gets: u64,
    concurrency: u64,
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
                for _ in 0..gets {
                    let index = rng.next_u64() % keyspace;
                    let key = Sha256::hash(&index.to_be_bytes());
                    if db.get(&key).await.unwrap().is_some() {
                        found += 1;
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

/// Time a single `init` of the database at `cfg`'s folder with the given cache size, returning the
/// elapsed time and the replay-region size (`0` if the database is empty/absent).
fn time_init(
    cfg: &Config,
    cache_size: Option<NonZeroUsize>,
    page_size: NonZeroU16,
) -> (Duration, u64) {
    Runner::new(cfg.clone()).start(|ctx| async move {
        let mut config = any_fix_cfg_with(
            &ctx,
            ITEMS_PER_BLOB,
            CacheRef::from_pooler(&ctx, page_size, PAGE_CACHE_SIZE),
        );
        config.init_cache_size = cache_size;
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

/// Whether `folder` exists and contains any entries (used to avoid silently appending to an
/// existing database during `generate`).
fn db_dir_nonempty(folder: &str) -> bool {
    std::fs::read_dir(folder)
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false)
}

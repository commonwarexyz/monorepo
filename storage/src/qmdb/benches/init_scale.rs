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
//! reporting the total build time. `bench` reopens it (read-only) at cache off / a quarter of the
//! replay region / the whole replay region, reporting each init time plus the replay-region size `R`
//! (what the cache must cover to avoid eviction).

#[allow(dead_code, unused_imports, unused_macros)]
#[path = "common.rs"]
mod common;

use common::{any_fix_cfg_with, gen_random_kv, make_fixed_value, AnyOFixDb};
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

fn usage() {
    eprintln!(
        "usage:\n  generate <folder> <keyspace> <num_updates> [zipf_exponent]   build a database (omit exponent => zipf 1.0; 0 => uniform)\n  bench    <folder>              reopen + time init at cache off / R/4 / R\n  destroy  <folder>              delete the database"
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

/// Reopen the database at `folder` (read-only) and time `init` at three cache regimes: off, a
/// quarter of the replay region (fills + evicts), and the whole replay region (no eviction).
fn bench(folder: &str) {
    if !db_dir_nonempty(folder) {
        eprintln!(
            "no database at {folder}; run `generate {folder} <keyspace> <num_updates>` first"
        );
        return;
    }
    let cfg = Config::default().with_storage_directory(folder);

    // No-cache baseline; also learn the replay region R (ops above the inactivity floor) -- what the
    // location cache must cover to avoid eviction (a key-cache would need only the key count).
    let (baseline, region) = time_init(&cfg, None);
    if region == 0 {
        eprintln!(
            "database at {folder} is empty; run `generate {folder} <keyspace> <num_updates>` first"
        );
        return;
    }
    println!("init_scale: {folder}  (any::ordered::fixed::mmr)");
    println!("  replay region R = {region} ops");
    println!("  cache=off          : {baseline:?}");
    let _ = std::io::stdout().flush();

    for cache_size in [
        NonZeroUsize::new((region / 4) as usize),
        NonZeroUsize::new(region as usize),
    ] {
        let (elapsed, _) = time_init(&cfg, cache_size);
        println!("  cache={cache_size:?}: {elapsed:?}");
        let _ = std::io::stdout().flush();
    }
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
fn time_init(cfg: &Config, cache_size: Option<NonZeroUsize>) -> (Duration, u64) {
    Runner::new(cfg.clone()).start(|ctx| async move {
        let mut config = any_fix_cfg_with(&ctx, ITEMS_PER_BLOB, PAGE_CACHE_SIZE);
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

/// Whether `folder` exists and contains any entries (used to avoid silently appending to an existing
/// database during `generate`).
fn db_dir_nonempty(folder: &str) -> bool {
    std::fs::read_dir(folder)
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false)
}

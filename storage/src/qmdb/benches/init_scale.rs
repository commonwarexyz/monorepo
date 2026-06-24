//! Standalone, opt-in large-scale measurement of QMDB init (snapshot rebuild) with the init-time
//! `(location -> key)` cache off vs on.
//!
//! The criterion init benchmark ([init](super::init)) can't reach these sizes: it resamples, and the
//! database is multi-GB. This binary instead builds a *real* on-disk database once and then times a
//! *real* reopen ([`Db::init`], i.e. `build_snapshot_from_log`) at several cache sizes, so the
//! cache's effect on the redundant collision-resolution log reads shows at scale.
//!
//! Generation and benchmarking are split so the (multi-minute, multi-GB) database is built once and
//! reused across many measurement runs. A folder names the database's on-disk location:
//!
//! ```text
//! cargo bench -p commonware-storage --bench init_scale --features test-traits -- generate /tmp/db 50000000
//! cargo bench -p commonware-storage --bench init_scale --features test-traits -- bench    /tmp/db
//! cargo bench -p commonware-storage --bench init_scale --features test-traits -- destroy  /tmp/db
//! ```
//!
//! `generate` seeds `elements` keys (a uniform-random subset of a `KEYSPACE_MULTIPLIER`x larger
//! keyspace) then `elements * CHURN` Zipf-distributed updates over that whole keyspace -- so churn is
//! skewed (a hot subset is re-updated, which makes collision resolution, and thus the cache, matter)
//! and some updates land on unseeded keys, inserting them (a growing keyspace). It then prunes and
//! syncs. `bench` reopens it (read-only) at cache off / a quarter of the replay region / the whole
//! replay region, reporting each init time plus the replay-region size `R` (what the cache must cover
//! to avoid eviction).

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

/// Random updates per element after the initial seed. Higher = more re-updates above the inactivity
/// floor = more collision-resolution reads for the cache to eliminate.
const CHURN: u64 = 5;

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

/// Keyspace size as a multiple of the seeded `elements`. The seed is a uniform-random `elements`-key
/// subset of this larger space, and updates draw (via Zipf) from the whole space, so some updates land
/// on unseeded keys and insert them. This models a growing keyspace (inserts interleaved with updates)
/// rather than churning a fixed population.
const KEYSPACE_MULTIPLIER: u64 = 4;

/// Cap on seeds accumulated before a merkleize+apply, so seeding a huge key set stays bounded in
/// memory instead of buffering every entry in one batch.
const SEED_BATCH: u64 = 100_000;

fn usage() {
    eprintln!(
        "usage:\n  generate <folder> <elements>   build a database once and keep it\n  bench    <folder>              reopen + time init at cache off / R/4 / R\n  destroy  <folder>              delete the database"
    );
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match argv.first().map(String::as_str) {
        Some("generate") => match (argv.get(1), argv.get(2).and_then(|a| a.parse().ok())) {
            (Some(folder), Some(elements)) => generate(folder, elements),
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

/// Build a database of `elements` keys (plus `elements * CHURN` random updates) at `folder` and
/// leave it on disk for later `bench` runs.
fn generate(folder: &str, elements: u64) {
    if db_dir_nonempty(folder) {
        eprintln!("{folder} already contains data; `destroy` it first or pick a new folder");
        return;
    }
    let operations = elements * CHURN;
    let cfg = Config::default().with_storage_directory(folder);
    Runner::new(cfg).start(|ctx| async move {
        let mut db = AnyOFixDb::<Mmr>::init(
            ctx.child("storage"),
            any_fix_cfg_with(&ctx, ITEMS_PER_BLOB, PAGE_CACHE_SIZE),
        )
        .await
        .unwrap();
        gen_random_kv::<Mmr, _>(
            &mut db,
            elements,
            operations,
            Some(COMMIT_FREQUENCY),
            Some(SEED_BATCH),
            Some(PRUNE_FREQUENCY),
            Some(KEY_ZIPF_EXPONENT),
            Some(KEYSPACE_MULTIPLIER * elements),
            make_fixed_value,
        )
        .await;
        db.prune(db.sync_boundary()).await.unwrap();
        db.sync().await.unwrap();
    });
    println!("generated {elements} keys + {operations} updates at {folder}");
}

/// Reopen the database at `folder` (read-only) and time `init` at three cache regimes: off, a
/// quarter of the replay region (fills + evicts), and the whole replay region (no eviction).
fn bench(folder: &str) {
    let cfg = Config::default().with_storage_directory(folder);

    // No-cache baseline; also learn the replay region R (ops above the inactivity floor) -- what the
    // location cache must cover to avoid eviction (a key-cache would need only the key count).
    let (baseline, region) = time_init(&cfg, 0);
    if region == 0 {
        eprintln!("no database at {folder}; run `generate {folder} <elements>` first");
        return;
    }
    println!("init_scale: {folder}  (any::ordered::fixed::mmr)");
    println!("  replay region R = {region} ops");
    println!("  cache=off          : {baseline:?}");
    let _ = std::io::stdout().flush();

    for cache_size in [(region / 4) as usize, region as usize] {
        let (elapsed, _) = time_init(&cfg, cache_size);
        println!("  cache={cache_size:>11}: {elapsed:?}");
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
fn time_init(cfg: &Config, cache_size: usize) -> (Duration, u64) {
    Runner::new(cfg.clone()).start(|ctx| async move {
        let mut config = any_fix_cfg_with(&ctx, ITEMS_PER_BLOB, PAGE_CACHE_SIZE);
        config.init_cache_size = cache_size;
        let start = Instant::now();
        let db = AnyOFixDb::<Mmr>::init(ctx.child("storage"), config)
            .await
            .unwrap();
        let elapsed = start.elapsed();
        let end: u64 = *db.bounds().await.end;
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

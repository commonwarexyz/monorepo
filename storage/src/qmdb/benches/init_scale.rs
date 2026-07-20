//! Standalone, opt-in large-scale measurement of two QMDB operations at multi-GB scale: building a
//! database (`generate`) and reopening it, i.e. rebuilding the snapshot (`bench`), at a chosen
//! init-time `(location -> key)` cache size and build concurrency.
//!
//! The criterion init benchmark ([init](super::init)) can't reach these sizes: it resamples, and the
//! database is multi-GB. This binary instead builds a *real* on-disk database once and then times a
//! *real* reopen ([`Db::init`]) so the cache's effect on the redundant collision-resolution log reads,
//! and the parallel build's speedup, show at scale.
//!
//! Generation and benchmarking are split so the (multi-minute, multi-GB) database is built once and
//! reused across many reopen runs -- but generation is itself an interesting benchmark: building a
//! database of this size is a large-scale seed/churn/commit workload, and `generate` reports its
//! elapsed build time. A folder names the database's on-disk location:
//!
//! ```text
//! cargo bench -p commonware-storage --bench init_scale --features test-traits -- generate /tmp/db <keyspace> <num_updates> [zipf_exponent] [ordered|unordered]
//! cargo bench -p commonware-storage --bench init_scale --features test-traits -- bench    /tmp/db <cache> <concurrency> [ordered|unordered]
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
//! `bench` reopens it (read-only) and times one `init` at the given init cache size (`cache` entries,
//! `0` = off) and `concurrency` (`1` = serial, `N` = N total build tasks, so N-1 workers alongside
//! the init task). It reports the
//! replay-region size `R` (so a full-coverage cache is `cache = R`)
//! and the elapsed time. Sweep cache/concurrency by driving the command from a shell loop.
//!
//! The optional index flavor (default `ordered`) selects the snapshot index whose parallel
//! `build_snapshot` override is exercised: `ordered` is the P=3 partitioned ordered index (the
//! inline-SoA config for large key sets), `unordered` the P=2 (65,536 partition) hash index.
//! Bench a database with the flavor it was generated with, since the two db variants write
//! different operation logs.
//!
//! Each invocation does exactly one reopen, so numbers are warm only if the OS file cache is already
//! warm. For the realistic cold-cache case (init at process start), have the driver drop the OS cache
//! (`sudo purge` on macOS) between invocations.

#[allow(dead_code, unused_imports, unused_macros)]
#[path = "common.rs"]
mod common;

use common::{
    AnyOFixP3Db, AnyUFixP64kDb, Digest, any_fix_cfg_full, gen_random_kv, make_fixed_value,
};
use commonware_runtime::{
    Runner as _, Supervisor as _,
    tokio::{Config, Runner},
};
use commonware_storage::{merkle::mmr::Family as Mmr, qmdb::any::traits::DbAny};
use commonware_utils::{NZU64, NZUsize};
use std::{
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
        "usage:\n  generate <folder> <keyspace> <num_updates> [zipf_exponent] [ordered|unordered]   build a database (omit exponent => zipf 1.0; 0 => uniform)\n  bench     <folder> <cache> <concurrency> [ordered|unordered]   reopen + time one init (cache=entries, 0=off; concurrency=1 serial / N total build tasks)\n  destroy   <folder>                          delete the database"
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
        Some("bench") => match (
            argv.get(1),
            argv.get(2).and_then(|a| a.parse().ok()),
            argv.get(3).and_then(|a| parse_concurrency(a)),
            argv.get(4)
                .map_or(Some(IndexKind::Ordered), |a| IndexKind::parse(a)),
        ) {
            (Some(folder), Some(cache), Some(concurrency), Some(index)) => {
                bench(folder, cache, concurrency, index)
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
/// space, leaving it on disk for later `bench` runs. Reports the elapsed build time -- a large-scale
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
fn bench(folder: &str, cache: usize, concurrency: NonZeroUsize, index: IndexKind) {
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
        "init_scale ({label}) {folder} cache={cache} concurrency={concurrency} region={region} time={elapsed:?}"
    );
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

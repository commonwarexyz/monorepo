//! Benchmarks for range scans over an ordered QMDB.
//!
//! Each case seeds a database once, then times scans. Seeding writes the keys in random order
//! across many small batches, so keys that are adjacent in key order are far apart in the log, as
//! in a long-lived database.

use crate::{
    common::{AnyOFixDb, AnyOFixP64kDb, AnyOVarDigestDb, Digest},
    merkleize::{LARGE_PAGE_CACHE_SIZE, PAGE_SIZE, any_fix_cfg_with_cache, any_var_cfg_with_cache},
};
use commonware_cryptography::{Hasher as _, Sha256, sha256};
use commonware_runtime::{
    Runner as _, Supervisor as _,
    benchmarks::{context, tokio},
    buffer::paged::CacheRef,
    tokio::{Config, Context},
};
use commonware_storage::{
    merkle::{Family, mmr},
    qmdb::{
        any::{
            FixedConfig,
            traits::{DbAny, UnmerkleizedBatch as _},
        },
        floor::Proportional,
    },
};
use commonware_utils::{NZUsize, TestRng};
use criterion::{Criterion, criterion_group};
use futures::{StreamExt as _, TryStreamExt as _, future::ready};
use rand::{Rng as _, seq::SliceRandom as _};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

const NUM_KEYS: u64 = 100_000;
const KEYS_PER_BATCH: usize = 100;

/// Active keys per translated key. One models hashed keys. Sixteen models keys that share an
/// 8-byte prefix, such as one account's storage slots.
const BUCKET_SIZES: [u64; 2] = [1, 16];

/// The scans to time.
const SCANS: [Scan; 5] = [
    Scan::Take(10),
    Scan::Range(1),
    Scan::Range(10),
    Scan::Range(1_000),
    Scan::All,
];

/// A scan's shape. Random scans start at a random active key.
#[derive(Clone, Copy)]
enum Scan {
    /// An unbounded scan the caller stops after this many keys.
    Take(usize),
    /// A scan bounded to exactly this many keys.
    Range(usize),
    /// The whole database.
    All,
}

impl Scan {
    fn name(self) -> String {
        match self {
            Self::Take(len) => format!("scan=take len={len}"),
            Self::Range(len) => format!("scan=range len={len}"),
            Self::All => format!("scan=all len={NUM_KEYS}"),
        }
    }

    /// The number of keys the scan yields.
    const fn len(self) -> usize {
        match self {
            Self::Take(len) | Self::Range(len) => len,
            Self::All => NUM_KEYS as usize,
        }
    }
}

/// The database to scan.
#[derive(Clone, Copy)]
enum Variant {
    /// Fixed-size values, with the ordered snapshot index.
    Fixed,
    /// Fixed-size values, with the partitioned snapshot index (P=2).
    FixedP64k,
    /// Variable-size values, with the ordered snapshot index.
    Variable,
}

impl Variant {
    const fn name(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::FixedP64k => "fixed::p64k",
            Self::Variable => "variable",
        }
    }
}

/// Opens the variant's database as `$db`, with the page cache it reads through as `$cache`.
macro_rules! with_db {
    ($ctx:expr, $variant:expr, |$db:ident, $cache:ident| $body:expr) => {{
        let $cache = CacheRef::from_pooler(&$ctx, PAGE_SIZE, LARGE_PAGE_CACHE_SIZE);
        match $variant {
            Variant::Fixed => {
                let cfg = any_fix_cfg_with_cache(&$ctx, $cache.clone());
                let $db = AnyOFixDb::<mmr::Family>::init($ctx.child("storage"), cfg, None)
                    .await
                    .unwrap();
                $body
            }
            Variant::FixedP64k => {
                // The partitioned index takes a snapshot-build concurrency.
                let FixedConfig {
                    merkle_config,
                    journal_config,
                    translator,
                    init_cache,
                    init_buffer,
                    ..
                } = any_fix_cfg_with_cache(&$ctx, $cache.clone());
                let cfg = FixedConfig {
                    merkle_config,
                    journal_config,
                    translator,
                    init_cache,
                    init_buffer,
                    init_concurrency: NZUsize!(1),
                };
                let $db = AnyOFixP64kDb::<mmr::Family>::init($ctx.child("storage"), cfg, None)
                    .await
                    .unwrap();
                $body
            }
            Variant::Variable => {
                let cfg = any_var_cfg_with_cache(&$ctx, $cache.clone());
                let $db = AnyOVarDigestDb::<mmr::Family>::init($ctx.child("storage"), cfg, None)
                    .await
                    .unwrap();
                $body
            }
        }
    }};
}

/// Runs `$scan` `$iters` times and returns the total time. A cold scan clears the page cache first.
/// Each scan must yield the expected number of keys, so a scan that stops early cannot pass for a
/// fast one.
macro_rules! time_scans {
    ($db:ident, $cache:ident, $bucket:expr, $scan:expr, $cold:expr, $iters:expr) => {{
        let mut keys: Vec<Digest> = (0..NUM_KEYS).map(|i| key(i, $bucket)).collect();
        keys.sort_unstable();
        let count = |scan: Scan, start: usize| {
            let stream = match scan {
                Scan::Take(len) => $db
                    .stream_range(keys[start]..)
                    .take(len)
                    .left_stream()
                    .left_stream(),
                Scan::Range(len) => $db
                    .stream_range(keys[start]..keys[start + len])
                    .right_stream()
                    .left_stream(),
                Scan::All => $db.stream_range(..).right_stream(),
            };
            stream.try_fold(0usize, |count, _| ready(Ok(count + 1)))
        };

        // Each sample reopens the database, so fill the cache before timing warm scans.
        if !$cold {
            assert_eq!(count(Scan::All, 0).await.unwrap(), Scan::All.len());
        }
        let mut rng = TestRng::new(1);
        let mut total = Duration::ZERO;
        for _ in 0..$iters {
            let start = rng.next_u64() as usize % (keys.len() - 1_000);
            if $cold {
                $cache.clear();
            }
            let now = Instant::now();
            let count = count($scan, start).await.unwrap();
            total += now.elapsed();
            assert_eq!(black_box(count), $scan.len());
        }
        total
    }};
}

/// The `i`th seeded key: the hash of `i`, with its first 8 bytes taken from the hash of its bucket.
fn key(i: u64, bucket: u64) -> Digest {
    let mut key = Sha256::hash(&[&i.to_be_bytes()]).0;
    key[..8].copy_from_slice(&Sha256::hash(&[&(i / bucket).to_be_bytes()])[..8]);
    sha256::Digest(key)
}

async fn seed<F: Family, C: DbAny<F, Key = Digest, Value = Digest>>(mut db: C, bucket: u64) {
    let mut order: Vec<u64> = (0..NUM_KEYS).collect();
    order.shuffle(&mut TestRng::new(0));
    for chunk in order.chunks(KEYS_PER_BATCH) {
        let mut batch = db.new_batch();
        for &i in chunk {
            batch = batch.write(key(i, bucket), Some(Sha256::hash(&[&i.to_be_bytes()])));
        }
        let batch = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
        (db, _) = db.apply_batch(batch).await.unwrap();
    }
    db.sync().await.unwrap();
}

fn bench_stream_range(c: &mut Criterion) {
    let cfg = Config::default();
    for variant in [Variant::Fixed, Variant::FixedP64k, Variant::Variable] {
        for bucket in BUCKET_SIZES {
            // Seeded on the first matched case, then shared by the rest.
            let mut seeded = false;
            for scan in SCANS {
                for cold in [false, true] {
                    let runner = tokio::Runner::new(cfg.clone());
                    let name = format!(
                        "{}/db={} keys={NUM_KEYS} bucket={bucket} {} cache={}",
                        module_path!(),
                        variant.name(),
                        scan.name(),
                        if cold { "cold" } else { "warm" },
                    );
                    c.bench_function(&name, |b| {
                        if !seeded {
                            commonware_runtime::tokio::Runner::new(cfg.clone()).start(
                                |ctx| async move {
                                    with_db!(ctx, variant, |db, _cache| seed(db, bucket).await)
                                },
                            );
                            seeded = true;
                        }
                        b.to_async(&runner).iter_custom(move |iters| async move {
                            let ctx = context::get::<Context>();
                            with_db!(ctx, variant, |db, cache| {
                                time_scans!(db, cache, bucket, scan, cold, iters)
                            })
                        });
                    });
                }
            }

            if seeded {
                commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                    with_db!(ctx, variant, |db, _cache| db.destroy().await.unwrap())
                });
            }
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_stream_range
}

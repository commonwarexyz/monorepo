//! Benchmark for chained-growth merkleization against Current QMDB variants.
//!
//! Setup (untimed): seed `NUM_KEYS` keys, then grow a chain of `PREBUILT_CHAIN` batches applying
//! each parent while the child is still alive.
//!
//! Timed: do `batches` more merkleize + apply iterations on top of the pre-built chain, with a
//! single random update per batch so each overlay covers a tiny fraction of chunks.

use crate::common::{dispatch_arm, make_fixed_value, Digest};
use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context},
};
use commonware_storage::{
    merkle::{self, mmb::Family as Mmb},
    qmdb::{
        any::traits::{DbAny, MerkleizedBatch as _, UnmerkleizedBatch as _},
        current::{ordered::fixed::Db as OCFixed, unordered::fixed::Db as UCFixed},
    },
    translator::EightCap,
};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

const SMALL_CHUNK_SIZE: usize = 32;
const LARGE_CHUNK_SIZE: usize = 256;

type CurUFix32Mmb = UCFixed<Mmb, Context, Digest, Digest, Sha256, EightCap, SMALL_CHUNK_SIZE>;
type CurOFix32Mmb = OCFixed<Mmb, Context, Digest, Digest, Sha256, EightCap, SMALL_CHUNK_SIZE>;
type CurUFix256Mmb = UCFixed<Mmb, Context, Digest, Digest, Sha256, EightCap, LARGE_CHUNK_SIZE>;
type CurOFix256Mmb = OCFixed<Mmb, Context, Digest, Digest, Sha256, EightCap, LARGE_CHUNK_SIZE>;

/// Number of pre-populated keys in the seeded database.
const NUM_KEYS: u64 = 1_000_000;

/// Random updates per batch. One update means each batch's chunk overlay covers ~1 / num_chunks
/// of the bitmap, forcing chain reads to walk deep before finding a matching layer.
const UPDATES_PER_BATCH: u64 = 1;

/// Number of batches grown during the untimed seed phase, producing a Db::status chain of this
/// depth that subsequent reads must walk through.
const PREBUILT_CHAIN: u64 = 10_000;

/// Number of additional batches to grow during the timed region.
const GROW_COUNTS: [u64; 1] = [100];

#[derive(Debug, Clone, Copy)]
enum CurrentVariant {
    UnorderedFixed32,
    OrderedFixed32,
    UnorderedFixed256,
    OrderedFixed256,
}

impl CurrentVariant {
    const fn name(self) -> &'static str {
        match self {
            Self::UnorderedFixed32 => "current::unordered::fixed::mmb chunk=32",
            Self::OrderedFixed32 => "current::ordered::fixed::mmb chunk=32",
            Self::UnorderedFixed256 => "current::unordered::fixed::mmb chunk=256",
            Self::OrderedFixed256 => "current::ordered::fixed::mmb chunk=256",
        }
    }
}

const CURRENT_VARIANTS: [CurrentVariant; 4] = [
    CurrentVariant::UnorderedFixed32,
    CurrentVariant::OrderedFixed32,
    CurrentVariant::UnorderedFixed256,
    CurrentVariant::OrderedFixed256,
];

/// Construct a Current database for `$variant`, bind it as `$db`, and execute `$body`.
macro_rules! with_current_db {
    ($ctx:expr, $variant:expr, |mut $db:ident| $body:expr) => {{
        match $variant {
            CurrentVariant::UnorderedFixed32 => {
                dispatch_arm!($ctx, $db, $body, CurUFix32Mmb, cur_fix_cfg)
            }
            CurrentVariant::OrderedFixed32 => {
                dispatch_arm!($ctx, $db, $body, CurOFix32Mmb, cur_fix_cfg)
            }
            CurrentVariant::UnorderedFixed256 => {
                dispatch_arm!($ctx, $db, $body, CurUFix256Mmb, cur_fix_cfg)
            }
            CurrentVariant::OrderedFixed256 => {
                dispatch_arm!($ctx, $db, $body, CurOFix256Mmb, cur_fix_cfg)
            }
        }
    }};
}

/// Pre-populate the database with `num_keys` unique keys, then commit and sync so that
/// seed-phase buffered writes are flushed before the timer starts.
async fn seed_db<F: merkle::Family, C: DbAny<F, Key = Digest, Value = Digest>>(
    db: &mut C,
    num_keys: u64,
) {
    let mut rng = StdRng::seed_from_u64(42);
    let mut batch = db.new_batch();
    for i in 0u64..num_keys {
        let k = Sha256::hash(&i.to_be_bytes());
        batch = batch.write(k, Some(make_fixed_value(&mut rng)));
    }
    let merkleized = batch.merkleize(db, None).await.unwrap();
    db.apply_batch(merkleized).await.unwrap();
    db.commit().await.unwrap();
    db.sync().await.unwrap();
}

/// Write `num_updates` random key updates into a batch.
fn write_random_updates<
    B: commonware_storage::qmdb::any::traits::UnmerkleizedBatch<Db, K = Digest, V = Digest>,
    Db: ?Sized,
>(
    mut batch: B,
    num_updates: u64,
    num_keys: u64,
    rng: &mut StdRng,
) -> B {
    for _ in 0..num_updates {
        let idx = rng.next_u64() % num_keys;
        let k = Sha256::hash(&idx.to_be_bytes());
        batch = batch.write(k, Some(make_fixed_value(rng)));
    }
    batch
}

/// Run a chained-growth sequence with a pre-built deep chain.
///
/// `fork_child` bridges the generic trait and the concrete `new_batch` method on a merkleized
/// batch.
async fn run_chained_growth<
    F: merkle::Family,
    C: DbAny<F, Key = Digest, Value = Digest>,
    Fork: Fn(&C::Merkleized) -> C::Batch,
>(
    mut db: C,
    grow: u64,
    fork_child: Fork,
) -> Duration {
    seed_db(&mut db, NUM_KEYS).await;
    let mut rng = StdRng::seed_from_u64(99);

    // Pre-build a deep chain (untimed).
    let initial = write_random_updates(db.new_batch(), UPDATES_PER_BATCH, NUM_KEYS, &mut rng);
    let mut parent = initial.merkleize(&db, None).await.unwrap();
    for _ in 0..PREBUILT_CHAIN {
        let child_batch =
            write_random_updates(fork_child(&parent), UPDATES_PER_BATCH, NUM_KEYS, &mut rng);
        let child = child_batch.merkleize(&db, None).await.unwrap();
        db.apply_batch(parent).await.unwrap();
        parent = child;
    }

    // Flush buffered data so the timed region doesn't inherit setup fsync cost.
    db.commit().await.unwrap();
    db.sync().await.unwrap();

    // Timed: grow more batches on top of the pre-built chain.
    let start = Instant::now();
    for _ in 0..grow {
        let child_batch =
            write_random_updates(fork_child(&parent), UPDATES_PER_BATCH, NUM_KEYS, &mut rng);
        let child = child_batch.merkleize(&db, None).await.unwrap();
        black_box(child.root());
        db.apply_batch(parent).await.unwrap();
        parent = child;
    }
    db.apply_batch(parent).await.unwrap();
    let total = start.elapsed();

    db.destroy().await.unwrap();
    total
}

fn bench_chained_growth(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for batches in GROW_COUNTS {
        for &variant in &CURRENT_VARIANTS {
            c.bench_function(
                &format!(
                    "{}/variant={} batches={batches}",
                    module_path!(),
                    variant.name()
                ),
                |b| {
                    b.to_async(&runner).iter_custom(|iters| async move {
                        let ctx = context::get::<Context>();
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            with_current_db!(ctx.clone(), variant, |mut db| {
                                total += run_chained_growth(db, batches, |p| p.new_batch()).await;
                            });
                        }
                        total
                    });
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_chained_growth
}

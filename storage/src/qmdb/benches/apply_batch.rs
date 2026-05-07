//! Benchmarks for applying already-merkleized QMDB batches.

use crate::common::{any_fix_cfg, make_fixed_value, seed_db, AnyUFixDb, CHUNK_SIZE};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context},
    Supervisor,
};
use commonware_storage::{merkle::mmb::Family as Mmb, qmdb::any::traits::BatchableDb};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::time::{Duration, Instant};

const NUM_KEYS: u64 = 65_536;
const UPDATES: [u64; 1] = [16_384];

type Db = AnyUFixDb<Mmb>;

fn write_updates(
    mut batch: <Db as BatchableDb>::Batch,
    updates: u64,
    rng: &mut StdRng,
) -> <Db as BatchableDb>::Batch {
    for _ in 0..updates {
        let idx = rng.next_u64() % NUM_KEYS;
        let key = Sha256::hash(&idx.to_be_bytes());
        batch = batch.write(key, Some(make_fixed_value(rng)));
    }
    batch
}

async fn open_db(ctx: &Context) -> Db {
    Db::init(ctx.child("storage"), any_fix_cfg(ctx))
        .await
        .unwrap()
}

async fn bench_direct_apply(ctx: &Context, updates: u64) -> Duration {
    let mut db = open_db(ctx).await;
    seed_db(&mut db, NUM_KEYS).await;

    let mut rng = StdRng::seed_from_u64(7);
    let batch = write_updates(db.new_batch(), updates, &mut rng);
    let batch = batch.merkleize(&db, None).await.unwrap();

    let start = Instant::now();
    db.apply_batch(batch).await.unwrap();
    let elapsed = start.elapsed();

    db.destroy().await.unwrap();
    elapsed
}

async fn bench_apply_with_uncommitted_ancestor(ctx: &Context, updates: u64) -> Duration {
    let mut db = open_db(ctx).await;
    seed_db(&mut db, NUM_KEYS).await;

    let mut rng = StdRng::seed_from_u64(7);
    let parent = write_updates(db.new_batch(), updates, &mut rng);
    let parent = parent.merkleize(&db, None).await.unwrap();

    let child = write_updates(parent.new_batch(), updates, &mut rng);
    let child = child.merkleize(&db, None).await.unwrap();

    let start = Instant::now();
    db.apply_batch(child).await.unwrap();
    let elapsed = start.elapsed();

    db.destroy().await.unwrap();
    elapsed
}

async fn bench_apply_with_committed_ancestor(ctx: &Context, updates: u64) -> Duration {
    let mut db = open_db(ctx).await;
    seed_db(&mut db, NUM_KEYS).await;

    let mut rng = StdRng::seed_from_u64(7);
    let parent = write_updates(db.new_batch(), updates, &mut rng);
    let parent = parent.merkleize(&db, None).await.unwrap();

    let child = write_updates(parent.new_batch(), updates, &mut rng);
    let child = child.merkleize(&db, None).await.unwrap();

    db.apply_batch(parent).await.unwrap();

    let start = Instant::now();
    db.apply_batch(child).await.unwrap();
    let elapsed = start.elapsed();

    db.destroy().await.unwrap();
    elapsed
}

// 1 committed + 1 uncommitted ancestor: apply A, then apply C (whose chain is [B, A]).
async fn bench_apply_committed_uncommitted_chain(ctx: &Context, updates: u64) -> Duration {
    let mut db = open_db(ctx).await;
    seed_db(&mut db, NUM_KEYS).await;

    let mut rng = StdRng::seed_from_u64(7);
    let a = write_updates(db.new_batch(), updates, &mut rng);
    let a = a.merkleize(&db, None).await.unwrap();

    let b = write_updates(a.new_batch(), updates, &mut rng);
    let b = b.merkleize(&db, None).await.unwrap();

    let c = write_updates(b.new_batch(), updates, &mut rng);
    let c = c.merkleize(&db, None).await.unwrap();

    db.apply_batch(a).await.unwrap();

    let start = Instant::now();
    db.apply_batch(c).await.unwrap();
    let elapsed = start.elapsed();

    db.destroy().await.unwrap();
    elapsed
}

// 2 uncommitted ancestors: apply C directly without applying A or B.
async fn bench_apply_multi_uncommitted(ctx: &Context, updates: u64) -> Duration {
    let mut db = open_db(ctx).await;
    seed_db(&mut db, NUM_KEYS).await;

    let mut rng = StdRng::seed_from_u64(7);
    let a = write_updates(db.new_batch(), updates, &mut rng);
    let a = a.merkleize(&db, None).await.unwrap();

    let b = write_updates(a.new_batch(), updates, &mut rng);
    let b = b.merkleize(&db, None).await.unwrap();

    let c = write_updates(b.new_batch(), updates, &mut rng);
    let c = c.merkleize(&db, None).await.unwrap();

    drop(a);
    drop(b);

    let start = Instant::now();
    db.apply_batch(c).await.unwrap();
    let elapsed = start.elapsed();

    db.destroy().await.unwrap();
    elapsed
}

fn bench_apply_batch(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());

    for updates in UPDATES {
        c.bench_function(
            &format!(
                "{}/case=direct variant=any::unordered::fixed::mmb chunk={CHUNK_SIZE} updates={updates}",
                module_path!(),
            ),
            |b| {
                b.to_async(&runner).iter_custom(|iters| async move {
                    let ctx = context::get::<Context>();
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        total += bench_direct_apply(&ctx, updates).await;
                    }
                    total
                });
            },
        );

        c.bench_function(
            &format!(
                "{}/case=uncomm_ancestor variant=any::unordered::fixed::mmb chunk={CHUNK_SIZE} updates={updates}",
                module_path!(),
            ),
            |b| {
                b.to_async(&runner).iter_custom(|iters| async move {
                    let ctx = context::get::<Context>();
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        total += bench_apply_with_uncommitted_ancestor(&ctx, updates).await;
                    }
                    total
                });
            },
        );

        c.bench_function(
            &format!(
                "{}/case=comm_ancestor variant=any::unordered::fixed::mmb chunk={CHUNK_SIZE} updates={updates}",
                module_path!(),
            ),
            |b| {
                b.to_async(&runner).iter_custom(|iters| async move {
                    let ctx = context::get::<Context>();
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        total += bench_apply_with_committed_ancestor(&ctx, updates).await;
                    }
                    total
                });
            },
        );

        c.bench_function(
            &format!(
                "{}/case=comm_uncomm_chain variant=any::unordered::fixed::mmb chunk={CHUNK_SIZE} updates={updates}",
                module_path!(),
            ),
            |b| {
                b.to_async(&runner).iter_custom(|iters| async move {
                    let ctx = context::get::<Context>();
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        total += bench_apply_committed_uncommitted_chain(&ctx, updates).await;
                    }
                    total
                });
            },
        );

        c.bench_function(
            &format!(
                "{}/case=multi_uncomm variant=any::unordered::fixed::mmb chunk={CHUNK_SIZE} updates={updates}",
                module_path!(),
            ),
            |b| {
                b.to_async(&runner).iter_custom(|iters| async move {
                    let ctx = context::get::<Context>();
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        total += bench_apply_multi_uncommitted(&ctx, updates).await;
                    }
                    total
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_apply_batch
}

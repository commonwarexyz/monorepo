//! Merkleize children of a large pending ordered batch. Setup and child construction are
//! untimed; timing includes merkleization, reading the root, and dropping the child.
//!
//! The committed seed contains `KEYS` keys; the optional pending parent overwrites all of
//! them. Each iteration forks the same parent. `value=0` uses fixed-layout `Digest` values;
//! positive sizes use `Vec<u8>` values in a variable-layout journal without compression.

use crate::common::{AnyOFixDb, AnyOVarVecDb, Digest, any_fix_cfg, any_var_vec_cfg};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_runtime::{
    Supervisor as _,
    benchmarks::{context, tokio},
    tokio::Context,
};
use commonware_storage::{
    merkle::mmb::Family,
    qmdb::any::traits::{DbAny, MerkleizedBatch as _, UnmerkleizedBatch as _},
};
use criterion::{Criterion, criterion_group};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

const KEYS: u64 = 32_768;

fn key(i: u64) -> Digest {
    Sha256::hash(&[&i.to_be_bytes()])
}

async fn measure<C: DbAny<Family, Key = Digest>>(
    mut db: C,
    value: C::Value,
    child_of: fn(&C::Merkleized) -> C::Batch,
    pending: bool,
    creates: bool,
    count: u64,
    iters: u64,
) -> Duration {
    let mut seed = db.new_batch();
    for i in 0..KEYS {
        seed = seed.write(key(2 * i), Some(value.clone()));
    }
    let seed = seed.merkleize(&db, None).await.unwrap();
    (db, _) = db.apply_batch(seed).await.unwrap();
    db = db.sync().await.unwrap();

    let parent = if pending {
        let mut batch = db.new_batch();
        for i in 0..KEYS {
            batch = batch.write(key(2 * i), Some(value.clone()));
        }
        Some(batch.merkleize(&db, None).await.unwrap())
    } else {
        None
    };

    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let mut child = parent.as_ref().map_or_else(|| db.new_batch(), child_of);
        for i in 0..count {
            let index = i * (KEYS / count);
            child = child.write(key(2 * index + u64::from(creates)), Some(value.clone()));
        }
        let start = Instant::now();
        let child = child.merkleize(&db, None).await.unwrap();
        black_box(child.root());
        drop(child);
        total += start.elapsed();
    }
    drop(parent);
    db.destroy().await.unwrap();
    total
}

fn bench_ancestor_candidates(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    for (pending, creates, count) in [
        (false, false, 256),
        (true, false, 256),
        (true, true, 256),
        (true, true, KEYS),
    ] {
        for size in [0, 32, 1024] {
            let name = format!(
                "{}/parent={KEYS} pending={pending} creates={creates} child={count} value={size}",
                module_path!(),
            );
            c.bench_function(&name, |b| {
                b.to_async(&runner).iter_custom(|iters| async move {
                    let ctx = context::get::<Context>();
                    if size == 0 {
                        let db = AnyOFixDb::<Family>::init(ctx.child("storage"), any_fix_cfg(&ctx))
                            .await
                            .unwrap();
                        measure(
                            db,
                            key(0),
                            |p| p.new_batch::<Sha256>(),
                            pending,
                            creates,
                            count,
                            iters,
                        )
                        .await
                    } else {
                        let db = AnyOVarVecDb::<Family>::init(
                            ctx.child("storage"),
                            any_var_vec_cfg(&ctx),
                        )
                        .await
                        .unwrap();
                        measure(
                            db,
                            vec![42; size],
                            |p| p.new_batch::<Sha256>(),
                            pending,
                            creates,
                            count,
                            iters,
                        )
                        .await
                    }
                });
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20).warm_up_time(Duration::from_secs(1)).measurement_time(Duration::from_secs(3));
    targets = bench_ancestor_candidates,
}

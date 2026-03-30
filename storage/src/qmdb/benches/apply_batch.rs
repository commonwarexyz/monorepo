//! Benchmarks for QMDB changeset application in isolation.
//!
//! Measures the time to apply a merkleized changeset to the database,
//! separated from batch construction and merkleization.

use crate::common::{make_fixed_value, with_fixed_value_db, FIXED_VALUE_VARIANTS};
use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context},
};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::time::{Duration, Instant};

const SEED_ELEMENTS: u64 = 1_000;

fn bench_fixed_value_apply_batch(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    for batch_size in [100u64, 1_000, 10_000] {
        for variant in FIXED_VALUE_VARIANTS {
            c.bench_function(
                &format!(
                    "{}/variant={} batch_size={batch_size}",
                    module_path!(),
                    variant.name(),
                ),
                |b| {
                    b.to_async(&runner).iter_custom(|iters| async move {
                        let ctx = context::get::<Context>();
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            total += with_fixed_value_db!(ctx, variant, |mut db| {
                                // Seed with a small base dataset
                                let mut rng = StdRng::seed_from_u64(42);
                                {
                                    let mut batch = db.new_batch();
                                    for i in 0u64..SEED_ELEMENTS {
                                        let k = Sha256::hash(&i.to_be_bytes());
                                        batch = batch.write(k, Some(make_fixed_value(&mut rng)));
                                    }
                                    let finalized =
                                        batch.merkleize(None, &db).await.unwrap().finalize();
                                    db.apply_batch(finalized).await.unwrap();
                                }

                                // Build and merkleize batch (untimed)
                                let mut batch = db.new_batch();
                                for _ in 0..batch_size {
                                    let k = Sha256::hash(
                                        &(rng.next_u64() % SEED_ELEMENTS).to_be_bytes(),
                                    );
                                    batch = batch.write(k, Some(make_fixed_value(&mut rng)));
                                }
                                let changeset =
                                    batch.merkleize(None, &db).await.unwrap().finalize();

                                // Time only apply_batch
                                let start = Instant::now();
                                db.apply_batch(changeset).await.unwrap();
                                let elapsed = start.elapsed();

                                db.destroy().await.unwrap();
                                elapsed
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
    targets = bench_fixed_value_apply_batch
}

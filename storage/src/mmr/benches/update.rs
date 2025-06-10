use commonware_cryptography::{sha256, Digest as _, Sha256};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
};
use commonware_storage::mmr::{hasher::Standard, mem::Mmr};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{collections::HashMap, time::Instant};

#[derive(PartialEq, Debug, Clone, Copy)]
enum SyncType {
    NoBatching,
    BatchedSerial,
    BatchedParallel,
}

/// Minimum number of computations required to trigger parallelization. This value doesn't appear to
/// impact performance all that much so we use just this fixed value for all benchmarks.
const MIN_TO_PARALLELIZE: usize = 100;

/// Threads (cores) to use for parallelization. We pick 8 since our benchmarking pipeline is
/// configured to provide 8 cores. More threads may be faster on machines with more cores, but
/// returns start diminishing.
const THREADS: usize = 8;

/// Benchmark the performance of randomly updating leaves in an MMR.
fn bench_update(c: &mut Criterion) {
    let cfg = Config::default();
    let runner = tokio::Runner::new(cfg);
    for updates in [1_000_000, 100_000] {
        for leaves in [100_000, 1_000_000, 5_000_000, 10_000_000] {
            for sync_type in [
                SyncType::NoBatching,
                SyncType::BatchedSerial,
                SyncType::BatchedParallel,
            ] {
                c.bench_function(
                    &format!(
                        "{}/updates={} leaves={} sync_type={:?}",
                        module_path!(),
                        updates,
                        leaves,
                        sync_type,
                    ),
                    |b| {
                        b.to_async(&runner).iter_custom(|_iters| async move {
                            let mut mmr = Mmr::<Sha256>::new();
                            let mut elements = Vec::with_capacity(leaves as usize);
                            let mut sampler = StdRng::seed_from_u64(0);
                            let mut leaf_positions = Vec::with_capacity(leaves as usize);
                            let mut h = Standard::new();

                            // Append random elements to MMR
                            for _ in 0..leaves {
                                let digest = sha256::Digest::random(&mut sampler);
                                elements.push(digest);
                                let pos = mmr.add(&mut h, &digest);
                                leaf_positions.push(pos);
                            }
                            let ctx = context::get::<commonware_runtime::tokio::Context>();
                            let mut pool =
                                commonware_runtime::create_pool(ctx.clone(), THREADS).unwrap();

                            // Randomly update leaves -- this is what we are benchmarking.
                            let start = Instant::now();

                            // Simulate leaf-batching being the responsibility of the caller.
                            let mut leaf_map = HashMap::new();
                            for _ in 0..updates {
                                let rand_leaf_num = sampler.gen_range(0..leaves);
                                let rand_leaf_pos = leaf_positions[rand_leaf_num as usize];
                                let rand_leaf_swap = sampler.gen_range(0..elements.len());
                                let new_element = &elements[rand_leaf_swap];
                                leaf_map.insert(rand_leaf_pos, *new_element);
                            }

                            match sync_type {
                                SyncType::NoBatching => {
                                    for (pos, element) in leaf_map {
                                        mmr.update_leaf(&mut h, pos, &element);
                                    }
                                }
                                SyncType::BatchedSerial => {
                                    mmr.update_leaf_batched(&mut h, leaf_map.into_iter());
                                }
                                SyncType::BatchedParallel => {
                                    let update_vec = leaf_map
                                        .into_iter()
                                        .collect::<Vec<(u64, sha256::Digest)>>();
                                    mmr.update_leaf_parallel(
                                        &mut h,
                                        &mut pool,
                                        MIN_TO_PARALLELIZE,
                                        update_vec,
                                    );
                                }
                            }

                            if sync_type == SyncType::BatchedParallel {
                                mmr.sync_parallel(&mut h, &mut pool, MIN_TO_PARALLELIZE);
                            } else {
                                mmr.sync(&mut h);
                            }

                            start.elapsed()
                        });
                    },
                );
            }
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_update
}

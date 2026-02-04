use commonware_cryptography::{sha256, Sha256};
use commonware_math::algebra::Random as _;
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
    ThreadPooler,
};
use commonware_storage::mmr::{mem::DirtyMmr, Location, StandardHasher};
use commonware_utils::NZUsize;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{collections::HashMap, num::NonZeroUsize, time::Instant};

#[derive(PartialEq, Debug, Clone, Copy)]
enum Strategy {
    NoBatching,
    BatchedSerial,
    BatchedParallel,
}

/// Threads (cores) to use for parallelization. We pick 8 since our benchmarking pipeline is
/// configured to provide 8 cores. More threads may be faster on machines with more cores, but
/// returns start diminishing.
const THREADS: NonZeroUsize = NZUsize!(8);

#[cfg(not(full_bench))]
const N_LEAVES: [usize; 1] = [100_000];
#[cfg(full_bench)]
const N_LEAVES: [usize; 4] = [100_000, 1_000_000, 5_000_000, 10_000_000];

/// Benchmark the performance of randomly updating leaves in an MMR.
fn bench_update(c: &mut Criterion) {
    let cfg = Config::default();
    let runner = tokio::Runner::new(cfg);
    for updates in [1_000_000, 100_000] {
        for leaves in N_LEAVES {
            for strategy in [
                Strategy::NoBatching,
                Strategy::BatchedSerial,
                Strategy::BatchedParallel,
            ] {
                c.bench_function(
                    &format!(
                        "{}/updates={} leaves={} strategy={:?}",
                        module_path!(),
                        updates,
                        leaves,
                        strategy,
                    ),
                    |b| {
                        b.to_async(&runner).iter_custom(|_iters| async move {
                            let pool = match strategy {
                                Strategy::BatchedParallel => {
                                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                                    let pool = ctx.create_thread_pool(THREADS).unwrap();
                                    Some(pool)
                                }
                                _ => None,
                            };
                            let mut elements = Vec::with_capacity(leaves);
                            let mut sampler = StdRng::seed_from_u64(0);
                            let mut leaf_locations = Vec::with_capacity(leaves);
                            let mut h = StandardHasher::<Sha256>::new();

                            // Append random elements to MMR
                            let mut mmr = DirtyMmr::new();
                            for _ in 0..leaves {
                                let digest = sha256::Digest::random(&mut sampler);
                                elements.push(digest);
                                let pos = mmr.add(&mut h, &digest);
                                let loc = Location::try_from(pos).expect("leaf position");
                                leaf_locations.push(loc);
                            }
                            let mut mmr = mmr.merkleize(&mut h, None);

                            // Randomly update leaves -- this is what we are benchmarking.
                            let start = Instant::now();

                            // Simulate leaf-batching being the responsibility of the caller.
                            let mut leaf_map = HashMap::new();
                            for _ in 0..updates {
                                let rand_leaf_num = sampler.gen_range(0..leaves);
                                let rand_leaf_loc = leaf_locations[rand_leaf_num];
                                let rand_leaf_swap = sampler.gen_range(0..elements.len());
                                let new_element = &elements[rand_leaf_swap];
                                leaf_map.insert(rand_leaf_loc, *new_element);
                            }

                            match strategy {
                                Strategy::NoBatching => {
                                    for (loc, element) in &leaf_map {
                                        mmr.update_leaf(&mut h, *loc, element).unwrap();
                                    }
                                }
                                _ => {
                                    // Collect the map into a Vec of (position, element) pairs for batched updates
                                    let updates: Vec<(
                                        Location,
                                        commonware_cryptography::sha256::Digest,
                                    )> = leaf_map.into_iter().collect();
                                    let mut mmr = mmr.into_dirty();
                                    mmr.update_leaf_batched(&mut h, pool.clone(), &updates)
                                        .unwrap();
                                    mmr.merkleize(&mut h, pool);
                                }
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

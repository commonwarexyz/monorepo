use commonware_cryptography::{sha256, Sha256};
use commonware_math::algebra::Random as _;
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
    ThreadPooler,
};
use commonware_storage::merkle::{self, mem::Mem, Family, Location};
use commonware_utils::NZUsize;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{collections::HashMap, num::NonZeroUsize, time::Instant};

type StandardHasher<H> = merkle::hasher::Standard<H>;

#[derive(PartialEq, Debug, Clone, Copy)]
enum Mode {
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

fn bench_update_family<F: Family>(c: &mut Criterion, runner: &tokio::Runner, family: &str) {
    for updates in [1_000_000, 100_000] {
        for leaves in N_LEAVES {
            for mode in [Mode::BatchedSerial, Mode::BatchedParallel] {
                c.bench_function(
                    &format!(
                        "{}/updates={updates} leaves={leaves} strategy={mode:?} family={family}",
                        module_path!(),
                    ),
                    |b| {
                        b.to_async(runner).iter_custom(|iters| async move {
                            let strategy = match mode {
                                Mode::BatchedParallel => {
                                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                                    Some(ctx.create_strategy(THREADS).unwrap())
                                }
                                Mode::BatchedSerial => None,
                            };
                            let mut elements = Vec::with_capacity(leaves);
                            let mut sampler = StdRng::seed_from_u64(0);
                            let mut leaf_locations = Vec::with_capacity(leaves);
                            let h = StandardHasher::<Sha256>::new();

                            let mut mem = Mem::<F, _>::new(&h);
                            let batch = {
                                let mut batch = mem.new_batch();
                                for _ in 0..leaves {
                                    let digest = sha256::Digest::random(&mut sampler);
                                    elements.push(digest);
                                    let loc = batch.leaves();
                                    leaf_locations.push(loc);
                                    batch = batch.add(&h, &digest);
                                }
                                batch.merkleize(&mem, &h)
                            };
                            mem.apply_batch(&batch).unwrap();

                            // Randomly update leaves -- this is what we are benchmarking.
                            let start = Instant::now();
                            for _ in 0..iters {
                                // Simulate leaf-batching being the responsibility of the caller.
                                let mut leaf_map = HashMap::new();
                                for _ in 0..updates {
                                    let rand_leaf_num = sampler.gen_range(0..leaves);
                                    let rand_leaf_loc = leaf_locations[rand_leaf_num];
                                    let rand_leaf_swap = sampler.gen_range(0..elements.len());
                                    let new_element = &elements[rand_leaf_swap];
                                    leaf_map.insert(rand_leaf_loc, *new_element);
                                }

                                let updates: Vec<(
                                    Location<F>,
                                    commonware_cryptography::sha256::Digest,
                                )> = leaf_map.into_iter().collect();
                                match strategy {
                                    Some(ref s) => {
                                        let mut batch = mem.new_batch_with_strategy(s.clone());
                                        batch = batch.update_leaf_batched(&updates).unwrap();
                                        let batch = batch.merkleize(&mem, &h);
                                        mem.apply_batch(&batch).unwrap();
                                    }
                                    None => {
                                        let mut batch = mem.new_batch();
                                        batch = batch.update_leaf_batched(&updates).unwrap();
                                        let batch = batch.merkleize(&mem, &h);
                                        mem.apply_batch(&batch).unwrap();
                                    }
                                };
                            }
                            start.elapsed()
                        });
                    },
                );
            }
        }
    }
}

fn bench_update(c: &mut Criterion) {
    let cfg = Config::default();
    let runner = tokio::Runner::new(cfg);
    bench_update_family::<commonware_storage::mmr::Family>(c, &runner, "mmr");
    bench_update_family::<commonware_storage::mmb::Family>(c, &runner, "mmb");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_update
}

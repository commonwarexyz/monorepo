use commonware_cryptography::{sha256, Digest as _, Hasher, Sha256};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
};
use commonware_storage::mmr::{hasher::Standard, mem::Mmr};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::time::Instant;

#[derive(PartialEq, Debug, Clone, Copy)]
enum SyncType {
    NoBatching,
    Batched,
    Parallel,
}
//
/// Benchmark the performance of randomly updating leaves in an MMR.
fn bench_update(c: &mut Criterion) {
    let cfg = Config::default();
    let runner = tokio::Runner::new(cfg);
    for updates in [100_000, 1_000_000] {
        for leaves in [10_000u64, 100_000, 1_000_000, 5_000_000, 10_000_000] {
            for sync_type in [SyncType::NoBatching, SyncType::Batched, SyncType::Parallel] {
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
                            let mut h = Sha256::new();
                            let mut h = Standard::new(&mut h);

                            // Append random elements to MMR
                            for _ in 0..leaves {
                                let digest = sha256::Digest::random(&mut sampler);
                                elements.push(digest);
                                let pos = mmr.add(&mut h, &digest).await.unwrap();
                                leaf_positions.push(pos);
                            }
                            let ctx = context::get::<commonware_runtime::tokio::Context>();
                            let mut pool = commonware_runtime::create_pool(ctx.clone(), 8).unwrap();

                            // Randomly update leaves -- this is what we are benchmarking.
                            let start = Instant::now();
                            for _ in 0..updates {
                                let rand_leaf_num = sampler.gen_range(0..leaves);
                                let rand_leaf_pos = leaf_positions[rand_leaf_num as usize];
                                let rand_leaf_swap = sampler.gen_range(0..elements.len());
                                let new_element = &elements[rand_leaf_swap];
                                if sync_type != SyncType::NoBatching {
                                    mmr.update_leaf_batched(&mut h, rand_leaf_pos, new_element)
                                        .await
                                        .unwrap();
                                } else {
                                    mmr.update_leaf(&mut h, rand_leaf_pos, new_element)
                                        .await
                                        .unwrap();
                                }
                            }
                            if sync_type == SyncType::Parallel {
                                mmr.sync_parallel_by_level(&mut h, &mut pool, 100);
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

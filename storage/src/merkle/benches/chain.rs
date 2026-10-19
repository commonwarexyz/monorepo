use commonware_cryptography::{Sha256, sha256};
use commonware_math::algebra::Random as _;
use commonware_runtime::{
    Strategizer,
    benchmarks::{context, tokio},
    tokio::Config,
};
use commonware_storage::merkle::{self, Bagging::ForwardFold, Family, Location, mem::Mem};
use commonware_utils::{NZUsize, test_rng};
use criterion::{Criterion, criterion_group};
use rand::{CryptoRng, RngExt as _};
use std::{
    num::NonZeroUsize,
    time::{Duration, Instant},
};

type StandardHasher<H> = merkle::hasher::Standard<H>;

/// Threads (cores) to use for parallelization, matching the update benchmark.
const THREADS: NonZeroUsize = NZUsize!(8);

/// Random leaf updates in each batch.
const UPDATES: usize = 10_000;

#[cfg(not(full_bench))]
const N_LEAVES: [usize; 1] = [100_000];
#[cfg(full_bench)]
const N_LEAVES: [usize; 2] = [100_000, 1_000_000];

fn random_updates<F: Family>(
    rng: &mut impl CryptoRng,
    leaves: usize,
) -> Vec<(Location<F>, sha256::Digest)> {
    (0..UPDATES)
        .map(|_| {
            let loc = Location::new(rng.random_range(0..leaves as u64));
            (loc, sha256::Digest::random(&mut *rng))
        })
        .collect()
}

/// Merkleize a batch of random leaf updates on top of `pending` unapplied batches of random leaf
/// updates.
fn bench_chain_family<F: Family>(c: &mut Criterion, runner: &tokio::Runner, family: &str) {
    for leaves in N_LEAVES {
        for pending in [1, 2, 4] {
            c.bench_function(
                &format!(
                    "{}/updates={UPDATES} leaves={leaves} pending={pending} family={family}",
                    module_path!(),
                ),
                |b| {
                    b.to_async(runner).iter_custom(|iters| async move {
                        let ctx = context::get::<commonware_runtime::tokio::Context>();
                        let strategy = ctx.strategy(THREADS);
                        let mut rng = test_rng();
                        let h = StandardHasher::<Sha256>::new(ForwardFold);

                        let mut mem = Mem::<F, _>::new();
                        let batch = {
                            let mut batch = mem.new_batch();
                            for _ in 0..leaves {
                                batch = batch.add(&h, &sha256::Digest::random(&mut rng));
                            }
                            batch.merkleize(&mem, &h)
                        };
                        mem.apply_batch(&batch).unwrap();

                        // As in QMDB, the root batch over `mem` is dropped once the first batch
                        // merkleizes, and only the pending batches stay alive.
                        let updates = random_updates::<F>(&mut rng, leaves);
                        let first = mem
                            .new_batch_with_strategy(strategy)
                            .update_leaf_batched(&updates)
                            .unwrap()
                            .merkleize(&mem, &h);
                        let mut chain = vec![first];
                        for _ in 1..pending {
                            let updates = random_updates::<F>(&mut rng, leaves);
                            let batch = chain.last().unwrap().new_batch();
                            let batch = batch.update_leaf_batched(&updates).unwrap();
                            chain.push(batch.merkleize(&mem, &h));
                        }
                        let parent = chain.last().unwrap();

                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            let updates = random_updates::<F>(&mut rng, leaves);
                            let batch = parent.new_batch().update_leaf_batched(&updates).unwrap();
                            let start = Instant::now();
                            let _merkleized = batch.merkleize(&mem, &h);
                            total += start.elapsed();
                        }
                        total
                    });
                },
            );
        }
    }
}

fn bench_chain(c: &mut Criterion) {
    let cfg = Config::default();
    let runner = tokio::Runner::new(cfg);
    bench_chain_family::<commonware_storage::mmr::Family>(c, &runner, "mmr");
    bench_chain_family::<commonware_storage::mmb::Family>(c, &runner, "mmb");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_chain
}

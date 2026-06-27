//! Benchmark for building a large in-memory MMR/MMB from a batch of leaves.
//!
//! Mirrors how databases actually build the structure (e.g. `qmdb`): leaf digests are computed
//! (optionally in parallel via the strategy), appended in bulk with `add_leaf_digests`, merkleized
//! (node hashing parallelized by the strategy), and applied. The timed region is the full build;
//! one-time element generation is setup. Contrast with `append`, which builds via per-leaf `add`.

use commonware_cryptography::{sha256, Sha256};
use commonware_math::algebra::Random as _;
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::{Config, Context},
    ThreadPooler,
};
use commonware_storage::merkle::{
    self, hasher::Hasher as _, mem::Mem, Bagging::ForwardFold, Family, Location,
};
use commonware_utils::NZUsize;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::{
    hint::black_box,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

type StandardHasher<H> = merkle::hasher::Standard<H>;

const THREADS: NonZeroUsize = NZUsize!(8);

#[cfg(not(full_bench))]
const N_LEAVES: [usize; 2] = [100_000, 1_000_000];
#[cfg(full_bench)]
const N_LEAVES: [usize; 4] = [100_000, 1_000_000, 5_000_000, 10_000_000];

fn make_elements(n: usize) -> Vec<sha256::Digest> {
    let mut sampler = StdRng::seed_from_u64(0);
    (0..n)
        .map(|_| sha256::Digest::random(&mut sampler))
        .collect()
}

/// Full build: (strategy-parallel) leaf hashing, bulk append, merkleize, apply.
fn build<F: Family, S: Strategy>(
    h: &StandardHasher<Sha256>,
    elements: &[sha256::Digest],
    strategy: S,
) -> sha256::Digest {
    let leaf_digests: Vec<sha256::Digest> = strategy.map_init_collect_vec(
        elements.iter().enumerate(),
        || (),
        |_, (i, e)| h.leaf_digest(Location::<F>::new(i as u64), e.as_ref()),
    );
    let mut mem = Mem::<F, sha256::Digest>::new();
    let batch = mem
        .new_batch_with_strategy(strategy)
        .add_leaf_digests(leaf_digests);
    let merkleized = batch.merkleize(&mem, h);
    mem.apply_batch(&merkleized).unwrap();
    mem.root(h, 0).unwrap()
}

fn bench_build_family<F: Family>(c: &mut Criterion, runner: &tokio::Runner, family: &str) {
    for &n in N_LEAVES.iter() {
        for parallel in [false, true] {
            c.bench_function(
                &format!(
                    "{}/n={n} family={family} parallel={parallel}",
                    module_path!()
                ),
                |b| {
                    b.to_async(runner).iter_custom(move |iters| async move {
                        let ctx = context::get::<Context>();
                        let h = StandardHasher::<Sha256>::new(ForwardFold);
                        let elements = make_elements(n);
                        let strategy: Option<Rayon> = if parallel {
                            Some(ctx.create_strategy(THREADS).unwrap())
                        } else {
                            None
                        };
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            let start = Instant::now();
                            let root = strategy.as_ref().map_or_else(
                                || build::<F, _>(&h, &elements, Sequential),
                                |s| build::<F, _>(&h, &elements, s.clone()),
                            );
                            total += start.elapsed();
                            black_box(root);
                        }
                        total
                    });
                },
            );
        }
    }
}

fn bench_build(c: &mut Criterion) {
    let runner = tokio::Runner::new(Config::default());
    bench_build_family::<commonware_storage::mmr::Family>(c, &runner, "mmr");
    bench_build_family::<commonware_storage::mmb::Family>(c, &runner, "mmb");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_build
}

use commonware_cryptography::{sha256, Sha256};
use commonware_math::algebra::Random as _;
use commonware_storage::merkle::{
    self, mem::Mem, Bagging::ForwardFold, Family, Location, LocationRangeExt as _,
};
use criterion::{criterion_group, BatchSize, Criterion};
use futures::executor::block_on;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::ops::Range;

type StandardHasher<H> = merkle::hasher::Standard<H>;

const SAMPLE_SIZE: usize = 100;

#[cfg(not(full_bench))]
const N_LEAVES: [usize; 2] = [10_000, 100_000];
#[cfg(full_bench)]
const N_LEAVES: [usize; 5] = [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000];

type Sample<F> = (Range<Location<F>>, Vec<sha256::Digest>);

fn make_test_data<F: Family>(
    n: usize,
    range: u64,
) -> (Mem<F, sha256::Digest>, sha256::Digest, Vec<Sample<F>>) {
    let hasher = StandardHasher::<Sha256>::new(ForwardFold);
    let mut mem = Mem::<F, _>::new();
    let mut elements = Vec::with_capacity(n);
    let mut sampler = StdRng::seed_from_u64(0);

    block_on(async {
        let batch = {
            let mut batch = mem.new_batch();
            for _ in 0..n {
                let element = sha256::Digest::random(&mut sampler);
                batch = batch.add(&hasher, &element);
                elements.push(element);
            }
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();
    });
    let root = mem.root(&hasher, 0).unwrap();
    let max_start = n as u64 - range;
    let mut samples: Vec<Sample<F>> = Vec::with_capacity(SAMPLE_SIZE);
    while samples.len() < SAMPLE_SIZE {
        let start_index = sampler.gen_range(0..max_start);
        let leaf_range = Location::<F>::new(start_index)..Location::<F>::new(start_index + range);
        if samples
            .iter()
            .any(|(range, _)| range.start == leaf_range.start)
        {
            continue;
        }
        let expected = elements[leaf_range.to_usize_range()].to_vec();
        samples.push((leaf_range, expected));
    }
    (mem, root, samples)
}

fn bench_prove_many_elements_family<F: Family>(c: &mut Criterion, family: &str) {
    for n in N_LEAVES {
        for range in [2, 5, 10, 25, 50, 100, 250, 500, 1_000, 5_000] {
            c.bench_function(
                &format!(
                    "{}/n={n} range={range} samples={SAMPLE_SIZE} family={family}",
                    module_path!(),
                ),
                |b| {
                    b.iter_batched(
                        || make_test_data::<F>(n, range),
                        |(mem, root, samples)| {
                            let hasher = StandardHasher::<Sha256>::new(ForwardFold);
                            block_on(async {
                                for (range, elements) in samples {
                                    let proof = mem.range_proof(&hasher, range.clone(), 0).unwrap();
                                    assert!(proof.verify_range_inclusion(
                                        &hasher,
                                        &elements,
                                        range.start,
                                        &root
                                    ));
                                }
                            })
                        },
                        BatchSize::LargeInput,
                    )
                },
            );
        }
    }
}

fn bench_prove_many_elements(c: &mut Criterion) {
    bench_prove_many_elements_family::<commonware_storage::mmr::Family>(c, "mmr");
    bench_prove_many_elements_family::<commonware_storage::mmb::Family>(c, "mmb");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_prove_many_elements
}

use commonware_cryptography::{sha256, Sha256};
use commonware_math::algebra::Random as _;
use commonware_storage::merkle::{self, mem::Mem, Family, Location, LocationRangeExt as _};
use criterion::{criterion_group, Criterion};
use futures::executor::block_on;
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

type StandardHasher<H> = merkle::hasher::Standard<H>;

const SAMPLE_SIZE: usize = 100;

#[cfg(not(full_bench))]
const N_LEAVES: [usize; 2] = [10_000, 100_000];
#[cfg(full_bench)]
const N_LEAVES: [usize; 5] = [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000];

fn bench_prove_many_elements_family<F: Family>(c: &mut Criterion, family: &str) {
    for n in N_LEAVES {
        let hasher = StandardHasher::<Sha256>::new();
        let mut mem = Mem::<F, _>::new(&hasher);
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
                batch.merkleize(&hasher, &mem)
            };
            mem.apply_batch(&batch).unwrap();
        });
        let root = *mem.root();

        // Generate SAMPLE_SIZE random starts without replacement and create/verify range proofs
        for range in [2, 5, 10, 25, 50, 100, 250, 500, 1_000, 5_000] {
            c.bench_function(
                &format!(
                    "{}/n={n} range={range} samples={SAMPLE_SIZE} family={family}",
                    module_path!(),
                ),
                |b| {
                    b.iter_batched(
                        || {
                            let start_locs: Vec<u64> = (0u64..n as u64 - range).collect();
                            let start_loc_samples = start_locs
                                .choose_multiple(&mut sampler, SAMPLE_SIZE)
                                .cloned()
                                .collect::<Vec<_>>();
                            let mut samples = Vec::with_capacity(SAMPLE_SIZE);
                            block_on(async {
                                for start_index in start_loc_samples {
                                    let leaf_range = Location::<F>::new(start_index)
                                        ..Location::<F>::new(start_index + range);
                                    samples.push(leaf_range);
                                }
                                samples
                            })
                        },
                        |samples| {
                            let hasher = StandardHasher::<Sha256>::new();
                            block_on(async {
                                for range in samples {
                                    let proof = mem.range_proof(&hasher, range.clone()).unwrap();
                                    assert!(proof.verify_range_inclusion(
                                        &hasher,
                                        &elements[range.to_usize_range()],
                                        range.start,
                                        &root,
                                    ));
                                }
                            })
                        },
                        criterion::BatchSize::SmallInput,
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

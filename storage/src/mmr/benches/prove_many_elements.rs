use commonware_cryptography::{sha256, Digest as _, Sha256};
use commonware_storage::mmr::{
    location::LocationRangeExt as _, mem::Mmr, Location, StandardHasher,
};
use criterion::{criterion_group, Criterion};
use futures::executor::block_on;
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

const SAMPLE_SIZE: usize = 100;

#[cfg(not(full_bench))]
const N_LEAVES: [usize; 2] = [10_000, 100_000];
#[cfg(full_bench)]
const N_LEAVES: [usize; 5] = [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000];

fn bench_prove_many_elements(c: &mut Criterion) {
    for n in N_LEAVES {
        // Populate MMR
        let mut mmr = Mmr::<Sha256>::new();
        let mut elements = Vec::with_capacity(n);
        let mut sampler = StdRng::seed_from_u64(0);
        let mut hasher = StandardHasher::new();

        block_on(async {
            for _ in 0..n {
                let element = sha256::Digest::random(&mut sampler);
                mmr.add(&mut hasher, &element);
                elements.push(element);
            }
        });
        let root = mmr.root(&mut hasher);

        // Generate SAMPLE_SIZE random starts without replacement and create/verify range proofs
        for range in [2, 5, 10, 25, 50, 100, 250, 500, 1_000, 5_000] {
            c.bench_function(
                &format!(
                    "{}/n={} range={} samples={}",
                    module_path!(),
                    n,
                    range,
                    SAMPLE_SIZE
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
                                    let leaf_range = Location::new(start_index).unwrap()
                                        ..Location::new(start_index + range).unwrap();
                                    samples.push(leaf_range);
                                }
                                samples
                            })
                        },
                        |samples| {
                            let mut hasher = StandardHasher::<Sha256>::new();
                            block_on(async {
                                for range in samples {
                                    let proof = mmr.range_proof(range.clone()).unwrap();
                                    assert!(proof.verify_range_inclusion(
                                        &mut hasher,
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

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_prove_many_elements
}

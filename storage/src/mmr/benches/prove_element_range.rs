use commonware_cryptography::{Digest, Hasher, Sha256};
use commonware_storage::mmr::mem::Mmr;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

const SAMPLE_SIZE: usize = 100;

fn bench_prove_element_range(c: &mut Criterion) {
    for n in [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000] {
        for range in [2, 5, 10, 25, 50, 100] {
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
                            // Populate MMR
                            let mut mmr = Mmr::<Sha256>::new();
                            let mut positions = Vec::with_capacity(n);
                            let mut elements = Vec::with_capacity(n);
                            let mut sampler = StdRng::seed_from_u64(0);
                            for _ in 0..n {
                                let mut digest = vec![0u8; Sha256::len()];
                                sampler.fill_bytes(&mut digest);
                                let element = Digest::from(digest);
                                let pos = mmr.add(&element);
                                positions.push(pos);
                                elements.push(element);
                            }
                            let root_hash = mmr.root_hash();

                            // Generate samples
                            let mut samples = Vec::with_capacity(SAMPLE_SIZE);
                            for _ in 0..SAMPLE_SIZE {
                                let start_index = sampler.gen_range(0..(n - range));
                                let start_pos = positions[start_index];
                                let end_index = start_index + range;
                                let end_pos = positions[end_index];
                                samples.push(((start_index, end_index), (start_pos, end_pos)));
                            }
                            (mmr, root_hash, elements, samples)
                        },
                        |(mmr, mmr_root, elements, samples)| {
                            let mut hasher = Sha256::new();
                            for ((start_index, end_index), (start_pos, end_pos)) in samples {
                                let proof = mmr.range_proof(start_pos, end_pos);
                                assert!(proof.verify_range_inclusion(
                                    &elements[start_index..=end_index],
                                    start_pos,
                                    end_pos,
                                    &mmr_root,
                                    &mut hasher
                                ));
                            }
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
    targets = bench_prove_element_range
}

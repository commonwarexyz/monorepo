use commonware_cryptography::{Hasher, Sha256};
use commonware_storage::mmr::mem::Mmr;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

const SAMPLE_SIZE: usize = 100;

fn bench_prove_many_elements(c: &mut Criterion) {
    for n in [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000] {
        // Populate MMR
        let mut mmr = Mmr::<Sha256>::new();
        let mut positions = Vec::with_capacity(n);
        let mut elements = Vec::with_capacity(n);
        let mut sampler = StdRng::seed_from_u64(0);
        for i in 0..n {
            let element = Sha256::random(&mut sampler);
            let pos = mmr.add(&element);
            positions.push((i, pos));
            elements.push(element);
        }
        let root_hash = mmr.root();

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
                            let start_positions = &positions[0..n - range];
                            let starts = start_positions
                                .choose_multiple(&mut sampler, SAMPLE_SIZE)
                                .cloned()
                                .collect::<Vec<_>>();
                            let mut samples = Vec::with_capacity(SAMPLE_SIZE);
                            for (start_index, start_pos) in starts {
                                let end_index = start_index + range;
                                let end_pos = positions[end_index].1;
                                samples.push(((start_index, end_index), (start_pos, end_pos)));
                            }
                            samples
                        },
                        |samples| {
                            let mut hasher = Sha256::new();
                            for ((start_index, end_index), (start_pos, end_pos)) in samples {
                                let proof = mmr.range_proof(start_pos, end_pos).unwrap();
                                assert!(proof.verify_range_inclusion(
                                    &mut hasher,
                                    &elements[start_index..=end_index],
                                    start_pos,
                                    end_pos,
                                    &root_hash,
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
    targets = bench_prove_many_elements
}

use commonware_cryptography::{Digest, Hasher, Sha256};
use commonware_storage::mmr::mem::Mmr;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};

const SAMPLE_SIZE: usize = 100;

fn bench_prove_element_range(c: &mut Criterion) {
    for n in [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000] {
        c.bench_function(
            &format!("{}/n={} samples={}", module_path!(), n, SAMPLE_SIZE),
            |b| {
                b.iter_batched(
                    || {
                        let mut mmr = Mmr::<Sha256>::new();
                        let mut leaf_sample = Vec::new();
                        let mut elements = Vec::with_capacity(n);
                        let mut sampler = StdRng::seed_from_u64(0);
                        for i in 0..n {
                            let mut digest = vec![0u8; Sha256::len()];
                            sampler.fill_bytes(&mut digest);
                            let element = Digest::from(digest);
                            let pos = mmr.add(&element);
                            elements.push(element.clone());
                            if i % SAMPLE_SIZE == 0 {
                                leaf_sample.push(pos);
                            }
                        }
                        let root_hash = mmr.root_hash();
                        (mmr, root_hash, elements, leaf_sample)
                    },
                    |(mmr, mmr_root, elements, leaf_sample)| {
                        let mut hasher = Sha256::new();
                        let mut iter = leaf_sample.iter();
                        let mut pos1 = iter.next().unwrap();
                        let mut count: usize = 0;
                        for pos2 in iter {
                            let proof = mmr.range_proof(*pos1, *pos2);
                            assert!(proof.verify_range_inclusion(
                                &elements[count..count + SAMPLE_SIZE + 1],
                                *pos1,
                                *pos2,
                                &mmr_root,
                                &mut hasher
                            ));
                            pos1 = pos2;
                            count += SAMPLE_SIZE;
                        }
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_prove_element_range
}

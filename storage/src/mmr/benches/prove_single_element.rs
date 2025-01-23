use commonware_cryptography::{Digest, Hasher, Sha256};
use commonware_storage::mmr::mem::Mmr;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};

const SAMPLE_SIZE: usize = 100;

fn bench_prove_single_element(c: &mut Criterion) {
    for n in [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000] {
        c.bench_function(
            &format!("{}/n={} samples={}", module_path!(), n, SAMPLE_SIZE),
            |b| {
                b.iter_batched(
                    || {
                        let mut mmr = Mmr::<Sha256>::new();
                        let mut elements = Vec::new();
                        let mut sampler = StdRng::seed_from_u64(0);
                        for i in 0..n {
                            let mut digest = vec![0u8; Sha256::len()];
                            sampler.fill_bytes(&mut digest);
                            let element = Digest::from(digest);
                            let pos = mmr.add(&element);
                            if i % SAMPLE_SIZE == 0 {
                                elements.push((pos, element));
                            }
                        }
                        let root_hash = mmr.root_hash();
                        (mmr, root_hash, elements)
                    },
                    |(mmr, mmr_root, elements)| {
                        let mut hasher = Sha256::new();
                        for (pos, element) in elements {
                            let proof = mmr.proof(pos);
                            assert!(proof.verify_element_inclusion(
                                &element,
                                pos,
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
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_prove_single_element
}

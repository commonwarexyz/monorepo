use commonware_cryptography::{Hasher, Sha256};
use commonware_storage::binary::Tree;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

const SAMPLE_SIZE: usize = 100;

fn bench_prove_single_element(c: &mut Criterion) {
    for n in [100, 1_000, 5_000, 10_000, 25_000, 50_000, 100_000] {
        // Populate Binary Merkle Tree
        let mut elements = Vec::with_capacity(n);
        let mut queries = Vec::with_capacity(n);
        let mut sampler = StdRng::seed_from_u64(0);
        for pos in 0..n {
            let element = Sha256::random(&mut sampler);
            elements.push(element.clone());
            queries.push((pos, element));
        }
        let mut hasher = Sha256::new();
        let tree = Tree::<Sha256>::new(&mut hasher, elements).unwrap();
        let root = tree.root();

        // Select SAMPLE_SIZE random elements without replacement and create/verify proofs
        c.bench_function(
            &format!("{}/n={} samples={}", module_path!(), n, SAMPLE_SIZE),
            |b| {
                b.iter_batched(
                    || {
                        let samples = queries
                            .choose_multiple(&mut sampler, SAMPLE_SIZE)
                            .cloned()
                            .collect::<Vec<_>>();
                        samples
                    },
                    |samples| {
                        let mut hasher = Sha256::new();
                        for (pos, element) in samples {
                            let proof = tree.prove(pos).unwrap();
                            assert!(proof.verify(&mut hasher, &element, pos as u64, &root));
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

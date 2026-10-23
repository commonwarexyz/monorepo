use crate::common::{N_LEAVES, SAMPLE_SIZE, StandardHasher, single_samples};
use commonware_cryptography::Sha256;
use commonware_storage::merkle::{Bagging::ForwardFold, Family};
use criterion::{BatchSize, Criterion, criterion_group};
use futures::executor::block_on;

/// Times single-leaf proof verification, with the proofs generated in setup.
fn bench_verify_single_element_family<F: Family>(c: &mut Criterion, family: &str) {
    for n in N_LEAVES {
        c.bench_function(
            &format!(
                "{}/n={n} samples={SAMPLE_SIZE} family={family}",
                module_path!(),
            ),
            |b| {
                b.iter_batched(
                    || {
                        let (mem, root, samples) = single_samples::<F>(n);
                        let hasher = StandardHasher::<Sha256>::new(ForwardFold);
                        let proofs = block_on(async {
                            let mut proofs = Vec::with_capacity(samples.len());
                            for (loc, element) in samples {
                                proofs.push((loc, element, mem.proof(&hasher, loc, 0).unwrap()));
                            }
                            proofs
                        });
                        (root, proofs)
                    },
                    |(root, proofs)| {
                        let hasher = StandardHasher::<Sha256>::new(ForwardFold);
                        for (loc, element, proof) in proofs {
                            assert!(proof.verify_element_inclusion(&hasher, &element, loc, &root));
                        }
                    },
                    BatchSize::LargeInput,
                )
            },
        );
    }
}

fn bench_verify_single_element(c: &mut Criterion) {
    bench_verify_single_element_family::<commonware_storage::mmr::Family>(c, "mmr");
    bench_verify_single_element_family::<commonware_storage::mmb::Family>(c, "mmb");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_verify_single_element
}

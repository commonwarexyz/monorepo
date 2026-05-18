use commonware_cryptography::{sha256, Sha256};
use commonware_math::algebra::Random as _;
use commonware_storage::merkle::{self, mem::Mem, Bagging::ForwardFold, Family, Location};
use criterion::{criterion_group, BatchSize, Criterion};
use futures::executor::block_on;
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

type StandardHasher<H> = merkle::hasher::Standard<H>;

const SAMPLE_SIZE: usize = 100;

#[cfg(not(full_bench))]
const N_LEAVES: [usize; 2] = [10_000, 100_000];
#[cfg(full_bench)]
const N_LEAVES: [usize; 5] = [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000];

type Sample<F> = (Location<F>, sha256::Digest);

fn make_test_data<F: Family>(n: usize) -> (Mem<F, sha256::Digest>, sha256::Digest, Vec<Sample<F>>) {
    let hasher = StandardHasher::<Sha256>::new(ForwardFold);
    let mut mem = Mem::<F, _>::new();
    let mut elements = Vec::with_capacity(n);
    let mut sampler = StdRng::seed_from_u64(0);
    block_on(async {
        let batch = {
            let mut batch = mem.new_batch();
            for i in 0..n {
                let element = sha256::Digest::random(&mut sampler);
                batch = batch.add(&hasher, &element);
                elements.push((i, element));
            }
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();
    });
    let root = mem.root(&hasher, 0).unwrap();
    let samples = elements
        .choose_multiple(&mut sampler, SAMPLE_SIZE)
        .cloned()
        .map(|(loc, element)| (Location::<F>::new(loc as u64), element))
        .collect::<Vec<_>>();
    (mem, root, samples)
}

fn bench_prove_single_element_family<F: Family>(c: &mut Criterion, family: &str) {
    for n in N_LEAVES {
        c.bench_function(
            &format!(
                "{}/n={n} samples={SAMPLE_SIZE} family={family}",
                module_path!(),
            ),
            |b| {
                b.iter_batched(
                    || make_test_data::<F>(n),
                    |(mem, root, samples)| {
                        block_on(async {
                            let hasher = StandardHasher::<Sha256>::new(ForwardFold);
                            for (loc, element) in samples {
                                let proof = mem.proof(&hasher, loc, 0).unwrap();
                                assert!(
                                    proof.verify_element_inclusion(&hasher, &element, loc, &root)
                                );
                            }
                        });
                    },
                    BatchSize::LargeInput,
                )
            },
        );
    }
}

fn bench_prove_single_element(c: &mut Criterion) {
    bench_prove_single_element_family::<commonware_storage::mmr::Family>(c, "mmr");
    bench_prove_single_element_family::<commonware_storage::mmb::Family>(c, "mmb");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_prove_single_element
}

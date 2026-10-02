use commonware_cryptography::{Blake3, Hasher, Sha256};
use commonware_math::algebra::Random as _;
use commonware_parallel::Rayon;
use commonware_storage::merkle::{self, Bagging::ForwardFold, Family, mem::Mem};
use commonware_utils::{NZUsize, test_rng};
use criterion::{BatchSize, Criterion, criterion_group};

type StandardHasher<H> = merkle::hasher::Standard<H>;

#[cfg(not(full_bench))]
const N_LEAVES: [usize; 2] = [10_000, 100_000];
#[cfg(full_bench)]
const N_LEAVES: [usize; 5] = [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000];

/// Worker threads for the parallel strategy.
const THREADS: usize = 8;

fn make_elements<H: Hasher>(n: usize) -> Vec<H::Digest> {
    let mut elements = Vec::with_capacity(n);
    let mut sampler = test_rng();
    for _ in 0..n {
        elements.push(H::Digest::random(&mut sampler));
    }
    elements
}

fn bench_append_many_family<F: Family, H: Hasher>(c: &mut Criterion, family: &str, hasher: &str) {
    let rayon = Rayon::new(NZUsize!(THREADS)).unwrap();
    for n in N_LEAVES {
        for strategy in ["serial", "parallel"] {
            c.bench_function(
                &format!(
                    "{}/n={n} strategy={strategy} family={family} hasher={hasher}",
                    module_path!()
                ),
                |b| {
                    b.iter_batched(
                        || make_elements::<H>(n),
                        |elements| {
                            let h = StandardHasher::<H>::new(ForwardFold);
                            let mut mem = Mem::<F, _>::new();
                            if strategy == "parallel" {
                                let batch = mem
                                    .new_batch_with_strategy(rayon.clone())
                                    .add_many(&h, &elements)
                                    .merkleize(&mem, &h);
                                mem.apply_batch(&batch).unwrap();
                            } else {
                                let batch =
                                    mem.new_batch().add_many(&h, &elements).merkleize(&mem, &h);
                                mem.apply_batch(&batch).unwrap();
                            }
                            mem
                        },
                        BatchSize::LargeInput,
                    );
                },
            );
        }
    }
}

fn bench_append_many(c: &mut Criterion) {
    bench_append_many_family::<commonware_storage::mmr::Family, Sha256>(c, "mmr", "sha256");
    bench_append_many_family::<commonware_storage::mmr::Family, Blake3>(c, "mmr", "blake3");
    bench_append_many_family::<commonware_storage::mmb::Family, Sha256>(c, "mmb", "sha256");
    bench_append_many_family::<commonware_storage::mmb::Family, Blake3>(c, "mmb", "blake3");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_append_many
}
